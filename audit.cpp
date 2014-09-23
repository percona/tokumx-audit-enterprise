/**
 *    Copyright (C) 2014 Tokutek Inc.
 */

#include "mongo/bson/bson_field.h"
#include "mongo/db/audit.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/client_basic.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/matcher.h"
#include "mongo/db/namespacestring.h"
#include "mongo/util/concurrency/rwlock.h"
#include "mongo/util/concurrency/simplerwlock.h"
#include "mongo/util/file.h"
#include "mongo/util/log.h"
#include "mongo/util/time_support.h"

#include <cstdio>

#if MONGO_ENTERPRISE_VERSION
#define MONGO_AUDIT_STUB ;
#else
#define MONGO_AUDIT_STUB {}
#endif

namespace mongo {
namespace audit {

    class Log : public AuditLog {
    public:
        virtual void append(const BSONObj & obj) {};
        virtual ~Log() {};
        virtual void rotate() {};
    };

    class FileLog : public Log {
    public:
        FileLog(const std::string & file, const BSONObj & filter)
            : _file(new File), 
              _matcher(filter.getOwned()), 
              _fileName(file),
              _rwLock("auditfileRWLock") {
            _file->open(file.c_str(), false, false);
        };

        virtual void append(const BSONObj & obj) {
            if (_matcher.matches(obj)) {
                std::string str = obj.str();
                SimpleRWLock::Shared lck(_rwLock);
                _file->write(_file->len(), str.c_str(), str.size());
                _file->write(_file->len(), "\n", 1);
                _file->fsync();
            }
        };

        virtual void rotate() {
            SimpleRWLock::Exclusive lck(_rwLock);

            // Close the current file.
            _file.reset();

            // Rename the current file
            // Note: we append a timestamp to the file name.
            stringstream ss;
            ss << _fileName << "." << terseCurrentTime(false);
            std::string s = ss.str();
            int r = std::rename(_fileName.c_str(), s.c_str());
            if (r != 0) {
                error() << "Could not rotate audit log:" 
                        << errnoWithDescription()
                        << endl;
                return;
            }

            // Open a new file, with the same name as the original.
            _file.reset(new File);
            _file->open(_fileName.c_str(), false, false);
        }

    private:
        scoped_ptr<File> _file;
        Matcher _matcher;
        std::string _fileName;
        SimpleRWLock _rwLock;
    };

    static shared_ptr<Log> logger = shared_ptr<Log>(new Log);

    bool commandLineArgumentsSet() {
        if (cmdLine.auditDestination == "" || cmdLine.auditFormat == "") {
            return false;
        }

        return true;
    }

    bool commandLineArgumentsValid() {
        if (cmdLine.auditDestination != "file") {
            return false;
        }
        
        if (cmdLine.auditFormat != "JSON") {
            return false;
        }

        return true;
    }

    Status initialize() {
        if (!commandLineArgumentsSet()) {
            return Status::OK();
        }

        try {
            log() << "Initializing audit..." << endl;
            if (!commandLineArgumentsValid()) {
                // TODO: Return Status from above check, with specific failures.
                return Status(ErrorCodes::BadValue, "Invalid Audit Command Line Arguments.");
            }

            const BSONObj filter = fromjson(cmdLine.auditFilter);            
            logger.reset(new FileLog(cmdLine.auditPath, filter));
        }
        catch (const std::exception &ex) {
            log() << "Audit Filter Error:" << ex.what() << endl;
            const std::string s = str::stream() << "Audit initialization error: " << ex.what(); 
            // TODO: It isnt always invalid bson..
            return Status(ErrorCodes::InvalidBSON, s);
        }

        setAuditLog(logger.get());

        return Status::OK();
    }

    namespace AuditFields {
        BSONField<StringData> type("atype");
        BSONField<Date_t> timestamp("ts");
        BSONField<StringData> ns("ns");
        BSONField<ErrorCodes::Error> result("result");
        BSONField<StringData> users("users");
        BSONField<StringData> dbs("dbs");
        BSONField<BSONObj> filter("filter");
    }

    static void appendCommonInfo(BSONObjBuilder &builder,
                                 const StringData &atype,
                                 ClientBasic* client) {
        builder << AuditFields::type(atype);
        builder << AuditFields::timestamp(jsTime());

        if (client->hasRemote()) {
            builder.append("HostAndPort", client->getRemote().toString());
        }

        if (client->hasAuthorizationManager()) {
            AuthorizationManager * manager = client->getAuthorizationManager();

            // First get the user name array.
            PrincipalSet::NameIterator nameIter = manager->getAuthenticatedPrincipalNames();
            BSONArrayBuilder allUsers(builder.subarrayStart(AuditFields::users()));
            for ( ; nameIter.more(); nameIter.next()) {
                allUsers.append(AuthorizationManager::USER_NAME_FIELD_NAME, nameIter->getUser());
            }

            allUsers.doneFast();

            // Now get the db name array.
            PrincipalSet::NameIterator dbIter = manager->getAuthenticatedPrincipalNames();
            BSONArrayBuilder allDBs(builder.subarrayStart(AuditFields::dbs()));
            for ( ; dbIter.more(); dbIter.next()) {
                allDBs.append(AuthorizationManager::USER_SOURCE_FIELD_NAME, dbIter->getDB());
            }

            allDBs.doneFast();
        }
    }

    void logAuthentication(ClientBasic* client,
                           const StringData& mechanism,
                           const std::string& user,
                           ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "authentication", client);
        builder.append("mechanism", mechanism);
        builder.append("user", user);
        logger->append(builder.done());
    }

    void logCommandAuthzCheck(ClientBasic* client,
                              const NamespaceString& ns,
                              const BSONObj& cmdObj,
                              ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "commandAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logDeleteAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& pattern,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "deleteAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder.append("pattern", pattern);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logGetMoreAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "getMoreAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder.append("cursor_id", cursorId);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logInProgAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "inProgAuthzCheck", client);
        builder << AuditFields::filter(filter);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logInsertAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& insertedObj,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "insertAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder.append("obj", insertedObj); 
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logKillCursorsAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "killCursorsAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder.append("cursor_id", cursorId);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logKillOpAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "killOpAuthzCheck", client);
        builder << AuditFields::filter(filter);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logQueryAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& query,
            ErrorCodes::Error result) {
        // HACK: This is to avoid printing internal "Client"
        // heartbeat queries.
        if (client->hasRemote()) {
            BSONObjBuilder builder;
            appendCommonInfo(builder, "queryAuthCheck", client);
            builder << AuditFields::ns(ns.toString());
            builder.append("query", query);
            builder << AuditFields::result(result);
            logger->append(builder.done());
        }
    }

    void logUpdateAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& query,
            const BSONObj& updateObj,
            bool isUpsert,
            bool isMulti,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "updateAuthzCheck", client);
        builder << AuditFields::ns(ns.toString());
        builder.append("query", query);
        builder.append("upsert", isUpsert);
        builder.append("multi", isMulti);
        builder << AuditFields::result(result);
        logger->append(builder.done());
    }

    void logReplSetReconfig(ClientBasic* client,
                            const BSONObj* oldConfig,
                            const BSONObj* newConfig) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "replSetReconfig", client);
        builder.append("old_config", oldConfig);
        builder.append("new_config", newConfig);
        logger->append(builder.done());
    }

    void logApplicationMessage(ClientBasic* client,
                               const StringData& msg) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "applicationMessage", client);
        builder.append("message", msg);
        logger->append(builder.done());
    }

    void logShutdown(ClientBasic* client) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "shutdown", client);
        logger->append(builder.done());
    }

    void logAuditLogRotate(ClientBasic* client,
                           const StringData& file) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "rotateAuditLog", client);
        builder.append("file", file);
        logger->append(builder.done());
    }

    void logCreateIndex(ClientBasic* client,
                        const BSONObj* indexSpec,
                        const StringData& indexname,
                        const StringData& nsname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "createIndex", client);
        builder.append("index_spec", indexSpec);
        builder.append("index_name", indexname);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logCreateCollection(ClientBasic* client,
                             const StringData& nsname) { 
        BSONObjBuilder builder;
        appendCommonInfo(builder, "createCollection", client);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logCreateDatabase(ClientBasic* client,
                           const StringData& nsname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "createDatabase", client);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logDropIndex(ClientBasic* client,
                      const StringData& indexname,
                      const StringData& nsname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "dropIndex",  client);
        builder.append("index", indexname);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logDropCollection(ClientBasic* client,
                           const StringData& nsname) { 
        BSONObjBuilder builder;
        appendCommonInfo(builder, "dropCollection", client);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logDropDatabase(ClientBasic* client,
                         const StringData& nsname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "dropDatabase", client);
        builder << AuditFields::ns(nsname);
        logger->append(builder.done());
    }

    void logRenameCollection(ClientBasic* client,
                             const StringData& source,
                             const StringData& target) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "renameCollection", client);
        builder.append("source", source);
        builder.append("target", target);
        logger->append(builder.done());
    }

    void logEnableSharding(ClientBasic* client,
                           const StringData& nsname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "enableSharding", client);
        builder << AuditFields::ns(nsname); 
        logger->append(builder.done());
    }

    void logAddShard(ClientBasic* client,
                     const StringData& name,
                     const std::string& servers,
                     long long maxsize) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "addShard", client);
        builder.append("name", name);
        builder.append("servers", servers);
        builder.append("max_size", maxsize);
        logger->append(builder.done());
    }

    void logRemoveShard(ClientBasic* client,
                        const StringData& shardname) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "removeShard", client);
        builder.append("shard_name", shardname);
        logger->append(builder.done());
    }

    void logShardCollection(ClientBasic* client,
                            const StringData& ns,
                            const BSONObj& keyPattern,
                            bool unique) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, "shardCollection", client);
        builder << AuditFields::ns(ns);
        builder.append("key_pattern", keyPattern);
        logger->append(builder.done());
    }

}  // namespace audit
}  // namespace mongo

