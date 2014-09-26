/**
 *    Copyright (C) 2014 Tokutek Inc.
 */

#include <cstdio>

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
#include "mongo/util/net/sock.h"
#include "mongo/util/time_support.h"

namespace mongo {
namespace audit {

    // Writable interface for audit events
    class WritableAuditLog : public AuditLog {
    public:
        virtual ~WritableAuditLog() {};
        virtual void append(const BSONObj &obj) = 0;
        virtual void rotate() = 0;
    };

    // Writes audit events to a json file
    class JSONAuditLog : public WritableAuditLog {
    public:
        JSONAuditLog(const std::string &file, const BSONObj &filter)
            : _file(new File), 
              _matcher(filter.getOwned()), 
              _fileName(file),
              _rwLock("auditfileRWLock") {
            _file->open(file.c_str(), false, false);
        };

        virtual void append(const BSONObj &obj) {
            if (_matcher.matches(obj)) {
                const std::string str = obj.str();
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
        const Matcher _matcher;
        const std::string _fileName;
        SimpleRWLock _rwLock;
    };

    // Opens an audit log writes to the void - no logging action is taken
    // other than doing a simple sanity check on the obj to see that it
    // is non-empty and iterable.
    // empty and is iterable.
    class VoidAuditLog : public WritableAuditLog {
    public:
        void append(const BSONObj &obj) {
            verify(!obj.str().empty());
        }

        void rotate() { }
    };

    // A null logger means audit is not enabled.
    static shared_ptr<WritableAuditLog> logger;

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
            // Write audit events into the void for debug builds, so we get
            // coverage on the code that generates audit log objects.
            DEV {
                log() << "Initializing dev null audit log..." << endl;
                logger.reset(new VoidAuditLog()); 
                setAuditLog(logger.get());
            }
            return Status::OK();
        }

        try {
            log() << "Initializing audit..." << endl;
            if (!commandLineArgumentsValid()) {
                // TODO: Return Status from above check, with specific failures.
                return Status(ErrorCodes::BadValue, "Invalid audit command line arguments.");
            }

            const BSONObj filter = fromjson(cmdLine.auditFilter);            
            logger.reset(new JSONAuditLog(cmdLine.auditPath, filter));
            setAuditLog(logger.get());
            return Status::OK();
        }
        catch (const std::exception &ex) {
            log() << "Audit filter error:" << ex.what() << endl;
            const std::string s = str::stream() << "Audit initialization error: " << ex.what(); 
            // TODO: It isnt always invalid bson..
            return Status(ErrorCodes::InvalidBSON, s);
        }
    }

    namespace AuditFields {
        // Common fields
        BSONField<StringData> type("atype");
        BSONField<BSONObj> timestamp("ts");
        BSONField<BSONObj> local("local");
        BSONField<BSONObj> remote("remote");
        BSONField<BSONObj> params("params");
        BSONField<int> result("result");
    }

    // This exists because NamespaceString::toString() prints "admin."
    // when dbname == "admin" and coll == "", which isn't so great.
    static std::string nssToString(const NamespaceString &nss) {
        stringstream ss;
        if (!nss.db.empty()) {
            ss << nss.db;
        }
        if (!nss.coll.empty()) {
            ss << '.' << nss.coll;
        }
        return ss.str();
    }

    static void appendCommonInfo(BSONObjBuilder &builder,
                                 const StringData &atype,
                                 ClientBasic* client) {
        builder << AuditFields::type(atype);
        builder << AuditFields::timestamp(BSON("$date" << jsTime()));
        builder << AuditFields::local(BSON("host" << getHostNameCached() << "port" << cmdLine.port));
        if (client->hasRemote()) {
            const HostAndPort hp = client->getRemote();
            builder << AuditFields::remote(BSON("host" << hp.host() << "port" << hp.port()));
        } else {
            // It's not 100% clear that an empty obj here actually makes sense..
            builder << AuditFields::remote(BSONObj());
        }
        if (client->hasAuthorizationManager()) {
            // Build the users array, which consists of (user, db) pairs
            AuthorizationManager *manager = client->getAuthorizationManager();
            BSONArrayBuilder users(builder.subarrayStart("users"));
            for (PrincipalSet::NameIterator it = manager->getAuthenticatedPrincipalNames();
                 it.more(); it.next()) {
                users.append(BSON("user" << it->getUser() << "db" << it->getDB()));
            }
            users.doneFast();
        } else {
            // It's not 100% clear that an empty obj here actually makes sense..
            builder << "users" << BSONObj();
        }
    }

    static void _auditEvent(ClientBasic* client,
                            const StringData& atype,
                            const BSONObj& params,
                            ErrorCodes::Error result = ErrorCodes::OK) {
        BSONObjBuilder builder;
        appendCommonInfo(builder, atype, client);
        builder << AuditFields::params(params);
        builder << AuditFields::result(static_cast<int>(result));
        logger->append(builder.done());
    }

    static void _auditAuthzFailure(ClientBasic* client,
                                 const StringData& ns,
                                 const StringData& command,
                                 const BSONObj& args,
                                 ErrorCodes::Error result) {
        const BSONObj params = !ns.empty() ?
            BSON("command" << command << "ns" << ns << "args" << args) :
            BSON("command" << command << "args" << args);
        _auditEvent(client, "authCheck", params, result);
    }

    void logAuthentication(ClientBasic* client,
                           const StringData& dbname,
                           const StringData& mechanism,
                           const std::string& user,
                           ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("user" << user <<
                                    "db" << dbname <<
                                    "mechanism" << mechanism);
        _auditEvent(client, "authenticate", params, result);
    }

    void logCommandAuthzCheck(ClientBasic* client,
                              const NamespaceString& ns,
                              const BSONObj& cmdObj,
                              ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), cmdObj.firstElement().fieldName(), cmdObj, result);
        }
    }

    void logDeleteAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& pattern,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "delete", BSON("pattern" << pattern), result);
        }
    }

    void logGetMoreAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "getMore", BSON("cursorId" << cursorId), result);
        }
    }

    void logInProgAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, "", "inProg", BSON("filter" << filter), result);
        }
    }

    void logInsertAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& insertedObj,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "insert", BSON("obj" << insertedObj), result);
        }
    }

    void logKillCursorsAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "killCursors", BSON("cursorId" << cursorId), result);
        }
    }

    void logKillOpAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, "", "killOp", BSON("filter" << filter), result);
        }
    }

    void logQueryAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& query,
            ErrorCodes::Error result) {
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "query", BSON("query" << query), result);
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
        if (!logger) {
            return;
        }

        if (result != ErrorCodes::OK) {
            const BSONObj args = BSON("pattern" << query <<
                                      "upsert" << isUpsert <<
                                      "multi" << isMulti); 
            _auditAuthzFailure(client, nssToString(ns), "update", args, result);
        }
    }

    void logReplSetReconfig(ClientBasic* client,
                            const BSONObj* oldConfig,
                            const BSONObj* newConfig) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("old" << oldConfig << "new" << newConfig);
        _auditEvent(client, "replSetReconfig", params);
    }

    void logApplicationMessage(ClientBasic* client,
                               const StringData& msg) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("msg" << msg);
        _auditEvent(client, "applicationMessage", params);
    }

    void logShutdown(ClientBasic* client) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSONObj();
        _auditEvent(client, "shutdown", params);
    }

    void logCreateIndex(ClientBasic* client,
                        const BSONObj* indexSpec,
                        const StringData& indexname,
                        const StringData& nsname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname <<
                                    "indexName" << indexname <<
                                    "indexSpec" << indexSpec);
        _auditEvent(client, "createIndex", params);
    }

    void logCreateCollection(ClientBasic* client,
                             const StringData& nsname) { 
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "createCollection", params);
    }

    void logCreateDatabase(ClientBasic* client,
                           const StringData& nsname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "createDatabase", params);
    }

    void logDropIndex(ClientBasic* client,
                      const StringData& indexname,
                      const StringData& nsname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname << "indexName" << indexname);
        _auditEvent(client, "dropIndex", params);
    }

    void logDropCollection(ClientBasic* client,
                           const StringData& nsname) { 
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "dropCollection", params);
    }

    void logDropDatabase(ClientBasic* client,
                         const StringData& nsname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "dropDatabase", params);
    }

    void logRenameCollection(ClientBasic* client,
                             const StringData& source,
                             const StringData& target) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("old" << source << "new" << target);
        _auditEvent(client, "renameCollection", params);
    }

    void logEnableSharding(ClientBasic* client,
                           const StringData& nsname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "enableSharding", params);
    }

    void logAddShard(ClientBasic* client,
                     const StringData& name,
                     const std::string& servers,
                     long long maxsize) {
        if (!logger) {
            return;
        }

        const BSONObj params= BSON("shard" << name <<
                                   "connectionString" << servers <<
                                   "maxSize" << maxsize);
        _auditEvent(client, "addShard", params);
    }

    void logRemoveShard(ClientBasic* client,
                        const StringData& shardname) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("shard" << shardname);
        _auditEvent(client, "removeShard", params);
    }

    void logShardCollection(ClientBasic* client,
                            const StringData& ns,
                            const BSONObj& keyPattern,
                            bool unique) {
        if (!logger) {
            return;
        }

        const BSONObj params = BSON("ns" << ns <<
                                    "key" << keyPattern <<
                                    "options" << BSON("unique" << unique));
        _auditEvent(client, "shardCollection", params);
    }

}  // namespace audit
}  // namespace mongo

