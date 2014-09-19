/**
 *    Copyright (C) 2013 10gen Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mongo/db/audit.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/client_basic.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/matcher.h"
#include "mongo/db/namespacestring.h"
#include "mongo/util/file.h"

#include <stdio.h>

#if MONGO_ENTERPRISE_VERSION
#define MONGO_AUDIT_STUB ;
#else
#define MONGO_AUDIT_STUB {}
#endif

namespace mongo {
namespace audit {

    //-------------------- CUT HERE -----------------------

    class Log {
    public:
        virtual void append(const BSONObj & obj) {};
        virtual ~Log() {};
        virtual void rotate() {};
    };

    class FileLog : public Log {
    public:
        FileLog(const std::string & file, const BSONObj & filter)
            : _matcher(filter.getOwned()), _fileName(file) {
            _file = new File;
            // TODO: We may want to rotate() an already existing file.
            _file->open(file.c_str(), false, false);
        };

        virtual void append(const BSONObj & obj) {
            if (_matcher.matches(obj)) {
                std::string str = obj.str();
                _file->write(_file->len(), str.c_str(), str.size());
                newLine();
                sync();
            }
        };

        virtual void rotate() {
            // Close the current file.
            delete _file;

            // Rename the current file
            // Note: we append a timestamp to the file name.
            stringstream ss;
            ss << _fileName << "." << terseCurrentTime(false);
            std::string s = ss.str();
            int r = rename(_fileName.c_str(), s.c_str());
            if (r != 0) {
                error() << "Could not rotate audit log:" 
                        << errnoWithDescription()
                        << endl;
                return;
            }

            // Open a new file, with the same name as the original.
            _file = new File;
            _file->open(_fileName.c_str(), false, false);
        }

    private:
        void newLine() {
            _file->write(_file->len(), "\n", 1);
        };

        void sync() {
            _file->fsync();
        };

    private:
        File * _file;
        Matcher _matcher;
        std::string _fileName;
    };

    static shared_ptr<Log> logger = shared_ptr<Log>(new Log);

    bool commandLineArgumentsValid() {
        // Extra error checking...
        if (cmdLine.auditDestination != "file") {
            out() << "" << endl;
            return false;
        }
        
        if (cmdLine.auditFormat != "JSON") {
            return false;
        }
        
        // TODO: Check for validity of filename and path.
        // TODO: Determine if we need to replace the file or not.
        
        return true;
    }

    Status initialize() {
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

        return Status::OK();
    }

    void rotateLog() {
        logger->rotate();
    }

    //-------------------- CUT HERE -----------------------

    static void printClientInfo(BSONObjBuilder &builder, ClientBasic* client) {
        if (client->hasRemote()) {
            builder.append("HostAndPort", client->getRemote().toString());
        }

        if (client->hasAuthorizationManager()) {
            AuthorizationManager * manager;
            manager = client->getAuthorizationManager();

            // First get the user name array.
            PrincipalSet::NameIterator nameIter = manager->getAuthenticatedPrincipalNames();
            BSONArrayBuilder allUsers(builder.subarrayStart("users"));
            for ( ; nameIter.more(); nameIter.next()) {
                allUsers.append(AuthorizationManager::USER_NAME_FIELD_NAME, nameIter->getUser());
            }

            allUsers.doneFast();

            // Now get the db name array.
            PrincipalSet::NameIterator dbIter = manager->getAuthenticatedPrincipalNames();
            BSONArrayBuilder allDBs(builder.subarrayStart("db"));
            for ( ; dbIter.more(); dbIter.next()) {
                allDBs.append(AuthorizationManager::USER_SOURCE_FIELD_NAME, dbIter->getDB());
            }

            allDBs.doneFast();
        }
    }

    const char * AUDIT_TYPE = "atype"; 
    const char * NAMESPACE = "namespace";
    const char * RESULT = "result";
    const char * USERS = "users";
    const char * DBS = "dbs";

    void logAuthentication(ClientBasic* client,
                           const StringData& mechanism,
                           const std::string& user,
                           ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Authenticantion");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append("mechanism", mechanism);
        builder.append("user", user);
        logger->append(builder.obj());
    }

    void logCommandAuthzCheck(ClientBasic* client,
                              const NamespaceString& ns,
                              const BSONObj& cmdObj,
                              ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Command Authz Check");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append(NAMESPACE, ns.toString());
        logger->append(builder.obj());
    }

    void logDeleteAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& pattern,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Delete Authz Check");
        printClientInfo(builder, client);
        builder.append("Result", result);
        builder.append("Namespace", ns.toString());
        builder.append("Pattern", pattern);
        logger->append(builder.obj());
    }

    void logGetMoreAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Get More Authz Check");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append(NAMESPACE, ns.toString());
        builder.append("cursor_id", cursorId);
        logger->append(builder.obj());
    }

    void logInProgAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "InProg Authz Check");
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

    void logInsertAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            const BSONObj& insertedObj,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Insert Authz Check");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append(NAMESPACE, ns.toString());
        builder.append("inserted_object", insertedObj); 
        logger->append(builder.obj());
    }

    void logKillCursorsAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Kill Cursors Authz Check");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append(NAMESPACE, ns.toString());
        builder.append("cursor_id", cursorId);
        logger->append(builder.obj());
    }

    void logKillOpAuthzCheck(
            ClientBasic* client,
            const BSONObj& filter,
            ErrorCodes::Error result) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Kill Operation Authz Check");
        printClientInfo(builder, client);
        builder.append("filter", filter);
        builder.append(RESULT, result);
        logger->append(builder.obj());
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
            builder.append(AUDIT_TYPE, "Query Authz Check");
            printClientInfo(builder, client);
            builder.append(RESULT, result);
            builder.append(NAMESPACE, ns.toString());
            builder.append("query", query);
            logger->append(builder.obj());
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
        builder.append(AUDIT_TYPE, "UpdateAuthzCheck");
        printClientInfo(builder, client);
        builder.append(RESULT, result);
        builder.append(NAMESPACE, ns.toString());
        builder.append("query", query);
        builder.append("upsert", isUpsert);
        builder.append("multi", isMulti);
        logger->append(builder.obj());
    }

    void logReplSetReconfig(ClientBasic* client,
                            const BSONObj* oldConfig,
                            const BSONObj* newConfig) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Repl Set Reconfig");
        printClientInfo(builder, client);
        builder.append("old_config", oldConfig);
        builder.append("new_config", newConfig);
        logger->append(builder.obj());
    }

    void logApplicationMessage(ClientBasic* client,
                               const StringData& msg) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Application Message");
        printClientInfo(builder, client);
        builder.append("message", msg);
        logger->append(builder.obj());
    }

    void logShutdown(ClientBasic* client) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Shutdown");
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

    void logAuditLogRotate(ClientBasic* client,
                           const StringData& file) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Rotate Audit Log");
        printClientInfo(builder, client);
        builder.append("file", file);
        logger->append(builder.obj());
    }

    void logCreateIndex(ClientBasic* client,
                        const BSONObj* indexSpec,
                        const StringData& indexname,
                        const StringData& nsname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Create Index");
        printClientInfo(builder, client);
        builder.append("index_spec", indexSpec);
        builder.append("index_name", indexname);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logCreateCollection(ClientBasic* client,
                             const StringData& nsname) { 
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Create Collection");
        printClientInfo(builder, client);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logCreateDatabase(ClientBasic* client,
                           const StringData& nsname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Create Database");
        printClientInfo(builder, client);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logDropIndex(ClientBasic* client,
                      const StringData& indexname,
                      const StringData& nsname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Create Database");
        printClientInfo(builder, client);
        builder.append("index", indexname);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logDropCollection(ClientBasic* client,
                           const StringData& nsname) { 
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Drop Collection");
        printClientInfo(builder, client);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logDropDatabase(ClientBasic* client,
                         const StringData& nsname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Drop Database");
        printClientInfo(builder, client);
        builder.append(NAMESPACE, nsname);
        logger->append(builder.obj());
    }

    void logRenameCollection(ClientBasic* client,
                             const StringData& source,
                             const StringData& target) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Rename Collection");
        printClientInfo(builder, client);
        builder.append("source", source);
        builder.append("target", target);
        logger->append(builder.obj());
    }

    void logEnableSharding(ClientBasic* client,
                           const StringData& nsname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Enable Sharding");
        builder.append(NAMESPACE, nsname); 
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

    void logAddShard(ClientBasic* client,
                     const StringData& name,
                     const std::string& servers,
                     long long maxsize) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Add Shard");
        builder.append("name", name);
        builder.append("servers", servers);
        builder.append("max_size", maxsize);
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

    void logRemoveShard(ClientBasic* client,
                        const StringData& shardname) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Remove Shard");
        builder.append("shard_name", shardname);
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

    void logShardCollection(ClientBasic* client,
                            const StringData& ns,
                            const BSONObj& keyPattern,
                            bool unique) {
        BSONObjBuilder builder;
        builder.append(AUDIT_TYPE, "Shard Collection");
        builder.append(NAMESPACE, ns);
        builder.append("key_pattern", keyPattern);
        printClientInfo(builder, client);
        logger->append(builder.obj());
    }

}  // namespace audit
}  // namespace mongo

