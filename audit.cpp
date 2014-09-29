/**
 *    Copyright (C) 2014 Tokutek Inc.
 */

#include "mongo/pch.h"

#include <cstdio>
#include <iostream>
#include <string>

#include <boost/filesystem/path.hpp>

#include "mongo/base/init.h"
#include "mongo/bson/bson_field.h"
#include "mongo/db/audit.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/client_basic.h"
#include "mongo/db/commands.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/matcher.h"
#include "mongo/db/namespacestring.h"
#include "mongo/util/concurrency/mutex.h"
#include "mongo/util/exit_code.h"
#include "mongo/util/file.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/sock.h"
#include "mongo/util/paths.h"
#include "mongo/util/time_support.h"

namespace mongo {

namespace audit {

    static struct AuditOptions {
        // Output format, 'eg JSON'
        std::string format;

        // Destination path, eg '/data/db/audit.json'
        std::string path;

        // Destination style, eg 'file'
        std::string destination;

        // Filter query for audit events.
        // eg "{ atype: { $in: [ 'authenticate', 'dropDatabase' ] } }"
        std::string filter;

        AuditOptions() :
            format("JSON"),
            path(""),
            destination("file"),
            filter("{}") {
        }

        BSONObj toBSON() {
            return BSON("format" << format <<
                        "path" << path <<
                        "destination" << destination <<
                        "filter" << filter);
        }

        Status initializeFromCommandLine() {
            if (cmdLine.auditFormat != "") {
                if (cmdLine.auditFormat != "JSON") {
                    return Status(ErrorCodes::BadValue,
                                  "The only audit format currently supported is `JSON'");
                }
                format = cmdLine.auditFormat;
            }

            if (cmdLine.auditPath != "") {
                File auditFile;
                auditFile.open(cmdLine.auditPath.c_str(), false, false);
                if (auditFile.bad()) {
                    return Status(ErrorCodes::BadValue,
                                  "Could not open a file for writing at the given auditPath: "
                                  + cmdLine.auditPath);
                }
                path = cmdLine.auditPath;
            } else if (!cmdLine.logWithSyslog && !cmdLine.logpath.empty()) {
                path = (boost::filesystem::path(cmdLine.logpath).parent_path() / "auditLog.json").native();
            } else if (!dbpath.empty()) {
                path = (boost::filesystem::path(dbpath) / "auditLog.json").native();
            } else {
                path = (boost::filesystem::path(cmdLine.cwd) / "auditLog.json").native();
            }

            if (cmdLine.auditDestination != "") {
                if (cmdLine.auditDestination != "file") {
                    return Status(ErrorCodes::BadValue,
                                  "The only audit destination currently supported is `file'");
                }
                destination = cmdLine.auditDestination;
            }

            if (cmdLine.auditFilter != "") {
                try {
                    fromjson(cmdLine.auditFilter);
                } catch (const std::exception &ex) {
                    return Status(ErrorCodes::BadValue,
                                  "Could not parse audit filter into valid json: "
                                  + cmdLine.auditFilter);
                }
                filter = cmdLine.auditFilter;
            }

            return Status::OK();
        }
    } _auditOptions;

    NOINLINE_DECL void realexit( ExitCode rc ) {
#ifdef _COVERAGE
        // Need to make sure coverage data is properly flushed before exit.
        // It appears that ::_exit() does not do this.
        log() << "calling regular ::exit() so coverage data may flush..." << endl;
        ::exit( rc );
#else
        ::_exit( rc );
#endif
    }

    // Writable interface for audit events
    class WritableAuditLog : public AuditLog {
    public:
        virtual ~WritableAuditLog() {}
        virtual void append(const BSONObj &obj) = 0;
        virtual void rotate() = 0;
    };

    // Writes audit events to a json file
    class JSONAuditLog : public WritableAuditLog {
        bool ioErrorShouldRetry(int errcode) {
            return (errcode == EAGAIN ||
                    errcode == EWOULDBLOCK ||
                    errcode == EINTR);
        }

    public:
        JSONAuditLog(const std::string &file, const BSONObj &filter)
            : _file(new File), 
              _matcher(filter.getOwned()), 
              _fileName(file),
              _mutex("auditFileMutex") {
            _file->open(file.c_str(), false, false);
        }

        virtual void append(const BSONObj &obj) {
            if (_matcher.matches(obj)) {
                const std::string str = mongoutils::str::stream() << obj.str() << "\n";

                // mongo::File does not have an "atomic append" operation.
                // As such, with a rwlock we are vulnerable to a race
                // where we get the length of the file, then try to pwrite
                // at that offset.  If another write beats us to pwrite,
                // we'll overwrite that audit data when our write goes
                // through.
                //
                // Somewhere, we need a mutex around grabbing the file
                // offset and trying to write to it (even if this were in
                // the kernel, the synchronization is still there).  This
                // is a good enough place as any.
                //
                // Note that we don't need the mutex around fsync.
                {
                    SimpleMutex::scoped_lock lck(_mutex);

                    // If pwrite performs a partial write, we don't want to
                    // muck about figuring out how much it did write (hard to
                    // get out of the File abstraction) and then carefully
                    // writing the rest.  Easier to calculate the position
                    // first, then repeatedly write to that position if we
                    // have to retry.
                    fileofs pos = _file->len();

                    int writeRet;
                    for (int retries = 10; retries > 0; --retries) {
                        writeRet = _file->writeReturningError(pos, str.c_str(), str.size());
                        if (writeRet == 0) {
                            break;
                        } else if (!ioErrorShouldRetry(writeRet)) {
                            error() << "Audit system cannot write event " << obj.str() << " to log file " << _fileName << std::endl;
                            error() << "Write failed with fatal error " << errnoWithDescription(writeRet) << std::endl;
                            error() << "As audit cannot make progress, the server will now shut down." << std::endl;
                            realexit(EXIT_AUDIT_ERROR);
                        }
                        warning() << "Audit system cannot write event " << obj.str() << " to log file " << _fileName << std::endl;
                        warning() << "Write failed with retryable error " << errnoWithDescription(writeRet) << std::endl;
                        warning() << "Audit system will retry this write another " << retries - 1 << " times." << std::endl;
                        if (retries <= 7 && retries > 0) {
                            sleepmillis(1 << ((7 - retries) * 2));
                        }
                    }

                    if (writeRet != 0) {
                        error() << "Audit system cannot write event " << obj.str() << " to log file " << _fileName << std::endl;
                        error() << "Write failed with fatal error " << errnoWithDescription(writeRet) << std::endl;
                        error() << "As audit cannot make progress, the server will now shut down." << std::endl;
                        realexit(EXIT_AUDIT_ERROR);
                    }
                }

                int fsyncRet;
                for (int retries = 10; retries > 0; --retries) {
                    fsyncRet = _file->fsyncReturningError();
                    if (fsyncRet == 0) {
                        break;
                    } else if (!ioErrorShouldRetry(fsyncRet)) {
                        error() << "Audit system cannot fsync event " << obj.str() << " to log file " << _fileName << std::endl;
                        error() << "Fsync failed with fatal error " << errnoWithDescription(fsyncRet) << std::endl;
                        error() << "As audit cannot make progress, the server will now shut down." << std::endl;
                        realexit(EXIT_AUDIT_ERROR);
                    }
                    warning() << "Audit system cannot fsync event " << obj.str() << " to log file " << _fileName << std::endl;
                    warning() << "Fsync failed with retryable error " << errnoWithDescription(fsyncRet) << std::endl;
                    warning() << "Audit system will retry this fsync another " << retries - 1 << " times." << std::endl;
                    if (retries <= 7 && retries > 0) {
                        sleepmillis(1 << ((7 - retries) * 2));
                    }
                }

                if (fsyncRet != 0) {
                    error() << "Audit system cannot fsync event " << obj.str() << " to log file " << _fileName << std::endl;
                    error() << "Fsync failed with fatal error " << errnoWithDescription(fsyncRet) << std::endl;
                    error() << "As audit cannot make progress, the server will now shut down." << std::endl;
                    realexit(EXIT_AUDIT_ERROR);
                }
            }
        }

        virtual void rotate() {
            SimpleMutex::scoped_lock lck(_mutex);

            // Close the current file.
            _file.reset();

            // Rename the current file
            // Note: we append a timestamp to the file name.
            stringstream ss;
            ss << _fileName << "." << terseCurrentTime(false);
            std::string s = ss.str();
            int r = std::rename(_fileName.c_str(), s.c_str());
            if (r != 0) {
                error() << "Could not rotate audit log, but continuing normally "
                        << "(error desc: " << errnoWithDescription() << ")"
                        << endl;
            }

            // Open a new file, with the same name as the original.
            _file.reset(new File);
            _file->open(_fileName.c_str(), false, false);
        }

    private:
        scoped_ptr<File> _file;
        const Matcher _matcher;
        const std::string _fileName;
        SimpleMutex _mutex;
    };

    // A void audit log does not actually write any audit events. Instead, it
    // verifies that we can call toString() on the generatd bson obj and that
    // the result is non-empty. This is useful for sanity testing the audit bson
    // generation code even when auditing is not explicitly enabled in debug builds.
    class VoidAuditLog : public WritableAuditLog {
    public:
        void append(const BSONObj &obj) {
            verify(!obj.str().empty());
        }

        void rotate() { }
    };

    static shared_ptr<WritableAuditLog> _auditLog;

    static void _setGlobalAuditLog(WritableAuditLog *log) {
        _auditLog.reset(log);

        // Sets the audit log in the general logging framework which
        // will rotate() the audit log when the server log rotates.
        setAuditLog(log);
    }

    static bool _auditEnabledOnCommandLine() {
        return cmdLine.auditDestination != "";
    }
    
    Status initialize() {
        if (!_auditEnabledOnCommandLine()) {
            // Write audit events into the void for debug builds, so we get
            // coverage on the code that generates audit log objects.
            DEV {
                log() << "Initializing dev null audit..." << endl;
                _setGlobalAuditLog(new VoidAuditLog());
            }
            return Status::OK();
        }

        log() << "Initializing audit..." << endl;
        Status s = _auditOptions.initializeFromCommandLine();
        if (!s.isOK()) {
            return s;
        }

        const BSONObj filter = fromjson(_auditOptions.filter);            
        _setGlobalAuditLog(new JSONAuditLog(_auditOptions.path, filter));
        return Status::OK();
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
        builder << AuditFields::timestamp(BSON("$date" << static_cast<long long>(jsTime().millis)));
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
                BSONObjBuilder user(users.subobjStart());
                user.append("user", it->getUser());
                user.append("db", it->getDB());
                user.doneFast();
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
        _auditLog->append(builder.done());
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
        if (!_auditLog) {
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
        if (!_auditLog) {
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
        if (!_auditLog) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "delete", BSON("pattern" << pattern), result);
        } else if (ns.coll == "system.users") {
            _auditEvent(client, "dropUser", BSON("db" << ns.db << "pattern" << pattern));
        }
    }

    void logGetMoreAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        if (!_auditLog) {
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
        if (!_auditLog) {
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
        if (!_auditLog) {
            return;
        }

        if (result != ErrorCodes::OK) {
            _auditAuthzFailure(client, nssToString(ns), "insert", BSON("obj" << insertedObj), result);
        } else if (ns.coll == "system.users") {
            _auditEvent(client, "createUser", BSON("db" << ns.db << "userObj" << insertedObj));
        }
    }

    void logKillCursorsAuthzCheck(
            ClientBasic* client,
            const NamespaceString& ns,
            long long cursorId,
            ErrorCodes::Error result) {
        if (!_auditLog) {
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
        if (!_auditLog) {
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
        if (!_auditLog) {
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
        if (!_auditLog) {
            return;
        }

        if (result != ErrorCodes::OK) {
            const BSONObj args = BSON("pattern" << query <<
                                      "updateObj" << updateObj <<
                                      "upsert" << isUpsert <<
                                      "multi" << isMulti); 
            _auditAuthzFailure(client, nssToString(ns), "update", args, result);
        } else if (ns.coll == "system.users") {
            const BSONObj params = BSON("db" << ns.db <<
                                        "pattern" << query <<
                                        "updateObj" << updateObj <<
                                        "upsert" << isUpsert <<
                                        "multi" << isMulti); 
            _auditEvent(client, "updateUser", params);
        }
    }

    void logReplSetReconfig(ClientBasic* client,
                            const BSONObj* oldConfig,
                            const BSONObj* newConfig) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("old" << *oldConfig << "new" << *newConfig);
        _auditEvent(client, "replSetReconfig", params);
    }

    void logApplicationMessage(ClientBasic* client,
                               const StringData& msg) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("msg" << msg);
        _auditEvent(client, "applicationMessage", params);
    }

    void logShutdown(ClientBasic* client) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSONObj();
        _auditEvent(client, "shutdown", params);
    }

    void logCreateIndex(ClientBasic* client,
                        const BSONObj* indexSpec,
                        const StringData& indexname,
                        const StringData& nsname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname <<
                                    "indexName" << indexname <<
                                    "indexSpec" << *indexSpec);
        _auditEvent(client, "createIndex", params);
    }

    void logCreateCollection(ClientBasic* client,
                             const StringData& nsname) { 
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "createCollection", params);
    }

    void logCreateDatabase(ClientBasic* client,
                           const StringData& nsname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "createDatabase", params);
    }

    void logDropIndex(ClientBasic* client,
                      const StringData& indexname,
                      const StringData& nsname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname << "indexName" << indexname);
        _auditEvent(client, "dropIndex", params);
    }

    void logDropCollection(ClientBasic* client,
                           const StringData& nsname) { 
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "dropCollection", params);
    }

    void logDropDatabase(ClientBasic* client,
                         const StringData& nsname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "dropDatabase", params);
    }

    void logRenameCollection(ClientBasic* client,
                             const StringData& source,
                             const StringData& target) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("old" << source << "new" << target);
        _auditEvent(client, "renameCollection", params);
    }

    void logEnableSharding(ClientBasic* client,
                           const StringData& nsname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << nsname);
        _auditEvent(client, "enableSharding", params);
    }

    void logAddShard(ClientBasic* client,
                     const StringData& name,
                     const std::string& servers,
                     long long maxsize) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params= BSON("shard" << name <<
                                   "connectionString" << servers <<
                                   "maxSize" << maxsize);
        _auditEvent(client, "addShard", params);
    }

    void logRemoveShard(ClientBasic* client,
                        const StringData& shardname) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("shard" << shardname);
        _auditEvent(client, "removeShard", params);
    }

    void logShardCollection(ClientBasic* client,
                            const StringData& ns,
                            const BSONObj& keyPattern,
                            bool unique) {
        if (!_auditLog) {
            return;
        }

        const BSONObj params = BSON("ns" << ns <<
                                    "key" << keyPattern <<
                                    "options" << BSON("unique" << unique));
        _auditEvent(client, "shardCollection", params);
    }

}  // namespace audit

    // -------------------------------------------------------------------------

    class LogApplicationMessageCommand : public QueryCommand {
    public:
        LogApplicationMessageCommand() : QueryCommand("logApplicationMessage") { }
        virtual ~LogApplicationMessageCommand() { }
        virtual void help( stringstream &help ) const {
            help << 
                "Log a custom application message string to the audit log. Must be a string." << 
                "Example: { logApplicationMessage: \"it's a trap!\" }";
        }
        virtual void addRequiredPrivileges(const std::string& dbname,
                                           const BSONObj& cmdObj,
                                           std::vector<Privilege>* out) {
            ActionSet actions;
            actions.addAction(ActionType::logApplicationMessage);
            out->push_back(Privilege(AuthorizationManager::SERVER_RESOURCE_NAME, actions));
        }
        bool run(const string& dbname, BSONObj& jsobj, int, string& errmsg, BSONObjBuilder& result, bool fromRepl) {
            bool ok = true;
            const BSONElement &e = jsobj["logApplicationMessage"];

            if (e.type() == String) {
                audit::logApplicationMessage(ClientBasic::getCurrent(), e.Stringdata());
            } else {
                errmsg = "logApplicationMessage only accepts string messages";
                ok = false;
            }
            result.append("ok", ok);
            return ok;
        }
    } cmdLogApplicationMessage;

    class AuditGetOptionsCommand : public QueryCommand {
    public:
        AuditGetOptionsCommand() : QueryCommand("auditGetOptions") { }
        virtual ~AuditGetOptionsCommand() { }
        virtual void help( stringstream &help ) const {
            help << 
                "Get the options the audit system is currently using"
                "Example: { auditGetOptions: 1 }";
        }
        virtual void addRequiredPrivileges(const std::string& dbname,
                                           const BSONObj& cmdObj,
                                           std::vector<Privilege>* out) { }
        bool run(const string& dbname, BSONObj& jsobj, int, string& errmsg, BSONObjBuilder& result, bool fromRepl) {
            result.appendElements(audit::_auditOptions.toBSON());
            return true;
        }
    };

    // so tests can determine where the audit log lives
    MONGO_INITIALIZER(RegisterAuditGetOptionsCommand)(InitializerContext* context) {
        if (Command::testCommandsEnabled) {
            // Leaked intentionally: a Command registers itself when constructed.
            new AuditGetOptionsCommand();
        }
        return Status::OK();
    }

}  // namespace mongo
