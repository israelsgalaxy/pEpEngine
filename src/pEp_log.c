/**
 * @file    pEp_log.c
 * @brief   pEp logging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#if 0 // I am disabling this thing that is getting too distracting
// #warning not suported by the windows compiler.  FIXME: re-introduce if possible inside another CPP conditional.
// #warning "windows: reimplement syslog using this: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openeventloga"
// #warning "android: ask the pEp security people"
#endif

#define _EXPORT_PEP_ENGINE_DLL
#include "pEp_log.h"

#include "pEp_internal.h"
#include "sql_reliability.h"
#include "engine_sql.h"
#include "timestamp.h"

#include <stdio.h>
#include <assert.h>
#include <inttypes.h> /* For PRId64 */
#include <string.h>


/* Using transactions is not terribly important for semantics in this case, but
   here it makes performance better when the oldest row is being deleted, as one
   can show by undefining this:
   On positron's machine (log 1000 entries,
                          PEP_LOG_DATABASE_ROW_NO_MAXIMUM set to 4000):
     real 34.90   no transactions
     real 18.24   transactions  */
#define TRANSACTIONS

#if defined (PEP_HAVE_SYSLOG)
#   include <syslog.h>
#endif

#if defined (PEP_HAVE_ANDROID_LOG)
#   include <android/log.h>
#endif

#if defined (PEP_HAVE_WINDOWS_LOG)
#   include <debugapi.h>
#endif


/* GNU/BSD formatted output emulation
 * ***************************************************************** */

static int pEp_vasprintf(char **string_pointer, const char *template,
                         va_list args)
{
    /* Sanity check. */
    assert(string_pointer != NULL);

    /* As an extension out of defensiveness we can also accept a NULL
       template. */
    if (template == NULL)
        template = "(null)";

    /* This is not performance-critical and we can afford doing the job twice,
       instead of first tentatively allocating a string that might or might not
       be big enough.
       So the idea is:
       1. first call vsnprintf giving a limit of 0 chars to be written, just to
          have its result value which is the required string size (minus one
          character for the trailing '\0');
       2. allocate a string with the right size;
       3. call vsnprintf once more, filling the string. */

    /* Since the va_list pointer (but not the pointed argument) is destroyed by
       each use (See the GNU C Library manual, §{"Variable Arguments Output
       Functions"}) I need a second copy of the pointer. */
    va_list args_copy;
    va_copy(args_copy, args);

    /* 1. Compute how many chars I need. */
    int needed_char_no = (vsnprintf(NULL, 0, template, args)
                          + /* for the trailing '\0' */ 1);
    va_end(args);

    /* 2. Allocate the string. */
    * string_pointer = malloc(needed_char_no);
    if (* string_pointer == NULL) {
        va_end(args_copy);
        return -1;
    }

    /* 3. Do the actual printing.  The string is now guaranteed to have
       sufficient size.  If I arrived at this point failure is no longer
       possible. */
    int res = vsnprintf(* string_pointer, needed_char_no, template, args_copy);
    va_end(args_copy);
    return res;
}

int pEp_asprintf(char **string_pointer, const char *template, ...)
{
    /* This is a simple wrapper around pEp_vasprintf, which does the actual
       work. */
    va_list ap;
    va_start(ap, template);
    int res = pEp_vasprintf(string_pointer, template, ap);
    va_end(ap);
    return res;
}


/* Logging facility: internal functionality
 * ***************************************************************** */

/* Given a log level return its printed representation */
static const char* _log_level_to_string(PEP_LOG_LEVEL level)
{
    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:    return "CRT";
    case PEP_LOG_LEVEL_ERROR:       return "ERR";
    case PEP_LOG_LEVEL_WARNING:     return "wng";
    case PEP_LOG_LEVEL_EVENT:       return "evt";
    case PEP_LOG_LEVEL_API:         return "api";
    case PEP_LOG_LEVEL_NONOK:       return "nok";
    case PEP_LOG_LEVEL_FUNCTION:    return "fnc";
    case PEP_LOG_LEVEL_TRACE:       return "trc";
    case PEP_LOG_LEVEL_EVERYTHING:  return "[everything log level (not for entries)]";
    default:                        return "invalid log level";
    }
}

/* The template string and arguments used by every destination relying on a
   printf-like API.  This expands to a string literal with no trailing newline
   character and no parentheses around. */
#define PEP_LOG_PRINTF_FORMAT                                 \
    "%04i-%02i-%02i %02i:%02i:%02i" /* date, time */          \
    "%s" PEP_LOG_PRINTF_FORMAT_NO_DATE

/* The variadic arguments to be passed after the template PEP_LOG_PRINTF_FORMAT
   .  This expands to a sequence of expressions separated by commas.  Notice
   newline separators here, that match line separators in PEP_LOG_PRINTF_FORMAT
   . */
#define PEP_LOG_PRINTF_ACTUALS                                    \
    time->tm_year + 1900, time->tm_mon + 1, time->tm_mday,        \
    time->tm_hour, time->tm_min, time->tm_sec,                    \
    system_subsystem_prefix, PEP_LOG_PRINTF_ACTUALS_NO_DATE


/* Like PEP_LOG_PRINTF_FORMAT and PEP_LOG_PRINTF_ACTUALS, but with
   different fields. */
#define PEP_LOG_PRINTF_FORMAT_NO_DATE                         \
    "%s%s%s"                        /* system, subsystem */   \
    " %" PRId64 "/%" PRId64         /* pid, tid */            \
    " %s"                           /* log level */           \
    " %s:%i%s%s"                    /* source location */     \
    "%s%s"                          /* entry */
#define PEP_LOG_PRINTF_ACTUALS_NO_DATE                            \
    system, system_subsystem_separator,  \
        subsystem,                                                \
    pid_and_tid.pid, pid_and_tid.tid,                             \
    _log_level_to_string(level),                                  \
    source_file_name, source_file_line, function_prefix,          \
        function_name,                                            \
    entry_prefix, entry


/* Logging facility: database destination.
 * ***************************************************************** */

/* In this module we do not use PEP_SQL_BEGIN_LOOP and PEP_SQL_END_LOOP as
   defined elsewhere, in order to avoid database writes as side effects of
   failed database writes.
   Define a simplified version here. */
#undef PEP_SQL_BEGIN_LOOP
#undef PEP_SQL_END_LOOP
#define PEP_SQL_BEGIN_LOOP  \
    do {
#define PEP_SQL_END_LOOP                    \
        do {                                \
            WARN_ON_SQLITE_ERROR;           \
        } while (false);                    \
    } while (sqlite_status == SQLITE_BUSY)

/* This compilation unit is defensive to a degree that appears unreasonable;
   yet its defensiveness has allowed me to find subtle bugs with ease, time
   and time again. */
#define WARN_ON_SQLITE_ERROR                                                \
    do {                                                                    \
        if (session->service_log                                            \
            && sqlite_status != SQLITE_OK                                   \
            && sqlite_status != SQLITE_DONE) {                              \
            struct pEp_pid_and_tid _warning_pid_and_tid;                    \
            pEp_set_pid_and_tid(& _warning_pid_and_tid);                    \
            fprintf(stderr, "%li/%li %s:%i %s sql_error is %i (%s)\n",      \
                    (long) _warning_pid_and_tid.pid,                        \
                    (long) _warning_pid_and_tid.tid,                        \
                    __FILE__, __LINE__, __func__,                           \
                    (int) sqlite_status, sqlite3_errmsg(session->log_db));  \
            fflush(stderr);                                                 \
            PEP_ASSERT(sqlite_status != SQLITE_LOCKED);                     \
        }                                                                   \
    } while (false)

/* A safe wrapper around sqlite3_prepare_v2 , which retries on SQLITE_BUSY. */
static int _safe_sqlite3_prepare_v2(
  PEP_SESSION session,
  sqlite3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlite3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
) {
    int sqlite_status;
    int failure_no = 0;
    PEP_SQL_BEGIN_LOOP;
        sqlite_status = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail);
        assert(sqlite_status != SQLITE_LOCKED);
        if (sqlite_status == SQLITE_BUSY) {
            fprintf(stderr, "failed preparing the statement %s: trying again\n",
                    zSql);
            failure_no ++;
        }
        WARN_ON_SQLITE_ERROR;
    PEP_SQL_END_LOOP;
    assert(sqlite_status == SQLITE_OK);
    if (failure_no > 0)
        fprintf(stderr, "succeeded preparing the statement %s after %i failures\n",
                zSql, failure_no);
    return sqlite_status;
}

/* These SQL statements create the schema and set the required parameters.  They
   are only executed at initialisation and do not need prepared statements. */

/* This statement list is executed just once: if it succeeds from one thread at
   any time it is enough. */
static const char *pEp_log_initialize_database_once_text =
" BEGIN EXCLUSIVE TRANSACTION;\n"
" "
/* Changing the auto_vacuum state can only happen when either the database
   is new (with no tables) or at vacuum time.  Notice that the effect of
   this pragma is persistent, in the sense that it is stored into the database
   and loaded when a new connection is started at any later time.
   Once this statement succeeds, on any thread, it is enough: there is no need
   to retry it in a loop in case of SQLITE_BUSY. */
" PRAGMA auto_vacuum = INCREMENTAL;\n"
/* The page_size setting also takes effect at the next VACUUM, and there is no
   need to set it from every connection. */
" PRAGMA page_size = 4096;\n" /* This should be the same as the filesystem
                                 page size */
" "
" CREATE TABLE IF NOT EXISTS Entries ("
"   -- The id is a good approximation of a timestamp, much more efficient.\n"
"   id               INTEGER  PRIMARY KEY  AUTOINCREMENT,"
"   Level            INTEGER  NOT NULL,"
"   Timestamp        TEXT     NOT NULL     DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),"
"   Pid              INTEGER  NOT NULL,"
"   Tid              INTEGER  NOT NULL,"
"   System           TEXT,"
"   Subsystem        TEXT,"
"   Source_file_name TEXT     NOT NULL,"
"   Source_file_line INTEGER  NOT NULL,"
"   Function_name    TEXT     NOT NULL,"
"   Entry            TEXT"
" );"
" "
" -- This makes aggregate functions such as MIN fast.\n"
" CREATE UNIQUE INDEX IF NOT EXISTS idx_Entries_Id on Entries (id);"
" "
" COMMIT TRANSACTION;\n"
" "
" VACUUM;\n" /* I have verified with this statement *commented out* that the
                database file does not grow to an unbounded size. */
;

/* Notice that SQLite forbids setting PRAGMA synchronous inside a transaction. */
static const char *pEp_log_set_synchronous_text =
" PRAGMA synchronous = FULL;\n" /* This is forbidden inside a transaction. */
" VACUUM;\n"
;
static const char *pEp_log_set_asynchronous_text =
" PRAGMA synchronous = OFF;\n" /* This is forbidden inside a transaction. */
" VACUUM;\n"
;

static const char *pEp_log_upgrade_database_1_once_text =
" ALTER TABLE Entries ADD Column Tid              INTEGER  NOT NULL DEFAULT -1;\n"
;

static const char *pEp_log_create_view_once_text =
" BEGIN EXCLUSIVE TRANSACTION;\n"
" -- This is very convenient for interactive use.\n"
" DROP VIEW IF EXISTS UserEntries;"
" CREATE VIEW UserEntries AS"
"   SELECT E.id,"
"          CASE E.Level WHEN  10 THEN 'CRT'"
"                       WHEN  20 THEN 'ERR'"
"                       WHEN 100 THEN 'wng'"
"                       WHEN 200 THEN 'evt'"
"                       WHEN 210 THEN 'api'"
"                       WHEN 300 THEN 'nok'"
"                       WHEN 310 THEN 'fnc'"
"                       WHEN 320 THEN 'trc'"
"                                ELSE CAST(E.Level AS TEXT)"
"          END AS Lvl,"
"          E.Timestamp,"
"          (CAST(E.Pid AS TEXT) || '/' || CAST(E.Tid AS TEXT)) AS PidTid,"
"          CASE WHEN E.System is NULL THEN"
"            CASE WHEN E.SubSystem is NULL THEN  NULL"
"            ELSE                                '/' || E.SubSystem END"
"          ELSE"
"            CASE WHEN E.SubSystem is NULL THEN  E.System || '/'"
"            ELSE                                E.System || '/' || E.SubSystem END"
"          END AS System_SubSystem,"
"          (E.Source_file_name || ':' || CAST(E.Source_file_line AS TEXT)"
"           || ' ' || E.Function_name) AS Location,"
"          E.Entry"
"   FROM Entries E"
"   ORDER BY E.id;"
" COMMIT TRANSACTION;\n"
;

/* This statement list is executed from each new session. */
static const char *pEp_log_initialize_database_at_every_connection_text =
/* This setting is not persistent. */
" PRAGMA secure_delete = OFF;\n"
/* There is no need for PRAGMA foreign_keys on a single-table database with no
   foreign keys. */

" PRAGMA locking_mode=NORMAL;\n"
" PRAGMA journal_mode=WAL;\n"
;

/* Begin a transaction. */
static const char *pEp_log_begin_transaction_text =
"  BEGIN EXCLUSIVE TRANSACTION;";

/* Commit the current transaction. */
static const char *pEp_log_commit_transaction_text =
"  COMMIT TRANSACTION;";

/* Insert a new row. */
static const char *pEp_log_insert_text =
" INSERT INTO Entries"
"   (Level, Pid, Tid, System, Subsystem, Source_file_name, Source_file_line,"
"    Function_name, Entry)"
" VALUES"
"   (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);";

/* Delete the oldest row, if the total number of rows is large enough. */
static const char *pEp_log_delete_oldest_text =
" DELETE FROM Entries"
"                     -- MAX is a faster approximation of COUNT\n"
" WHERE id = (SELECT (CASE WHEN MAX(id) < ?1 THEN"
"                       -1"
"                     ELSE"
"                       MIN(id)"
"                     END)"
"             FROM Entries);";

/* Return the latest rows from the view. */
static const char *pEp_log_crashdump_text =
" SELECT REPLACE(U.Timestamp || ' ' || U.PidTid || ' ' || U.Lvl, '\"', '\"\"')"
"            AS title,"
"        REPLACE(U.System_SubSystem, '\"', '\"\"') AS Entity,"
"        REPLACE(U.Location, '\"', '\"\"') AS Description,"
"        REPLACE(U.Entry, '\"', '\"\"') As Comment"
/*" ,        U.Id"*/ /* for debugging*/
" FROM UserEntries U"
" ORDER BY U.id"
" DESC"
" LIMIT ?1;";


/* Pepare the SQL statements worth preparing. */
static PEP_STATUS _pEp_log_prepare_sql_statements(PEP_SESSION session)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_status = SQLITE_OK;

#define CHECK_SQL_STATUS                                                     \
    do {                                                                     \
        if (sqlite_status != SQLITE_OK) {                                    \
            fprintf(stderr, "preparing an SQL statement failed: %i (%s)\n",  \
                    sqlite_status, sqlite3_errmsg(session->log_db));         \
        }                                                                    \
        if (sqlite_status != SQLITE_OK) {                                    \
            WARN_ON_SQLITE_ERROR;                                            \
            status = PEP_INIT_CANNOT_OPEN_DB;                                \
            goto end;                                                        \
        }                                                                    \
    } while (false)
    sqlite_status
        = _safe_sqlite3_prepare_v2(session, session->log_db,
                                   pEp_log_begin_transaction_text, -1,
                                   & session->log_begin_transaction_prepared_statement,
                                   NULL);
    CHECK_SQL_STATUS;
    sqlite_status
        = _safe_sqlite3_prepare_v2(session, session->log_db,
                                   pEp_log_commit_transaction_text, -1,
                                   & session->log_commit_transaction_prepared_statement,
                                   NULL);
    CHECK_SQL_STATUS;
    sqlite_status
        = _safe_sqlite3_prepare_v2(session, session->log_db,
                                   pEp_log_delete_oldest_text, -1,
                                   & session->log_delete_oldest_prepared_statement,
                                   NULL);
    CHECK_SQL_STATUS;
    sqlite_status
        = _safe_sqlite3_prepare_v2(session, session->log_db,
                                   pEp_log_insert_text, -1,
                                   & session->log_insert_prepared_statement,
                                   NULL);
    CHECK_SQL_STATUS;
    sqlite_status
        = _safe_sqlite3_prepare_v2(session, session->log_db,
                                   pEp_log_crashdump_text, -1,
                                   & session->log_crashdump_prepared_statement,
                                   NULL);
    CHECK_SQL_STATUS;

 end:
    return status;
}

/* This code relies on the same restriction on concurrency as init: init calls
   are *not* concurrent and the first must complete with success before any
   other is initiated.

   Since the initialisation functions here are only called by init we can rely
   on the same restrictions for free, without affecting the user. */

PEP_STATUS pEp_log_set_synchronous_database(PEP_SESSION session,
                                            bool synchronous)
{
    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_status = SQLITE_OK;

    const char *sql_statement_text
        = (synchronous
           ? pEp_log_set_synchronous_text
           : pEp_log_set_asynchronous_text);
    PEP_SQL_BEGIN_LOOP;
        sqlite_status = sqlite3_exec(session->log_db,
                                     sql_statement_text,
                                     NULL, NULL, NULL);
    PEP_SQL_END_LOOP;

    assert(sqlite_status != SQLITE_LOCKED);
    if (sqlite_status != SQLITE_OK) {
        status = PEP_INIT_CANNOT_OPEN_DB;
        fprintf(stderr, "failed initialising the log database: %i (%s)\n",
                sqlite_status, sqlite3_errmsg(session->log_db));
    }
    return status;
}


/* Initialise the database subsystem.  Called once at session initialisation. */
static PEP_STATUS _pEp_log_initialize_database(PEP_SESSION session)
{
    assert(session != NULL && session->log_db == NULL);
    if (! (session != NULL && session->log_db == NULL))
        return PEP_ILLEGAL_VALUE;
    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_status = SQLITE_OK;

    /* Open (creating it as needed) the log database. */
    const char *database_file_path = LOG_DB;
    if (database_file_path == NULL) {
        status = PEP_INIT_CANNOT_OPEN_DB;
        goto end;
    }
    sqlite_status = sqlite3_open_v2(database_file_path, & session->log_db,
                                    SQLITE_OPEN_READWRITE
                                    | SQLITE_OPEN_FULLMUTEX
                                    | (session->first_session_at_init_time
                                       ? SQLITE_OPEN_CREATE
                                       : 0),
                                    NULL);
    if (sqlite_status != SQLITE_OK) {
        sqlite3_close(session->log_db);
        session->log_db = NULL;
        status = PEP_INIT_CANNOT_OPEN_DB;
        goto end;
    }

    /* Create the schema and change its persistent settings.
       This must be done only once, in the initial thread; performing the kind
       of schema and pragma modification we execute here seems to affect
       prepared statements badly in other threads, sometimes causing SQLITE_BUSY
       -- let us avoid all of that. */
    if (session->first_session_at_init_time) {
        sqlite_status = sqlite3_exec(session->log_db,
                                     pEp_log_initialize_database_once_text,
                                     NULL, NULL, NULL);
        if (sqlite_status != SQLITE_OK) {
            status = PEP_INIT_CANNOT_OPEN_DB;
            goto end;
        }

        /* Execute upgrade commands that only need to run once.  These are used
           for adding columns which did not exist in older versions.  It is
           difficult to handle every possible error correctly here, and there
           is not ADD COLUMM IF NOT EXISTS. */
        sqlite_status = sqlite3_exec(session->log_db,
                                     pEp_log_upgrade_database_1_once_text,
                                     NULL, NULL, NULL);
        /* This line will be convenient for debugging.  Notice that
           "duplicate column name: Tid" is expected here. */
        assert(sqlite_status != SQLITE_LOCKED);
        if (sqlite_status == SQLITE_BUSY) {
            status = PEP_INIT_CANNOT_OPEN_DB;
            goto end;
        }

        /* (Drop any old version of it and) create the view. */
        sqlite_status = sqlite3_exec(session->log_db,
                                     pEp_log_create_view_once_text,
                                     NULL, NULL, NULL);
        if (sqlite_status != SQLITE_OK) {
            status = PEP_INIT_CANNOT_OPEN_DB;
            goto end;
        }
    }

    /* Execute the SQL statements needed for every session, not only for the
       first. */
    PEP_SQL_BEGIN_LOOP;
        sqlite_status
            = sqlite3_exec(session->log_db,
                           pEp_log_initialize_database_at_every_connection_text,
                           NULL, NULL, NULL);
    PEP_SQL_END_LOOP;

    /* Prepare SQL statements. */
    status = _pEp_log_prepare_sql_statements(session);

    /* Set synchronous versus asynchronoys log according to the session
       state. */
    pEp_log_set_synchronous_database(session, session->enable_log_synchronous);

 end:
    /* If this succeeded from from now on we can actually log to the database;
       actually adding log entries is conditionalised on this field in order to
       allow for very early logging, at initialisation time -- to different
       destinations. */
    if (status == PEP_STATUS_OK)
        session->log_database_initialised = true;
    else
        fprintf(stderr, "failed initialising the log database: "
                "sqlite_status %i (%s)\n",
                sqlite_status, sqlite3_errmsg(session->log_db));
    return status;
}

/* Finalise the database subsystem.  Called once at session release. */
static PEP_STATUS _pEp_log_finalize_database(PEP_SESSION session)
{
    assert(session != NULL && session->log_db != NULL);
    if (! (session != NULL && session->log_db != NULL))
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_status = SQLITE_OK;
#define CHECK_SQL                                                        \
    do {                                                                 \
        WARN_ON_SQLITE_ERROR;                                            \
        if (sqlite_status != SQLITE_OK) {                                \
            status = PEP_UNKNOWN_DB_ERROR;                               \
            /* Do not jump.  Recovery from error is difficult here, and  \
               this should not happen anyway. */                         \
        }                                                                \
    } while (false)

    /* Finialise prepared SQL statements.  Go on even in case of failure. */
    sqlite_status
        = sqlite3_finalize(session->log_begin_transaction_prepared_statement);
    CHECK_SQL;
    sqlite_status
        = sqlite3_finalize(session->log_commit_transaction_prepared_statement);
    CHECK_SQL;
    sqlite_status
        = sqlite3_finalize(session->log_delete_oldest_prepared_statement);
    CHECK_SQL;
    sqlite_status
        = sqlite3_finalize(session->log_insert_prepared_statement);
    CHECK_SQL;
    sqlite_status
        = sqlite3_finalize(session->log_crashdump_prepared_statement);
    CHECK_SQL;

    /* Close the database. */
    sqlite_status = sqlite3_close(session->log_db);
    if (sqlite_status != SQLITE_OK)
        status = PEP_UNKNOWN_DB_ERROR;
    /* Out of defensiveness. */
    session->log_db = NULL;

    return status;
#undef CHECK_SQL
}

/* Delete the oldest row, if more than PEP_LOG_DATABASE_ROW_NO_MAXIMUM rows seem
   to be there already.  Do nothing otherwise. */
static void _pEp_log_delete_oldest_row_when_too_many(PEP_SESSION session)
{
    int sqlite_status = SQLITE_OK;

    sql_reset_and_clear_bindings(session->log_delete_oldest_prepared_statement);
    sqlite_status
        = sqlite3_bind_int64(session->log_delete_oldest_prepared_statement,
                             1, PEP_LOG_DATABASE_ROW_NO_MAXIMUM);
    if (sqlite_status != SQLITE_OK)
        return;
    PEP_SQL_BEGIN_LOOP;
        sqlite_status
            = sqlite3_step(session->log_delete_oldest_prepared_statement);
    PEP_SQL_END_LOOP;
    sqlite3_reset(session->log_delete_oldest_prepared_statement);

    /* Here sqlite_status will be SQLITE_DONE on success, including the case in
       which no row is deleted. */
}

/* The implementation of pEp_log for the database destination. */
static PEP_STATUS _pEp_log_db(PEP_SESSION session,
                              PEP_LOG_LEVEL level,
                              const timestamp *time,
                              const struct pEp_pid_and_tid pid_and_tid,
                              const char *system_subsystem_prefix,
                              const char *system,
                              const char *system_subsystem_separator,
                              const char *subsystem,
                              const char *source_file_name,
                              int source_file_line,
                              const char *function_prefix,
                              const char *function_name,
                              const char *entry_prefix,
                              const char *entry)
{
    /* We cannot use PEP_REQUIRE here without risking an infinite loop. */
    assert(session != NULL && PEP_IMPLIES(session->log_database_initialised,
                                          session->log_db != NULL));
    if (! (session != NULL && PEP_IMPLIES(session->log_database_initialised,
                                          session->log_db != NULL)))
        return PEP_ILLEGAL_VALUE;

    /* Do not try to log to the database  if we have not initialised the
       database yet.  This may happen for logging messages related to the
       database initialisation itself. */
    if (! session->log_database_initialised)
        return PEP_UNKNOWN_DB_ERROR;

    PEP_STATUS status = PEP_STATUS_OK;
    int sqlite_status = SQLITE_OK;
#define CHECK_SQL(expected_sqlite_status)                 \
    do                                                    \
        if (sqlite_status != (expected_sqlite_status)) {  \
            WARN_ON_SQLITE_ERROR;                         \
            status = PEP_UNKNOWN_DB_ERROR;                \
            goto error;                                   \
        }                                                 \
    while (false)

#ifdef TRANSACTIONS
    sql_reset_and_clear_bindings(session->log_begin_transaction_prepared_statement);
    PEP_SQL_BEGIN_LOOP;
        sqlite_status = sqlite3_step(session->log_begin_transaction_prepared_statement);
    PEP_SQL_END_LOOP;
    sqlite3_reset(session->log_begin_transaction_prepared_statement);
    CHECK_SQL(SQLITE_DONE);
#endif // #ifdef TRANSACTIONS

    /* If the table has become too large delete the oldest row, before inserting
       the next one. */
    _pEp_log_delete_oldest_row_when_too_many(session);

    /* Bind parameters to the compiled statement. */
    sql_reset_and_clear_bindings(session->log_insert_prepared_statement);
    sqlite_status = sqlite3_bind_int(session->log_insert_prepared_statement,
                                     1, level);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_int64(session->log_insert_prepared_statement,
                                     2, pid_and_tid.pid);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_int64(session->log_insert_prepared_statement,
                                     3, pid_and_tid.tid);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_text(session->log_insert_prepared_statement,
                                      4, system, -1, SQLITE_STATIC);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_text(session->log_insert_prepared_statement,
                                      5, subsystem, -1, SQLITE_STATIC);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_text(session->log_insert_prepared_statement,
                                      6, source_file_name, -1, SQLITE_STATIC);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_int(session->log_insert_prepared_statement,
                                     7, source_file_line);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_text(session->log_insert_prepared_statement,
                                      8, function_name, -1, SQLITE_STATIC);
    CHECK_SQL(SQLITE_OK);
    sqlite_status = sqlite3_bind_text(session->log_insert_prepared_statement,
                                      9,
                                      (EMPTYSTR(entry) ? NULL : entry), -1,
                                      SQLITE_STATIC);
    CHECK_SQL(SQLITE_OK);

    PEP_SQL_BEGIN_LOOP;
        sqlite_status = sqlite3_step(session->log_insert_prepared_statement);
    PEP_SQL_END_LOOP;
    CHECK_SQL(SQLITE_DONE);
    sqlite3_reset(session->log_insert_prepared_statement);

#ifdef TRANSACTIONS
    sql_reset_and_clear_bindings(session->log_commit_transaction_prepared_statement);
    PEP_SQL_BEGIN_LOOP;
        sqlite_status = sqlite3_step(session->log_commit_transaction_prepared_statement);
    PEP_SQL_END_LOOP;
    CHECK_SQL(SQLITE_DONE);
    sqlite3_reset(session->log_commit_transaction_prepared_statement);
#endif // #ifdef TRANSACTIONS

 error:
    return status;
#undef CHECK_SQL
}


/* Logging facility: FILE* destinations
 * ***************************************************************** */

/* The implementation of pEp_log for FILE * destinations. */
static PEP_STATUS _pEp_log_file_star(FILE* file_star,
                                     PEP_SESSION session,
                                     PEP_LOG_LEVEL level,
                                     const timestamp *time,
                                     const struct pEp_pid_and_tid pid_and_tid,
                                     const char *system_subsystem_prefix,
                                     const char *system,
                                     const char *system_subsystem_separator,
                                     const char *subsystem,
                                     const char *source_file_name,
                                     int source_file_line,
                                     const char *function_prefix,
                                     const char *function_name,
                                     const char *entry_prefix,
                                     const char *entry)
{
    int fprintf_result = fprintf(file_star,
                                 PEP_LOG_PRINTF_FORMAT "\n",
                                 PEP_LOG_PRINTF_ACTUALS);
    fflush(file_star);
    if (fprintf_result < 0)
        return PEP_UNKNOWN_ERROR;
    else
        return PEP_STATUS_OK;
}


/* Logging facility: syslog destination
 * ***************************************************************** */

#if defined (PEP_HAVE_SYSLOG)
/* Given a pEp log level return its syslog equivalent, as the value to be
   passed as the first argument to the syslog function. */
static int _log_level_to_syslog_facility_priority(PEP_LOG_LEVEL level)
{
    int facility = LOG_USER;
#define RETURN_SYSLOG_PRIORITY(priority) \
    do { return LOG_MAKEPRI(facility, (priority)); } while (false)

    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:
        RETURN_SYSLOG_PRIORITY(LOG_CRIT);
    case PEP_LOG_LEVEL_ERROR:
        RETURN_SYSLOG_PRIORITY(LOG_ERR);
    case PEP_LOG_LEVEL_WARNING:
        RETURN_SYSLOG_PRIORITY(LOG_WARNING);
    case PEP_LOG_LEVEL_EVENT:
        RETURN_SYSLOG_PRIORITY(LOG_NOTICE);
    case PEP_LOG_LEVEL_API:
        RETURN_SYSLOG_PRIORITY(LOG_NOTICE);
    case PEP_LOG_LEVEL_FUNCTION:
        RETURN_SYSLOG_PRIORITY(LOG_INFO);
    case PEP_LOG_LEVEL_TRACE:
        RETURN_SYSLOG_PRIORITY(LOG_DEBUG);
    case PEP_LOG_LEVEL_EVERYTHING:
        /* This should not happen.  Let us make the log entry visible. */
        RETURN_SYSLOG_PRIORITY(LOG_DEBUG);
    default:
        /* Invalid.  Let us make the log entry visible. */
        RETURN_SYSLOG_PRIORITY(LOG_EMERG);
    }
#undef RETURN
}

/* The implementation of pEp_log for the syslog destination. */
static PEP_STATUS _pEp_log_syslog(PEP_SESSION session,
                                  PEP_LOG_LEVEL level,
                                  const timestamp *time,
                                  const struct pEp_pid_and_tid pid_and_tid,
                                  const char *system_subsystem_prefix,
                                  const char *system,
                                  const char *system_subsystem_separator,
                                  const char *subsystem,
                                  const char *source_file_name,
                                  int source_file_line,
                                  const char *function_prefix,
                                  const char *function_name,
                                  const char *entry_prefix,
                                  const char *entry)
{
    int facility_priority
        = _log_level_to_syslog_facility_priority(level);
    syslog(facility_priority, PEP_LOG_PRINTF_FORMAT_NO_DATE,
           PEP_LOG_PRINTF_ACTUALS_NO_DATE);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_SYSLOG) */


/* Logging facility: Android destination
 * ***************************************************************** */

#if defined (PEP_HAVE_ANDROID_LOG)
/* positron: this code is completely untested.  I read
     https://android.googlesource.com/platform/system/core/+/jb-dev/include/android/log.h
   and tried to do something reasonable, based on the (tested and working)
   syslog destination. */

/* Given a pEp log level return its enum android_LogPriority equivalent, as the
   value to be passed as the first argument to the __android_log_print
   function. */
static enum android_LogPriority _log_level_to_android_logpriority(
   PEP_LOG_LEVEL level)
{
    int facility = LOG_USER;
#define RETURN_ANDROID_LOGPRIORITY(priority)  \
    { return LOG_MAKEPRI(facility, (priority)); }

    switch (level) {
    case PEP_LOG_LEVEL_CRITICAL:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_FATAL);
    case PEP_LOG_LEVEL_ERROR:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_ERROR);
    case PEP_LOG_LEVEL_WARNING:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_WARN);
    case PEP_LOG_LEVEL_EVENT:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_INFO);
    case PEP_LOG_LEVEL_API:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_INFO);
    case PEP_LOG_LEVEL_FUNCTION:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_DEBUG);
    case PEP_LOG_LEVEL_TRACE:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_DEBUG);
    /* This should not happen. */
    case PEP_LOG_LEVEL_EVERYTHING:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_UNKNOWN);
    /* Invalid. */
    default:
        RETURN_ANDROID_LOGPRIORITY(ANDROID_LOG_UNKNOWN);
    }
#undef RETURN
}

/* The implementation of pEp_log for the android_log destination. */
static PEP_STATUS _pEp_log_android_log(PEP_SESSION session,
                                       PEP_LOG_LEVEL level,
                                       const timestamp *time,
                                       const struct pEp_pid_and_tid pid_and_tid,
                                       const char *system_subsystem_prefix,
                                       const char *system,
                                       const char *system_subsystem_separator,
                                       const char *subsystem,
                                       const char *source_file_name,
                                       int source_file_line,
                                       const char *function_prefix,
                                       const char *function_name,
                                       const char *entry_prefix,
                                       const char *entry)
{
    int prio = _log_level_to_android_logpriority(level);
    __android_log_print(prio, (system != NULL ? system : "pEp"),
                        PEP_LOG_PRINTF_FORMAT,
                        PEP_LOG_PRINTF_ACTUALS);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_ANDROID_LOG) */


/* Logging facility: windows destination
 * ***************************************************************** */

#if defined (PEP_HAVE_WINDOWS_LOG)
/* positron: this code is completely untested.  I read
     http://www.unixwiz.net/techtips/outputdebugstring.html
   and the previously existing code in
     platform_windows.cpp
   and tried to do something reasonable, based on the other tested and working
   destinations. */

/* The implementation of pEp_log for the windows_log destination. */
static PEP_STATUS _pEp_log_windows_log(PEP_SESSION session,
                                       PEP_LOG_LEVEL level,
                                       const timestamp *time,
                                       const struct pEp_pid_and_tid pid_and_tid,
                                       const char *system_subsystem_prefix,
                                       const char *system,
                                       const char *system_subsystem_separator,
                                       const char *subsystem,
                                       const char *source_file_name,
                                       int source_file_line,
                                       const char *function_prefix,
                                       const char *function_name,
                                       const char *entry_prefix,
                                       const char *entry)
{
    char *heap_string;
    int asprintf_result = pEp_asprintf(& heap_string,
                                       PEP_LOG_PRINTF_FORMAT,
                                       PEP_LOG_PRINTF_ACTUALS);
    if (heap_string == NULL || asprintf_result < 1) {
        free(heap_string);
        return PEP_OUT_OF_MEMORY;
    }

    OutputDebugString(heap_string);
    free(heap_string);
    return PEP_STATUS_OK;
}
#endif /* #if defined (PEP_HAVE_WINDOWS_LOG) */


/* Logging facility: log an entry (function API)
 * ***************************************************************** */

DYNAMIC_API PEP_STATUS pEp_log(PEP_SESSION session,
                               PEP_LOG_LEVEL level,
                               const char *system,
                               const char *subsystem,
                               const char *source_file_name,
                               int source_file_line,
                               const char *function_name,
                               const char *entry)
{
    /* Sanity checks. */
    assert(session);
    if (! session)
        return PEP_ILLEGAL_VALUE;

    /* Before doing anything, check that the log level does not exceed the
       verbosity limit; if it does just return without doing anything. */
    if (level > PEP_LOG_LEVEL_MAXIMUM)
        return PEP_STATUS_OK;

    /* If logging is disabled do nothing. */
    if (! session->enable_log)
        return PEP_STATUS_OK;

    /* Get the current time. */
    time_t now_in_seconds = time(NULL);
    timestamp* now = new_timestamp(now_in_seconds);
    if (now == NULL)
        return PEP_OUT_OF_MEMORY;

    /* Get the current pid and tid. */
    struct pEp_pid_and_tid pid_and_tid;
    pEp_set_pid_and_tid(& pid_and_tid);

    /* Normalise system/subsystem strings and compute cosmetic parameters. */
    const char *system_subsystem_prefix = " ";
    const char *system_subsystem_separator = "/";
    if (EMPTYSTR(system) && EMPTYSTR(subsystem))
        system_subsystem_prefix = "";
    if (EMPTYSTR(system)) {
        system = "";
        system_subsystem_separator = "";
    }
    if (EMPTYSTR(subsystem)) {
        subsystem = "";
        system_subsystem_separator = "";
    }

    /* Normalise location strings and compute cosmetic parameters. */
    if (EMPTYSTR(source_file_name))
        source_file_name = "UNKNOWN_FILE";
    const char *function_prefix = " ";
    if (EMPTYSTR(function_name)) {
        function_prefix = "";
        function_name = "";
    }

    /* Normalise entry and compute cosmetic parameters. */
    const char *entry_prefix = " ";
    if (EMPTYSTR(entry)) {
        entry_prefix = "";
        entry = "";
    }

    /* Now prepare for calling helper functions which will perform the actual
       logging, for each destination.  Since these functions have many
       parameters which are always the same, it is convenient to define what the
       actuals are once and for all. */
#define ACTUALS                                                              \
    session, level,                                                          \
    now,                                                                     \
    pid_and_tid,                                                             \
    system_subsystem_prefix, system, system_subsystem_separator, subsystem,  \
    source_file_name, source_file_line, function_prefix, function_name,      \
    entry_prefix, entry

    /* Evalutate an expression returning a pEp status; combine its result with
       the current status, updating the current status if the new one is "worse"
       than the current value. */
#define COMBINE_STATUS(expression)                                             \
    do {                                                                       \
        PEP_STATUS _new_status = (expression);                                 \
        /* This assumes, somewhat crudely, that higher-valued error codes      \
           are "more serious".  It is an acceptable approximation in the       \
           sense that non-zero status codes are more serious than              \
           PEP_STATUS_OK ; ranking different kinds of errors seems futile. */  \
        if (_new_status > status)                                              \
            status = _new_status;                                              \
    } while (false)

    /* Now log to each enabled destination, combining the status we obtain for
       every attempt.  Notice that we do not bail out on the first error. */
    PEP_STATUS status = PEP_STATUS_OK;
#if defined (PEP_HAVE_STDOUT_AND_STDERR)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDOUT)
        COMBINE_STATUS(_pEp_log_file_star(stdout, ACTUALS));
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDERR)
        COMBINE_STATUS(_pEp_log_file_star(stderr, ACTUALS));
#endif /* #if defined (PEP_HAVE_STDOUT_AND_STDERR) */

    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_DATABASE)
        COMBINE_STATUS(_pEp_log_db(ACTUALS));

#if defined (PEP_HAVE_SYSLOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_SYSLOG)
        COMBINE_STATUS(_pEp_log_syslog(ACTUALS));
#endif /* #if defined (PEP_HAVE_SYSLOG) */

#if defined (PEP_HAVE_ANDROID_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_ANDROID)
        COMBINE_STATUS(_pEp_log_android_log(ACTUALS));
#endif /* #if defined (PEP_HAVE_ANDROID_LOG) */

#if defined (PEP_HAVE_WINDOWS_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_WINDOWS)
        COMBINE_STATUS(_pEp_log_windows_log(ACTUALS));
#endif /* #if defined (PEP_HAVE_WINDOWS_LOG) */

    free (now);
    return status;
}


/* Initialisation and finalisation
 * ***************************************************************** */

/* Print a warning about enabled but unsupported destinations.  This will be
   executed once at startup. */
static void warn_about_unsupported_destinations(void) {
#if ! defined (PEP_HAVE_STDOUT_AND_STDERR)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDOUT)
        printf("Warning: stdout logging selected but unavailable\n");
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_STDERR)
        printf("Warning: stderr logging selected but unavailable\n");
#endif
    /* The database destination is always available. */
#if ! defined (PEP_HAVE_SYSLOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_SYSLOG)
        fprintf(stderr, "Warning: syslog logging selected but unavailable\n");
#endif
#if ! defined (PEP_HAVE_ANDROID_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_ANDROID)
        fprintf(stderr, "Warning: Android logging selected but unavailable\n");
#endif
#if ! defined (PEP_HAVE_WINDOWS_LOG)
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_WINDOWS)
        fprintf(stderr, "Warning: windows logging selected but unavailable\n");
#endif
}

PEP_STATUS pEp_log_initialize(PEP_SESSION session)
{
    PEP_STATUS status = PEP_STATUS_OK;
    warn_about_unsupported_destinations();

    /* The database destination is always enabled: no need for a CPP
       conditional. */
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_DATABASE)
        status = _pEp_log_initialize_database(session);

    return status;
}

PEP_STATUS pEp_log_finalize(PEP_SESSION session)
{
    PEP_STATUS status = PEP_STATUS_OK;

    /* The database destination is always enabled: no need for a CPP
       conditional. */
    if (PEP_LOG_DESTINATIONS & PEP_LOG_DESTINATION_DATABASE)
        status = _pEp_log_finalize_database(session);

    return status;
}


