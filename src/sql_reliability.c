/**
 * @file    sql_reliability.c
 * @brief   Internal definitions to make SQLite easy to use safely in
 *          multi-threaded applications, using loops and spinlocks with
 *          exponential backoff.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* For this compilation unit I want to disable function-entry log lines, which
   would be very frequent and very distracting. */
#define PEP_NO_LOG_FUNCTION_ENTRY 1

#define _EXPORT_PEP_ENGINE_DLL  /* some symbols are used in external compilation
                                   units, in particular through macros. */
#include "sql_reliability.h"

#include "pEp_internal.h"
#include "engine_sql.h"

#include "pEpEngine.h"

#include <errno.h>


/* Exponential backoff.
 * ***************************************************************** */

PEP_STATUS pEp_backoff_state_initialize(PEP_SESSION session,
                                        struct pEp_backoff_state *s,
                                        const char *source_location)
{
    PEP_REQUIRE(session && s && source_location);

    s->failure_no = 0;
    s->total_time_slept_in_ms = 0;
    s->current_upper_limit_in_ms = PEP_INITIAL_UPPER_LIMIT_BACKOFF_IN_MS;
    s->source_location = source_location;
    return PEP_STATUS_OK;
}

PEP_STATUS pEp_backoff_state_finalize(PEP_SESSION session,
                                      const struct pEp_backoff_state *s)
{
    PEP_REQUIRE(session && s);

    /* I might want to actually add some statistics in the session, in the
       future. */
    if (s->failure_no > 0)
        LOG_WARNING("SQLite at %s: success after %i failures, total backoff %li ms",
                    s->source_location,
                    (int) s->failure_no, (long) s->total_time_slept_in_ms);
    return PEP_STATUS_OK;
}

/* Increase the backoff length and the failure counter in the pointed state,
   recording that we have just slept for the given amount of time. */
static void pEp_backoff_bump(PEP_SESSION session,
                             struct pEp_backoff_state *s,
                             long sleep_time_ms)
{
    PEP_REQUIRE_ORELSE(session
                       && /* Useful to check in case this is invoked early
                             at initialisation time, for example from the
                             logging subsystem. */ session->db
                       && s , { return; });

    /* Record statistics. */
    s->failure_no ++;
    s->total_time_slept_in_ms += sleep_time_ms;

#if 0
    if ((s->failure_no % PEP_BACKOFF_TIMES_BEFORE_CHECKPOINTING) == 0)
        PEP_SQL_CHECKPOINT;
#endif
    if ((s->failure_no % PEP_BACKOFF_TIMES_BEFORE_LOGGING) == 0)
        LOG_NONOK("backing off from %s (%i times already; logging once"
                  " every %i times)",
                  s->source_location, (int) s->failure_no,
                  (int) PEP_BACKOFF_TIMES_BEFORE_LOGGING);

    /* Raise the sleep time upper limit. */
    double unclamped_upper_limit
        = (s->current_upper_limit_in_ms * PEP_BACKOFF_UPPER_LIMIT_GROWTH_FACTOR);
    if (unclamped_upper_limit <= PEP_MAXIMUM_BACKOFF_IN_MS)
        s->current_upper_limit_in_ms = unclamped_upper_limit;
    else
        s->current_upper_limit_in_ms = PEP_MAXIMUM_BACKOFF_IN_MS;
}

/* Return a random sleeping time appropriate for the current state, without
   bumping it. */
static long pEp_backoff_compute_sleep_time(PEP_SESSION session,
                                           const struct pEp_backoff_state *s)
{
    PEP_REQUIRE_ORELSE(session && s, { return 0; });

    long range_width
        = (s->current_upper_limit_in_ms - PEP_MINIMUM_BACKOFF_IN_MS);
    assert(range_width >= 0);
    long random_component = rand() % (range_width + 1);
    return PEP_MINIMUM_BACKOFF_IN_MS + random_component;
}

PEP_STATUS pEp_back_off(PEP_SESSION session,
                        struct pEp_backoff_state *s)
{
    PEP_REQUIRE(session && s);

    /* Very easy: sleep, and bump. */
    long sleep_time_in_ms = pEp_backoff_compute_sleep_time(session, s);
    if (sleep_time_in_ms != 0)
        pEp_sleep_ms(sleep_time_in_ms);
    pEp_backoff_bump(session, s, sleep_time_in_ms);

    return PEP_STATUS_OK;
}


/* Convenience wrapper for "automatic" one-statement transactions
 * ***************************************************************** */

int pEp_sqlite3_step_nonbusy(PEP_SESSION session,
                             sqlite3_stmt *prepared_statement)
{
    PEP_REQUIRE_ORELSE_RETURN(session && prepared_statement,
                              /* Something generic is acceptable: this will only
                                 happen because of Engine bugs */ SQLITE_ERROR);
    int sqlite_status;

    bool transaction_in_progress_at_entry
        = session->transaction_in_progress_no > 0;
    if (! transaction_in_progress_at_entry)
        PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();
    sqlite_status = sqlite3_step(prepared_statement);
    if (sqlite_status != SQLITE_OK && sqlite_status != SQLITE_ROW
        && sqlite_status != SQLITE_DONE)
        LOG_NONOK("sqlite_status is %s from executing %s",
                  pEp_sql_status_text(session),
                  sqlite3_expanded_sql(prepared_statement));
    PEP_ASSERT(sqlite_status != SQLITE_LOCKED); /* LOCKED should never happen. */
    if (! transaction_in_progress_at_entry) {
        PEP_ASSERT(sqlite_status != SQLITE_BUSY); /* BUSY should not happen in an
                                                     exclusive transaction. */
        PEP_SQL_COMMIT_TRANSACTION();
    }

    return sqlite_status;
}

int pEp_sqlite3_prepare_v3_nonbusy_nonlocked(PEP_SESSION session,
                                             sqlite3 *db,
                                             const char *zSql,
                                             int nByte,
                                             unsigned int prepFlags,
                                             sqlite3_stmt **ppStmt,
                                             const char **pzTail)
{
    PEP_REQUIRE_ORELSE_RETURN(session && db && ppStmt,
                              /* Something generic: this will not happen anyway
                                 except for internal bugs */ SQLITE_ERROR);
    int sqlite_status = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(sqlite_status);
        sqlite_status
            = sqlite3_prepare_v3(db, zSql, nByte, prepFlags, ppStmt, pzTail);
        if (sqlite_status == SQLITE_LOCKED) {
            /* This can actually happen when preparing statements, but such a
               status is not supported by PEP_SQL_END_LOOP which is mostly used
               for stepping.  We can log a warning and work as if this were
               SQLITE_BUSY. */
            LOG_NONOK("get SQLITE_LOCKED when preparing the statement %s --"
                      " trying again.", zSql);
            sqlite_status = SQLITE_BUSY;
        }
    PEP_SQL_END_LOOP();

    return sqlite_status;
}

int pEp_sqlite3_prepare_v2_nonbusy_nonlocked(PEP_SESSION session,
                                             sqlite3 *db,
                                             const char *zSql,
                                             int nByte,
                                             sqlite3_stmt **ppStmt,
                                             const char **pzTail)
{
    return pEp_sqlite3_prepare_v3_nonbusy_nonlocked(session, db, zSql, nByte,
                                                    /* the missing argument */ 0,
                                                    ppStmt, pzTail);
}
