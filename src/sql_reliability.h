/**
 * @file    sql_reliability.h
 * @brief   Internal header to make SQLite easy to use safely in multi-threaded
 *          applications, using loops and spinlocks with exponential backoff.
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* This header should not be used (or #include'd) out of the pEp Engine. */

#ifndef PEP_SQL_RELIABILITY_H
#define PEP_SQL_RELIABILITY_H

#include "pEp_internal.h"
#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Exponential backoff.
 * ***************************************************************** */

/* This facility implements an exponential backoff variant.  The main intended
   application is concurrent execution of SQLite statements, which are subject
   to fail with SQLITE_BUSY or SQLITE_LOCKED and need to be retried in a loop.
   Backing off before trying again makes such loops less CPU-intensive, and
   should lead to faster eventual progress.

   The constant definitions below could be tuned in application-, platform- and
   even machine-specific ways.  Here the intent is simply sustaining a moderate
   amount of threads, in the order of a few hundreds, all concurrently writing
   to the same database, with a write bandwidth not too far from the sequential
   case.
   These values were tentatively set by positron in early 2023 by testing on his
   "moore" laptop (4-core 8-thread Intel i7 3.2GHz, 16GB RAM, SSD drive),
   GNU/Linux. */

/* The minimum wait in milliseconds; no wait is ever shorter than this value.
   This is also the lower bound of the random wait time, and never changes. */
#define PEP_MINIMUM_BACKOFF_IN_MS              10

/* The initial wait upper limit in milliseconds.  This upper limit will start at
   this value and then grow after each backoff, up to
   PEP_MAXIMUM_BACKOFF_IN_MS. */
#define PEP_INITIAL_UPPER_LIMIT_BACKOFF_IN_MS  20

/* The maximum wait in milliseconds.  No wait is ever longer than this value. */
#define PEP_MAXIMUM_BACKOFF_IN_MS              250

/* The wait length upper limit increasing ratio: after every wait we make the next
   one potentially longer (up to PEP_MAXIMUM_BACKOFF_IN_MS) by multiplying the
   current upper limit by this value.  The minimum value remains at
   PEP_MINIMUM_BACKOFF_IN_MS .*/
#define PEP_BACKOFF_UPPER_LIMIT_GROWTH_FACTOR  (1 + 1.0)  /* 100 % increase */

/* After this number of consecutive backoffs log one message. */
#define PEP_BACKOFF_TIMES_BEFORE_LOGGING       10


/* This is the local state of a block using exponential backoff.  The struct is
   used internally and its fields should be treated as opaque. */
struct pEp_backoff_state
{
    /* How many times we failed and therefore we had to wait before now. */
    int failure_no;

    /* How long we have slept (in this state) before now, in milliseconds. */
    long total_time_slept_in_ms;

    /* When waiting a random delay is extracted (uniform probability
       distribution), from PEP_MINIMUM_BACKOFF_IN_NS to this value, both in
       milliseconds. */
    long current_upper_limit_in_ms;

    /* Where the PEP_SQL_BEGIN_LOOP call occurs in the source file.  This is
       useful for logging and debugging. */
    const char *source_location;
};

/*
 *  @internal
 *  <!--        pEp_backoff_state_initialize()       -->
 *
 *  @brief      Initialise the exponential-backoff state.
 *
 *  @param[in]    session           session handle
 *  @param[inout] s                 initialize the pointed state.  Ownership
 *                                  remains with the caller
 *  @param[in]    location          the source location for the macro call,
 *                                  used for logging and debugging
 *
 *  @retval     PEP_ILLEGAL_VALUE   NULL arguments
 *  @retval     PEP_STATUS_OK       success
 */
PEP_STATUS pEp_backoff_state_initialize(
   PEP_SESSION session,
   struct pEp_backoff_state *s,
   const char *source_location);

/*
 *  @internal
 *  <!--        pEp_back_off()       -->
 *
 *  @brief      Sleep in the given state for an appropriate time, and update
 *              the state to remember the current failed attempt and to compute
 *              the next bound.  This is guaranteed to sleep for the established
 *              amount of time if a signal arrives.
 *
 *  @param[in]    session           session handle
 *  @param[inout] s                 the state to read and update
 *
 *  @retval     PEP_ILLEGAL_VALUE   NULL arguments
 *  @retval     PEP_STATUS_OK       success
 */
PEP_STATUS pEp_back_off(PEP_SESSION session,
                        struct pEp_backoff_state *s);

/*
 *  @internal
 *  <!--        pEp_backoff_state_finalize()       -->
 *
 *  @brief      Keep into account the current state for possible logging
 *              and statistics, at the end of its use.  This is used after
 *              the action has finally been executed successfully, and the
 *              exponential-backoff state contains information about the
 *              previous failed attempts.
 *
 *  @param[in]    session           session handle
 *  @param[inout] s                 the pointed state to initialize; ownership
 *                                  remains with the caller
 *
 *  @retval     PEP_ILLEGAL_VALUE   NULL arguments
 *  @retval     PEP_STATUS_OK       success
 */
PEP_STATUS pEp_backoff_state_finalize(
   PEP_SESSION session,
   const struct pEp_backoff_state *s);


/* SQLite loop-until-nonbusy execution
 * ***************************************************************** */

/* This facility provides a convenient way to execute C statement performing
   SQLite database actions, automatically retrying as necessary, with an
   exonential backoff, until the sql status code becomes different from
   SQLITE_LOCKED and SQLITE_BUSY.

   The facility defined here can be used with any database connection, and
   does not rely on EXCLUSIVE transactions.  For a different facility
   implementing exclusivity by spinlocking (with exponential backoff) see
   the section below. */

/* PEP_SQL_BEGIN_LOOP, PEP_SQL_END_LOOP: expand to a C statement executing
   SQLite statements in a loop until the result is no longer SQLITE_LOCKED or
   SQLITE_BUSY.
   The user should write her C code containing SQLite statements to be repeated
   within a single scope delimited by a call to PEP_SQL_BEGIN_LOOP and a call to
   PEP_SQL_END_LOOP .  For example:
      int sqlite_status = SQLITE_OK;
      PEP_SQL_BEGIN_LOOP(sqlite_status);
      sqlite_status = sqlite3_exec(db, "INSERT INTO Foo (foo) VALUES (42);",
                                   NULL, NULL, NULL);
      PEP_SQL_END_LOOP();
   At run time the statements surrounded by the two macros will be repeated
   until the SQLite status referred as an lvalue in PEP_SQL_BEGIN_LOOP is
   different from both SQLITE_LOCKED and SQLITE_BUSY.  After each failure with
   either SQLITE_LOCKED or SQLITE_BUSY release the CPU for a random time
   according to an exponential backoff policy.
   After the expansion of PEP_SQL_END_LOOP it is guaranteed that the status will
   be different from SQLITE_LOCKED and SQLITE_BUSY -- even if it might still be
   an error state.
   Macro calls to PEP_SQL_BEGIN_LOOP and PEP_SQL_END_LOOP *must* be paired as
   shown above: calling only one of them, or calling them both in different
   scopes, may expend to invalid code and has undefined behaviour even when the
   expansion happened to be syntactically valid.
   It is possible to nest paired macro calls to PEP_SQL_BEGIN_LOOP and
   PEP_SQL_END_LOOP , even if this is probably unnecessary. */
#define PEP_SQL_BEGIN_LOOP(sqlite_status_lvalue)                                \
    /* The logic using _pEp_sql_run_the_inner_loop_body_once_more is not out of \
       structured programming pedantry: I (positron) would in fact be much more \
       aesthetically satisfied using goto to exit nested loops.                 \
       Unfortunately goto is not usable here without a user-supplied label namd \
       name, which would be intrusive, fragile and error-prone.  With C not     \
       allowing nested labels with the same name shadowing each other I find    \
       this to be the least ugly solution. */                                   \
    do { /* Outer "loop", not really looping. */                                \
        const char *_pEp_sql_begin_location                                     \
            = (__FILE__ ":" _STRINGIFY(__LINE__));                              \
        struct pEp_backoff_state _pEp_sql_backoff_state;                        \
        pEp_backoff_state_initialize(session,                                   \
                                     & _pEp_sql_backoff_state,                  \
                                     _pEp_sql_begin_location);                  \
        int *_pEp_sql_sqlite_status_address = & (sqlite_status_lvalue);         \
        bool _pEp_sql_run_the_inner_loop_body_once_more = true;                 \
        do { /* Inner loop beginning... */                                      \
            /* After the expansion of this macro comes the user C code to be    \
               tried multiple times.  Looking at macroexpanded the user C code  \
               will appear inside this inner loop... */                         \
            { /* user code beginning... */
#define PEP_SQL_END_LOOP()                                                      \
            } /* ...user code end */                                            \
            /* ... still inside the inner loop started at PEP_SQL_BEGIN, now    \
               after the user C code to be tried multiple times. */             \
            if (* _pEp_sql_sqlite_status_address == SQLITE_LOCKED               \
                || * _pEp_sql_sqlite_status_address == SQLITE_BUSY) {           \
                /* Only for defensiveness's sake: */                            \
                * _pEp_sql_sqlite_status_address = SQLITE_OK;                   \
                /* This attempt failed.  Back off... */                         \
                PEP_STATUS _pEp_sql_state                                       \
                    = pEp_back_off(session, & _pEp_sql_backoff_state);          \
                PEP_ASSERT(_pEp_sql_state == PEP_STATUS_OK);                    \
                /* ...And now iterate in the inner block again, skipping over   \
                   the assignment which would make it end. */                   \
                continue;                                                       \
            }                                                                   \
                                                                                \
            /* If we arrived here the user C code succeeded, or failed with an  \
               error which cannot be hidden by just retrying: exit the inner    \
               loop. */                                                         \
            _pEp_sql_run_the_inner_loop_body_once_more = false;                 \
        } while (_pEp_sql_run_the_inner_loop_body_once_more); /* ...Inner loop  \
                                                                 end.  */       \
        /* Finalize the state and take backoff data into account for statistics \
           and logging, now that we have stopped looping. */                    \
/*local_failure_no += _pEp_sql_backoff_state.failure_no; \
local_wait_time += _pEp_sql_backoff_state.total_time_slept_in_ms;*/ \
        pEp_backoff_state_finalize(session,                                     \
                                   & _pEp_sql_backoff_state);                   \
    } while (false) /* End of the outer block. */


/* SQLite EXCLUSIVE transactions and spinlocking
 * ***************************************************************** */

/* The facility defined in this section uses the macros above to implement
   "BEGIN EXCLUSIVE TRANSACTION" and "COMMIT TRANSACTION" / "ROLLBACK
   TRANSACTION" forms which are guaranteed to hide any problem with
   SQLITE_LOCKED and SQLITE_BUSY: once an exclusive transaction is succesfully
   begun it is guaranteed that any SQL statement over the same database will
   *not* fail with SQLITE_LOCKED or SQLITE_BUSY over the current connection,
   but *will* instead fail with SQLITE_LOCKED or SQLITE_BUSY over any other
   connection.
   In other words beginning a transaction with this facility acquires an
   exclusive lock, to be only released at transaction end.
   The pEp Engine was originally written without giving much thought to the
   problem of SQL concurrency; adopting this simple-minded solution is a good
   way to make existing code robust without modifying it to roll back the C
   state every time a retry is needed -- which would be very difficult to do
   correctly.
   This facility is only defined for use with the management database.  Of
   course it could be factored and generalised.

   This is a higher-level facility defined on top of the facility above
   (beginning an exclusive transaction requires a loop), useful in non-trivial
   tranasctions where more than one SQL statement needs to be executed.

   Differently from PEP_SQL_BEGIN_LOOP and PEP_SQL_END_LOOP the macros defined
   here do not need to be paired syntactically: however ending a transaction
   via commiting or rolling back is necessary to release the lock. */

/**
 *  @internal
 *  <!--       PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION()       -->
 *
 *  @brief     Begin an exclusive transaction on the management database.  */
#define PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION()                                   \
    do {                                                                        \
        int _pEp_sql_sqlite_status;                                             \
        /* First reset the statement; we can and in fact should ignore the      \
           return value of this, which may be an error or even SQLITE_BUSY,     \
           referred to the previous execution.  The reset operation itself      \
           cannot fail. */                                                      \
        sqlite3_reset(session->begin_exclusive_transaction);                    \
        /* Begin the exclusive transaction, inside an SQL loop: this is where   \
           we spinlock with exponential backoff. */                             \
        PEP_SQL_BEGIN_LOOP(_pEp_sql_sqlite_status);                             \
            /* Ignore the return value of sqlite3_reset: if the last            \
               sqlite3_step on the statement returned an error, this            \
               sqlite3_reset will return the same error: we certainly do not    \
               want to see SQLITE_BUSY here for no reason.                      \
               I am in fact not at all sure that we need to reset inside this   \
               loop.  I am being very defensive here, in the hope of solving    \
               the particularly difficult to reproduce problem in               \
               https://gitea.pep.foundation/pEp.foundation/pEpEngine/issues/133 \
               . */                                                             \
            _pEp_sql_sqlite_status                                              \
                = sqlite3_step(session->begin_exclusive_transaction);           \
            if (_pEp_sql_sqlite_status != SQLITE_OK)                            \
                LOG_TRACE("in PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION loop with "   \
                          "sqlite status %i", _pEp_sql_sqlite_status);          \
        PEP_SQL_END_LOOP();                                                     \
        /* After this point we must have opened the transaction with success.   \
           Make sure something unexpected has not happened. */                  \
        PEP_ASSERT(_pEp_sql_sqlite_status != SQLITE_BUSY);                      \
        PEP_ASSERT(_pEp_sql_sqlite_status != SQLITE_LOCKED);                    \
        if (_pEp_sql_sqlite_status != SQLITE_DONE)                              \
            LOG_ERROR("UNEXPECTED error on BEGIN EXCLUSIVE TRANSACTION: %i %s", \
                      _pEp_sql_sqlite_status, sqlite3_errmsg(session->db));     \
        PEP_ASSERT(_pEp_sql_sqlite_status == SQLITE_DONE);                      \
    } while (false)

/* This macro factors the common logic of PEP_SQL_COMMIT_TRANSACTION and
   PEP_SQL_ROLLBACK_TRANSACTION . */
#define PEP_SQL_COMMIT_OR_ROLLBACK_TRANSACTION(commit)                          \
    do {                                                                        \
        /* Here thre is no need to loop using PEP_SQL_BEGIN_LOOP and            \
           PEP_SQL_END_LOOP: if we first began the transaction with             \
           PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION then it is *impossbile* to fail  \
           with SQLITE_BUSY or SQLITE_LOCKED here; for defensiveness's sake we  \
           still check for that, but there is no need to loop. */               \
        bool _pEp_bool_commit = (commit);                                       \
        sqlite3_stmt *_pEp_statement = (_pEp_bool_commit                        \
                                        ? session->commit_transaction           \
                                        : session->rollback_transaction);       \
        /* Reset the prepared statement.  Ignore the result of sqlite3_reset,   \
           even if in this case it should not be an error: see the comment      \
           inside PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION . */                      \
        sqlite3_reset(_pEp_statement);                                          \
        /* Execute the statement.  Surprisingly this can fail with SQLITE_BUSY  \
           or SQLITE_LOCKED even inside an EXCLUSIVE tranasction. */            \
        int _pEp_sql_sqlite_status = SQLITE_OK;                                 \
        PEP_SQL_BEGIN_LOOP(_pEp_sql_sqlite_status);                             \
        _pEp_sql_sqlite_status = sqlite3_step(_pEp_statement);                  \
        PEP_SQL_END_LOOP();                                                     \
        if (_pEp_sql_sqlite_status != SQLITE_DONE)                              \
            LOG_ERROR("UNEXPECTED error on %s: %i %s",                          \
                      (_pEp_bool_commit ? "COMMIT" : "ROLLBACK"),               \
                      _pEp_sql_sqlite_status, sqlite3_errmsg(session->db));     \
        PEP_ASSERT(_pEp_sql_sqlite_status == SQLITE_DONE);                      \
    } while (false)

/**
 *  @internal
 *  <!--       PEP_SQL_COMMIT_TRANSACTION()       -->
 *
 *  @brief     Commit the current exclusive transaction.  */
#define PEP_SQL_COMMIT_TRANSACTION()              \
    PEP_SQL_COMMIT_OR_ROLLBACK_TRANSACTION(true)

/**
 *  @internal
 *  <!--       PEP_SQL_ROLLBACK_TRANSACTION()       -->
 *
 *  @brief     Rollback the current exclusive transaction.  */
#define PEP_SQL_ROLLBACK_TRANSACTION()             \
    PEP_SQL_COMMIT_OR_ROLLBACK_TRANSACTION(false)


/* Convenience wrapper for "automatic" one-statement transactions
 * ***************************************************************** */

/* This provides the same API as sqlite3_step, making use of the functionality
   above which executes SQL statements in a loop to avoid a result of
   SQLITE_BUSY or SQLITE_LOCK.  The actual documentation of sqlite3_step is at
   https://www.sqlite.org/capi3ref.html#sqlite3_step . */
int pEp_sqlite3_step_nonbusy(PEP_SESSION session,
                             sqlite3_stmt *statement);


#ifdef __cplusplus
} /* extern "C" */
#endif



#endif /* #ifndef PEP_SQL_RELIABILITY_H */
