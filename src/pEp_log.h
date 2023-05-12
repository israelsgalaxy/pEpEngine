/**
 * @file    pEp_log.h
 * @brief   pEp logging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_LOG_H
#define PEP_LOG_H

#include "pEpEngine.h"
#include "status_to_string.h"

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Introduction
 * ***************************************************************** */

/* This general-purpose log facility is used internally in the Engine, but is
   also meant for adapters and applications.  The pEp logging facility can
   output information to any number of "destinations" among the supported ones:
   databases, standard error, syslog, system-dependent outputs, and so on.

   Each log entry consists of:
   * a "level", describing the verbosity associated to the current entry;
   * a system name;
   * a sub-system name;
   * a user-specified string;
   * precise source location: source file name, line number, function name;
   * timing information.

   Global configuration allows to suppress long entries above a given verbosity.

   At least when called from C this facility is meant to be used from the macro
   API, which is much more convenient: in particular the macro API allows the
   user to specify the entry string as a literal string template along with a
   set of values to be filled in the template, following the formatted output
   conventions of printf.

   The function API below serves as the internal implementation of the macro
   API, and possibly for calling the log facility from non-C languages. */


/* How to use
 * ***************************************************************** */

/* A convenient way of using this facility for debugging prints is to define
   a CPP macro with a short name and only variadic parameters directly in the
   C file where it will be used; then one can add calls to the local macro in
   the functions being debugged.

   For example imagine a "frob" application containg a source file quux.c, with
   some of the content as shown here:
   98   #define LOG(...) PEP_LOG_TRACE("frob", NULL, __VA_ARGS__)
   99
   100  void foo(int x) {
   101      LOG("About to call bar.  x is %i", x);
   102      bar();
   103      int y = x + 2;
   104      LOG("y is %i", y);
   105      LOG();
   106  }
   107
   108  void bar(void) {
   109      LOG("Hello");
   110  }

   Notice the call at line 105, which will only show the function name and
   source location.  The template is completely absent in that case: one does
   not even need to supply an empty string; however the template string, when
   supplied, must be a literal, due to the implementation with token-level
   string concatenation through CPP.

   Assuming PEP_LOG_LEVEL_MAXIMUM to be at least PEP_LOG_LEVEL_TRACE the log
   will contain something like:

   2022-09-23 20:39:13 frob 523621 trc quux.c:101:foo About to call bar.  x is 10
   2022-09-23 20:39:13 frob 523621 trc quux.c:109:bar Hello
   2022-09-23 20:39:13 frob 523621 trc quux.c:104:foo y is 12
   2022-09-23 20:39:13 frob 523621 trc quux.c:105:foo

   Here "trc" is an abbreviation of the log level name; 523621 is the process id
   of the running process; (it would be useful to show a thread id as well next
   to the process id, but unfortunately the value of thread ids varies depending
   on the thread API, even on the same system).


   Logging at multiple log levels in the same compilation units requires
   multiple macros, but these are easy to factor with a single "higher-order"
   definition taking a macro name as a parameter:

   #define _LOG_WITH_MACRO_NAME(name, ...)     \
      name("p≡p Engine", "my beautiful module", "" __VA_ARGS__)
   #define LOG_CRITICAL(...)  _LOG_WITH_MACRO_NAME(PEP_LOG_CRITICAL, __VA_ARGS__)
   #define LOG_ERROR(...)     _LOG_WITH_MACRO_NAME(PEP_LOG_ERROR, __VA_ARGS__)
   #define LOG_WARNING(...)   _LOG_WITH_MACRO_NAME(PEP_LOG_WARNING, __VA_ARGS__)

   This is in fact what every compilation unit gets for free for using *inside*
   the Engine, just by including pEp_internal.h: look at the "Logging" section
   in pEp_internal.h .  */


/* Parameters
 * ***************************************************************** */

/**
 *  @enum    PEP_LOG_LEVEL
 *
 *  @brief   This can be thought of the verbosity or redundance or
 *           non-importance or a log entry: the higher the value is, the less
 *           important the entry is.
 *
 *           Setting PEP_LOG_LEVEL_MAXIMUM to a certain level means that entries
 *           with strictly more verbosity than the level are ignored.  Said
 *           otherwise PEP_LOG_LEVEL_MAXIMUM is the level of the most verbose or
 *           least important information that will be logged.
 */
typedef enum {
    /* Errors. */
    PEP_LOG_LEVEL_CRITICAL    =   10,
    PEP_LOG_LEVEL_ERROR       =   20,

    /* Warnings. */
    PEP_LOG_LEVEL_WARNING     =  100,

    /* Events. */
    PEP_LOG_LEVEL_EVENT       =  200,
    PEP_LOG_LEVEL_API         =  210,

    /* Debugging. */
    PEP_LOG_LEVEL_NONOK       =  300,
    PEP_LOG_LEVEL_NOTOK       =  300  /* alias */,
    PEP_LOG_LEVEL_FUNCTION    =  310,
    PEP_LOG_LEVEL_TRACE       =  320, /* this is annoyingly verbose, and mostly
                                         intended for the Engine maintainer. */

    /* Aliases or sensible PEP_LOG_LEVEL_MAXIMUM values for practical use. */
    PEP_LOG_LEVEL_PRODUCTION  =  PEP_LOG_LEVEL_CRITICAL /* Never log less. */,
    PEP_LOG_LEVEL_BASIC       =  PEP_LOG_LEVEL_WARNING,
    PEP_LOG_LEVEL_SERVICE     =  PEP_LOG_LEVEL_API,

    /* A strict upper limit: not intended for actual log entries. */
    PEP_LOG_LEVEL_EVERYTHING  = 1000,
} PEP_LOG_LEVEL;

/**
 *  @enum    PEP_LOG_DESTINATION_ENUM
 *
 *  @brief   Where to output log entries.  A bitwise-or combination of the
 *           enum values can be used: one copy will be printed to each
 *           destination.
 *           Not every platform will support every possibility; entries logged
 *           to an unsupported destination will simply be discarded.
 *
 *           This type is used for PEP_LOG_DESTINATIONS: see below.
 */
typedef enum {
    /* No destination: if PEP_LOG_DESTINATION is defined as this then every
       log entry is simply discarded. */
    PEP_LOG_DESTINATION_NONE      =   0,

    /* Print log entries in text format to the standard output or the standard
       error stream. */
    PEP_LOG_DESTINATION_STDOUT    =   1,
    PEP_LOG_DESTINATION_STDERR    =   2,

    /* Add entries to a local database.  The database file is named log.db , and
       always kept in the same directory as management.db .  The recommended way
       for humans to read entries is through the view UserEntries:
         sqlite3 ~/.pEp/log.db
         sqlite> SELECT * FROM UserEntries;  */
    PEP_LOG_DESTINATION_DATABASE  =   4,

    /* Send log entries to the syslog service, or (on windows) on the native log
       destination obtained from OpenEventLogW -- windows logging is implemented
       as an emulated syslog API. */
    /*
      https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openeventlogw
      OpenEventLogW
      example: https://learn.microsoft.com/en-us/windows/win32/eventlog/querying-for-event-source-messages

      ReportEvent
      example: https://learn.microsoft.com/en-us/windows/win32/eventlog/reporting-an-event
      */

    PEP_LOG_DESTINATION_SYSLOG    =   8,

    /* Use the Android logging system. */
    PEP_LOG_DESTINATION_ANDROID   =  16,

    /* Use the windows logging system. */
    PEP_LOG_DESTINATION_WINDOWS   =  32,


    /* Every possible destination.  This is mostly intended for testing. */
    PEP_LOG_DESTINATION_ALL       = 255
} PEP_LOG_DESTINATION_ENUM;


/* Configuration
 * ***************************************************************** */

/**
 *  @macro   PEP_LOG_LEVEL_MAXIMUM
 *
 *  @brief   A constant expression of type PEP_LOG_LEVEL, evaluating to
 *           the maximum level of verbosity which is not ignored.
 *
 *           This macro, defined either here or from the compilation
 *           command line, is an upper bound to the log verbosity.  Any
 *           log entry strictly more verbose than this value will not be
 *           printed,  and may be entirely optimised away at compile time.
 */
#if ! defined(PEP_LOG_LEVEL_MAXIMUM)
    /* If the macro has not been defined already (likely from the build system)
       provide a default for it. */
#   if defined(_PEP_SERVICE_LOG_OFF)
#       define PEP_LOG_LEVEL_MAXIMUM  PEP_LOG_LEVEL_PRODUCTION
#   elif defined(NDEBUG)
#       define PEP_LOG_LEVEL_MAXIMUM  PEP_LOG_LEVEL_SERVICE
#   else
#       define PEP_LOG_LEVEL_MAXIMUM  PEP_LOG_LEVEL_EVERYTHING
#   endif
#endif

/**
 *  @macro   PEP_LOG_DESTINATIONS
 *
 *  @brief   The destinations used for all logging, as a constant
 *           unsigned-integer expression.  For every PEP_LOG_DESTINATION_ENUM
 *           case, if the case bit value is contained in the constant then the
 *           destination is used.
 *           Notice that this macro is only ever used from pEp_log.c , and so
 *           its value is only important at engine compile time: software using
 *           the Engine, including adapters, do not need to be concerned with
 *           defining the macro in a way consistent with the Engine.
 */
#if ! defined(PEP_LOG_DESTINATIONS)
    /* If the macro has not been defined already (likely from the build system)
       provide a default for it. */
#   if defined(NDEBUG)
#       define PEP_LOG_DESTINATIONS   (PEP_LOG_DESTINATION_STDOUT      \
                                       | PEP_LOG_DESTINATION_DATABASE  \
                                       | PEP_LOG_DESTINATION_SYSLOG)
#   else
#       define PEP_LOG_DESTINATIONS   (PEP_LOG_DESTINATION_STDERR       \
                                       | PEP_LOG_DESTINATION_DATABASE)
#   endif
#endif

/* If this is enabled then requirements at function entry will also log a line
   (level Function) about the function being entered.  Since this can make the
   logs very noisy I am making it possible to disable the feature independently
   from PEP_LOG_LEVEL_MAXIMUM , by commenting-out the #define line below.

   It is also possible to disable this feature for specific compilation units by
   defining PEP_NO_LOG_FUNCTION_ENTRY before including this header. */
#if ! defined(PEP_NO_LOG_FUNCTION_ENTRY)
# define PEP_LOG_FUNCTION_ENTRY  1
#endif

/* If this is enabled then *failed* status checkswill also log a line (level
   NonOK) about the expression, usually a function call, failing.  Since this
   can make the logs noisy I made it possible to disable the feature
   independently from PEP_LOG_LEVEL_MAXIMUM , by commenting-out this line. */
#define PEP_LOG_LOCAL_FAILURE  1

/* Every time database rows become more than this number delete the oldest one.
   This is needed to prevent the database from growing to an unbounded size.

   Just as a rule of thumb:
   - 10000 entries take 1MB
   - 1 entry takes ~100B   */
#define PEP_LOG_DATABASE_ROW_NO_MAXIMUM 100000


/* Logging an entry: user macros
 * ***************************************************************** */

/**
 *  <!--       PEP_LOG_CRITICAL()       -->
 *
 *  @brief This macro expands to a C statement logging a message using the
 *         current session, found by capturing a variable named "session"
 *         (assumed to be of type PEP_SESSION) in the current scope.
 *
 *  @param[in]  system     a string identifying the system being run, or NULL
 *  @param[in]  subsystem  a string identifying the subsystem being run, or NULL
 *
 *  @param[in]  template   a literal string (*not* a generic expression)
 *                         expressing a template to be filled with the rest of
 *                         the arguments, if any, in the style of printf.
 *                         If the compiler supports the GNU C extension allowing
 *                         for zero arguments in variadic macros (supported by
 *                         both GCC and Clang) then the template can also be not
 *                         given at all: calling PEP_LOG_CRITICAL with only two
 *                         arguments is correct, and uses an empty string as the
 *                         logged entry string.
 *  @param[in]  ...        Other arguments matching the template, following
 *                         the formatted-output conventions of printf.
 *
 *  @note This macro can be used directly in any context where a variable named
 *        "session" of type PEP_SESSION is visible, but it is usually more
 *        convenient to define a macro, local to the compilation unit, having
 *        only variadic arguments.  See the comment in the "How to use" section.
 */
/* This style of definition would work, conceptually: but in early 2023 Alex had
   problems using the microsoft compiler, which emitted some arguments grouped
   by unwanted parentheses, nowhere to be found in the macro definition; the GCC
   and Clang C preprocessors do not exhibit this problem.
   I (positron) suspect that the microsoft preprocessor may be wrong, but this
   would need to be distilled into a simpler test case.  Anyway I asked Alex to
   try the alternative below, much more verbose, and he confirmed that this
   version works as intended with microsoft's compiler as well.
   --positron, 2023-01  */
/* #define PEP_LOG_CRITICAL(first, ...)                                  \
     PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_CRITICAL, (first), __VA_ARGS__)  */
#define PEP_LOG_CRITICAL(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_CRITICAL), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_ERROR()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_ERROR(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_ERROR), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_WARNING()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_WARNING(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_WARNING), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_EVENT()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_EVENT(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_EVENT), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_API()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_API(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_API), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_FUNCTION()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_FUNCTION(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_FUNCTION), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_NONOK()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_NONOK(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_NONOK), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_NOTOK()       -->
 *  @brief A convenience alias for PEP_LOG_NONOK.
 */
#define PEP_LOG_NOTOK  PEP_LOG_NONOK

/**
 *  <!--       PEP_LOG_TRACE()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_TRACE(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_TRACE), (system), (subsystem), "" __VA_ARGS__)


/**
 *  <!--       PEP_LOG_PRODUCTION()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_PRODUCTION(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_PRODUCTION), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_BASIC()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_BASIC(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_BASIC), (system), (subsystem), "" __VA_ARGS__)

/**
 *  <!--       PEP_LOG_SERVICE()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_SERVICE(system, subsystem, ...)  \
    PEP_LOG_WITH_SESSION_AND_LEVEL((session), (PEP_LOG_LEVEL_SERVICE), (system), (subsystem), "" __VA_ARGS__)


/* Logging facility: internal macros
 * ***************************************************************** */

/* When available use GNU C's __PRETTY_FUNCTION__ instead of the standard
   __func__ from C99.  The GNU version is much more useful in C++, as its
   expansion shows namespaces and classes as well. */
#if defined (PEP_HAVE_PRETTY_FUNCTION)
#   define PEP_func_OR_PRETTY_FUNCTION  __PRETTY_FUNCTION__
#else
#   define PEP_func_OR_PRETTY_FUNCTION  __func__
#endif

/* ICS
 * ***************************************************************** */

/* Expand to a dummy initialising declaration of the ICS automatic variable
   _ics_nest_level , to be used in contexts where PEP_ICS_SET_FOR_THIS_FUNCTION
   or PEP_REQUIRE are not appropriate (see pEp_debug.h ) but we still want to
   log. */
#define PEP_ICS_DUMMY                                  \
    int _ics_nest_level __attribute__ ((unused)) = 0;

/* Update the current nesting level as stored in the ICS struct, copying from
   the automatic variable which is always the most up-to-date. */
#define PEP_ICS_UPDATE                                    \
    do {                                                  \
        session->ics_state.nest_level = _ics_nest_level;  \
    } while (false)


/* Internal macros
 * ***************************************************************** */

/* The macros here are used internally to implement the user macros above. */

// Disabled in early 2023 since now unused: see the comment above about the
// microsoft preprocessor.
/* /\** */
/*  *  <!--       PEP_LOG_WITH_LEVEL()       --> */
/*  * */
/*  * @brief Exactly like PEP_LOG_CRITICAL, with one more parameter prepended */
/*  *        to the others. */
/*  *        Same caveat about capturing a variable named "session". */
/*  * */
/*  *  @param[in]     level       log level, of type PEP_LOG_LEVEL */
/*  *  @param[in]     ...         the remaining parameters are exactly the same */
/*  *                             as in PEP_LOG_CRITICAL. */
/*  * */
/*  *  @warning       This macro is not the most convenient to use from C; the */
/*  *                 macros defined above such as PEP_LOG_CRITICAL and */
/*  *                 PEP_LOG_EVENT are more natural to write in most */
/*  *                 circumstances. */
/*  *\/ */
/* #define PEP_LOG_WITH_LEVEL(first, ...)                                        \ */
/*     do {                                                                      \ */
/*        /\* Capture the local variable named "session" -- static-scoping        \ */
/*           purists will not like this -- then call a less convenient macro     \ */
/*           doing the actual job.  The first parameter level is not in any way  \ */
/*           special, except for its position: defining a variadic macro with    \ */
/*           *zero* or more arguments in portable C can be annoying, but we can  \ */
/*           entirely avoid the complication here since there will be at least   \ */
/*           one parameter. *\/                                                   \ */
/*         PEP_SESSION _pEp_log_session = (session);                             \ */
/*                                                                               \ */
/*         /\* Do the actual work. *\/                                             \ */
/*         PEP_LOG_WITH_SESSION_AND_LEVEL(_pEp_log_session, (first),             \ */
/*                                        __VA_ARGS__);                          \ */
/*     } while (false) */

/**
 *  <!--       PEP_LOG_WITH_SESION_AND_LEVEL()       -->
 *
 * @brief Like PEP_LOG_CRITICAL, with two more parameters prepended
 *        to the others.
 *        Differently from PEP_LOG_CRITICAL this does not capture any
 *        variable named "session": the used session needs to be passed
 *        as a parameter.
 *
 *  @param[in]     session     pEp session
 *  @param[in]     level       log level, of type PEP_LOG_LEVEL
 *  @param[in]     ...         the remaining parameters are exactly the same
 *                             as in PEP_LOG_CRITICAL.
 *
 *  @warning       This macro is not the most convenient to use from C; the
 *                 macros defined above such as PEP_LOG_CRITICAL and
 *                 PEP_LOG_EVENT are more natural to write in most
 *                 circumstances.
 */
#define PEP_LOG_WITH_SESSION_AND_LEVEL(session, level, system, subsystem, ...)  \
    do {                                                                        \
        /* This is a good opportunity to update the current stack depth.  It    \
           is even a good idea to do this when *not* actually logging because   \
           of the current maximum level. */                                     \
        PEP_ICS_UPDATE;                                                         \
        /* The level argument will be a compile-time constant in almost every   \
           conceivable use case.  This is a good opportunity to optimise away   \
           the entire macro call when this entry exceeds the maximum            \
           verbosity. */                                                        \
        PEP_LOG_LEVEL _pEp_log_level = (level);                                 \
        if (_pEp_log_level > PEP_LOG_LEVEL_MAXIMUM)                             \
            break;                                                              \
                                                                                \
        char *_pEp_log_heap_string;                                             \
        char *_pEp_log_entry;                                                   \
        int _pEp_log_asprintf_result                                            \
          = pEp_asprintf(& _pEp_log_heap_string,                                \
                         /* Here the beginning of the expansion of __VA_ARGS__, \
                            if not empty, will be a literal string, which will  \
                            concatenate with "" with no harm; but if on the     \
                            other hand __VA_ARGS__ expands to nothing there     \
                            will still be a valid template.  This trick makes   \
                            it possible to use the logging facility to trace a  \
                            line number without supplying any explicit string   \
                            to print at all, not even "". */                    \
                         "" __VA_ARGS__);                                       \
        if (_pEp_log_heap_string == NULL || _pEp_log_asprintf_result < 0)       \
            /* Allocation failure.  This will be very hard to deal with, but    \
               we can make a desperate attempt of writing some memory           \
               allocation error to the log. */                                  \
            _pEp_log_entry = "could not heap-allocate log string!";             \
        else                                                                    \
            _pEp_log_entry = _pEp_log_heap_string;                              \
        /* Finally log. */                                                      \
        pEp_log((session),                                                      \
                (level),                                                        \
                (system),                                                       \
                (subsystem),                                                    \
                __FILE__,                                                       \
                __LINE__,                                                       \
                _ics_nest_level,                                                \
                PEP_func_OR_PRETTY_FUNCTION,                                    \
                _pEp_log_entry);                                                \
        free (_pEp_log_heap_string);                                            \
    } while (false)


/* Logging facility: functions
 * ***************************************************************** */

/* PEP_LOG_WITH_SESSION_AND_LEVEL , which despite its inconvenience is the heart
   of every user macro, ultimately relies on the following function.
   The function is not intended for the user, at least in C.  It might be
   convenient for wrapping in other languages. */

/**
 *  <!--       pEp_log()       -->
 *
 *  @brief Emit a log entry to the session destinations in PEP_LOG_DESTINATIONS,
 *         if its level does not pass the verbosity limit PEP_LOG_LEVEL_MAXIMUM.
 *
 *         The log entry time will be the current time.
 *
 *  @param[in]   session          session
 *  @param[in]   level            log level of the new entry
 *  @param[in]   system           the name of the system this log is about;
 *                                this is allowed to be NULL.
 *  @param[in]   subsystem        the name of the subsystem this log is about;
 *                                this is allowed to be NULL.
 *  @param[in]   source_file_name the source file name to log; this is meant
 *                                to be the expansion of __FILE__ at this
 *                                function's call site, but can also be NULL.
 *  @param[in]   source_file_line the source line number to log, 1-based; this
 *                                is meant to be the expansion of __LINE__ at
 *                                this function's call site.
 *  @param[in]   ics_nest_level   the nesting level, as stored in the automatic
 *                                variable _ics_nest_level .  See ics.h
 *  @param[in]   function_name    the function name to log; this is meant
 *                                to be the expansion of __func__ (or better
 *                                __PRETTY_FUNCTION__, when available) at this
 *                                function's call site, but can also be NULL.
 *  @param[in]   entry            the entry as a human-readable string
 *
 *  @retval PEP_ILLEGAL_VALUE     NULL session
 *  @retval PEP_STATUS_OK         success, if logging to *every* destination
 *                                succeeded
 *  @retval other values          logging to at least one destination failed
 *                                (the function always attempts to log to
 *                                *every* destination)
 *
 */
DYNAMIC_API PEP_STATUS pEp_log(PEP_SESSION session,
                               PEP_LOG_LEVEL level,
                               const char *system,
                               const char *subsystem,
                               const char *source_file_name,
                               int source_file_line,
                               int ics_nest_level,
                               const char *function_name,
                               const char *entry);


/* Initialisation and finalisation
 * ***************************************************************** */

/* These functions are used internally at the time of session initialisation and
   finalisation.  Not for the user. */
PEP_STATUS pEp_log_initialize(PEP_SESSION session);
PEP_STATUS pEp_log_finalize(PEP_SESSION session);


/* Set up
 * ***************************************************************** */

/* These are not API functions; they are called internally by configuration
   functions. */

/**
 *  <!--       pEp_log_set_synchronous_database()       -->
 *
 *  @brief Set database-destination logging to be synchronous or asynchronous,
 *         as demanded.  This does nothing if database is not among the
 *         destinations.
 *
 *  @param[in]   session          session
 *  @param[in]   synchronous      true iff database logging should be
 *                                synchronous.
 *
 *  @retval PEP_STATUS_OK         success
 *          any other value       failure to set -- should not happen
 */
PEP_STATUS pEp_log_set_synchronous_database(PEP_SESSION session,
                                            bool synchronous);


/* GNU/BSD formatted output emulation
 * ***************************************************************** */

/* Prototype for the non-standard GNU/BSD function asprintf, missing on windows,
   which performs formatted output on a malloc-allocated string to be freed by
   the caller.
   Set * string_pointer to NULL on allocation failure.

   This prototype needs to be in a header, since the function is called in the
   macroexpansion of logging functions, even out of the Engine.  This is a
   redefinition and not simply a function named asprintf on windows:
   unfortunately GCC likes to give warnings for empty format strings when used
   on recognised printf-like functions, and empty format strings here are
   useful; disabling selected warnings in *user* code is very messay.  Better to
   use our own differently-named function, and prevent the problem.. */
int pEp_asprintf(char **string_pointer, const char *template_, ...);


/* Compatibility
 * ***************************************************************** */

/* The new log system no longer supports this macro.  Let us make sure it is not
   used by mistake. */
#if defined(_PEP_SERVICE_LOG_OFF) || defined(NOLOG)
#   error "The macros _PEP_SERVICE_LOG_OFF and NOLOG are obsolete.  If you want"
#   error "to customise logging please define PEP_LOG_LEVEL_MAXIMUM and"
#   error "PEP_LOG_DESTINATIONS instead, which are well explained in the"
#   error "comments in src/pEp_log.h ."
#endif


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // #ifndef PEP_LOG_H

/*
  Local Variables:
    eval: (setq show-trailing-whitespace t indicate-empty-lines t)
    eval: (flyspell-mode t)
    eval: (ispell-change-dictionary "british")
  End:
*/
