/**
 * @file    log.h
 * @brief   pEp logging facility
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

// (setq show-trailing-whitespace t indicate-empty-lines t)

#ifndef PEP_LOG_H
#define PEP_LOG_H

#include "pEpEngine.h"

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Debugging definitions for myself
 * ***************************************************************** */

#define PEP_LOG_LEVEL_MAXIMUM  PEP_LOG_LEVEL_EVERYTHING // FIXME: a test for myself, of course
#define PEP_LOG_DESTINATIONS   (PEP_LOG_DESTINATION_STDERR | PEP_LOG_DESTINATION_DATABASE)


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

/* A convenient way of using this facility for debugging prints is to define
   a CPP macro with a short name and only variadic parameters directly in the
   C file where it will be used; then one can add calls to the local macro in
   the functions being debugged.

   For example imagine a "frob" module in an unnamed application [FIXME:
   Shall I make the system name definable globally?] in frob.c:

   98   #define LOG(...) PEP_LOG_TRACE(NULL, "frob", __VA_ARGS__)
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
   source location.  The that the template is completely absent in that case:
   one does not even need to supply an empty string.

   Assuming PEP_LOG_LEVEL_MAXIMUM to be at least PEP_LOG_LEVEL_TRACE the log
   will contain something like:

   2022-09-23 20:39:13 frob Trace frob.c:101:foo About to call bar.  x is 10
   2022-09-23 20:39:13 frob Trace frob.c:109:bar Hello
   2022-09-23 20:39:13 frob Trace frob.c:104:foo y is 12
   2022-09-23 20:39:13 frob Trace frob.c:105:foo
*/


/* Parameters
 * ***************************************************************** */

/**
 *  @enum    PEP_LOG_LEVEL
 *
 *  @brief   This can be thought of the verbosity or redundance or
 *           non-importance or a log entry: the higher the value is, the less
 *           important the entry is.
 *
 *           Enabling logging at a certain level means that entries with more
 *           verbosity than the level are ignored.
 */
typedef enum {
    /* A strict lower limit: not intended for actual log entries. */
    PEP_LOG_LEVEL_NOTHING     =   0,

    /* Errors. */
    PEP_LOG_LEVEL_CRITICAL    =  10,
    PEP_LOG_LEVEL_ERROR       =  20,

    /* Warnings. */
    PEP_LOG_LEVEL_WARNING     = 100,
    PEP_LOG_LEVEL_BASIC       = PEP_LOG_LEVEL_WARNING,

    /* Events. */
    PEP_LOG_LEVEL_EVENT       = 200,
    PEP_LOG_LEVEL_API         = 210,
    PEP_LOG_LEVEL_SERVICE     = PEP_LOG_LEVEL_API,

    /* Debugging. */
    PEP_LOG_LEVEL_DEBUG       =  300,
    PEP_LOG_LEVEL_TRACE       =  310,

    /* A strict upper limit: not intended for actual log entries. */
    PEP_LOG_LEVEL_EVERYTHING  = 1000
} PEP_LOG_LEVEL;

/**
 *  @enum    PEP_LOG_DESTINATION_ENUM
 *
 *  @brief   Where to output log entries.  A bitwise-or combination of the
 *           enum values can be used: one copy will be printed to each
 *           destination.
 *           Not every platform will support every possibility; entries logged
 *           to an unsupported destination will simply be discarded.
 */
typedef enum {
    /* Discard log entries. */
    PEP_LOG_DESTINATION_NONE      =  0,

    /* Print log entries in text format to the standard output or the standard
       error stream. */
    PEP_LOG_DESTINATION_STDOUT    =  1,
    PEP_LOG_DESTINATION_STDERR    =  2,

    /* Send log entries to the syslog service. */
    PEP_LOG_DESTINATION_SYSLOG    =  4,

    /* Use the Android logging system. */
    PEP_LOG_DESTINATION_ANDROID   =  8,

    /* Add entries to a local database. */
    PEP_LOG_DESTINATION_DATABASE  = 16,
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
#       define PEP_LOG_LEVEL_MAXIMUM  PEP_LOG_LEVEL_NOTHING
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
 */
#if ! defined(PEP_LOG_DESTINATIONS)
    /* If the macro has not been defined already (likely from the build system)
       provide a default for it. */
#   if defined(NDEBUG)
#       define PEP_LOG_DESTINATIONS   PEP_LOG_LEVEL_DATABASE
#   else
#       define PEP_LOG_DESTINATIONS   (PEP_LOG_DESTINATION_STDERR       \
                                       | PEP_LOG_DESTINATION_DATABASE)
#   endif
#endif


/* Logging an entry: user macros
 * ***************************************************************** */

/**
 *  <!--       PEP_LOG_CRITICAL()       -->
 *
 *  @brief This macro expands to a C statement logging a message using the
 *         current session, found by capturing a variable named "session"
 *         (assumed to be of type PEP_SESSION) in the current scope.
 *
 *  @param[in]     ??? FIXME: document every parameter: this is important
 *                 ??? The template must be a literal string if supplied, but can be omitted altogether
 *                 ???????????????????????
 *
 */
#define PEP_LOG_CRITICAL(first, ...)                                  \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_CRITICAL, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_ERROR()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_ERROR(first, ...)                                  \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_ERROR, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_WARNING()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_WARNING(first, ...)                                  \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_WARNING, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_EVENT()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_EVENT(first, ...)                                  \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_EVENT, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_API()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_API(first, ...)                                  \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_API, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_DEBUG()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_DEBUG(first, ...)                                      \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_DEBUG, (first), __VA_ARGS__)

/**
 *  <!--       PEP_LOG_TRACE()       -->
 *  @brief Exactly like PEP_LOG_CRITICAL, with a different log level.
 */
#define PEP_LOG_TRACE(first, ...)                                      \
    PEP_LOG_WITH_LEVEL(PEP_LOG_LEVEL_TRACE, (first), __VA_ARGS__)


/* Logging facility: internal macros
 * ***************************************************************** */

/* The macros here are used internally to implement the user macros above. */

/**
 *  <!--       PEP_LOG_WITH_LEVEL()       -->
 *
 * @brief Exactly like PEP_LOG_CRITICAL, with one more parameter prepended
 *        to the others.
 *        Same caveat about capturing a variable named "session".
 *
 *  @param[in]     level       log level, of type PEP_LOG_LEVEL
 *  @param[in]     ...         the remaining parameters are exactly the same
 *                             as in PEP_LOG_CRITICAL.
 *
 *  @warning       This macro is not the most convenient to use from C; the
 *                 macros defined above such as PEP_LOG_CRITICAL and
 *                 PEP_LOG_EVENT are more natural to write in most
 *                 circumstances.
 */
#define PEP_LOG_WITH_LEVEL(first, ...)                                        \
    do {                                                                      \
       /* Capture the local variable named "session" -- static-scoping        \
          purists will not like this -- then call a less convenient macro     \
          doing the actual job.  The first parameter level is not in any way  \
          special, except for its position: defining a variadic macro with    \
          *zero* or more arguments in portable C can be annoying, but we can  \
          entirely avoid the complication here since there will be at least   \
          one parameter. */                                                   \
        PEP_SESSION _pEp_log_session = (session);                             \
                                                                              \
        /* Do the actual work. */                                             \
        PEP_LOG_WITH_SESSION_AND_LEVEL(_pEp_log_session, (first),             \
                                       __VA_ARGS__);                          \
    } while (false)

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
        int _pEp_log_vasprintf_result                                           \
          = pEp_asprintf(& _pEp_log_heap_string,                                \
                         /* Here the beginning of the expansion of              \
                            __VA_ARGS__, if not empty, will be a literal        \
                            string, which will concatenate with "" with no      \
                            harm; but if on the other hand __VA_ARGS__ expands  \
                            to nothing there will still be a valid template.    \
                            This trick makes it possible to use the logging     \
                            facility to trace a line number without supplying   \
                            any explicit string to print at all, not even       \
                            "". */                                              \
                         "" __VA_ARGS__);                                       \
        if (_pEp_log_heap_string == NULL || _pEp_log_vasprintf_result < 0)      \
            /* Allocation failure.  This will be very hard to deal with, but    \
               we can make a desperate attempt of writing some memory           \
               allocation error to the log. */                                  \
            _pEp_log_entry = "could not heap-allocate log string!";             \
        else                                                                    \
            _pEp_log_entry = _pEp_log_heap_string;                              \
        pEp_log((session),                                                      \
                (level),                                                        \
                (system),                                                       \
                (subsystem),                                                    \
                __FILE__,                                                       \
                __LINE__,                                                       \
                __func__,                                                       \
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
 *  @param[in]   function_name    the function name to log; this is meant
 *                                to be the expansion of __func__ at this
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
                               const char *function_name,
                               const char *entry);


/* Logging facility: internal functions implementation
 * ***************************************************************** */

/* A portable implementations of the non-standard GNU/BSD function asprintf
   which performs formatted output on a malloc-allocated string, to be freed by
   the user.  Set * string_pointer to NULL on allocation failure. */
int pEp_asprintf(char **string_pointer, const char *template, ...);


/* Initialisation and finalisation
 * ***************************************************************** */

/* These functions are used internally at the time of session initialisation and
   finalisation.  Not for the user. */
PEP_STATUS pEp_log_initialize(PEP_SESSION session);
PEP_STATUS pEp_log_finalize(PEP_SESSION session);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // #ifndef PEP_LOG_H
