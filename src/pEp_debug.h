/**
 * @file    pEp_debug.h
 * @brief   pEp Engine debugging facilities
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_ENGINE_DEBUG_H
#define PEP_ENGINE_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>  // FIXME: remove unless used
#include <stdio.h>

#include "pEpEngine.h"
#include "pEp_log.h"    /* We log on requirement / assertion failure. */


/* Safety modes
 * ***************************************************************** */

/* The pEp Engine can be configured to follow exactly one of the following
   modes, according to the value of the macro PEP_SAFETY_MODE (see below).
   The Engine safety mode determines defensiveness and fatality (see below)
   for requirements and assertions. */
typedef enum {
    /* This mode is intended for production. */
    PEP_SAFETY_MODE_RELEASE    = 0,

    /* This mode is useful for debugging code which uses the Engine. */
    PEP_SAFETY_MODE_DEBUG      = 1,

    /* This mode is useful for debugging the Engine itself. */
    PEP_SAFETY_MODE_MAINTAINER = 2
} PEP_safety_mode;


/* Configuration
 * ***************************************************************** */

/* If the safety mode has not been defined on the command line use a sensible
   default.
   Notice that PEP_SAFETY_MODE_MAINTAINER is never the default: the few Engine
   developers will set that mode when needed, without inconveniencing the many
   Engine users. */
#if ! defined(PEP_SAFETY_MODE)
#   if defined(NDEBUG)
#       define PEP_SAFETY_MODE  PEP_SAFETY_MODE_RELEASE
#   else
#       define PEP_SAFETY_MODE  PEP_SAFETY_MODE_DEBUG
#   endif
#endif



/* Define defensiveness and fatality mode.
 * ***************************************************************** */

/* These constant expressions evaluate to non-false when we check for
   requirements or assertions at all; otherwise assertions and requirements
   will be completely ignored, with the condition not even computed.
   These Boolean values express *defensiveness*. */
#define PEP_CHECK_REQUIREMENTS  \
    true
#define PEP_CHECK_WEAK_ASSERTIONS  \
    true
#define PEP_CHECK_ASSERTIONS  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)

/* These constant expressions evaluate to non-false when failed checks should
   cause an abort.
   These Boolean values express *fatality*.

   Notice that abort is never actually called when the environment variable
   PEP_NOABORT is defined; see the comment for pEp_abort_unless_PEP_NOABORT.
   PEP_NOABORT is intended for use by the Engine developers in the test
   suite. */
#define PEP_ABORT_ON_VIOLATED_REQUIRE  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)
#define PEP_ABORT_ON_VIOLATED_WEAK_ASSERT  \
    (PEP_SAFETY_MODE == PEP_SAFETY_MODE_MAINTAINER)
#define PEP_ABORT_ON_VIOLATED_ASSERT  \
    (PEP_SAFETY_MODE >= PEP_SAFETY_MODE_DEBUG)


/* ICS
 * ***************************************************************** */

/* This must be expanded exactly once per function whenever the ICS
   functionality is used; after that point it will be possible to refer to the
   current ICS depth.  in practice it is convenient to have this macro expanded
   from PEP_REQUIRE, which is used once in almost every function.
   The expansion is *not* a single C statement or even a block; unfortunately
   we require the automatic variable _ics_nest_level to remain in scope
   throughout the function body. */
#define PEP_ICS_SET_FOR_THIS_FUNCTION  \
    ICS_ENTER(& session->ics_state);


/* Assertions and requirements
 * ***************************************************************** */

/* Here a "check" is either an assertion or a requirement. */

/* Complain to the log about a violated check. */
#define _PEP_LOG_VIOLATED_CHECK(logging_macro, what_as_string,   \
                                expression_as_string)            \
    logging_macro("p≡p", "Engine", what_as_string " violated: "  \
                  expression_as_string)

/* Emit a logging entry about the current function being entered, level Function
   -- as long as the feature is enabled via PEP_LOG_FUNCTION_ENTRY .  There is
   no need to pollute the output with anything more than the function name,
   which is always included anyway, and the logging level which is
   "function". */
#if defined (PEP_LOG_FUNCTION_ENTRY)
#   define _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED   \
    do {                                        \
        PEP_LOG_FUNCTION("p≡p", "Engine", "");  \
    } while (false)
#else
#   define _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED  \
    do {                                       \
    } while (false)
#endif

/* Same idea as LOG_FUNCTION_ENTRY, for local checks.  The argument is the
   expression whose evaluation failed.  Notice that this uses a captured
   variable of type PEP_STATUS named "status". */
#if defined (PEP_LOG_LOCAL_FAILURE)
#   define _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(expression_as_string)   \
        PEP_LOG_NONOK("p≡p", "Engine",                               \
                      "%s evaluated to %li %s",                      \
                      (expression_as_string),                        \
                      (long) status, pEp_status_to_string (status))
#else
#   define _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(expression_as_string)  \
    do { } while (false)
#endif

/* Perform a chack.  In case of failure log if appropriate according to the kind
   of check, and either execute the given statement or abort, as requested. */
#define _PEP_CHECK_ORELSE(logging_macro,                            \
                          what_as_string, expression_as_string,     \
                          check, abort_on_failure,                  \
                          expression, else_statement)               \
    do {                                                            \
        /* Before checking anything check that the session pointer  \
           is non-NULL; this makes it unnecessary for the user to   \
           check explicitly every time. */                          \
        if ((check) && (session) == NULL)  {                        \
            _PEP_LOG_VIOLATED_CHECK(logging_macro,                  \
                                    what_as_string " precondition", \
                                    "session != NULL");             \
            if (abort_on_failure)                                   \
                pEp_abort_unless_PEP_NOABORT(session);              \
            do {                                                    \
                else_statement;                                     \
            } while (false);                                        \
        }                                                           \
        if ((check) && ! (expression)) {                            \
            _PEP_LOG_VIOLATED_CHECK(logging_macro,                  \
                                    what_as_string,                 \
                                    expression_as_string);          \
            if (abort_on_failure)                                   \
                pEp_abort_unless_PEP_NOABORT(session);              \
            do {                                                    \
                else_statement;                                     \
            } while (false);                                        \
        }                                                           \
    } while (false)

/**
 *  <!--       PEP_ASSERT()       -->
 *
 *  @brief Expand to an assertion on the given expression.  The run-time
 *         behaviour depends on defensiveness and fatality mode.
 *
 *  @param[in]  expression     the expression asserted to be true
 *
 */
#define PEP_ASSERT(expression)                                              \
    _PEP_CHECK_ORELSE(PEP_LOG_CRITICAL, "assertion", # expression,          \
                      PEP_CHECK_ASSERTIONS, PEP_ABORT_ON_VIOLATED_ASSERT,   \
                      (expression), {})

/* An internal factor of PEP_WEAK_ASSERT_ORELSE, PEP_WEAK_ASSERT_ORELSE_RETURN
   and friends, PEP_WEAK_ASSERT_ORELSE_GOTO.  It is necessary to stringize
   expression into expression_as_string immediately after the first call from
   user code in order for the expression to be pritned non macro-expanded, which
   is highly desirable: for example we want to print "false" and not "0".  Of
   course expression_as_string should never be visible to the user. */
#define _PEP_WEAK_ASSERT_ORELSE(expression, expression_as_string,               \
                                else_statement)                                 \
    _PEP_CHECK_ORELSE(PEP_LOG_WARNING, "weak assertion", expression_as_string,  \
                      PEP_CHECK_WEAK_ASSERTIONS,                                \
                      PEP_ABORT_ON_VIOLATED_WEAK_ASSERT,                        \
                      (expression), else_statement)

/**
 *  <!--       PEP_WEAK_ASSERT_ORELSE()       -->
 *
 *  @brief Expand to a weak assertion on the given expression.  The
 *         run-time behaviour depends on defensiveness and fatality mode.
 *         Unless the fatality mode says that we should abort, on checked
 *         and violated assertion here we execute the given statement; this
 *         will usually either return a result or jump to a label
 *         performing some cleanup and then returning a result.
 *
 *  @param[in]  expression     the expression asserted to be true
 *  @param[in]  else_statement the statement to execute when we are checking,
 *                             the expression evaluates to false and we do not
 *                             abort on failure.
 *
 */
#define PEP_WEAK_ASSERT_ORELSE(expression, else_statement)  \
    _PEP_WEAK_ASSERT_ORELSE((expression), # expression,     \
                            else_statement)

/**
 *  <!--       PEP_WEAK_ASSERT_ORELSE_GOTO()       -->
 *
 *  @brief Like PEP_WEAK_ASSERT_ORELSE, but instead of a statement to execute
 *         in case of on checked and violated assertion this takes a label to
 *         jump to..
 *
 *  @param[in]  expression     the expression asserted to be true
 *  @param[in]  else_label     the label to jump to when we are checking, the
 *                             expression evaluates to false and we do not abort
 *                             on failure.
 *
 */
#define PEP_WEAK_ASSERT_ORELSE_GOTO(expression, label)   \
    _PEP_WEAK_ASSERT_ORELSE((expression), # expression,  \
                            { goto label; })

/**
 *  <!--       PEP_WEAK_ASSERT_ORELSE_RETURN()       -->
 *
 *  @brief Like PEP_WEAK_ASSERT_ORELSE, but instead of a statement to execute
 *         in case of on checked and violated assertion this takes a label to
 *         jump to..
 *
 *  @param[in]  expression     the expression asserted to be true
 *  @param[in]  else_result    the expression to evaluate for its result to
 *                             return when we are checking, the expression
 *                             evaluates to false and we do not abort on
 *                             failure.
 *
 */
#define PEP_WEAK_ASSERT_ORELSE_RETURN(expression, else_result)  \
    _PEP_WEAK_ASSERT_ORELSE((expression), # expression,         \
                            { return (else_result); })

/**
 *  <!--       PEP_WEAK_ASSERT_ORELSE_ILLEGAL_VALUE()       -->
 *
 *  @brief Like PEP_WEAK_ASSERT_ORELSE, without an explicit statement to execute
 *         in case of on checked and violated assertion.  In such a case the
 *         expansion of this macro just returns PEP_ILLEGAL_VALUE.
 *
 *  @param[in]  expression     the expression asserted to be true
 *
 */
#define PEP_WEAK_ASSERT_ORELSE_ILLEGAL_VALUE(expression)     \
    _PEP_WEAK_ASSERT_ORELSE((expression), # expression,      \
                            { return PEP_ILLEGAL_VALUE; } )

/**
 *  <!--       PEP_WEAK_ASSERT_ORELSE_NULL()       -->
 *
 *  @brief Like PEP_WEAK_ASSERT_ORELSE_ILLEGAL_VALUE, but instead of returning
 *         PEP_ILLEGAL_VALUE return NULL.
 *
 *  @param[in]  expression     the expression asserted to be true
 *
 */
#define PEP_WEAK_ASSERT_ORELSE_NULL(expression, label)   \
    _PEP_WEAK_ASSERT_ORELSE((expression), # expression,  \
                            { return NULL; } )

/* This has the same role as _PEP_WEAK_ASSERT_ORELSE.  See its comment. */
#define _PEP_REQUIRE_ORELSE(expression, expression_as_string,  \
                            else_statement)                    \
    /* Yes, this does not expand to a single statement or even to a block; but  \
       we need declarations from ICS_ENTER to be visible in the entire body     \
       this macro is called.*/                                                  \
    PEP_ICS_SET_FOR_THIS_FUNCTION;                                              \
    do {                                                                        \
        /* This is used at the beginning of more or less every function, so why \
           not getting this log entry for free?  Of course this will not be     \
           enabled in production because of PEP_LOG_LEVEL_MAXIMUM . */          \
        _PEP_LOG_FUNCTION_ENTRY_IF_ENABLED;                                     \
        _PEP_CHECK_ORELSE(PEP_LOG_ERROR, "requirement", expression_as_string,   \
                          PEP_CHECK_REQUIREMENTS, PEP_ABORT_ON_VIOLATED_REQUIRE,\
                          (expression), else_statement);                        \
    } while (false)

/**
 *  <!--       PEP_REQUIRE_ORELSE()       -->
 *
 *  @brief     Expand to a requirement, executing the given statement in case
 *             of failure, when not aborting.
 *
 *  @param[in]  expression       the expression required to be true
 *  @param[in]  else_expression  the expression to evaluate for its result, to
 *                               return in case of failure.
 *
 */
#define PEP_REQUIRE_ORELSE(expression, else_statement)               \
    _PEP_REQUIRE_ORELSE((expression), # expression, else_statement)

/**
 *  <!--       PEP_REQUIRE_ORELSE_RETURN()       -->
 *
 *  @brief     Expand to a requirement, returning the result of the
 *             evaluation of the given expression in case of non-aborting
 *             failure.
 *
 *  @param[in]  expression       the expression required to be true
 *  @param[in]  else_expression  the expression to evaluate for its result, to
 *                               return in case of failure.
 *
 */
#define PEP_REQUIRE_ORELSE_RETURN(expression, else_expression)  \
    _PEP_REQUIRE_ORELSE((expression), # expression,             \
                        { return (else_expression); })

/**
 *  <!--       PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE()       -->
 *
 *  @brief Expand to a requirement on the given expression.  In case of
 *         non-aborting failure execute the statement
 *           return PEP_ILLEGAL_VALUE;
 *
 *  @param[in]  expression     the expression required to be true
 *
 */
#define PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE(expression)  \
    _PEP_REQUIRE_ORELSE((expression), # expression,          \
                        { return PEP_ILLEGAL_VALUE; })

/**
 *  <!--       PEP_REQUIRE_ORELSE_RETURN_NULL()       -->
 *
 *  @brief Expand to a requirement on the given expression.  In case of
 *         non-aborting failure execute the statement
 *           return NULL;
 *
 *  @param[in]  expression     the expression required to be true
 *
 */
#define PEP_REQUIRE_ORELSE_RETURN_NULL(expression)   \
    _PEP_REQUIRE_ORELSE((expression), # expression,  \
                        { return NULL; })

/**
 *  <!--       PEP_REQUIRE()       -->
 *
 *  @brief A convenience short alias for PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE
 *         which is by far the most common use case of requirements.
 */
#define PEP_REQUIRE  PEP_REQUIRE_ORELSE_RETURN_ILLEGAL_VALUE

/**
 *  <!--       PEP_WEAK_ASSERT()       -->
 *
 *  @brief A convenience shorter alias for PEP_WEAK_ASSERT_ORELSE.
 */
#define PEP_WEAK_ASSERT  PEP_WEAK_ASSERT_ORELSE


/* Fatal assertion variants.
 * ***************************************************************** */

/* The common code in fatal assertion variants. */
#define _PEP_ASSERT_VARIANT(...)                     \
    do {                                             \
        PEP_LOG_CRITICAL("p≡p", NULL, __VA_ARGS__);  \
        PEP_ASSERT(false);                           \
    } while (false)


/**
 *  <!--       PEP_UNIMPLEMENTED()       -->
 *
 *  @brief Like PEP_UNREACHABLE with a different message for a different use.
 */
#define PEP_UNIMPLEMENTED  \
    _PEP_ASSERT_VARIANT("this functionality is not implemented yet")

/**
 *  <!--       PEP_UNREACHABLE()       -->
 *
 *  @brief Fail fatally, unless assertions are non-aborting, first logging an
 *         critical message appropriate for an "unreachable" situation.
 */
#define PEP_UNREACHABLE  \
    _PEP_ASSERT_VARIANT("this program point is supposed to be unreachable")

/**
 *  <!--       PEP_IMPOSSIBLE()       -->
 *
 *  @brief Like PEP_UNREACHABLE with a different message for a different use.
 */
#define PEP_IMPOSSIBLE  \
    _PEP_ASSERT_VARIANT("this is supposed to be impossible")

/**
 *  <!--       PEP_UNEXPECTED_VALUE()       -->
 *
 *  @brief Like PEP_UNREACHABLE with a different message for a different use.
 *         Show the unexpected integer value in the log.
 *         This is meant to be used in the default branch of switch statements
 *         which are supposed to be already complete.
 */
#define PEP_UNEXPECTED_VALUE(integer_value)                                 \
    do {                                                                    \
        long _pEp_unexpected_value = (long) (integer_value);                \
        _PEP_ASSERT_VARIANT("unexpected value 0x%lx %li",                   \
                            _pEp_unexpected_value, _pEp_unexpected_value);  \
    } while (false)


/* Utility macros for Boolean conditions.
 * ***************************************************************** */

/* This macro implements logical implication from the first Boolean expression
   to the second Boolean expression.
   The expansion evaluates to
     A → B  */
#define PEP_IMPLIES(boolean_expression_a, boolean_expression_b)  \
    /* A → B  is logically equivalent to  ¬A ∨ B */              \
    (! (boolean_expression_a) || (boolean_expression_b))

/* This macro implements the logical equivalence of the two given Boolean
   expressions, which is not a simple equality because of how truth values are
   handled in C, without a single normal form for the true value.
   The expansion evaluates to
     A ≡ B
   , sometimes written as
     A ↔ B  */
#define PEP_IFF(boolean_expression_a, boolean_expression_b)              \
    /* !X is guaranteed to evaluate to either 0 or 1 in ANSI C, for any  \
       expression X; we could use !! to normalise each expression to 0   \
       or 1, but instead of doing that we can just compare the two       \
       negated values. */                                                \
    (! (boolean_expression_a) == ! (boolean_expression_b))

/* Given an integer expression expand to an expression evaluating to a non-false
   value iff the integer expression evaluates to an even number.  The integer
   expression is allowed to evaluate to zero or to a negative number. */
#define PEP_EVEN(integer_expression)  \
    ((integer_expression) % 2 == 0)

/* Given an integer expression expand to an expression evaluating to a non-false
   value iff the integer expression evaluates to an odd number.  The integer
   expression is allowed to evaluate to zero or to a negative number. */
#define PEP_ODD(integer_expression)  \
    ((integer_expression) % 2 != 0) /* == 1  might not be portable. */


/* Handling status checks and local failure.  [TENTATIVE]
 * ***************************************************************** */

/* This API is tentative.  Volker does not like it and I am not very convinced
   myself.  It will probably go away.  Nobody should use it yet. */

#define _PEP_SET_STATUS_ORELSE(expression, else_statement,    \
                               ...)                           \
    do {                                                      \
        status = (expression);                                \
        if (status != PEP_STATUS_OK) {                        \
            _PEP_LOG_LOCAL_FAILURE_IF_ENABLED(# expression);  \
            do {                                              \
                __VA_ARGS__;                                  \
            } while (false);                                  \
            do {                                              \
                else_statement;                               \
            } while (false);                                  \
        }                                                     \
    } while (false)

#define PEP_SET_STATUS_ORELSE_GOTO(expression, label, ...)          \
    _PEP_SET_STATUS_ORELSE(expression, {goto label;}, __VA_ARGS__)

#define PEP_SET_STATUS_ORELSE_GOTO_END(expression, ...)         \
    PEP_SET_STATUS_ORELSE_GOTO(expression, end, __VA_ARGS__)
#define PEP_SET_STATUS_ORELSE_GOTO_ERROR(expression, ...)       \
    PEP_SET_STATUS_ORELSE_GOTO(expression, error, __VA_ARGS__)

#define ORELSE_GOTO        PEP_SET_STATUS_ORELSE_GOTO
#define ORELSE_GOTO_END    PEP_SET_STATUS_ORELSE_GOTO_END
#define ORELSE_GOTO_ERROR  PEP_SET_STATUS_ORELSE_GOTO_ERROR

#define PEP_SET_STATUS_ORELSE_RETURN(expression, else_result, ...)  \
    _PEP_SET_STATUS_ORELSE(expression, {return (else_result);}, __VA_ARGS__)


/* Internal functions.
 * ***************************************************************** */

/**
 *  <!--       pEp_abort_unless_PEP_NOABORT()       -->
 *
 *  @brief Call abort(3), unless the environment variable PEP_NOABORT is
 *         currently defined, to any value -- in which case do nothing.
 *         This function is useful to override the current fatality mode
 *         when running the test suite: when called from test cases pEp
 *         functions should always return failure codes, and never abort.
 *
 *         In order to help debugging this function even accepts a NULL
 *         session; when it receives no session this prints to stderr.
 */
DYNAMIC_API void pEp_abort_unless_PEP_NOABORT(PEP_SESSION session);


#ifdef __cplusplus

} /* extern "C" */
#endif

#endif // #ifndef PEP_ENGINE_DEBUG_H

/*
  Local Variables:
    eval: (setq show-trailing-whitespace t indicate-empty-lines t)
    eval: (flyspell-mode t)
    eval: (ispell-change-dictionary "british")
  End:
*/
