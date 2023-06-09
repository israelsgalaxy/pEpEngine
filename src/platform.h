/**
 * @file     platform.h
 * @brief    Checks platform values and causes the appropriate platform-specific header to be included
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Right now z/OS is not mutually exclusive with the other platforms: the way we
   use it, it is a flavour of Unix... */
#if defined (__MVS__)
# include "platform_zos.h"
#endif

/* ...However the other platforms are indeed mutually exclusive, for the
   purposes of the platform_* files in the engine. */
#if defined (UNIX)
# include "platform_unix.h"
#elif defined (_WIN32)
# include "platform_windows.h"
#else
  /* Unix is the default: this is useful for installed headers. */
# include "platform_unix.h"
#endif


/* Functions implemented in a different way according to the platform
 * ***************************************************************** */

/**
 *  <!--       pEp_fnmatch()       -->
 *
 *  @brief A portability wrapper meant to provide functionality equivalent to
 *         Unix fnmatch(3) with the default flags, on every platform.
 *         Return zero iff the string matches the pattern with Unix-style
 *         wildcards ("?" and "*").  This does not access the filesystem or
 *         check the existence of files.
 *
 *  @param[in]   pattern          the pattern including Unix-style wildcards
 *                                "?" and "*".
 *  @param[in]   string           the string being matched against the pattern.
 *
 *  @retval 0                     match
 *  @retval a non-zero value      no match
 *
 */
int pEp_fnmatch(const char *pattern, const char *string);

/**
 *  <!--       pEp_sleep_ms()       -->
 *
 *  @brief Sleep for the given number of milliseconds.  If interrupted by a
 *         signal continue sleeping until the given total sleep time is
 *         reached.
 *
 *  @param[in]   ms           The number of milliseconds to sleep for.
 */
void pEp_sleep_ms(unsigned long ms);

/**
 *  <!--       pEp_pid_and_tid()       -->
 *
 *  @brief A struct containing a thread id and a process Id.  See the comment
 *         before pEp_get_pid_and_tid
 */
struct pEp_pid_and_tid {
    /* A process identifier as an integer number: this might be larger than
       needed, but will always be possible to print. */
    int64_t pid;

    /* A thread identifier.  See above.*/
    int64_t tid;
};

/**
 *  <!--       pEp_set_pid_and_tid()       -->
 *
 *  @brief Fill the pointed struct setting the current process id and thread id.
 *         This could have been done differently, providing emulation of POSIX
 *         functions where missed; still this solution is more general, and
 *         allows for wider identifiers, with the same size on every platform.
 *         It is not really necessary that these identifiers are consistent
 *         with system APIs: they just need to be consistent with themselves
 *         when used as part of logging.
 *         This function always succeeeds.
 *
 *  @param[in]   pid_and_tid      a pointer to the struct to be filled.
 *
 */
void pEp_set_pid_and_tid(struct pEp_pid_and_tid *pid_and_tid);


/* Feature macros
 * ***************************************************************** */

/* Nothing interesting here.  But in the "Feature macros" section of each
   platform-specifid header file there will be feature macros definitions,
   as poor man's approximation of what a configure script would discover.

   This is particuarly useful for features implemented as CPP macros. */

#ifdef __cplusplus
}
#endif

#endif
