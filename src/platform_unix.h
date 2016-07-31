#ifndef __APPLE__
#define _POSIX_C_SOURCE 200809L
#endif

#include <unistd.h>
#include <strings.h>
#include <sys/select.h>
#include <uuid/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *unix_local_db(void);

const char *gpg_conf(void);
const char *gpg_agent_conf(void);
const char *gpg_home(void);

#ifdef ANDROID

char *stpncpy(char *, const char *, size_t);
char *stpcpy(char *, const char *);

// Beware: predictable pseudo random with static seed!
// Only the lowest 31 bits are filled randomly.
long int random(void);

const char *android_system_db(void);
#define SYSTEM_DB android_system_db()
#define LIBGPGME "libgpgme.so"

#elif __APPLE__
#include "TargetConditionals.h"
#include <string.h>
#if TARGET_OS_IPHONE

extern char* SystemDB;
#define SYSTEM_DB SystemDB
    
#endif
#endif

#if !defined(BSD) && !defined(__APPLE__)
size_t strlcpy(char* dst, const	char* src, size_t size);
size_t strlcat(char* dst, const	char* src, size_t size);
#endif

#ifndef _UUID_STRING_T
#define _UUID_STRING_T
typedef char uuid_string_t[37];
#endif
#ifdef UUID
#undef UUID
#endif
// on *nix, uuid_t is an array and already implements pointer semantics
#define UUID uuid_t

#ifdef __cplusplus
}
#endif
