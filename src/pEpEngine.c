/** 
 * @file pEpEngine.c 
 * @brief implementation of the pEp Engine API
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "cryptotech.h"
#include "transport.h"
#include "KeySync_fsm.h"
#include "echo_api.h"
#include "media_key.h"
#include "engine_sql.h"
#include "pEp_log.h"
#include "status_to_string.h"
#include "string_utilities.h"

#include <time.h>
#include <stdlib.h>


void
__sql_reset_and_clear_bindings(sqlite3_stmt *s)
{
    assert(s != NULL);

    sqlite3_reset(s);
    sqlite3_clear_bindings(s);
} 

static volatile int init_count = -1;

DYNAMIC_API PEP_STATUS init(
        PEP_SESSION *session,
        messageToSend_t messageToSend,
        inject_sync_event_t inject_sync_event,
        ensure_passphrase_t ensure_passphrase
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    // Initialise the path cache.  It is the state of the environment at this
    // time that determines path names, unless the path cache is explicitly
    // reset later.
    status = reset_path_cache ();
    if (status != PEP_STATUS_OK)
        return status;

    bool in_first = false;

    // a little race condition - but still a race condition
    // mitigated by calling caveat (see documentation)

    // this increment is made atomic IN THE ADAPTERS by
    // guarding the call to init with the appropriate mutex.
    int _count = ++init_count;
    if (_count == 0)
        in_first = true;
    
    // Race condition mitigated by calling caveat starts here :
    // If another call to init() preempts right now, then preemptive call
    // will have in_first false, will not create SQL tables, and following
    // calls relying on those tables will fail.
    //
    // Therefore, as above, adapters MUST guard init() with a mutex.
    // 
    // Therefore, first session
    // is to be created and last session to be deleted alone, and not
    // concurently to other sessions creation or deletion.
    // We expect adapters to enforce this either by implicitely creating a
    // client session, or by using synchronization primitive to protect
    // creation/deletion of first/last session from the app.

    if (session == NULL)
        return PEP_ILLEGAL_VALUE;

    *session = NULL;

    pEpSession *_session = calloc(1, sizeof(pEpSession));
    assert(_session);
    if (_session == NULL)
        goto enomem;

    /* Remember if this session is indeed the first, which may be useful when
       initialising subsystems. */
    _session->first_session_at_init_time = in_first;

    _session->version = PEP_ENGINE_VERSION;
    _session->messageToSend = messageToSend;
    _session->inject_sync_event = inject_sync_event;
    _session->ensure_passphrase = ensure_passphrase;
    _session->enable_echo_protocol = true;
    _session->enable_echo_in_outgoing_message_rating_preview = true;

    /* Logging is off by default, unless the environment variable PEP_LOG is
       defined to any value.  Logging can also be enabled by the configuration
       call config_enable_log . */
    _session->enable_log = (getenv("PEP_LOG") != NULL);

    /* Database-logging is synchronous by default, unless the environment
       variable PEP_LOG_ASYNC is defined, to any value. */
    config_enable_log_synchronous(_session, (getenv("PEP_LOG_ASYNC") == NULL));

    /* There are no nested SQL transactions in progress yet. */
    _session->transaction_in_progress_no = 0;

    status = pEp_log_initialize(_session);
    if (status != PEP_STATUS_OK)
        return status;

    /* Since here there is no variable named "session" to capture we cannot use
       the ordinary PEP_LOG_* macros.  But it is very easy to define an
       automatic variable temporarily. */
#define _INTERNAL_LOG_WITH_MACRO_NAME(name, ...)         \
    do {                                        \
        PEP_SESSION session = _session;         \
        name("p≡p", "Engine", "" __VA_ARGS__);  \
    } while (false)
#define _LOG_CRITICAL(...) _INTERNAL_LOG_WITH_MACRO_NAME(PEP_LOG_CRITICAL, __VA_ARGS__)
#define _LOG_ERROR(...)  _INTERNAL_LOG_WITH_MACRO_NAME(PEP_LOG_ERROR, __VA_ARGS__)
#define _LOG_EVENT(...)  _INTERNAL_LOG_WITH_MACRO_NAME(PEP_LOG_EVENT, __VA_ARGS__)
#define _LOG_API(...)    _INTERNAL_LOG_WITH_MACRO_NAME(PEP_LOG_API, __VA_ARGS__)
#define _LOG_TRACE(...)  _INTERNAL_LOG_WITH_MACRO_NAME(PEP_LOG_TRACE, __VA_ARGS__)

    /* Initialise the management and system databases, but not the log database
       (which has been initialised already if needed). */
    status = pEp_sql_init(_session);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // We need to init a few globals for message id that we'd rather not
    // calculate more than once.
    if (in_first)
        _init_globals();

    status = init_cryptotech(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = init_transport_system(_session, in_first);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = echo_initialize(_session);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // Make sure that we have been consistent in linking a version SQLite3
    // maching its headers.
    if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER) {
        _LOG_CRITICAL("inconsistent SQLite versions: library %li headers %li",
                      (long) sqlite3_libversion_number(), (long) SQLITE_VERSION_NUMBER);
        // Failing would be the right thing here, but many configurations seem
        // this problem; disabling it for the time being.
        // assert(false);
    }
    _LOG_EVENT("p≡p Engine %s   protocol %s   SQLite %s",
               PEP_ENGINE_VERSION, PEP_PROTOCOL_VERSION,
               sqlite3_libversion());
    _LOG_API("initialise session %p", _session);

    // runtime config

    // Will now be called by adapter.
    // // clean up invalid keys 
    // status = clean_own_key_defaults(_session);
    // if (status != PEP_STATUS_OK)
    //     goto pEp_error;

    *session = _session;

    // Note: Following statement is NOT for any cryptographic/secure functionality; it is
    //       ONLY used for some randomness in generated outer message ID, which are
    //       required by the RFC to be globally unique!
    srand((unsigned int) time(NULL));

#if 0
    // import positron's testing media key.
    const char key_data[]
        =
#include "media_key_example.h"
        ;
    PEP_STATUS s = PEP_STATUS_OK;
    s = import_key(_session, key_data, sizeof(key_data), NULL);
    _LOG_TRACE("Import positron's testing key: %s %.4x\n", pEp_status_to_string(s), (int) s);
    s = import_key(_session, key_data, sizeof(key_data), NULL);
    _LOG_TRACE("Import positron's testing key again: %s %.4x\n", pEp_status_to_string(s), (int) s);
    stringpair_list_t *media_key_map
        = new_stringpair_list(new_stringpair("*ageinghacker.net",
                                             /* mixed case, on purpose. */
                                             "8A7E7F89493766693c03f941d35d42584008ee76"));
    config_media_keys(_session, media_key_map);
    free_stringpair_list(media_key_map);
#endif

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    _LOG_ERROR("failed at init for session %p: 0x%x %i %s", session,
               (int) status, (int) status, pEp_status_to_string(status));
    release(_session);
    return status;
#undef _INTERNAL_LOG_WITH_MACRO_NAME
#undef _LOG_ERROR
#undef _LOG_EVENT
#undef _LOG_API
#undef _LOG_TRACE
}

DYNAMIC_API void release(PEP_SESSION session)
{
    PEP_REQUIRE_ORELSE(session, { return; });

    LOG_API("finalising session %p", session);
    bool out_last = false;
    int _count = --init_count;
    if (_count < -1)
        LOG_CRITICAL("_count is wrong: %i", _count);
    // a small race condition but still a race condition
    // mitigated by calling caveat (see documentation)
    // (release() is to be guarded by a mutex by the caller)
    if (_count == -1)
        out_last = true;

    if (session->transaction_in_progress_no != 0)
        LOG_CRITICAL("at least an SQL transaction was not closed: there are"
                     " %i nested transactions in progress at finalisation time",
                     (int) session->transaction_in_progress_no);

    /* Free local data. */
    free(session->sql_status_text);

    free_Sync_state(session);

    /* Clear the path cache, releasing a little memory. */
    if (out_last)
        clear_path_cache();

    /* Finalise the Echo subsystem, which uses the management database... */
    echo_finalize(session);

    /* ... And then finalise the database subsystem. */
    pEp_sql_finalize(session, out_last);

    if (!EMPTYSTR(session->curr_passphrase)) {
        free (session->curr_passphrase);
        /* In case the following freeing code still uses the field. */
        session->curr_passphrase = NULL;
    }

    release_transport_system(session, out_last);
    release_cryptotech(session, out_last);
    LOG_API("session %p finalised", session);
    pEp_log_finalize(session);
    free(session);
}

/* Return true iff PEP_STATUS has one of the intended values.  This never
   fails. */
static bool PEP_STATUS_is_valid(PEP_STATUS status)
{
    switch (status) {
    case PEP_STATUS_OK:
    case PEP_INIT_CANNOT_LOAD_CRYPTO_LIB:
    case PEP_INIT_CRYPTO_LIB_INIT_FAILED:
    case PEP_INIT_NO_CRYPTO_HOME:
    /* case PEP_INIT_NETPGP_INIT_FAILED: */ /* obsolete */
    case PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION:
    case PEP_INIT_UNSUPPORTED_CRYPTO_VERSION:
    case PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT:
    case PEP_INIT_SQLITE3_WITHOUT_MUTEX:
    case PEP_INIT_CANNOT_OPEN_DB:
    case PEP_INIT_CANNOT_OPEN_SYSTEM_DB:
    case PEP_INIT_DB_DOWNGRADE_VIOLATION:
    case PEP_UNKNOWN_DB_ERROR:
    case PEP_KEY_NOT_FOUND:
    case PEP_KEY_HAS_AMBIG_NAME:
    case PEP_GET_KEY_FAILED:
    case PEP_CANNOT_EXPORT_KEY:
    case PEP_CANNOT_EDIT_KEY:
    case PEP_KEY_UNSUITABLE:
    case PEP_MALFORMED_KEY_RESET_MSG:
    case PEP_KEY_NOT_RESET:
    case PEP_CANNOT_DELETE_KEY:
    case PEP_KEY_IMPORTED:
    case PEP_NO_KEY_IMPORTED:
    case PEP_KEY_IMPORT_STATUS_UNKNOWN:
    case PEP_SOME_KEYS_IMPORTED:
    case PEP_CANNOT_FIND_IDENTITY:
    case PEP_CANNOT_SET_PERSON:
    case PEP_CANNOT_SET_PGP_KEYPAIR:
    case PEP_CANNOT_SET_IDENTITY:
    case PEP_CANNOT_SET_TRUST:
    case PEP_KEY_BLACKLISTED:
    case PEP_CANNOT_FIND_PERSON:
    case PEP_CANNOT_SET_PEP_PROTOCOL_VERSION:
    /* case PEP_CANNOT_SET_PEP_VERSION: */ /* obsolete alias */
    case PEP_CANNOT_FIND_ALIAS:
    case PEP_CANNOT_SET_ALIAS:
    case PEP_NO_OWN_USERID_FOUND:
    case PEP_UNENCRYPTED:
    case PEP_VERIFIED:
    case PEP_DECRYPTED:
    case PEP_DECRYPTED_AND_VERIFIED:
    case PEP_DECRYPT_WRONG_FORMAT:
    case PEP_DECRYPT_NO_KEY:
    case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH:
    case PEP_VERIFY_NO_KEY:
    case PEP_VERIFIED_AND_TRUSTED:
    case PEP_CANNOT_REENCRYPT:
    case PEP_VERIFY_SIGNER_KEY_REVOKED:
    case PEP_CANNOT_DECRYPT_UNKNOWN:
    case PEP_TRUSTWORD_NOT_FOUND:
    case PEP_TRUSTWORDS_FPR_WRONG_LENGTH:
    case PEP_TRUSTWORDS_DUPLICATE_FPR:
    case PEP_CANNOT_CREATE_KEY:
    case PEP_CANNOT_SEND_KEY:
    case PEP_PHRASE_NOT_FOUND:
    case PEP_SEND_FUNCTION_NOT_REGISTERED:
    case PEP_CONTRAINTS_VIOLATED:
    case PEP_CANNOT_ENCODE:
    case PEP_SYNC_NO_NOTIFY_CALLBACK:
    case PEP_SYNC_ILLEGAL_MESSAGE:
    case PEP_SYNC_NO_INJECT_CALLBACK:
    case PEP_SYNC_NO_CHANNEL:
    case PEP_SYNC_CANNOT_ENCRYPT:
    case PEP_SYNC_NO_MESSAGE_SEND_CALLBACK:
    case PEP_SYNC_CANNOT_START:
    case PEP_CANNOT_INCREASE_SEQUENCE:
    case PEP_STATEMACHINE_ERROR:
    case PEP_NO_TRUST:
    case PEP_STATEMACHINE_INVALID_STATE:
    case PEP_STATEMACHINE_INVALID_EVENT:
    case PEP_STATEMACHINE_INVALID_CONDITION:
    case PEP_STATEMACHINE_INVALID_ACTION:
    case PEP_STATEMACHINE_INHIBITED_EVENT:
    case PEP_STATEMACHINE_CANNOT_SEND:
    case PEP_PASSPHRASE_REQUIRED:
    case PEP_WRONG_PASSPHRASE:
    case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED:
    case PEP_CANNOT_CREATE_GROUP:
    case PEP_CANNOT_FIND_GROUP_ENTRY:
    case PEP_GROUP_EXISTS:
    case PEP_GROUP_NOT_FOUND:
    case PEP_CANNOT_ENABLE_GROUP:
    case PEP_CANNOT_DISABLE_GROUP:
    case PEP_CANNOT_ADD_GROUP_MEMBER:
    case PEP_CANNOT_DEACTIVATE_GROUP_MEMBER:
    case PEP_NO_MEMBERSHIP_STATUS_FOUND:
    case PEP_CANNOT_LEAVE_GROUP:
    case PEP_CANNOT_JOIN_GROUP:
    case PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO:
    case PEP_DISTRIBUTION_ILLEGAL_MESSAGE:
    case PEP_STORAGE_ILLEGAL_MESSAGE:
    case PEP_PEPMESSAGE_ILLEGAL_MESSAGE:
    case PEP_TRANSPORT_CANNOT_INIT:
    case PEP_TRANSPORT_CANNOT_INIT_SEND:
    case PEP_TRANSPORT_CANNOT_INIT_RECV:
    case PEP_TRANSPORT_DOWN:
    case PEP_TRANSPORT_ERROR:
    case PEP_COMMIT_FAILED:
    case PEP_MESSAGE_CONSUME:
    case PEP_MESSAGE_IGNORE:
    case PEP_CANNOT_CONFIG:
    case PEP_UNBOUND_ENVIRONMENT_VARIABLE:
    case PEP_PATH_SYNTAX_ERROR:
    case PEP_RECORD_NOT_FOUND:
    case PEP_CANNOT_CREATE_TEMP_FILE:
    case PEP_ILLEGAL_VALUE:
    case PEP_BUFFER_TOO_SMALL:
    case PEP_OUT_OF_MEMORY:
    case PEP_UNKNOWN_ERROR:
    case PEP_VERSION_MISMATCH:
        return true;

    default:
        return false;
    }
}

DYNAMIC_API bool PEP_STATUS_is_error(PEP_STATUS status)
{
    /* Crash visibly if the status is wrong. */
    assert(PEP_STATUS_is_valid(status));

    /* This is for when assertions are disabled.  Even if the behaviour is not
       documented because I do not want to encourage users to use invalid
       statuses, it is safer to consider a wrong status as an error: the caller
       will check it. */
    if (! PEP_STATUS_is_valid(status))
        return true;

    /* Now, judge each case: */
    switch (status) {
    case PEP_STATUS_OK:
    case PEP_KEY_NOT_FOUND:              // questionable
    case PEP_KEY_IMPORTED:
    case PEP_NO_KEY_IMPORTED:
    case PEP_KEY_IMPORT_STATUS_UNKNOWN:  // questionable: never used anyway
    case PEP_SOME_KEYS_IMPORTED:
    case PEP_UNENCRYPTED:
    case PEP_VERIFIED:
    case PEP_DECRYPTED:
    case PEP_DECRYPTED_AND_VERIFIED:
    case PEP_VERIFIED_AND_TRUSTED:
    case PEP_PASSPHRASE_REQUIRED:               // questionable
    case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED:  // questionable
    case PEP_VERIFY_SIGNER_KEY_REVOKED:
        return false;

    case PEP_INIT_CANNOT_LOAD_CRYPTO_LIB:
    case PEP_INIT_CRYPTO_LIB_INIT_FAILED:
    case PEP_INIT_NO_CRYPTO_HOME:
    /* case PEP_INIT_NETPGP_INIT_FAILED: */ /* obsolete */
    case PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION:
    case PEP_INIT_UNSUPPORTED_CRYPTO_VERSION:
    case PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT:
    case PEP_INIT_SQLITE3_WITHOUT_MUTEX:
    case PEP_INIT_CANNOT_OPEN_DB:
    case PEP_INIT_CANNOT_OPEN_SYSTEM_DB:
    case PEP_INIT_DB_DOWNGRADE_VIOLATION:
    case PEP_UNKNOWN_DB_ERROR:
    case PEP_KEY_HAS_AMBIG_NAME:
    case PEP_GET_KEY_FAILED:
    case PEP_CANNOT_EXPORT_KEY:
    case PEP_CANNOT_EDIT_KEY:
    case PEP_KEY_UNSUITABLE:
    case PEP_MALFORMED_KEY_RESET_MSG:
    case PEP_KEY_NOT_RESET:
    case PEP_CANNOT_DELETE_KEY:
    case PEP_CANNOT_FIND_IDENTITY:
    case PEP_CANNOT_SET_PERSON:
    case PEP_CANNOT_SET_PGP_KEYPAIR:
    case PEP_CANNOT_SET_IDENTITY:
    case PEP_CANNOT_SET_TRUST:
    case PEP_KEY_BLACKLISTED: /* no longer used */
    case PEP_CANNOT_FIND_PERSON:
    case PEP_CANNOT_SET_PEP_PROTOCOL_VERSION:
    /* case PEP_CANNOT_SET_PEP_VERSION: */ /* obsolete alias */
    case PEP_CANNOT_FIND_ALIAS:
    case PEP_CANNOT_SET_ALIAS:
    case PEP_NO_OWN_USERID_FOUND:
    case PEP_DECRYPT_WRONG_FORMAT:
    case PEP_DECRYPT_NO_KEY:
    case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH:  /* questionable but I think this should not be ignored */
    case PEP_VERIFY_NO_KEY:
    case PEP_CANNOT_REENCRYPT:
    case PEP_CANNOT_DECRYPT_UNKNOWN:
    case PEP_TRUSTWORD_NOT_FOUND:
    case PEP_TRUSTWORDS_FPR_WRONG_LENGTH:
    case PEP_TRUSTWORDS_DUPLICATE_FPR:
    case PEP_CANNOT_CREATE_KEY:
    case PEP_CANNOT_SEND_KEY:
    case PEP_PHRASE_NOT_FOUND:
    case PEP_SEND_FUNCTION_NOT_REGISTERED:
    case PEP_CONTRAINTS_VIOLATED:
    case PEP_CANNOT_ENCODE:
    case PEP_SYNC_NO_NOTIFY_CALLBACK:
    case PEP_SYNC_ILLEGAL_MESSAGE:
    case PEP_SYNC_NO_INJECT_CALLBACK:
    case PEP_SYNC_NO_CHANNEL:
    case PEP_SYNC_CANNOT_ENCRYPT:
    case PEP_SYNC_NO_MESSAGE_SEND_CALLBACK:
    case PEP_SYNC_CANNOT_START:
    case PEP_CANNOT_INCREASE_SEQUENCE:
    case PEP_STATEMACHINE_ERROR:
    case PEP_NO_TRUST:
    case PEP_STATEMACHINE_INVALID_STATE:
    case PEP_STATEMACHINE_INVALID_EVENT:
    case PEP_STATEMACHINE_INVALID_CONDITION:
    case PEP_STATEMACHINE_INVALID_ACTION:
    case PEP_STATEMACHINE_INHIBITED_EVENT:
    case PEP_STATEMACHINE_CANNOT_SEND:
    case PEP_WRONG_PASSPHRASE:
    case PEP_CANNOT_CREATE_GROUP:
    case PEP_CANNOT_FIND_GROUP_ENTRY:
    case PEP_GROUP_EXISTS:
    case PEP_GROUP_NOT_FOUND:
    case PEP_CANNOT_ENABLE_GROUP:
    case PEP_CANNOT_DISABLE_GROUP:
    case PEP_CANNOT_ADD_GROUP_MEMBER:
    case PEP_CANNOT_DEACTIVATE_GROUP_MEMBER:
    case PEP_NO_MEMBERSHIP_STATUS_FOUND:
    case PEP_CANNOT_LEAVE_GROUP:
    case PEP_CANNOT_JOIN_GROUP:
    case PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO:
    case PEP_DISTRIBUTION_ILLEGAL_MESSAGE:
    case PEP_STORAGE_ILLEGAL_MESSAGE:
    case PEP_PEPMESSAGE_ILLEGAL_MESSAGE:
    case PEP_TRANSPORT_CANNOT_INIT:
    case PEP_TRANSPORT_CANNOT_INIT_SEND:
    case PEP_TRANSPORT_CANNOT_INIT_RECV:
    case PEP_TRANSPORT_DOWN:
    case PEP_TRANSPORT_ERROR:
    case PEP_COMMIT_FAILED:
    case PEP_MESSAGE_CONSUME:
    case PEP_MESSAGE_IGNORE:
    case PEP_CANNOT_CONFIG:
    case PEP_UNBOUND_ENVIRONMENT_VARIABLE:
    case PEP_PATH_SYNTAX_ERROR:
    case PEP_RECORD_NOT_FOUND:
    case PEP_CANNOT_CREATE_TEMP_FILE:
    case PEP_ILLEGAL_VALUE:
    case PEP_BUFFER_TOO_SMALL:
    case PEP_OUT_OF_MEMORY:
    case PEP_UNKNOWN_ERROR:
    case PEP_VERSION_MISMATCH:
        return true;

    default:
        /* This is meant to be unreachable. */
        assert(false);
    }

}

DYNAMIC_API void config_enable_echo_protocol(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->enable_echo_protocol = enable;
}

DYNAMIC_API void config_enable_echo_in_outgoing_message_rating_preview(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->enable_echo_in_outgoing_message_rating_preview = enable;
}

DYNAMIC_API void config_enable_log(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->enable_log = enable;
}

DYNAMIC_API void config_enable_log_synchronous(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->enable_log_synchronous = enable;

    /* The actual functionality is implemented in the logging compilation
       unit, which of course uses SQL. */
    PEP_STATUS status = pEp_log_set_synchronous_database(session, enable);
    if (status != PEP_STATUS_OK)
        LOG_ERROR("pEp_log_set_synchronous_database failed");
    else
        LOG_EVENT("database-destination logging is now %s",
                  (enable ? "SYNCHRONOUS" : "Asynchronous"));
}

DYNAMIC_API void config_passive_mode(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->passive_mode = enable;
}

DYNAMIC_API void config_unencrypted_subject(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    session->unencrypted_subject = enable;
}

DYNAMIC_API PEP_STATUS config_passphrase(PEP_SESSION session, const char *passphrase) {
    PEP_REQUIRE(session);

    PEP_STATUS status = PEP_STATUS_OK;
    free(session->curr_passphrase);
    if (!passphrase)
        session->curr_passphrase = NULL;
    else {
        session->curr_passphrase = strdup(passphrase);
        if (!session->curr_passphrase)
            status = PEP_OUT_OF_MEMORY;
    }
    return status;
}

DYNAMIC_API PEP_STATUS config_passphrase_for_new_keys(PEP_SESSION session, bool enable, const char *passphrase) {
    PEP_REQUIRE(session);

    session->new_key_pass_enable = enable;
    PEP_STATUS status = PEP_STATUS_OK;

    free(session->generation_passphrase);
    if (EMPTYSTR(passphrase)) {
        session->generation_passphrase = NULL;
    } else {
        session->generation_passphrase = strdup(passphrase);
        if (!session->generation_passphrase)
            status = PEP_OUT_OF_MEMORY;
    }
    return status;    
}

DYNAMIC_API void config_service_log(PEP_SESSION session, bool enable)
{
    PEP_REQUIRE_ORELSE(session, { return; });
    DEPRECATED;
    session->service_log = enable;
}

DYNAMIC_API PEP_STATUS trustword(
            PEP_SESSION session, uint16_t value, const char *lang,
            char **word, size_t *wsize
        )
{
    PEP_REQUIRE(session && word && wsize);
    PEP_STATUS status = PEP_STATUS_OK;

    *word = NULL;
    *wsize = 0;

    if (lang == NULL)
        lang = "en";

    // FIXME: should this not be an actual check???
    PEP_ASSERT((lang[0] >= 'A' && lang[0] <= 'Z')
               || (lang[0] >= 'a' && lang[0] <= 'z'));
    PEP_ASSERT((lang[1] >= 'A' && lang[1] <= 'Z')
               || (lang[1] >= 'a' && lang[1] <= 'z'));
    PEP_ASSERT(lang[2] == 0);

    sql_reset_and_clear_bindings(session->trustword);
    sqlite3_bind_text(session->trustword, 1, lang, -1, SQLITE_STATIC);
    sqlite3_bind_int(session->trustword, 2, value);

    const int result = pEp_sqlite3_step_nonbusy(session, session->trustword);
    if (result == SQLITE_ROW) {
        *word = strdup((const char *) sqlite3_column_text(session->trustword,
                    1));
        if (*word)
            *wsize = sqlite3_column_bytes(session->trustword, 1);
        else
            status = PEP_OUT_OF_MEMORY;
    } else
        status = PEP_TRUSTWORD_NOT_FOUND;

    sql_reset_and_clear_bindings(session->trustword);
    return status;
}

DYNAMIC_API PEP_STATUS trustwords(
        PEP_SESSION session, const char *fingerprint, const char *lang,
        char **words, size_t *wsize, int max_words
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fingerprint) && words && wsize
                && max_words >= 0);

    const char *source = fingerprint;

    *words = NULL;
    *wsize = 0;

    char *buffer = calloc(1, MAX_TRUSTWORDS_SPACE);
    PEP_WEAK_ASSERT_ORELSE_RETURN(buffer, PEP_OUT_OF_MEMORY);
    char *dest = buffer;

    const size_t fsize = strlen(fingerprint);

    if (EMPTYSTR(lang))
        lang = "en";

    // FIXME: Should this not be an actual check?
    PEP_ASSERT((lang[0] >= 'A' && lang[0] <= 'Z')
               || (lang[0] >= 'a' && lang[0] <= 'z'));
    PEP_ASSERT((lang[1] >= 'A' && lang[1] <= 'Z')
               || (lang[1] >= 'a' && lang[1] <= 'z'));
    PEP_ASSERT(lang[2] == 0);

    int n_words = 0;
    while (source < fingerprint + fsize) {
        PEP_STATUS _status;
        uint16_t value;
        char *word = NULL;
        size_t _wsize = 0;
        int j;

        for (value=0, j=0; j < 4 && source < fingerprint + fsize; ) {
            if (*source >= 'a' && *source <= 'f')
                value += (*source - 'a' + 10) << (3 - j++) * 4;
            else if (*source >= 'A' && *source <= 'F')
                value += (*source - 'A' + 10) << (3 - j++) * 4;
            else if (*source >= '0' && *source <= '9')
                value += (*source - '0') << (3 - j++) * 4;
            
            source++;
        }

        _status = trustword(session, value, lang, &word, &_wsize);
        if (_status == PEP_OUT_OF_MEMORY) {
            free(buffer);
            return PEP_OUT_OF_MEMORY;
        }
        if (word == NULL) {
            free(buffer);
            return PEP_TRUSTWORD_NOT_FOUND;
        }

        if (dest + _wsize < buffer + MAX_TRUSTWORDS_SPACE - 1) {
            strncpy(dest, word, _wsize);
            free(word);
            dest += _wsize;
        }
        else {
            free(word);
            break; // buffer full
        }

        ++n_words;
        if (max_words && n_words >= max_words)
            break;
            
        if (source < fingerprint + fsize
                && dest + _wsize < buffer + MAX_TRUSTWORDS_SPACE - 1)
            *dest++ = ' ';
    }

    *words = buffer;
    *wsize = dest - buffer;
    return PEP_STATUS_OK;
}

pEp_identity *new_identity(
        const char *address, const char *fpr, const char *user_id,
        const char *username
    )
{
    pEp_identity *result = calloc(1, sizeof(pEp_identity));
    if (result) {
        if (address) {
            result->address = strdup(address);
            assert(result->address);
            if (result->address == NULL) {
                free(result);
                return NULL;
            }
        }
        if (fpr) {
            result->fpr = strdup(fpr);
            assert(result->fpr);
            if (result->fpr == NULL) {
                free_identity(result);
                return NULL;
            }
        }
        if (user_id) {
            result->user_id = strdup(user_id);
            assert(result->user_id);
            if (result->user_id == NULL) {
                free_identity(result);
                return NULL;
            }
        }
        if (username) {
            result->username = strdup(username);
            assert(result->username);
            if (result->username == NULL) {
                free_identity(result);
                return NULL;
            }
        }
    }
    return result;
}

pEp_identity *identity_dup(const pEp_identity *src)
{
    pEp_identity* dup = NULL;
    if (src) {
        dup = new_identity(src->address, src->fpr, src->user_id,
                src->username);
        assert(dup);
        if (dup == NULL)
            return NULL;
        
        dup->comm_type = src->comm_type;
        dup->lang[0] = src->lang[0];
        dup->lang[1] = src->lang[1];
        dup->lang[2] = 0;
        dup->flags = src->flags;
        dup->me = src->me;
        dup->major_ver = src->major_ver;
        dup->minor_ver = src->minor_ver;
        dup->enc_format = src->enc_format;
    }
    return dup;
}

void free_identity(pEp_identity *identity)
{
    if (identity) {
        free(identity->address);
        free(identity->fpr);
        free(identity->user_id);
        free(identity->username);
        free(identity);
    }
}

DYNAMIC_API PEP_STATUS get_default_own_userid(
        PEP_SESSION session, 
        char** userid
    )
{
    PEP_REQUIRE(session && userid);
        
    PEP_STATUS status = PEP_STATUS_OK;
    char* retval = NULL;
    
    sql_reset_and_clear_bindings(session->get_default_own_userid);

    const int result = pEp_sqlite3_step_nonbusy(session, session->get_default_own_userid);
    const char* id;
    
    switch (result) {
        case SQLITE_ROW:
            id = (const char *) sqlite3_column_text(session->get_default_own_userid, 0);
            if (!id) {
                // Shouldn't happen.
                status = PEP_UNKNOWN_ERROR;
            }
            else {
                retval = strdup(id);
                if (!retval)
                    status = PEP_OUT_OF_MEMORY;
            }
            break;
        default:
            // Technically true, given how we find it, but FIXME we need a more descriptive error
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    *userid = retval;
    sql_reset_and_clear_bindings(session->get_default_own_userid);
    LOG_NONOK_STATUS_NONOK;
    return status;
}

DYNAMIC_API PEP_STATUS get_userid_alias_default(
        PEP_SESSION session, 
        const char* alias_id,
        char** default_id) {
    PEP_REQUIRE(session && alias_id && alias_id[0] && default_id);

    PEP_STATUS status = PEP_STATUS_OK;
    char* retval = NULL;

    sql_reset_and_clear_bindings(session->get_userid_alias_default);
    sqlite3_bind_text(session->get_userid_alias_default, 1, alias_id, -1, SQLITE_STATIC);

    const char* tempid;
    
    const int result = pEp_sqlite3_step_nonbusy(session, session->get_userid_alias_default);
    switch (result) {
    case SQLITE_ROW:
        tempid = (const char *) sqlite3_column_text(session->get_userid_alias_default, 0);
        if (tempid) {
            retval = strdup(tempid);
            PEP_WEAK_ASSERT_ORELSE_RETURN(retval, PEP_OUT_OF_MEMORY);
        }
    
        *default_id = retval;
        break;
    default:
        status = PEP_CANNOT_FIND_ALIAS;
        *default_id = NULL;
    }

    sql_reset_and_clear_bindings(session->get_userid_alias_default);
    return status;            
}

DYNAMIC_API PEP_STATUS set_userid_alias (
        PEP_SESSION session, 
        const char* default_id,
        const char* alias_id) {
    PEP_REQUIRE(session && ! EMPTYSTR(default_id) && ! EMPTYSTR(alias_id));

    int result;
    
    PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();

    sql_reset_and_clear_bindings(session->add_userid_alias);
    sqlite3_bind_text(session->add_userid_alias, 1, default_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_userid_alias, 2, alias_id, -1,
            SQLITE_STATIC);
        
    result = sqlite3_step(session->add_userid_alias);
    PEP_ASSERT(result != SQLITE_LOCKED);
    PEP_ASSERT(result != SQLITE_BUSY); // we are inside an EXCLUSIVE transaction

    sql_reset_and_clear_bindings(session->add_userid_alias);
    if (result != SQLITE_DONE) {
        PEP_SQL_ROLLBACK_TRANSACTION();
        return PEP_CANNOT_SET_ALIAS;
    }
    PEP_SQL_COMMIT_TRANSACTION();
        

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS get_identity(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    )
{
    PEP_REQUIRE(session && address && address[0] && identity);

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *_identity = NULL;
    *identity = NULL;

    sql_reset_and_clear_bindings(session->get_identity);
    sqlite3_bind_text(session->get_identity, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_identity, 2, user_id, -1, SQLITE_STATIC);

    const int result = pEp_sqlite3_step_nonbusy(session, session->get_identity);
    switch (result) {
    case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity, 0),
                user_id,
                (const char *) sqlite3_column_text(session->get_identity, 1)
                );
        PEP_WEAK_ASSERT_ORELSE(_identity, {
            sql_reset_and_clear_bindings(session->get_identity);
            return PEP_OUT_OF_MEMORY;
        });

        _identity->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identity, 2);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identity, 3);
        if (_lang && _lang[0]) {
            PEP_ASSERT(_lang[0] >= 'a' && _lang[0] <= 'z');
            PEP_ASSERT(_lang[1] >= 'a' && _lang[1] <= 'z');
            PEP_ASSERT(_lang[2] == 0);
            _identity->lang[0] = _lang[0];
            _identity->lang[1] = _lang[1];
            _identity->lang[2] = 0;
        }
        _identity->flags = (unsigned int)
            sqlite3_column_int(session->get_identity, 4);
        _identity->me = (unsigned int)
            sqlite3_column_int(session->get_identity, 5);
        _identity->major_ver =
            sqlite3_column_int(session->get_identity, 6);
        _identity->minor_ver =
            sqlite3_column_int(session->get_identity, 7);
        _identity->enc_format =    
            sqlite3_column_int(session->get_identity, 8);    
        *identity = _identity;
        break;
    default:
        sql_reset_and_clear_bindings(session->get_identity);
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    sql_reset_and_clear_bindings(session->get_identity);
    return status;
}

PEP_STATUS get_identities_by_userid(
        PEP_SESSION session,
        const char *user_id,
        identity_list **identities
    )
{
    PEP_REQUIRE(session && identities && ! EMPTYSTR(user_id));

    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* ident = NULL;

    *identities = new_identity_list(NULL);

    sql_reset_and_clear_bindings(session->get_identities_by_userid);
    sqlite3_bind_text(session->get_identities_by_userid, 1, user_id, -1, SQLITE_STATIC);

    int result = -1;
    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_identities_by_userid)) == SQLITE_ROW) {
            // "select address, identity.main_key_id, username, comm_type, lang,"
            // "   identity.flags | pgp_keypair.flags,"
            // "   is_own"
            // "   from identity"
            // "   join person on id = identity.user_id"
            // "   join pgp_keypair on fpr = identity.main_key_id"
            // "   join trust on id = trust.user_id"
            // "       and pgp_keypair_fpr = identity.main_key_id"    
            // "   where identity.user_id = ?1" 
            // "   order by is_own desc, "
            // "   timestamp desc; ";

        ident = new_identity(
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 0),
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 1),                
                    user_id,
                    (const char *) sqlite3_column_text(session->get_identities_by_userid, 2)
                );
                
        PEP_WEAK_ASSERT_ORELSE(ident, {
            sql_reset_and_clear_bindings(session->get_identities_by_userid);
            return PEP_OUT_OF_MEMORY;
        });

        ident->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identities_by_userid, 3);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_userid, 4);
        if (_lang && _lang[0]) {
            PEP_ASSERT(_lang[0] >= 'a' && _lang[0] <= 'z');
            PEP_ASSERT(_lang[1] >= 'a' && _lang[1] <= 'z');
            PEP_ASSERT(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_userid, 5);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_userid, 6);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_userid, 7);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_userid, 8);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_userid, 9);    
            
    
        identity_list_add(*identities, ident);
        ident = NULL;
    }

    if ((*identities)->ident == NULL) {
        free_identity_list(*identities);
        *identities = NULL;
        status = PEP_CANNOT_FIND_IDENTITY;
    }
            
    sql_reset_and_clear_bindings(session->get_identities_by_userid);

    return status;
}

PEP_STATUS get_identities_by_main_key_id(
        PEP_SESSION session,
        const char *fpr,
        identity_list **identities
    )
{
    PEP_REQUIRE(session && identities && ! EMPTYSTR(fpr));

    PEP_STATUS status = PEP_STATUS_OK;
    
    pEp_identity* ident = NULL;

    *identities = new_identity_list(NULL);

    sql_reset_and_clear_bindings(session->get_identities_by_main_key_id);
    sqlite3_bind_text(session->get_identities_by_main_key_id, 1, fpr, -1, SQLITE_STATIC);

    int result = -1;
    
    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_identities_by_main_key_id)) == SQLITE_ROW) {
        ident = new_identity(
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 0),
                    fpr,
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 1),                
                    (const char *) sqlite3_column_text(session->get_identities_by_main_key_id, 2)
                );
                
        PEP_WEAK_ASSERT_ORELSE(ident, {
            sql_reset_and_clear_bindings(session->get_identities_by_main_key_id);
            return PEP_OUT_OF_MEMORY;
        });

        ident->comm_type = (PEP_comm_type)
            sqlite3_column_int(session->get_identities_by_main_key_id, 3);
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_main_key_id, 4);
        if (_lang && _lang[0]) {
            PEP_ASSERT(_lang[0] >= 'a' && _lang[0] <= 'z');
            PEP_ASSERT(_lang[1] >= 'a' && _lang[1] <= 'z');
            PEP_ASSERT(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_main_key_id, 5);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_main_key_id, 6);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_main_key_id, 7);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_main_key_id, 8);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_main_key_id, 9);                
    
        identity_list_add(*identities, ident);
        ident = NULL;
    }

    if ((*identities)->ident == NULL) {
        free_identity_list(*identities);
        *identities = NULL;
        status = PEP_CANNOT_FIND_IDENTITY;
    }
            
    sql_reset_and_clear_bindings(session->get_identities_by_main_key_id);

    return status;
}

PEP_STATUS get_identity_without_trust_check(
        PEP_SESSION session,
        const char *address,
        const char *user_id,
        pEp_identity **identity
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(address) && identity);

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *_identity = NULL;

    *identity = NULL;

    sql_reset_and_clear_bindings(session->get_identity_without_trust_check);
    sqlite3_bind_text(session->get_identity_without_trust_check, 1, address, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_identity_without_trust_check, 2, user_id, -1, SQLITE_STATIC);

    const int result = pEp_sqlite3_step_nonbusy(session, session->get_identity_without_trust_check);
    switch (result) {
    case SQLITE_ROW:
        _identity = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identity_without_trust_check, 0),
                user_id,
                (const char *) sqlite3_column_text(session->get_identity_without_trust_check, 1)
                );
        PEP_WEAK_ASSERT_ORELSE(_identity, {
            sql_reset_and_clear_bindings(session->get_identity_without_trust_check);
            return PEP_OUT_OF_MEMORY;
        });

        _identity->comm_type = PEP_ct_unknown;
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identity_without_trust_check, 2);
        if (_lang && _lang[0]) {
            PEP_ASSERT(_lang[0] >= 'a' && _lang[0] <= 'z');
            PEP_ASSERT(_lang[1] >= 'a' && _lang[1] <= 'z');
            PEP_ASSERT(_lang[2] == 0);
            _identity->lang[0] = _lang[0];
            _identity->lang[1] = _lang[1];
            _identity->lang[2] = 0;
        }
        _identity->flags = (unsigned int)
            sqlite3_column_int(session->get_identity_without_trust_check, 3);
        _identity->me = (unsigned int)
            sqlite3_column_int(session->get_identity_without_trust_check, 4);
        _identity->major_ver =
            sqlite3_column_int(session->get_identity_without_trust_check, 5);
        _identity->minor_ver =
            sqlite3_column_int(session->get_identity_without_trust_check, 6);
        _identity->enc_format =    
            sqlite3_column_int(session->get_identity_without_trust_check, 7);                
    
        *identity = _identity;
        break;
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
        *identity = NULL;
    }

    sql_reset_and_clear_bindings(session->get_identity_without_trust_check);
    return status;
}


PEP_STATUS get_identities_by_address(
        PEP_SESSION session,
        const char *address,
        identity_list** id_list
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(address) && id_list);

    *id_list = NULL;
    identity_list* ident_list = NULL;

    sql_reset_and_clear_bindings(session->get_identities_by_address);
    sqlite3_bind_text(session->get_identities_by_address, 1, address, -1, SQLITE_STATIC);
    int result;

    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_identities_by_address)) == SQLITE_ROW) {
        //"select user_id, main_key_id, username, comm_type, lang,"
        //"   identity.flags, is_own"
        pEp_identity *ident = new_identity(
                address,
                (const char *) sqlite3_column_text(session->get_identities_by_address, 1),
                (const char *) sqlite3_column_text(session->get_identities_by_address, 0),
                (const char *) sqlite3_column_text(session->get_identities_by_address, 2)
                );
        PEP_WEAK_ASSERT_ORELSE(ident, {
            sql_reset_and_clear_bindings(session->get_identities_by_address);
            return PEP_OUT_OF_MEMORY;
        });

        ident->comm_type = PEP_ct_unknown;
        
        const char* const _lang = (const char *)
            sqlite3_column_text(session->get_identities_by_address, 3);
        if (_lang && _lang[0]) {
            PEP_ASSERT(_lang[0] >= 'a' && _lang[0] <= 'z');
            PEP_ASSERT(_lang[1] >= 'a' && _lang[1] <= 'z');
            PEP_ASSERT(_lang[2] == 0);
            ident->lang[0] = _lang[0];
            ident->lang[1] = _lang[1];
            ident->lang[2] = 0;
        }
        ident->flags = (unsigned int)
            sqlite3_column_int(session->get_identities_by_address, 4);
        ident->me = (unsigned int)
            sqlite3_column_int(session->get_identities_by_address, 5);
        ident->major_ver =
            sqlite3_column_int(session->get_identities_by_address, 6);
        ident->minor_ver =
            sqlite3_column_int(session->get_identities_by_address, 7);
        ident->enc_format =    
            sqlite3_column_int(session->get_identities_by_address, 8);               
                 
        if (ident_list)
            identity_list_add(ident_list, ident);
        else
            ident_list = new_identity_list(ident);
    }

    sql_reset_and_clear_bindings(session->get_identities_by_address);
    
    *id_list = ident_list;
    
    if (!ident_list)
        return PEP_CANNOT_FIND_IDENTITY;
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       exists_identity_entry()       -->
 *
 *  @brief      checks if an identity entry already exists in the DB    
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *identity        pEp_identity
 *  @param[out]    *exists            bool
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value 
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
PEP_STATUS exists_identity_entry(PEP_SESSION session, pEp_identity* identity,
                                 bool* exists) {
    PEP_REQUIRE(session && identity && exists && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->address));
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    sql_reset_and_clear_bindings(session->exists_identity_entry);
    sqlite3_bind_text(session->exists_identity_entry, 1, identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_identity_entry, 2, identity->user_id, -1,
                      SQLITE_STATIC);
                  
    int result = pEp_sqlite3_step_nonbusy(session, session->exists_identity_entry);

    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_identity_entry, 0) != 0);
            break;
        }
        default: 
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sql_reset_and_clear_bindings(session->exists_identity_entry);
    return status;
}

PEP_STATUS exists_trust_entry(PEP_SESSION session, pEp_identity* identity,
                              bool* exists) {
    PEP_REQUIRE(session && exists && identity
                && ! EMPTYSTR(identity->user_id) && ! EMPTYSTR(identity->fpr));
    
    *exists = false;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    sql_reset_and_clear_bindings(session->exists_trust_entry);
    sqlite3_bind_text(session->exists_trust_entry, 1, identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_trust_entry, 2, identity->fpr, -1,
                      SQLITE_STATIC);
                  
    int result = pEp_sqlite3_step_nonbusy(session, session->exists_trust_entry);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_trust_entry, 0) != 0);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sql_reset_and_clear_bindings(session->exists_trust_entry);
    return status;
}

PEP_STATUS set_pgp_keypair(PEP_SESSION session, const char* fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    int result;
    
    sql_reset_and_clear_bindings(session->set_pgp_keypair);
    sqlite3_bind_text(session->set_pgp_keypair, 1, fpr, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->set_pgp_keypair);
    sql_reset_and_clear_bindings(session->set_pgp_keypair);
    if (result != SQLITE_DONE) {
        return PEP_CANNOT_SET_PGP_KEYPAIR;
    }
    
    return PEP_STATUS_OK;
}

PEP_STATUS clear_trust_info(PEP_SESSION session,
                            const char* user_id,
                            const char* fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id) && ! EMPTYSTR(fpr));

    int result;
    
    sql_reset_and_clear_bindings(session->clear_trust_info);
    sqlite3_bind_text(session->clear_trust_info, 1, user_id, -1,
            SQLITE_STATIC);    
    sqlite3_bind_text(session->clear_trust_info, 2, fpr, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->clear_trust_info);
    sql_reset_and_clear_bindings(session->clear_trust_info);
    if (result != SQLITE_DONE) {
        return PEP_UNKNOWN_ERROR;
    }
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK     
 *  @retval     PEP_CANNOT_SET_TRUST          
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *
 */
static PEP_STATUS _set_or_update_trust(PEP_SESSION session,
                                       pEp_identity* identity,
                                       sqlite3_stmt* set_or_update) {
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->fpr));

    PEP_STATUS status = set_pgp_keypair(session, identity->fpr);
    if (status != PEP_STATUS_OK)
        return status;
        
    int result;
                
    sql_reset_and_clear_bindings(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 3, identity->comm_type);
    result = pEp_sqlite3_step_nonbusy(session, set_or_update);
    sql_reset_and_clear_bindings(set_or_update);
    PEP_WEAK_ASSERT_ORELSE_RETURN(result == SQLITE_DONE, PEP_CANNOT_SET_TRUST);

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_identity_entry()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK 
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_ILLEGAL_VALUE           illegal parameter value
 *
 */
static PEP_STATUS _set_or_update_identity_entry(PEP_SESSION session,
                                                pEp_identity* identity,
                                                sqlite3_stmt* set_or_update) {
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->address));

    sql_reset_and_clear_bindings(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, EMPTYSTR(identity->fpr) ? NULL : identity->fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 3, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 4, identity->username, -1,
                      SQLITE_STATIC);
    sqlite3_bind_int(set_or_update, 5, identity->flags);
    sqlite3_bind_int(set_or_update, 6, identity->me);
    sqlite3_bind_int(set_or_update, 7, identity->major_ver);
    sqlite3_bind_int(set_or_update, 8, identity->minor_ver);
        
    int result = pEp_sqlite3_step_nonbusy(session, set_or_update);
    sql_reset_and_clear_bindings(set_or_update);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;
    
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       _set_or_update_person()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session             session handle        
 *  @param[in]    *identity            pEp_identity
 *  @param[in]    *set_or_update        sqlite3_stmt
 *
 *  @retval     PEP_STATUS_OK 
 *  @retval     PEP_CANNOT_SET_IDENTITY
 *  @retval     PEP_CANNOT_SET_PERSON
 *
 */
static PEP_STATUS _set_or_update_person(PEP_SESSION session,
                                        pEp_identity* identity,
                                        sqlite3_stmt* set_or_update) {
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->username));

    sql_reset_and_clear_bindings(set_or_update);
    sqlite3_bind_text(set_or_update, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(set_or_update, 2, identity->username, -1,
            SQLITE_STATIC);
    if (identity->lang[0])
        sqlite3_bind_text(set_or_update, 3, identity->lang, 2,
                SQLITE_STATIC);
    else
        sqlite3_bind_null(set_or_update, 3);
    sqlite3_bind_text(set_or_update, 4, EMPTYSTR(identity->fpr) ? NULL : identity->fpr, -1,
                      SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, set_or_update);
    sql_reset_and_clear_bindings(set_or_update);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;
    
    return PEP_STATUS_OK;                                         
}

PEP_STATUS set_or_update_with_identity(PEP_SESSION session,
                                       pEp_identity* identity,
                                       PEP_STATUS (* set_function)(PEP_SESSION, pEp_identity*, sqlite3_stmt*),
                                       PEP_STATUS (* exists_function)(PEP_SESSION, pEp_identity*, bool*),                                       
                                       sqlite3_stmt* update_query,
                                       sqlite3_stmt* set_query,
                                       bool guard_transaction) {
    PEP_REQUIRE(session && identity && set_function && exists_function);

    if (guard_transaction)
        PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();
    bool exists = false;
    PEP_STATUS status = exists_function(session, identity, &exists);
    
    if (status == PEP_STATUS_OK) {
        if (exists) {
            status = set_function(session, identity, update_query);
        }
        else {
            status = set_function(session, identity, set_query);                                              
        }                    
    }   
    if (guard_transaction) {        
        if (status != PEP_STATUS_OK)
            PEP_SQL_ROLLBACK_TRANSACTION();
        else
            PEP_SQL_COMMIT_TRANSACTION();
    }                      
    return status;
}

/**
 *  @internal
 *
 *  <!--       _set_trust_internal()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *identity                pEp_identity
 *  @param[in]    guard_transaction        bool
 *
 */
PEP_STATUS _set_trust_internal(PEP_SESSION session, pEp_identity* identity,
                               bool guard_transaction) {
    PEP_REQUIRE(session && identity);

    return set_or_update_with_identity(session, identity,
                                       _set_or_update_trust,
                                        exists_trust_entry,
                                        session->update_trust,
                                        session->set_trust,
                                        guard_transaction);
}

// This is the TOP-LEVEL function. If you're calling from set_identity,
// you can't use this one.
PEP_STATUS set_trust(PEP_SESSION session, pEp_identity* identity) {
    PEP_REQUIRE(session && identity);

    PEP_STATUS status = PEP_STATUS_OK;
    status = _set_trust_internal(session, identity, true);
    if (status == PEP_STATUS_OK) {
        if ((identity->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
            status = set_as_pEp_user(session, identity);
    }
    return status;
}

PEP_STATUS set_person(PEP_SESSION session, pEp_identity* identity,
                      bool guard_transaction) {
    PEP_REQUIRE(session && identity);

    return set_or_update_with_identity(session, identity,
                                       _set_or_update_person,
                                       exists_person,
                                       session->update_person,
                                       session->set_person,
                                       guard_transaction);
}

/**
 *  @internal
 *
 *  <!--       set_identity_entry()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                    session handle    
 *  @param[in]    *identity                pEp_identity
 *  @param[in]    guard_transaction        bool
 *
 */
PEP_STATUS set_identity_entry(PEP_SESSION session, pEp_identity* identity,
                              bool guard_transaction) {
    PEP_REQUIRE(session && identity);

    return set_or_update_with_identity(session, identity,
                                       _set_or_update_identity_entry,
                                       exists_identity_entry,
                                       session->update_identity_entry,
                                       session->set_identity_entry,
                                       guard_transaction);
}


// This will NOT call set_as_pEp_user, nor set_protocol_version; you have to do that separately.
DYNAMIC_API PEP_STATUS set_identity(
        PEP_SESSION session, const pEp_identity *identity
    )
{
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->address)
                && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->username));

    int result;
    PEP_STATUS status = PEP_STATUS_OK;
    bool has_fpr = (!EMPTYSTR(identity->fpr));
    pEp_identity* ident_copy = NULL;

    if (identity->lang[0]) {
        PEP_ASSERT(identity->lang[0] >= 'a' && identity->lang[0] <= 'z');
        PEP_ASSERT(identity->lang[1] >= 'a' && identity->lang[1] <= 'z');
        PEP_ASSERT(identity->lang[2] == 0);
    }

#define FAIL(_status)            \
    do {                         \
        status = (_status);      \
        LOG_NONOK_STATUS_NONOK;  \
        goto end;                \
    } while (false)
#define FAIL_IF_NEEDED                \
    do {                              \
        if (status != PEP_STATUS_OK)  \
            FAIL(status);             \
    } while (false)

    sql_reset_and_clear_bindings(session->set_pgp_keypair);
    PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();
    if (has_fpr) {
        sqlite3_bind_text(session->set_pgp_keypair, 1, identity->fpr, -1,
                          SQLITE_STATIC);
        result = sqlite3_step(session->set_pgp_keypair);
        PEP_ASSERT(result != SQLITE_LOCKED);
        PEP_ASSERT(result != SQLITE_BUSY); // we are inside an EXCLUSIVE transaction
        if (result != SQLITE_DONE)
            FAIL(PEP_CANNOT_SET_PGP_KEYPAIR);
    }

    // We do this because there are checks in set_person for
    // aliases, which modify the identity object on return.
    ident_copy = identity_dup(identity); 
    if (!ident_copy)
        FAIL(PEP_OUT_OF_MEMORY);

    // For now, we ALWAYS set the person.username.
    status = set_person(session, ident_copy, false);
    FAIL_IF_NEEDED;

    status = set_identity_entry(session, ident_copy, false);
    FAIL_IF_NEEDED;

    if (has_fpr) {
        status = _set_trust_internal(session, ident_copy, false);
        FAIL_IF_NEEDED;
    }

    status = set_protocol_version(session, ident_copy, ident_copy->major_ver, ident_copy->minor_ver);
    FAIL_IF_NEEDED;

end:
    free_identity(ident_copy);
    sql_reset_and_clear_bindings(session->set_pgp_keypair);
    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK)
        PEP_SQL_COMMIT_TRANSACTION();
    else
        PEP_SQL_ROLLBACK_TRANSACTION();

    return status;
#undef FAIL
#undef FAIL_IF_NEEDED
}

//static const char* sql_force_set_identity_username =
//        "update identity "
//        "   set username = coalesce(username, ?3) "
//        "   where (case when (address = ?1) then (1)"
//        "               when (lower(address) = lower(?1)) then (1)"
//        "               when (replace(lower(address),'.','') = replace(lower(?1),'.','')) then (1) "
//        "               else 0 "
//        "          end) = 1 "
//        "          and user_id = ?2 ;";

PEP_STATUS force_set_identity_username(PEP_SESSION session, pEp_identity* ident, const char* username) {
    PEP_REQUIRE(session && ident && ! EMPTYSTR(ident->address)
                && ! EMPTYSTR(ident->user_id)
                /* username is allowed to be NULL. */);

    // If username is NULL, it's fine. This defaults to sqlite3_bind_null() and clears the username, which
    // might be intended. The caller should decide that before calling this. This is really the force-bludgeon.
    if (EMPTYSTR(username))
        username = NULL;

    sql_reset_and_clear_bindings(session->force_set_identity_username);
    sqlite3_bind_text(session->force_set_identity_username, 1, ident->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->force_set_identity_username, 2, ident->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->force_set_identity_username, 3, username, -1,
                      SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->force_set_identity_username);

    sql_reset_and_clear_bindings(session->force_set_identity_username);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       update_pEp_user_trust_vals()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *user        pEp_identity
 *
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_SET_TRUST
 *
 */
PEP_STATUS update_pEp_user_trust_vals(PEP_SESSION session,
                                      pEp_identity* user) {
    PEP_REQUIRE(session && user && ! EMPTYSTR(user->user_id));

    sql_reset_and_clear_bindings(session->update_trust_to_pEp);
    sqlite3_bind_text(session->update_trust_to_pEp, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->update_trust_to_pEp);
    sql_reset_and_clear_bindings(session->update_trust_to_pEp);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    PEP_STATUS status
        = upgrade_protocol_version_by_user_id(session, user,
                                              PEP_PROTOCOL_MINIMUM_VERSION_MAJOR,
                                              PEP_PROTOCOL_MINIMUM_VERSION_MINOR);
    return status;
}


// This ONLY sets the user flag. Must be called outside of a transaction.
DYNAMIC_API PEP_STATUS set_as_pEp_user(PEP_SESSION session, pEp_identity* user) {
    PEP_REQUIRE(session && user && ! EMPTYSTR(user->user_id));

    PEP_STATUS status = PEP_STATUS_OK;
    
    bool person_exists = false;
    
    status = exists_person(session, user, &person_exists);
    
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!person_exists)
        status = set_person(session, user, true);
        
    // Ok, let's set it.
    sql_reset_and_clear_bindings(session->set_as_pEp_user);
    sqlite3_bind_text(session->set_as_pEp_user, 1, user->user_id, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->set_as_pEp_user);
    sql_reset_and_clear_bindings(session->set_as_pEp_user);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    status = update_pEp_user_trust_vals(session, user);
        
    return status;
}

// This ONLY sets the version flag. Must be called outside of a transaction.
PEP_STATUS set_protocol_version(PEP_SESSION session, pEp_identity* ident, unsigned int new_ver_major, unsigned int new_ver_minor) {
    PEP_REQUIRE(session && ident && ! EMPTYSTR(ident->user_id)
                && ! EMPTYSTR(ident->address));

    sql_reset_and_clear_bindings(session->set_protocol_version);
    sqlite3_bind_double(session->set_protocol_version, 1, new_ver_major);
    sqlite3_bind_double(session->set_protocol_version, 2, new_ver_minor);    
    sqlite3_bind_text(session->set_protocol_version, 3, ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_protocol_version, 4, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = pEp_sqlite3_step_nonbusy(session, session->set_protocol_version);
    sql_reset_and_clear_bindings(session->set_protocol_version);
        
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PEP_PROTOCOL_VERSION;
    
    return PEP_STATUS_OK;
}

// Generally ONLY called by set_as_pEp_user, and ONLY from < 2.0 to 2.0.
PEP_STATUS upgrade_protocol_version_by_user_id(PEP_SESSION session, 
        pEp_identity* ident, 
        unsigned int new_ver_major,
        unsigned int new_ver_minor
    ) 
{
    PEP_REQUIRE(session && ident && ! EMPTYSTR(ident->user_id));

    sql_reset_and_clear_bindings(session->upgrade_protocol_version_by_user_id);
    sqlite3_bind_int(session->upgrade_protocol_version_by_user_id, 1, new_ver_major);
    sqlite3_bind_int(session->upgrade_protocol_version_by_user_id, 2, new_ver_minor);    
    sqlite3_bind_text(session->upgrade_protocol_version_by_user_id, 3, ident->user_id, -1,
            SQLITE_STATIC);
    
    int result = pEp_sqlite3_step_nonbusy(session, session->upgrade_protocol_version_by_user_id);
    sql_reset_and_clear_bindings(session->upgrade_protocol_version_by_user_id);
        
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PEP_PROTOCOL_VERSION;
    
    return PEP_STATUS_OK;    
}

PEP_STATUS exists_person(PEP_SESSION session, pEp_identity* identity,
                         bool* exists) {            
    PEP_REQUIRE(session && exists && identity && ! EMPTYSTR(identity->user_id));

    *exists = false;

    const char* user_id = identity->user_id;
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        sql_reset_and_clear_bindings(session->exists_person);
        sqlite3_bind_text(session->exists_person, 1, user_id, -1,
                SQLITE_STATIC);
        int result = pEp_sqlite3_step_nonbusy(session, session->exists_person);
        switch (result) {
            case SQLITE_ROW: {
                // yeah yeah, I know, we could be lazy here, but it looks bad.
                *exists = (sqlite3_column_int(session->exists_person, 0) != 0);
                status = PEP_STATUS_OK;
                break;
            }
            default:
                sql_reset_and_clear_bindings(session->exists_person);
                return PEP_UNKNOWN_DB_ERROR;
        }
        sql_reset_and_clear_bindings(session->exists_person);
    }
    else if (status == PEP_STATUS_OK) {
        *exists = true; // thank you, delete on cascade!
        // FIXME: Should we correct the userid default here? I think we should.
        free(identity->user_id);
        identity->user_id = alias_default; // ownership transfer
    }
    else
        free(alias_default);
            
    return status;
}

/**
 *  @internal
 *
 *  <!--       delete_person()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *user_id        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_UNKNOWN_ERROR
 *
 */
PEP_STATUS delete_person(PEP_SESSION session, const char* user_id) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id));

    PEP_STATUS status = PEP_STATUS_OK;
    sql_reset_and_clear_bindings(session->delete_person);
    sqlite3_bind_text(session->delete_person, 1, user_id, -1,
                      SQLITE_STATIC);
                      
    int result = pEp_sqlite3_step_nonbusy(session, session->delete_person);
    
    if (result != SQLITE_DONE)
        status = PEP_UNKNOWN_ERROR;
        
    sql_reset_and_clear_bindings(session->delete_person);
    return status;
}

DYNAMIC_API PEP_STATUS is_pEp_user(PEP_SESSION session, pEp_identity *identity, bool* is_pEp)
{
    PEP_REQUIRE(session && is_pEp && identity && ! EMPTYSTR(identity->user_id));

    *is_pEp = false;
            
    const char* user_id = identity->user_id;
            
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        free(alias_default);
        alias_default = strdup(user_id);
    }
    
    sql_reset_and_clear_bindings(session->is_pEp_user);
    sqlite3_bind_text(session->is_pEp_user, 1, user_id, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->is_pEp_user);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *is_pEp = (sqlite3_column_int(session->is_pEp_user, 0) != 0);
            break;
        }
        default:
            sql_reset_and_clear_bindings(session->is_pEp_user);
            free(alias_default);
            return PEP_CANNOT_FIND_PERSON;
    }

    sql_reset_and_clear_bindings(session->is_pEp_user);
    
    free(alias_default);
    return PEP_STATUS_OK;
}

PEP_STATUS is_own_address(PEP_SESSION session, const char* address, bool* is_own_addr)
{
    PEP_REQUIRE(session && is_own_addr && ! EMPTYSTR(address));

    *is_own_addr = false;

    sql_reset_and_clear_bindings(session->is_own_address);
    sqlite3_bind_text(session->is_own_address, 1, address, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->is_own_address);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *is_own_addr = (sqlite3_column_int(session->is_own_address, 0) != 0);
            break;
        }
        default:
            sql_reset_and_clear_bindings(session->is_own_address);
            return PEP_RECORD_NOT_FOUND;
    }

    sql_reset_and_clear_bindings(session->is_own_address);
    
    return PEP_STATUS_OK;
}

PEP_STATUS bind_own_ident_with_contact_ident(PEP_SESSION session,
                                             pEp_identity* own_ident, 
                                             pEp_identity* contact_ident) {
    PEP_REQUIRE(session && own_ident && contact_ident
                && ! EMPTYSTR(own_ident->address)
                && ! EMPTYSTR(own_ident->user_id)
                && ! EMPTYSTR(contact_ident->user_id));

    sql_reset_and_clear_bindings(session->add_into_social_graph);
    sqlite3_bind_text(session->add_into_social_graph, 1, own_ident->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 2, own_ident->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->add_into_social_graph, 3, contact_ident->user_id, -1,
            SQLITE_STATIC);
        
    int result = pEp_sqlite3_step_nonbusy(session, session->add_into_social_graph);
    sql_reset_and_clear_bindings(session->add_into_social_graph);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

// FIXME: should be more like is there a communications relationship,
// since this could be either way
PEP_STATUS has_partner_contacted_address(PEP_SESSION session, const char* partner_id,
                                         const char* own_address, bool* was_contacted) {    PEP_REQUIRE(session && was_contacted && ! EMPTYSTR(partner_id)
                                                                                                        && ! EMPTYSTR(own_address));

    *was_contacted = false;

    PEP_STATUS status = PEP_STATUS_OK;
    
    sql_reset_and_clear_bindings(session->has_id_contacted_address);
    sqlite3_bind_text(session->has_id_contacted_address, 1, own_address, -1,
            SQLITE_STATIC);            
    sqlite3_bind_text(session->has_id_contacted_address, 2, partner_id, -1,
            SQLITE_STATIC);
            
    int result = pEp_sqlite3_step_nonbusy(session, session->has_id_contacted_address);
    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *was_contacted = (sqlite3_column_int(session->has_id_contacted_address, 0) != 0);
            status = PEP_STATUS_OK;
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    sql_reset_and_clear_bindings(session->has_id_contacted_address);
            
    return status;
}

// FIXME: problematic - can be multiple and this now matters
PEP_STATUS get_own_ident_for_contact_id(PEP_SESSION session,
                                          const pEp_identity* contact,
                                          pEp_identity** own_ident) {
    PEP_REQUIRE(session && contact && ! EMPTYSTR(contact->user_id)
                && own_ident);

    char* own_user_id = NULL;
    *own_ident = NULL;
    PEP_STATUS status = get_default_own_userid(session, &own_user_id);
    
    if (status != PEP_STATUS_OK)
        return status;

    sql_reset_and_clear_bindings(session->get_own_address_binding_from_contact);
    sqlite3_bind_text(session->get_own_address_binding_from_contact, 1, own_user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_address_binding_from_contact, 2, contact->user_id, -1,
            SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->get_own_address_binding_from_contact);
    
    const char* own_address = NULL;
    
    switch (result) {
        case SQLITE_ROW:
            own_address = (const char *)
                sqlite3_column_text(session->get_own_address_binding_from_contact, 0);
            if (own_address) {
                status = get_identity(session, own_address, own_user_id, own_ident);
                if (status == PEP_STATUS_OK) {
                    if (!own_ident)
                        status = PEP_CANNOT_FIND_IDENTITY;
                }
            }
            break;
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }
    sql_reset_and_clear_bindings(session->get_own_address_binding_from_contact);
    
    free(own_user_id);
    return status;
}

PEP_STATUS remove_fpr_as_default(PEP_SESSION session, 
                                 const char* fpr) 
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    sql_reset_and_clear_bindings(session->remove_fpr_as_identity_default);
    sqlite3_bind_text(session->remove_fpr_as_identity_default, 1, fpr, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->remove_fpr_as_identity_default);
    sql_reset_and_clear_bindings(session->remove_fpr_as_identity_default);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY; 

    sql_reset_and_clear_bindings(session->remove_fpr_as_user_default);
    sqlite3_bind_text(session->remove_fpr_as_user_default, 1, fpr, -1,
                      SQLITE_STATIC);

    result = pEp_sqlite3_step_nonbusy(session, session->remove_fpr_as_user_default);
    sql_reset_and_clear_bindings(session->remove_fpr_as_user_default);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON; 
        
    return PEP_STATUS_OK;
}


PEP_STATUS replace_identities_fpr(PEP_SESSION session, 
                                 const char* old_fpr, 
                                 const char* new_fpr) 
{
    PEP_REQUIRE(session && ! EMPTYSTR(old_fpr) && ! EMPTYSTR(new_fpr));

    sql_reset_and_clear_bindings(session->replace_identities_fpr);
    sqlite3_bind_text(session->replace_identities_fpr, 1, new_fpr, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->replace_identities_fpr, 2, old_fpr, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->replace_identities_fpr);
    sql_reset_and_clear_bindings(session->replace_identities_fpr);
    
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

PEP_STATUS update_trust_for_fpr(PEP_SESSION session, 
                                const char* fpr, 
                                PEP_comm_type comm_type)
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    sql_reset_and_clear_bindings(session->update_trust_for_fpr);
    sqlite3_bind_int(session->update_trust_for_fpr, 1, comm_type);
    sqlite3_bind_text(session->update_trust_for_fpr, 2, fpr, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->update_trust_for_fpr);
    sql_reset_and_clear_bindings(session->update_trust_for_fpr);
    if (result != SQLITE_DONE) {
        return PEP_CANNOT_SET_TRUST;
    }
    
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS set_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        unsigned int flags
    )
{
    PEP_REQUIRE(session && identity
                && ! EMPTYSTR(identity->address)
                && ! EMPTYSTR(identity->user_id));

    int result;
    sql_reset_and_clear_bindings(session->set_identity_flags);
    sqlite3_bind_int(session->set_identity_flags, 1, flags);
    sqlite3_bind_text(session->set_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_identity_flags, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = pEp_sqlite3_step_nonbusy(session, session->set_identity_flags);

    sql_reset_and_clear_bindings(session->set_identity_flags);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    identity->flags |= flags;
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS unset_identity_flags(
        PEP_SESSION session,
        pEp_identity *identity,
        unsigned int flags
    )
{
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->address)
                && ! EMPTYSTR(identity->user_id));

    int result;
    sql_reset_and_clear_bindings(session->unset_identity_flags);
    sqlite3_bind_int(session->unset_identity_flags, 1, flags);
    sqlite3_bind_text(session->unset_identity_flags, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->unset_identity_flags, 3, identity->user_id, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->unset_identity_flags);
    sql_reset_and_clear_bindings(session->unset_identity_flags);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    identity->flags &= ~flags;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS set_ident_enc_format(
        PEP_SESSION session,
        pEp_identity *identity,
        PEP_enc_format format
    )
{
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->address)
                && ! EMPTYSTR(identity->user_id));

    int result;
    sql_reset_and_clear_bindings(session->set_ident_enc_format);
    sqlite3_bind_int(session->set_ident_enc_format, 1, format);
    sqlite3_bind_text(session->set_ident_enc_format, 2, identity->address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_ident_enc_format, 3, identity->user_id, -1,
        SQLITE_STATIC);
        
    result = pEp_sqlite3_step_nonbusy(session, session->set_ident_enc_format);

    sql_reset_and_clear_bindings(session->set_ident_enc_format);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_IDENTITY;

    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       get_trust_by_userid()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session                session handle    
 *  @param[in]    *user_id            constchar
 *  @param[in]    **trust_list        labeled_int_list_t
 *  
 *  @retval     PEP_ILLEGAL_VALUE   illegal parameter value
 *  @retval     PEP_STATUS_OK
 *
 */
PEP_STATUS get_trust_by_userid(PEP_SESSION session, const char* user_id,
                                           labeled_int_list_t** trust_list)
{
    PEP_REQUIRE(session && ! EMPTYSTR(user_id) && trust_list);

    int result;
    *trust_list = NULL;
    labeled_int_list_t* t_list = NULL;

    sql_reset_and_clear_bindings(session->get_trust_by_userid);
    sqlite3_bind_text(session->get_trust_by_userid, 1, user_id, -1, SQLITE_STATIC);

    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_trust_by_userid)) == SQLITE_ROW) {
        if (!t_list)
            t_list = new_labeled_int_list(sqlite3_column_int(session->get_trust_by_userid, 1),
                                         (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
        else
            labeled_int_list_add(t_list, sqlite3_column_int(session->get_trust_by_userid, 1),
                                (const char *) sqlite3_column_text(session->get_trust_by_userid, 0));
    }

    sql_reset_and_clear_bindings(session->get_trust_by_userid);

    *trust_list = t_list;
        
    return PEP_STATUS_OK;
}

/**
 *  @internal
 *
 *  <!--       reconcile_trust()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    t_old        PEP_comm_type
 *  @param[in]    t_new        PEP_comm_type
 *  
 *  @retval     PEP_comm_type   result     
 */
PEP_comm_type reconcile_trust(PEP_comm_type t_old, PEP_comm_type t_new) {
    switch (t_new) {
        case PEP_ct_mistrusted:
        case PEP_ct_key_revoked:
        case PEP_ct_compromised:
        case PEP_ct_key_b0rken:
            return t_new;
        default:
            break;
    }
    switch (t_old) {
        case PEP_ct_mistrusted:
        case PEP_ct_key_revoked:
        case PEP_ct_compromised:
        case PEP_ct_key_b0rken:
            return t_old;
        default:
            break;
    }
    if (t_old < PEP_ct_strong_but_unconfirmed && t_new >= PEP_ct_strong_but_unconfirmed)
        return t_new;
    
    bool confirmed = (t_old & PEP_ct_confirmed) || (t_new & PEP_ct_confirmed);
    PEP_comm_type result = _MAX(t_old, t_new);
    if (confirmed)
        result |= PEP_ct_confirmed;
    return result;
}

/**
 *  @internal
 *
 *  <!--       reconcile_pEp_status()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_uid        constchar
 *  @param[in]    *new_uid        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *
 */
PEP_STATUS reconcile_pEp_status(PEP_SESSION session, const char* old_uid,
                                const char* new_uid) {
    PEP_REQUIRE(session && ! EMPTYSTR(old_uid) && ! EMPTYSTR(new_uid));

    PEP_STATUS status = PEP_STATUS_OK;
    // We'll make this easy - if the old one has a pEp status, we set no matter
    // what.
    pEp_identity* ident = new_identity(NULL, NULL, old_uid, NULL);
    bool is_pEp_peep = false;
    status = is_pEp_user(session, ident, &is_pEp_peep);
    if (is_pEp_peep) {
        free(ident->user_id);
        ident->user_id = strdup(new_uid);
        if (!ident->user_id) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
        status = set_as_pEp_user(session, ident);
    }
pEp_free:
    free_identity(ident);
    return status;
}

/**
 *  @internal
 *
 *  <!--       reconcile_usernames()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *old_name        constchar
 *  @param[in]    *new_name        constchar
 *  @param[in]    *address        constchar
 *
 *
 */
const char* reconcile_usernames(const char* old_name, const char* new_name,
                                const char* address) {
    if (EMPTYSTR(old_name)) {
        if (EMPTYSTR(new_name))
            return address;
        else
            return new_name;
    }
    if (EMPTYSTR(new_name))
        return old_name;        
    if (strcmp(new_name, address) == 0)
        return old_name;
    return new_name;        
}

/**
 *  @internal
 *
 *  <!--       reconcile_default_keys()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_ident        pEp_identity
 *  @param[in]    *new_ident        pEp_identity
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *
 */
PEP_STATUS reconcile_default_keys(PEP_SESSION session, pEp_identity* old_ident,
                                  pEp_identity* new_ident) {
    PEP_REQUIRE(session && old_ident && new_ident);

    PEP_STATUS status = PEP_STATUS_OK;
    const char* old_fpr = old_ident->fpr;
    const char* new_fpr = new_ident->fpr;
    if (!old_fpr)
        return status;

    PEP_comm_type old_ct = old_ident->comm_type;    
    PEP_comm_type new_ct = new_ident->comm_type;
    
    if (!new_fpr) {
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
        return status;
    }        
    
    if (strcmp(old_fpr, new_fpr) == 0) {
        new_ident->comm_type = reconcile_trust(old_ct, new_ct);
        return status;
    }
    
    bool old_confirmed = old_ct & PEP_ct_confirmed;
    bool new_confirmed = new_ct & PEP_ct_confirmed;
    
    if (new_confirmed)
        return status;
    else if (old_confirmed) {
        free(new_ident->fpr);
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
        return status;
    }
    
    if (old_ct > new_ct) {
        free(new_ident->fpr);
        new_ident->fpr = strdup(old_fpr);
        if (!new_ident->fpr)
            status = PEP_OUT_OF_MEMORY;
        else    
            new_ident->comm_type = old_ct;
    }
    return status;
}

/**
 *  @internal
 *
 *  <!--       reconcile_language()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *old_ident        pEp_identity
 *  @param[in]    *new_ident        pEp_identity
 *
 */
void reconcile_language(pEp_identity* old_ident,
                        pEp_identity* new_ident) {
    if (new_ident->lang[0] == 0) {
        if (old_ident->lang[0] != 0) {
            new_ident->lang[0] = old_ident->lang[0];
            new_ident->lang[1] = old_ident->lang[1];
            new_ident->lang[2] = old_ident->lang[2];
        }
    }
}

// ONLY CALL THIS IF BOTH IDs ARE IN THE PERSON DB, FOOL! </Mr_T>
/**
 *  @internal
 *
 *  <!--       merge_records()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session            session handle    
 *  @param[in]    *old_uid        constchar
 *  @param[in]    *new_uid        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *  @retval     PEP_CANNOT_FIND_IDENTITY
 *
 */
PEP_STATUS merge_records(PEP_SESSION session, const char* old_uid,
                         const char* new_uid) {
    PEP_REQUIRE(session && ! EMPTYSTR(old_uid) && ! EMPTYSTR(new_uid));

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* new_ident = NULL;
    identity_list* old_identities = NULL;
    labeled_int_list_t* trust_list = NULL;
    stringlist_t* touched_keys = new_stringlist(NULL);
    char* main_user_fpr = NULL;

    status = reconcile_pEp_status(session, old_uid, new_uid);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
                        
    bool new_is_pEp = false;
    new_ident = new_identity(NULL, NULL, new_uid, NULL);
    status = is_pEp_user(session, new_ident, &new_is_pEp);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    free(new_ident);
    new_ident = NULL;
        
    status = get_identities_by_userid(session, old_uid, &old_identities);
    if (status == PEP_STATUS_OK && old_identities) {
        identity_list* curr_old = old_identities;
        for (; curr_old && curr_old->ident; curr_old = curr_old->next) {
            pEp_identity* old_ident = curr_old->ident;
            const char* address = old_ident->address;
            status = get_identity(session, address, new_uid, &new_ident);
            if (status == PEP_CANNOT_FIND_IDENTITY) {
                // No new identity matching the old one, so we just set one w. new user_id
                free(old_ident->user_id);
                old_ident->user_id = strdup(new_uid);
                if (!old_ident->user_id) {
                    status = PEP_OUT_OF_MEMORY;
                    goto pEp_free;
                }
                if (new_is_pEp) {
                    PEP_comm_type confirmed_bit = old_ident->comm_type & PEP_ct_confirmed;
                    if ((old_ident->comm_type | PEP_ct_confirmed) == PEP_ct_OpenPGP)
                        old_ident->comm_type = PEP_ct_pEp_unconfirmed | confirmed_bit;
                }
                
                status = set_identity(session, old_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;
            }
            else if (status != PEP_STATUS_OK)
                goto pEp_free;
            else {
                // Ok, so we have two idents which might be in conflict. Have to merge them.
                const char* username = reconcile_usernames(old_ident->username,
                                                           new_ident->username,
                                                           address);
                                                           
                if (!new_ident->username || strcmp(username, new_ident->username) != 0) {
                    free(new_ident->username);
                    new_ident->username = strdup(username);
                    if (!new_ident->username) {
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_free;
                    }
                }
        
                // Reconcile default keys if they differ, trust if they don't
                status = reconcile_default_keys(session, old_ident, new_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;
                    
                // reconcile languages
                reconcile_language(old_ident, new_ident);

                // reconcile flags - FIXME - is this right?
                new_ident->flags |= old_ident->flags;
                
                // NOTE: In principle, this is only called from update_identity,
                // which would never have me flags set. So I am ignoring them here.
                // if this function is ever USED for that, though, you'll have
                // to go through making sure that the user ids are appropriately
                // aliased, etc. So be careful.
                
                // Set the reconciled record
                    
                status = set_identity(session, new_ident);
                if (status != PEP_STATUS_OK)
                    goto pEp_free;

                if (new_ident->fpr)
                    stringlist_add(touched_keys, new_ident->fpr);
                        
                free_identity(new_ident);
                new_ident = NULL;    
            }
        }
    }
    // otherwise, no need to reconcile identity records. But maybe trust...    
    new_ident = new_identity(NULL, NULL, new_uid, NULL);
    if (!new_ident) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }
    status = get_trust_by_userid(session, old_uid, &trust_list);

    labeled_int_list_t* trust_curr = trust_list;
    for (; trust_curr && trust_curr->label; trust_curr = trust_curr->next) {
        const char* curr_fpr = trust_curr->label;
        new_ident->fpr = strdup(curr_fpr); 
        status = get_trust(session, new_ident);
        switch (status) {
            case PEP_STATUS_OK:
                new_ident->comm_type = reconcile_trust(trust_curr->value,
                                                       new_ident->comm_type);
                break;
            case PEP_CANNOT_FIND_IDENTITY:
                new_ident->comm_type = trust_curr->value;
                break;
            default:
                goto pEp_free;
        }
        new_ident->comm_type = reconcile_trust(trust_curr->value,
                                               new_ident->comm_type);
        if (new_is_pEp) {
            PEP_comm_type confirmed_bit = new_ident->comm_type & PEP_ct_confirmed;
            if ((new_ident->comm_type | PEP_ct_confirmed) == PEP_ct_OpenPGP)
                new_ident->comm_type = PEP_ct_pEp_unconfirmed | confirmed_bit;
        }

        status = set_trust(session, new_ident);
        if (status != PEP_STATUS_OK) {
            goto pEp_free;
        }                  
                              
        free(new_ident->fpr);
        new_ident->fpr = NULL;
        new_ident->comm_type = 0;
    }

    // reconcile the default keys if the new id doesn't have one?
    status = get_main_user_fpr(session, new_uid, &main_user_fpr);
    if (status == PEP_KEY_NOT_FOUND || (status == PEP_STATUS_OK && !main_user_fpr)) {
        status = get_main_user_fpr(session, old_uid, &main_user_fpr);
        if (status == PEP_STATUS_OK && main_user_fpr)
            status = replace_main_user_fpr(session, new_uid, main_user_fpr);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    }
    
    // delete the old user
    status = delete_person(session, old_uid);
    
pEp_free:
    free_identity(new_ident);
    free_identity_list(old_identities);
    free_labeled_int_list(trust_list);
    free_stringlist(touched_keys);
    free(main_user_fpr);
    return status;
}

PEP_STATUS replace_userid(PEP_SESSION session, const char* old_uid,
                          const char* new_uid) {
    PEP_REQUIRE(session && ! EMPTYSTR(old_uid) && ! EMPTYSTR(new_uid));

    pEp_identity* temp_ident = new_identity(NULL, NULL, new_uid, NULL);
    bool new_exists = false;
    PEP_STATUS status = exists_person(session, temp_ident, &new_exists);
    free_identity(temp_ident);
    if (status != PEP_STATUS_OK) // DB error
        return status;
        
    if (new_exists)
        return merge_records(session, old_uid, new_uid);

    int result;

    sql_reset_and_clear_bindings(session->replace_userid);
    sqlite3_bind_text(session->replace_userid, 1, new_uid, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_userid, 2, old_uid, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->replace_userid);
    if (result != SQLITE_DONE) {
        const char *errmsg = sqlite3_errmsg(session->db);
        LOG_ERROR("SQLite3 error: replace_userid failed: %s", errmsg);
    }
    sql_reset_and_clear_bindings(session->replace_userid);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON; // May need clearer retval

    return PEP_STATUS_OK;
}

PEP_STATUS remove_key(PEP_SESSION session, const char* fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    int result;
    sql_reset_and_clear_bindings(session->delete_key);
    sqlite3_bind_text(session->delete_key, 1, fpr, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->delete_key);
    sql_reset_and_clear_bindings(session->delete_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR;

    return PEP_STATUS_OK;
}


PEP_STATUS refresh_userid_default_key(PEP_SESSION session, const char* user_id) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id));

    int result;
    sql_reset_and_clear_bindings(session->refresh_userid_default_key);
    sqlite3_bind_text(session->refresh_userid_default_key, 1, user_id, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->refresh_userid_default_key);
    sql_reset_and_clear_bindings(session->refresh_userid_default_key);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;    
}

PEP_STATUS replace_main_user_fpr(PEP_SESSION session, const char* user_id,
                                 const char* new_fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id) && ! EMPTYSTR(new_fpr));

    int result;
    sql_reset_and_clear_bindings(session->replace_main_user_fpr);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr, 2, user_id, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->replace_main_user_fpr);
    sql_reset_and_clear_bindings(session->replace_main_user_fpr);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

PEP_STATUS replace_main_user_fpr_if_equal(PEP_SESSION session, const char* user_id,
                                          const char* new_fpr, const char* compare_fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id)
                /* new_fpr is allowed to be empty. */
                && ! EMPTYSTR(compare_fpr));

    // N.B. new_fpr can be empty - if there's no key to replace it, this is fine.
    // See sqlite3 documentation on sqlite3_bind_text() and sqlite3_bind_null()
    if (EMPTYSTR(new_fpr))
        new_fpr = NULL;

    int result;

    sql_reset_and_clear_bindings(session->replace_main_user_fpr_if_equal);
    sqlite3_bind_text(session->replace_main_user_fpr, 1, new_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 2, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->replace_main_user_fpr_if_equal, 3, compare_fpr, -1,
            SQLITE_STATIC);            
    result = pEp_sqlite3_step_nonbusy(session, session->replace_main_user_fpr_if_equal);
    sql_reset_and_clear_bindings(session->replace_main_user_fpr_if_equal);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PERSON;

    return PEP_STATUS_OK;
}

PEP_STATUS get_main_user_fpr(PEP_SESSION session, 
                             const char* user_id,
                             char** main_fpr)
{
    PEP_REQUIRE(session && ! EMPTYSTR(user_id) && main_fpr);

    PEP_STATUS status = PEP_STATUS_OK;
    int result;
    *main_fpr = NULL;
    
    sql_reset_and_clear_bindings(session->get_main_user_fpr);
    sqlite3_bind_text(session->get_main_user_fpr, 1, user_id, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->get_main_user_fpr);
    switch (result) {
    case SQLITE_ROW: {
        const char* _fpr = 
            (const char *) sqlite3_column_text(session->get_main_user_fpr, 0);
        if (_fpr) {
            *main_fpr = strdup(_fpr);
            if (!(*main_fpr))
                status = PEP_OUT_OF_MEMORY;
        }
        else {
            status = PEP_KEY_NOT_FOUND;
        }
        break;
    }
    default:
        status = PEP_CANNOT_FIND_PERSON;
    }

    sql_reset_and_clear_bindings(session->get_main_user_fpr);
    return status;
}


PEP_STATUS set_default_identity_fpr(PEP_SESSION session,
                                    const char* user_id,
                                    const char* address,
                                    const char* fpr) {
    PEP_REQUIRE(session && ! EMPTYSTR(user_id) && ! EMPTYSTR(address)
                && ! EMPTYSTR(fpr));

    // Make sure fpr is in the management DB
    PEP_STATUS status = set_pgp_keypair(session, fpr);
    if (status != PEP_STATUS_OK)
        return status;

    int result;

    sql_reset_and_clear_bindings(session->set_default_identity_fpr);
    sqlite3_bind_text(session->set_default_identity_fpr, 1, user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_default_identity_fpr, 2, address, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_default_identity_fpr, 3, fpr, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->set_default_identity_fpr);
    sql_reset_and_clear_bindings(session->set_default_identity_fpr);
    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR;

    return PEP_STATUS_OK;
}



PEP_STATUS get_default_identity_fpr(PEP_SESSION session, 
                                    const char* address,                            
                                    const char* user_id,
                                    char** main_fpr)
{
    PEP_REQUIRE(session && ! EMPTYSTR(address) && ! EMPTYSTR(user_id)
                && main_fpr);

    PEP_STATUS status = PEP_STATUS_OK;
    int result;
    *main_fpr = NULL;
    
    sql_reset_and_clear_bindings(session->get_default_identity_fpr);
    sqlite3_bind_text(session->get_default_identity_fpr, 1, address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_default_identity_fpr, 2, user_id, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->get_default_identity_fpr);
    switch (result) {
    case SQLITE_ROW: {
        const char* _fpr = 
            (const char *) sqlite3_column_text(session->get_default_identity_fpr, 0);
        if (_fpr) {
            *main_fpr = strdup(_fpr);
            if (!(*main_fpr))
                status = PEP_OUT_OF_MEMORY;
        }
        else {
            status = PEP_KEY_NOT_FOUND;
        }
        break;
    }
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
    }

    sql_reset_and_clear_bindings(session->get_default_identity_fpr);
    return status;
}


// Deprecated
DYNAMIC_API PEP_STATUS mark_as_compromized(
        PEP_SESSION session,
        const char *fpr
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    LOG_WARNING("deprecated function");
    return mark_as_compromised(session, fpr);
}

DYNAMIC_API PEP_STATUS mark_as_compromised(
        PEP_SESSION session,
        const char *fpr
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    int result;
    sql_reset_and_clear_bindings(session->mark_compromised);
    sqlite3_bind_text(session->mark_compromised, 1, fpr, -1,
            SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->mark_compromised);
    sql_reset_and_clear_bindings(session->mark_compromised);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_TRUST;

    return PEP_STATUS_OK;
}

DYNAMIC_API void pEp_free(void *p)
{
    free(p);
}

DYNAMIC_API void *pEp_realloc(void *p, size_t size)
{
    return realloc(p, size);
}

DYNAMIC_API PEP_STATUS get_trust(PEP_SESSION session, pEp_identity *identity)
{
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->user_id)
                && ! EMPTYSTR(identity->fpr));

    PEP_STATUS status = PEP_STATUS_OK;
    int result;
    identity->comm_type = PEP_ct_unknown;
    sql_reset_and_clear_bindings(session->get_trust);

    sqlite3_bind_text(session->get_trust, 1, identity->user_id, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->get_trust, 2, identity->fpr, -1, SQLITE_STATIC);

    result = pEp_sqlite3_step_nonbusy(session, session->get_trust);
    switch (result) {
    case SQLITE_ROW: {
        int comm_type = (PEP_comm_type) sqlite3_column_int(session->get_trust,
                0);
        identity->comm_type = comm_type;
        break;
    }
 
    default:
        status = PEP_CANNOT_FIND_IDENTITY;
    }

    sql_reset_and_clear_bindings(session->get_trust);
    return status;
}


DYNAMIC_API PEP_STATUS least_trust(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && comm_type);

    PEP_STATUS status = PEP_STATUS_OK;
    int result;

    *comm_type = PEP_ct_unknown;

    sql_reset_and_clear_bindings(session->least_trust);
    sqlite3_bind_text(session->least_trust, 1, fpr, -1, SQLITE_STATIC);

    result = pEp_sqlite3_step_nonbusy(session, session->least_trust);
    switch (result) {
        case SQLITE_ROW: {
            int _comm_type = sqlite3_column_int(session->least_trust, 0);
            *comm_type = (PEP_comm_type) _comm_type;
            break;
        }
        default:
            // never reached because of sql min()
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sql_reset_and_clear_bindings(session->least_trust);
    return status;
}

/**
 *  @internal
 *
 *  <!--       sanitize_pgp_filename()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *filename        char
 *
 */
static void sanitize_pgp_filename(char *filename)
{
    for (int i=0; filename[i]; ++i) {
        switch(filename[i]) {
            // path separators
            case '/':
            case ':':
            case '\\':
            // expansion operators
            case '%':
            case '$':
            // code execution operators
            case '`':
            case '|':
                filename[i] = '-';
                break;
        }
    }
}

DYNAMIC_API PEP_STATUS decrypt_and_verify(
    PEP_SESSION session, const char *ctext, size_t csize,
    const char *dsigtext, size_t dsigsize,
    char **ptext, size_t *psize, stringlist_t **keylist,
    char** filename_ptr
    )
{
    PEP_REQUIRE(session && ctext && csize
                && ptext && psize && keylist);

    PEP_STATUS status = session->cryptotech[PEP_crypt_OpenPGP].decrypt_and_verify(
            session, ctext, csize, dsigtext, dsigsize, ptext, psize, keylist,
            filename_ptr);

    if (status == PEP_DECRYPT_NO_KEY)
        signal_Sync_event(session, Sync_PR_keysync, CannotDecrypt, NULL);

    if (filename_ptr && *filename_ptr)
        sanitize_pgp_filename(*filename_ptr);

    return status;
}

DYNAMIC_API PEP_STATUS encrypt_and_sign(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    PEP_REQUIRE(session && keylist && ptext && psize
                && ctext && csize);

    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_and_sign(session,
            keylist, ptext, psize, ctext, csize);
}

PEP_STATUS encrypt_only(
    PEP_SESSION session, const stringlist_t *keylist, const char *ptext,
    size_t psize, char **ctext, size_t *csize
    )
{
    PEP_REQUIRE(session && keylist && ptext && psize
                && ctext && csize);

    return session->cryptotech[PEP_crypt_OpenPGP].encrypt_only(session,
            keylist, ptext, psize, ctext, csize);
}

PEP_STATUS sign_only(PEP_SESSION session, 
                     const char *data, 
                     size_t data_size, 
                     const char *fpr, 
                     char **sign, 
                     size_t *sign_size) {
    PEP_REQUIRE(session && data && data_size && ! EMPTYSTR(fpr)
                && sign && sign_size);

    return session->cryptotech[PEP_crypt_OpenPGP].sign_only(session,
                                fpr, data, data_size, sign, sign_size);
                         
}

DYNAMIC_API PEP_STATUS probe_encrypt(PEP_SESSION session, const char *fpr)
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    stringlist_t *keylist = new_stringlist(fpr);
    if (!keylist)
        return PEP_OUT_OF_MEMORY;

    char *ctext = NULL;
    size_t csize = 0;
    PEP_STATUS status = encrypt_and_sign(session, keylist, "pEp", 4, &ctext, &csize);
    free(ctext);

    return status;
}


DYNAMIC_API PEP_STATUS verify_text(
    PEP_SESSION session, const char *text, size_t size,
    const char *signature, size_t sig_size, stringlist_t **keylist
    )
{
    PEP_REQUIRE(session && text && size && signature && sig_size && keylist);

    return session->cryptotech[PEP_crypt_OpenPGP].verify_text(session, text,
            size, signature, sig_size, keylist);
}

DYNAMIC_API PEP_STATUS delete_keypair(PEP_SESSION session, const char *fpr)
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr));

    return session->cryptotech[PEP_crypt_OpenPGP].delete_keypair(session, fpr);
}

DYNAMIC_API PEP_STATUS export_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && key_data && size);

    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr,
            key_data, size, false);
}

DYNAMIC_API PEP_STATUS export_secret_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && key_data && size);

    // don't accept key IDs but full fingerprints only
    if (strlen(fpr) < 16)
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].export_key(session, fpr,
            key_data, size, true);
}

// Deprecated
DYNAMIC_API PEP_STATUS export_secrect_key(
        PEP_SESSION session, const char *fpr, char **key_data, size_t *size
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && key_data && size);

    LOG_WARNING("deprecated function");
    return export_secret_key(session, fpr, key_data, size);
}

DYNAMIC_API PEP_STATUS find_keys(
        PEP_SESSION session, const char *pattern, stringlist_t **keylist
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(pattern) && keylist);

    return session->cryptotech[PEP_crypt_OpenPGP].find_keys(session, pattern,
            keylist);
}


DYNAMIC_API PEP_STATUS generate_keypair(
        PEP_SESSION session, pEp_identity *identity
    )
{
    PEP_REQUIRE(session && identity);

    return _generate_keypair(session, identity, false);
}

PEP_STATUS _generate_keypair(PEP_SESSION session, 
                             pEp_identity *identity,
                             bool suppress_event
    )
{
    PEP_REQUIRE(session && identity && ! EMPTYSTR(identity->address)
                /* identity->username is allowed to be empty */
                && /* not a mistake: it must be empty */ EMPTYSTR(identity->fpr)
                );

    // N.B. We now allow empty usernames, so the underlying layer for 
    // non-sequoia crypto implementations will have to deal with this.

    char* saved_username = NULL;

    // KB: In light of the above, remove? FIXME.
    if (identity->username) {    
        char* at = NULL;
        size_t uname_len = strlen(identity->username);
        
        if (uname_len > 0)
            at = strstr(identity->username, "@"); 
        
        if (at) {
            saved_username = identity->username;
            identity->username = calloc(uname_len + 3, 1);
            if (!identity->username) {
                identity->username = saved_username;
                return PEP_OUT_OF_MEMORY;
            }
            identity->username[0] = '"';
            strlcpy((identity->username) + 1, saved_username, uname_len + 1);
            identity->username[uname_len + 1] = '"';        
        }
    }
        
    PEP_STATUS status =
        session->cryptotech[PEP_crypt_OpenPGP].generate_keypair(session,
                identity);
                
    if (saved_username) {
        free(identity->username);
        identity->username = saved_username;
    }            
    if (status != PEP_STATUS_OK)
        return status;

    if (identity->fpr)
        status = set_pgp_keypair(session, identity->fpr);

    if ((!suppress_event) && (identity->flags & PEP_idf_devicegroup))
        signal_Sync_event(session, Sync_PR_keysync, KeyGen, NULL);

    // add to known keypair DB, as this might not end up being a default
    return status;
}

// SHOULD NOT (in implementation) ever return PASSPHRASE errors
DYNAMIC_API PEP_STATUS get_key_rating(
        PEP_SESSION session,
        const char *fpr,
        PEP_comm_type *comm_type
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && comm_type);

    return session->cryptotech[PEP_crypt_OpenPGP].get_key_rating(session, fpr,
            comm_type);
}

DYNAMIC_API PEP_STATUS import_key(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys)
{
    PEP_REQUIRE(session && key_data && size
                /* private_keys is allowed to be NULL. */);

    /* When provided initialise private_keys out of defensiveness, to avoid
       misleading the caller with invalid pointers even in case of failure. */
    if (private_keys != NULL)
        * private_keys = NULL;

    return import_key_with_fpr_return(session, key_data, size, private_keys, NULL, NULL);
}

DYNAMIC_API PEP_STATUS import_key_with_fpr_return(
        PEP_SESSION session,
        const char *key_data,
        size_t size,
        identity_list **private_keys,
        stringlist_t** imported_keys,
        uint64_t* changed_public_keys        
    )
{
    PEP_REQUIRE(session && key_data && size
                /* the other fields are allowed to be NULL. */);

    /* When provided initialise private_keys out of defensiveness, to avoid
       misleading the caller with invalid pointers even in case of failure;
       do not do the same with imported_keys, which is an inout parameter. */
    if (private_keys != NULL)
        * private_keys = NULL;

    if (imported_keys && !*imported_keys && changed_public_keys)
        *changed_public_keys = 0;

    return session->cryptotech[PEP_crypt_OpenPGP].import_key(session, key_data,
            size, private_keys, imported_keys, changed_public_keys);
}

DYNAMIC_API PEP_STATUS recv_key(PEP_SESSION session, const char *pattern)
{
    PEP_REQUIRE(session && ! EMPTYSTR(pattern));

    return session->cryptotech[PEP_crypt_OpenPGP].recv_key(session, pattern);
}

DYNAMIC_API PEP_STATUS send_key(PEP_SESSION session, const char *pattern)
{
    PEP_REQUIRE(session && ! EMPTYSTR(pattern));

    return session->cryptotech[PEP_crypt_OpenPGP].send_key(session, pattern);
}

DYNAMIC_API PEP_STATUS renew_key(
        PEP_SESSION session,
        const char *fpr,
        const timestamp *ts
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr)
                /* ts is allowed to be NULL. */);

    return session->cryptotech[PEP_crypt_OpenPGP].renew_key(session, fpr, ts);
}

DYNAMIC_API PEP_STATUS revoke_key(
        PEP_SESSION session,
        const char *fpr,
        const char *reason
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr)
                /* reason is allowed to be empty. */);

    // Check to see first if it is revoked
    bool revoked = false;
    PEP_STATUS status = key_revoked(session, fpr, &revoked);
    if (status != PEP_STATUS_OK)
        return status;
        
    if (revoked)
        return PEP_STATUS_OK;

    return session->cryptotech[PEP_crypt_OpenPGP].revoke_key(session, fpr,
            reason);
}

DYNAMIC_API PEP_STATUS key_expired(
        PEP_SESSION session,
        const char *fpr,
        const time_t when,
        bool *expired
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && expired);

    PEP_STATUS status
        = session->cryptotech[PEP_crypt_OpenPGP].key_expired(session, fpr,
                                                             when, expired);
    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK && * expired)
        LOG_NONOK("EXPIRED KEY: %s", fpr);
    return status;
}

DYNAMIC_API PEP_STATUS key_revoked(
       PEP_SESSION session,
       const char *fpr,
       bool *revoked
   )
{    
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && revoked);

    PEP_STATUS status
        = session->cryptotech[PEP_crypt_OpenPGP].key_revoked(session, fpr,
                                                             revoked);
    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK && * revoked)
        LOG_NONOK("REVOKED KEY: %s", fpr);
    return status;
}

DYNAMIC_API PEP_STATUS config_cipher_suite(PEP_SESSION session,
        PEP_CIPHER_SUITE suite)
{
    PEP_REQUIRE(session);

    return session->cryptotech[PEP_crypt_OpenPGP].config_cipher_suite(session, suite);
}

/**
 *  @internal
 *
 *  <!--       _concat_string()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    *str1        char
 *  @param[in]    *str2        const char
 *  @param[in]    delim        char
 *  
 */
static char *_concat_string(char *str1, const char *str2, char delim)
{
    str2 = str2 ? str2 : "";
    size_t len1 = str1 ? strlen(str1) : 0;
    size_t len2 = strlen(str2);
    size_t len = len1 + len2 + 3;
    char * result = realloc(str1, len + 1);

    if (result) {
        result[len1] = '"';
        strcpy(result + len1 + 1, str2);
        result[len - 2] = '"';
        result[len - 1] = delim;
        result[len] = 0;
    }
    else {
        free(str1);
    }

    return result;
}

/* A helper function for get_crashdump_log . */
static PEP_STATUS get_crashdump_log_combine(PEP_SESSION session,
                                            char **logdata_p,
                                            size_t *used_size_p,
                                            size_t *allocated_size_p,
                                            const char *field,
                                            bool end_of_the_line)
{
    if (false) // too distracting
    PEP_REQUIRE(session && logdata_p
                && used_size_p && allocated_size_p
                /* the new field is allowed to be an empty string or even NULL. */);

    /* We quote if there is any '"' or ',' character inside the field.  '"'
       characters are already escaped as double "\"\"" two-character sequences
       when they come as result of this SQL query; there is no need to escape
       ','. */
    bool need_quotes = (! EMPTYSTR(field)
                        && (strchr(field, '"') != NULL
                            || strchr(field, ',') != NULL));
#define GO(string)                                               \
    do {                                                         \
        status = append_string(session, logdata_p, used_size_p,  \
                               allocated_size_p, (string));      \
        if (status != PEP_STATUS_OK)                             \
            goto end;                                            \
    } while (false)

    PEP_STATUS status = PEP_STATUS_OK;

    if (need_quotes) GO("\"");
    GO(field);
    if (need_quotes) GO("\"");
    if (end_of_the_line) GO("\r\n"); else GO(",");

#undef GO
end:
    return status;
}

DYNAMIC_API PEP_STATUS get_crashdump_log(
        PEP_SESSION session,
        int maxlines,
        char **logdata_p
    )
{
    PEP_REQUIRE(session && logdata_p
                && maxlines >= 0 && maxlines <= CRASHDUMP_MAX_LINES);

    /* Be defensive: start by making the output reasonable. */
    * logdata_p = NULL;

    char *logdata = NULL;
    size_t logdata_used_size = 0;
    size_t logdata_allocated_size = 0;
    PEP_STATUS status = PEP_STATUS_OK;

    /* Fail immediately if we did not initialise prepared statements for the
       database log destination. */
    if (session->log_crashdump_prepared_statement == NULL) {
        status = PEP_RECORD_NOT_FOUND;
        goto end;
    }

    int limit = maxlines ? maxlines : CRASHDUMP_DEFAULT_LINES;

#define APPEND_FIELD(index, end_of_the_line)                                          \
            do {                                                                      \
                const char *_field                                                    \
                    = ((const char *)                                                 \
                       sqlite3_column_text(session->log_crashdump_prepared_statement, \
                                           (index)));                                 \
                status = get_crashdump_log_combine(session, & logdata,          \
                                                   & logdata_used_size,         \
                                                   & logdata_allocated_size,    \
                                                   _field,                      \
                                                   (end_of_the_line));          \
                if (status != PEP_STATUS_OK)                                    \
                    goto end;                                                   \
            } while (false)

    /* Run the SQL prepared statement. */
    sql_reset_and_clear_bindings(session->log_crashdump_prepared_statement);
    sqlite3_bind_int(session->log_crashdump_prepared_statement, 1, limit);

    /* The prepared statement will return each column from the rows to be
       combined, in reverse row order. */
    int sqlite_status = SQLITE_OK;
    do {
        sqlite_status
            = pEp_sqlite3_step_nonbusy(session,
                                       session->log_crashdump_prepared_statement);
        switch (sqlite_status) {
        case SQLITE_DONE:
            /* Do nothing. */
            break;
        case SQLITE_ROW: {
            /* Combine this row to the logdata we already have. */
            APPEND_FIELD(0, false);
            APPEND_FIELD(1, false);
            APPEND_FIELD(2, false);
            APPEND_FIELD(3, true);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
            goto end;
        }
    } while (sqlite_status != SQLITE_DONE);

end:
    /* Only if everything succeeded make the concatenated string accessible to
       the caller. */
    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK)
        * logdata_p = logdata;
    else
        free(logdata);
    return status;

#undef APPEND_FIELD
}

DYNAMIC_API PEP_STATUS get_languagelist(
        PEP_SESSION session,
        char **languages
    )
{
    PEP_REQUIRE(session && languages);

    PEP_STATUS status = PEP_STATUS_OK;
    char *_languages= NULL;
    *languages = NULL;

    const char *lang = NULL;
    const char *name = NULL;
    const char *phrase = NULL;

    sql_reset_and_clear_bindings(session->languagelist);

    int result;

    do {
        result = pEp_sqlite3_step_nonbusy(session, session->languagelist);
        switch (result) {
        case SQLITE_ROW:
            lang = (const char *) sqlite3_column_text(session->languagelist,
                    0);
            name = (const char *) sqlite3_column_text(session->languagelist,
                    1);
            phrase = (const char *) sqlite3_column_text(session->languagelist,
                    2);

            _languages = _concat_string(_languages, lang, ',');
            if (_languages == NULL)
                goto enomem;

            _languages = _concat_string(_languages, name, ',');
            if (_languages == NULL)
                goto enomem;

            _languages = _concat_string(_languages, phrase, '\n');
            if (_languages == NULL)
                goto enomem;

            break;

        case SQLITE_DONE:
            break;

        default:
            status = PEP_UNKNOWN_DB_ERROR;
            result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);

    sql_reset_and_clear_bindings(session->languagelist);
    if (status == PEP_STATUS_OK)
        *languages = _languages;

    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

DYNAMIC_API PEP_STATUS get_phrase(
        PEP_SESSION session,
        const char *lang,
        int phrase_id,
        char **phrase
    )
{
    PEP_REQUIRE(session
                && ! EMPTYSTR(lang)
                && lang[0] != '\0' && lang[1] != '\0' && lang[2] == '\0'
                && phrase);

    PEP_STATUS status = PEP_STATUS_OK;
    *phrase = NULL;

    sql_reset_and_clear_bindings(session->i18n_token);
    sqlite3_bind_text(session->i18n_token, 1, lang, -1, SQLITE_STATIC);
    sqlite3_bind_int(session->i18n_token, 2, phrase_id);

    const char *_phrase = NULL;
    int result;

    result = pEp_sqlite3_step_nonbusy(session, session->i18n_token);
    switch (result) {
    case SQLITE_ROW:
        _phrase = (const char *) sqlite3_column_text(session->i18n_token, 0);
        break;

    case SQLITE_DONE:
        status = PEP_PHRASE_NOT_FOUND;
        break;

    default:
        status = PEP_UNKNOWN_DB_ERROR;
    }

    if (status == PEP_STATUS_OK) {
        *phrase = strdup(_phrase);
        if (*phrase == NULL)
            goto enomem;
    }

    sql_reset_and_clear_bindings(session->i18n_token);
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    return status;
}

/**
 *  @internal
 *
 *  <!--       _get_sequence_value()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *name        const char
 *  @param[in]    *value        int32_t
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_RECORD_NOT_FOUND
 *  @retval     PEP_UNKNOWN_DB_ERROR
 *
 */
static PEP_STATUS _get_sequence_value(PEP_SESSION session, const char *name,
        int32_t *value)
{
    PEP_REQUIRE(session && ! EMPTYSTR(name) && value);

    PEP_STATUS status = PEP_STATUS_OK;
    sql_reset_and_clear_bindings(session->sequence_value2);
    sqlite3_bind_text(session->sequence_value2, 1, name, -1,
            SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->sequence_value2);
    switch (result) {
        case SQLITE_ROW: {
            int32_t _value = (int32_t)
                    sqlite3_column_int(session->sequence_value2, 0);
            *value = _value;
            break;
        }
        case SQLITE_DONE:
            status = PEP_RECORD_NOT_FOUND;
            break;
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    sql_reset_and_clear_bindings(session->sequence_value2);

    return status;
}

/**
 *  @internal
 *
 *  <!--       _increment_sequence_value()       -->
 *
 *  @brief            TODO
 *
 *  @param[in]    session        session handle    
 *  @param[in]    *name        constchar
 *
 *  @retval     PEP_STATUS_OK
 *  @retval     PEP_ILLEGAL_VALUE       illegal parameter value
 *  @retval     PEP_CANNOT_INCREASE_SEQUENCE
 *
 */
static PEP_STATUS _increment_sequence_value(PEP_SESSION session,
        const char *name)
{
    PEP_REQUIRE(session && ! EMPTYSTR(name));

    sql_reset_and_clear_bindings(session->sequence_value1);
    sqlite3_bind_text(session->sequence_value1, 1, name, -1, SQLITE_STATIC);
    int result = pEp_sqlite3_step_nonbusy(session, session->sequence_value1);
    sql_reset_and_clear_bindings(session->sequence_value1);
    PEP_WEAK_ASSERT_ORELSE_RETURN(result == SQLITE_DONE,
                                  PEP_CANNOT_INCREASE_SEQUENCE);
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS sequence_value(
        PEP_SESSION session,
        const char *name,
        int32_t *value
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(name) && value);

    PEP_STATUS status = PEP_STATUS_OK;
    *value = 0;
    PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();
    status = _increment_sequence_value(session, name);
    if (status == PEP_STATUS_OK)
        status = _get_sequence_value(session, name, value);

    if (status == PEP_STATUS_OK) {
        PEP_SQL_COMMIT_TRANSACTION();
        PEP_ASSERT(*value < INT32_MAX);
        if (*value == INT32_MAX){
            return PEP_CANNOT_INCREASE_SEQUENCE;
        }
        return status;
    } else {
        PEP_SQL_ROLLBACK_TRANSACTION();
        return status;
    }

    return status;
}

PEP_STATUS is_own_key(PEP_SESSION session, const char* fpr, bool* own_key) {
    PEP_REQUIRE (session && ! EMPTYSTR(fpr) && own_key);

    *own_key = false;

    char* default_own_userid = NULL;
    pEp_identity* placeholder_ident = NULL;

    PEP_STATUS status = get_default_own_userid(session, &default_own_userid);

    if (status == PEP_STATUS_OK && !EMPTYSTR(default_own_userid)) {
        placeholder_ident = new_identity(NULL, fpr, default_own_userid, NULL);
        if (!placeholder_ident)
            status = PEP_OUT_OF_MEMORY;
        else
            status = get_trust(session, placeholder_ident);

        if (status == PEP_STATUS_OK) {
            if (placeholder_ident->comm_type == PEP_ct_pEp) {
                stringlist_t* keylist = NULL;
                status = find_private_keys(session, fpr, &keylist);
                if (status == PEP_STATUS_OK) {
                    if (keylist && !EMPTYSTR(keylist->value))
                        *own_key = true;
                }
                free_stringlist(keylist);
            }
        }
    }
    if (status == PEP_CANNOT_FIND_IDENTITY)
        status = PEP_STATUS_OK; // either no default own id yet, so no own keys yet
                                // or there was no own trust entry! False either way

    free(default_own_userid);
    free_identity(placeholder_ident);

    return status;
}

DYNAMIC_API PEP_STATUS set_revoked(
       PEP_SESSION session,
       const char *revoked_fpr,
       const char *replacement_fpr,
       const uint64_t revocation_date
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(revoked_fpr)
                && ! EMPTYSTR(replacement_fpr));

    PEP_STATUS status = PEP_STATUS_OK;
    sql_reset_and_clear_bindings(session->set_revoked);
    sqlite3_bind_text(session->set_revoked, 1, revoked_fpr, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->set_revoked, 2, replacement_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_int64(session->set_revoked, 3, revocation_date);

    int result;
    
    result = pEp_sqlite3_step_nonbusy(session, session->set_revoked);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sql_reset_and_clear_bindings(session->set_revoked);
    return status;
}

DYNAMIC_API PEP_STATUS get_revoked(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && revoked_fpr && revocation_date);

    PEP_STATUS status = PEP_STATUS_OK;
    *revoked_fpr = NULL;
    *revocation_date = 0;

    sql_reset_and_clear_bindings(session->get_revoked);
    sqlite3_bind_text(session->get_revoked, 1, fpr, -1, SQLITE_STATIC);

    int result;
    
    result = pEp_sqlite3_step_nonbusy(session, session->get_revoked);
    switch (result) {
        case SQLITE_ROW: {
            *revoked_fpr = strdup((const char *)
                    sqlite3_column_text(session->get_revoked, 0));
            if(*revoked_fpr)
                *revocation_date = sqlite3_column_int64(session->get_revoked,
                        1);
            else
                status = PEP_OUT_OF_MEMORY;

            break;
        }
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sql_reset_and_clear_bindings(session->get_revoked);

    LOG_NONOK_STATUS_NONOK;
    return status;
}

/* doxygen will fetch documentation from pEpEngine.h
 */
DYNAMIC_API PEP_STATUS get_replacement_fpr(
        PEP_SESSION session,
        const char *fpr,
        char **revoked_fpr,
        uint64_t *revocation_date
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && revoked_fpr && revocation_date);

    PEP_STATUS status = PEP_STATUS_OK;
    *revoked_fpr = NULL;
    *revocation_date = 0;

    sql_reset_and_clear_bindings(session->get_replacement_fpr);
    sqlite3_bind_text(session->get_replacement_fpr, 1, fpr, -1, SQLITE_STATIC);

    int result;
    
    result = pEp_sqlite3_step_nonbusy(session, session->get_replacement_fpr);
    switch (result) {
        case SQLITE_ROW: {
            *revoked_fpr = strdup((const char *)
                    sqlite3_column_text(session->get_replacement_fpr, 0));
            if(*revoked_fpr)
                *revocation_date = sqlite3_column_int64(session->get_replacement_fpr,
                        1);
            else
                status = PEP_OUT_OF_MEMORY;

            break;
        }
        default:
            status = PEP_CANNOT_FIND_IDENTITY;
    }

    sql_reset_and_clear_bindings(session->get_replacement_fpr);

    if (status != PEP_CANNOT_FIND_IDENTITY) /* this is not an error, here */
        LOG_NONOK_STATUS_NONOK;
    return status;
}

PEP_STATUS get_last_contacted(
        PEP_SESSION session,
        identity_list** id_list
    )
{
    PEP_REQUIRE(session && id_list);

    *id_list = NULL;
    identity_list* ident_list = NULL;

    sql_reset_and_clear_bindings(session->get_last_contacted);
    int result;

    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_last_contacted)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity(
                (const char *) sqlite3_column_text(session->get_last_contacted, 1),
                NULL,
                (const char *) sqlite3_column_text(session->get_last_contacted, 0),
                NULL);
                
        PEP_WEAK_ASSERT_ORELSE(ident, {
            sql_reset_and_clear_bindings(session->get_last_contacted);
            return PEP_OUT_OF_MEMORY;
        });
    
        if (ident_list)
            identity_list_add(ident_list, ident);
        else
            ident_list = new_identity_list(ident);
    }

    sql_reset_and_clear_bindings(session->get_last_contacted);
    
    *id_list = ident_list;
    
    if (!ident_list)
        return PEP_CANNOT_FIND_IDENTITY;
    
    return PEP_STATUS_OK;    
}


PEP_STATUS key_created(
        PEP_SESSION session,
        const char *fpr,
        time_t *created
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(fpr) && created);

    return session->cryptotech[PEP_crypt_OpenPGP].key_created(session, fpr,
            created);
}

PEP_STATUS find_private_keys(PEP_SESSION session, const char* pattern,
                             stringlist_t **keylist) {
    PEP_REQUIRE(session && keylist);
    
    return session->cryptotech[PEP_crypt_OpenPGP].find_private_keys(session, pattern,
                                                                    keylist);
}

/* These are visible as read-only symbols in some data section of compiled
   executables. */
const char *pEpEngineVersion = PEP_ENGINE_VERSION;
const char *pEpEngineProtcolVersion = PEP_PROTOCOL_VERSION;

DYNAMIC_API const char* get_engine_version(void) {
    return PEP_ENGINE_VERSION;
}

DYNAMIC_API const char* get_protocol_version(void) {
    return PEP_PROTOCOL_VERSION;
}

DYNAMIC_API PEP_STATUS reset_pEptest_hack(PEP_SESSION session)
{
    PEP_REQUIRE(session);

    int int_result = SQLITE_OK;
    PEP_SQL_BEGIN_LOOP(int_result);
    int_result = sqlite3_exec(
        session->db,
        "delete from identity where address like '%@pEptest.ch' ;",
        NULL,
        NULL,
        NULL
    );
    PEP_SQL_END_LOOP();
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    int_result = pEp_sqlite3_prepare_v2_nonbusy_nonlocked(session, session->db, sql_get_all_keys_for_identity,
            (int)strlen(sql_get_all_keys_for_identity), &session->get_all_keys_for_identity, NULL);
    PEP_WEAK_ASSERT_ORELSE_RETURN(int_result == SQLITE_OK, PEP_UNKNOWN_DB_ERROR);

    return PEP_STATUS_OK;
}

PEP_STATUS set_all_userids_to_own(PEP_SESSION session, identity_list* id_list) {
    PEP_REQUIRE(session);

    static char* ownid = NULL;
    PEP_STATUS status = PEP_STATUS_OK;
    if (!ownid) {
        status = get_default_own_userid(session, &ownid);
    }    
    if (status == PEP_STATUS_OK) {
        if (ownid) {
            status = set_all_userids_in_list(id_list, ownid);
        }
    }
    return status;    
}


/* Temporary compatibility definitions
 * ***************************************************************** */
DYNAMIC_API void set_debug_color(PEP_SESSION session, int ansi_color)
{
    PEP_REQUIRE_ORELSE(session != NULL, { return; });
    LOG_WARNING("deprecated function");
}
