/**
 * @file    status_to_string.h
 * @brief   Convert various statuses and enums into string format (generally for logs)
 * @license GNU General Public License 3.0 - see LICENSE.txt
 * @todo    generate this file
 */

#ifndef STATUS_TO_STRING_H
#define STATUS_TO_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pEpEngine.h"
#ifndef PEP_STATUS_TO_STRING
#define PEP_STATUS_TO_STRING
#endif

/**
 *  <!--       pEp_status_to_string()       -->
 *
 *  @brief     Return a human-readable string representation of the given
 *             state, or a human-readable string saying that the state is
 *             invalid if it is.
 *
 *  @param[in]  status		PEP_STATUS
 *  @retval	char*		string representation of status	
 *
 *  positron may want to use this again:
 *    (replace-regexp " +\\(PEP_.*\\)$" "    case \\1: return \"\\1\";")
 */
static inline const char *pEp_status_to_string(PEP_STATUS status) {
    switch (status) {
    case PEP_STATUS_OK: return "PEP_STATUS_OK";
    case PEP_INIT_CANNOT_LOAD_CRYPTO_LIB: return "PEP_INIT_CANNOT_LOAD_CRYPTO_LIB";
    case PEP_INIT_CRYPTO_LIB_INIT_FAILED: return "PEP_INIT_CRYPTO_LIB_INIT_FAILED";
    case PEP_INIT_NO_CRYPTO_HOME: return "PEP_INIT_NO_CRYPTO_HOME";
//    case PEP_INIT_NETPGP_INIT_FAILED: return "PEP_INIT_NETPGP_INIT_FAILED";
    case PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION: return "PEP_INIT_CANNOT_DETERMINE_CRYPTO_VERSION";
    case PEP_INIT_UNSUPPORTED_CRYPTO_VERSION: return "PEP_INIT_UNSUPPORTED_CRYPTO_VERSION";
    case PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT: return "PEP_INIT_CANNOT_CONFIG_CRYPTO_AGENT";
    case PEP_INIT_SQLITE3_WITHOUT_MUTEX: return "PEP_INIT_SQLITE3_WITHOUT_MUTEX";
    case PEP_INIT_CANNOT_OPEN_DB: return "PEP_INIT_CANNOT_OPEN_DB";
    case PEP_INIT_CANNOT_OPEN_SYSTEM_DB: return "PEP_INIT_CANNOT_OPEN_SYSTEM_DB";
    case PEP_INIT_DB_DOWNGRADE_VIOLATION: return "PEP_INIT_DB_DOWNGRADE_VIOLATION";
    case PEP_UNKNOWN_DB_ERROR: return "PEP_UNKNOWN_DB_ERROR";
    case PEP_KEY_NOT_FOUND: return "PEP_KEY_NOT_FOUND";
    case PEP_KEY_HAS_AMBIG_NAME: return "PEP_KEY_HAS_AMBIG_NAME";
    case PEP_GET_KEY_FAILED: return "PEP_GET_KEY_FAILED";
    case PEP_CANNOT_EXPORT_KEY: return "PEP_CANNOT_EXPORT_KEY";
    case PEP_CANNOT_EDIT_KEY: return "PEP_CANNOT_EDIT_KEY";
    case PEP_KEY_UNSUITABLE: return "PEP_KEY_UNSUITABLE";
    case PEP_MALFORMED_KEY_RESET_MSG: return "PEP_MALFORMED_KEY_RESET_MSG";
    case PEP_KEY_NOT_RESET: return "PEP_KEY_NOT_RESET";
    case PEP_CANNOT_DELETE_KEY: return "PEP_CANNOT_DELETE_KEY";
    case PEP_KEY_IMPORTED: return "PEP_KEY_IMPORTED";
    case PEP_NO_KEY_IMPORTED: return "PEP_NO_KEY_IMPORTED";
    case PEP_KEY_IMPORT_STATUS_UNKNOWN: return "PEP_KEY_IMPORT_STATUS_UNKNOWN";
    case PEP_SOME_KEYS_IMPORTED: return "PEP_SOME_KEYS_IMPORTED";
    case PEP_CANNOT_FIND_IDENTITY: return "PEP_CANNOT_FIND_IDENTITY";
    case PEP_CANNOT_SET_PERSON: return "PEP_CANNOT_SET_PERSON";
    case PEP_CANNOT_SET_PGP_KEYPAIR: return "PEP_CANNOT_SET_PGP_KEYPAIR";
    case PEP_CANNOT_SET_IDENTITY: return "PEP_CANNOT_SET_IDENTITY";
    case PEP_CANNOT_SET_TRUST: return "PEP_CANNOT_SET_TRUST";
    case PEP_KEY_BLACKLISTED: return "PEP_KEY_BLACKLISTED";
    case PEP_CANNOT_FIND_PERSON: return "PEP_CANNOT_FIND_PERSON";
    case PEP_CANNOT_SET_PEP_PROTOCOL_VERSION: return "PEP_CANNOT_SET_PEP_PROTOCOL_VERSION";
    case PEP_CANNOT_FIND_ALIAS: return "PEP_CANNOT_FIND_ALIAS";
    case PEP_CANNOT_SET_ALIAS: return "PEP_CANNOT_SET_ALIAS";
    case PEP_NO_OWN_USERID_FOUND: return "PEP_NO_OWN_USERID_FOUND";
    case PEP_UNENCRYPTED: return "PEP_UNENCRYPTED";
    case PEP_VERIFIED: return "PEP_VERIFIED";
    case PEP_DECRYPTED: return "PEP_DECRYPTED";
    case PEP_DECRYPTED_AND_VERIFIED: return "PEP_DECRYPTED_AND_VERIFIED";
    case PEP_DECRYPT_WRONG_FORMAT: return "PEP_DECRYPT_WRONG_FORMAT";
    case PEP_DECRYPT_NO_KEY: return "PEP_DECRYPT_NO_KEY";
    case PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH: return "PEP_DECRYPT_SIGNATURE_DOES_NOT_MATCH";
    case PEP_VERIFY_NO_KEY: return "PEP_VERIFY_NO_KEY";
    case PEP_VERIFIED_AND_TRUSTED: return "PEP_VERIFIED_AND_TRUSTED";
    case PEP_CANNOT_REENCRYPT: return "PEP_CANNOT_REENCRYPT";
    case PEP_VERIFY_SIGNER_KEY_REVOKED: return "PEP_VERIFY_SIGNER_KEY_REVOKED";
    case PEP_MESSAGE_FULLY_PROCESSED: return "PEP_MESSAGE_FULLY_PROCESSED";
    case PEP_CANNOT_DECRYPT_UNKNOWN: return "PEP_CANNOT_DECRYPT_UNKNOWN";
    case PEP_TRUSTWORD_NOT_FOUND: return "PEP_TRUSTWORD_NOT_FOUND";
    case PEP_TRUSTWORDS_FPR_WRONG_LENGTH: return "PEP_TRUSTWORDS_FPR_WRONG_LENGTH";
    case PEP_TRUSTWORDS_DUPLICATE_FPR: return "PEP_TRUSTWORDS_DUPLICATE_FPR";
    case PEP_CANNOT_CREATE_KEY: return "PEP_CANNOT_CREATE_KEY";
    case PEP_CANNOT_SEND_KEY: return "PEP_CANNOT_SEND_KEY";
    case PEP_PHRASE_NOT_FOUND: return "PEP_PHRASE_NOT_FOUND";
    case PEP_SEND_FUNCTION_NOT_REGISTERED: return "PEP_SEND_FUNCTION_NOT_REGISTERED";
    case PEP_CONTRAINTS_VIOLATED: return "PEP_CONTRAINTS_VIOLATED";
    case PEP_CANNOT_ENCODE: return "PEP_CANNOT_ENCODE";
    case PEP_SYNC_NO_NOTIFY_CALLBACK: return "PEP_SYNC_NO_NOTIFY_CALLBACK";
    case PEP_SYNC_ILLEGAL_MESSAGE: return "PEP_SYNC_ILLEGAL_MESSAGE";
    case PEP_SYNC_NO_INJECT_CALLBACK: return "PEP_SYNC_NO_INJECT_CALLBACK";
    case PEP_SYNC_NO_CHANNEL: return "PEP_SYNC_NO_CHANNEL";
    case PEP_SYNC_CANNOT_ENCRYPT: return "PEP_SYNC_CANNOT_ENCRYPT";
    case PEP_SYNC_NO_MESSAGE_SEND_CALLBACK: return "PEP_SYNC_NO_MESSAGE_SEND_CALLBACK";
    case PEP_SYNC_CANNOT_START: return "PEP_SYNC_CANNOT_START";
    case PEP_CANNOT_INCREASE_SEQUENCE: return "PEP_CANNOT_INCREASE_SEQUENCE";
    case PEP_STATEMACHINE_ERROR: return "PEP_STATEMACHINE_ERROR";
    case PEP_NO_TRUST: return "PEP_NO_TRUST";
    case PEP_STATEMACHINE_INVALID_STATE: return "PEP_STATEMACHINE_INVALID_STATE";
    case PEP_STATEMACHINE_INVALID_EVENT: return "PEP_STATEMACHINE_INVALID_EVENT";
    case PEP_STATEMACHINE_INVALID_CONDITION: return "PEP_STATEMACHINE_INVALID_CONDITION";
    case PEP_STATEMACHINE_INVALID_ACTION: return "PEP_STATEMACHINE_INVALID_ACTION";
    case PEP_STATEMACHINE_INHIBITED_EVENT: return "PEP_STATEMACHINE_INHIBITED_EVENT";
    case PEP_STATEMACHINE_CANNOT_SEND: return "PEP_STATEMACHINE_CANNOT_SEND";
    case PEP_PASSPHRASE_REQUIRED: return "PEP_PASSPHRASE_REQUIRED";
    case PEP_WRONG_PASSPHRASE: return "PEP_WRONG_PASSPHRASE";
    case PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED: return "PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED";
    case PEP_CANNOT_CREATE_GROUP: return "PEP_CANNOT_CREATE_GROUP";
    case PEP_CANNOT_FIND_GROUP_ENTRY: return "PEP_CANNOT_FIND_GROUP_ENTRY";
    case PEP_GROUP_EXISTS: return "PEP_GROUP_EXISTS";
    case PEP_GROUP_NOT_FOUND: return "PEP_GROUP_NOT_FOUND";
    case PEP_CANNOT_ENABLE_GROUP: return "PEP_CANNOT_ENABLE_GROUP";
    case PEP_CANNOT_DISABLE_GROUP: return "PEP_CANNOT_DISABLE_GROUP";
    case PEP_CANNOT_ADD_GROUP_MEMBER: return "PEP_CANNOT_ADD_GROUP_MEMBER";
    case PEP_CANNOT_DEACTIVATE_GROUP_MEMBER: return "PEP_CANNOT_DEACTIVATE_GROUP_MEMBER";
    case PEP_NO_MEMBERSHIP_STATUS_FOUND: return "PEP_NO_MEMBERSHIP_STATUS_FOUND";
    case PEP_CANNOT_LEAVE_GROUP: return "PEP_CANNOT_LEAVE_GROUP";
    case PEP_CANNOT_JOIN_GROUP: return "PEP_CANNOT_JOIN_GROUP";
    case PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO: return "PEP_CANNOT_RETRIEVE_MEMBERSHIP_INFO";
    case PEP_DISTRIBUTION_ILLEGAL_MESSAGE: return "PEP_DISTRIBUTION_ILLEGAL_MESSAGE";
    case PEP_STORAGE_ILLEGAL_MESSAGE: return "PEP_STORAGE_ILLEGAL_MESSAGE";
    case PEP_PEPMESSAGE_ILLEGAL_MESSAGE: return "PEP_PEPMESSAGE_ILLEGAL_MESSAGE";
    case PEP_TRANSPORT_CANNOT_INIT: return "PEP_TRANSPORT_CANNOT_INIT";
    case PEP_TRANSPORT_CANNOT_INIT_SEND: return "PEP_TRANSPORT_CANNOT_INIT_SEND";
    case PEP_TRANSPORT_CANNOT_INIT_RECV: return "PEP_TRANSPORT_CANNOT_INIT_RECV";
    case PEP_TRANSPORT_DOWN: return "PEP_TRANSPORT_DOWN";
    case PEP_TRANSPORT_ERROR: return "PEP_TRANSPORT_ERROR";
    case PEP_COMMIT_FAILED: return "PEP_COMMIT_FAILED";
    case PEP_MESSAGE_CONSUME: return "PEP_MESSAGE_CONSUME";
    case PEP_MESSAGE_IGNORE: return "PEP_MESSAGE_IGNORE";
    case PEP_CANNOT_CONFIG: return "PEP_CANNOT_CONFIG";
    case PEP_UNBOUND_ENVIRONMENT_VARIABLE: return "PEP_UNBOUND_ENVIRONMENT_VARIABLE";
    case PEP_PATH_SYNTAX_ERROR: return "PEP_PATH_SYNTAX_ERROR";
    case PEP_RECORD_NOT_FOUND: return "PEP_RECORD_NOT_FOUND";
    case PEP_CANNOT_CREATE_TEMP_FILE: return "PEP_CANNOT_CREATE_TEMP_FILE";
    case PEP_ILLEGAL_VALUE: return "PEP_ILLEGAL_VALUE";
    case PEP_BUFFER_TOO_SMALL: return "PEP_BUFFER_TOO_SMALL";
    case PEP_OUT_OF_MEMORY: return "PEP_OUT_OF_MEMORY";
    case PEP_UNKNOWN_ERROR: return "PEP_UNKNOWN_ERROR";
    case PEP_VERSION_MISMATCH: return "PEP_VERSION_MISMATCH";
    default: return "unknown status code";
    }
}

/**
 *  <!--       pEp_comm_type_to_string()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]  ct        PEP_comm_type
 *  @retval	char*	  string representation of ct	
 *  
 */
static inline const char *pEp_comm_type_to_string(PEP_comm_type ct) {
    switch (ct) {
    case PEP_ct_unknown: return "unknown";
    case PEP_ct_no_encryption: return "no_encryption";
    case PEP_ct_no_encrypted_channel: return "no_encrypted_channel";
    case PEP_ct_key_not_found: return "key_not_found";
    case PEP_ct_key_expired: return "key_expired";
    case PEP_ct_key_revoked: return "key_revoked";
    case PEP_ct_key_b0rken: return "key_b0rken";
    case PEP_ct_my_key_not_included: return "my_key_not_included";
    case PEP_ct_security_by_obscurity: return "security_by_obscurity";
    case PEP_ct_b0rken_crypto: return "b0rken_crypto";
    case PEP_ct_key_too_short: return "key_too_short";
    case PEP_ct_compromised: return "compromised";
    case PEP_ct_mistrusted: return "mistrusted";
    case PEP_ct_unconfirmed_encryption: return "unconfirmed_encryption";
    case PEP_ct_OpenPGP_weak_unconfirmed: return "OpenPGP_weak_unconfirmed";
    case PEP_ct_to_be_checked: return "to_be_checked";
    case PEP_ct_SMIME_unconfirmed: return "SMIME_unconfirmed";
    case PEP_ct_CMS_unconfirmed: return "CMS_unconfirmed";
    case PEP_ct_strong_but_unconfirmed: return "strong_but_unconfirmed";
    case PEP_ct_OpenPGP_unconfirmed: return "OpenPGP_unconfirmed";
    case PEP_ct_OTR_unconfirmed: return "OTR_unconfirmed";
    case PEP_ct_unconfirmed_enc_anon: return "unconfirmed_enc_anon";
    case PEP_ct_pEp_unconfirmed: return "pEp_unconfirmed";
    case PEP_ct_confirmed: return "confirmed";
    case PEP_ct_confirmed_encryption: return "confirmed_encryption";
    case PEP_ct_OpenPGP_weak: return "OpenPGP_weak";
    case PEP_ct_to_be_checked_confirmed: return "to_be_checked_confirmed";
    case PEP_ct_SMIME: return "SMIME";
    case PEP_ct_CMS: return "CMS";
    case PEP_ct_strong_encryption: return "strong_encryption";
    case PEP_ct_OpenPGP: return "OpenPGP";
    case PEP_ct_OTR: return "OTR";
    case PEP_ct_confirmed_enc_anon: return "confirmed_enc_anon";
    case PEP_ct_pEp: return "pEp";
    default: return "invalid comm type";
    }
}

#ifdef __cplusplus
} // "C"
#endif
#endif
