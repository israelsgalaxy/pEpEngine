/**
 * @file     message_api.h
 * @brief    pEp engine API for message handling and evaluation and related functions
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */


#ifndef MESSAGE_API_H
#define MESSAGE_API_H

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 *  @enum    PEP_encrypt_flags
 *
 *  @brief    TODO
 *
 */
typedef enum _PEP_encrypt_flags {
    /// "default" means whatever the default behaviour for the function is.
    PEP_encrypt_flag_default = 0x0,
    PEP_encrypt_flag_force_encryption = 0x1,

    /// This flag is for special use cases and should not be used by normal pEp clients!
    PEP_encrypt_flag_force_unsigned = 0x2,
    PEP_encrypt_flag_force_no_attached_key = 0x4,
    
    /// This is used for outer messages (used to wrap the real message)
    /// This is only used internally and (eventually) by transport functions
    PEP_encrypt_flag_inner_message = 0x8,
    
    /// This is mainly used by pEp clients to send private keys to 
    /// their own PGP-only device
    PEP_encrypt_flag_force_version_1 = 0x10,
        
    PEP_encrypt_flag_key_reset_only = 0x20,
    
    /// This flag is used to let internal functions know that an encryption 
    /// call is being used as part of a reencryption operation
    PEP_encrypt_reencrypt = 0x40,

    /// This flag is used to check if encrypt_message is called inside an onion encryption loop
    PEP_encrypt_onion = 0x80

} PEP_encrypt_flags; 

typedef unsigned int PEP_encrypt_flags_t;

/**
 *  @enum    message_wrap_type
 *
 *  @brief    TODO
 *
 */
typedef enum _message_wrap_type {
    PEP_message_unwrapped,  ///< 1.0 or anything we don't wrap    
    PEP_message_default,    ///< typical inner/outer message 2.0
    PEP_message_transport,  ///< e.g. for onion layers
    PEP_message_key_reset   ///< for wrapped key reset information
} message_wrap_type;


/**
 *  <!--       encrypt_message_possibly_with_media_key()       -->
 *
 *  @brief Similar to encrypt_message: FIXME: write a good comment.
 */
PEP_STATUS encrypt_message_possibly_with_media_key(
        PEP_SESSION session,
        message *src,
        stringlist_t * extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags,
        const char *media_key_or_NULL);

/**
 *  <!--       encrypt_message()       -->
 *
 *  @brief Encrypt message in memory
 *
 *  @param[in]     session       session handle
 *  @param[in,out] src           message to encrypt - usually in-only except for
 *                               the rating field, but can be in-out for
 *                               unencrypted messages; in that case, we may
 *                               attach the key and decorate the message.
 *                               In any case, reset the rating.
 *  @param[in]     extra         extra keys for encryption
 *  @param[out]    dst           pointer to new encrypted message or NULL if no
 *                               encryption could take place
 *  @param[in]     enc_format    The desired format this message should be encrypted with
 *  @param[in]     flags         flags to set special encryption features
 *
 *  @retval PEP_STATUS_OK                   on success
 *  @retval PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
 *                                          an ambiguous name
 *  @retval PEP_UNENCRYPTED                 on demand or no recipients with usable
 *                                          key, is left unencrypted, and key is
 *                                          attached to it
 *  @retval PEP_ILLEGAL_VALUE               illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY               out of memory
 *  @retval any other value on error
 *
 *  @warning the ownership of src remains with the caller
 *           the ownership of dst goes to the caller
 *
 *  @warning enc_format PEP_enc_inline_EA:
 *              internal format of the encrypted attachments is changing, see
 *              https://dev.pep.foundation/Engine/ElevatedAttachments\n
 *               Only use this for transports without support for attachments
 *               when attached data must be sent inline
 *
 */

DYNAMIC_API PEP_STATUS encrypt_message(
        PEP_SESSION session,
        message *src,
        stringlist_t *extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


/**
 *  <!--       encrypt_message_and_add_priv_key()       -->
 *
 *  @brief Encrypt message in memory, adding an encrypted private
 *         key (encrypted separately and sent within the inner message)
 *
 *  @param[in]   session       session handle
 *  @param[in]   src           message to encrypt
 *  @param[out]  dst           pointer to new encrypted message or NULL if no
 *                               encryption could take place
 *  @param[in]   to_fpr        fingerprint of the recipient key to which the private key
 *                               should be encrypted
 *  @param[in]   enc_format    encrypted format
 *  @param[in]   flags         flags to set special encryption features
 *
 *  @retval PEP_STATUS_OK                   on success
 *  @retval PEP_KEY_HAS_AMBIG_NAME          at least one of the receipient keys has
 *                                          an ambiguous name
 *  @retval PEP_UNENCRYPTED                 on demand or no recipients with usable
 *                                          key, is left unencrypted, and key is
 *                                          attached to it
 *  @retval PEP_ILLEGAL_VALUE               illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY               out of memory
 *  @retval PEP_UNKNOWN_ERROR
 *  @retval any other value on error
 *
 *  @warning the ownershop of src remains with the caller\n
 *           the ownership of dst goes to the caller
 *
 */
DYNAMIC_API PEP_STATUS encrypt_message_and_add_priv_key(
        PEP_SESSION session,
        message *src,
        message **dst,
        const char* to_fpr,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


/**
 *  <!--       encrypt_message_for_self()       -->
 *
 *  @brief Encrypt message in memory for user's identity only,
 *         ignoring recipients and other identities from
 *         the message
 *
 *  @param[in]   session       session handle
 *  @param[in]   target_id     self identity this message should be encrypted for
 *  @param[in]   src           message to encrypt
 *  @param[in]   extra         extra keys for encryption
 *  @param[out]  dst           pointer to new encrypted message or NULL on failure
 *  @param[in]   enc_format    encrypted format
 *  @param[in]   flags         flags to set special encryption features
 *
 *  @retval PEP_STATUS_OK            on success
 *  @retval PEP_KEY_NOT_FOUND        at least one of the receipient keys
 *                                   could not be found
 *  @retval PEP_KEY_HAS_AMBIG_NAME   at least one of the receipient keys has
 *                                   an ambiguous name
 *  @retval PEP_GET_KEY_FAILED       cannot retrieve key
 *  @retval PEP_CANNOT_FIND_IDENTITY
 *  @retval PEP_ILLEGAL_VALUE
 *  @retval PEP_OUT_OF_MEMORY
 *
 *  @warning the ownership of src remains with the caller\n
 *           the ownership of target_id remains w/ caller\n
 *           the ownership of dst goes to the caller\n
 *           message is NOT encrypted for identities other than the target_id (and then,
 *           only if the target_id refers to self!)
 *
 */
DYNAMIC_API PEP_STATUS encrypt_message_for_self(
        PEP_SESSION session,
        pEp_identity* target_id,
        message *src,
        stringlist_t* extra,
        message **dst,
        PEP_enc_format enc_format,
        PEP_encrypt_flags_t flags
    );


/**
 *  @enum    PEP_color
 *
 *  @brief    Internal encoding of colors for status bar.
 *
 */
typedef enum _PEP_color {
    PEP_color_no_color = 0,
    PEP_color_yellow,
    PEP_color_green,
    PEP_color_red = -1,
} PEP_color;


/**
 *  <!--       color_from_rating()       -->
 *
 *  @brief Calculate color from rating
 *
 *  @param[in]   rating    rating
 *
 *  @retval PEP_color   color representing the rating
 */
DYNAMIC_API PEP_color color_from_rating(PEP_rating rating);

/**
 *  @enum    PEP_decrypt_flags
 *
 *  @brief    TODO
 *
 */
typedef enum _PEP_decrypt_flags {
    PEP_decrypt_flag_own_private_key = 0x1,
    PEP_decrypt_flag_consume = 0x2,
    PEP_decrypt_flag_ignore = 0x4,
    PEP_decrypt_flag_src_modified = 0x8,

    // input flags    
    PEP_decrypt_flag_untrusted_server = 0x100,
    PEP_decrypt_flag_dont_trigger_sync = 0x200,
    PEP_decrypt_flag_ignore_onion = 0x400
} PEP_decrypt_flags; 

typedef unsigned int PEP_decrypt_flags_t;


/**
 *  <!--       decrypt_message_2()     -->
 *
 *  @brief Decrypt message in memory
 *
 *  @param[in]     session    session handle
 *  @param[in,out] src        message to decrypt - see warning about identities below.
 *                            the rating field of src (instead of dst) is updated
 *                            in case encryption fails.
 *  @param[out]    dst        pointer to new decrypted message or NULL on failure
 *  @param[in,out] keylist    in: stringlist with additional keyids for reencryption if needed
 *                            (will be freed and replaced with output keylist)
 *                            out: stringlist with keyids used for signing and encryption. first
 *                            first key is signer, additional keys are the ones it was encrypted
 *                            to. Only signer and whichever of the user's keys was used are
 *                            reliable
 *  @param[in,out] flags      flags to signal special decryption features
 *
 *  @retval <ERROR>                 any error status
 *  @retval PEP_DECRYPTED           if message decrypted but not verified
 *  @retval PEP_CANNOT_REENCRYPT    if message was decrypted (and possibly
 *                                  verified) but a reencryption operation is expected by the caller
 *                                  and failed
 *  @retval PEP_STATUS_OK           on success
 *
 *  @note Flags above are as follows:
 *  @verbatim
 *  ---------------------------------------------------------------------------------------------|
 *  Incoming flags                                                                               |
 *  ---------------------------------------------------------------------------------------------|
 *  Flag                                  | Description                                          |
 *  --------------------------------------|------------------------------------------------------|
 *  PEP_decrypt_flag_untrusted_server     | used to signal that decrypt function should engage   |
 *                                        | in behaviour specified for when the server storing   |
 *                                        | the source is untrusted.                             |
 *  PEP_decrypt_flag_dont_trigger_sync    | [FIXME]                                              |
 *  PEP_decrypt_flag_ignore_onion         | Do not relay the message even if we find an onion-   |
 *                                        | routing optional field: otherwise a suitably crafted |
 *                                        | message could make decryption recurse infinitely     |
 *  ---------------------------------------------------------------------------------------------|
 *  Outgoing flags                                                                               |
 *  ---------------------------------------------------------------------------------------------|
 *  PEP_decrypt_flag_own_private_key      | private key was imported for one of our addresses    |
 *                                        | (NOT trusted or set to be used - handshake/trust is  |
 *                                        | required for that)                                   |
 *                                        |                                                      |
 *  PEP_decrypt_flag_src_modified         | indicates that the modified_src field should contain |
 *                                        | a modified version of the source, at the moment      |
 *                                        | always as a result of the input flags.               |
 *                                        |                                                      |
 *  PEP_decrypt_flag_consume              | used by sync to indicate this was a pEp internal     |
 *                                        | message and should be consumed externally without    |
 *                                        | showing it as a normal message to the user           |
 *                                        |                                                      |
 *  PEP_decrypt_flag_ignore               | used by sync                                         |
 *  ---------------------------------------------------------------------------------------------| @endverbatim
 *
 *  @ownership src remains with the caller; HOWEVER, the contents
 *               might be modified (strings freed and allocated anew or set to NULL,
 *               etc) intentionally; when this happens, PEP_decrypt_flag_src_modified
 *               is set.
 *
 *  @ownership dst goes to the caller
 *
 *  @ownership contents of keylist goes to the caller
 *
 *  @note if src is unencrypted this function returns PEP_UNENCRYPTED and sets
 *        dst to NULL
 *  @note if src->enc_format is PEP_enc_inline_EA on input then elevated attachments
 *        will be expected
 *
 *
 *  @warning decrypt_message RELIES on the fact that identity information provided in src for recips and
 *           sender is AS TAKEN FROM THE ORIGINAL PARSED MESSAGE. This means that if update_identity or
 *           myself is called on those identities by the caller before passing the message struct to decrypt_message,
 *           the caller will have to cache and restore those to their original state before sending them
 *           to this function. ADAPTERS AND APPLICATIONS PLEASE TAKE NOTE OF THIS. (Obviously, this doesn't
 *           include information like user_ids, but we very specifically need the incoming usernames preserved
 *           so that they can be handled by the internal algorithm appropriately)
 */

DYNAMIC_API PEP_STATUS decrypt_message_2(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_decrypt_flags_t *flags
);

/**
 *  <!--       decrypt_message()       -->
 *
 *  @brief Exactly like decrypt_message_2, but with the rating output parameter.
 *         This function is kept for API compatibility: new code should use
 *         decrypt_message_2 instead of this function.
 *
 *  @param[out] rating      output message rating, only valid in case
 *                          decryption succeeded.
 */

DYNAMIC_API PEP_STATUS decrypt_message(
        PEP_SESSION session,
        message *src,
        message **dst,
        stringlist_t **keylist,
        PEP_rating *rating,
        PEP_decrypt_flags_t *flags
);

/**
 *  <!--       own_message_private_key_details()       -->
 *
 *  @brief Details on own key in own message
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to decrypt
 *  @param[out]  ident      identity containing uid, address and fpr of key
 *                            note:
 *                            In order to obtain details about key to be possibly imported
 *                            as a replacement of key currently used as own identity,
 *                            application passes message that have been previously flagged by
 *                            decrypt_message() as own message containing own key to this function
 *
 *  @retval PEP_STATUS_OK       on success
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 *
 *  @warning the ownership of msg remains with the caller\n
 *           the ownership of ident goes to the caller\n
 *           msg MUST be encrypted so that this function can check own signature
 *
 */
DYNAMIC_API PEP_STATUS own_message_private_key_details(
        PEP_SESSION session,
        message *msg,
        pEp_identity **ident 
);


/**
 *  <!--       sent_message_rating()       -->
 *
 *  @brief Get rating for a sent message
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to get the rating for
 *  @param[out]  rating     rating for the message
 *
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *
 *  @warning msg->from must point to a valid pEp_identity\n
 *           msg->dir must be PEP_dir_outgoing\n
 *           the ownership of msg remains with the caller
 *
 */
DYNAMIC_API PEP_STATUS sent_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );
// FIXME: the current implementation is a stub, until ENGINE-847 is ready.


/**
 *  <!--       outgoing_message_rating()       -->
 *
 *  @brief Get rating for an outgoing message
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to get the rating for
 *  @param[out]  rating     rating for the message
 *
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *
 *  @warning msg->from must point to a valid pEp_identity\n
 *           msg->dir must be PEP_dir_outgoing\n
 *           the ownership of msg remains with the caller
 *
 */
DYNAMIC_API PEP_STATUS outgoing_message_rating(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );


/**
 *  <!--       outgoing_message_rating_preview()       -->
 *
 *  @brief Get rating preview
 *
 *  @param[in]   session    session handle
 *  @param[in]   msg        message to get the rating for
 *  @param[out]  rating     rating preview for the message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *
 *  @warning msg->from must point to a valid pEp_identity\n
 *           msg->dir must be PEP_dir_outgoing\n
 *           the ownership of msg remains with the caller
 *
 */
DYNAMIC_API PEP_STATUS outgoing_message_rating_preview(
        PEP_SESSION session,
        message *msg,
        PEP_rating *rating
    );

/**
 *  <!--       identity_rating()       -->
 *
 *  @brief Get rating for a single identity
 *
 *  @param[in]   session    session handle
 *  @param[in]   ident      identity to get the rating for
 *  @param[out]  rating     rating for the identity
 
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval any other value on error
 *
 *  @warning the ownership of ident remains with the caller
 *
 */
DYNAMIC_API PEP_STATUS identity_rating(
        PEP_SESSION session,
        pEp_identity *ident,
        PEP_rating *rating
    );


/**
 *  <!--       get_binary_path()       -->
 *
 *  @brief Retrieve path of cryptotech binary if available
 *
 *  @param[in]   tech    cryptotech to get the binary for
 *  @param[out]  path    path to cryptotech binary or NULL if not available
 *                         **path is owned by the library, do not change it!
 *
 *
 */
DYNAMIC_API PEP_STATUS get_binary_path(PEP_cryptotech tech, const char **path);


/**
 *  <!--       get_trustwords()       -->
 *
 *  @brief Get full trustwords string for a *pair* of identities
 *
 *  @param[in]   session    session handle
 *  @param[in]   id1        identity of first party in communication - fpr can't be NULL
 *  @param[in]   id2        identity of second party in communication - fpr can't be NULL
 *  @param[in]   lang       C string with ISO 639-1 language code
 *  @param[out]  words      pointer to C string with all trustwords UTF-8 encoded,
 *                            separated by a blank each
 *                            NULL if language is not supported or trustword
 *                            wordlist is damaged or unavailable
 *  @param[out]  wsize      length of full trustwords string
 *  @param[in]   full       if true, generate ALL trustwords for these identities.
 *                            else, generate a fixed-size subset. (TODO: fixed-minimum-entropy
 *                            subset in next version)
 *
 *  @retval PEP_STATUS_OK            trustwords retrieved
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval PEP_ILLEGAL_VALUE        illegal parameter values
 *  @retval PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
 *
 *  @warning the word pointer goes to the ownership of the caller.
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *
 */
DYNAMIC_API PEP_STATUS get_trustwords(
        PEP_SESSION session, const pEp_identity* id1, const pEp_identity* id2,
        const char* lang, char **words, size_t *wsize, bool full
    );


/**
 *  <!--       get_message_trustwords()       -->
 *
 *  @brief Get full trustwords string for message sender and reciever identities.
 *         This will use either get_ripemd160_trustwords_for_fprs or (if
 *         trustword-xor-compatibility mode is enabled and the communication
 *         partner requires an old protocol) get_ripemd160_trustwords_for_fprs.
 *
 *  @param[in]   session        session handle
 *  @param[in]   msg            message to get sender identity from
 *  @param[in]   keylist        NULL if message to be decrypted,
 *                                keylist returned by decrypt_message() otherwise
 *  @param[in]   received_by    identity for account receiving message can't be NULL
 *  @param[in]   lang           C string with ISO 639-1 language code
 *  @param[out]  words          pointer to C string with all trustwords UTF-8 encoded,
 *                                separated by a blank each
 *                                NULL if language is not supported or trustword
 *                                wordlist is damaged or unavailable
 *  @param[in]   full           if true, generate ALL trustwords for these identities.
 *                                else, generate a fixed-size subset. (TODO: fixed-minimum-entropy
 *                                subset in next version)
 *
 *  @retval PEP_STATUS_OK            trustwords retrieved
 *  @retval PEP_ILLEGAL_VALUE        illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
 *  @retval PEP_CANNOT_FIND_IDENTITY identity not found
 *  @retval error                    status of decrypt_message() if decryption fails.
 *
 *  @warning the word pointer goes to the ownership of the caller.
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *
 */
DYNAMIC_API PEP_STATUS get_message_trustwords(
        PEP_SESSION session, 
        message *msg,
        stringlist_t *keylist,
        pEp_identity* received_by,
        const char* lang, char **words, bool full
    );

/**
 *  <!--       get_xor_trustwords_for_fprs()       -->
 *
 *  @brief Get full trustwords string for a pair of fingerprints, combinind the
 *         two FPRs with a xor operation.
 *
 *  @param[in]   session    session handle
 *  @param[in]   fpr1       fingerprint 1
 *  @param[in]   fpr2       fingerprint 2
 *  @param[in]   lang       C string with ISO 639-1 language code
 *  @param[out]  words      pointer to C string with all trustwords UTF-8 encoded,
 *                            separated by a blank each
 *                            NULL if language is not supported or trustword
 *                            wordlist is damaged or unavailable
 *  @param[out]  wsize      length of full trustwords string
 *  @param[in]   full       if true, generate ALL trustwords for these identities.
 *                            else, generate a fixed-size subset. (TODO: fixed-minimum-entropy
 *                            subset in next version)
 *
 *  @retval PEP_STATUS_OK            trustwords retrieved
 *  @retval PEP_OUT_OF_MEMORY        out of memory
 *  @retval PEP_ILLEGAL_VALUE        illegal parameter values
 *  @retval PEP_TRUSTWORD_NOT_FOUND  at least one trustword not found
 *
 *  @warning the word pointer goes to the ownership of the caller.
 *           the caller is responsible to free() it (on Windoze use pEp_free())
 *
 */
DYNAMIC_API PEP_STATUS get_xor_trustwords_for_fprs(
        PEP_SESSION session, const char* fpr1, const char* fpr2,
        const char* lang, char **words, size_t *wsize, bool full
    );

/**
 *  <!--       get_ripemd160_trustwords_for_fprs()       -->
 *
 *  @brief Exactly like get_xor_trustwords_for_fprs, but instead of combining
 *         with xor combine with ordered concatenation and then the RIPEMD-160
 *         hash.
 */
DYNAMIC_API PEP_STATUS get_ripemd160_trustwords_for_fprs(
        PEP_SESSION session, const char* fpr1, const char* fpr2,
        const char* lang, char **words, size_t *wsize, bool full
    );

/**
 *  <!--       re_evaluate_message_rating()       -->
 *
 *  @brief Re-evaluate already decrypted message rating
 *
 *  @param[in]   session         session handle
 *  @param[in]   msg             message to get the rating for
 *  @param[in]   x_keylist       decrypted message recipients keys fpr
 *  @param[in]   x_enc_status    original rating for the decrypted message
 *  @param[out]  rating          rating for the message
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE       if decrypted message doesn't contain
 *                                  X-EncStatus optional field and x_enc_status is
 *                                  pEp_rating_udefined
 *                                  or if decrypted message doesn't contain
 *                                  X-Keylist optional field and x_keylist is NULL
 *  @retval PEP_OUT_OF_MEMORY       if not enough memory could be allocated
 *  @retval any other value on error
 *
 *  @warning msg->from must point to a valid pEp_identity\n
 *           the ownership of msg remains with the caller\n
 *           the ownership of x_keylist remains with to the caller
 *
 */

DYNAMIC_API PEP_STATUS re_evaluate_message_rating(
    PEP_SESSION session,
    message *msg,
    stringlist_t *x_keylist,
    PEP_rating x_enc_status,
    PEP_rating *rating
);

/**
 *  <!--       get_key_rating_for_user()       -->
 *
 *  @brief Get the rating of a certain key for a certain user
 *
 *  @param[in]   session    session handle
 *  @param[in]   user_id    string with user ID
 *  @param[in]   fpr        string with fingerprint
 *  @param[out]  rating     rating of key for this user
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval PEP_RECORD_NOT_FOUND    if no trust record for user_id
 *                                  and fpr can be found
 *  @retval any other value on error
 *
 *
 */

DYNAMIC_API PEP_STATUS get_key_rating_for_user(
        PEP_SESSION session,
        const char *user_id,
        const char *fpr,
        PEP_rating *rating
    );

/**
 *  <!--       rating_from_comm_type()       -->
 *
 *  @brief Get the rating for a comm type
 *
 *  @param[in]   ct    the comm type to deliver the rating for
 *
 *  @retval PEP_rating    rating value for comm type ct
 *
 *
 */

DYNAMIC_API PEP_rating rating_from_comm_type(PEP_comm_type ct);


/* Utility functions.
 * ***************************************************************** */

/*
 *  <!--        normalize_fpr()       -->
 *
 *  @brief      Given an fpr compute its normalised version.  A normalised fpr
 *              has no separators and only upper-case hex digits.  This function
 *              should fail in every case where an fpr is invalid.
 *
 *  @param[in]  session             session handle
 *  @param[out] normalize_fpr       a normalised copy of fpr
 *  @param[in]  fpr                 the input fpr
 *
 *  @retval     PEP_ILLEGAL_VALUE   invalid fpr, NULL arguments
 *  @retval     PEP_OUT_OF_MEMORY   out of memory
 *  @retval     PEP_STATUS_OK       success
 */
PEP_STATUS normalize_fpr(PEP_SESSION session, char **normalized_fpr,
                         const char *input);


#ifdef __cplusplus
}
#endif

#endif
