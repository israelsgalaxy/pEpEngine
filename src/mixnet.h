/**
 * @file     mixnet.h
 * @brief    Onion-routing and mixnet for pEp: header
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#ifndef PEP_MIXNET_H
#define PEP_MIXNET_H

#include "pEpEngine.h"
#include "message_api.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Onion routing.
 * ***************************************************************** */

/* The name of a message optional field.  If this field is present then the
   message is an onion-routed message, whose attachment needs to be relayed, to
   either another relay or to the final recipient (it should be impossible to
   tell which). */
#define PEP_THIS_IS_AN_ONION_MESSAGE_FIELD_NAME "X-pEp-onion"

/* The MIME type we use for onion messages (that appear as attachments, always
   inside encrypted messages). */
#define PEP_ONION_MESSAGE_MIME_TYPE "application/pEp.onion"

/**
 *  <!--       onion_identities()       -->
 *
 *  @brief      Pick random known identities suitable to be used for onion
 *              routing, and provide them to the caller as a list.
 *
 *  @param[in]  session             session handle
 *  @param[in]  trusted_identity_no how many identities are required to be
 *                                  trusted
 *  @param[in]  total_identity_no   the total number of identities, which must
 *                                  be at least as large as trusted_identity_no
 *  @param[out] identities          the result list.  If the return status is
 *                                  PEP_STATUS_OK this is guaranteed to contain
 *                                  total_identity_no elements, all distinct, of
 *                                  which trusted_identity_no are trusted.
 *
 *  @retval     PEP_STATUS_OK             success
 *  @retval     PEP_CANNOT_FIND_IDENTITY  it is impossible to satisfy the
 *                                        request using only the identities we
 *                                        know
 *  @retval     PEP_ILLEGAL_VALUE         NULL session or list pointer, trusted
 *                                        identity number larger than total
 *                                        identity number
 *  @retval     PEP_OUT_OF_MEMORY         out of memory
 *  @retval     PEP_UNKNOWN_DB_ERROR      database error
 *
 */
DYNAMIC_API PEP_STATUS onion_identities(PEP_SESSION session,
                                        size_t trusted_identity_no,
                                        size_t total_identity_no,
                                        identity_list **identities);

/**
 *  <!--       onionize()       -->
 *
 *  @brief  Turn an unencrypted message into an onionised message.
 *
 *  @param[in]   session    session
 *  @param[in]   in         the message to be onionised; it must be outgoing
 *                          and unencrypted
 *  @param[in]   extra      extra keys, to be used only for the innermost
 *                          message
 *  @param[out]  out        the resulting encrypted and onionised message
 *  @param[in]   enc_format requested format for the outgoing message.  It
 *                          must be a recent format.
 *  @param[in]   flags      requested flags for the outgoing message.  The
 *                          onionisation flag is added automatically and
 *                          must not be given here
 *  @param[in]   relays     the list of relays to be used, in order.  Relays
 *                          must be at least three, all non-own
 *
 *  @retval      PEP_STATUS_OK  success
 *  @retval      any other value means failure (and in remains valid)
 */
DYNAMIC_API PEP_STATUS onionize(PEP_SESSION session,
                                message *in,
                                stringlist_t *extra,
                                message **out_p,
                                PEP_enc_format enc_format,
                                PEP_encrypt_flags_t flags,
                                identity_list *relays_as_list);


/* Message serialisation and deserialisation.
 * ***************************************************************** */

/* This functionality is useful for onion-routing, where we need to encode a
   message into a byte string, and vice-versa.
   It may also be useful elsewhere... */

/**
 *  <!--       onion_serialize_message()       -->
 *
 *  @brief  encode the given message into a byte array, using an ASN.1
 *          representation.
 *          The message must be in a state suitable to be sent, with all of
 *          its mandatory information present.
 *
 *  @param[in]   session    session
 *  @param[in]   in         the message to be encoded.
 *  @param[out]  encoded_p  the result byte array, malloc-allocated.
 *  @param[out]  encoded_size_in_bytes_p
 *                          the encoding length in bytes
 *
 *  @retval      PEP_ILLEGAL_VALUE
 *                               invalid message, with some mandatory field
 *                               NULL
 *  @retval      PEP_STATUS_OK   success
 *  @retval                      any other value means failure.
 */
DYNAMIC_API PEP_STATUS onion_serialize_message(PEP_SESSION session,
                                               message *in,
                                               char **encoded_p,
                                               size_t *encoded_size_in_bytes_p);

/**
 *  <!--       onion_deserialize_message()       -->
 *
 *  @brief  extract a pEp message from the pointed byte array.  The array must
 *          have been obtaine with onion_serialize_message, which uses an
 *          ASN.1 representation.
 *
 *  @param[in]   session    session
 *  @param[in]   encoded    the input byte array
 *  @param[in]   encoded_size_in_bytes
 *                          the input byte array length
 *  @param[out]  out_p      the resulting message
 *
 *  @retval      PEP_STATUS_OK      Success
 *  @retval      PEP_PEPMESSAGE_ILLEGAL_MESSAGE
 *                                  Invalid serialised data
 *  @retval      PEP_OUT_OF_MEMORY  Out of memory.
 *  @retval      any other value means failure
 *               It may not always be possible to distinguish the error
 *               condition of PEP_OUT_OF_MEMORY from the error condition of
 *               PEP_PEPMESSAGE_ILLEGAL_MESSAGE.
 */
DYNAMIC_API PEP_STATUS onion_deserialize_message(PEP_SESSION session,
                                                 const char *encoded,
                                                 size_t encoded_size_in_bytes,
                                                 message **out_p);

/**
 *  <!--       handle_incoming_onion_routed_message()       -->
 *
 *  @brief  Handle an incoming onion-routed message, which has just been
 *          decrypted and recognised as onion-routed by its outer-message
 *          header.
 *          This functions is called by decrypt_message.
 *
 *  @param[in]   session    session
 *  @param[in]   msg        the received message
 *
 *  @retval      PEP_STATUS_OK                   success
 *  @retval      PEP_PEPMESSAGE_ILLEGAL_MESSAGE  ill-formed message
 *  @retval      any other value means failure
 *               It may not always be possible to distinguish the error
 *               condition of PEP_OUT_OF_MEMORY from the error condition of
 *               PEP_PEPMESSAGE_ILLEGAL_MESSAGE.
 */
PEP_STATUS
handle_incoming_onion_routed_message(PEP_SESSION session,
                                     message *msg);


#ifdef __cplusplus
}
#endif

#endif
