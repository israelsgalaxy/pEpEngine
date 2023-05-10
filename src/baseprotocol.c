/** 
 * @internal
 * @file     baseprotocol.c
 * @brief    Implementation of basic functions for administrative pEp messages (preparation,
 *           decoration, payload, extraction, etc.). These are used for
 *           protocol messages in, for example, key sync and key reset.
 *           The payloads of these messages are, in general, not human-readable.
 * @see      baseprotocol.h
 * @license  GNU General Public License 3.0 - see LICENSE.txt
*/

#include "pEp_internal.h"
#include "message_api.h"
#include "baseprotocol.h"
#include "Distribution.h" // for Distribution_t
#include "distribution_codec.h" // for decode_Distribution_message

#include "status_to_string.h" // for decode_Distribution_message

/**
 * @internal
 * @brief Convert base protocol type from enum to MIME type string
 * @param[in] type	base_protocol_type
 * @param[out] type_str	char**
 * @retval PEP_STATUS_OK
 * @retval PEP_ILLEGAL_VALUE on illegal value of `type`
 */
static PEP_STATUS _get_base_protocol_type_str(base_protocol_type type, const char** type_str) {
    *type_str = NULL;
    switch(type) {
        case BASE_SIGN:
            *type_str = _BASE_PROTO_MIME_TYPE_SIGN;
            break;
        case BASE_SYNC:
            *type_str = _BASE_PROTO_MIME_TYPE_SYNC;
            break;
        case BASE_DISTRIBUTION:
            *type_str = _BASE_PROTO_MIME_TYPE_DIST;
            break;
        default:
            return PEP_ILLEGAL_VALUE;
    }
    return PEP_STATUS_OK;
}

PEP_STATUS base_decorate_message(
        PEP_SESSION session,
        message *msg,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    PEP_REQUIRE(msg && payload && size
                && (type == BASE_SYNC || type == BASE_DISTRIBUTION));

    bloblist_t *bl;

    const char* type_str = NULL;

    switch (type) {
        case BASE_SYNC:
            bl = bloblist_add(msg->attachments, payload, size,
                              _BASE_PROTO_MIME_TYPE_SYNC, "sync.pEp");
            break;
        case BASE_DISTRIBUTION:
            bl = bloblist_add(msg->attachments, payload, size,
                              _BASE_PROTO_MIME_TYPE_DIST, "distribution.pEp");
            break;
        default:
            status = _get_base_protocol_type_str(type, &type_str);
            if (status != PEP_STATUS_OK)
                return status;
            else if (!type_str)
                return PEP_UNKNOWN_ERROR;

            bl = bloblist_add(msg->attachments, payload, size,
                              type_str, "ignore_this_attachment.pEp");
            type_str = NULL;
    }

    if (bl == NULL)
        goto enomem;
    else if (!msg->attachments)
        msg->attachments = bl;

    if (fpr && fpr[0] != '\0') {
        char *sign;
        size_t sign_size;
        status = sign_only(session,  payload, size, fpr, &sign, &sign_size);
        if (status)
            goto error;

        PEP_ASSERT(sign && sign_size);

        bl = bloblist_add(bl, sign, sign_size,
                _BASE_PROTO_MIME_TYPE_SIGN, "electronic_signature.asc");
        if (!bl)
            goto enomem;
    }

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

error:
    return status;
}

PEP_STATUS base_prepare_message(
        PEP_SESSION session,
        const pEp_identity *me,
        const pEp_identity *partner,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr,
        message **result
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    PEP_REQUIRE(me && partner && payload && size && result
                && (type == BASE_SYNC || type == BASE_DISTRIBUTION));

    *result = NULL;

    message *msg = new_message(PEP_dir_outgoing);
    if (!msg)
        goto enomem;

    add_opt_field(msg, "pEp-auto-consume", "yes");
    msg->in_reply_to = stringlist_add(msg->in_reply_to, "pEp-auto-consume@pEp.foundation");

    msg->from = identity_dup(me);
    if (!msg->from)
        goto enomem;

    msg->to = new_identity_list(identity_dup(partner));
    if (!msg->to)
        goto enomem;

    if (type == BASE_SYNC)
        msg->shortmsg = strdup("p≡p key management message (Sync) - please ignore");
    else
        msg->shortmsg = strdup("p≡p key management message (Distribution) - please ignore");
    PEP_WEAK_ASSERT_ORELSE_GOTO(msg->shortmsg, enomem);

    msg->longmsg = strdup("This message is part of p≡p's concept to manage keys.\n\n"
                        "You can safely ignore it. It will be deleted automatically.\n");
    PEP_WEAK_ASSERT_ORELSE_GOTO(msg->longmsg, enomem);

    status = base_decorate_message(session, msg, type, payload, size, fpr);
    if (status == PEP_STATUS_OK)
        *result = msg;
    return status;

enomem:
    free_message(msg);
    return PEP_OUT_OF_MEMORY;
}

PEP_STATUS base_extract_message(
        PEP_SESSION session,
        message *msg,
        base_protocol_type type,
        size_t *size,
        const char **payload,
        char **fpr
    )
{
    PEP_REQUIRE(session && msg && size && payload && fpr
                && (type == BASE_SYNC || type == BASE_DISTRIBUTION));

    PEP_STATUS status = PEP_STATUS_OK;
    *size = 0;
    *payload = NULL;
    *fpr = NULL;

    const char *_payload = NULL;
    size_t _payload_size = 0;
    const char *_sign = NULL;
    size_t _sign_size = 0;
    stringlist_t *keylist = NULL;

    const char* type_str = NULL;

    status = _get_base_protocol_type_str(type, &type_str);
    if (status != PEP_STATUS_OK || !type_str)
        return status;

    for (bloblist_t *bl = msg->attachments; bl ; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, type_str) == 0) {
            if (!_payload) {
                _payload = bl->value;
                _payload_size = bl->size;
            }
            else {
                status = PEP_DECRYPT_WRONG_FORMAT;
                goto the_end;
            }
        }
        else if (bl->mime_type && strcasecmp(bl->mime_type, _BASE_PROTO_MIME_TYPE_SIGN) == 0) {
            if (!_sign) {
                _sign = bl->value;
                _sign_size = bl->size;
            }
            else {
                status = PEP_DECRYPT_WRONG_FORMAT;
                goto the_end;
            }
        }
    }
    
    if (!(_payload && _payload_size))
        goto the_end;

    /* We need to check the signature and drop a message with an invalid or
       missing signature if the protocol is one of:
       - Sync.Sync;
       - Distribution.Key_reset
       but *not* if the protocol is
       - Distribytion.Echo.
       Here we know the family (Sync vs Distribution) but not the actual
       protcol.  Unfortunately we need to decode the payload here just to
       check, in case the family is Distribution.  A little wasteful, but
       not terribly important: this engine branch will not live long, and
       v3 does not need this same hack. */
    char *_fpr = NULL;
    bool _require_signature = false;
    switch (type) {
    case BASE_SYNC:
        _require_signature = true;
        break;
    case BASE_DISTRIBUTION: {
        Distribution_t *_dist = NULL;
        status = decode_Distribution_message(_payload, _payload_size, &_dist);
        if (status != PEP_STATUS_OK) {
            LOG_MESSAGE_WARNING("about the message", msg);
            LOG_STATUS_WARNING;
            LOG_WARNING("this should not happen");
            goto the_end;
        }
        switch (_dist->present) {
        case Distribution_PR_keyreset:
            _require_signature = true; break;
        case Distribution_PR_managedgroup:
            LOG_ERROR("here I am tentatively assuming that an administrative message with protocol Distribution_PR_managedgroup requires a signature");
            LOG_ERROR("FIXME: confirm with Volker");
            _require_signature = true;
            break;
        case Distribution_PR_exploration:
            PEP_UNIMPLEMENTED; // FIXME: ask Volker if this requires a valid signature
            break;
        case Distribution_PR_echo:
            _require_signature = false; break;
        default:
            PEP_UNEXPECTED_VALUE(_dist->present);
        }
        ASN_STRUCT_FREE(asn_DEF_Distribution, _dist);
        break;
    }
    default:
        PEP_IMPOSSIBLE;
    }
    if (_require_signature && _sign) {
        status = verify_text(session, _payload, _payload_size, _sign, _sign_size, &keylist);
        if (!(status == PEP_VERIFIED || status == PEP_VERIFIED_AND_TRUSTED) || !keylist || !keylist->value) {
            LOG_MESSAGE_WARNING("signature mismatch", msg);
            // signature invalid or does not match; ignore message
            status = PEP_STATUS_OK;
            goto the_end;
        }

        _fpr = strdup(keylist->value);
        PEP_WEAK_ASSERT_ORELSE(_fpr, {
            status = PEP_OUT_OF_MEMORY;
            goto the_end;
        });
    }

    *size = _payload_size;
    *payload = _payload;
    *fpr = _fpr;
    status = PEP_STATUS_OK;

the_end:
    free_stringlist(keylist);
    return status;
}

PEP_STATUS try_base_prepare_message(
        PEP_SESSION session,
        const pEp_identity *me,
        const pEp_identity *partner,
        base_protocol_type type,
        char *payload,
        size_t size,
        const char *fpr,
        message **result
    )
{
    PEP_REQUIRE(session
                //&& session->messageToSend // temporarily disabled: see below
                && session->notifyHandshake
                && me && partner && payload && size && result
                && (type == BASE_SYNC || type == BASE_DISTRIBUTION));
    PEP_STATUS status = PEP_STATUS_OK;

    /* Special case: if messageToSend is not defined there is no way to handle
       passphrases: in that case just exit with PEP_SYNC_NO_CHANNEL.  This is
       required for pEp4Thunderbird (P4TB-413) with the most recent
       libpEpAdapter (master) and JSONServerAdapter (master) as of 2021-11-05:
       JSONServerAdapter performs a temporary incomplete initialisation by
       supplying some NULL callbacks, and initialises in a complete way only
       later. */
    if (session->messageToSend == NULL) {
        LOG_ERROR("there is no session->messageToSend in %p", session);
        return PEP_SYNC_NO_CHANNEL;
    }

    // https://dev.pep.foundation/Engine/MessageToSendPassphrase

    // first try with empty passphrase
    char *passphrase = session->curr_passphrase;
    session->curr_passphrase = NULL;
    status = base_prepare_message(session, me, partner, type, payload, size, fpr, result);
    session->curr_passphrase = passphrase;
    if (!(status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE))
        return status;

    if (!EMPTYSTR(session->curr_passphrase)) {
        // try configured passphrase
        status = base_prepare_message(session, me, partner, type, payload, size, fpr, result);
        if (!(status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE))
            return status;
    }

    do {
        // then try passphrases from the cache
        status = session->messageToSend(NULL);

        // if there will be no passphrase then exit
        if (status == PEP_SYNC_NO_CHANNEL)
            break;

        // if a passphrase is needed ask the app
        if (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE) {
            pEp_identity* _me = identity_dup(me);
            if (!_me)
                return PEP_OUT_OF_MEMORY;
            session->notifyHandshake(_me, NULL, SYNC_PASSPHRASE_REQUIRED);
        }
        else if (status == PEP_STATUS_OK) {
            status = base_prepare_message(session, me, partner, type, payload, size, fpr, result);
        }
    } while (status == PEP_PASSPHRASE_REQUIRED || status == PEP_WRONG_PASSPHRASE);

    return status;
}
