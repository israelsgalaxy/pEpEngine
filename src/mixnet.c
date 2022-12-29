/**
 * @file     mixnet.c
 * @brief    Onion-routing and mixnet for pEp
 * @license  GNU General Public License 3.0 - see LICENSE.txt
 */

#include "pEp_internal.h"
#include "message_api.h"
#include "pEpEngine.h"

#include "mixnet.h"

/* Here we need to translate between our internal representation and ASN.1 . */
#include "map_asn1.h"
#include "message_codec.h"


//#define ONION_DEBUG_SERIALIZE_TO_XER  1
//#define ONION_DEBUG_LOG_XER           1  // Only used if ONION_DEBUG_SERIALIZE_TO_XER is defined
//#define ONION_DEBUG_NO_ENCRYPT        1


/* Message serialisation and deserialisation.
 * ***************************************************************** */

/* Turn the given message into a compact in-memory representation using ASN.1. */
DYNAMIC_API PEP_STATUS onion_serialize_message(PEP_SESSION session,
                                               message *in,
                                               char **encoded_p,
                                               size_t *encoded_size_in_bytes_p)
{
    PEP_REQUIRE(session && in && encoded_p && encoded_size_in_bytes_p);

    /* First initialise output parameters, for defeniveness's sake. */
    * encoded_p = NULL;
    * encoded_size_in_bytes_p = 0;

    /* Initialise data to be freed at the end. */
    PEP_STATUS status = PEP_STATUS_OK;
    ASN1Message_t *in_as_ASN1Message_t = NULL;
    char *encoded = NULL;
    size_t encoded_size_in_bytes;

    /* Perform the actual conversion: from the pEp internal representation
       to the ASN.1 struct in memory, and from that to PER. */
    in_as_ASN1Message_t = ASN1Message_from_message(in, NULL, true, 0);
    if (in_as_ASN1Message_t == NULL) {
        status = PEP_ILLEGAL_VALUE;
        goto end;
    }
    status = encode_ASN1Message_message(in_as_ASN1Message_t, & encoded, & encoded_size_in_bytes);
    if (status != PEP_STATUS_OK)
        goto end;

#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    // test: switch to XER, for debugging.
    char *encoded_per = encoded;
    char *encoded_xer = NULL;
    status = PER_to_XER_ASN1Message_msg(encoded_per, encoded_size_in_bytes,
                                        & encoded_xer);
    if (status != PEP_STATUS_OK) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    free(encoded_per);
    encoded = encoded_xer;
    encoded_size_in_bytes = strlen(encoded_xer);
#   if defined(ONION_DEBUG_LOG_XER)
    LOG_TRACE("encoded message as XML: %s", encoded);
#   endif
#endif

 end:
    /* Free temporary data structures we need to free in every case, error or
       not. */
    ASN_STRUCT_FREE(asn_DEF_ASN1Message, in_as_ASN1Message_t);

    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK) {
        * encoded_p = encoded;
        * encoded_size_in_bytes_p = encoded_size_in_bytes;
    }
    else
        free(encoded);
    return status;
}

/* Turn the given in-memory ASN.1 object into a pEp message. */
DYNAMIC_API PEP_STATUS onion_deserialize_message(PEP_SESSION session,
                                                 const char *encoded,
                                                 size_t encoded_size_in_bytes,
                                                 message **out_p)
{
    PEP_REQUIRE(session && encoded && encoded_size_in_bytes > 0
                && out_p);

    /* First initialise output parameters, for defeniveness's sake. */
    * out_p = NULL;

    /* Initialise data to be freed at the end. */
    PEP_STATUS status = PEP_STATUS_OK;
    message *out = NULL;
    ASN1Message_t *as_ASN1Message_t = NULL;

    /* Perform the actual conversion: from PER to the in-memory ASN.1 struct,
       and from that to the internal pEp representation. */
#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    const char *encoded_xer = encoded;
    char *encoded_per = NULL;
    size_t encoded_per_size_in_bytes;
    status = XER_to_PER_ASN1Message_msg(encoded_xer, & encoded_per,
                                        & encoded_per_size_in_bytes);
    if (status != PEP_STATUS_OK)
        goto end;
    encoded = encoded_per;
    encoded_size_in_bytes = encoded_per_size_in_bytes;
#endif
    status = decode_ASN1Message_message(encoded, encoded_size_in_bytes,
                                        & as_ASN1Message_t);
#if defined(ONION_DEBUG_SERIALIZE_TO_XER)
    free(encoded_per);
#endif
    if (status != PEP_STATUS_OK)
        goto end;
    out = ASN1Message_to_message(as_ASN1Message_t, NULL, true, 0);
    if (out == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }

 end:
    /* Free temporary data structures we need to free in every case, error or
       not. */
    ASN_STRUCT_FREE(asn_DEF_ASN1Message, as_ASN1Message_t);

    LOG_NONOK_STATUS_NONOK;
    if (status == PEP_STATUS_OK)
        * out_p = out;
    else
        free(out);
    return status;
}


/* Search for onion identities.
 * ***************************************************************** */

/* The implementation of this is in fact completely separate from the rest of
   onion-routing: this is an SQL exercise. */

DYNAMIC_API PEP_STATUS onion_identities(
        PEP_SESSION session,
        size_t trusted_identity_no,
        size_t total_identity_no,
        identity_list **identities)
{
    PEP_REQUIRE(session && identities
                && trusted_identity_no <= total_identity_no);

#define FAIL(pepstatus)        \
    do {                       \
        status = (pepstatus);  \
        goto end;              \
    } while (false)
#define CHECK_SQL_STATUS                                          \
    do {                                                          \
        if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE  \
            && sql_status != SQLITE_ROW) {                        \
            FAIL(PEP_UNKNOWN_DB_ERROR);                           \
        }                                                         \
    } while (false)

    /* Defensiveness: initialise the output to a sensible value before doing
       anything, and work with automatic variables instead of affecting the
       caller's memory. */
    PEP_STATUS status = PEP_STATUS_OK;
    * identities = NULL;
    identity_list *res = NULL;
    size_t found_identity_no = 0;

    /* Run the complicated SQL query returning our identities. */
    int sql_status = SQLITE_OK;
    sql_reset_and_clear_bindings(session->get_onion_identities);
    sqlite3_bind_int(session->get_onion_identities, 1, trusted_identity_no);
    sqlite3_bind_int(session->get_onion_identities, 2, total_identity_no);
    sqlite3_bind_int(session->get_onion_identities, 3, 0/*PEP_ct_pEp_unconfirmed*/);

    /* Keep reading one more line as long as we have not enough rows. */
    while (found_identity_no < total_identity_no) {
        /* Step. */
        sql_status = pEp_sqlite3_step_nonbusy(session, session->get_onion_identities);
        CHECK_SQL_STATUS;
        if (sql_status == SQLITE_DONE)
            FAIL(PEP_CANNOT_FIND_IDENTITY); /* Not enough rows. */

        /* Bind columns into local variables.  These char* variables are only
           bound here, and their memory is handled here.  It is difficult to
           unconditionally free at the end of the function because of sharing:
           strings are shared with the identity, which is shared with the
           list. */
        char *user_id
            = strdup((char *)
                     sqlite3_column_text(session->get_onion_identities, 0));
        if (user_id == NULL)
            FAIL(PEP_OUT_OF_MEMORY);
        char *address
            = strdup((char *)
                     sqlite3_column_text(session->get_onion_identities, 1));;
        if (address == NULL) {
            free(user_id);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        bool trusted;
        trusted = sqlite3_column_int(session->get_onion_identities, 2);
        LOG_TRACE("# found %s %s", user_id,
                  (trusted ? "TRUSTED" : "NOT as trusted (even if it may be)"));

        /* Make an identity data structure, and update it to fill in whatever
           field this query did not fill. */
        pEp_identity *identity = new_identity(address, NULL, user_id, NULL);
        if (identity == NULL) {
            free(user_id);
            free(address);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        status = update_identity(session, identity);
        if (status != PEP_STATUS_OK) {
            free_identity(identity);
            goto end;
        }

        /* Attach the identity to the list.  Notice that the identity is
           shared with the list. */
        identity_list *new_last = identity_list_add(res, identity);
        if (new_last == NULL) {
            free_identity(identity);
            FAIL(PEP_OUT_OF_MEMORY);
        }
        if (res == NULL)
            res = new_last;

        /* End of the iteration: we have found an identity. */
        found_identity_no ++;
    }

 end:
    LOG_TRACE("found %i identities", (int) found_identity_no);
    sql_reset_and_clear_bindings(session->get_onion_identities);
    if (status != PEP_STATUS_OK) {
        free_identity_list(res);
    }
    else
        * identities = res; /* Make the result visible to the caller. */
    LOG_NONOK_STATUS_NONOK;
    return status;
#undef CHECK_SQL_STATUS
#undef FAIL
}


/* Onion routing.
 * ***************************************************************** */

/* Modify the given message by "layer-decorating" it: this is called once per
   layer, on the *inner* message. */
static PEP_STATUS _onion_layer_decorate_message(PEP_SESSION session,
                                                message *msg)
{
    PEP_REQUIRE(session && msg);
    PEP_STATUS status = PEP_STATUS_OK;

    add_opt_field(msg, PEP_THIS_IS_AN_ONION_MESSAGE_FIELD_NAME, "yes");
    add_opt_field(msg, "X-This-Must-Be-Inner-Only", "foo");
    _add_auto_consume(msg);

    return status;
}

static PEP_STATUS _onion_make_layer(PEP_SESSION session,
                                    message *in,
                                    stringlist_t *extra,
                                    message **out_p,
                                    PEP_enc_format enc_format,
                                    PEP_encrypt_flags_t flags,
                                    pEp_identity *own_from,
                                    pEp_identity *relay_from,
                                    pEp_identity *relay_to,
                                    bool innermost,
                                    bool outermost)
{
    LOG_TRACE("👉👉👉👉👉 %s %s <%s> %s ->  %s <%s>", (outermost?"OUTERMOST":"NON-outermost"), relay_from->username, relay_from->address, (relay_from->me ? "ME" : "NON-me"), relay_to->username, relay_to->address);
    PEP_REQUIRE(session && in && in->dir == PEP_dir_outgoing && out_p
                && own_from && ! EMPTYSTR(own_from->username)
                && ! EMPTYSTR(own_from->address)
                && relay_from && ! EMPTYSTR(relay_from->username)
                && ! EMPTYSTR(relay_from->address)
                && relay_to && ! EMPTYSTR(relay_to->username)
                && ! EMPTYSTR(relay_to->address)
                /* // This is conceptually true, but the identity might not
                   // be up-to-date in the sense of myself.
                && PEP_IMPLIES(outermost, relay_from->me) */);
    PEP_STATUS status = PEP_STATUS_OK;

    LOG_TRACE("* innermost: %s.  %s <%s>  ->  %s <%s>", (innermost ? "yes" : "no"), relay_from->username, relay_from->address, relay_to->username, relay_to->address);

    /* Initialise the output parameter, for defensiveness's sake.  We will only
       set the actual pointer to a non-NULL value at the end, on success. */
    * out_p = NULL;

    /* Initialise each local variable so that in case of error we can free them
       all. */
    message *new = NULL;
    pEp_identity *own_from_copy = NULL;
    pEp_identity *relay_from_copy = NULL;
    identity_list *relay_tos_copy = NULL;
    char *shortmsg = NULL;
    char *longmsg = NULL;
    char *encoded_message = NULL;
    size_t encoded_message_length = 0;

    if (innermost) {
# define UPDATE_FROM_AND_TO(the_msg)                                     \
        do {                                                             \
            message *_msg = (the_msg);                                   \
            if (_msg == NULL) { status = PEP_OUT_OF_MEMORY; goto end; }  \
            if (_msg->from->me)                                          \
                status = myself(session, _msg->from);                    \
            else                                                         \
                status = update_identity(session, _msg->from);           \
            if (status != PEP_STATUS_OK) goto end;                       \
            if (_msg->to->ident->me)                                     \
                status = myself(session, _msg->to->ident);               \
            else                                                         \
                status = update_identity(session, _msg->to->ident);      \
            if (status != PEP_STATUS_OK) goto end;                       \
        } while (false)
#if defined(ONION_DEBUG_NO_ENCRYPT)
        new = message_dup(in);
        UPDATE_FROM_AND_TO(new);
#else
        /* This is just an ordinary message to encrypt. */
        LOG_TRACE("🧅🧅🧅🧅 encrypting the innermost layer");
        status = encrypt_message_possibly_with_media_key(session, in, extra,
                                                         & new, enc_format,
                                                         flags, NULL);
        if (status != PEP_STATUS_OK) goto end;
        LOG_TRACE("🧅🧅🧅🧅 after innermost encryption: %s <%s>  ->  %s <%s>", new->from->username, new->from->address, new->to->ident->username, new->to->ident->address);
#endif
    }
    else {
        /* We need to take the in message and wrap it as an attachment into a
           new message.  Allocate message components, then the message itself.
           In case of any allocation error go to the end, where we free every
           non-NULL thing unconditionally. */
        own_from_copy = identity_dup(own_from);
        relay_from_copy = identity_dup(relay_from);
        relay_tos_copy = identity_list_cons_copy(relay_to, NULL);
        shortmsg = strdup("🧅 p≡p 🧅");
        longmsg = strdup("This is an onion-routed message.\n"
                         "Humans should not normally see this; a p≡p system\n"
                         "receiving this message should decode its attachment\n"
                         "and pass it along.\n");
        new = new_message(PEP_dir_outgoing);
        if (own_from_copy == NULL
            || relay_from_copy == NULL || relay_tos_copy == NULL
            || shortmsg == NULL || longmsg == NULL
            || new == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        /* Fill message fields, and set the local variables holding copies of
           message heap-allocated fields to NULL, so that we can free the local
           variables unconditionally at the end.  */
        new->from = own_from_copy;
        new->to = relay_tos_copy;
        new->shortmsg = shortmsg;
        new->longmsg = longmsg;
        own_from_copy = NULL;
        relay_tos_copy = NULL;
        shortmsg = NULL;
        longmsg = NULL;
        status = _onion_layer_decorate_message(session, new);
        if (status != PEP_STATUS_OK)
            goto end;

        /* Add the "in" message to new as an attachment. */
        status = onion_serialize_message(session, in, & encoded_message,
                                         & encoded_message_length);
        if (status != PEP_STATUS_OK) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        bloblist_t *added_bloblist = new_bloblist(encoded_message,
                                                  encoded_message_length,
                                                  PEP_ONION_MESSAGE_MIME_TYPE,
                                                  /* no file name */NULL);
        if (added_bloblist == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        set_blob_disposition(added_bloblist, PEP_CONTENT_DISP_ATTACHMENT);
        new->attachments = added_bloblist;
        encoded_message = NULL; /* do not free this twice */

#if defined(ONION_DEBUG_NO_ENCRYPT)
        UPDATE_FROM_AND_TO(new);
#else
        /* Replace new with an encrypted version of itself. */
        message *new_encrypted = NULL;
        status = encrypt_message_possibly_with_media_key(
                    session, new,
                    /* By design we ignore extra keys in every layer except the
                       innermost */ NULL,
                    & new_encrypted,
                    enc_format, flags, NULL);
        LOG_NONOK_STATUS_NONOK;
        if (status != PEP_STATUS_OK)
            goto end;
        free_message(new);
        new = new_encrypted;
#endif
        /* Make a slight change in the outer message: we used our own identity
           as From when encrypting, so that that we could sign; but after
           encrypting we should replace the outer-message From to be the sending
           relay, so that the message looks like an ordinary PGP-encrypted
           message from relay_from to relay_to. */
        free_identity(new->from);
        new->from = relay_from_copy;
        relay_from_copy = NULL;  /* Avoid freeing it later. */
    }

end:
    LOG_NONOK_STATUS_NONOK;
    /* Free the temporary data we need to dispose of in either case, success or
       error.  The ones that we must not free have been set to NULL already. */
    free(encoded_message);
    free(shortmsg);
    free(longmsg);
    free_identity(own_from_copy);
    free_identity(relay_from_copy);
    free_identity_list(relay_tos_copy);

    if (status == PEP_STATUS_OK)
        * out_p = new;
    else
        free_message(new);
    return status;
#undef UPDATE_FROM_TO
}

DYNAMIC_API PEP_STATUS onionize(PEP_SESSION session,
                                message *in,
                                stringlist_t *extra,
                                message **out_p,
                                PEP_enc_format enc_format,
                                PEP_encrypt_flags_t flags,
                                identity_list *relays_as_list)
{
    PEP_REQUIRE(session && in && in->dir == PEP_dir_outgoing && out_p
                && enc_format == PEP_enc_PEP_message_v2
                && ! (flags & PEP_encrypt_onion)
                //&& identity_list_length(relays_as_list) >= 3
                );
    PEP_STATUS status = PEP_STATUS_OK;

    /* Initialise the output parameter, for defensiveness's sake.  We will only
       set the actual pointer to a non-NULL value at the end, on success. */
    * out_p = NULL;

    message *out = NULL;
    pEp_identity **relay_array = NULL;
    pEp_identity *layer_from = NULL;
    pEp_identity *layer_to = NULL;
    pEp_identity *original_from = in->from;
    pEp_identity *original_to = in->to->ident;
    PEP_ASSERT(original_to != NULL);
    PEP_ASSERT(in->to->next == NULL);

    /* At every layer we will replace out. */
    out = message_dup(in);
    if (out == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }

    /* Make an array from the relay list; it will be much more convenient to
       scan in any order, looking at the previous and next element.  The array
       contains pointers to the same identities pointed in the list. */
    size_t relay_no = identity_list_length(relays_as_list);
    relay_array = calloc(relay_no, sizeof (pEp_identity *));
    if (relay_array == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    int next_index = 0;
    identity_list *rest;
    for (rest = relays_as_list; rest != NULL; rest = rest->next) {
        if (rest->ident == NULL) continue; /* Ignore silly NULL identities. */
        pEp_identity *identity = rest->ident;
        /* This is also a convenient place to perform some sanity checks on
           relays. */
        if (identity->me || EMPTYSTR(identity->username)
            || EMPTYSTR(identity->address)) {
            status = PEP_ILLEGAL_VALUE;
            goto end;
        }
        relay_array [next_index] = identity;
        next_index ++;
    }
    relay_no = next_index; /* this allows for silly NULL elements in the list */

    /* Build the layers inside-out, which is to say recipient-to-sender. */
    size_t layer_no = (/* each relay receives one message */ relay_no
                       + /* last relay to recepient */ 1);
    int i;
    for (i = 0; i < layer_no; i ++) {
        /* Decide who From and To are. */
        bool innermost = (i == 0);
        bool outermost = (i == layer_no - 1);
        layer_to = innermost ? original_to : relay_array [relay_no - i];
        layer_from = outermost ? original_from : relay_array [relay_no - i - 1];
LOG_TRACE("🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅🧅 Layer %i of (1-based) %i:  from %s <%s>  to  %s <%s>", i, (int) relay_no, layer_from->username, layer_from->address, layer_to->username, layer_to->address);
        /* Wrap the current "out" message into a new layer. */
        message *new_out = NULL;
        status = _onion_make_layer(session, out, extra, & new_out, enc_format,
                                   flags | (innermost ? 0 : PEP_encrypt_onion),
                                   original_from, layer_from, layer_to,
                                   innermost, outermost);
        if (status == PEP_STATUS_OK) {
            free_message(out);
            out = new_out;
        }
        else
            goto end;
    }

 end: __attribute__((unused));
    /* Free the temporary structures we need to release on both error and
       success. */
    free(relay_array);

    if (status == PEP_STATUS_OK)
        * out_p = out;
    else
        free_message(out);
    LOG_NONOK_STATUS_NONOK;
    return status;
}

PEP_STATUS
handle_incoming_onion_routed_message(PEP_SESSION session,
                                     message *msg)
{
    PEP_REQUIRE(session && msg
                && session->messageToSend);

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity *own_identity = NULL;
    const char *attachment = NULL;
    size_t attachment_size;
    message *message_to_relay = NULL;
    message *decrypted_msg = NULL;
    message *the_interesting_msg = NULL; /* Equal to one of the previous */

    /* Make a copy of the identity the message was addressed to; this is an own
       identity, and we will use the same identity as the sender when
       relaying. */
    if(msg->to == NULL || msg->to->ident == NULL
       || ! msg->to->ident->me) {
        LOG_WARNING("invalid outer-message: not an own identity");
        status = PEP_PEPMESSAGE_ILLEGAL_MESSAGE;
        goto end;
    }
    own_identity = identity_dup(msg->to->ident);
    if (own_identity == NULL) {
        status = PEP_OUT_OF_MEMORY;
        goto end;
    }
    if (EMPTYSTR(own_identity->username)) {
        status = myself(session, own_identity);
        if (status != PEP_STATUS_OK)
            goto end;
    }

    /* Decrypt the message. */
    // FIXME: aggressively check for correctness here: we do not want to be in
    // a situation where decrypt_message crashes because we do not satisfy its
    // requirements.
    stringlist_t *keylist = NULL;
    PEP_decrypt_flags_t flags = PEP_decrypt_flag_ignore_onion;
    LOG_TRACE("FIXME: aggressively check for correctness");
    status = decrypt_message_2(session, msg, & decrypted_msg, & keylist, & flags);
    LOG_TRACE("🧅 decrypted the attached onion message with status %i 0x%x %s", (int) status, (int) status, pEp_status_to_string(status));
    free_stringlist(keylist);
    if (status == PEP_UNENCRYPTED) {
        LOG_WARNING("the attachment is an unencrypted message");
        the_interesting_msg = msg;
    }
    else if (status != PEP_STATUS_OK) {
        LOG_ERROR("could not decrypt message");
        goto end;
    }
    else
        the_interesting_msg = decrypted_msg;

    /* Search for an attachment that looks like the relayed message. */
    bloblist_t *rest;
    for (rest = the_interesting_msg->attachments; rest != NULL; rest = rest->next) {
        if (rest->mime_type != NULL
            && ! strcasecmp(rest->mime_type, PEP_ONION_MESSAGE_MIME_TYPE)) {
            LOG_TRACE("🧅found an attachment with MIME type %s", rest->mime_type);
            attachment = rest->value;
            attachment_size = rest->size;
            break;
        }
    }
    if (attachment == NULL) {
        LOG_WARNING("🧅 could not find an attachment with MIME type %s",
                    PEP_ONION_MESSAGE_MIME_TYPE);
        status = PEP_PEPMESSAGE_ILLEGAL_MESSAGE;
        goto end;
    }

    /* Decode the message. */
    status = onion_deserialize_message(session, attachment, attachment_size,
                                       & message_to_relay);
    if (status != PEP_STATUS_OK) {
        LOG_NONOK_STATUS_NONOK;
        status = PEP_PEPMESSAGE_ILLEGAL_MESSAGE;
        LOG_WARNING("🧅 failed deserialising message to relay");
        goto end;
    }

    /* Make sure that the message direction is what I want. */
    LOG_TRACE("the message direction was %s ; making it sure it becomes outgoing",
              ((message_to_relay->dir == PEP_dir_incoming) ? "incoming" : "outgoing"));
    message_to_relay->dir = PEP_dir_outgoing;

    /* Replace the From identity in the message. */
    free_identity(message_to_relay->from);
    message_to_relay->from = own_identity;
    own_identity = NULL; /* do not free this at the end. */

    /* Send the message.  messageToSend consumes the message, so we should not
       destroy it ourselves if we arrive here. */
    LOG_TRACE("🧅 RELAYING FROM %s <%s>  TO  %s <%s>", message_to_relay->from->username, message_to_relay->from->address, message_to_relay->to->ident->username, message_to_relay->to->ident->address);
    session->messageToSend(message_to_relay);
    LOG_MESSAGE_TRACE("🧅 SUCCESS: relayed", message_to_relay);
    message_to_relay = NULL; /* Do not destroy it twice. */

 end:
    LOG_NONOK_STATUS_NONOK;
    free_identity(own_identity);
    free_message(decrypted_msg);
    free_message(message_to_relay);
    /* We must not free the_interesting_msg, which is equal to one of the
       pointers we have handled already. */
    return status;
}
