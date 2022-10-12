#include "echo_api.h"

#include "pEp_internal.h"
#include "baseprotocol.h"
#include "distribution_codec.h"
#include "sync_api.h" // for notifyHandshake, currently defined in this header

#include <assert.h>
/* Either <sqlite3.h> or "sqlite3.h" has already been included by
   pEp_internal.h so we do not need to deal with it here.  */

#include "status_to_string.h" // FIXME: remove.
#include "media_key.h" // for identity_known_to_use_pEp


/* Debugging.
 * ***************************************************************** */

#define DEBUG_ECHO

#if ! defined(DEBUG_ECHO)
# define echo_log(stream, ...)               \
    do { /* Do nothing. */ } while (false)
# else
# define echo_log fprintf
#endif


/* Initialisation and finalisation
 * ***************************************************************** */

/* The functions in this section actually serve to handle prepared SQL
   statements, compiled once and for all from these SQL statements. */
static const char *echo_get_challenge_text
= "   SELECT echo_challenge"
    " FROM Identity I"
    " WHERE I.address = ?1"
    " AND I.user_id = ?2;";
static const char *echo_set_challenge_text
= "   UPDATE Identity"
    " SET echo_challenge = ?1"
    " WHERE address = ?2"
    " AND user_id = ?3;";

/* This is a convenient way to check for SQL errors without duplicating code. */
#define ON_SQL_ERROR_SET_STATUS_AND_GOTO               \
    do {                                               \
        if (sql_status != SQLITE_OK                    \
            && sql_status != SQLITE_DONE               \
            && sql_status != SQLITE_ROW) {             \
            status = PEP_UNKNOWN_DB_ERROR;             \
            /* This should not happen in production,   \
               so I can afford a debug print when      \
               something unexpected happens. */        \
            if (sql_status == SQLITE_ERROR)            \
                fprintf(stderr, "SQL ERROR: %s\n",     \
                        sqlite3_errmsg(session->db));  \
            goto end;                                  \
        }                                              \
    } while (false)


/**
 *  <!--       upgrade_add_echo_challange_field()       -->
 *
 *  @brief Upgrade database schema to support the Echo protocol.  Alter the
 *         identity table to add an echo_challange column, in case it is not
 *         there already.  There is no need to version this simple change.
 *
 *         This is called at initialisation.
 *
 *  @param[in]   session
 *
 *  @retval PEP_STATUS_OK            upgrade successful or not needed
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *
 */
static PEP_STATUS upgrade_add_echo_challange_field(PEP_SESSION session) {
    /* Sanity checks. */
    assert(session);
    if (! session)
        return PEP_ILLEGAL_VALUE;

    /* Alter the table.  This is executed only once at initialisation time,
       so keeping the SQL statement prepared would be counter-productive. */
    int sql_status
        = sqlite3_exec(session->db,
                       " ALTER TABLE Identity"
                       " ADD COLUMN echo_challenge BLOB;"
                       , NULL, NULL, NULL);
    switch (sql_status) {
    case SQLITE_OK:
        /* Upgrading was successful. */
        return PEP_STATUS_OK;
    case SQLITE_ERROR:
        /* Upgrading was not needed, but this is not a problem: the column
           we want to add exists. */
        return PEP_STATUS_OK;
    default:
        /* An actual unforeseen error. */
        return PEP_UNKNOWN_DB_ERROR;
    }
}

PEP_STATUS echo_initialize(PEP_SESSION session)
{
    /* Sanity checks. */
    assert(session && session->db);
    if (! (session && session->db))
        return PEP_ILLEGAL_VALUE;

    /* Change the schema if needed, once and for all.  We want to do this
       *before* prepraring statements using the new column that is created by
       this upgrade. */
    PEP_STATUS status = PEP_STATUS_OK;
    status = upgrade_add_echo_challange_field(session);
    if (status != PEP_STATUS_OK)
        goto end;

    /* Prepare SQL statements, so that we only do it once and for all.  This
       will be important in the future for embedded platforms with limited
       resources. */
    int sql_status;
    sql_status = sqlite3_prepare_v2(session->db, echo_get_challenge_text,
                                    -1, &session->echo_get_challenge,
                                    NULL);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_prepare_v2(session->db, echo_set_challenge_text,
                                    -1, &session->echo_set_challenge,
                                    NULL);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    
 end:
    return status;
}

PEP_STATUS echo_finalize(PEP_SESSION session)
{
    /* Sanity checks. */
    assert(session);
    if (! session)
        return PEP_ILLEGAL_VALUE;

    /* Finialise prepared SQL statements. */
    sqlite3_finalize(session->echo_get_challenge);
    sqlite3_finalize(session->echo_set_challenge);
    return PEP_STATUS_OK;
}


/* Challenge/response handling
 * ***************************************************************** */

/**
 *  <!--       echo_challenge_for_identity()       -->
 *
 *  @brief Retrieve the stored challenge for the given identity; if
 *         the identity has no stored challenge write a new one first.
 *         This is inteded for use when:
 *         (1) preparing a challenge for an outgoing Ping message;
 *         (2) checking that an incoming Pong message has the repsonse
 *             we expect.
 *
 *  @param[in]   session             session
 *  @param[in]   identity            the identity we are dealing with
 *  @param[out]  challenge           ownership remains to the caller.
 *                                   Only meaningful on success.
 *
 *  @retval PEP_STATUS_OK            success
 *  @retval PEP_UNKNOWN_DB_ERROR     unforeseen database error
 *
 */
static PEP_STATUS echo_challenge_for_identity(PEP_SESSION session,
                                              const pEp_identity *identity,
                                              pEpUUID challenge)
{
    /* Sanity checks. */
    assert(session && identity && challenge);
    if (! (session && identity && challenge))
        return PEP_ILLEGAL_VALUE;

    /* I need this below, in some cases.  It is easier to declare it here and to
       set it to NULL, in order to free it unconditionally at the end. */
    pEp_identity *identity_copy = NULL;

    /* Define a macro used everywhere with the SQL api below. */
    PEP_STATUS status = PEP_STATUS_OK;
    int sql_status;

    /* Look at the database.  First check if we have a stored challenge... */
    sql_reset_and_clear_bindings(session->echo_get_challenge);
    sql_status = sqlite3_bind_text(session->echo_get_challenge,
                                   1, identity->address, -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_bind_text(session->echo_get_challenge,
                                   2, identity->user_id, -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_step(session->echo_get_challenge);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    const void *stored_challenge;
    if (sql_status != SQLITE_ROW) {
        /* The identity is not in the database yet: make sure it is there before
           we alter the row in order to set its challenge field.

           FIXME FIXME FIXME: this is not supposed to happen, but it does at
           least on 2.x.   There should be no need to call update_identity
           if this is called from decrypt_message or outgoing_message_rating or
           outgoing_message_rating_preview .

           Something in 2.x is badly broken, and not worth fixing.  In 3.x we
           shall find the actual problem. */
        identity_copy = identity_dup(identity);
        if (identity_copy == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto end;
        }
        status = update_identity(session, identity_copy);
        if (status != PEP_STATUS_OK)
            goto end;
        stored_challenge = NULL;
    }
    else if (sqlite3_column_type(session->echo_get_challenge, 0) == SQLITE_NULL)
        stored_challenge = NULL;
    else
        stored_challenge = sqlite3_column_blob(session->echo_get_challenge, 0);
    if (stored_challenge != NULL) {
        memcpy(challenge, stored_challenge, sizeof(pEpUUID));
        goto end;
    }

    /* If we are here then we have no stored challenge.  Make a new one... */
    uuid_generate_random(challenge);
    /* These crude alternatives are convenient for debugging: */
//challenge[sizeof(pEpUUID) - 1] = '\0';
//sprintf(challenge, "to-%s-%i", getenv("USER"), rand() % (1 << 15));

    /* ...and store it into the database. */
    sql_reset_and_clear_bindings(session->echo_set_challenge);
    sql_status
        = sqlite3_bind_blob(session->echo_set_challenge,
                            1, challenge, sizeof(pEpUUID), SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status
        = sqlite3_bind_text(session->echo_set_challenge, 2, identity->address,
                            -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status
        = sqlite3_bind_text(session->echo_set_challenge, 3, identity->user_id,
                            -1, SQLITE_STATIC);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    sql_status = sqlite3_step(session->echo_set_challenge);
    ON_SQL_ERROR_SET_STATUS_AND_GOTO;
    /* If we arrived here then the SQL UPDATE statement succeeded. */

 end:
    free_identity(identity_copy);
    return status;
}

PEP_STATUS handle_pong(PEP_SESSION session,
                       const pEp_identity *own_identity,
                       const pEp_identity *partner_identity,
                       const Distribution_t *pong_distribution_message)
{
    /* Sanity checks. */
    if (! (session && own_identity && partner_identity
           && pong_distribution_message))
        return PEP_ILLEGAL_VALUE;
    if (pong_distribution_message->present != Distribution_PR_echo)
        return PEP_ILLEGAL_VALUE;
    if (pong_distribution_message->choice.echo.present != Echo_PR_echoPong)
        return PEP_ILLEGAL_VALUE; /* We handle Pong, not Ping. */

    /* Retrieve the two values. */
    PEP_STATUS status = PEP_STATUS_OK;
    pEpUUID expected_response;
    status = echo_challenge_for_identity(session, partner_identity,
                                         expected_response);
    if (status != PEP_STATUS_OK)
        return status;
    pEpUUID actual_response; /* I am not completely sure about how the type is
                                defined on windows: make this robust at the cost
                                of one more copy. */
    memcpy(actual_response,
           pong_distribution_message->choice.echo.choice.echoPong.challenge.buf,
           pong_distribution_message->choice.echo.choice.echoPong.challenge.size);

    /* Compare the response to the stored challenge. */
    if (memcmp(actual_response, expected_response, sizeof(pEpUUID))) {
        /* Bad repsonse!  It is different from the stored challenge. */
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    }
    else {
        /* Good response.  Okay, notify the application that some rating
           might have improved.  */
        fprintf(stderr, "session->notifyHandshake is %p\n", session->notifyHandshake);
        if (session->notifyHandshake == NULL)
            return PEP_SYNC_NO_NOTIFY_CALLBACK;
        pEp_identity *own_identity_copy = identity_dup(own_identity);
        pEp_identity *partner_identity_copy
            = identity_dup(partner_identity);
        if (own_identity_copy != NULL || partner_identity_copy != NULL)
            goto fail;
        echo_log(stderr, "SYNC_NOTIFY_OUTGOING_RATING_CHANGE\n");
        return session->notifyHandshake(own_identity_copy,
                                        partner_identity_copy,
                                        SYNC_NOTIFY_OUTGOING_RATING_CHANGE);
    fail:
        free(own_identity_copy);
        free(partner_identity_copy);
        return PEP_OUT_OF_MEMORY;
    }
}


/* Echo messages
 * ***************************************************************** */

/* Return a new Ping or Pong message, or NULL on failure.  The given uuid is
   used to fill the challenge / response field. */
static Distribution_t* create_Ping_or_Pong_message(const pEpUUID uuid,
                                                   bool ping)
{
    Distribution_t *msg = calloc(sizeof(Distribution_t), 1);
    if (msg == NULL || uuid == NULL)
        return NULL;
    msg->present = Distribution_PR_echo;
    int failure;
    if (ping) {
        msg->choice.echo.present = Echo_PR_echoPing;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.echoPing.challenge,
                                       (char *) uuid, 16);
    }
    else {
        msg->choice.echo.present = Echo_PR_echoPong;
        failure = OCTET_STRING_fromBuf(& msg->choice.echo.choice.echoPong.challenge,
                                       (char *) uuid, 16);
    }
    if (failure) {
        free(msg);
        return NULL;
    }
    return msg;
}

/* A helper factoring the common code in send_ping and send_pong.
   The Boolean flag determines what kind of message is sent.  The uuid field
   is used for challenge / response. */
static PEP_STATUS send_ping_or_pong(PEP_SESSION session,
                                    const pEp_identity *from,
                                    const pEp_identity *to,
                                    const pEpUUID uuid,
                                    bool ping)
{
    /* Sanity checks. */
    if (! (session && session->messageToSend && from && to))
        return PEP_ILLEGAL_VALUE;

    if (! session->enable_echo_protocol) {
        fprintf(stderr,  "* Echo protocol disabled: not sending a %s to %s <%s>\n", (ping ? "Ping" : "Pong"), (to->username ? to->username : "<no username>"), (to->address ? to->address : "<no address>"));
        return PEP_STATUS_OK;
    }

    PEP_STATUS status = PEP_STATUS_OK;
    char *data = NULL;

    /* Craft an attachment. */
    Distribution_t *msg = create_Ping_or_Pong_message(uuid, ping);
    if (msg == NULL)
        return PEP_OUT_OF_MEMORY;

    /* Encode it as an ASN.1 PER, then free the one we built. */
    size_t size;
    status = encode_Distribution_message(msg, &data, &size);
    ASN_STRUCT_FREE(asn_DEF_Distribution, msg); /* free on error as well:
                                                   move sementics */
    if (status != PEP_STATUS_OK)
        return PEP_OUT_OF_MEMORY;

    /* Make a message with the binary attached, as a network-data-structure
       message. */
    message *non_encrypted_m = NULL;
    status = base_prepare_message(session, from, to, BASE_DISTRIBUTION,
                                  data, size, NULL, & non_encrypted_m);
    if (status != PEP_STATUS_OK) {
        free(data);
        return status;
    }

    /* "Encrypt" the message in the sense of calling encrypt_message; this, in
       case we have no key for the recipient, as it will normally happen with
       Ping messages, will alter the message to contain the sender's key. */
    message *m = NULL;
    status = encrypt_message(session, non_encrypted_m, NULL, &m,
                             PEP_enc_PEP, PEP_encrypt_flag_default);
    echo_log(stderr, "  send %s from %s <%s> to %s <%s>, status after encrypting %i %s\n", (ping ? "Ping" : "Pong"), from->username, from->address, to->username, to->address, status, pEp_status_to_string(status));
    if (status == PEP_STATUS_OK)
        free_message(non_encrypted_m);
    else if (status == PEP_UNENCRYPTED)
        m = non_encrypted_m;
    else {
        free_message(non_encrypted_m);
        /* Differently from a status of PEP_UNENCRYPTED this is an actual
           unexpected error, to be reported to the caller. */
        return status;
    }

    /* Send it. */
    status = session->messageToSend(m);
    if (status != PEP_STATUS_OK) {
        free_message(m);
        return status;
    }

    /* In case of success we must *not* free the message: the called function
       gets ownership of it. */
    return PEP_STATUS_OK;
}

PEP_STATUS send_ping(PEP_SESSION session,
                     const pEp_identity *from,
                     const pEp_identity *to)
{
    pEpUUID challenge;
    PEP_STATUS status = echo_challenge_for_identity(session, to, challenge);
    if (status != PEP_STATUS_OK)
        return status;
    else
        return send_ping_or_pong(session, from, to, challenge, true);
}

PEP_STATUS send_pong(PEP_SESSION session,
                     const message *ping_message,
                     const Distribution_t *ping_distribution_message) {
fprintf(stderr, "WWWW session->notifyHandshake is %p\n", session->notifyHandshake);
    /* Argument checks.  No need to check for messageToSend here, since we
       will check later when actually sending. */
    assert(session && ping_message && ping_distribution_message);
    if (! (session && ping_message && ping_distribution_message))
        return PEP_ILLEGAL_VALUE;
    /* Sanity checks. */
    if (ping_message->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;
    if (ping_message->recv_by == NULL)
        return PEP_ILLEGAL_VALUE;
    if (! ping_message->recv_by->me)
        return PEP_ILLEGAL_VALUE;
    if (ping_distribution_message->present != Distribution_PR_echo)
        return PEP_ILLEGAL_VALUE;
    if (ping_distribution_message->choice.echo.present != Echo_PR_echoPing)
        return PEP_ILLEGAL_VALUE; /* We reply to Ping, not to Pong. */

    /* About identities, the To and From fields must be swapped between ping and
       pong.  In particular we have that  pong.from = ping.recv_by
                                and that  pong.to   = ping.from .
       About the challenge, we simply reuse the challenge allocated string
       as a response. */
    const pEp_identity *pong_from = ping_message->recv_by;
    if (! pong_from->me)
        return PEP_ILLEGAL_VALUE;
    const pEp_identity *pong_to = ping_message->from;
    const unsigned char *response
        = ping_distribution_message->choice.echo.choice.echoPing.challenge.buf;

    return send_ping_or_pong(session,
                             pong_from,
                             pong_to,
                             response,
                             false);
}


/* Policy
 * ***************************************************************** */

/* The functions in this section serve to implement some policy using the
   Distribution.Echo protocol.

   Properly handling failure in a situation where we send multiple messages
   to multiple recipients over an unreliable protocol seems futile; I have
   avoided complicated status code returns. */

/* Return true iff the given identity is known, in the sense that we do have at
   least a key for it.  In case of error consider the identity as known, which
   will avoid a Ping. */
static bool identity_known(PEP_SESSION session,
                           const pEp_identity *identity)
{
    bool result = true;
    stringlist_t *keys = NULL;
    if (identity->me)
        return true;
    pEp_identity *identity_copy = NULL;
    PEP_STATUS status;
    status = get_identity(session, identity->address, identity->user_id,
                          & identity_copy);
    if (status != PEP_STATUS_OK) {
        /* An identity not in the database is of course not known. */
        result = false;
        goto end;
    }

    status = get_all_keys_for_identity(session, identity_copy, &keys);
    if (status == PEP_KEY_NOT_FOUND)
        result = false;
    else if (status == PEP_STATUS_OK)
        result = (keys != NULL); /* I could say have written "result = true;"
                                    but I am not fond as PEP_KEY_NOT_FOUND as a
                                    status in this case, and this code will
                                    break if the status is removed later. */
    else /* An actual error. */
        goto end;

 end:
    free_identity(identity_copy);
    free_stringlist(keys);
    return result;
}

/* Send a Distribution.Ping message from the identity to the to identity, if we
   do not have a key for the to identity and the identity is not own; do nothing
   otherwise.  Ignore failures.  The to identity is allowed to be NULL.
   Iff only_if_pEp is true, do not send Ping messages to identities not known
   to use pEp. */
static void send_ping_if_unknown(PEP_SESSION session,
                                 const pEp_identity *from_identity,
                                 const pEp_identity *to_identity,
                                 bool only_if_pEp)
{
    assert(session && from_identity);
    if (! (session && from_identity))
        return;
    if (! from_identity->me) {
        echo_log(stderr, "send_ping_if_unknown: trying to send from non-own identity %s <%s>\n", from_identity->username, from_identity->address);
        return;
    }

    /* The To identity is allowed to be NULL, but in that case we do nothing.
       Own identities are dealt with in identity_known . */
    if (to_identity == NULL)
        return;

    /* In case the identity is unknown we may want to ping it... */
    if (! identity_known(session, to_identity))
        {
            /* ...As long as it uses pEp, or we do not care whether it does. */
            if (! only_if_pEp)
                send_ping(session, from_identity, to_identity);
            else {
                bool known_to_use_pEp;
                PEP_STATUS status = identity_known_to_use_pEp (session, to_identity,
                                                               & known_to_use_pEp);
                if (status != PEP_STATUS_OK) {
echo_log(stderr, "!!!! send_ping_if_unknown: %s -> %s FAILED: status %i %s\n", from_identity->address, to_identity->address, (int)status,pEp_status_to_string(status));
                    return;
                }
                if (known_to_use_pEp)
                    send_ping(session, from_identity, to_identity);
            }
        }
}

/* Send a Distribution.Ping message from the from identity to every identity in
   the to list which has no known key.  Ignore failures.  If only_pEp is true
   ignore identities not known to use pEp. */
static void send_ping_to_unknowns_in(PEP_SESSION session,
                                     const pEp_identity *from_identity,
                                     const identity_list *to_identities,
                                     bool only_pEp)
{
    const identity_list *rest;
    for (rest = to_identities; rest != NULL; rest = rest->next)
        send_ping_if_unknown(session, from_identity, rest->ident, only_pEp);
}

/* This factors the common logic of
   send_ping_to_all_unknowns_in_incoming_message and
   send_ping_to_unknown_pEp_identities_in_incoming_message . */
static PEP_STATUS send_ping_to_unknowns_in_incoming_message(PEP_SESSION session,
                                                            const message *msg,
                                                            bool only_pEp)
{
    /* Sanity checks. */
    assert(session && msg);
    if (! (session && msg))
        return PEP_ILLEGAL_VALUE;
    if (msg->dir != PEP_dir_incoming)
        return PEP_ILLEGAL_VALUE;

    /* Find the identity who received the message and should send Pings. */
    const pEp_identity *ping_from_identity = msg->recv_by;
    if (msg->recv_by == NULL) {
        /* Applications are supposed never to let this happen, but in practice
           it is difficult to find a reasonable value for messages received as
           Bcc. */
        fprintf(stderr, "APPLICATION BUG: message %s \"%s\" has no Recv-By\n", msg->id, msg->shortmsg ? msg->shortmsg : "<no subject>");
        return PEP_ILLEGAL_VALUE;
    }

    /* Send Pings.  It is harmless to consider our own identities as well as
       potential Ping recipients: those will simply never be sent to, as they
       will all have a known key.  Here we do not make any effort to avoid
       sending multiple Ping messages to the same recipient. */
    send_ping_if_unknown(session, ping_from_identity, msg->from, only_pEp);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->to, only_pEp);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->cc, only_pEp);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->reply_to,
                             only_pEp);
    /* Do not consider Bcc identities; the Bcc field should be empty anyway,
       and sending Pings would leak privacy. */

    return PEP_STATUS_OK;
}

PEP_STATUS send_ping_to_all_unknowns_in_incoming_message(PEP_SESSION session,
                                                         const message *msg)
{
    //echo_log(stderr, "send_ping_to_all_unknowns_in_incoming_message\n");
    return send_ping_to_unknowns_in_incoming_message (session, msg, false);
}

PEP_STATUS send_ping_to_unknown_pEp_identities_in_incoming_message(PEP_SESSION session,
                                                                   const message *msg)
{
    //echo_log(stderr, "send_ping_to_unknown_pEp_identities_in_incoming_message\n");
    return send_ping_to_unknowns_in_incoming_message (session, msg, true);
}

PEP_STATUS send_ping_to_unknown_pEp_identities_in_outgoing_message(PEP_SESSION session,
                                                                   const message *msg)
{
    //echo_log(stderr, "send_ping_to_unknown_pEp_identities_in_outgoing_message\n");
    /* Sanity checks. */
    assert(session && msg);
    if (! (session && msg))
        return PEP_ILLEGAL_VALUE;
    if (msg->dir != PEP_dir_outgoing)
        return PEP_ILLEGAL_VALUE;

    /* Find the identity who is sending the message and should send Pings. */
    const pEp_identity *ping_from_identity = msg->from;
    if (msg->from == NULL) {
        fprintf(stderr, "message %s \"%s\" has no From\n", msg->id, msg->shortmsg ? msg->shortmsg : "<no subject>");
        return PEP_ILLEGAL_VALUE;
    }

    /* Send Pings to identities known to use pEp -- see the Boolean parameter at
       the end.  It is harmless to consider our own identities as well as
       potential Ping recipients: those will simply never be sent to, as they
       will all have a known key.  Here we do not make any effort to avoid
       sending multiple Ping messages to the same recipient. */
    send_ping_to_unknowns_in(session, ping_from_identity, msg->to, true);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->cc, true);
    send_ping_to_unknowns_in(session, ping_from_identity, msg->reply_to, true);
    /* Do not consider Bcc identities; the Bcc field should be empty anyway,
       and sending Pings would leak privacy. */

    return PEP_STATUS_OK;
}
