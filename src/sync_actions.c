// Actions for DeviceState state machine

#include <assert.h>
#include "pEp_internal.h"
#include "message.h"
#include "sync_fsm.h"
#include "map_asn1.h"
#include "../asn.1/DeviceGroup-Protocol.h"

// conditions

static const char *sql_stored_group_keys =
        "select count(device_group) from person where id = "PEP_OWN_USERID";"; 

static int _stored_group_keys(void *_gc, int count, char **text, char **name)
{
    assert(_gc);
    assert(count == 1);
    assert(text && text[0]);
    if (!(_gc && count == 1 && text && text[0]))
        return -1;

    bool *gc = (bool *) _gc;
    *gc = atoi(text[0]) != 0;
    return 0;
}

int storedGroupKeys(PEP_SESSION session)
{
    assert(session);
    if (!session)
        return invalid_condition; // error

    bool gc = false;
    int int_result = sqlite3_exec(
        session->db,
        sql_stored_group_keys,
        _stored_group_keys,
        &gc,
        NULL
    );
    assert(int_result == SQLITE_OK);
    if (int_result != SQLITE_OK)
        return invalid_condition; // error

    if (gc)
        return 1;
    else
        return 0;
}

int keyElectionWon(PEP_SESSION session, Identity partner)
{
    assert(session);
    assert(partner);
    if (!(session && partner))
        return invalid_condition; // error

    // an already existing group always wins

    if (storedGroupKeys(session)) {
        assert(!(partner->flags & PEP_idf_devicegroup));
        return 1;
    }

    if (partner->flags & PEP_idf_devicegroup)
        return 0;

    Identity me = NULL;
    PEP_STATUS status = get_identity(session, partner->address, PEP_OWN_USERID,
            &me);
    if (status == PEP_OUT_OF_MEMORY)
        return invalid_out_of_memory;
    if (status != PEP_STATUS_OK)
        return invalid_condition; // error

    int result = invalid_condition; // error state has to be overwritten

    time_t own_created;
    time_t partners_created;

    status = key_created(session, me->fpr, &own_created);
    if (status != PEP_STATUS_OK)
        goto the_end;

    status = key_created(session, partner->fpr, &partners_created);
    if (status != PEP_STATUS_OK)
        goto the_end;

    if (own_created > partners_created)
        result = 0;
    else
        result = 1;

the_end:
    free_identity(me);
    return result;
}

// showHandshake() - trigger the handshake dialog of the application
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS showHandshake(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(extra == NULL);

    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    assert(session->showHandshake);
    if (!session->showHandshake)
        return PEP_SYNC_NO_TRUSTWORDS_CALLBACK;

    pEp_identity *me = NULL;
    status = get_identity(session, partner->address, PEP_OWN_USERID, &me);
    if (status != PEP_STATUS_OK)
        goto error;
    
    status = session->showHandshake(session, me, partner);
    if (status != PEP_STATUS_OK)
        goto error;

    return status;

error:
    free_identity(me);
    free_identity(partner);
    return status;
}


// reject() - stores rejection of partner
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS reject(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *extra
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(extra == NULL);
    if (!(session && partner))
        return PEP_ILLEGAL_VALUE;

    status = set_identity_flags(session, partner,
            partner->flags | PEP_idf_not_for_sync);

    free_identity(partner);
    return status;
}


// storeGroupKeys() - 
//
//  params:
//      session (in)        session handle
//      state (in)          state the state machine is in
//      partner (in)        partner to communicate with
//      _group_keys (in)    group keys received from partner
//
//  returns:
//      PEP_STATUS_OK or any other value on error

PEP_STATUS storeGroupKeys(
        PEP_SESSION session,
        DeviceState_state state,
        Identity partner,
        void *_group_keys
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(partner);
    assert(_group_keys);
    if (!(session && partner && _group_keys))
        return PEP_ILLEGAL_VALUE;

    identity_list *group_keys = (identity_list *) _group_keys;

    for (identity_list *il = group_keys; il && il->ident; il = il->next) {
        free(il->ident->user_id);
        il->ident->user_id = strdup(PEP_OWN_USERID);
        assert(il->ident->user_id);
        if (!il->ident->user_id)
            goto enomem;
        status = set_identity(session, il->ident);
        if (status != PEP_STATUS_OK)
            break;
    }

    free_identity(partner);
    free_identity_list(group_keys);
    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;
    free_identity(partner);
    free_identity_list(group_keys);
    return status;
}

static PEP_STATUS receive_sync_msg(
        PEP_SESSION session,
        DeviceGroup_Protocol_t *msg
    )
{
    assert(session && msg && msg->present != DeviceGroup_Protocol_PR_NOTHING);
    if (!(session && msg && msg->present != DeviceGroup_Protocol_PR_NOTHING))
        return PEP_ILLEGAL_VALUE;

    void *extra = NULL;
    Identity partner = NULL;
    DeviceState_event event = DeviceState_event_NONE;

    switch (msg->present) {
        case DeviceGroup_Protocol_PR_beacon:
            partner = Identity_to_Struct(&msg->choice.beacon.header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = Beacon;
            break;

        case DeviceGroup_Protocol_PR_handshakeRequest:
            partner = Identity_to_Struct(
                    &msg->choice.handshakeRequest.header.me, NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            event = HandshakeRequest;
            break;

        case DeviceGroup_Protocol_PR_groupKeys:
            partner = Identity_to_Struct(&msg->choice.groupKeys.header.me,
                    NULL);
            if (!partner)
                return PEP_OUT_OF_MEMORY;
            identity_list *group_keys = IdentityList_to_identity_list(
                    &msg->choice.groupKeys.ownIdentities, NULL);
            if (!group_keys) {
                free_identity(partner);
                return PEP_OUT_OF_MEMORY;
            }
            extra = (void *) group_keys;
            event = GroupKeys;
            break;

        default:
            return PEP_SYNC_ILLEGAL_MESSAGE;
    }

    return fsm_DeviceState_inject(session, event, partner, extra);
}

PEP_STATUS receive_DeviceState_msg(PEP_SESSION session, message *src)
{
    assert(session && src);
    if (!(session && src))
        return PEP_ILLEGAL_VALUE;

    bool found = false;

    for (bloblist_t *bl = src->attachments; bl && bl->value; bl = bl->next) {
        if (bl->mime_type && strcasecmp(bl->mime_type, "application/pEp") == 0
                && bl->size) {
            DeviceGroup_Protocol_t *msg;
            uper_decode_complete(NULL, &asn_DEF_DeviceGroup_Protocol,
                    (void **) &msg, bl->value, bl->size);
            if (msg) {
                found = true;
                PEP_STATUS status = receive_sync_msg(session, msg);
                ASN_STRUCT_FREE(asn_DEF_DeviceGroup_Protocol, msg);
                if (status != PEP_STATUS_OK)
                    return status;
            }
        }
    }

    if (found) {
        for (stringpair_list_t *spl = src->opt_fields ; spl && spl->value ;
                spl = spl->next) {
            if (spl->value->key &&
                    strcasecmp(spl->value->key, "pEp-auto-consume") == 0) {
                if (spl->value->value &&
                        strcasecmp(spl->value->value, "yes") == 0)
                    return PEP_MESSAGE_CONSUMED;
            }
        }
    }

    return PEP_STATUS_OK;
}

