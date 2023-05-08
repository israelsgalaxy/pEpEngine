/**
 * @file group.c
 * @brief Implementation of in-memory objects and functions for representation of groups
 * @license This file is under GNU General Public License 3.0 - see LICENSE.txt
 */

#include "group.h"
#include "group_internal.h"

#include "pEp_internal.h"
#include "message_api.h"
#include "message_api_internal.h"
#include "distribution_codec.h"
#include "map_asn1.h"
#include "baseprotocol.h"
#include "sync_api.h"

// ** Static functions
/******************************************************************************************
 * STATIC FUNCTIONS
 ******************************************************************************************/

/******************************************************************************************
 *
 * @internal
 *
 *  <!--   * _build_managed_group_message_payload -->
 *
 * @brief TODO
 *
 * @param session
 * @param group_identity
 * @param manager
 * @param data
 * @param size
 * @param managed_group_msg_type
 * @retval PEP_STATUS_OK
 * @retval any other on error
 */
static PEP_STATUS _build_managed_group_message_payload(PEP_SESSION session,
                                                       const pEp_identity* group_identity,
                                                       const pEp_identity* manager,
                                                       char** data, size_t* size,
                                                       ManagedGroup_PR managed_group_msg_type
) {

    PEP_STATUS status = PEP_STATUS_OK;
    char *_data = NULL;
    size_t _size = 0;

    // Ok, let's get the payload set up
    Distribution_t *outdist = (Distribution_t *) calloc(1, sizeof(Distribution_t));

    if (!outdist)
        return PEP_OUT_OF_MEMORY;

    *data = NULL;
    *size = 0;

    outdist->present = Distribution_PR_managedgroup;
    outdist->choice.managedgroup.present = managed_group_msg_type;

    Identity_t* group_identity_Ident = NULL;
    Identity_t* other_identity_Ident = NULL;

    switch (managed_group_msg_type) {
        case ManagedGroup_PR_groupInvite:
            group_identity_Ident = &(outdist->choice.managedgroup.choice.groupInvite.groupIdentity);
            other_identity_Ident = &(outdist->choice.managedgroup.choice.groupInvite.manager);
            break;
        case ManagedGroup_PR_groupDissolve:
            group_identity_Ident = &(outdist->choice.managedgroup.choice.groupDissolve.groupIdentity);
            other_identity_Ident = &(outdist->choice.managedgroup.choice.groupDissolve.manager);
            break;
        case ManagedGroup_PR_groupAdopted:
            group_identity_Ident = &(outdist->choice.managedgroup.choice.groupAdopted.groupIdentity);
            other_identity_Ident = &(outdist->choice.managedgroup.choice.groupAdopted.member);
            break;
        default:
            status = PEP_ILLEGAL_VALUE;
            goto pEp_error;
    }
    // We don't free anything here because PEP_OUT_OF_MEMORY is always fatal up the stack
    if (!Identity_from_Struct(group_identity, group_identity_Ident))
        goto enomem;
    if (!Identity_from_Struct(manager, other_identity_Ident))
        goto enomem;

    // Man, I hope this is it.
    status = encode_Distribution_message(outdist, &_data, &_size);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    *data = _data;
    *size = _size;

    free(outdist);

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free(_data);
    free(outdist);
    return status;
}

/******************************************************************************************
 *
 * @internal
 *
 * <!-- _create_and_send_managed_group_message -->
 *
 * @brief TODO
 *
 * @param session
 * @param from
 * @param recip
 * @param data
 * @param size
 * @param attachments
 * @return
 */
static PEP_STATUS _create_and_send_managed_group_message(PEP_SESSION session,
                                                         pEp_identity* from,
                                                         pEp_identity* recip,
                                                         char* data,
                                                         size_t size,
                                                         bloblist_t* attachments
) {
    PEP_REQUIRE(session && from && recip
                && ! EMPTYSTR(from->user_id) && ! EMPTYSTR(from->address)
                && ! EMPTYSTR(recip->user_id) && ! EMPTYSTR(recip->address)
                && ! EMPTYSTR(from->fpr));

    message* msg = NULL;
    message* enc_msg = NULL;

    PEP_STATUS status = base_prepare_message(session, from, recip, BASE_DISTRIBUTION,
                                             data, size, from->fpr, &msg);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // Fatal, bail
    if (!msg)
        return PEP_OUT_OF_MEMORY;

    if (!msg->attachments) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    if (attachments)
        msg->attachments = bloblist_join(msg->attachments, attachments);

    // encrypt this baby and get out
    // extra keys???
    status = encrypt_message(session, msg, NULL, &enc_msg, PEP_enc_auto, 0); // FIXME

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    _add_auto_consume(enc_msg);

    // insert into queue
    status = session->messageToSend(enc_msg);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    free_message(msg);
    msg = NULL;
    return status;

pEp_error:
    free_message(msg);
    free_message(enc_msg);
    return status;
}

/******************************************************************************************
 *
 * @param session
 * @param group
 * @param message_type
 * @return
 */
static PEP_STATUS _send_managed_group_message_to_list(PEP_SESSION session,
                                                      pEp_group* group,
                                                      ManagedGroup_PR message_type) {
    PEP_REQUIRE(session && group && group->group_identity && group->manager
                && ! EMPTYSTR(group->group_identity->user_id)
                && ! EMPTYSTR(group->group_identity->address)
                && ! EMPTYSTR(group->manager->user_id)
                && ! EMPTYSTR(group->manager->address)
                && is_me(session, group->manager));
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    char *_data = NULL;
    size_t _size = 0;

    char* key_material_priv = NULL;
    size_t key_material_size = 0;

    bloblist_t* keycopyblob = NULL;

    // Ok, let's get the payload set up, because we can duplicate this for each message.
    PEP_STATUS status = _build_managed_group_message_payload(session, group->group_identity,
                                                             group->manager, &_data, &_size,
                                                             message_type);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // Let's also get the private key for the group we want to distribute and set up a bloblist element to
    // dup

    status = export_secret_key(session, group->group_identity->fpr, &key_material_priv, &key_material_size);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    if (key_material_size == 0 || !key_material_priv) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    keycopyblob = new_bloblist(key_material_priv, key_material_size,
                               "application/pgp-keys",
                               "file://pEpkey_group_priv.asc");

    // Ok, for every member in the member list, send away.
    // (We'll copy in for now. It's small and quick.)
    member_list* curr_member = NULL;


    for (curr_member = group->members; curr_member && curr_member->member && curr_member->member->ident; curr_member = curr_member->next) {
        pEp_identity* recip = curr_member->member->ident; // This will be duped in base_prepare_message
        PEP_rating recip_rating;
        status = identity_rating(session, recip, &recip_rating);
        if (status != PEP_STATUS_OK)
            goto pEp_error;
        if (recip_rating < PEP_rating_reliable)
            continue;

        // Copy the data to send in as an argument
        char* data_copy = (char*)malloc(_size);
        if (!data_copy)
            goto enomem;
        memcpy(data_copy, _data, _size);

        bloblist_t* key_attachment = bloblist_dup(keycopyblob);

        // encrypt and send this baby and get out
        status = _create_and_send_managed_group_message(session, group->manager, recip, data_copy, _size, key_attachment);

        if (status != PEP_STATUS_OK)
            goto pEp_error;
    }

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    free(key_material_priv);
    free(_data);
    return status;
}

/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @param as_member
 * @return
 */
static PEP_STATUS _set_own_status_joined(PEP_SESSION session,
                                            pEp_identity* group_identity,
                                            pEp_identity* as_member) {
    int result = 0;

    sql_reset_and_clear_bindings(session->group_join);

    sqlite3_bind_text(session->group_join, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_join, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_join, 3, as_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_join, 4, as_member->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->group_join);

    sql_reset_and_clear_bindings(session->group_join);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @param as_member
 * @return
 */
static PEP_STATUS _remove_member_from_group(PEP_SESSION session,
                                            pEp_identity* group_identity,
                                            pEp_identity* member) {
    int result = 0;

    sql_reset_and_clear_bindings(session->group_delete_member);

    sqlite3_bind_text(session->group_delete_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_delete_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_delete_member, 3, member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_delete_member, 4, member->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->group_delete_member);

    sql_reset_and_clear_bindings(session->group_delete_member);

    if (result != SQLITE_DONE)
        return PEP_UNKNOWN_ERROR;

    return PEP_STATUS_OK;
}


/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @param leaver
 * @return
 */
static PEP_STATUS _set_leave_group_status(PEP_SESSION session, pEp_identity* group_identity, pEp_identity* leaver) {

    sql_reset_and_clear_bindings(session->leave_group);

    sqlite3_bind_text(session->leave_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 3, leaver->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 4, leaver->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->leave_group);

    sql_reset_and_clear_bindings(session->leave_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_LEAVE_GROUP;
    else
        return PEP_STATUS_OK;
}

/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @return
 */
static PEP_STATUS _set_group_as_disabled(PEP_SESSION session, pEp_identity* group_identity) {
    int result = 0;

    sql_reset_and_clear_bindings(session->disable_group);

    sqlite3_bind_text(session->disable_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->disable_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->disable_group);

    sql_reset_and_clear_bindings(session->disable_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_DISABLE_GROUP;

    else
        return PEP_STATUS_OK;

}

/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @param memberlist
 * @return
 */
static PEP_STATUS _retrieve_own_membership_info_for_group(PEP_SESSION session, pEp_identity* group_identity,
                                                          member_list** memberlist) {
    PEP_STATUS status = PEP_STATUS_OK;
    int result = 0;

    member_list* _mbr_list_head = NULL;
    member_list** _mbr_list_next = &_mbr_list_head;
    pEp_identity* ident = NULL;
    pEp_member* member = NULL;

    sql_reset_and_clear_bindings(session->retrieve_own_membership_info_for_group);

    sqlite3_bind_text(session->retrieve_own_membership_info_for_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    while ((result = pEp_sqlite3_step_nonbusy(session, session->retrieve_own_membership_info_for_group)) == SQLITE_ROW) {
            ident = new_identity((const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group, 1),
                               NULL,(const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group, 0),
                               NULL);

        if (ident == NULL)
            goto enomem;

        member = new_member(ident);
        ident = NULL; // prevent double-free on error

        if (!member)
            goto enomem;

        member->joined = sqlite3_column_int(session->retrieve_own_membership_info_for_group, 2);

        *_mbr_list_next = new_memberlist(member);
        member = NULL; // prevent double-free on error

        if (!(*_mbr_list_next))
            goto enomem;

        _mbr_list_next = &((*_mbr_list_next)->next);
    }

    if (result != SQLITE_DONE) {
        status = PEP_CANNOT_DISABLE_GROUP;
        goto pEp_error;
    }

    sql_reset_and_clear_bindings(session->retrieve_own_membership_info_for_group);

    *memberlist = _mbr_list_head;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    sql_reset_and_clear_bindings(session->retrieve_own_membership_info_for_group);

    if (ident) // Only true if problem allocating member
        free_identity(ident);

    if (member) // Only true if problem allocating memberlist node
        free_member(member);

    free_memberlist(_mbr_list_head);

    return status;
}

/******************************************************************************************
 *
 * @param session
 * @param group_identity
 * @param member
 * @param is_member
 * @return
 */
static PEP_STATUS is_invited_group_member(PEP_SESSION session, pEp_identity* group_identity,
                                          pEp_identity* member, bool* is_member) {
    PEP_REQUIRE(session && is_member
                && group_identity
                && ! EMPTYSTR(group_identity->user_id) && ! EMPTYSTR(group_identity->address)
                && member
                && ! EMPTYSTR(member->user_id) && ! EMPTYSTR(member->address));

    PEP_STATUS status = PEP_STATUS_OK;

    sql_reset_and_clear_bindings(session->is_invited_group_member);

    sqlite3_bind_text(session->is_invited_group_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 3, member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_invited_group_member, 4, member->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->is_invited_group_member);

    if (result != SQLITE_ROW)
        status = PEP_UNKNOWN_DB_ERROR;
    else
        *is_member = sqlite3_column_int(session->is_invited_group_member, 0);

    sql_reset_and_clear_bindings(session->is_invited_group_member);

    return status;
}

/******************************************************************************************
 * UTILITY FUNCTIONS
 ******************************************************************************************/

identity_list* member_list_to_identity_list(member_list* memberlist) {
    member_list* curr_mem = memberlist;
    identity_list* head = NULL;
    identity_list** id_list_curr_ptr = &head;

    for ( ; curr_mem && curr_mem->member && curr_mem->member->ident; curr_mem = curr_mem->next,
            id_list_curr_ptr = &((*id_list_curr_ptr)->next)) {
        *id_list_curr_ptr = new_identity_list(identity_dup(curr_mem->member->ident));
        if (!(*id_list_curr_ptr))
            return NULL; // Out of memory - FIXME: can we be cleaner here?
    }
    return head;
}

member_list* identity_list_to_memberlist(identity_list* ident_list) {

    identity_list* curr_ident = ident_list;
    member_list* head = NULL;
    member_list** mem_list_curr_ptr = &head;

    pEp_identity* tmp_ident = NULL;
    pEp_member* member = NULL;
    member_list* new_node = NULL;

    for ( ; curr_ident && curr_ident->ident; curr_ident = curr_ident->next,
            mem_list_curr_ptr = &((*mem_list_curr_ptr)->next)) {
        tmp_ident = identity_dup(curr_ident->ident);
        if (!tmp_ident)
            goto enomem;
        pEp_member* member = new_member(tmp_ident);
        if (!member)
            goto enomem;
        tmp_ident = NULL;
        new_node = new_memberlist(member);
        if (!new_node)
            goto enomem;
        member = NULL;
        *mem_list_curr_ptr = new_node;
    }

    return head;

enomem:
    if (!member)
        free(tmp_ident); // is probably NULL anyway
    else {
        free_member(member);
    }
    free_memberlist(head);
    return NULL;
}

// Exposed for testing.
PEP_STATUS set_membership_status(PEP_SESSION session,
                                            pEp_identity* group_identity,
                                            pEp_identity* as_member,
                                            bool active) {
    int result = 0;

    sql_reset_and_clear_bindings(session->set_group_member_status);

    sqlite3_bind_int(session->set_group_member_status, 1, active);
    sqlite3_bind_text(session->set_group_member_status, 2, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 3, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 4, as_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->set_group_member_status, 5, as_member->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->set_group_member_status);

    sql_reset_and_clear_bindings(session->set_group_member_status);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}


PEP_STATUS get_group_manager(PEP_SESSION session,
                             pEp_identity* group_identity,
                             pEp_identity** manager) {
    PEP_REQUIRE(session && group_identity && manager
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address));

    PEP_STATUS status = PEP_STATUS_OK;

    sql_reset_and_clear_bindings(session->get_group_manager);

    sqlite3_bind_text(session->get_group_manager, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_group_manager, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    *manager = NULL;

    int result = pEp_sqlite3_step_nonbusy(session, session->get_group_manager);

    if (result != SQLITE_ROW)
        status = PEP_GROUP_NOT_FOUND;
    else {
        *manager = new_identity((const char *) sqlite3_column_text(session->get_group_manager, 1),
                                NULL, (const char *) sqlite3_column_text(session->get_group_manager, 0),
                                NULL);
        if (!*manager)
            return PEP_OUT_OF_MEMORY;
    }
    sql_reset_and_clear_bindings(session->get_group_manager);
    return status;
}

PEP_STATUS is_group_active(PEP_SESSION session, pEp_identity* group_identity, bool* active) {
    PEP_REQUIRE(session && group_identity && active
                && ! EMPTYSTR(group_identity->address) && ! EMPTYSTR(group_identity->user_id));

    PEP_STATUS status = PEP_STATUS_OK;
    *active = false;

    sql_reset_and_clear_bindings(session->is_group_active);
    sqlite3_bind_text(session->is_group_active, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_group_active, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->is_group_active);

    switch (result) {
        case SQLITE_ROW:
            *active = (sqlite3_column_int(session->is_group_active, 0) != 0);
            break;
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sql_reset_and_clear_bindings(session->is_group_active);

    return status;
}

PEP_STATUS is_group_mine(PEP_SESSION session, pEp_identity* group_identity, bool* own_manager) {
    PEP_REQUIRE(session && own_manager);

    *own_manager = false;

    // Ok, we have a group ident. Someone ensure I'm the manager...
    pEp_identity* manager = NULL;
    PEP_STATUS status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        return status;
    if (!manager)
        return PEP_GROUP_NOT_FOUND;

    if (is_me(session, manager))
        *own_manager = true;

    free_identity(manager);

    return PEP_STATUS_OK;
}

// group_identity MUST have been myself'd.
// Called only from create_group and PRESUMES group, group->identity (user_id and address),
// group->manager (user_id and address) are there AND VALIDATED. This is JUST the DB call factored out.
PEP_STATUS create_group_entry(PEP_SESSION session,
                              pEp_group* group) {
    PEP_REQUIRE(session && group);
    pEp_identity* group_identity = group->group_identity;
    pEp_identity* manager = group->manager;

    int result = 0;

    sql_reset_and_clear_bindings(session->create_group);

    sqlite3_bind_text(session->create_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 3, manager->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->create_group, 4, manager->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->create_group);

    sql_reset_and_clear_bindings(session->create_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

// This presumes these values have been checked!!!!!!!!
PEP_STATUS add_own_membership_entry(PEP_SESSION session,
                                    pEp_identity* group_identity,
                                    pEp_identity* manager,
                                    pEp_identity* own_identity_recip) {
    PEP_REQUIRE(session && group_identity && manager && own_identity_recip
                && ! EMPTYSTR(group_identity->user_id) && ! EMPTYSTR(group_identity->address)
                && ! EMPTYSTR(manager->user_id) && ! EMPTYSTR(manager->address)
                && ! EMPTYSTR(own_identity_recip->user_id) && ! EMPTYSTR(own_identity_recip->address));

    sql_reset_and_clear_bindings(session->add_own_membership_entry);

    int result = 0;

    sqlite3_bind_text(session->add_own_membership_entry, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 3, own_identity_recip->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->add_own_membership_entry, 4, own_identity_recip->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->add_own_membership_entry);

    sql_reset_and_clear_bindings(session->add_own_membership_entry);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS get_own_membership_status(PEP_SESSION session,
                                     pEp_identity* group_identity,
                                     pEp_identity* own_identity,
                                     bool* have_joined) {
    PEP_REQUIRE(session && group_identity && own_identity && have_joined);
    PEP_STATUS status = PEP_STATUS_OK;

    sql_reset_and_clear_bindings(session->get_own_membership_status);
    sqlite3_bind_text(session->get_own_membership_status, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 3, own_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->get_own_membership_status, 4, own_identity->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->get_own_membership_status);

    switch (result) {
        case SQLITE_ROW:
            *have_joined = sqlite3_column_int(session->get_own_membership_status, 0);
            break;
        default:
            status = PEP_NO_MEMBERSHIP_STATUS_FOUND;
    }

    sql_reset_and_clear_bindings(session->get_own_membership_status);

    return status;
}

PEP_STATUS retrieve_own_membership_info_for_group_and_identity(PEP_SESSION session,
                                                     pEp_group* group,
                                                     pEp_identity* own_identity) {
    const pEp_identity* group_identity;
    PEP_REQUIRE(session && group && own_identity
                && ! EMPTYSTR(own_identity->user_id) && ! EMPTYSTR(own_identity->address)
                && (/* yes, an assignment */ group_identity = group->group_identity)
                && ! EMPTYSTR(group_identity->user_id) && ! EMPTYSTR(group_identity->address));
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity* my_member_ident = NULL;
    pEp_member* me_mem = NULL;
    member_list* memberlist = NULL;
    
    sql_reset_and_clear_bindings(session->retrieve_own_membership_info_for_group_and_ident);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 1, group->group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 2, group->group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 3, own_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->retrieve_own_membership_info_for_group_and_ident, 4, own_identity->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->retrieve_own_membership_info_for_group_and_ident);


    switch (result) {
        case SQLITE_ROW: {
            my_member_ident = identity_dup(own_identity);
            if (!my_member_ident)
                goto enomem;
            me_mem = new_member(my_member_ident);
            if (!me_mem)
                goto enomem;
            me_mem->joined = sqlite3_column_int(session->retrieve_own_membership_info_for_group_and_ident, 0);
            memberlist = new_memberlist(me_mem);
            if (!memberlist)
                goto enomem;

            group->members = memberlist;
            group->manager = new_identity((const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group_and_ident, 2),
                                                NULL,
                                                (const char *) sqlite3_column_text(session->retrieve_own_membership_info_for_group_and_ident, 1),
                                                NULL);
            if (!group->manager)
                goto enomem;
            group->active = sqlite3_column_int(session->retrieve_own_membership_info_for_group_and_ident, 3);
            break;
        }
        default:
            status = PEP_NO_MEMBERSHIP_STATUS_FOUND;
    }

    return status;

enomem:
    if (!memberlist) {
        if (!me_mem)
            free_identity(my_member_ident);
        else
            free_member(me_mem);
    }
    else
        free_memberlist(memberlist);
    return PEP_OUT_OF_MEMORY;
}


PEP_STATUS leave_group(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *member_identity
) {
    PEP_REQUIRE(session && group_identity && member_identity
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address)
                && ! EMPTYSTR(member_identity->user_id)
                && ! EMPTYSTR(member_identity->address));

    // get our status, if there is any
    bool am_member = false;
    PEP_STATUS status = get_own_membership_status(session, group_identity, member_identity, &am_member);

    if (status == PEP_NO_MEMBERSHIP_STATUS_FOUND)
        return PEP_STATUS_OK;

    if (status != PEP_STATUS_OK)
        return status;

    if (!am_member)
        return PEP_STATUS_OK;

    // Ok, we clearly joined the group at some point.
    int result = 0;

    sql_reset_and_clear_bindings(session->leave_group);

    sqlite3_bind_text(session->leave_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 3, member_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->leave_group, 4, member_identity->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->leave_group);

    sql_reset_and_clear_bindings(session->leave_group);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_CREATE_GROUP;

    return PEP_STATUS_OK;
}

PEP_STATUS group_enable(
        PEP_SESSION session,
        pEp_identity *group_identity
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sql_reset_and_clear_bindings(session->enable_group);

    sqlite3_bind_text(session->enable_group, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->enable_group, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    result = pEp_sqlite3_step_nonbusy(session, session->enable_group);

    sql_reset_and_clear_bindings(session->enable_group);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_ENABLE_GROUP;

    return status;
}

PEP_STATUS exists_group(
        PEP_SESSION session,
        pEp_identity* group_identity,
        bool* exists
) {

    PEP_STATUS status = PEP_STATUS_OK;

    sql_reset_and_clear_bindings(session->exists_group_entry);
    sqlite3_bind_text(session->exists_group_entry, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->exists_group_entry, 2, group_identity->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->exists_group_entry);

    switch (result) {
        case SQLITE_ROW: {
            // yeah yeah, I know, we could be lazy here, but it looks bad.
            *exists = (sqlite3_column_int(session->exists_group_entry, 0) != 0);
            break;
        }
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }

    sql_reset_and_clear_bindings(session->exists_group_entry);

    return status;
}

// N.B. Call update_identity first!!
PEP_STATUS group_add_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
) {
    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    int result = 0;

    sql_reset_and_clear_bindings(session->group_add_member);

    sqlite3_bind_text(session->group_add_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 3, group_member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->group_add_member, 4, group_member->address, -1,
                      SQLITE_STATIC);


    result = pEp_sqlite3_step_nonbusy(session, session->group_add_member);

    sql_reset_and_clear_bindings(session->group_add_member);

    if (result != SQLITE_DONE)
        status = PEP_CANNOT_ADD_GROUP_MEMBER;

    return status;
}


PEP_STATUS retrieve_full_group_membership(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** members)
{
    PEP_REQUIRE(session && group_identity && members
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address));

    PEP_STATUS status = PEP_STATUS_OK;
    *members = NULL;

    sql_reset_and_clear_bindings(session->get_all_members);
    sqlite3_bind_text(session->get_all_members, 1, group_identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_all_members, 2, group_identity->address, -1, SQLITE_STATIC);
    int result;

    member_list* retval = NULL;
    member_list** member_list_next = &retval;

    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_all_members)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->get_all_members, 1),
                                           NULL,(const char *) sqlite3_column_text(session->get_all_members, 0),
                                           NULL);
        PEP_WEAK_ASSERT_ORELSE_GOTO(ident, enomem);

        pEp_member* new_mem = new_member(ident);
        new_mem->joined = sqlite3_column_int(session->get_all_members, 2);
        member_list* new_node = new_memberlist(new_mem);
        if (!new_node)
            goto enomem;

        *member_list_next = new_node;
        member_list_next = &(new_node->next);
    }

    member_list* curr = retval;

    for ( ; curr ; curr = curr->next) {
        if (!(curr->member && curr->member->ident))
            goto enomem;
        status = update_identity(session, curr->member->ident);
    }

    sql_reset_and_clear_bindings(session->get_all_members);
    *members = retval;

    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

//pEp_error: // Uncomment if other errors are valid
    sql_reset_and_clear_bindings(session->get_all_members);
    free_memberlist(retval);
    return status;
}

PEP_STATUS retrieve_active_member_list(
        PEP_SESSION session,
        pEp_identity* group_identity,
        member_list** mbr_list)
{
    PEP_REQUIRE(session && group_identity && mbr_list
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address));

    PEP_STATUS status = PEP_STATUS_OK;
    *mbr_list = NULL;

    sql_reset_and_clear_bindings(session->get_active_members);
    sqlite3_bind_text(session->get_active_members, 1, group_identity->user_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(session->get_active_members, 2, group_identity->address, -1, SQLITE_STATIC);
    int result;

    member_list* retval = NULL;
    member_list** mbr_list_next = &retval;

    while ((result = pEp_sqlite3_step_nonbusy(session, session->get_active_members)) == SQLITE_ROW) {
        pEp_identity *ident = new_identity((const char *) sqlite3_column_text(session->get_active_members, 1),
                NULL,(const char *) sqlite3_column_text(session->get_active_members, 0),
                NULL);
        PEP_WEAK_ASSERT_ORELSE_GOTO(ident, enomem);

        pEp_member* member = new_member(ident);
        if (!member)
            goto enomem;

        member_list* new_node = new_memberlist(member);
        if (!new_node) {
            free_member(member);
            goto enomem;
        }

        new_node->member->joined = true;

        *mbr_list_next = new_node;
        mbr_list_next = &(new_node->next);
    }

    member_list* curr = retval;

    for ( ; curr && curr->member && curr->member->ident; curr = curr->next) {
        if (!curr->member->ident)
            goto enomem;
        status = update_identity(session, curr->member->ident);
    }

    sql_reset_and_clear_bindings(session->get_active_members);

    *mbr_list = retval;
    return PEP_STATUS_OK;

enomem:
    status = PEP_OUT_OF_MEMORY;

//pEp_error: // Uncomment if other errors are valid
    sql_reset_and_clear_bindings(session->get_active_members);
    free_memberlist(retval);
    return status;
}

PEP_STATUS retrieve_group_info(PEP_SESSION session, pEp_identity* group_identity, pEp_group** group_info) {
    PEP_REQUIRE(session && group_identity
                && ! EMPTYSTR(group_identity->address) && group_info);

    pEp_group* group = NULL;
    pEp_identity* manager = NULL;
    member_list* members = NULL;

    PEP_STATUS status = PEP_STATUS_OK;
    *group_info = NULL;

    pEp_identity* stored_identity = NULL;

    status = get_identity(session, group_identity->address, group_identity->user_id, &stored_identity);
    if (status != PEP_STATUS_OK)
        return status;

    if (!stored_identity)
        return PEP_CANNOT_FIND_IDENTITY;

    status = retrieve_full_group_membership(session, stored_identity, &members);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    status = get_group_manager(session, stored_identity, &manager);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    group = new_group(stored_identity, manager, members);
    if (!group)
        goto enomem;

    bool active = false;
    status = is_group_active(session, group_identity, &active);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    group->active = active;
    *group_info = group;

    return status;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_error:
    if (!group) {
        free_memberlist(members);
        free_identity(manager);
    }
    else {
        free_group(group);
    }
    return status;
}

PEP_STATUS send_GroupAdopted(PEP_SESSION session, pEp_identity* group_identity, pEp_identity* from) {
    PEP_REQUIRE(session && group_identity && from
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address)
                && ! EMPTYSTR(from->user_id)
                && ! EMPTYSTR(from->address));
    if (!session->messageToSend)
        return PEP_SEND_FUNCTION_NOT_REGISTERED;

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* manager = NULL;

    if (!is_me(session, group_identity))
        status = update_identity(session, group_identity);
    else
        status = _myself(session, group_identity, false, false, false, true);

    if (status != PEP_STATUS_OK)
        return status;
    else if (!(is_me(session, group_identity) && group_identity->flags & PEP_idf_group_ident)) {
        return PEP_ILLEGAL_VALUE;
    }

    // Get the manager

    status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        return status;
    else if (!manager)
        return PEP_OUT_OF_MEMORY;
    else if (EMPTYSTR(manager->address) || EMPTYSTR(manager->user_id)) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }

    // ?? Is this really necessary? It's an internal call. Well, anything can mess up, no?
    if (is_me(session, manager))
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    // ??

    char* _data = NULL;
    size_t _size = 0;

    // Ok, let's get the payload set up, because we can duplicate this for each message.
    status = _build_managed_group_message_payload(session, group_identity,
                                                  from, &_data, &_size,
                                                  ManagedGroup_PR_groupAdopted);

    if (status != PEP_STATUS_OK)
        return status;

    pEp_identity* recip = manager; // This will be duped in base_prepare_message
    PEP_rating recip_rating;
    status = identity_rating(session, recip, &recip_rating);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
    if (recip_rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // ??? FIXME

    // encrypt and send this baby and get out
    status = _create_and_send_managed_group_message(session, from, recip, _data, _size, NULL);

    if (status != PEP_STATUS_OK)
        goto pEp_error;

    return status;

pEp_error:
    free_identity(manager);
    return status;
}

PEP_STATUS receive_GroupInvite(PEP_SESSION session, message* msg, PEP_rating rating, GroupInvite_t* gc) {
    PEP_REQUIRE(session && msg);

    PEP_STATUS status = PEP_STATUS_OK;
    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    // Make sure everything's there are enforce exactly one recip
    if (!gc || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    pEp_identity* member_ident = NULL;
    pEp_identity* group_identity = NULL;
    pEp_identity* manager = NULL;
    identity_list* list = NULL;

    pEp_group* group = NULL;

    char* own_id = NULL;
    stringlist_t* keylist = NULL;


    // FIXME: this will be hard without address aliases.

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            return status;
    }

    if (!is_me(session, msg->to->ident))
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    group_identity = Identity_to_Struct(&(gc->groupIdentity), NULL);
    if (!group_identity)
        return PEP_UNKNOWN_ERROR; // we really don't know why


    manager = Identity_to_Struct(&(gc->manager), NULL);
    if (!manager)
        return PEP_UNKNOWN_ERROR;

    free(manager->user_id);
    manager->user_id = NULL;
    free(group_identity->user_id);
    group_identity->user_id = NULL;

    status = update_identity(session, manager);
    if (!manager->fpr) {// at some point, we can require this to be the sender fpr I think - FIXME
        status = PEP_KEY_NOT_FOUND;
        goto pEp_free;
    }
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    // If we are the manager of this group, we should ignore this message - Volker, fixme if groupsync should be different here
    // when you implement it
    if (is_me(session, manager))
        goto pEp_free;

    // Ok then - let's do this:
    // First, we need to ensure the group_ident has an own ident instead
    status = get_default_own_userid(session, &own_id);
    if (status != PEP_STATUS_OK) {
        free(own_id); // Just in case
        goto pEp_free;
    }

    if (!own_id) {
        status = PEP_NO_OWN_USERID_FOUND;
        goto pEp_free;
    }

    // Takes ownership here, which is why we DON'T free own_id at the end
    group_identity->user_id = own_id;
    own_id = NULL; // avoid double-free;

    // Ok, let's ensure we HAVE the key for this group:
    status = find_private_keys(session, group_identity->fpr, &keylist);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!keylist) {
        status = PEP_KEY_NOT_FOUND;
        goto pEp_free;
    }

    status = set_own_key(session, group_identity, group_identity->fpr);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    member_ident = identity_dup(msg->to->ident);
    if (!member_ident) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }

    list = new_identity_list(member_ident);
    if (!list) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }

    status = group_create(session, group_identity, manager, list, &group);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    status = add_own_membership_entry(session, group_identity, manager, msg->to->ident);

    // Ok, we did all we have to do and it worked out. Notify the app.
    if (status == PEP_STATUS_OK && session->notifyHandshake) {
        // identities go to the callee, so we have to dup them here because the normal ones belong
        // to the returned group. #notmyspec ;)
        pEp_identity* grp = identity_dup(group_identity);
        pEp_identity* mgr = identity_dup(manager);
        status = session->notifyHandshake(grp, mgr, SYNC_NOTIFY_GROUP_INVITATION);
    }

pEp_free:
    if (!group) {
        if (!list)
            free_identity(member_ident);
        else
            free_identity_list(list);

        free_identity(manager);
        free_identity(group_identity);
    }
    else
        free_group(group);
    free_stringlist(keylist);

    return status;
}

PEP_STATUS receive_GroupDissolve(PEP_SESSION session, message* msg, PEP_rating rating, GroupDissolve_t* gd) {
    PEP_REQUIRE(session && msg);

    PEP_STATUS status = PEP_STATUS_OK;

    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    if (!msg->_sender_fpr) // We'll never be able to verify. Reject
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // Make sure everything's there are enforce exactly one recip
    if (!gd || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            return status;
    }

    // this will be hard without address aliases
    if (!is_me(session, msg->to->ident))
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    stringlist_t* keylist = NULL;
    pEp_identity* manager = NULL;
    pEp_identity* group_identity = NULL;
    pEp_identity* tmp_ident = NULL;
    pEp_group* group = NULL;

    pEp_identity* own_identity = msg->to->ident;

    group_identity = Identity_to_Struct(&(gd->groupIdentity), NULL);
    if (!group_identity)
        return PEP_UNKNOWN_ERROR; // we really don't know why, and nothing is allocated yet

    manager = Identity_to_Struct(&(gd->manager), NULL);
    if (!manager) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

    free(manager->user_id);
    manager->user_id = NULL;
    status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (is_me(session, manager)) {
        // if this is from me, I should never have received this message, so we ignore it
        status = PEP_STATUS_OK;
        goto pEp_free;
    }

    if (!manager->fpr) {
        status = PEP_KEY_NOT_FOUND;
        goto pEp_free;
    }

    // N.B. This check is sort of a placeholder - this will change once it is possible
    // for the signer to NOT be the manager of the group. For now, we check the claim against
    // the sender and the known database manager against the sender.

    // It would be stupid to lie here, but form and all.. FIXME: Change when signature delivery is
    // implemented as in https://dev.pep.foundation/Engine/GroupEncryption#design - this will no longer
    // be sufficient or entirely correct
    // FIXME - we'll have to check that it matches A sender key, not "THE" sender key.
    // FIXME AGAIN - actually, this is a problem. It could match a GREEN sender key, sure.
    //               but yellow won't do (I guess unless it was once a default?)
    // 1. is manager->fpr the same as the sender key? If not, look for other previous defaults for this user...
    if (strcmp(manager->fpr, msg->_sender_fpr) != 0) {
        // 2. See if there exists a trust entry in the DB for this key and user
        pEp_identity* tmp_ident = identity_dup(manager);
        if (!tmp_ident) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
        free(tmp_ident->fpr);
        tmp_ident->fpr = strdup(msg->_sender_fpr);
        if (!tmp_ident->fpr) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
        tmp_ident->comm_type = PEP_ct_unknown;
        status = get_trust(session, tmp_ident);

        if (status != PEP_STATUS_OK)
            goto pEp_free;

        if (tmp_ident->comm_type < PEP_ct_strong_but_unconfirmed) {
            status = PEP_MESSAGE_IGNORE; // Should this be "ignore" or "OK"?
            goto pEp_free;
        }
    }

    if (strcmp(manager->address, msg->from->address) != 0) {// FIXME: aliases...
        status = PEP_DISTRIBUTION_ILLEGAL_MESSAGE; // FIXME: Do we just ignore it?
        goto pEp_free;
    }

    // Update group identity id
    char* own_id = NULL;
    status = get_default_own_userid(session, &own_id);
    if (status != PEP_STATUS_OK) {
        free(own_id);
        goto pEp_free;
    }
    if (EMPTYSTR(own_id)) {
        status = PEP_NO_OWN_USERID_FOUND;
        goto pEp_free;
    }

    free(group_identity->user_id);

    // Takes ownership
    group_identity->user_id = own_id;
    own_id = NULL; // PREVENT DOUBLE-FREE!

    // Note: at this point, group_identity ownership goes to the group object. pEp_free takes account of this.
    status = retrieve_group_info(session, group_identity, &group);
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    if (!group) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

    status = retrieve_own_membership_info_for_group_and_identity(session, group, own_identity);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    // If none of these are true, then we don't know about it. FIXME: check against above
    // This shouldn't be fatal - "receive group we don't know about? Ignore"
    if (!group->members || !group->members->member || !group->members->member->ident)
        goto pEp_free; // status is PEP_STATUS_OK

    // Ok, so we have a group with this manager and we have received info about it from our own
    // membership info. We've at least been invited.

    // Ok then - let's do this:

    // set group to inactive and our own membership to non-participant
    status = group_dissolve(session, group_identity, manager);

    // Ok, database is set. Now for the keys:

    // Ok, let's ensure we HAVE the key for this group:
    status = find_private_keys(session, group_identity->fpr, &keylist);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!keylist) {
        status = PEP_KEY_NOT_FOUND;
        goto pEp_free;
    }

    // It should have been revoked on message import. Was it?
    bool revoked = false;
    status = key_revoked(session, group_identity->fpr, &revoked);

    if (!revoked) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

pEp_free:
    free_identity(manager);
    free_stringlist(keylist);
    free_identity(tmp_ident);
    if (group)
        free_group(group);
    else
        free_identity(group_identity);

    return status;
}

PEP_STATUS receive_GroupAdopted(PEP_SESSION session, message* msg, PEP_rating rating, GroupAdopted_t* ga) {
    PEP_REQUIRE(session && msg);
    PEP_STATUS status = PEP_STATUS_OK;

    pEp_identity* db_group_ident = NULL;
    char* own_id = NULL;
    pEp_identity* group_identity = NULL;
    pEp_identity* member = NULL;

    if (rating < PEP_rating_reliable)
        return PEP_NO_TRUST; // Find better error

    // Make sure everything's there are enforce exactly one recip
    if (!ga || !msg->to || !msg->to->ident || msg->to->next)
        return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;

    // We will probably always have to do this, but if something changes externally we need this check.
    if (!msg->to->ident->me) {
        status = update_identity(session, msg->to->ident);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    }

    // this will be hard without address aliases
    if (!is_me(session, msg->to->ident)) {
        status = PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
        goto pEp_free;
    }

    // FIXME: is there a check we need to do here?
    //    pEp_identity* own_identity = msg->to->ident;

    group_identity = Identity_to_Struct(&(ga->groupIdentity), NULL);
    if (!group_identity) {
        status = PEP_UNKNOWN_ERROR; // we really don't know why
        goto pEp_free;
    }

    member = Identity_to_Struct(&(ga->member), NULL);
    if (!member) {
        status = PEP_UNKNOWN_ERROR; // we really don't know why
        goto pEp_free;
    }

    status = get_default_own_userid(session, &own_id);
    if (status != PEP_STATUS_OK || EMPTYSTR(own_id)) {
        if (status == PEP_STATUS_OK)
            status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }

    // is this even our group? If not, ignore.
    status = get_identity(session, group_identity->address, own_id, &db_group_ident);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!db_group_ident) {
        status = PEP_CANNOT_FIND_IDENTITY;
        goto pEp_free;
    }

    // There's nothing in the group_identity we care about actually other than the address, so free and replace
    free_identity(group_identity);
    group_identity = db_group_ident;
    db_group_ident = NULL; // prevent double-free!!

    bool is_mine = NULL;
    status = is_group_mine(session, group_identity, &is_mine);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!is_mine) // If it's not my group, I don't care and will ignore it.
        goto pEp_free;

    // is this even someone we invited? If not, ignore.
    bool invited = false;

    // Ok, first off, the user_id will be wrong.
    free(member->user_id);
    member->user_id = NULL;
    status = update_identity(session, member);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    status = is_invited_group_member(session, group_identity, member, &invited);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (!invited)
        goto pEp_free; // Nice try, NSA Bob! But we ignore it.

    // Ok. So. Do we need to check sender's FPR? I think we do.
    // It would be stupid to lie here, but form and all.. FIXME: Change when signature delivery is
    // implemented as in https://dev.pep.foundation/Engine/GroupEncryption#design - this will no longer
    // be sufficient or entirely correct
    if ((strcmp(member->fpr, msg->_sender_fpr) != 0) || (strcmp(member->address, msg->from->address) != 0)) {
        status = PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
        goto pEp_free;
    }

    // Ok, we invited them. Set their status to "joined".
    status = set_membership_status(session, group_identity, member, true);

pEp_free:
    free_identity(db_group_ident);
    free(own_id);
    free_identity(group_identity);
    free_identity(member);

    return status;
}



PEP_STATUS receive_managed_group_message(PEP_SESSION session, message* msg, PEP_rating rating, Distribution_t* dist) {
    PEP_REQUIRE(session && msg && ! EMPTYSTR(msg->_sender_fpr) && dist);

    switch (dist->choice.managedgroup.present) {
        case ManagedGroup_PR_groupInvite:
            return receive_GroupInvite(session, msg, rating, &(dist->choice.managedgroup.choice.groupInvite));
        case ManagedGroup_PR_groupDissolve:
            return receive_GroupDissolve(session, msg, rating, &(dist->choice.managedgroup.choice.groupDissolve));
        case ManagedGroup_PR_groupAdopted:
            return receive_GroupAdopted(session, msg, rating, &(dist->choice.managedgroup.choice.groupAdopted));
            break;
        default:
            return PEP_DISTRIBUTION_ILLEGAL_MESSAGE;
    }
    return PEP_STATUS_OK;
}

PEP_STATUS is_own_group_identity(PEP_SESSION session, pEp_identity* group_identity, bool* is_own) {
    PEP_REQUIRE(session && group_identity
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(group_identity->address));

    *is_own = false;

    pEp_identity* manager = NULL;

    PEP_STATUS status = get_group_manager(session, group_identity, &manager);

    if (status == PEP_STATUS_OK && manager) {
        if (is_me(session, manager))
            *is_own = true;
    }

    free(manager);
    return status;
}


/******************************************************************************************
 * API FUNCTIONS
 ******************************************************************************************/

DYNAMIC_API pEp_member *new_member(pEp_identity *ident) {
    if (!ident)
        return NULL;
    pEp_member* member = (pEp_member*)calloc(1, sizeof(pEp_member));
    member->ident = ident;
    return member;
}

DYNAMIC_API void free_member(pEp_member *member) {
    if (member) {
        free_identity(member->ident);
        free(member);
    }
}

DYNAMIC_API member_list *new_memberlist(pEp_member *member) {
    member_list* retval = (member_list*)(calloc(1, sizeof(member_list)));
    if (!retval)
        return NULL;
    retval->member = member;
    return retval;
}

DYNAMIC_API void free_memberlist(member_list *list) {
    member_list* curr = list;

    while (curr) {
        member_list *next = curr->next;
        free_member(curr->member);
        free(curr);
        curr = next;
    }
}

DYNAMIC_API member_list *memberlist_add(member_list *list, pEp_member *member) {
    if (!list)
        return new_memberlist(member);

    if (!list->member) {
        list->member = member;
        return list;
    }

    member_list* curr = list;
    member_list** last_ptr = NULL;
    while (curr) {
        last_ptr = &(curr->next);
        curr = curr->next;
    }

    *last_ptr = new_memberlist(member);
    return *last_ptr;

}

DYNAMIC_API pEp_group *new_group(
        pEp_identity *group_identity,
        pEp_identity *manager,
        member_list *memberlist
) {
    if (!group_identity)
        return NULL;

    pEp_group* retval = (pEp_group*)calloc(1, sizeof(pEp_group));
    if (!retval)
        return NULL;

    retval->group_identity = group_identity;
    retval->manager = manager;
    retval->members = memberlist;

    return retval;
}

DYNAMIC_API void free_group(pEp_group *group) {
    free_identity(group->group_identity);
    free_identity(group->manager);
    free_memberlist(group->members);
}

static PEP_STATUS _validate_member_ident(PEP_SESSION session, pEp_identity* ident) {
    PEP_REQUIRE(session && ident
                && ! EMPTYSTR(ident->address) && ! EMPTYSTR(ident->username)
                && ! EMPTYSTR(ident->fpr));
    if (_rating(ident->comm_type) < PEP_rating_reliable)
        return PEP_KEY_UNSUITABLE;
    return PEP_STATUS_OK;
}

static PEP_STATUS _validate_member_identities(PEP_SESSION session, identity_list* member_idents) {
    PEP_REQUIRE(session  /* member_idents is allowed to be NULL. */);

    identity_list* curr = member_idents;

    for ( ; curr && curr->ident; curr = curr->next) {
        pEp_identity* the_id = curr->ident;
        if (_validate_member_ident(session, the_id) != PEP_STATUS_OK)
            return PEP_CANNOT_ADD_GROUP_MEMBER;
    }
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS group_create(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        identity_list *member_ident_list,
        pEp_group **group
) {
    PEP_REQUIRE(session && group_identity && manager
                && ! EMPTYSTR(group_identity->address)
                && ! EMPTYSTR(manager->address));

    PEP_STATUS status = _validate_member_identities(session, member_ident_list);
    if (status != PEP_STATUS_OK)
        return status;

    pEp_group* _group = NULL;
    pEp_identity* group_ident_clone = NULL;
    pEp_identity* manager_clone = NULL;
    member_list* memberlist = NULL;


    if (!group_identity->user_id || !is_me(session, group_identity)) {
        char* own_id = NULL;
        status = get_default_own_userid(session, &own_id);
        if (status != PEP_STATUS_OK)
            return status;

        free(group_identity->user_id);
        group_identity->user_id = own_id;
    }

    // We have an address, create a key for the group if needed
    status = myself(session, group_identity);
    if (status != PEP_STATUS_OK)
        return status;

    // Do we already have this group?
    bool already_exists = false;
    status = exists_group(session, group_identity, &already_exists);
    if (already_exists)
        return PEP_GROUP_EXISTS;

    // set it as a group_identity
    status = set_identity_flags(session, group_identity, group_identity->flags | PEP_idf_group_ident);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // ALLOCATIONS BEGIN HERE - after this, stuff has to be freed.

    // from here on out: group_identity still belongs to the caller. So we dup it.
    group_ident_clone = identity_dup(group_identity);
    manager_clone = identity_dup(manager);

    if (!group_ident_clone || !manager_clone) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_error;
    }

    // update the manager ident
    if (is_me(session, manager))
        status = myself(session, manager);
    else
        status = update_identity(session, manager);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    if (manager->flags & PEP_idf_group_ident) {
        status = PEP_ILLEGAL_VALUE;
        goto pEp_error;
    }

    // Ok, we're ready to do DB stuff. Do some allocation:
    memberlist = identity_list_to_memberlist(member_ident_list);
    // FIXME: double-check empty list head in function above
    if (member_ident_list && member_ident_list->ident && !memberlist) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_error;
    }

    // memberlist fully belongs to us and will now go to the group
    // All fields here belong to us; if the group fails, they'll
    // be freed individually in the error block
    _group = new_group(group_ident_clone, manager_clone, memberlist);
    if (!_group) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_error;
    }

    // Before we start doing database stuff, also get current member info (yes, I realise
    // we're traversing the list twice.)
    member_list* curr_member = NULL;
    // Will bail if adding fails.
    for (curr_member = memberlist; curr_member && curr_member->member && curr_member->member->ident && status == PEP_STATUS_OK;
         curr_member = curr_member->next) {

        pEp_identity* member = curr_member->member->ident;

        if (is_me(session, member))
            status = myself(session, member);
        else
            status = update_identity(session, member);

        if (status != PEP_STATUS_OK)
            goto pEp_error; // We can do this because we are BEFORE the start of the transaction!!!
    }

    PEP_SQL_BEGIN_EXCLUSIVE_TRANSACTION();

    status = create_group_entry(session, _group);

    if (status == PEP_STATUS_OK) {
        status = group_enable(session, group_ident_clone);
    }

    if (status == PEP_STATUS_OK) {
        curr_member = NULL;
        // Will bail if adding fails.
        for (curr_member = memberlist; curr_member && curr_member->member && status == PEP_STATUS_OK;
             curr_member = curr_member->next) {
            if (!curr_member->member->ident)
                status = PEP_ILLEGAL_VALUE;
            else {
                pEp_identity *member = curr_member->member->ident;
                if (EMPTYSTR(member->user_id) || EMPTYSTR(member->address)) {
                    status = PEP_ILLEGAL_VALUE;
                } else {
                    status = group_add_member(session, group_ident_clone, member);
                    if (status == PEP_STATUS_OK) {
                        if (is_me(session, member)) {
                            status = add_own_membership_entry(session, group_ident_clone, manager, member);
                            if (status == PEP_STATUS_OK && is_me(session, manager))
                                status = group_join(session, group_ident_clone, member);
                        }
                    }
                }
            }
            if (status != PEP_STATUS_OK)
                break; // will cause rollback and goto pEp_error
        }
    }


    if (status != PEP_STATUS_OK) {
        PEP_SQL_ROLLBACK_TRANSACTION();
        goto pEp_error;
    }
    PEP_SQL_COMMIT_TRANSACTION();

    // Ok, mail em.
    if (is_me(session, manager))
        status = _send_managed_group_message_to_list(session, _group, ManagedGroup_PR_groupInvite);

    if (group)
        *group = _group;
    else
        free_group(_group);

    return status;

pEp_error:
    if (!_group) {
        free_memberlist(memberlist);
        free_identity(group_ident_clone);
        free_identity(manager_clone);
    }
    else
        free_group(_group);
    *group = NULL;
    return status;
}

DYNAMIC_API PEP_STATUS group_join(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *as_member
) {
    PEP_REQUIRE(session && group_identity && as_member
                && ! EMPTYSTR(group_identity->user_id)
                && ! EMPTYSTR(as_member->user_id)
                && ! EMPTYSTR(group_identity->address)
                && ! EMPTYSTR(as_member->address));

    // get our status, if there is any
    bool am_member = false;
    // FIXME: differentiate between no records and DB error in call
    PEP_STATUS status = get_own_membership_status(session, group_identity, as_member, &am_member);

    if (status != PEP_STATUS_OK)
        return status;

    if (am_member)
        return PEP_STATUS_OK; // FIXME: ask Volker if there is a reason to do this, like the message wasn't sent

    // Ok, group invite exists. Do it.
    status = send_GroupAdopted(session, group_identity, as_member);
    if (status != PEP_STATUS_OK)
        return status;

    status = _set_own_status_joined(session, group_identity, as_member);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS group_dissolve(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager
) {
    PEP_REQUIRE(session && group_identity && manager);

    pEp_identity* stored_manager = NULL;
    member_list* list = NULL;
    pEp_group* group = NULL;

    bool exists = false;
    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    // Ok, do we have the right manager? If not, don't do it.
    status = get_group_manager(session, group_identity, &stored_manager);
    if (status != PEP_STATUS_OK)
        return status;

    if (!stored_manager)
        return PEP_OUT_OF_MEMORY;

    if (!stored_manager->user_id || !stored_manager->address) {
        status = PEP_UNKNOWN_DB_ERROR;
        goto pEp_free;
    }

    if ((strcmp(stored_manager->user_id, manager->user_id) != 0) ||
        (strcmp(stored_manager->address, manager->address) != 0)) {
        status = PEP_CANNOT_DISABLE_GROUP;
        goto pEp_free;
    }

    status = _set_group_as_disabled(session, group_identity);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    // If I'm the manager, then I have to send out the dissolution stuff and deactivate
    if (is_me(session, manager)) {
        status = revoke_key(session, group_identity->fpr, NULL);
        if (status != PEP_STATUS_OK)
            goto pEp_free;

        // You'd better get all the group info here
        status = retrieve_active_member_list(session, group_identity, &list);
        if (status != PEP_STATUS_OK)
            return status;

        group = new_group(group_identity, manager, list);
        if (!group) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }

        status = _send_managed_group_message_to_list(session, group, ManagedGroup_PR_groupDissolve);
        if (status != PEP_STATUS_OK)
            goto pEp_free; // fixme ??

        // deactivate members
        member_list* memb = group->members;

        while (memb && memb->member && memb->member->ident) {
            pEp_identity* memb_ident = memb->member->ident;
            if (EMPTYSTR(memb_ident->user_id) || EMPTYSTR(memb_ident->address)) {
                status = PEP_UNKNOWN_ERROR;
                goto pEp_free;
            }
            status = set_membership_status(session, group_identity, memb->member->ident, false);
            memb = memb->next;
        }
    }
    else {
        // I'm not the manager. So I need to find the identities I have that
        // know about or have joined this group and tell them the fun is over
        member_list* my_group_idents = NULL;
        status = _set_group_as_disabled(session, group_identity);
        if (status != PEP_STATUS_OK)
            goto pEp_free;

        // Ok, group is now not usable. Let's get our membership straight.
        status = _retrieve_own_membership_info_for_group(session, group_identity, &my_group_idents);

        if (status != PEP_STATUS_OK)
            goto pEp_free;

        member_list* curr_member = my_group_idents;

        while (curr_member) {
            if (!curr_member->member)
                break; // ??
            pEp_identity* ident = curr_member->member->ident;
            if (!ident)
                break; // er... this should probably be an error, but given how we do lists, it's acceptable
            status = _set_leave_group_status(session, group_identity, ident);
            if (status != PEP_STATUS_OK)
                goto pEp_free;

            curr_member = curr_member->next;
        }
    }

pEp_free:
    free_identity(stored_manager);
    free_memberlist(list);

    if (group) {
        // We don't own the group_ident or manager that comes in here, so we need to set them to NULL.
        group->group_identity = NULL;
        group->manager = NULL;
        group->members = NULL; // already freed
        free_group(group);
    }
    return status;

}

DYNAMIC_API PEP_STATUS group_invite_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
) {
    PEP_REQUIRE(session && group_identity && group_member);

    PEP_STATUS status = PEP_STATUS_OK;
    pEp_identity* manager = NULL;
    char* data = NULL;
    size_t size = 0;
    char* key_material_priv = NULL;
    size_t key_material_size = 0;
    bloblist_t* key_attachment = NULL;

    if (_validate_member_ident(session, group_member) != PEP_STATUS_OK)
        return PEP_CANNOT_ADD_GROUP_MEMBER;

    status = get_group_manager(session, group_identity, &manager);
    if (status != PEP_STATUS_OK)
        return status;
    if (!manager)
        return PEP_UNKNOWN_ERROR;

    // Trying to be sneaky
    if (!is_me(session, manager))
        return PEP_ILLEGAL_VALUE;

    status = myself(session, manager);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    status = group_add_member(session, group_identity, group_member);
    if (status == PEP_STATUS_OK) {
        if (is_me(session, group_member)) {
            status = add_own_membership_entry(session, group_identity, manager, group_member);
            if (status == PEP_STATUS_OK)
                status = group_join(session, group_identity, group_member);
            else {
                status = PEP_UNKNOWN_ERROR;
                goto pEp_free;
            }
        }
        else {

            status = _build_managed_group_message_payload(session, group_identity,
                                                          manager, &data, &size,
                                                          ManagedGroup_PR_groupInvite);

            if (status != PEP_STATUS_OK)
                goto pEp_free;

            // Let's also get the private key for the group we want to distribute
            status = export_secret_key(session, group_identity->fpr, &key_material_priv, &key_material_size);
            if (status != PEP_STATUS_OK)
                return status;
            if (key_material_size == 0 || !key_material_priv)
                return PEP_UNKNOWN_ERROR;

            bloblist_t* key_attachment = new_bloblist(key_material_priv, key_material_size,
                                                      "application/pgp-keys",
                                                      "file://pEpkey_group_priv.asc");

            if (key_attachment == NULL) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }
            key_material_priv = NULL; // belongs to attachment now

            PEP_rating recip_rating;
            status = identity_rating(session, group_member, &recip_rating);
            if (status == PEP_STATUS_OK) {
                if (recip_rating < PEP_rating_reliable) {
                    status = PEP_CANNOT_ADD_GROUP_MEMBER;
                    goto pEp_free;
                }

                // encrypt and send this baby and get out
                // FIXME: mem? - it gets freed IF all goes well, but if not?
                status = _create_and_send_managed_group_message(session, manager, group_member, data, size,
                                                                key_attachment);
                // FIXME
                data = NULL; // avoid double-free - check this
            }
        }
    }

pEp_free:
    free_identity(manager);
    free(data);
    if (!key_attachment)
        free(key_material_priv);
    else
        free_bloblist(key_attachment);

    return status;
}

DYNAMIC_API PEP_STATUS group_remove_member(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *group_member
) {
    PEP_REQUIRE(session);

    bool exists = false;
    pEp_identity* manager = NULL;
    char* group_key_to_revoke = NULL;

    PEP_STATUS status = exists_group(session, group_identity, &exists);
    if (status != PEP_STATUS_OK)
        return status;

    if (!exists)
        return PEP_GROUP_NOT_FOUND;

    // Make sure this person was ever invited to the group
    bool is_invited = false;
    status = is_invited_group_member(session, group_identity, group_member, &is_invited);
    if (!is_invited)
        return PEP_NO_MEMBERSHIP_STATUS_FOUND;

    status = _remove_member_from_group(session, group_identity, group_member);

    if (status != PEP_STATUS_OK)
        return status;

    status = get_group_manager(session, group_identity, &manager);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
    else if (!manager)
        return PEP_UNKNOWN_ERROR; // nothing to deallocate at the moment

    // We dup this because I'm not sure about ownership on the group identity fpr in key reset.
    // FIXME: check this against key reset and revise if necessarily
    group_key_to_revoke = strdup(group_identity->fpr);
    if (!group_key_to_revoke) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }

    status = key_reset(session, group_key_to_revoke, group_identity);


pEp_free:
    free(group_key_to_revoke);
    free_identity(manager);
    return status;
}

DYNAMIC_API PEP_STATUS group_rating(
        PEP_SESSION session,
        pEp_identity *group_identity,
        pEp_identity *manager,
        PEP_rating *rating
) {

    PEP_STATUS status = PEP_STATUS_OK;
    if (!is_me(session, manager))
        return identity_rating(session, group_identity, rating);

    member_list* active_members = NULL;

    status = retrieve_active_member_list(session, group_identity, &active_members);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    PEP_rating _rating = PEP_rating_fully_anonymous;

    if (active_members) {
        member_list* curr;

        for (curr = active_members; curr; curr = curr->next) {
            if (!(curr->member) && curr->next != NULL) {
                status = PEP_ILLEGAL_VALUE;
                goto pEp_free;
            }

            if (!(curr->member->ident)) {
                status = PEP_ILLEGAL_VALUE;
                goto pEp_free;
            }

            PEP_rating tmp_rating = PEP_rating_undefined;

            status = identity_rating(session, curr->member->ident, &tmp_rating);
            if (status != PEP_STATUS_OK)
                goto pEp_free;

            if (tmp_rating < _rating)
                _rating = tmp_rating;
        }
    }
    else {
        _rating = PEP_rating_undefined; // ??? or group_identity? I dunno.
    }

    *rating = _rating;

    status = PEP_STATUS_OK;

pEp_free:
    free_memberlist(active_members);
    return status;
}

PEP_STATUS is_active_group_member(PEP_SESSION session, pEp_identity* group_identity,
                                  pEp_identity* member, bool* is_active) {
    PEP_REQUIRE(session && is_active
                && group_identity
                && ! EMPTYSTR(group_identity->user_id) && ! EMPTYSTR(group_identity->address)
                && member
                && ! EMPTYSTR(member->user_id) && ! EMPTYSTR(member->address));

    PEP_STATUS status = PEP_STATUS_OK;

    sql_reset_and_clear_bindings(session->is_active_group_member);

    sqlite3_bind_text(session->is_active_group_member, 1, group_identity->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_active_group_member, 2, group_identity->address, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_active_group_member, 3, member->user_id, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(session->is_active_group_member, 4, member->address, -1,
                      SQLITE_STATIC);

    int result = pEp_sqlite3_step_nonbusy(session, session->is_active_group_member);

    if (result == SQLITE_ROW)
        *is_active = sqlite3_column_int(session->is_active_group_member, 0);
    else if (result == SQLITE_DONE)
        status = PEP_NO_MEMBERSHIP_STATUS_FOUND;
    else
        status = PEP_UNKNOWN_DB_ERROR;

    sql_reset_and_clear_bindings(session->is_active_group_member);

    return status;
}
