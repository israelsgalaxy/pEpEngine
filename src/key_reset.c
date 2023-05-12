/**
 * @file    key_reset.c
 * @brief   Implementation of functions for resetting partner key defaults and trust and mistrusting and revoking own keys, 
 *          as well as of functions to inform partners of own revoked keys and their replacements
 * @license GNU General Public License 3.0 - see LICENSE.txt
 */

/* In this compilation unit very few functions take a session as a
   paramter; this prevents me from using the new debugging and logging
   functionalities.  I wonder if we should systematically add a session
   paramter to our functions, even when not needed, just for this.
   --positron, 2022-10 */

#include "pEp_internal.h"
#include "dynamic_api.h"
#include "message_api.h"
#include "key_reset.h"
#include "key_reset_internal.h"

#include "group.h"
#include "group_internal.h"
#include "distribution_codec.h"
#include "map_asn1.h"
#include "keymanagement.h"
#include "baseprotocol.h"
#include "../asn.1/Distribution.h"
#include "Sync_impl.h" // this seems... bad

#include <string.h>
#include <stdlib.h>

// FIXME: these should be taken from sync/Distribution.fsm

#define KEY_RESET_MAJOR_VERSION 1L
#define KEY_RESET_MINOR_VERSION 0L

/**
 *  @internal
 *  
 *  <!--       _generate_reset_structs()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]        session               session handle
 *  @param[in]        *reset_ident          identity whose key is being reset
 *  @param[in]        *old_fpr              key which is being reset for this identity
 *  @param[in]        *new_fpr              replacement key for this key for this identity
 *  @param[in,out]    **key_attachments     bloblist_t
 *  @param[in,out]    **command_list        keyreset_command_list
 *  @param[in]        include_secret        bool
 *
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE       illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval any other value on error
 *
 *  @ownership  reset_ident, old_fpr, new_fpr remain with the caller
 *  

  */
static PEP_STATUS _generate_reset_structs(PEP_SESSION session,
                                          const pEp_identity* reset_ident,
                                          const char* old_fpr,
                                          const char* new_fpr,
                                          bloblist_t** key_attachments,
                                          keyreset_command_list** command_list,
                                          bool include_secret) {
    PEP_REQUIRE(session && reset_ident && ! EMPTYSTR(old_fpr)
                && ! EMPTYSTR(new_fpr) && key_attachments && command_list);
    
    // Ok, generate payload here...
    pEp_identity* outgoing_ident = identity_dup(reset_ident);
    if (!outgoing_ident)
        return PEP_OUT_OF_MEMORY;
    free(outgoing_ident->fpr);
    outgoing_ident->fpr = strdup(old_fpr);
    if (!outgoing_ident->fpr)
        return PEP_OUT_OF_MEMORY;
        
    keyreset_command* kr_command = new_keyreset_command(outgoing_ident, new_fpr);
    if (!kr_command)
        return PEP_OUT_OF_MEMORY;
    if (!*command_list)
        *command_list = new_keyreset_command_list(kr_command);
    else
        if (keyreset_command_list_add(*command_list, kr_command) == NULL)
            return PEP_OUT_OF_MEMORY;
    
    bloblist_t* keys = NULL;
    
    char* key_material_old = NULL;
    char* key_material_new = NULL;   
    char* key_material_priv = NULL;
     
    size_t datasize = 0;
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!include_secret) { // This isn't to own recips, so shipping the rev'd key is OK. Own keys are revoked on each device.
        status = export_key(session, old_fpr, &key_material_old, &datasize);

        // Shouldn't happen, but we can't make presumptions about crypto engine
        if (PASS_ERROR(status))
            goto pEp_error;
            
        if (datasize > 0 && key_material_old) {         
            if (status != PEP_STATUS_OK)
                goto pEp_error;

            if (!keys)
                keys = new_bloblist(key_material_old, datasize, 
                                                "application/pgp-keys",
                                                "file://pEpkey_old.asc");
            else                                    
                bloblist_add(keys, key_material_old, datasize, "application/pgp-keys",
                                                                       "file://pEpkey_old.asc");
        }
        datasize = 0;
    }                                                                  
    status = export_key(session, new_fpr, &key_material_new, &datasize);
    // Shouldn't happen, but we can't make presumptions about crypto engine
    if (PASS_ERROR(status))
        goto pEp_error;

    if (datasize > 0 && key_material_new) {         
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        if (!keys)
            keys = new_bloblist(key_material_new, datasize, 
                                            "application/pgp-keys",
                                            "file://pEpkey_new_pub.asc");
        else                                    
            bloblist_add(keys, key_material_new, datasize, "application/pgp-keys", "file://pEpkey_new_pub.asc");
                        
        datasize = 0;    
        if (include_secret) {
            status = export_secret_key(session, new_fpr, &key_material_priv, &datasize);    
            if (status != PEP_STATUS_OK) // includes PASS_ERROR
                goto pEp_error;
            if (datasize > 0 && key_material_priv) {
                bloblist_add(keys, key_material_priv, datasize, "application/pgp-keys",
                                                                            "file://pEpkey_priv.asc");
            }                                                      
        }    
    }
    if (keys) {
        if (*key_attachments)
            bloblist_join(*key_attachments, keys);
        else
            *key_attachments = keys;
    }        
    return status;

pEp_error:
    free(key_material_old);
    free(key_material_new);
    free(key_material_priv);
    free_bloblist(keys);
    return status;    
}

// For multiple idents under a single key
// idents contain new fprs
/**
 *  @internal
 *  
 *  <!--       generate_own_commandlist_msg()       -->
 *  
 *  @brief       generate a key reset commandlist message for an own identity - either a device group or
 *               group identity (group encryption)
 *  
 *  @param[in]    session           PEP_SESSION
 *  @param[in]    *reset_idents     identity_list
 *  @param[in]    alt_sender        in case sender needs to be different (group identity needs manager, for example)
 *  @param[in]    *old_fpr          constchar
 *  @param[in]    **dst             message
 *
 *  @retval PEP_STATUS_OK
 *  @retval any other value on error
 *
 *  @ownership
 *  
 */
PEP_STATUS generate_own_commandlist_msg(PEP_SESSION session,
                                        identity_list* reset_idents,
                                        bool ignore_ungrouped,
                                        pEp_identity* alt_sender,
                                        pEp_identity* alt_recip,
                                        const char* old_fpr,
                                        message** dst) {
    PEP_STATUS status = PEP_STATUS_OK;
    message* msg = NULL;                                                
    identity_list* list_curr = NULL;
    keyreset_command_list* kr_commands = NULL;
    bloblist_t* key_attachments = NULL;
    pEp_identity* from = NULL;
    pEp_identity* to = NULL;

    char* payload = NULL;
    size_t size = 0;

    for (list_curr = reset_idents ; list_curr && list_curr->ident; list_curr = list_curr->next) {
        pEp_identity* curr_ident = list_curr->ident;
        
        if (curr_ident->flags & (PEP_idf_devicegroup | PEP_idf_group_ident)) {

            // All of these items belong to us after the call anyway
            PEP_STATUS status = _generate_reset_structs(session,
                                                        curr_ident,
                                                        old_fpr,
                                                        curr_ident->fpr,
                                                        &key_attachments,
                                                        &kr_commands,
                                                        true);
            if (status != PEP_STATUS_OK)
                goto pEp_error; 
            if (!key_attachments || !kr_commands) {
                status = PEP_UNKNOWN_ERROR;
                goto pEp_error;
            }    
        }        
    }
    
    if (!kr_commands) {
        // There was nothing for us to send to self - we could be ungrouped,
        // etc
        return PEP_STATUS_OK;
    }

    status = key_reset_commands_to_PER(session, kr_commands, &payload, &size);
    if (status != PEP_STATUS_OK)
        goto pEp_error;
        
    // From and to our first ident - this only goes to us.
    from = identity_dup(alt_sender ? alt_sender : reset_idents->ident);
    to = identity_dup(alt_recip ? alt_recip : from);
    status = base_prepare_message(session, from, to,
                                  BASE_DISTRIBUTION, payload, size, NULL,
                                  &msg);

    if (status != PEP_STATUS_OK)
        goto pEp_error;
    
    if (!msg) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_error;
    }    
    if (!msg->attachments) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }    
    
    if (!bloblist_join(msg->attachments, key_attachments)) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_error;
    }    

    if (msg)
        *dst = msg;

    free_keyreset_command_list(kr_commands);
        
    return status;
    
pEp_error:
    if (!msg) {
        free_bloblist(key_attachments);
        free_identity(from);
        free_identity(to);
        free(payload);
    }
    else
        free_message(msg);

    free_keyreset_command_list(kr_commands);

    return status;
}

/**
 *  @internal
 *  
 *  <!--       _generate_keyreset_command_message()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    session       session handle
 *  @param[in]    *from_ident   pEp_identity
 *  @param[in]    *to_ident     pEp_identity
 *  @param[in]    *old_fpr      constchar
 *  @param[in]    *new_fpr      constchar
 *  @param[in]    is_private    bool
 *  @param[in]    **dst         message
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_OUT_OF_MEMORY   out of memory
 *  @retval any other value on error
 */
static PEP_STATUS _generate_keyreset_command_message(PEP_SESSION session,
                                                     const pEp_identity* from_ident,
                                                     const pEp_identity* to_ident,
                                                     const char* old_fpr,
                                                     const char* new_fpr,
                                                     bool is_private,
                                                     message** dst) {
    PEP_REQUIRE(session && from_ident && ! EMPTYSTR(old_fpr)
                && ! EMPTYSTR(new_fpr) && dst
                && is_me(session, from_ident));

    PEP_STATUS status = PEP_STATUS_OK;
        
    *dst = NULL;
        
    message* msg = NULL;
    
    // Ok, generate payload here...
    pEp_identity* outgoing_ident = identity_dup(from_ident);
    if (!outgoing_ident)
        return PEP_OUT_OF_MEMORY;
    free(outgoing_ident->fpr);
    outgoing_ident->fpr = strdup(old_fpr);
    if (!outgoing_ident->fpr)
        return PEP_OUT_OF_MEMORY;
        
    keyreset_command_list* kr_list = NULL;
    bloblist_t* key_attachments = NULL;
            
    // Check memory        
    status = _generate_reset_structs(session,
                                     outgoing_ident,
                                     old_fpr,
                                     new_fpr,
                                     &key_attachments,
                                     &kr_list,
                                     is_private);
                                     
    // N.B. command list and key attachments are freed by
    //      _generate_reset_structs when status is not OK                                
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!key_attachments || !kr_list)
        return PEP_UNKNOWN_ERROR;
        
    char* payload = NULL;
    size_t size = 0;
    status = key_reset_commands_to_PER(session, kr_list, &payload, &size);
    if (status != PEP_STATUS_OK)
        return status;
        
    status = base_prepare_message(session, outgoing_ident, to_ident,
                                  BASE_DISTRIBUTION, payload, size, NULL,
                                  &msg);
                                  
    if (status != PEP_STATUS_OK) {
        free(msg);
        return status;
    }    
    if (!msg)
        return PEP_OUT_OF_MEMORY;
        
    if (!msg->attachments) {
        free(msg);
        return PEP_UNKNOWN_ERROR;
    }    
    
    if (msg)
        *dst = msg;
    return status;
        
}

PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* from_addr,
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted)
{
    PEP_REQUIRE(session
                && ! EMPTYSTR(from_addr) && ! EMPTYSTR(user_id)
                && ! EMPTYSTR(revoked_fpr)
                && contacted);
    
    *contacted = false;
                    
    char* alias_default = NULL;
    
    PEP_STATUS status = get_userid_alias_default(session, user_id, &alias_default);
    
    if (status == PEP_CANNOT_FIND_ALIAS || EMPTYSTR(alias_default)) {
        free(alias_default);
        alias_default = strdup(user_id);
    }
    
    sql_reset_and_clear_bindings(session->was_id_for_revoke_contacted);
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 1, revoked_fpr, -1,
            SQLITE_STATIC);
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 2, from_addr, -1,
            SQLITE_STATIC);        
    sqlite3_bind_text(session->was_id_for_revoke_contacted, 3, user_id, -1,
            SQLITE_STATIC);        
    int result = pEp_sqlite3_step_nonbusy(session, session->was_id_for_revoke_contacted);
    switch (result) {
        case SQLITE_ROW: {
            *contacted = (sqlite3_column_int(session->was_id_for_revoke_contacted, 0) != 0);
            break;
        }
        default:
            sql_reset_and_clear_bindings(session->was_id_for_revoke_contacted);
            free(alias_default);
            return PEP_UNKNOWN_DB_ERROR;
    }

    // positron: is alias_default leaked when we arrive here?  I strongly suspect it is.

    sql_reset_and_clear_bindings(session->was_id_for_revoke_contacted);
    return PEP_STATUS_OK;
}

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* own_address,
        const char* revoke_fpr,
        const char* contact_id
    )
{
    PEP_REQUIRE(session && ! EMPTYSTR(own_address) && ! EMPTYSTR(revoke_fpr)
                && ! EMPTYSTR(contact_id));

    PEP_STATUS status = PEP_STATUS_OK;
    sql_reset_and_clear_bindings(session->set_revoke_contact_as_notified);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 1, revoke_fpr, -1, 
            SQLITE_STATIC);
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 2, own_address, -1, 
            SQLITE_STATIC);            
    sqlite3_bind_text(session->set_revoke_contact_as_notified, 3, contact_id, -1,
            SQLITE_STATIC);

    int result;
    
    result = pEp_sqlite3_step_nonbusy(session, session->set_revoke_contact_as_notified);
    switch (result) {
        case SQLITE_DONE:
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_DB_ERROR;
    }
    
    sql_reset_and_clear_bindings(session->set_revoke_contact_as_notified);
    return status;    
}

// FIXME: fpr ownership
PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg) {
    PEP_REQUIRE(session && reset_msg && ! EMPTYSTR(reset_msg->_sender_fpr));

    PEP_STATUS status = PEP_STATUS_OK;

    stringlist_t* keylist = NULL;
    
    char* sender_fpr = reset_msg->_sender_fpr;

    bool revoked = false;

    // Check to see if sender fpr is revoked already - if this was 
    // from us, we won't have done it yet for obvious reasons (i.e. 
    // we need to verify it's from us before we accept someone telling
    // us to reset our private key), and if this was from someone else,
    // a key reset message will be signed by their new key, because 
    // we presume the old one was compromised (and we remove trust from 
    // the replacement key until verified)
    status = key_revoked(session, sender_fpr, &revoked); 
    
    if (status != PEP_STATUS_OK)
        return status;

    // Bail if *sender fpr* revoked or mistrusted (i.e. red channel)
    if (revoked) {
        return PEP_ILLEGAL_VALUE; // could be an attack            
    }
    else {
        bool mistrusted = false;
        status = is_mistrusted_key(session, sender_fpr, &mistrusted);
        
        if (status != PEP_STATUS_OK)
            return status;
        
        if (mistrusted)
            return PEP_ILLEGAL_VALUE;
    }

    
    // Parse reset message
    pEp_identity* sender_id = reset_msg->from;

    if (!sender_id)
        return PEP_MALFORMED_KEY_RESET_MSG;

    if (is_me(session, sender_id)) {
        // first off, we need to make sure we're up-to-date
        status = myself(session, sender_id);
    }
    else {    
        status = update_identity(session, sender_id);
        if (EMPTYSTR(sender_id->user_id))
            return PEP_UNKNOWN_ERROR;
    }
    if (status != PEP_STATUS_OK) // Do we need to be more specific??
        return status;


    bool sender_own_key = false;
    bool from_me = is_me(session, sender_id);
    
    if (from_me) {
        // Do own-reset-checks
        status = is_own_key(session, sender_fpr, &sender_own_key);
        
        if (status != PEP_STATUS_OK)
            return status;
        
        // Should we mistrust the sender_fpr here??
        if (!sender_own_key) 
            return PEP_ILLEGAL_VALUE; // actually, this is an attack                
        
        // Make sure it's a TRUSTED own key
        char* keyholder = sender_id->fpr;
        
        sender_id->fpr = sender_fpr;                     
        status = get_trust(session, sender_id);
        sender_id->fpr = keyholder;
            
        if (sender_id->comm_type < PEP_ct_pEp)
            return PEP_ILLEGAL_VALUE;
    }
        
    status = PEP_STATUS_OK;
    char* old_fpr = NULL;
    char* new_fpr = NULL;
    
    size_t size = 0;
    const char* payload = NULL;

    char* not_used_fpr = NULL;
    status = base_extract_message(session,
                                  reset_msg,
                                  BASE_DISTRIBUTION,
                                  &size,
                                  &payload,
                                  &not_used_fpr);
                                  
    if (status != PEP_STATUS_OK)
        return status;
        
    if (!payload || size == 0)
        return PEP_MALFORMED_KEY_RESET_MSG;
        
    keyreset_command_list* resets = NULL; 
    
    status = PER_to_key_reset_commands(session, payload, size, &resets);

    if (status != PEP_STATUS_OK)
        return status;
        
    if (!resets)
        return PEP_MALFORMED_KEY_RESET_MSG;

    keyreset_command_list* curr_cl = resets;

    stringpair_list_t* rev_pairs = NULL;
    
    // Ok, go through the list of reset commands. Right now, this 
    // is actually only one, but could be more later.
    for ( ; curr_cl && curr_cl->command; curr_cl = curr_cl->next) {    
        keyreset_command* curr_cmd = curr_cl->command;
        if (!curr_cmd || !curr_cmd->ident || EMPTYSTR(curr_cmd->ident->fpr) ||
            EMPTYSTR(curr_cmd->ident->address)) {
            return PEP_MALFORMED_KEY_RESET_MSG;        
        }
        pEp_identity* curr_ident = curr_cmd->ident;


        old_fpr = curr_ident->fpr;
        new_fpr = strdup(curr_cmd->new_key);

        // Ok, we have to do this earlier now because we need group ident info

        // We need to update the identity to get the user_id
        curr_ident->fpr = NULL; // ensure old_fpr is preserved
        free(curr_ident->user_id);
        curr_ident->user_id = NULL;
        status = update_identity(session, curr_ident); // Won't gen key, so safe
        if (status != PEP_STATUS_OK && status != PEP_GET_KEY_FAILED)
            return status;

        bool is_group_identity = curr_ident->flags & PEP_idf_group_ident; // sender_own_key will be false
        // If it's a group ident (that we are a member of), let's make sure the manager sent it
        if (is_group_identity) {
            pEp_identity* manager = NULL;
            status = get_group_manager(session, curr_ident, &manager);
            if (status != PEP_STATUS_OK)
                goto pEp_free;
            if (!manager) {
                status = PEP_KEY_NOT_RESET;
                goto pEp_free;
            }
            if (strcmp(manager->address, reset_msg->from->address) != 0 ||
                strcmp(manager->user_id, reset_msg->from->user_id) != 0) {
                status = PEP_KEY_NOT_RESET;
                goto pEp_free;
            }
        }

        bool is_old_own = false;
        // if the SENDER key is our key and the old one is revoked, we skip it.
        // Sorry, them's the rules/
        if (sender_own_key) {
            status = is_own_key(session, old_fpr, &is_old_own);
            if (is_old_own) {
                bool old_revoked = false;
                status = key_revoked(session, old_fpr, &old_revoked);
                if (old_revoked)
                    continue;
            }
        }

        // Make sure that this key is at least one we associate 
        // with the sender. FIXME: check key election interaction
        // N.B. If we ever allow ourselves to send resets to ourselves
        // for not-own stuff, this will have to be revised
        status = find_keys(session, new_fpr, &keylist);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
        if (!keylist) {
            status = PEP_MALFORMED_KEY_RESET_MSG;
            goto pEp_free;
        }

        if (is_group_identity) {
            bool has_private = false;
            status = contains_priv_key(session, new_fpr, &has_private);
            if (status != PEP_STATUS_OK)
                goto pEp_free;
            if (!has_private) {
                status = PEP_KEY_NOT_RESET;
                goto pEp_free;
            }
        }

        // Ok, now check the old fpr to see if we have an entry for it
        // temp fpr set for function call
        curr_ident->fpr = old_fpr;
        status = get_trust(session, curr_ident);
        if (status != PEP_STATUS_OK)
            return status;
        
        PEP_comm_type ct_result = curr_ident->comm_type;

        // Basically, see if fpr is even in the database
        // for this user - we'll get PEP_ct_unknown if it isn't
        if (ct_result == PEP_ct_unknown)
            return PEP_KEY_NOT_RESET;
        
        // Alright, so we have a key to reset. Good.
        
        // If this is a non-own user, for NOW, we presume key reset 
        // by email for non-own keys is ONLY in case of revoke-and-replace. 
        // This means we have, at a *minimum*, an object that once 
        // required the initial private key in order to replace that key 
        // with another.
        //
        // The limitations on what this guarantees are known - this does 
        // not prevent, for example, replay attacks from someone with 
        // access to the original revocation cert are possible if they 
        // get to us before we receive this object from the original sender.
        // The best we can do in this case is to NOT trust the new key.
        // It will be used by default, but if the original was trusted,
        // the rating will visibly change for the sender, and even if it was 
        // not, if we do use it, the sender can report unreadable mails to us 
        // and detect it that way. FIXME: We may need to have some kind 
        // of even alert the user when such a change occurs for their contacts
        //
        // If this is from US, we already made sure that the sender_fpr 
        // was a valid own key, so we don't consider it here.
        if (!from_me) {
            revoked = false;
            status = key_revoked(session, old_fpr, &revoked); 

            if (!revoked)
                return PEP_KEY_NOT_RESET;            

            // Also don't let someone change the replacement fpr 
            // if the replacement fpr was also revoked - we really need 
            // to detect that something fishy is going on at this point
            // FIXME: ensure that PEP_KEY_NOT_RESET responses to 
            // automated key reset functions are propagated upward - 
            // app should be made aware if someone is trying to reset someone 
            // else's key and it's failing for some reason.
            revoked = false;
            status = key_revoked(session, new_fpr, &revoked); 

            if (revoked)
                return PEP_KEY_NOT_RESET;                        
        }
        
        // Hooray! We apparently now are dealing with keys 
        // belonging to the user from a message at least marginally
        // from the user
        if (!sender_own_key && !is_group_identity)   {
            // Clear all info (ALSO REMOVES OLD KEY RIGHT NOW!!!)            
            status = key_reset(session, old_fpr, curr_ident);
            if (status != PEP_STATUS_OK)
                return status;
                                
            // Make new key the default    
            curr_ident->fpr = new_fpr;
    
            // Whether new_key is NULL or not, if this key is equal to the current user default, we 
            // replace it.
            status = replace_main_user_fpr_if_equal(session, curr_ident->user_id, 
                                                    new_fpr, old_fpr);                    

            if (status != PEP_STATUS_OK)
                return status;
                
            // This only sets as the default, does NOT TRUST IN ANY WAY
            PEP_comm_type new_key_rating = PEP_ct_unknown;
            
            // No key is ever returned as "confirmed" from here - it's based on raw key
            status = get_key_rating(session, new_fpr, &new_key_rating);
            if (status != PEP_STATUS_OK)
                return status;

            if (new_key_rating >= PEP_ct_strong_but_unconfirmed) {
                bool is_pEp = false;
                status = is_pEp_user(session, curr_ident, &is_pEp);
                if (is_pEp)
                    curr_ident->comm_type = PEP_ct_pEp_unconfirmed;
                else    
                    curr_ident->comm_type = new_key_rating & (~PEP_ct_confirmed);
            }
            else
                curr_ident->comm_type = new_key_rating;
                
            status = set_identity(session, curr_ident);  
            if (status != PEP_STATUS_OK)
                goto pEp_free; 
        }    
        else {

            // FIXME: this also applies to group identities, not just device groups!

            // set new key as the default for this identity
            // N.B. If for some reason this is only a pubkey,
            // then so be it - but we need to double-check to 
            // ensure that in this case, we end up with a private one,
            // so talk to vb about this.
            
            // Make new key the default    
            
            // This is REQUIRED for set_own_key (see doc)
            curr_ident->fpr = NULL;
            
            status = set_own_key(session, curr_ident, new_fpr);
            
            if (status != PEP_STATUS_OK)
                return status;

            // Whether new_key is NULL or not, if this key is equal to the current user default, we 
            // replace it.
            status = replace_main_user_fpr_if_equal(session, curr_ident->user_id, 
                                                    new_fpr, old_fpr);                    

            if (status != PEP_STATUS_OK)
                return status;            
                
            status = myself(session, curr_ident);

            if (status != PEP_STATUS_OK)
                return status;            

            char* old_copy = NULL;
            char* new_copy = NULL;
            old_copy = strdup(old_fpr);
            new_copy = strdup(new_fpr);
            if (!old_copy || !new_copy)
                return PEP_OUT_OF_MEMORY;
                                

            stringpair_t* revp = new_stringpair(old_copy, new_copy);                
            if (!rev_pairs) {
                rev_pairs = new_stringpair_list(revp);
                if (!rev_pairs)
                    return PEP_OUT_OF_MEMORY;
            }
            else    
                stringpair_list_add(rev_pairs, revp);
                            
        }    
        
        old_fpr = NULL;
        free(new_fpr);
        new_fpr = NULL;    
    }

    // actually revoke - list only exists with own keys
    stringpair_list_t* curr_rev_pair = rev_pairs;
    while (curr_rev_pair && curr_rev_pair->value) {
        char* rev_key = curr_rev_pair->value->key;
        char* new_key = curr_rev_pair->value->value;
            
        if (EMPTYSTR(rev_key) || EMPTYSTR(new_key))
            return PEP_UNKNOWN_ERROR;
        bool revoked = false;
        status = key_revoked(session, rev_key, &revoked);
        if (!revoked) {
            // key reset on old key
            status = revoke_key(session, rev_key, NULL);

            if (status != PEP_STATUS_OK)
                goto pEp_free;    
        }
        // N.B. This sort of sucks because we overwrite this every time.
        // But this case is infrequent and we don't rely on the binding.

        if (status == PEP_STATUS_OK) 
            status = set_revoked(session, rev_key, new_key, time(NULL));            

        if (status != PEP_STATUS_OK)
            goto pEp_free;      
                  
        curr_rev_pair = curr_rev_pair->next;    
    }


pEp_free:    
    free_stringlist(keylist);    
    free_stringpair_list(rev_pairs);
    free(old_fpr);
    free(new_fpr);
    return status;
}

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* own_identity,
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr) {
    PEP_REQUIRE(session && dst
                && own_identity && ! EMPTYSTR(own_identity->address)
                && recip && ! EMPTYSTR(recip->address)
                && ! EMPTYSTR(old_fpr) && ! EMPTYSTR(new_fpr));

    *dst = NULL;
    
    message* reset_msg = NULL;
    
    PEP_STATUS status = _generate_keyreset_command_message(session, own_identity,
                                                           recip,
                                                           old_fpr, new_fpr, false,
                                                           &reset_msg);
                            
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    if (!reset_msg)
        return PEP_ILLEGAL_VALUE;
                                                                         
    if (!reset_msg->attachments) {
        status = PEP_UNKNOWN_ERROR;
        goto pEp_free;
    }    
    
    message* output_msg = NULL;
    
    status = encrypt_message(session, reset_msg, NULL,
                             &output_msg, PEP_enc_auto,
                             PEP_encrypt_flag_key_reset_only);

    if (status == PEP_STATUS_OK)
        *dst = output_msg;
    else if (output_msg) // shouldn't happen, but...
        free_message(output_msg); 
        
pEp_free:
        
    free_message(reset_msg);    
    return status;
}

static PEP_STATUS send_key_reset_to_active_group_members(PEP_SESSION session,
                                                         pEp_identity* group_ident,
                                                         pEp_identity* manager,
                                                         const char* old_fpr,
                                                         const char* new_key) {
    PEP_STATUS status = PEP_STATUS_OK;

    // Declared out here for clean memory cleanup on failure
    member_list* members = NULL;
    pEp_identity* group_ident_clone = NULL;
    identity_list* reset_ident_list = NULL;
    message* outmsg = NULL;

    messageToSend_t send_cb = session->messageToSend;
    if (!send_cb)
        return PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;

    // Get active group member list
    status = retrieve_active_member_list(session, group_ident, &members);

    if (status != PEP_STATUS_OK)
        goto pEp_free;

    if (members) {
        member_list* curr_member = members;

        // The identity we're resetting is the group_identity, which is why it is the "reset_ident_list"
        // and is the sole member. We send a reset message to each identity.
        for ( ; curr_member && curr_member->member && curr_member->member->ident; curr_member = curr_member->next) {
            pEp_identity* member_ident = curr_member->member->ident;
            if (EMPTYSTR(member_ident->user_id) || EMPTYSTR(member_ident->address))
                return PEP_UNKNOWN_ERROR;

            outmsg = NULL;
            group_ident_clone = identity_dup(group_ident);
            if (!group_ident_clone) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }

            reset_ident_list = new_identity_list(group_ident_clone);
            if (!reset_ident_list) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_free;
            }
            group_ident_clone = NULL; // Prevent double-free

            // FIXME: this is a little expensive - we should refactor so that
            // we cache the command list and prepare the messages in a loop with a copy
            status = generate_own_commandlist_msg(session,
                                                   reset_ident_list,
                                                   false,
                                                   manager,
                                                   member_ident,
                                                   old_fpr,
                                                   &outmsg);

            if (status != PEP_STATUS_OK)
                goto pEp_free;

            if (!outmsg || !outmsg->attachments) {// Must have keys
                status = PEP_UNKNOWN_ERROR;
                goto pEp_free;
            }

            // Attach key revocation
            char* revoked_key_material = NULL;
            size_t revoked_key_size = 0;
            status = export_key(session, old_fpr, &revoked_key_material, &revoked_key_size);
            if (status != PEP_STATUS_OK)
                goto pEp_free;

            bloblist_add(outmsg->attachments, revoked_key_material, revoked_key_size,
                         "application/pgp-keys","file://pEpkey_revoked.asc");

            message* enc_msg = NULL;

            // encrypt this baby and get out
            // extra keys???
            status = encrypt_message(session, outmsg, NULL, &enc_msg, PEP_enc_auto, PEP_encrypt_flag_key_reset_only);

            if (status != PEP_STATUS_OK)
                goto pEp_free;

            free_message(outmsg);
            outmsg = NULL; // Stop double-frees today!

            _add_auto_consume(enc_msg);

            // insert into queue
            status = send_cb(enc_msg);

            if (status != PEP_STATUS_OK) // FIXME: Do we still own enc_msg on failure?
                goto pEp_free;
        }
    }

    return status;

pEp_free:
    free_message(outmsg);
    free_memberlist(members);
    if (!reset_ident_list)
        free_identity(group_ident_clone);
    else
        free_identity_list(reset_ident_list);
    return status;
}

PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     pEp_identity* from_ident,
                                     const char* old_fpr, 
                                     const char* new_fpr) {
    PEP_REQUIRE(session
                && from_ident && ! EMPTYSTR(from_ident->address)
                && ! EMPTYSTR(from_ident->user_id)
                && ! EMPTYSTR(old_fpr) && ! EMPTYSTR(new_fpr));
//    assert(session->messageToSend); NO. Don't assert this, FFS.

    messageToSend_t send_cb = session->messageToSend;
    if (!send_cb)
        return PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;

    bool is_group_ident = (from_ident->flags & PEP_idf_group_ident);

    identity_list* recent_contacts = NULL;
    message* reset_msg = NULL;

    PEP_STATUS status = get_last_contacted(session, &recent_contacts);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
                    
    identity_list* curr_id_ptr = recent_contacts;

    for (curr_id_ptr = recent_contacts; curr_id_ptr; curr_id_ptr = curr_id_ptr->next) {
        pEp_identity* curr_id = curr_id_ptr->ident;
        
        if (!curr_id)
            break;
    
        const char* user_id = curr_id->user_id;
        
        // Should be impossible, but?
        if (!user_id)
            continue;
        
        // Check if it's us - if so, pointless...
        if (is_me(session, curr_id))
            continue;

        // If this is a from a group identity AND the curr_id_ptr points to an active member,
        // move on
        if (is_group_ident) {
            bool is_member = false;
            status = is_active_group_member(session, from_ident, curr_id, &is_member);
            if (is_member)
                continue;
        }

        // Also, don't bother to send it to non-pEp-users 
        bool pEp_user = false;
        status = is_pEp_user(session, curr_id, &pEp_user);

        if (status != PEP_STATUS_OK)
            goto pEp_free;

        if (!pEp_user)
            continue;
            
        // Check if they've already been told - this shouldn't be the case, but...
        bool contacted = false;
        status = has_key_reset_been_sent(session, from_ident->address, user_id, old_fpr, &contacted);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    
        if (contacted)
            continue;
            
        // Make sure they've ever *contacted* this address    
        bool in_contact_w_this_address = false;
        status = has_partner_contacted_address(session, curr_id->user_id, from_ident->address,  
                                               &in_contact_w_this_address);
        
        if (!in_contact_w_this_address)
            continue;
            
        // if not, make em a message    
        reset_msg = NULL;
        
        status = create_standalone_key_reset_message(session,
                                                     &reset_msg,
                                                     from_ident,
                                                     curr_id,
                                                     old_fpr,
                                                     new_fpr);

        if (status == PEP_CANNOT_FIND_IDENTITY) { // this is ok, just means we never mailed them 
            status = PEP_STATUS_OK;
            continue; 
        }
            
        if (status != PEP_STATUS_OK) {
            free(reset_msg);
            goto pEp_free;
        }

        _add_auto_consume(reset_msg);        
        // insert into queue
        status = send_cb(reset_msg);

        if (status != PEP_STATUS_OK) {
            free(reset_msg);
            goto pEp_free;            
        }
            
        // Put into notified DB
        status = set_reset_contact_notified(session, from_ident->address, old_fpr, user_id);
        if (status != PEP_STATUS_OK)
            goto pEp_free;            
    }
    
pEp_free:
    free_identity_list(recent_contacts);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        pEp_identity* ident,
        const char* fpr        
    )
{
    PEP_REQUIRE(session && ident
                && ! EMPTYSTR(ident->user_id) && ! EMPTYSTR(ident->address));

    return key_reset(session, fpr, ident);
}

DYNAMIC_API PEP_STATUS key_reset_user(
        PEP_SESSION session,
        const char* user_id,
        const char* fpr        
    )
{
    PEP_REQUIRE (session && ! EMPTYSTR(user_id));

    pEp_identity* input_ident = new_identity(NULL, NULL, user_id, NULL);
    if (!input_ident)
        return PEP_OUT_OF_MEMORY;
        
    if (is_me(session, input_ident) && EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;
        
    PEP_STATUS status = key_reset(session, fpr, input_ident);
    free_identity(input_ident);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_all_own_keys(PEP_SESSION session) {
    return key_reset(session, NULL, NULL);
}

/**
 *  @internal
 *  
 *  <!--       _dup_grouped_only()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *idents           identity_list
 *  @param[in]    **filtered        identity_list
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_OUT_OF_MEMORY       out of memory
 *  @retval any other value on error
 */
static PEP_STATUS _dup_grouped_only(identity_list* idents, identity_list** filtered) {
    if (!idents)
        return PEP_STATUS_OK;
        
    identity_list* id_node;
    pEp_identity* curr_ident = NULL;
    
    identity_list* ret_list = NULL;
    identity_list** ret_list_pp = &ret_list;
    
    for (id_node = idents; id_node && id_node->ident; id_node = id_node->next) {
        curr_ident = id_node->ident;
        if (curr_ident->flags & PEP_idf_devicegroup) {
            pEp_identity* new_ident = identity_dup(curr_ident);
            if (!new_ident) {
                free_identity_list(ret_list);
                return PEP_OUT_OF_MEMORY;
            }
            identity_list* new_ident_il = new_identity_list(new_ident);
            if (!new_ident_il) {
                free(new_ident);
                free_identity_list(ret_list);
                return PEP_OUT_OF_MEMORY;
            }
                
            *ret_list_pp = new_ident_il;
            ret_list_pp = &(new_ident_il->next);                
        }
    }
    *filtered = ret_list;
    return PEP_STATUS_OK;    
}

static PEP_STATUS _do_full_reset_on_single_own_ungrouped_identity(PEP_SESSION session,
                                                                  pEp_identity* ident,
                                                                  char* old_fpr) {

    bool is_own_identity_group = false;
    PEP_STATUS status = PEP_STATUS_OK;

    // Before we start, deal with group identities...
    // Deal with group identities
    if (ident->flags & PEP_idf_group_ident) {
        status = is_own_group_identity(session, ident, &is_own_identity_group);
        if (status != PEP_STATUS_OK)
            return status; // inconsistent crap going on here... hrm.
        if (!is_own_identity_group) {
            // dun dun dunnnnnn
        }
    }

    // Urgh. Can this cause a memleak? FIXME.
    char* cached_passphrase = EMPTYSTR(session->curr_passphrase) ? NULL : strdup(session->curr_passphrase);

    // Do the full reset on this identity
    // Base case for is_own_private starts here
    // Note that we reset this key for ANY own ident that has it. And if
    // tmp_ident did NOT have this key, it won't matter. We will reset this
    // key for all idents for this user.
    status = revoke_key(session, old_fpr, NULL);

    // Should never happen, we checked this, but STILL.
    if (PASS_ERROR(status))
        return status;

    const char* new_key = NULL;

    // If we have a full identity, we have some cleanup and generation tasks here
    // FIXME: I think this should always be true here
    if (!EMPTYSTR(ident->address)) {

        // Note - this will be ignored right now by keygen for group identities.
        // Testing needs to make sure all callers set the flag appropriately before
        // we get into the current function.
        config_passphrase(session, session->generation_passphrase);

        // generate new key
        ident->fpr = NULL;
        status = myself(session, ident);

        if (status == PEP_STATUS_OK && ident->fpr && strcmp(old_fpr, ident->fpr) != 0)
            new_key = strdup(ident->fpr);
        // Error handling?

        // mistrust old_fpr from trust
        ident->fpr = old_fpr;

        ident->comm_type = PEP_ct_mistrusted;
        status = set_trust(session, ident);
        ident->fpr = NULL;

        // Done with old use of ident.
        if (status == PEP_STATUS_OK) {
            // Generate new key
            status = myself(session, ident);
        }
        else
            return status; // FIXME: MEM
    }

    if (status == PEP_STATUS_OK)
        // cascade that mistrust for anyone using this key
        status = mark_as_compromised(session, old_fpr);

    if (status == PEP_STATUS_OK)
        status = remove_fpr_as_default(session, old_fpr);
    if (status == PEP_STATUS_OK)
        status = add_mistrusted_key(session, old_fpr);

    // If there's a new key, do the DB linkage with the revoked one, and
    // send the key reset mail opportunistically to recently contacted
    // partners
    if (new_key) {
        // add to revocation list
        if (status == PEP_STATUS_OK)
            status = set_revoked(session, old_fpr, new_key, time(NULL));
        // for all active communication partners:
        //      active_send revocation

        //ident->fpr = old_fpr; ???????
        if (status == PEP_STATUS_OK) {
            if (is_own_identity_group) {
                pEp_identity* manager = NULL;
                status = get_group_manager(session, ident, &manager);
                if (status == PEP_STATUS_OK) {
                    status = send_key_reset_to_active_group_members(session, ident, manager, old_fpr, new_key);
                }
            }
            if (status == PEP_STATUS_OK)
                status = send_key_reset_to_recents(session, ident, old_fpr, new_key);
        }
        ident->fpr = NULL;
    }
    config_passphrase(session, cached_passphrase);

    // Whether new_key is NULL or not, if this key is equal to the current user default, we
    // replace it.
    status = replace_main_user_fpr_if_equal(session, ident->user_id, new_key, old_fpr);

    return status;
}

/**
 *  @internal
 *  
 *  <!--       _check_own_reset_passphrase_readiness()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    session        session handle
 *  @param[in]    *key           constchar
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED
 *  @retval PEP_KEY_NOT_FOUND
 *  @retval any other value on error
 */
static PEP_STATUS _check_own_reset_passphrase_readiness(PEP_SESSION session,
                                                        const char* key) { 

    // Check generation setup
    // Because of the above, we can support a signing passphrase 
    // that differs from the generation passphrase. We'll 
    // just check to make sure everything is in order for 
    // later use, however
    if (session->new_key_pass_enable) {
        if (EMPTYSTR(session->generation_passphrase))
            return PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED;
    }
                                
    stringlist_t* test_key = NULL;
                              
    // Be sure we HAVE this key
    PEP_STATUS status = find_keys(session, key, &test_key);
    bool exists_key = test_key != NULL;
    free_stringlist(test_key);    

    if (!exists_key || status == PEP_KEY_NOT_FOUND) {
        remove_fpr_as_default(session, key);
        return PEP_KEY_NOT_FOUND;
    }        
    if (status != PEP_STATUS_OK)
        return status;
            
    ensure_passphrase_t ensure_key_cb = session->ensure_passphrase;
    
    // Check to see that this key has its passphrase set as the configured 
    // passphrase, IF it has one. If not, bail early.
    status = probe_encrypt(session, key);
    if (PASS_ERROR(status)) {
        if (ensure_key_cb)
            status = ensure_key_cb(session, key);
    }
    if (status != PEP_STATUS_OK)
        return status;
                            
    if (EMPTYSTR(session->curr_passphrase) && !EMPTYSTR(session->generation_passphrase)) {
        // We'll need it as the current passphrase to sign 
        // messages with the generated keys
        config_passphrase(session, session->generation_passphrase);
    }        
                                                          
    return PEP_STATUS_OK;                                                       
}



// This is for ONE specific key, but possibly many identities
// We could have ONE return for PEP_PASSPHRASE_FOR_NEW_KEYS_REQUIRED
// and another for  PEP_PASSPHRASE_REQUIRED/PEP_WRONG_PASSPHRASE
// State would advance though, it just might need to be called 
// twice with correct passwords, and more without.
// (In other words, with multiple passwords, this is not the end of all things)
//
// N.B. This function presumes that ALL idents in this group have the
//      key in question as their main key. That's what this function 
//      was created for.
// FIXME:
// I am not sure this is safe with already-revoked keys.
//
/**
 *  @internal
 *  
 *  <!--       _key_reset_device_group_for_shared_key()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    session         session handle
 *  @param[in]    *key_idents     identity_list
 *  @param[in]    *old_key        constchar
 *  @param[in]    grouped_only    bool
 *  
 *  @retval PEP_STATUS_OK
 *  @retval PEP_ILLEGAL_VALUE   illegal parameter values
 *  @retval PEP_SYNC_NO_MESSAGE_SEND_CALLBACK
 *  @retval any other value on error
 */
static PEP_STATUS _key_reset_device_group_for_shared_key(PEP_SESSION session, 
                                                         identity_list* key_idents, 
                                                         char* old_key,
                                                         bool grouped_only) {
    PEP_REQUIRE(session && key_idents && ! EMPTYSTR (old_key));

    messageToSend_t send_cb = session->messageToSend;
    if (!send_cb)
        return PEP_SYNC_NO_MESSAGE_SEND_CALLBACK;

    PEP_STATUS status = PEP_STATUS_OK;
            
    message* enc_msg = NULL;
    message* outmsg = NULL;
    stringlist_t* test_key = NULL;
            

    // Make sure the signing password is set correctly and that 
    // we are also ready for keygen
    status = _check_own_reset_passphrase_readiness(session, old_key);
    if (status != PEP_STATUS_OK)
        return status;
    
    char* cached_passphrase = EMPTYSTR(session->curr_passphrase) ? NULL : strdup(session->curr_passphrase);        

    // We need to create this list in either event because we only sync grouped
    // identities, so this is necessary for the command list:

    identity_list* grouped_idents = NULL;
    status = _dup_grouped_only(key_idents, &grouped_idents);
    if (status != PEP_STATUS_OK)
        goto pEp_error;

    // First, do grouped idents. That has to be done before we can revoke the key.

//    // if we only want grouped identities, we do this:
//    if (grouped_only) {
//        identity_list* new_list = NULL;
//        status = _dup_grouped_only(key_idents, &new_list);
//        if (status != PEP_STATUS_OK)
//            goto pEp_error;
//        key_idents = new_list; // local var change, won't impact caller
//                               // FIXME: How is this not a mem leak later?
//    }
//
//    if (!key_idents)
//        return PEP_STATUS_OK;
        
    // each of these has the same key and needs a new one.
    identity_list* curr_ident;

    if (grouped_idents) {
        for (curr_ident = grouped_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
            pEp_identity *ident = curr_ident->ident;
            free(ident->fpr);
            ident->fpr = NULL;
            status = _generate_keypair(session, ident, true);
            if (status != PEP_STATUS_OK)
                goto pEp_error;
        }

        // Ok, everyone who's grouped has got a new keypair. Hoorah!
        // generate, sign, and push messages into queue
        //

        // Because we have to export the NEW secret keys,
        // we have to switch in the passgen key
        // as the configured key. We'll switch it back
        // afterward (no revocation, decrypt, or signing
        // with the old key happens in here)
        // (N.B. For now, group encryption keys will ignore this
        // FIXME: I think group encryption keys probably have to do something different here anyway...
        config_passphrase(session, session->generation_passphrase);

        status = generate_own_commandlist_msg(session,
                                               grouped_idents,
                                               true,
                                               NULL,
                                               NULL,
                                               old_key,
                                               &outmsg);

        config_passphrase(session, cached_passphrase);

        // Key-based errors here shouldn't happen.
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        // Following will only be true if some idents were grouped,
        // and will only include grouped idents!
        // Will be signed with old signing key.
        // (Again, see the FIXME - we need to figure out what
        //  happens if it got revoked externally)
        if (outmsg) {

            // encrypt this baby and get out
            // extra keys???
            status = encrypt_message(session, outmsg, NULL, &enc_msg, PEP_enc_auto, PEP_encrypt_flag_key_reset_only);

            if (status != PEP_STATUS_OK)
                goto pEp_error;

            _add_auto_consume(enc_msg);

            // insert into queue
            status = send_cb(enc_msg);

            if (status != PEP_STATUS_OK)
                goto pEp_error;
        }

        // Ok, we've signed everything we need to with the old key,
        // Revoke that baby, in case we haven't already.
        status = revoke_key(session, old_key, NULL);

        // again, we should not have key-related issues here,
        // as we ensured the correct password earlier
        if (status != PEP_STATUS_OK)
            goto pEp_error;

        // Ok, NOW - the current password needs to be swapped out
        // because we're going to sign with keys using it.
        //
        // All new keys have the same passphrase, if any
        //
        config_passphrase(session, session->generation_passphrase);

        for (curr_ident = grouped_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
            pEp_identity *ident = curr_ident->ident;

            // set own key, you fool.
            // Grab ownership first.
            char *new_key = ident->fpr;
            ident->fpr = NULL;
            status = set_own_key(session, ident, new_key);
            if (status != PEP_STATUS_OK)
                // scream loudly and cry, then hang head in shame
                goto pEp_error;

            free(ident->fpr);

            // release ownership to the struct again
            ident->fpr = new_key;

            // N.B. This sort of sucks because we overwrite this every time.
            // But this case is infrequent and we don't rely on the binding.
            if (status == PEP_STATUS_OK)
                status = set_revoked(session, old_key, new_key, time(NULL));

            if (status != PEP_STATUS_OK)
                goto pEp_error;

            // Whether new_key is NULL or not, if this key is equal to the current user default, we
            // replace it.
            status = replace_main_user_fpr_if_equal(session,
                                                    ident->user_id,
                                                    new_key,
                                                    old_key);

            if (status != PEP_STATUS_OK)
                goto pEp_error;

            pEp_identity *tmp_ident = identity_dup(ident);
            if (!tmp_ident) {
                status = PEP_OUT_OF_MEMORY;
                goto pEp_error;
            }
            free(tmp_ident->fpr);

            // for all active communication partners:
            //      active_send revocation
            tmp_ident->fpr = strdup(old_key); // freed in free_identity
            if (status == PEP_STATUS_OK)
                status = send_key_reset_to_recents(session, tmp_ident, old_key, ident->fpr);

            if (status != PEP_STATUS_OK)
                goto pEp_error;

            free_identity(tmp_ident);
        }

        config_passphrase(session, cached_passphrase);

        if (status == PEP_STATUS_OK)
            // cascade that mistrust for anyone using this key
            status = mark_as_compromised(session, old_key);
        if (status == PEP_STATUS_OK)
            status = remove_fpr_as_default(session, old_key);
        if (status == PEP_STATUS_OK)
            status = add_mistrusted_key(session, old_key);

    }

    // Make sure non-grouped idents with this key get reset (this probably happens almost never, but
    // it's a legitimate use case.)
    if (status == PEP_STATUS_OK && !grouped_only) {
        for (curr_ident = key_idents; curr_ident && curr_ident->ident; curr_ident = curr_ident->next) {
            if (!(curr_ident->ident->flags & PEP_idf_devicegroup)) {
                status = _do_full_reset_on_single_own_ungrouped_identity(session, curr_ident->ident, old_key);
                if (status != PEP_STATUS_OK)
                    goto pEp_error;
            }
        }
    }

    return status;

pEp_error:
    // Just in case
    config_passphrase(session, cached_passphrase);
    free_stringlist(test_key);
    free_message(outmsg);
    free_message(enc_msg);
    free(cached_passphrase);
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_own_grouped_keys(PEP_SESSION session) {
    PEP_REQUIRE(session);

    stringlist_t* keys = NULL;
    char* user_id = NULL;    
    PEP_STATUS status = get_default_own_userid(session, &user_id);

    if (status != PEP_STATUS_OK || !user_id)
        goto pEp_free;                    

    
    status = get_all_keys_for_user(session, user_id, &keys);

    // TODO: free
    if (status == PEP_STATUS_OK) {            
        stringlist_t* curr_key;
        
        for (curr_key = keys; curr_key && curr_key->value; curr_key = curr_key->next) {
            identity_list* key_idents = NULL;
            char* own_key = curr_key->value;

            // If the sticky bit is set, ignore this beast
            bool is_sticky = false;
            status = get_key_sticky_bit_for_user(session, user_id, own_key, &is_sticky);
            if (is_sticky)
                continue;

            status = get_identities_by_main_key_id(session, own_key, &key_idents);
            
            if (status == PEP_CANNOT_FIND_IDENTITY) {
                status = PEP_STATUS_OK;
                continue;
            }    
            else if (status == PEP_STATUS_OK)    
                status = _key_reset_device_group_for_shared_key(session, key_idents, own_key, true);            
            else 
                goto pEp_free;
            
            // This is in a switch because our return statuses COULD get more 
            // complicated
            switch (status) {
                case PEP_STATUS_OK:
                case PEP_KEY_NOT_FOUND: // call removed it as a default
                    break;
                default:
                    goto pEp_free;
            }
                            
            free_identity_list(key_idents);    
        }
    }
    goto pEp_free;

pEp_free:
    free_stringlist(keys);
    free(user_id);
    return status;
}


PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* key_id,
        pEp_identity* ident
    )
{
    PEP_REQUIRE(session
                && (ident == NULL || ! EMPTYSTR(ident->user_id)));
        
    PEP_STATUS status = PEP_STATUS_OK;
        
    char* fpr_copy = NULL;
    char* own_id = NULL;
    char* user_id = NULL;
    char* new_key = NULL;
    pEp_identity* tmp_ident = NULL;
    identity_list* key_idents = NULL;
    stringlist_t* keys = NULL;
    
    char* cached_passphrase = EMPTYSTR(session->curr_passphrase) ? NULL : strdup(session->curr_passphrase);
    
    if (!EMPTYSTR(key_id)) {
        fpr_copy = strdup(key_id);
        if (!fpr_copy)
            return PEP_OUT_OF_MEMORY;
    }

    // This is true when we don't have a user_id and address and the fpr isn't specified
    bool reset_all_for_user = !fpr_copy && (!ident || EMPTYSTR(ident->address));

    // FIXME: does this need to be done everywhere?> I think not.
    if (ident) {
        user_id = strdup(ident->user_id);
        if (!user_id) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
    }
    else {
        status = get_default_own_userid(session, &user_id);
        if (status != PEP_STATUS_OK || !user_id)
            goto pEp_free;                    
    }
    
    // FIXME: Make sure this can't result in a double-free in recursive calls
    tmp_ident = (ident ? identity_dup(ident) : new_identity(NULL, NULL, user_id, NULL));
    
    if (reset_all_for_user) { // Implies no key fpr sent in on entry to function
        status = get_all_keys_for_user(session, user_id, &keys);
        // TODO: free
        if (status == PEP_STATUS_OK) {
            stringlist_t* curr_key;
            
            for (curr_key = keys; curr_key && curr_key->value; curr_key = curr_key->next) {
                // FIXME: Is the ident really necessary?
                status = key_reset(session, curr_key->value, tmp_ident);
                if (status != PEP_STATUS_OK && status != PEP_CANNOT_FIND_IDENTITY)
                    break;
                else 
                    status = PEP_STATUS_OK;
            }
        }
        goto pEp_free;
    }                   
    else {
        // tmp_ident => tmp_ident->user_id (was checked)
        //
        // !(EMPTYSTR(fpr) && (!tmp_ident || EMPTYSTR(tmp_ident->address)))
        // => fpr || (tmp_ident && tmp_ident->address)
        //
        // so: We have an fpr or we have an ident with user_id and address
        //     or both
        if (!fpr_copy) {
            // We are guaranteed to have an ident w/ id + addr here.
            // Get the default key.
            pEp_identity* stored_ident = NULL;
            status = get_identity(session, tmp_ident->address, 
                                  tmp_ident->user_id, &stored_ident);

            // FIXME FIXME FIXME - KB: What the Hell did I want to fix here? URGH.
            if (status == PEP_STATUS_OK) {
                // transfer ownership
                fpr_copy = stored_ident->fpr;
                stored_ident->fpr = NULL;
                free_identity(stored_ident);                
            }
            
            if (!fpr_copy || status == PEP_CANNOT_FIND_IDENTITY) {
                // There's no identity default. Try resetting user default
                status = get_user_default_key(session, tmp_ident->user_id, &fpr_copy);
            }            
                        
            if (!fpr_copy || status != PEP_STATUS_OK) // No default to free. We're done here.
                goto pEp_free;            
        }
        
        // Ok - now we have at least an ident with user_id and an fpr.
        // Now it matters if we're talking about ourselves or a partner.
        bool is_own_private = false;
        //bool is_own_identity_group = false;

        if (is_me(session, tmp_ident)) {
            // For now: We don't reset own revoked/mistrusted key. We're 
            // already done with this. @bug - check after key election removal
            bool mistr = false;
            bool revok = false;
            status = is_mistrusted_key(session, fpr_copy, &mistr);
            if (status != PEP_STATUS_OK || mistr)
                goto pEp_free;
            status = key_revoked(session, fpr_copy, &revok);
            if (status != PEP_STATUS_OK || revok)
                goto pEp_free;

            bool own_key = false;            
            status = is_own_key(session, fpr_copy, &own_key);

            if (status != PEP_STATUS_OK)
                goto pEp_free;
            if (!own_key) {
                status = PEP_ILLEGAL_VALUE;
                goto pEp_free;
            }

            status = contains_priv_key(session, fpr_copy, &is_own_private);
            if (status != PEP_STATUS_OK && status != PEP_KEY_NOT_FOUND)
                goto pEp_free;

        }


        // Up to this point, we haven't cared about whether or not we 
        // had a full identity. Now we have to deal with that in the 
        // case of own identities with private keys.
        if (is_own_private) {

            // This is now the "is_own" base case - we don't do this
            // per-identity, because all identities using this key will
            // need new ones. That said, this is really only a problem 
            // with manual key management, something which we only support 
            // to a limited extent in any event.
            
            bool is_in_device_group = false;
            status = deviceGrouped(session, &is_in_device_group);
             
            // Regardless of the single identity this is for, for own keys, we do this 
            // for all keys associated with the identity.
            status = get_identities_by_main_key_id(session, fpr_copy, &key_idents);
            
            if (status != PEP_CANNOT_FIND_IDENTITY) {
                
                // N.B. Possible user default key replacement will happen inside
                //      _key_reset_device_group_for_shared_key in the first case.
                //      We handle the reassignment for the second case in the block here.
                if (is_in_device_group) 
                    status = _key_reset_device_group_for_shared_key(session, key_idents, fpr_copy, false);
                else if (status == PEP_STATUS_OK) {
                    // KB: FIXME_NOW - revoked?
                    // Make sure we can even progress - if there are passphrase issues,
                    // bounce back to the caller now, because our attempts to make it work failed,
                    // even possibly with callback.
                    status = _check_own_reset_passphrase_readiness(session, fpr_copy);
                    if (status != PEP_STATUS_OK)
                        return status;
                    
                    // now have ident list, or should
                    identity_list* curr_ident;

                    for (curr_ident = key_idents; curr_ident && curr_ident->ident; 
                                                    curr_ident = curr_ident->next) {

                        pEp_identity *this_ident = curr_ident->ident;

                        status = _do_full_reset_on_single_own_ungrouped_identity(session,
                                                                                 this_ident,
                                                                                 fpr_copy);

                        // Should never happen, we checked this, but STILL.
                        if (PASS_ERROR(status))
                            goto pEp_free;
                    }

                }
                // Ok, we've either now reset for each own identity with this key, or 
                // we got an error and want to bail anyway.
                goto pEp_free;
            }
            else {
                status = PEP_CANNOT_FIND_IDENTITY;
                goto pEp_free;
            }    
        } // end is_own_private
        else {
            // if it's mistrusted, make it not be so.
            bool mistrusted_key = false;
            is_mistrusted_key(session, fpr_copy, &mistrusted_key);

            if (mistrusted_key)
                delete_mistrusted_key(session, fpr_copy);
            
            if (tmp_ident->user_id)
                status = clear_trust_info(session, tmp_ident->user_id, fpr_copy);

            // This is a public key (or a private key that isn't ours, which means
            // we want it gone anyway)
            //
            // Delete this key from the keyring.
            // FIXME: when key election disappears, so should this!
            status = delete_keypair(session, fpr_copy); /* positron: I believe the previous comment
                                                                     is wrong and we should in fact
                                                                     not delete the key from the
                                                                     keyring without key election.
                                                                     Can fdik confirm? */
        }

        // REGARDLESS OF WHO OWNS THE KEY, WE NOW NEED TO REMOVE IT AS A DEFAULT.
        PEP_STATUS cached_status = status;
        // remove fpr from all identities
        // remove fpr from all users
        status = remove_fpr_as_default(session, fpr_copy);
        // delete key from DB - this does NOT touch the keyring!
        // Note: for own priv keys, we cannot do this. But we'll never encrypt to/from it.
        if (status == PEP_STATUS_OK && !is_own_private) {
            status = remove_key(session, fpr_copy);
        }
        if (status == PEP_STATUS_OK)
            status = cached_status;
    }           
        
pEp_free:
    if (!ident)
        free_identity(tmp_ident);
    free(fpr_copy);
    free(own_id);
    free_identity_list(key_idents);
    free_stringlist(keys);
    free(new_key);   
    config_passphrase(session, cached_passphrase); 
    free(cached_passphrase);
    return status;
}

/**
 *  @internal
 *  
 *  <!--       Distribution_from_keyreset_command_list()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *command_list        keyreset_command_list
 *  @param[in]    *dist                Distribution_t
 *  
 */
Distribution_t *Distribution_from_keyreset_command_list(
        const keyreset_command_list *command_list,
        Distribution_t *dist
    )
{
    bool allocated = dist;

    assert(command_list);
    if (!command_list)
        return NULL;

    if (!allocated)
        dist = (Distribution_t *) calloc(1, sizeof(Distribution_t));

    assert(dist);
    if (!dist)
        goto enomem;

    dist->present = Distribution_PR_keyreset;
    dist->choice.keyreset.present = KeyReset_PR_commands;

    long *major = malloc(sizeof(long));
    assert(major);
    if (!major)
        goto enomem;
    *major = KEY_RESET_MAJOR_VERSION;
    dist->choice.keyreset.choice.commands.version.major = major;

    long *minor = malloc(sizeof(long));
    assert(minor);
    if (!minor)
        goto enomem;
    *minor = KEY_RESET_MINOR_VERSION;
    dist->choice.keyreset.choice.commands.version.minor = minor;

    for (const keyreset_command_list *cl = command_list; cl && cl->command; cl = cl->next) {
        Command_t *c = (Command_t *) calloc(1, sizeof(Command_t));
        assert(c);
        if (!c)
            goto enomem;

        if (!Identity_from_Struct(cl->command->ident, &c->ident)) {
            free(c);
            goto enomem;
        }

        if (OCTET_STRING_fromString(&c->newkey, cl->command->new_key)) {
            ASN_STRUCT_FREE(asn_DEF_Command, c);
            goto enomem;
        }

        if (ASN_SEQUENCE_ADD(&dist->choice.keyreset.choice.commands.commandlist, c)) {
            ASN_STRUCT_FREE(asn_DEF_Command, c);
            goto enomem;
        }
    }

    return dist;

enomem:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return NULL;
}


PEP_STATUS key_reset_commands_to_PER(PEP_SESSION session, const keyreset_command_list *command_list, char **cmds, size_t *size)
{
    PEP_REQUIRE(session && command_list && cmds && size);

    PEP_STATUS status = PEP_STATUS_OK;

    *cmds = NULL;
    *size = 0;

    // convert from pEp engine struct

    Distribution_t *dist = Distribution_from_keyreset_command_list(command_list, NULL);
    assert(dist);
    if (!dist)
        goto enomem;

    // encode

    char *_cmds;
    size_t _size;
    status = encode_Distribution_message(dist, &_cmds, &_size);
    if (status)
        goto the_end;

    // return result

    *cmds = _cmds;
    *size = _size;
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;

the_end:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return status;
}

/**
 *  @internal
 *  
 *  <!--       Distribution_to_keyreset_command_list()       -->
 *  
 *  @brief            TODO
 *  
 *  @param[in]    *dist                Distribution_t
 *  @param[in]    *command_list        keyreset_command_list
 *  
 */
keyreset_command_list * Distribution_to_keyreset_command_list(
        Distribution_t *dist,
        keyreset_command_list *command_list
    )
{
    bool allocated = !command_list;

    assert(dist);
    if (!dist)
        return NULL;

    if (allocated)
        command_list = new_keyreset_command_list(NULL);
    if (!command_list)
        goto enomem;

    struct Commands__commandlist *cl = &dist->choice.keyreset.choice.commands.commandlist;
    keyreset_command_list *_result = command_list;
    for (int i=0; i<cl->list.count; i++) {
        pEp_identity *ident = Identity_to_Struct(&cl->list.array[i]->ident, NULL);
        if (!ident)
            goto enomem;

        const char *new_key = (const char *) cl->list.array[i]->newkey.buf;

        keyreset_command *command = new_keyreset_command(ident, new_key);
        if (!command) {
            free_identity(ident);
            goto enomem;
        }

        _result = keyreset_command_list_add(_result, command);
        free_identity(ident);
        if (!_result)
            goto enomem;
    }

    return command_list;

enomem:
    if (allocated)
        free_keyreset_command_list(command_list);
    return NULL;
}

PEP_STATUS PER_to_key_reset_commands(PEP_SESSION session, const char *cmds, size_t size, keyreset_command_list **command_list)
{
    PEP_REQUIRE(session && command_list && cmds);

    *command_list = NULL;

    // decode

    Distribution_t *dist = NULL;
    PEP_STATUS status = decode_Distribution_message(cmds, size, &dist);
    if (status)
        goto the_end;

    // check if these are key reset commands or not

    assert(dist && dist->present == Distribution_PR_keyreset
            && dist->choice.keyreset.present == KeyReset_PR_commands);

    if (!(dist && dist->present == Distribution_PR_keyreset
            && dist->choice.keyreset.present == KeyReset_PR_commands)) {
        status = PEP_ILLEGAL_VALUE;
        goto the_end;
    }

    // convert to pEp engine struct

    keyreset_command_list *result = Distribution_to_keyreset_command_list(dist, NULL);
    if (!result)
        goto enomem;

    // return result

    *command_list = result;
    goto the_end;

enomem:
    status = PEP_OUT_OF_MEMORY;
    free_keyreset_command_list(result);

the_end:
    ASN_STRUCT_FREE(asn_DEF_Distribution, dist);
    return status;
}
