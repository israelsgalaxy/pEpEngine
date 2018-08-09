// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "pEp_internal.h"
#include "keymanagement.h"

#include "blacklist.h"

static bool key_matches_address(PEP_SESSION session, const char* address,
                                const char* fpr) {
    if (!session || !address || !fpr)
        return false;
    
    bool retval = false;
    stringlist_t *keylist = NULL;
    PEP_STATUS status = find_keys(session, address, &keylist);
    if (status == PEP_STATUS_OK && keylist) {
        stringlist_t* curr = keylist;
        while (curr) {
            if (curr->value) {
                if (strcasecmp(curr->value, fpr)) {
                    retval = true;
                    break;
                }
            }
            curr = curr->next;
        }
    }
    
    free_stringlist(keylist);
    return retval;                             
}

PEP_STATUS elect_pubkey(
        PEP_SESSION session, pEp_identity * identity, bool check_blacklist
    )
{
    PEP_STATUS status;
    stringlist_t *keylist = NULL;
    char *_fpr = "";
    identity->comm_type = PEP_ct_unknown;

    status = find_keys(session, identity->address, &keylist);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;
    
    if (!keylist || !keylist->value)
        identity->comm_type = PEP_ct_key_not_found;    
    else {
        stringlist_t *_keylist;
        for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
            PEP_comm_type _comm_type_key;

            status = get_key_rating(session, _keylist->value, &_comm_type_key);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY) {
                free_stringlist(keylist);
                return PEP_OUT_OF_MEMORY;
            }

            if (_comm_type_key != PEP_ct_compromised &&
                _comm_type_key != PEP_ct_unknown)
            {
                if (identity->comm_type == PEP_ct_unknown ||
                    _comm_type_key > identity->comm_type)
                {
                    bool blacklisted = false;
                    bool mistrusted = false;
                    status = is_mistrusted_key(session, _keylist->value, &mistrusted);
                    if (status == PEP_STATUS_OK && check_blacklist)
                        status = blacklist_is_listed(session, _keylist->value, &blacklisted);
                    if (status == PEP_STATUS_OK && !mistrusted && !blacklisted) {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
            }
        }
    }
    free(identity->fpr);

    if (!_fpr || _fpr[0] == '\0')
        identity->fpr = NULL;
    else {    
        identity->fpr = strdup(_fpr);
        if (identity->fpr == NULL) {
            free_stringlist(keylist);
            return PEP_OUT_OF_MEMORY;
        }
    }
    
    free_stringlist(keylist);
    return PEP_STATUS_OK;
}

static PEP_STATUS validate_fpr(PEP_SESSION session, 
                               pEp_identity* ident,
                               bool check_blacklist) {
    
    PEP_STATUS status = PEP_STATUS_OK;
    
    if (!session || !ident || !ident->fpr || !ident->fpr[0])
        return PEP_ILLEGAL_VALUE;    
        
    char* fpr = ident->fpr;
    
    bool has_private = false;
    
    if (ident->me) {
        status = contains_priv_key(session, fpr, &has_private);
        if (status != PEP_STATUS_OK || !has_private)
            return PEP_KEY_UNSUITABLE;
    }
    
    status = get_trust(session, ident);
    if (status != PEP_STATUS_OK)
        ident->comm_type = PEP_ct_unknown;
            
    PEP_comm_type ct = ident->comm_type;

    if (ct == PEP_ct_unknown) {
        // If status is bad, it's ok, we get the rating
        // we should use then (PEP_ct_unknown)
        get_key_rating(session, fpr, &ct);
        ident->comm_type = ct;
    }
    
    bool pEp_user = false;
    
    is_pEp_user(session, ident, &pEp_user);

    if (pEp_user) {
        switch (ct) {
            case PEP_ct_OpenPGP:
            case PEP_ct_OpenPGP_unconfirmed:
                ct += 0x47; // difference between PEP and OpenPGP values;
                ident->comm_type = ct;
                break;
            default:
                break;
        }
    }
    
    bool revoked, expired;
    bool blacklisted = false;
    
    status = key_revoked(session, fpr, &revoked);    
        
    if (status != PEP_STATUS_OK) {
        return status;
    }
    
    if (!revoked) {
        time_t exp_time = (ident->me ? 
                           time(NULL) + (7*24*3600) : time(NULL));
                           
        status = key_expired(session, fpr, 
                             exp_time,
                             &expired);
                             
        assert(status == PEP_STATUS_OK);
        if (status != PEP_STATUS_OK)
            return status;

        if (check_blacklist && IS_PGP_CT(ct) &&
            !ident->me) {
            status = blacklist_is_listed(session, 
                                         fpr, 
                                         &blacklisted);
                                         
            if (status != PEP_STATUS_OK)
                return status;
        }
    }
            
    if (ident->me && (ct >= PEP_ct_strong_but_unconfirmed) && !revoked && expired) {
        // extend key
        timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
        status = renew_key(session, fpr, ts);
        free_timestamp(ts);

        if (status == PEP_STATUS_OK) {
            // if key is valid (second check because pEp key might be extended above)
            //      Return fpr        
            status = key_expired(session, fpr, time(NULL), &expired);            
            if (status != PEP_STATUS_OK) {
                 ident->comm_type = PEP_ct_key_expired;
                 return status;
             }
            // communicate key(?)
        }        
    }
     
    if (revoked) 
        ct = PEP_ct_key_revoked;
    else if (expired)
        ct = PEP_ct_key_expired;        
    else if (blacklisted) { // never true for .me
        ident->comm_type = ct = PEP_ct_key_not_found;
        free(ident->fpr);
            ident->fpr = strdup("");
        status = PEP_KEY_BLACKLISTED;
    }
    
    switch (ct) {
        case PEP_ct_key_expired:
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
            // delete key from being default key for all users/identities
            status = remove_fpr_as_default(session, fpr);
            status = update_trust_for_fpr(session, 
                                          fpr, 
                                          ct);
        case PEP_ct_mistrusted:                                  
            free(ident->fpr);
            ident->fpr = NULL;
            ident->comm_type = ct;            
            status = PEP_KEY_UNSUITABLE;
        default:
            break;
    }            

    return status;
}

PEP_STATUS get_user_default_key(PEP_SESSION session, const char* user_id,
                                char** default_key) {
    assert(session);
    assert(user_id);
    
    if (!session || !user_id)
        return PEP_ILLEGAL_VALUE;

    PEP_STATUS status = PEP_STATUS_OK;
            
    // try to get default key for user_data
    sqlite3_reset(session->get_user_default_key);
    sqlite3_bind_text(session->get_user_default_key, 1, user_id, 
                      -1, SQLITE_STATIC);
    
    const int result = sqlite3_step(session->get_user_default_key);
    char* user_fpr = NULL;
    if (result == SQLITE_ROW) {
        const char* u_fpr =
            (char *) sqlite3_column_text(session->get_user_default_key, 0);
        if (u_fpr)
            user_fpr = strdup(u_fpr);
    }
    else
        status = PEP_GET_KEY_FAILED;
        
    sqlite3_reset(session->get_user_default_key);
    
    *default_key = user_fpr;
    return status;     
}

// Only call on retrieval of previously stored identity!
// Also, we presume that if the stored_identity was sent in
// without an fpr, there wasn't one in the trust DB for this
// identity.
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                         pEp_identity* stored_identity,
                         bool* is_identity_default,
                         bool* is_user_default,
                         bool* is_address_default,
                         bool check_blacklist) {
    
    PEP_STATUS status = PEP_STATUS_OK;

    if (!stored_identity || EMPTYSTR(stored_identity->user_id)
        || !is_identity_default || !is_user_default || !is_address_default)
        return PEP_ILLEGAL_VALUE;
        
    *is_identity_default = *is_user_default = *is_address_default = false;

    PEP_comm_type first_reject_comm_type = PEP_ct_key_not_found;
    PEP_STATUS first_reject_status = PEP_KEY_NOT_FOUND;
    
    char* stored_fpr = stored_identity->fpr;
    // Input: stored identity retrieved from database
    // if stored identity contains a default key
    if (!EMPTYSTR(stored_fpr)) {
        status = validate_fpr(session, stored_identity, check_blacklist);    
        if (status == PEP_STATUS_OK && !EMPTYSTR(stored_identity->fpr)) {
            *is_identity_default = *is_address_default = true;
            return status;
        }
        else if (status != PEP_KEY_NOT_FOUND) {
            first_reject_status = status;
            first_reject_comm_type = stored_identity->comm_type;
        }
    }
    // if no valid default stored identity key found
    free(stored_identity->fpr);
    stored_identity->fpr = NULL;
    
    char* user_fpr = NULL;
    status = get_user_default_key(session, stored_identity->user_id, &user_fpr);
    
    if (!EMPTYSTR(user_fpr)) {             
        // There exists a default key for user, so validate
        stored_identity->fpr = user_fpr;
        status = validate_fpr(session, stored_identity, check_blacklist);
        if (status == PEP_STATUS_OK && stored_identity->fpr) {
            *is_user_default = true;
            *is_address_default = key_matches_address(session, 
                                                      stored_identity->address,
                                                      stored_identity->fpr);
            return status;
        }        
        else if (status != PEP_KEY_NOT_FOUND && first_reject_status != PEP_KEY_NOT_FOUND) {
            first_reject_status = status;
            first_reject_comm_type = stored_identity->comm_type;
        }
    }
    
    status = elect_pubkey(session, stored_identity, check_blacklist);
    if (status == PEP_STATUS_OK) {
        if (!EMPTYSTR(stored_identity->fpr))
            validate_fpr(session, stored_identity, false); // blacklist already filtered of needed
    }    
    else if (status != PEP_KEY_NOT_FOUND && first_reject_status != PEP_KEY_NOT_FOUND) {
        first_reject_status = status;
        first_reject_comm_type = stored_identity->comm_type;
    }
    
    switch (stored_identity->comm_type) {
        case PEP_ct_key_revoked:
        case PEP_ct_key_b0rken:
        case PEP_ct_key_expired:
        case PEP_ct_compromised:
        case PEP_ct_mistrusted:
            // this only happens when it's all there is
            status = first_reject_status;
            free(stored_identity->fpr);
            stored_identity->fpr = NULL;
            stored_identity->comm_type = first_reject_comm_type;
            break;    
        default:
            if (check_blacklist && status == PEP_KEY_BLACKLISTED) {
                free(stored_identity->fpr);
                stored_identity->fpr = NULL;
                stored_identity->comm_type = PEP_ct_key_not_found;
            }
            break;
    }
    return status;
}

static void transfer_ident_lang_and_flags(pEp_identity* new_ident,
                                          pEp_identity* stored_ident) {
    if (new_ident->lang[0] == 0) {
      new_ident->lang[0] = stored_ident->lang[0];
      new_ident->lang[1] = stored_ident->lang[1];
      new_ident->lang[2] = 0;
    }

    new_ident->flags = stored_ident->flags;
    new_ident->me = new_ident->me || stored_ident->me;
}

static void adjust_pEp_trust_status(PEP_SESSION session, pEp_identity* identity) {
    assert(session);
    assert(identity);
    
    if (identity->comm_type < PEP_ct_strong_but_unconfirmed ||
        (identity->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
        return;
    
    bool pEp_user;
    
    is_pEp_user(session, identity, &pEp_user);
    
    if (pEp_user) {
        PEP_comm_type confirmation_status = identity->comm_type & PEP_ct_confirmed;
        identity->comm_type = PEP_ct_pEp_unconfirmed | confirmation_status;    
    }
}


static PEP_STATUS prepare_updated_identity(PEP_SESSION session,
                                                 pEp_identity* return_id,
                                                 pEp_identity* stored_ident,
                                                 bool store) {
    
    if (!session || !return_id || !stored_ident)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status;
    
    bool is_identity_default, is_user_default, is_address_default;
    status = get_valid_pubkey(session, stored_ident,
                                &is_identity_default,
                                &is_user_default,
                                &is_address_default,
                              false);
                                
    if (status == PEP_STATUS_OK && stored_ident->fpr && *(stored_ident->fpr) != '\0') {
    // set identity comm_type from trust db (user_id, FPR)
        status = get_trust(session, stored_ident);
        if (status == PEP_CANNOT_FIND_IDENTITY || stored_ident->comm_type == PEP_ct_unknown) {
            // This is OK - there is no trust DB entry, but we
            // found a key. We won't store this, but we'll
            // use it.
            PEP_comm_type ct = PEP_ct_unknown;
            status = get_key_rating(session, stored_ident->fpr, &ct);
            stored_ident->comm_type = ct;
        }
    }
    else {
        if (stored_ident->comm_type == PEP_ct_unknown)
            stored_ident->comm_type = PEP_ct_key_not_found;
    }
    free(return_id->fpr);
    return_id->fpr = NULL;
    if (status == PEP_STATUS_OK && !EMPTYSTR(stored_ident->fpr))
        return_id->fpr = strdup(stored_ident->fpr);
        
    return_id->comm_type = stored_ident->comm_type;
                    
    // We patch the DB with the input username, but if we didn't have
    // one, we pull it out of storage if available.
    // (also, if the input username is "anonymous" and there exists
    //  a DB username, we replace)
    if (!EMPTYSTR(stored_ident->username)) {
        if (!EMPTYSTR(return_id->username) && 
            (strcasecmp(return_id->username, return_id->address) == 0)) {
            free(return_id->username);
            return_id->username = NULL;
        }
        if (EMPTYSTR(return_id->username)) {
            free(return_id->username);
            return_id->username = strdup(stored_ident->username);
        }
    }
    else {
        if (EMPTYSTR(return_id->username))
            return_id->username = strdup(return_id->address);
    }
    
    return_id->me = stored_ident->me;
    
    // FIXME: Do we ALWAYS do this? We probably should...
    if (EMPTYSTR(return_id->user_id)) {
        free(return_id->user_id);
        return_id->user_id = strdup(stored_ident->user_id);
    } 
    
    adjust_pEp_trust_status(session, return_id);
   
    // Call set_identity() to store
    if ((is_identity_default || is_user_default) &&
         is_address_default) {                 
         // if we got an fpr which is default for either user
         // or identity AND is valid for this address, set in DB
         // as default
         status = set_identity(session, return_id);
    }
    else {
        // Store without default fpr/ct, but return the fpr and ct 
        // for current use
        char* save_fpr = return_id->fpr;
        PEP_comm_type save_ct = return_id->comm_type;
        return_id->fpr = NULL;
        return_id->comm_type = PEP_ct_unknown;
        PEP_STATUS save_status = status;
        status = set_identity(session, return_id);
        if (save_status != PEP_STATUS_OK)
            status = save_status;
        return_id->fpr = save_fpr;
        return_id->comm_type = save_ct;
    }
    
    transfer_ident_lang_and_flags(return_id, stored_ident);
    
    if (return_id->comm_type == PEP_ct_unknown)
        return_id->comm_type = PEP_ct_key_not_found;
    
    return status;
}

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return PEP_ILLEGAL_VALUE;

    char* default_own_id = NULL;
    status = get_default_own_userid(session, &default_own_id);    

    // Is this me, temporary or not? If so, BAIL.
    if (identity->me || 
       (default_own_id && identity->user_id && (strcmp(default_own_id, identity->user_id) == 0))) 
    {
        free(default_own_id);
        return PEP_ILLEGAL_VALUE;
    }

    // We have, at least, an address.
    // Retrieve stored identity information!    
    pEp_identity* stored_ident = NULL;

    if (!EMPTYSTR(identity->user_id)) {            
        // (we're gonna update the trust/fpr anyway, so we use the no-fpr-from-trust-db variant)
        //      * do get_identity() to retrieve stored identity information
        status = get_identity_without_trust_check(session, identity->address, identity->user_id, &stored_ident);

        // Before we start - if there was no stored identity, we should check to make sure we don't
        // have a stored identity with a temporary user_id that differs from the input user_id. This
        // happens in multithreaded environments sometimes.
        if (!stored_ident) {
            identity_list* id_list = NULL;
            status = get_identities_by_address(session, identity->address, &id_list);

            if (id_list) {
                identity_list* id_curr = id_list;
                while (id_curr) {
                    pEp_identity* this_id = id_curr->ident;
                    if (this_id) {
                        char* this_uid = this_id->user_id;
                        if (this_uid && (strstr(this_uid, "TOFU_") == this_uid)) {
                            // FIXME: should we also be fixing pEp_own_userId in this
                            // function here?
                            
                            // if usernames match, we replace the userid. Or if the temp username
                            // is anonymous.
                            // FIXME: do we need to create an address match function which
                            // matches the whole dot-and-case rigamarole from 
                            if (EMPTYSTR(this_id->username) ||
                                strcasecmp(this_id->username, this_id->address) == 0 ||
                                (identity->username && 
                                 strcasecmp(identity->username, 
                                            this_id->username) == 0)) {
                                
                                // Ok, we have a temp ID. We have to replace this
                                // with the real ID.
                                status = replace_userid(session, 
                                                        this_uid, 
                                                        identity->user_id);
                                if (status != PEP_STATUS_OK) {
                                    free_identity_list(id_list);
                                    free(default_own_id);
                                    return status;
                                }
                                    
                                free(this_uid);
                                this_uid = NULL;
                                
                                // Reflect the change we just made to the DB
                                this_id->user_id = strdup(identity->user_id);
                                stored_ident = this_id;
                                // FIXME: free list.
                                break;                                
                            }                            
                        } 
                    }
                    id_curr = id_curr->next;
                }
            }
        } 
                
        if (status == PEP_STATUS_OK && stored_ident) { 
            //  * if identity available
            //      * patch it with username
            //          (note: this will happen when 
            //           setting automatically below...)
            //      * elect valid key for identity
            //    * if valid key exists
            //        * set return value's fpr
            status = prepare_updated_identity(session,
                                              identity,
                                              stored_ident, true);
        }
        //  * else (identity unavailable)
        else {
            status = PEP_STATUS_OK;

            // FIXME: We may need to roll this back.
            // FIXME: change docs if we don't
            //  if we only have user_id and address and identity not available
            //      * return error status (identity not found)
            if (EMPTYSTR(identity->username)) {
                free(identity->username);
                identity->username = strdup(identity->address);
            }
            
            // Otherwise, if we had user_id, address, and username:
            //    * create identity with user_id, address, username
            //      (this is the input id without the fpr + comm type!)

            if (status == PEP_STATUS_OK) {
                elect_pubkey(session, identity, false);
            }
                        
            //    * We've already checked and retrieved
            //      any applicable temporary identities above. If we're 
            //      here, none of them fit.
            //    * call set_identity() to store
            if (status == PEP_STATUS_OK) {
                // FIXME: Do we set if we had to copy in the address?
                adjust_pEp_trust_status(session, identity);
                status = set_identity(session, identity);
            }
            //  * Return: created identity
        }        
    }
    else if (!EMPTYSTR(identity->username)) {
        /*
         * Temporary identity information with username supplied
            * Input: address, username (no others)
         */
         
        //  * See if there is an own identity that uses this address. If so, we'll
        //    prefer that
        stored_ident = NULL;
        
        if (default_own_id) {
            status = get_identity(session, 
                                  identity->address, 
                                  default_own_id, 
                                  &stored_ident);
        }
        // If there isn't an own identity, search for a non-temp stored ident
        // with this address.                      
        if (status == PEP_CANNOT_FIND_IDENTITY || !stored_ident) { 
 
            identity_list* id_list = NULL;
            status = get_identities_by_address(session, identity->address, &id_list);

            if (id_list) {
                identity_list* id_curr = id_list;
                while (id_curr) {
                    pEp_identity* this_id = id_curr->ident;
                    if (this_id) {
                        char* this_uid = this_id->user_id;
                        if (this_uid && (strstr(this_uid, "TOFU_") != this_uid)) {
                            // if usernames match, we replace the userid.
                            if (identity->username && 
                                strcasecmp(identity->username, 
                                           this_id->username) == 0) {
                                
                                // Ok, we have a real ID. Copy it!
                                identity->user_id = strdup(this_uid);
                                assert(identity->user_id);
                                if (!identity->user_id)
                                    goto enomem;

                                stored_ident = this_id;
                                
                                break;                                
                            }                            
                        } 
                    }
                    id_curr = id_curr->next;
                }
            }
        }
        
        if (stored_ident) {
            status = prepare_updated_identity(session,
                                              identity,
                                              stored_ident, true);
        }
        else {
            identity->user_id = calloc(1, strlen(identity->address) + 6);
            if (!identity->user_id)
                goto enomem;

            snprintf(identity->user_id, strlen(identity->address) + 6,
                     "TOFU_%s", identity->address);        

            status = get_identity(session, 
                                  identity->address, 
                                  identity->user_id, 
                                  &stored_ident);

            if (status == PEP_STATUS_OK && stored_ident) {
                status = prepare_updated_identity(session,
                                                  identity,
                                                  stored_ident, true);
            }
            else {
                         
                //    * We've already checked and retrieved
                //      any applicable temporary identities above. If we're 
                //      here, none of them fit.
                
                status = elect_pubkey(session, identity, false);
                             
                //    * call set_identity() to store
                if (identity->fpr)
                    status = get_key_rating(session, identity->fpr, &identity->comm_type);
            
                //    * call set_identity() to store
                adjust_pEp_trust_status(session, identity);            
                status = set_identity(session, identity);
            }
        }
    }
    else {
        /*
        * Input: address (no others)
         * Temporary identity information without username suplied
         */
         
        //  * Again, see if there is an own identity that uses this address. If so, we'll
        //    prefer that
        stored_ident = NULL;
         
        if (default_own_id) {
            status = get_identity(session, 
                                  identity->address, 
                                  default_own_id, 
                                  &stored_ident);
        }
        // If there isn't an own identity, search for a non-temp stored ident
        // with this address.                      
        if (status == PEP_CANNOT_FIND_IDENTITY || !stored_ident) { 
 
            identity_list* id_list = NULL;
            //    * Search for identity with this address
            status = get_identities_by_address(session, identity->address, &id_list);

            // Results are ordered by timestamp descending, so this covers
            // both the one-result and multi-result cases
            if (id_list) {
                if (stored_ident) // unlikely
                    free_identity(stored_ident);
                stored_ident = id_list->ident;
            }
        }
        if (stored_ident)
            status = prepare_updated_identity(session, identity,
                                              stored_ident, false);
        else  {            
            // too little info. BUT. We see if we can find a key; if so, we create a
            // temp identity, look for a key, and store.
                         
            // create temporary identity, store it, and Return this
            // This means TOFU_ user_id
            identity->user_id = calloc(1, strlen(identity->address) + 6);
            if (!identity->user_id)
                goto enomem;

            snprintf(identity->user_id, strlen(identity->address) + 6,
                     "TOFU_%s", identity->address);        
        
            identity->username = strdup(identity->address);
            if (!identity->address)
                goto enomem;
            
            free(identity->fpr);
            identity->fpr = NULL;
            identity->comm_type = PEP_ct_unknown;

            status = elect_pubkey(session, identity, false);
                         
            if (identity->fpr)
                status = get_key_rating(session, identity->fpr, &identity->comm_type);
        
            //    * call set_identity() to store
            adjust_pEp_trust_status(session, identity);            
            status = set_identity(session, identity);

        }
    }
    
    // FIXME: This is legacy. I presume it's a notification for the caller...
    // Revisit once I can talk to Volker
    if (identity->comm_type != PEP_ct_compromised &&
        identity->comm_type < PEP_ct_strong_but_unconfirmed)
        if (session->examine_identity)
            session->examine_identity(identity, session->examine_management);

    goto pEp_free;

enomem:
    status = PEP_OUT_OF_MEMORY;

pEp_free:
    free(default_own_id);
    free_identity(stored_ident);
    return status;
}

PEP_STATUS elect_ownkey(
        PEP_SESSION session, pEp_identity * identity
    )
{
    PEP_STATUS status;
    stringlist_t *keylist = NULL;

    free(identity->fpr);
    identity->fpr = NULL;

    status = find_private_keys(session, identity->address, &keylist);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;
    
    if (keylist != NULL && keylist->value != NULL)
    {
        char *_fpr = NULL;
        identity->comm_type = PEP_ct_unknown;

        stringlist_t *_keylist;
        for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
            bool is_own = false;
            
            status = own_key_is_listed(session, _keylist->value, &is_own);
            assert(status == PEP_STATUS_OK);
            if (status != PEP_STATUS_OK) {
                free_stringlist(keylist);
                return status;
            }
            
            if (is_own)
            {
                PEP_comm_type _comm_type_key;
                
                status = get_key_rating(session, _keylist->value, &_comm_type_key);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }
                
                if (_comm_type_key != PEP_ct_compromised &&
                    _comm_type_key != PEP_ct_unknown)
                {
                    if (identity->comm_type == PEP_ct_unknown ||
                        _comm_type_key > identity->comm_type)
                    {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
            }
        }
        
        if (_fpr)
        {
            identity->fpr = strdup(_fpr);
            assert(identity->fpr);
            if (identity->fpr == NULL)
            {
                free_stringlist(keylist);
                return PEP_OUT_OF_MEMORY;
            }
        }
        free_stringlist(keylist);
    }
    return PEP_STATUS_OK;
}

PEP_STATUS _has_usable_priv_key(PEP_SESSION session, char* fpr,
                                bool* is_usable) {
    
    bool has_private = false;
    PEP_STATUS status = contains_priv_key(session, fpr, &has_private);
    
    *is_usable = has_private;
    
    return status;
}

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags)
{

    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));
    assert(!EMPTYSTR(identity->user_id));

    if (!session || !identity || EMPTYSTR(identity->address) ||
        EMPTYSTR(identity->user_id))
        return PEP_ILLEGAL_VALUE;

    pEp_identity *stored_identity = NULL;
    char* revoked_fpr = NULL; 
    bool valid_key_found = false;
        
    char* default_own_id = NULL;
    status = get_default_own_userid(session, &default_own_id);

    // Deal with non-default user_ids.
    if (default_own_id && strcmp(default_own_id, identity->user_id) != 0) {
        
        status = set_userid_alias(session, default_own_id, identity->user_id);
        // Do we want this to be fatal? For now, we'll do it...
        if (status != PEP_STATUS_OK)
            goto pEp_free;
            
        free(identity->user_id);
        identity->user_id = strdup(default_own_id);
        if (identity->user_id == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
    }

    // NOTE: IF WE DON'T YET HAVE AN OWN_ID, WE IGNORE REFERENCES TO THIS ADDRESS IN THE
    // DB (WHICH MAY HAVE BEEN SET BEFORE MYSELF WAS CALLED BY RECEIVING AN EMAIL FROM
    // THIS ADDRESS), AS IT IS NOT AN OWN_IDENTITY AND HAS NO INFORMATION WE NEED OR WHAT TO
    // SET FOR MYSELF
    
    // Ok, so now, set up the own_identity:
    identity->comm_type = PEP_ct_pEp;
    identity->me = true;
    if(ignore_flags)
        identity->flags = 0;
    
    // Let's see if we have an identity record in the DB for 
    // this user_id + address
//    DEBUG_LOG("myself", "debug", identity->address);
 
    status = get_identity(session,
                          identity->address,
                          identity->user_id,
                          &stored_identity);

    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY) {
        status = PEP_OUT_OF_MEMORY;
        goto pEp_free;
    }

    // Set usernames - priority is input username > stored name > address
    // If there's an input username, we always patch the username with that
    // input.
    if (EMPTYSTR(identity->username)) {
        bool stored_uname = (stored_identity && !EMPTYSTR(stored_identity->username));
        char* uname = (stored_uname ? stored_identity->username : identity->address);
        free(identity->username);
        identity->username = strdup(uname);
        if (identity->username == NULL) {
            status = PEP_OUT_OF_MEMORY;
            goto pEp_free;
        }
    }

    // ignore input fpr

    if (identity->fpr) {
        free(identity->fpr);
        identity->fpr = NULL;
    }

    // check stored identity
    if (stored_identity && !EMPTYSTR(stored_identity->fpr)) {
        // Fall back / retrieve
        status = validate_fpr(session, stored_identity, false);
        if (status == PEP_OUT_OF_MEMORY)
            goto pEp_free;
        if (status == PEP_STATUS_OK) {
            if (stored_identity->comm_type >= PEP_ct_strong_but_unconfirmed) {
                identity->fpr = strdup(stored_identity->fpr);
                assert(identity->fpr);
                if (!identity->fpr) {
                    status = PEP_OUT_OF_MEMORY;
                    goto pEp_free;
                }
                valid_key_found = true;            
            }
            else {
                bool revoked = false;
                status = key_revoked(session, stored_identity->fpr, &revoked);
                if (status)
                    goto pEp_free;
                if (revoked) {
                    revoked_fpr = strdup(stored_identity->fpr);
                    assert(revoked_fpr);
                    if (!revoked_fpr) {
                        status = PEP_OUT_OF_MEMORY;
                        goto pEp_free;
                    }
                }
            }
        }
    }
    
    // Nothing left to do but generate a key
    if (!valid_key_found) {
        if (!do_keygen)
            status = PEP_GET_KEY_FAILED;
        else {
// /            DEBUG_LOG("Generating key pair", "debug", identity->address);

            free(identity->fpr);
            identity->fpr = NULL;
            status = generate_keypair(session, identity);
            assert(status != PEP_OUT_OF_MEMORY);

            if (status != PEP_STATUS_OK) {
                char buf[11];
                snprintf(buf, 11, "%d", status); // uh, this is kludgey. FIXME
//                DEBUG_LOG("Generating key pair failed", "debug", buf);
            }        
            else {
                valid_key_found = true;
                if (revoked_fpr) {
                    status = set_revoked(session, revoked_fpr,
                                         stored_identity->fpr, time(NULL));
                }
            }
        }
    }

    if (valid_key_found) {
        identity->comm_type = PEP_ct_pEp;
        status = PEP_STATUS_OK;
    }
    else {
        free(identity->fpr);
        identity->fpr = NULL;
        identity->comm_type = PEP_ct_unknown;
    }
    
    status = set_identity(session, identity);
    if (status == PEP_STATUS_OK)
        status = set_as_pEp_user(session, identity);

pEp_free:    
    free(default_own_id);
    free(revoked_fpr);                     
    free_identity(stored_identity);
    return status;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    return _myself(session, identity, true, false);
}

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    )
{
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    session->examine_management = management;
    session->examine_identity = examine_identity;

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS do_keymanagement(
        PEP_SESSION session,
        retrieve_next_identity_t retrieve_next_identity,
        messageToSend_t messageToSend,
        void *management
    )
{
    pEp_identity *identity;
    PEP_STATUS status;

    assert(session && retrieve_next_identity);
    if (!(session && retrieve_next_identity))
        return PEP_ILLEGAL_VALUE;

    log_event(session, "keymanagement thread started", "pEp engine", NULL, NULL);

    while ((identity = retrieve_next_identity(management))) 
    {
        assert(identity->address);
        if(identity->address)
        {
            DEBUG_LOG("do_keymanagement", "retrieve_next_identity", identity->address);

            if (identity->me) {
                status = myself(session, identity);
            } else {
                status = recv_key(session, identity->address);
            }

            assert(status != PEP_OUT_OF_MEMORY);
            if(status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;
        }
        free_identity(identity);
    }

    log_event(session, "keymanagement thread shutdown", "pEp engine", NULL, NULL);

    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS key_mistrusted(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->fpr));

    if (!(session && ident && ident->fpr))
        return PEP_ILLEGAL_VALUE;

    if (ident->me)
    {
        revoke_key(session, ident->fpr, NULL);
        myself(session, ident);
    }
    else
    {
        // for undo
        if (session->cached_mistrusted)
            free(session->cached_mistrusted);
        session->cached_mistrusted = identity_dup(ident);
        
        // set mistrust for this user_id/keypair (even if there's not an
        // identity set yet, this is important, as we need to record the mistrust
        // action)
        
        // double-check to be sure key is even in the DB
        if (ident->fpr)
            status = set_pgp_keypair(session, ident->fpr);

        // We set this temporarily but will grab it back from the cache afterwards
        ident->comm_type = PEP_ct_mistrusted;
        status = set_trust(session, ident);
        ident->comm_type = session->cached_mistrusted->comm_type;
        
        if (status == PEP_STATUS_OK)
            // cascade that mistrust for anyone using this key
            status = mark_as_compromised(session, ident->fpr);
        if (status == PEP_STATUS_OK)
            status = remove_fpr_as_default(session, ident->fpr);
        if (status == PEP_STATUS_OK)
            status = add_mistrusted_key(session, ident->fpr);
    }

    return status;
}

DYNAMIC_API PEP_STATUS undo_last_mistrust(PEP_SESSION session) {
    assert(session);
    
    if (!session)
        return PEP_ILLEGAL_VALUE;
    
    PEP_STATUS status = PEP_STATUS_OK;
        
    pEp_identity* cached_ident = session->cached_mistrusted;
    
    if (!cached_ident)
        status = PEP_CANNOT_FIND_IDENTITY;
    else {
        status = delete_mistrusted_key(session, cached_ident->fpr);
        if (status == PEP_STATUS_OK) {
            status = set_identity(session, cached_ident);
            // THIS SHOULDN'T BE NECESSARY - PREVIOUS VALUE WAS IN THE DB
            // if (status == PEP_STATUS_OK) {
            //     if ((cached_ident->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
            //         status = set_as_pEp_user(session, cached_ident);
            // }            
            free_identity(session->cached_mistrusted);
        }
    }
    
    session->cached_mistrusted = NULL;
    
    return status;
}

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->fpr));
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));

    if (!(session && ident && ident->fpr && ident->fpr[0] != '\0' && ident->address &&
            ident->user_id))
        return PEP_ILLEGAL_VALUE;

    // we do not change the input struct at ALL.
    pEp_identity* input_copy = identity_dup(ident);
    
    pEp_identity* tmp_ident = NULL;
    
    status = get_trust(session, input_copy);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    PEP_comm_type new_trust = PEP_ct_unknown;
    status = get_key_rating(session, ident->fpr, &new_trust);
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    bool pEp_user = false;
    
    status = is_pEp_user(session, ident, &pEp_user);
    
    if (pEp_user && new_trust >= PEP_ct_unconfirmed_encryption)
        input_copy->comm_type = PEP_ct_pEp_unconfirmed;
    else
        input_copy->comm_type = new_trust;
        
    status = set_trust(session, input_copy);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;

    bool mistrusted_key = false;
        
    status = is_mistrusted_key(session, ident->fpr, &mistrusted_key);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    if (mistrusted_key)
        status = delete_mistrusted_key(session, ident->fpr);

    if (status != PEP_STATUS_OK)
        goto pEp_free;
        
    tmp_ident = new_identity(ident->address, NULL, ident->user_id, NULL);

    if (!tmp_ident)
        return PEP_OUT_OF_MEMORY;
    
    if (is_me(session, tmp_ident))
        status = myself(session, tmp_ident);
    else
        status = update_identity(session, tmp_ident);
    
    if (status != PEP_STATUS_OK)
        goto pEp_free;
    
    // remove as default if necessary
    if (!EMPTYSTR(tmp_ident->fpr) && strcmp(tmp_ident->fpr, ident->fpr) == 0) {
        free(tmp_ident->fpr);
        tmp_ident->fpr = NULL;
        tmp_ident->comm_type = PEP_ct_unknown;
        status = set_identity(session, tmp_ident);
        if (status != PEP_STATUS_OK)
            goto pEp_free;
    }
    
    char* user_default = NULL;
    get_main_user_fpr(session, tmp_ident->user_id, &user_default);
    
    if (!EMPTYSTR(user_default)) {
        if (strcmp(user_default, ident->fpr) == 0)
            status = refresh_userid_default_key(session, ident->user_id);
        if (status != PEP_STATUS_OK)
            goto pEp_free;    
    }
            
pEp_free:
    free_identity(tmp_ident);
    free_identity(input_copy);
    return status;
}

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    )
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(ident);
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));
    assert(!EMPTYSTR(ident->fpr));

    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr))
        return PEP_ILLEGAL_VALUE;

    //bool ident_has_trusted_default = false;
    char* ident_default_fpr = NULL;

    // Before we do anything, be sure the input fpr is even eligible to be trusted
    PEP_comm_type input_default_ct = PEP_ct_unknown;
    status = get_key_rating(session, ident->fpr, &input_default_ct);
    if (input_default_ct < PEP_ct_strong_but_unconfirmed)
        return PEP_KEY_UNSUITABLE;

    status = set_pgp_keypair(session, ident->fpr);
    if (status != PEP_STATUS_OK)
        return status;

    bool me = is_me(session, ident);

    pEp_identity* ident_copy = identity_dup(ident);
    char* cached_fpr = NULL;

    // for setting up a temp trusted identity for the input fpr
    pEp_identity* tmp_id = NULL;

    // For later, in case we need to check the user default key
    pEp_identity* tmp_user_ident = NULL;

    if (me) {
        bool has_private = false;
        // first of all, does this key even have a private component.
        status = contains_priv_key(session, ident->fpr, &has_private);
        if (status != PEP_STATUS_OK && status != PEP_KEY_NOT_FOUND)
            goto pEp_free;
            
        if (has_private) {
            status = set_own_key(session, ident_copy, ident->fpr); 
            goto pEp_free;
        }
    }
    
    // Either it's not me, or it's me but the key has no private key. 
    // We're only talking about pub keys here. Moving on.
    
    // Save the input fpr, which we already tested as non-NULL
    cached_fpr = strdup(ident->fpr);

    // Set up a temp trusted identity for the input fpr without a comm type;
    tmp_id = new_identity(ident->address, ident->fpr, ident->user_id, NULL);
    
    // ->me isn't set, even if this is an own identity, so this will work.
    status = validate_fpr(session, tmp_id, false);
        
    if (status == PEP_STATUS_OK) {
        // Validate fpr gets trust DB or, when that fails, key comm type. we checked
        // above that the key was ok. (not revoked or expired), but we want the max.
        tmp_id->comm_type = _MAX(tmp_id->comm_type, input_default_ct) | PEP_ct_confirmed;

        // Get the default identity without setting the fpr                                       
        if (me)
            status = _myself(session, ident_copy, false, true);
        else    
            status = update_identity(session, ident_copy);
            
        ident_default_fpr = (EMPTYSTR(ident_copy->fpr) ? NULL : strdup(ident_copy->fpr));

        if (status == PEP_STATUS_OK) {
            bool trusted_default = false;

            // If there's no default, or the default is different from the input...
            if (me || EMPTYSTR(ident_default_fpr) || strcmp(cached_fpr, ident_default_fpr) != 0) {
                
                // If the default fpr (if there is one) is trusted and key is strong enough,
                // don't replace, we just set the trusted bit on this key for this user_id...
                // (If there's no default fpr, this won't be true anyway.)
                if (me || (ident_copy->comm_type >= PEP_ct_strong_but_unconfirmed && 
                          (ident_copy->comm_type & PEP_ct_confirmed))) {                        

                    trusted_default = true;
                                    
                    status = set_trust(session, tmp_id);
                    input_default_ct = tmp_id->comm_type;                    
                }
                else {
                    free(ident_copy->fpr);
                    ident_copy->fpr = strdup(cached_fpr);
                    ident_copy->comm_type = tmp_id->comm_type;
                    status = set_identity(session, ident_copy); // replace identity default
                    if (status == PEP_STATUS_OK) {
                        if ((ident_copy->comm_type | PEP_ct_confirmed) == PEP_ct_pEp)
                            status = set_as_pEp_user(session, ident_copy);
                    }            
                }
            }
            else { // we're setting this on the default fpr
                ident->comm_type = tmp_id->comm_type;
                status = set_identity(session, ident);
                trusted_default = true;
            }
            if (status == PEP_STATUS_OK && !trusted_default) {
                // Ok, there wasn't a trusted default, so we replaced. Thus, we also
                // make sure there's a trusted default on the user_id. If there
                // is not, we make this the default.
                char* user_default = NULL;
                status = get_main_user_fpr(session, ident->user_id, &user_default);
            
                if (status == PEP_STATUS_OK && user_default) {
                    tmp_user_ident = new_identity(ident->address, 
                                                  user_default, 
                                                  ident->user_id, 
                                                  NULL);
                    if (!tmp_user_ident)
                        status = PEP_OUT_OF_MEMORY;
                    else {
                        status = validate_fpr(session, tmp_user_ident, false);
                        
                        if (status != PEP_STATUS_OK ||
                            tmp_user_ident->comm_type < PEP_ct_strong_but_unconfirmed ||
                            !(tmp_user_ident->comm_type & PEP_ct_confirmed)) 
                        {
                            char* trusted_fpr = (trusted_default ? ident_default_fpr : cached_fpr);
                            status = replace_main_user_fpr(session, ident->user_id, trusted_fpr);
                        } 
                    }
                }
            }
        }
    }    

pEp_free:
    free(ident_default_fpr);
    free(cached_fpr);
    free_identity(tmp_id);
    free_identity(ident_copy);
    free_identity(tmp_user_ident);
    return status;
}

DYNAMIC_API PEP_STATUS own_key_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    int count;
    
    assert(session && fpr && fpr[0] && listed);
    
    if (!(session && fpr && fpr[0] && listed))
        return PEP_ILLEGAL_VALUE;
    
    *listed = false;
    
    sqlite3_reset(session->own_key_is_listed);
    sqlite3_bind_text(session->own_key_is_listed, 1, fpr, -1, SQLITE_STATIC);
    
    int result;
    
    result = sqlite3_step(session->own_key_is_listed);
    switch (result) {
        case SQLITE_ROW:
            count = sqlite3_column_int(session->own_key_is_listed, 0);
            *listed = count > 0;
            status = PEP_STATUS_OK;
            break;
            
        default:
            status = PEP_UNKNOWN_ERROR;
    }
    
    sqlite3_reset(session->own_key_is_listed);
    return status;
}

PEP_STATUS _own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities,
        identity_flags_t excluded_flags
      )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && own_identities);
    if (!(session && own_identities))
        return PEP_ILLEGAL_VALUE;
    
    *own_identities = NULL;
    identity_list *_own_identities = new_identity_list(NULL);
    if (_own_identities == NULL)
        goto enomem;
    
    sqlite3_reset(session->own_identities_retrieve);
    
    int result;
    // address, fpr, username, user_id, comm_type, lang, flags
    const char *address = NULL;
    const char *fpr = NULL;
    const char *username = NULL;
    const char *user_id = NULL;
    PEP_comm_type comm_type = PEP_ct_unknown;
    const char *lang = NULL;
    unsigned int flags = 0;
    
    identity_list *_bl = _own_identities;
    do {
        sqlite3_bind_int(session->own_identities_retrieve, 1, excluded_flags);
        result = sqlite3_step(session->own_identities_retrieve);
        switch (result) {
            case SQLITE_ROW:
                address = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 0);
                fpr = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 1);
                user_id = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 2);
                username = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 3);
                comm_type = PEP_ct_pEp;
                lang = (const char *)
                    sqlite3_column_text(session->own_identities_retrieve, 4);
                flags = (unsigned int)
                    sqlite3_column_int(session->own_identities_retrieve, 5);

                pEp_identity *ident = new_identity(address, fpr, user_id, username);
                if (!ident)
                    goto enomem;
                ident->comm_type = comm_type;
                if (lang && lang[0]) {
                    ident->lang[0] = lang[0];
                    ident->lang[1] = lang[1];
                    ident->lang[2] = 0;
                }
                ident->me = true;
                ident->flags = flags;

                _bl = identity_list_add(_bl, ident);
                if (_bl == NULL) {
                    free_identity(ident);
                    goto enomem;
                }
                
                break;
                
            case SQLITE_DONE:
                break;
                
            default:
                status = PEP_UNKNOWN_ERROR;
                result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);
    
    sqlite3_reset(session->own_identities_retrieve);
    if (status == PEP_STATUS_OK)
        *own_identities = _own_identities;
    else
        free_identity_list(_own_identities);
    
    goto the_end;
    
enomem:
    free_identity_list(_own_identities);
    status = PEP_OUT_OF_MEMORY;
    
the_end:
    return status;
}

DYNAMIC_API PEP_STATUS own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities
      )
{
    return _own_identities_retrieve(session, own_identities, 0);
}

PEP_STATUS _own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist,
        identity_flags_t excluded_flags
      )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && keylist);
    if (!(session && keylist))
        return PEP_ILLEGAL_VALUE;
    
    *keylist = NULL;
    stringlist_t *_keylist = NULL;
    
    sqlite3_reset(session->own_keys_retrieve);
    
    int result;
    char *fpr = NULL;
    
    stringlist_t *_bl = _keylist;
    do {
        sqlite3_bind_int(session->own_keys_retrieve, 1, excluded_flags);
        result = sqlite3_step(session->own_keys_retrieve);
        switch (result) {
            case SQLITE_ROW:
                fpr = strdup((const char *) sqlite3_column_text(session->own_keys_retrieve, 0));
                if(fpr == NULL)
                    goto enomem;

                _bl = stringlist_add(_bl, fpr);
                if (_bl == NULL) {
                    free(fpr);
                    goto enomem;
                }
                if (_keylist == NULL)
                    _keylist = _bl;
                
                break;
                
            case SQLITE_DONE:
                break;
                
            default:
                status = PEP_UNKNOWN_ERROR;
                result = SQLITE_DONE;
        }
    } while (result != SQLITE_DONE);
    
    sqlite3_reset(session->own_keys_retrieve);
    if (status == PEP_STATUS_OK)
        *keylist = _keylist;
    else
        free_stringlist(_keylist);
    
    goto the_end;
    
enomem:
    free_stringlist(_keylist);
    status = PEP_OUT_OF_MEMORY;
    
the_end:
    return status;
}

DYNAMIC_API PEP_STATUS own_keys_retrieve(PEP_SESSION session, stringlist_t **keylist)
{
    return _own_keys_retrieve(session, keylist, 0);
}

DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       pEp_identity *me,
       const char *fpr
    )
{
    PEP_STATUS status = PEP_STATUS_OK;
    
    assert(session && me);
    assert(!EMPTYSTR(fpr));
    assert(!EMPTYSTR(me->address));
    assert(!EMPTYSTR(me->user_id));
    assert(!EMPTYSTR(me->username));

    if (!session || !me || EMPTYSTR(fpr) || EMPTYSTR(me->address) ||
            EMPTYSTR(me->user_id) || EMPTYSTR(me->username))
        return PEP_ILLEGAL_VALUE;

    status = _myself(session, me, false, true);
    // we do not need a valid key but dislike other errors
    if (status != PEP_STATUS_OK && status != PEP_GET_KEY_FAILED && status != PEP_KEY_UNSUITABLE)
        return status;
    status = PEP_STATUS_OK;
 
    if (me->fpr)
        free(me->fpr);
    me->fpr = strdup(fpr);
    assert(me->fpr);
    if (!me->fpr)
        return PEP_OUT_OF_MEMORY;

    status = validate_fpr(session, me, false);
    if (status)
        return status;

    me->comm_type = PEP_ct_pEp;
    status = set_identity(session, me);
    return status;
}

PEP_STATUS contains_priv_key(PEP_SESSION session, const char *fpr,
                             bool *has_private) {

    assert(session);
    assert(fpr);
    assert(has_private);
    
    if (!(session && fpr && has_private))
        return PEP_ILLEGAL_VALUE;

    return session->cryptotech[PEP_crypt_OpenPGP].contains_priv_key(session, fpr, has_private);
}

PEP_STATUS add_mistrusted_key(PEP_SESSION session, const char* fpr)
{
    int result;

    assert(!EMPTYSTR(fpr));
    
    if (!(session) || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->add_mistrusted_key);
    sqlite3_bind_text(session->add_mistrusted_key, 1, fpr, -1,
            SQLITE_STATIC);

    result = sqlite3_step(session->add_mistrusted_key);
    sqlite3_reset(session->add_mistrusted_key);

    if (result != SQLITE_DONE)
        return PEP_CANNOT_SET_PGP_KEYPAIR; // FIXME: Better status?

    return PEP_STATUS_OK;
}

PEP_STATUS delete_mistrusted_key(PEP_SESSION session, const char* fpr)
{
    int result;

    assert(!EMPTYSTR(fpr));
    
    if (!(session) || EMPTYSTR(fpr))
        return PEP_ILLEGAL_VALUE;

    sqlite3_reset(session->delete_mistrusted_key);
    sqlite3_bind_text(session->delete_mistrusted_key, 1, fpr, -1,
            SQLITE_STATIC);

    result = sqlite3_step(session->delete_mistrusted_key);
    sqlite3_reset(session->delete_mistrusted_key);

    if (result != SQLITE_DONE)
        return PEP_UNKNOWN_ERROR; // FIXME: Better status?

    return PEP_STATUS_OK;
}

PEP_STATUS is_mistrusted_key(PEP_SESSION session, const char* fpr,
                             bool* mistrusted)
{
    PEP_STATUS status = PEP_STATUS_OK;

    assert(session);
    assert(!EMPTYSTR(fpr));

    if (!(session && fpr))
        return PEP_ILLEGAL_VALUE;

    *mistrusted = false;

    sqlite3_reset(session->is_mistrusted_key);
    sqlite3_bind_text(session->is_mistrusted_key, 1, fpr, -1, SQLITE_STATIC);

    int result;

    result = sqlite3_step(session->is_mistrusted_key);
    switch (result) {
    case SQLITE_ROW:
        *mistrusted = sqlite3_column_int(session->is_mistrusted_key, 0);
        status = PEP_STATUS_OK;
        break;

    default:
        status = PEP_UNKNOWN_ERROR;
    }

    sqlite3_reset(session->is_mistrusted_key);
    return status;
}

#ifdef USE_GPG
PEP_STATUS pgp_find_trusted_private_keys(
        PEP_SESSION session, stringlist_t **keylist
    );

enum _pgp_thing {
    _pgp_none = 0,
    _pgp_fpr,
    _pgp_email,
    _pgp_name
};

static enum _pgp_thing _pgp_thing_next(enum _pgp_thing thing)
{
    switch (thing) {
        case _pgp_fpr:
            return _pgp_email;
        case _pgp_email:
            return _pgp_name;
        case _pgp_name:
            return _pgp_fpr;
        default:
            return _pgp_fpr;
    }
}

PEP_STATUS pgp_import_ultimately_trusted_keypairs(PEP_SESSION session) {
    assert(session);
    if (!session)
        return PEP_ILLEGAL_VALUE;

    stringlist_t* priv_keylist = NULL;
    PEP_STATUS status = PEP_STATUS_OK;

    // 1. get keys
    status = pgp_find_trusted_private_keys(session, &priv_keylist);
    if (status)
        return status;

    pEp_identity *identity = NULL;
    stringlist_t *_sl;
	
    char *fpr = NULL;
    enum _pgp_thing thing = _pgp_none;
    for (_sl = priv_keylist; _sl && _sl->value; _sl = _sl->next) {
        thing = _pgp_thing_next(thing);
        switch (thing) {
            case _pgp_fpr:
                identity = new_identity(NULL, NULL, PEP_OWN_USERID, NULL);
                if (!identity)
                    status = PEP_OUT_OF_MEMORY;
                identity->me = true;
                fpr = strdup(_sl->value);
                assert(fpr);
                if (!fpr) {
                    status = PEP_OUT_OF_MEMORY;
                    free_identity(identity);
                }
                break;
            case _pgp_email:
                assert(identity);
                identity->address = strdup(_sl->value);
                assert(identity->address);
                if (!identity->address) {
                    status = PEP_OUT_OF_MEMORY;
                    free_identity(identity);
                }
                break;
            case _pgp_name:
                assert(identity);
                identity->username = strdup(_sl->value);
                assert(identity->username);
                if (!identity->username)
                    status = PEP_OUT_OF_MEMORY;
                else
                    status = set_own_key(session, identity, fpr);
                free_identity(identity);
                identity = NULL;
                break;
            default:
                assert(0);
                free_identity(identity);
                status = PEP_UNKNOWN_ERROR;
        }
        if (status)
            break;
    }
    
    free_stringlist(priv_keylist);
    return status;
}
#endif // USE_GPG
