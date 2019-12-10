// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"
#include "keymanagement.h"
#include "message.h"
#include "message_api.h"
#include "cryptotech.h"

#ifdef __cplusplus
extern "C" {
#endif

// key_reset_identity() - reset the default database status for the identity / keypair
//                        provided. If this corresponds to an own identity and a private key,
//                        also revoke the key, generate a new one, and communicate the 
//                        reset to recently contacted pEp partners for this identity.
//
//                        If it does not, remove the key from the keyring; the key's 
//                        status is completely fresh on next contact from the partner.
//
//                        If no key is provided, reset the identity default.
//
//                        Note that reset keys will be removed as defaults for all users and identities.
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL, we reset the default key
//                              this identity if there is one, and the user default if not.
//      ident (in)              identity for which the key reset should occur. Must contain 
//                              user_id and address. Must not be NULL.
//
//                              Note: ident->fpr field will be ignored.
//
//
DYNAMIC_API PEP_STATUS key_reset_identity(
        PEP_SESSION session,
        pEp_identity* ident,
        const char* fpr
    );

// key_reset_user() -  reset the default database status for the user / keypair
//                     provided. This will effectively perform key_reset_identity()
//                     each identity associated with the key and user_id, if a key is
//                     provided, and for each key (and all of their identities) if an fpr 
//                     is not.
//
//                     If the user_id is the own user_id, an fpr MUST be provided.
//                     For a reset of all own user keys, call key_reset_all_own_keys() instead.
//
//                     Note that reset keys will be removed as defaults for all users and identities.
//
//  parameters:
//      session (in)            session handle
//      user_id (in)            user_id for which the key reset should occur. If this 
//                              is the own user_id, fpr MUST NOT be NULL.
//      fpr (in)                fingerprint of key to reset.
//                              If NULL, we reset all default 
//                              keys for this user and all of its identities.
//                              *** However, it is forbidden to use the own user_id 
//                                  here when the fpr is NULL. For this functionality, 
//                                  call key_reset_all_own_keys ***

//
DYNAMIC_API PEP_STATUS key_reset_user(
        PEP_SESSION session,
        const char* user_id,
        const char* fpr
    );

// key_reset_all_own_keys() -  revoke and mistrust all own keys, generate new keys for all 
//                             own identities, and opportunistically communicate
//                             key reset information to people we have recently 
//                             contacted. 
//
// caveat: this will return PEP_CANNOT_FIND_IDENTITY if no own user yet exists.
//         HOWEVER, apps and adapters must decide if this is a reasonable state;
//         since the period where no own user exists will necessarily be very short
//         in most implementations, PEP_CANNOT_FIND_IDENTITY may be returned when 
//         there is some sort of DB corruption and we expect there to be an own user.
//         Apps are responsible for deciding whether or not this is an error condition;
//         one would expect that it generally is (rather than the uninitialised DB case)
//                             
//  parameters:
//      session (in)            session handle
//
DYNAMIC_API PEP_STATUS key_reset_all_own_keys(PEP_SESSION session);


// key_reset() - reset the database status for a key, removing all trust information
//               and default database connections. For own keys, also revoke the key
//               and communicate the revocation and new key to partners we have sent
//               mail to recently from the specific identity (i.e. address/user_id)
//               that contacted them. We also in this case set up information so that
//               if someone we mail uses the wrong key and wasn't yet contacted,
//               we can send them the reset information from the right address. 
//               For non-own keys, also remove key from the keyring.
//
//               Can be called manually or through another protocol.
//
//  parameters:
//      session (in)            session handle
//      fpr (in)                fingerprint of key to reset. If NULL and ident is NULL,
//                              we reset all keys for the own user. If NULL and ident is
//                              an own identity, we reset the default key for that
//                              identity. If that own identity has no default key, we
//                              reset the user default.
//                              if it is NULL and there is a non-own identity, we will reset 
//                              the default key for this identity if present, and user if not.
//      ident (in)              identity for which the key reset should occur.
//                              if NULL and fpr is non-NULL, we'll reset the key for all
//                              associated identities. If both ident and fpr are NULL, see 
//                              the fpr arg documentation.
//
//      Note: ident->fpr is always ignored
//
// Caveat: this is now used in large part for internal calls.
//         external apps should call key_reset_identity and key_reset_userdata
//         and this function should probably be removed from the dynamic api
PEP_STATUS key_reset(
        PEP_SESSION session,
        const char* fpr,
        pEp_identity* ident,
        identity_list** own_identities,
        stringlist_t** own_revoked_fprs
    );


PEP_STATUS key_reset_own_and_deliver_revocations(PEP_SESSION session, 
                                                 identity_list** own_identities, 
                                                 stringlist_t** revocations, 
                                                 stringlist_t** keys);


PEP_STATUS has_key_reset_been_sent(
        PEP_SESSION session, 
        const char* user_id, 
        const char* revoked_fpr,
        bool* contacted);

PEP_STATUS set_reset_contact_notified(
        PEP_SESSION session,
        const char* revoke_fpr,
        const char* contact_id
    );

PEP_STATUS receive_key_reset(PEP_SESSION session,
                             message* reset_msg);

PEP_STATUS create_standalone_key_reset_message(PEP_SESSION session,
                                               message** dst, 
                                               pEp_identity* recip,
                                               const char* old_fpr,
                                               const char* new_fpr);
                                               
PEP_STATUS send_key_reset_to_recents(PEP_SESSION session,
                                     const char* old_fpr, 
                                     const char* new_fpr);
    
#ifdef __cplusplus
}
#endif
