// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

// update_identity() - update identity information
//
//  parameters:
//      session (in)        session to use
//      identity (inout)    identity information of communication partner
//                          (identity->fpr is OUT ONLY), and at least
//                          .address must be set. 
//                          If .username is set, it will be used to set or patch
//                          the username record for this identity.                         
//  return value:
//      PEP_STATUS_OK if identity could be updated,
//      PEP_ILLEGAL_VALUE if called with illegal inputs, including an identity
//                        with .me set or with an own user_id specified in the
//                        *input* (see caveats) 
//      PEP_KEY_UNSUITABLE if a default key was found for this identity, no
//                         other acceptable keys were found; if this is returned,
//                         the reason for rejecting the first default key found
//                         may be found in the comm_type
//      any other value on error
//
//  caveat:
//      at least identity->address must be a non-empty UTF-8 string as input
//      update_identity() never writes flags; use set_identity_flags() for
//      writing
//      this function NEVER reads the incoming fpr, only writes to it.
//      this function will fail if called on an identity which, with its input
//      values, *explicitly* indicates it is an own identity (i.e. .me is set
//      to true on input, or a user_id is given AND it is a known own user_id).
//      however, it can RETURN an own identity if this is not indicated a
//      priori, and in fact will do so with prejudice when not faced with a
//      matching default (i.e. it is forced to search by address only).
//      if the identity is known to be an own identity (or the caller wishes
//      to make it one), call myself() on the identity instead.
//
//      FIXME: is this next point accurate?
//      if this function returns PEP_ct_unknown or PEP_ct_key_expired in
//      identity->comm_type, the caller must insert the identity into the
//      asynchronous management implementation, so retrieve_next_identity()
//      will return this identity later
//      END FIXME

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    );

// TODO: remove
// initialise_own_identities () - ensures that an own identity is complete
//
//  parameters:
//      session (in)        session to use
//      my_idents (inout)   identities of local user to quick-set
//                          For these, at least .address must be set.
//                          if no .user_id is set, AND the DB doesn't contain
//                          a default user_id, PEP_OWN_USERID will be used and
//                          become the perennial default for the DB.
//
//  return value:
//      PEP_STATUS_OK if identity could be set,
//      any other value on error
//
//  caveat:
//      this function does NOT generate keypairs. It is intended to
//      precede running of the engine on actual messages. It effectively
//      behaves like myself(), but when there would normally be key generation
//      (when there is no valid key, for example),
//      it instead stores an identity without keys.
//
//      N.B. to adapter devs - this function is likely unnecessary, so please
//      do not put work into exposing it yet. Tickets will be filed if need be.

// DYNAMIC_API PEP_STATUS initialise_own_identities(PEP_SESSION session,
//                                                  identity_list* my_idents);

// myself() - ensures that an own identity is complete
//
//  parameters:
//      session (in)        session to use
//      identity (inout)    identity of local user
//                          both .address and .user_id must be set.
//                          if .fpr is set, an attempt will be made to make
//                          that the default key for this identity after key
//                          validation
//                          if .fpr is not set, key retrieval is performed
//                          If .username is set, it will be used to set or patch
//                          the username record for this identity.                         
//
//  return value:
//      PEP_STATUS_OK if identity could be completed or was already complete,
//      any other value on error
//  caveat:
//      If an fpr was entered and is not a valid key, the reason for failure
//      is immediately returned in the status and, possibly, identity->comm_type
//      If a default own user_id exists in the database, an alias will 
//      be created for the default for the input user_id. The ENGINE'S default
//      user_id is always returned in the .user_id field
//      myself() NEVER elects keys from the keyring; it will only choose keys
//      which have been set up explicitly via myself(), or which were imported
//      during a first time DB setup from an OpenPGP keyring (compatibility only) 
//      this function generates a keypair on demand; because it's synchronous
//      it can need a decent amount of time to return
//      if you need to do this asynchronous, you need to return an identity
//      with retrieve_next_identity() where pEp_identity.me is true

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity);

PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags);

// retrieve_next_identity() - callback being called by do_keymanagement()
//
//  parameters:
//      management (in)     data structure to deliver (implementation defined)
//
//  return value:
//      identity to check or NULL to terminate do_keymanagement()
//      if given identity must be created with new_identity()
//      the identity struct is going to the ownership of this library
//      it must not be freed by the callee
//
//  caveat:
//      this callback has to block until an identity or NULL can be returned
//      an implementation is not provided by this library; instead it has to be
//      implemented by the user of this library

typedef pEp_identity *(*retrieve_next_identity_t)(void *management);


// examine_identity() - callback for appending to queue
//
//  parameters:
//      ident (in)          identity to examine
//      management (in)     data structure to deliver (implementation defined)
//
//  return value:
//      0 if identity was added successfully to queue or nonzero otherwise

typedef int (*examine_identity_t)(pEp_identity *ident, void *management);


// register_examine_function() - register examine_identity() callback
//
//  parameters:
//      session (in)            session to use
//      examine_identity (in)   examine_identity() function to register
//      management (in)     data structure to deliver (implementation defined)

DYNAMIC_API PEP_STATUS register_examine_function(
        PEP_SESSION session, 
        examine_identity_t examine_identity,
        void *management
    );


// do_keymanagement() - function to be run on an extra thread
//
//  parameters:
//      session (in)                session to use
//      retrieve_next_identity (in) pointer to retrieve_next_identity()
//                                  callback which returns at least a valid
//                                  address field in the identity struct
//      messageToSend (in)          callback for sending message by the
//                                  application
//      management (in)             management data to give to keymanagement
//                                  (implementation defined)
//
//  return value:
//      PEP_STATUS_OK if thread has to terminate successfully or any other
//      value on failure
//
//  caveat:
//      to ensure proper working of this library, a thread has to be started
//      with this function immediately after initialization
//
//      do_keymanagement() calls retrieve_next_identity(management)
//
//      messageToSend can only be null if no transport is application based
//      if transport system is not used it must not be NULL

DYNAMIC_API PEP_STATUS do_keymanagement(
        PEP_SESSION session,
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    );


// key_mistrusted() - mark key as being compromised
//
//  parameters:
//      session (in)        session to use
//      ident (in)          person and key which was compromised
//  caveat:
//      ident is INPUT ONLY. If you want updated trust on the identity, you'll have
//      to call update_identity or myself respectively after this.
//      N.B. If you are calling this on a key that is the identity or user default,
//      it will be removed as the default key for ANY identity and user for which
//      it is the default. Please keep in mind that the undo in undo_last_mistrust
//      will only undo the current identity's / it's user's default, not any
//      other identities which may be impacted (this will not affect most use
//      cases)

DYNAMIC_API PEP_STATUS key_mistrusted(
        PEP_SESSION session,
        pEp_identity *ident
    );

// trust_personal_key() - mark a key as trusted for a user
//
//  parameters:
//      session (in)        session to use
//      ident (in)          person and key to trust in
//
//  caveat:
//      the fields user_id, address and fpr must be supplied
//      for non-own users, this will 1) set the trust bit on its comm type in the DB,
//      2) set this key as the identity default if the current identity default
//      is not trusted, and 3) set this key as the user default if the current
//      user default is not trusted.
//      For an own user, this is simply a call to myself().

DYNAMIC_API PEP_STATUS trust_personal_key(
        PEP_SESSION session,
        pEp_identity *ident
    );


// key_reset_trust() - reset trust bit or explicitly mistrusted status for an identity and
//                     its accompanying key/user_id pair.
//  parameters:
//      session (in)        session to use
//      ident (in)          identity for person and key whose trust status is to be reset
//
//  caveat:
//      ident is INPUT ONLY. If you want updated trust on the identity, you'll have
//      to call update_identity or myself respectively after this.
//      N.B. If you are calling this on a key that is the identity or user default,
//      it will be removed as the default key for the identity and user (but is still
//      available for key election, it is just not the cached default anymore)

DYNAMIC_API PEP_STATUS key_reset_trust(
        PEP_SESSION session,
        pEp_identity *ident
    );

// own_key_is_listed() - returns true id key is listed as own key
//
//  parameters:
//      session (in)        session to use
//      fpr (in)            fingerprint of key to test
//      listed (out)        flags if key is own

DYNAMIC_API PEP_STATUS own_key_is_listed(
        PEP_SESSION session,
        const char *fpr,
        bool *listed
    );


// _own_identities_retrieve() - retrieve all own identities
//
//  parameters:
//      session (in)            session to use
//      own_identities (out)    list of own identities
//      excluded_flags (int)    flags to exclude from results
//
//  caveat:
//      the ownership of the copy of own_identities goes to the caller

DYNAMIC_API PEP_STATUS _own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities,
        identity_flags_t excluded_flags
    );

// own_identities_retrieve() - retrieve all own identities
//
//  parameters:
//      session (in)            session to use
//      own_identities (out)    list of own identities
//
//  caveat:
//      the ownership of the copy of own_identities goes to the caller

DYNAMIC_API PEP_STATUS own_identities_retrieve(
        PEP_SESSION session,
        identity_list **own_identities
    );

PEP_STATUS contains_priv_key(PEP_SESSION session, const char *fpr,
                             bool *has_private);

// _own_keys_retrieve() - retrieve all flagged keypair fingerprints 
//
//  parameters:
//      session (in)            session to use
//      keylist (out)           list of fingerprints
//      excluded_flags (int)    flags to exclude from results
//
//  caveat:
//      the ownership of the list goes to the caller
DYNAMIC_API PEP_STATUS _own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist,
        identity_flags_t excluded_flags
      );

// own_keys_retrieve() - retrieve all flagged keypair fingerprints 
//
//  parameters:
//      session (in)            session to use
//      keylist (out)           list of fingerprints
//
//  caveat:
//      the ownership of the list goes to the caller
DYNAMIC_API PEP_STATUS own_keys_retrieve(
        PEP_SESSION session,
        stringlist_t **keylist
      );

// set_own_key() - mark a key as own key
//
//  parameters:
//      session (in)            session to use
//      me (inout)              own identity this key is used for
//      fpr (in)                fingerprint of the key to mark as own key
//
//  caveat:
//      the key has to be in the key ring already
//      me->address, me->user_id and me->username must be set to valid data
//      myself() is called by set_own_key() without key generation
//      me->flags are ignored
//      me->address must not be an alias
//      me->fpr will be ignored and replaced by fpr

DYNAMIC_API PEP_STATUS set_own_key(
       PEP_SESSION session,
       pEp_identity *me,
       const char *fpr
    );

PEP_STATUS get_all_keys_for_user(PEP_SESSION session, 
                                 const char* user_id,
                                 stringlist_t** keys);


PEP_STATUS _myself(PEP_SESSION session, pEp_identity * identity, bool do_keygen, bool ignore_flags);

PEP_STATUS add_mistrusted_key(PEP_SESSION session, const char* fpr);
PEP_STATUS delete_mistrusted_key(PEP_SESSION session, const char* fpr);
PEP_STATUS is_mistrusted_key(PEP_SESSION session, const char* fpr, bool* mistrusted);
PEP_STATUS get_user_default_key(PEP_SESSION session, const char* user_id,
                                char** default_key);




// Only call on retrieval of previously stored identity!
// Also, we presume that if the stored_identity was sent in
// without an fpr, there wasn't one in the trust DB for this
// identity.
PEP_STATUS get_valid_pubkey(PEP_SESSION session,
                            pEp_identity* stored_identity,
                            bool* is_identity_default,
                            bool* is_user_default,
                            bool* is_address_default,
                            bool check_blacklist);

#ifdef __cplusplus
}
#endif
