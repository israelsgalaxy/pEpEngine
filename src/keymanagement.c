#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "pEp_internal.h"
#include "keymanagement.h"

#ifndef MIN
#define MIN(A, B) ((B) > (A) ? (A) : (B))
#endif

#ifndef EMPTYSTR
#define EMPTYSTR(STR) ((STR == NULL) || (STR)[0] == 0)
#endif

#define KEY_EXPIRE_DELTA (60 * 60 * 24 * 365)

DYNAMIC_API PEP_STATUS update_identity(
        PEP_SESSION session, pEp_identity * identity
    )
{
    pEp_identity *stored_identity;
    PEP_STATUS status;

    assert(session);
    assert(identity);
    assert(!EMPTYSTR(identity->address));

    if (!(session && identity && !EMPTYSTR(identity->address)))
        return PEP_ILLEGAL_VALUE;

    status = get_identity(session, identity->address, &stored_identity);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    if (stored_identity) {
        PEP_comm_type _comm_type_key;
        status = get_key_rating(session, stored_identity->fpr, &_comm_type_key);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;

        if (EMPTYSTR(identity->user_id)) {
            free(identity->user_id);
            identity->user_id = strndup(stored_identity->user_id, stored_identity->user_id_size);
            assert(identity->user_id);
            if (identity->user_id == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->user_id_size = stored_identity->user_id_size;
        }

        if (EMPTYSTR(identity->username)) {
            free(identity->username);
            identity->username = strndup(stored_identity->username, stored_identity->username_size);
            assert(identity->username);
            if (identity->username == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->username_size = stored_identity->username_size;
        }

        if (EMPTYSTR(identity->fpr)) {
            identity->fpr = strndup(stored_identity->fpr, stored_identity->fpr_size);
            assert(identity->fpr);
            if (identity->fpr == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->fpr_size = stored_identity->fpr_size;
            if (_comm_type_key < PEP_ct_unconfirmed_encryption) {
                identity->comm_type = _comm_type_key;
            }
            else {
                identity->comm_type = stored_identity->comm_type;
            }
        }
        else /* !EMPTYSTR(identity->fpr) */ {
            if (strncmp(identity->fpr, stored_identity->fpr, stored_identity->fpr_size) == 0) {
                if (_comm_type_key < PEP_ct_unconfirmed_encryption) {
                    identity->comm_type = _comm_type_key;
                }else{
                    identity->comm_type = stored_identity->comm_type;
                    if (identity->comm_type == PEP_ct_unknown) {
                        identity->comm_type = _comm_type_key;
                    }
                }
            } else {
                status = get_trust(session, identity);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY)
                    return PEP_OUT_OF_MEMORY;
                if (identity->comm_type < stored_identity->comm_type)
                    identity->comm_type = PEP_ct_unknown;
            }
        }

        if (identity->lang[0] == 0) {
            identity->lang[0] = stored_identity->lang[0];
            identity->lang[1] = stored_identity->lang[1];
            identity->lang[2] = 0;
        }
    }
    else /* stored_identity == NULL */ {
        if (!EMPTYSTR(identity->fpr)) {
            PEP_comm_type _comm_type_key;

            status = get_key_rating(session, identity->fpr, &_comm_type_key);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;

            identity->comm_type = _comm_type_key;
        }
        else /* EMPTYSTR(identity->fpr) */ {
            PEP_STATUS status;
            stringlist_t *keylist;
            char *_fpr = NULL;
            identity->comm_type = PEP_ct_unknown;

            status = find_keys(session, identity->address, &keylist);
            assert(status != PEP_OUT_OF_MEMORY);
            if (status == PEP_OUT_OF_MEMORY)
                return PEP_OUT_OF_MEMORY;

            stringlist_t *_keylist;
            for (_keylist = keylist; _keylist && _keylist->value; _keylist = _keylist->next) {
                PEP_comm_type _comm_type_key;

                status = get_key_rating(session, _keylist->value, &_comm_type_key);
                assert(status != PEP_OUT_OF_MEMORY);
                if (status == PEP_OUT_OF_MEMORY) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }

                if (identity->comm_type == PEP_ct_unknown) {
                    if (_comm_type_key != PEP_ct_compromized && _comm_type_key != PEP_ct_unknown) {
                        identity->comm_type = _comm_type_key;
                        _fpr = _keylist->value;
                    }
                }
                else {
                    if (_comm_type_key != PEP_ct_compromized && _comm_type_key != PEP_ct_unknown) {
                        if (_comm_type_key > identity->comm_type) {
                            identity->comm_type = _comm_type_key;
                            _fpr = _keylist->value;
                        }
                    }
                }
            }

            if (_fpr) {
                free(identity->fpr);

                identity->fpr = strdup(_fpr);
                if (identity->fpr == NULL) {
                    free_stringlist(keylist);
                    return PEP_OUT_OF_MEMORY;
                }
                identity->fpr_size = strlen(identity->fpr);
            }
            free_stringlist(keylist);
        }
    }

    status = PEP_STATUS_OK;

    if (identity->comm_type != PEP_ct_unknown && !EMPTYSTR(identity->user_id)) {
        assert(!EMPTYSTR(identity->username)); // this should not happen

        if (EMPTYSTR(identity->username)) { // mitigate
            free(identity->username);
            identity->username = strdup("anonymous");
            if (identity->username == NULL)
                return PEP_OUT_OF_MEMORY;
            identity->username_size = 9;
        }

        status = set_identity(session, identity);
        assert(status == PEP_STATUS_OK);
    }

    if (identity->comm_type != PEP_ct_compromized &&
            identity->comm_type < PEP_ct_strong_but_unconfirmed)
        if (session->examine_identity)
            session->examine_identity(identity, session->examine_management);

    return status;
}

DYNAMIC_API PEP_STATUS myself(PEP_SESSION session, pEp_identity * identity)
{
    PEP_STATUS status;
    stringlist_t *keylist = NULL;

    assert(session);
    assert(identity);
    assert(identity->address);
    assert(identity->username);
    assert(identity->user_id);

    if (!(session && identity && identity->address && identity->username &&
                identity->user_id))
        return PEP_ILLEGAL_VALUE;

    identity->comm_type = PEP_ct_pEp;
    identity->me = true;

    DEBUG_LOG("myself", "debug", identity->address);

    status = find_keys(session, identity->address, &keylist);
    assert(status != PEP_OUT_OF_MEMORY);
    if (status == PEP_OUT_OF_MEMORY)
        return PEP_OUT_OF_MEMORY;

    if (keylist == NULL || keylist->value == NULL) {
        DEBUG_LOG("generating key pair", "debug", identity->address);
        status = generate_keypair(session, identity);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status != PEP_STATUS_OK) {
            char buf[11];
            snprintf(buf, 11, "%d", status);
            DEBUG_LOG("generating key pair failed", "debug", buf);
            return status;
        }

        status = find_keys(session, identity->address, &keylist);
        assert(status != PEP_OUT_OF_MEMORY);
        if (status == PEP_OUT_OF_MEMORY)
            return PEP_OUT_OF_MEMORY;

        assert(keylist && keylist->value);
        if (keylist == NULL || keylist->value == NULL) {
            return PEP_UNKNOWN_ERROR;
        }
    }
    else {
        bool expired;
        status = key_expired(session, keylist->value, &expired);
        assert(status == PEP_STATUS_OK);

        if (status == PEP_STATUS_OK && expired) {
            timestamp *ts = new_timestamp(time(NULL) + KEY_EXPIRE_DELTA);
            renew_key(session, keylist->value, ts);
            free_timestamp(ts);
        }
    }

    if (identity->fpr)
        free(identity->fpr);
    identity->fpr = strdup(keylist->value);
    assert(identity->fpr);
    free_stringlist(keylist);
    if (identity->fpr == NULL)
        return PEP_OUT_OF_MEMORY;
    identity->fpr_size = strlen(identity->fpr);

    status = set_identity(session, identity);
    assert(status == PEP_STATUS_OK);

    return PEP_STATUS_OK;
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
        retrieve_next_identity_t retrieve_next_identity,
        void *management
    )
{
    PEP_SESSION session;
    pEp_identity *identity;
    PEP_STATUS status = init(&session);

    assert(status == PEP_STATUS_OK);
    if (status != PEP_STATUS_OK)
        return status;

    assert(retrieve_next_identity);
    assert(management);

    log_event(session, "keymanagement thread started", "pEp engine", NULL, NULL);

    while ((identity = retrieve_next_identity(management))) {
        assert(identity->address);
        DEBUG_LOG("do_keymanagement", "retrieve_next_identity", identity->address);
        if (identity->me) {
            status = myself(session, identity);
            assert(status != PEP_OUT_OF_MEMORY);
        } else {
            status = recv_key(session, identity->address);
            assert(status != PEP_OUT_OF_MEMORY);
        }
        free_identity(identity);
    }

    log_event(session, "keymanagement thread shutdown", "pEp engine", NULL, NULL);

    release(session);
    return PEP_STATUS_OK;
}

DYNAMIC_API PEP_STATUS key_compromized(
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
        revoke_key(session, ident->fpr, NULL);
    status = mark_as_compromized(session, ident->fpr);

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
    assert(!ident->me);
    assert(!EMPTYSTR(ident->fpr));
    assert(!EMPTYSTR(ident->address));
    assert(!EMPTYSTR(ident->user_id));

    if (!(session && ident && !ident->me && ident->fpr && ident->address &&
            ident->user_id))
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type == PEP_ct_mistrusted)
        ident->comm_type = PEP_ct_unknown;
    else
        ident->comm_type &= ~PEP_ct_confirmed;

    status = set_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type == PEP_ct_unknown)
        status = update_identity(session, ident);
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
    assert(!ident->me);

    if (!ident || EMPTYSTR(ident->address) || EMPTYSTR(ident->user_id) ||
            EMPTYSTR(ident->fpr) || ident->me)
        return PEP_ILLEGAL_VALUE;

    status = update_identity(session, ident);
    if (status != PEP_STATUS_OK)
        return status;

    if (ident->comm_type > PEP_ct_strong_but_unconfirmed) {
        ident->comm_type |= PEP_ct_confirmed;
        status = set_identity(session, ident);
    }
    else {
        // MISSING: S/MIME has to be handled depending on trusted CAs
        status = PEP_CANNOT_SET_TRUST;
    }

    return status;
}

