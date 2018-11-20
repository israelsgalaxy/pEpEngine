// This file is under GNU General Public License 3.0
// see LICENSE.txt

#pragma once

#include "message.h"

#ifdef __cplusplus
extern "C" {
#endif


// base_decorate_message() - decorate a message with payload
//
//  parameters:
//      msg (inout)     message to decorate
//      payload (in)    payload to send
//      size (in)       size of payload
//      fpr (in)        optional key to sign or NULL
//
//  returns:
//      PEP_STATUS_OK and result on success or an error on failure
//
//  caveat:
//      on success (and only then) payload goes to the ownership of the msg
//      the ownership of the msg remains with the caller

PEP_STATUS base_decorate_message(
        message *msg,
        char *payload,
        size_t size,
        char *fpr
    );


// base_prepare_message() - prepare a sync message with payload
//
//  parameters:
//      me (in)         identity to use for the sender
//      partner (in)    identity to use for the receiver
//      payload (in)    payload to send
//      size (in)       size of payload
//      fpr (in)        optional key to sign or NULL
//      result (out)    message with payload
//
//  returns:
//      PEP_STATUS_OK and result on success or an error on failure
//
//  caveat:
//      on success (and only then) payload goes to the ownership of the result
//      the ownership of the result goes to the caller

PEP_STATUS base_prepare_message(
        const pEp_identity *me,
        const pEp_identity *partner,
        char *payload,
        size_t size,
        char *fpr,
        message **result
    );


#ifdef __cplusplus
}
#endif

