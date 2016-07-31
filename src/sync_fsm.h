#pragma once

// state machine for DeviceState

#include "pEpEngine.h"
#include "../asn.1/DeviceGroup-Protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

// types

typedef pEp_identity * Identity;
typedef stringlist_t * Stringlist;
typedef union _param { Identity partner; stringlist_t *keylist; } param_t;

// error values

typedef enum _fsm_error {
    invalid_state = -2,
    invalid_event = -3
} fsm_error;

// conditions

bool storedGroupKeys(PEP_SESSION session);
bool keyElectionWon(PEP_SESSION session, Identity partner);

// states

typedef enum _DeviceState_state {
    DeviceState_state_NONE = 0,
    InitState, 
    Sole, 
    HandshakingSole, 
    WaitForGroupKeys, 
    Grouped
} DeviceState_state;

// events

typedef enum _DeviceState_event {
    DeviceState_event_NONE = 0,
    Init = 1,
    Beacon = 2,
    HandshakeRequest = 3,
    GroupKeys = 4,
    KeyGen, 
    CannotDecrypt, 
    HandshakeRejected, 
    HandshakeAccepted, 
    Cancel, 
    Reject, 
    Hand
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendHandshakeRequest(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS showHandshake(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS reject(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS storeGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);
PEP_STATUS sendGroupKeys(PEP_SESSION session, DeviceState_state state, Identity partner, void *extra);

// message receiver

PEP_STATUS receive_DeviceState_msg(PEP_SESSION session, DeviceGroup_Protocol_t *msg);

// state machine

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        Identity partner,
        void *extra
    );

// driver

DYNAMIC_API PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        void *extra
    );

#ifdef __cplusplus
}
#endif

