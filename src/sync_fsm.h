#pragma once

// state machine for DeviceState

#include "pEpEngine.h"

#ifdef __cplusplus
extern "C" {
#endif

// types

typedef pEp_identity * Identity;
typedef union _param { const Identity partner; const stringlist_t *keylist; } param_t;

// error values

typedef enum _fsm_error {
    invalid_state = -1,
    invalid_event = -2
} fsm_error;

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
    Init, 
    KeyGen, 
    CannotDecrypt, 
    Beacon, 
    HandshakeRequest, 
    HandshakeRejected, 
    HandshakeAccepted, 
    ReceiveGroupKeys, 
    Cancel, 
    Reject
} DeviceState_event;

// actions

PEP_STATUS sendBeacon(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS sendHandshakeRequest(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS showHandshake(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS reject(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS storeGroupKeys(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS sendOwnKeys(PEP_SESSION session, DeviceState_state state, const Identity partner);
PEP_STATUS transmitGroupKeys(PEP_SESSION session, DeviceState_state state, const Identity partner);

// state machine

DeviceState_state fsm_DeviceState(
        PEP_SESSION session,
        DeviceState_state state,
        DeviceState_event event,
        const Identity partner,
        DeviceState_state state_partner
    );

// driver

PEP_STATUS fsm_DeviceState_inject(
        PEP_SESSION session,
        DeviceState_event event,
        Identity partner,
        DeviceState_state state_partner
    );

#ifdef __cplusplus
}
#endif

