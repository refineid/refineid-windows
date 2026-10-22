// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The PKCS#11 functions a development build lists: each calls the
//! function of the same name and reports a failing return to the Windows
//! Event Log through `refineid-dev-errors`, by its `CKR_` name.
//!
//! A function's answers are not failures: the values PKCS#11 v2.40 has it
//! return to a caller that probes, such as a buffer too small for the
//! length query, a token not present, an attribute the object does not
//! have, or no slot event. Release builds list the functions themselves
//! and compile none of this.

use crate::ck::{
    CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID,
    CKR_NO_EVENT, CKR_OK, CKR_TOKEN_NOT_PRESENT, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN, CkAttributePtr, CkBbool, CkBytePtr, CkFlags, CkInfoPtr,
    CkMechanismInfoPtr, CkMechanismPtr, CkMechanismType, CkMechanismTypePtr, CkNotify,
    CkObjectHandle, CkObjectHandlePtr, CkRv, CkSessionHandle, CkSessionHandlePtr, CkSessionInfoPtr,
    CkSlotId, CkSlotIdPtr, CkSlotInfoPtr, CkTokenInfoPtr, CkUlong, CkUlongPtr, CkUserType,
    CkUtf8CharPtr, CkVoidPtr,
};

/// Defines, for each function, a wrapper of the same name and signature
/// that reports every value but `CKR_OK` and the listed answers.
macro_rules! reported {
    ($($name:ident as $function:ident($($argument:ident: $type:ty),*) answers [$($answer:ident),*];)*) => {
        $(
            #[doc = concat!("`", stringify!($function), "`, reporting its failures.")]
            pub unsafe extern "C" fn $name($($argument: $type),*) -> CkRv {
                // SAFETY: the caller's contract for this function passes on
                // unchanged.
                let rv = unsafe { super::$name($($argument),*) };
                if rv != CKR_OK $(&& rv != $answer)* {
                    refineid_dev_errors::report!(
                        Pkcs11,
                        concat!(stringify!($function), " failed"),
                        name crate::ck::rv_name(rv)
                    );
                }
                rv
            }
        )*
    };
}

reported! {
    c_initialize as C_Initialize(init_args: CkVoidPtr) answers [CKR_CRYPTOKI_ALREADY_INITIALIZED];
    c_finalize as C_Finalize(reserved: CkVoidPtr) answers [];
    c_get_info as C_GetInfo(info: CkInfoPtr) answers [];
    c_get_slot_list as C_GetSlotList(
        token_present: CkBbool,
        slot_list: CkSlotIdPtr,
        count: CkUlongPtr
    ) answers [CKR_BUFFER_TOO_SMALL];
    c_get_slot_info as C_GetSlotInfo(slot_id: CkSlotId, info: CkSlotInfoPtr) answers [];
    c_get_token_info as C_GetTokenInfo(
        slot_id: CkSlotId,
        info: CkTokenInfoPtr
    ) answers [CKR_TOKEN_NOT_PRESENT];
    c_get_mechanism_list as C_GetMechanismList(
        slot_id: CkSlotId,
        mechanism_list: CkMechanismTypePtr,
        count: CkUlongPtr
    ) answers [CKR_BUFFER_TOO_SMALL];
    c_get_mechanism_info as C_GetMechanismInfo(
        slot_id: CkSlotId,
        mechanism: CkMechanismType,
        info: CkMechanismInfoPtr
    ) answers [CKR_MECHANISM_INVALID];
    c_open_session as C_OpenSession(
        slot_id: CkSlotId,
        flags: CkFlags,
        application: CkVoidPtr,
        notify: CkNotify,
        session: CkSessionHandlePtr
    ) answers [];
    c_close_session as C_CloseSession(session: CkSessionHandle) answers [];
    c_close_all_sessions as C_CloseAllSessions(slot_id: CkSlotId) answers [];
    c_get_session_info as C_GetSessionInfo(
        session: CkSessionHandle,
        info: CkSessionInfoPtr
    ) answers [];
    c_login as C_Login(
        session: CkSessionHandle,
        user_type: CkUserType,
        pin_ptr: CkUtf8CharPtr,
        pin_len: CkUlong
    ) answers [CKR_USER_ALREADY_LOGGED_IN];
    c_logout as C_Logout(session: CkSessionHandle) answers [CKR_USER_NOT_LOGGED_IN];
    c_get_attribute_value as C_GetAttributeValue(
        session: CkSessionHandle,
        object: CkObjectHandle,
        template: CkAttributePtr,
        count: CkUlong
    ) answers [CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL];
    c_find_objects_init as C_FindObjectsInit(
        session: CkSessionHandle,
        template: CkAttributePtr,
        count: CkUlong
    ) answers [];
    c_find_objects as C_FindObjects(
        session: CkSessionHandle,
        object: CkObjectHandlePtr,
        max_count: CkUlong,
        count: CkUlongPtr
    ) answers [];
    c_find_objects_final as C_FindObjectsFinal(session: CkSessionHandle) answers [];
    c_sign_init as C_SignInit(
        session: CkSessionHandle,
        mechanism: CkMechanismPtr,
        key: CkObjectHandle
    ) answers [];
    c_sign as C_Sign(
        session: CkSessionHandle,
        data: CkBytePtr,
        data_len: CkUlong,
        signature: CkBytePtr,
        signature_len: CkUlongPtr
    ) answers [CKR_BUFFER_TOO_SMALL];
    c_verify_init as C_VerifyInit(
        session: CkSessionHandle,
        mechanism: CkMechanismPtr,
        key: CkObjectHandle
    ) answers [];
    c_verify as C_Verify(
        session: CkSessionHandle,
        data: CkBytePtr,
        data_len: CkUlong,
        signature: CkBytePtr,
        signature_len: CkUlong
    ) answers [];
    c_wait_for_slot_event as C_WaitForSlotEvent(
        flags: CkFlags,
        slot: CkSlotIdPtr,
        reserved: CkVoidPtr
    ) answers [CKR_NO_EVENT, CKR_FUNCTION_NOT_SUPPORTED];
}
