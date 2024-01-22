#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::convert::TryInto;
use std::os::raw::c_int;

use openthread_sys::*;

fn main() {
    unsafe {
        let instance = otInstanceInitSingle();
        let initted = otInstanceIsInitialized(instance);

        match initted {
            r if r == (true as _) => panic!("Instance should not be initialised already"),
            r if r == (false as _) => {}
            r => panic!("Unknown return value = {}", r),
        }
    }
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub extern "C" fn otPlatSettingsInit(_aInstance: *mut otInstance) {
    print!("otPlatSettingsInit");
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatSettingsDeinit(_aInstance: *mut otInstance) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatSettingsWipe(_aInstance: *mut otInstance) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatSettingsGet(
    _aInstance: *mut otInstance,
    _aKey: u16,
    _aIndex: c_int,
    _aValue: *mut u8,
    _aValueLength: *mut u16,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatSettingsAdd(
    _aInstance: *mut otInstance,
    _aKey: u16,
    _aValue: *const u8,
    _aValueLength: u16,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub extern "C" fn otPlatSettingsSet(
    _aInstance: *mut otInstance,
    _aKey: u16,
    _aValue: *const u8,
    _aValueLength: u16,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatSettingsDelete(
    _aInstance: *mut otInstance,
    _aKey: u16,
    _aIndex: c_int,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetPromiscuous(_aInstance: *mut otInstance) -> bool {
    false
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioSetPromiscuous(_aInstance: *mut otInstance, _aEnable: bool) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioAddSrcMatchShortEntry(
    _aInstance: *mut otInstance,
    _aShortAddress: otShortAddress,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioSetShortAddress(
    _aInstance: *mut otInstance,
    _aShortAddress: otShortAddress,
) {
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioEnableSrcMatch(_aInstance: *mut otInstance, _aEnable: bool) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioClearSrcMatchExtEntries(_aInstance: *mut otInstance) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioEnergyScan(
    _aInstance: *mut otInstance,
    _aScanChannel: u8,
    _aScanDuration: u16,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioClearSrcMatchShortEntries(_aInstance: *mut otInstance) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioAddSrcMatchExtEntry(
    _aInstance: *mut otInstance,
    _aExtAddress: *const otExtAddress,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioSetExtendedAddress(
    _aInstance: *mut otInstance,
    _aExtAddress: *const otExtAddress,
) {
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetIeeeEui64(
    _aInstance: *mut otInstance,
    _aIeeeEui64: *mut u8,
) {
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetReceiveSensitivity(_aInstance: *mut otInstance) -> i8 {
    0
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioSleep(_aInstance: *mut otInstance) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetRssi(_aInstance: *mut otInstance) -> i8 {
    0
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatReset(_aInstance: *mut otInstance) -> i8 {
    0
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioDisable(_aInstance: *mut otInstance) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetTransmitBuffer(
    _aInstance: *mut otInstance,
) -> *mut otRadioFrame {
    let mut aPsdu: Box<u8> = Box::new(128);
    //let aAesKey: Box<u8> = Box::new(16);
    // let aRadioIeInfo = otRadioIeInfo {
    //     mNetworkTimeOffset: 0,
    //     mTimeIeOffset: 0,
    //     mTimeSyncSeq: 0
    // };

    /*
        let aTxInfo = otRadioFrame__bindgen_ty_1__bindgen_ty_1 {
            mAesKey: &*aAesKey,
            mIeInfo: &aRadioIeInfo,
            mMaxCsmaBackoffs: 0,
            mMaxFrameRetries: 0,
            _bitfield_1: bitfield_tx,
            __bindgen_padding_0: padding_tx
        };
    */
    let aRxInfo = otRadioFrame__bindgen_ty_1__bindgen_ty_2 {
        mTimestamp: 0,
        mAckFrameCounter: 0,
        mAckKeyId: 0,
        mRssi: 0,
        mLqi: 0,
        _bitfield_align_1: Default::default(),
        _bitfield_1: __BindgenBitfieldUnit::new([1]),
        //__bindgen_padding_0: [0; 5]
    };

    let aInfo = otRadioFrame__bindgen_ty_1 {
        //        mTxInfo: aTxInfo,
        mRxInfo: aRxInfo,
    };

    let mut aFrame = otRadioFrame {
        mPsdu: &mut *aPsdu,
        mLength: 128,
        mChannel: 0,
        mRadioType: 0,
        mInfo: aInfo,
    };
    let rawFrame = &mut aFrame as *mut otRadioFrame;
    rawFrame
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioClearSrcMatchShortEntry(
    _aInstance: *mut otInstance,
    _aShortAddress: otShortAddress,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioTransmit(
    _aInstance: *mut otInstance,
    _aFrame: *mut otRadioFrame,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioEnable(_aInstance: *mut otInstance) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioSetPanId(_aInstance: *mut otInstance, _aPanId: otPanId) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioGetCaps(_aInstance: *mut otInstance) -> otRadioCaps {
    OT_RADIO_CAPS_NONE.try_into().unwrap()
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioReceive(_aInstance: *mut otInstance, _aChannel: u8) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatRadioClearSrcMatchExtEntry(
    _aInstance: *mut otInstance,
    _aExtAddress: *const otExtAddress,
) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatAlarmMilliStop(_aInstance: *mut otInstance) {}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatAlarmMilliStartAt(
    _aInstance: *mut otInstance,
    _aT0: u32,
    _aDt: u32,
) {
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatAlarmMilliGetNow() -> u32 {
    0
}

#[link(name = "openthread-ftd")]
#[no_mangle]
pub unsafe extern "C" fn otPlatEntropyGet(_aOutput: *mut u8, _aOutputLength: u16) -> otError {
    otError_OT_ERROR_NOT_IMPLEMENTED
}
