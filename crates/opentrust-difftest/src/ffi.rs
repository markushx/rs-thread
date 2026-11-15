//! Safe wrappers over the C++ shim. OpenThread's instance is not thread
//! safe, so all calls go through one lock; `lock()` also creates the instance
//! on first use (in a scratch working directory, because the simulation
//! platform writes its flash file to `./tmp`).

use std::sync::{Mutex, MutexGuard, OnceLock};

unsafe extern "C" {
    fn diff_init() -> i32;
    fn diff_aes_ccm(
        key: *const u8,
        nonce: *const u8,
        aad: *const u8,
        aad_len: u32,
        input: *const u8,
        len: u32,
        out: *mut u8,
        tag: *mut u8,
        tag_len: u8,
        encrypt: i32,
    ) -> i32;
    fn diff_ccm_nonce(ext: *const u8, counter: u32, level: u8, nonce: *mut u8);
    fn diff_thread_keys(network_key: *const u8, seq: u32, mle: *mut u8, mac: *mut u8);
    fn diff_trel_key(network_key: *const u8, seq: u32, out: *mut u8);
    fn diff_hkdf_sha256(
        salt: *const u8,
        salt_len: u16,
        ikm: *const u8,
        ikm_len: u16,
        info: *const u8,
        info_len: u16,
        out: *mut u8,
        out_len: u16,
    );
    fn diff_hmac_sha256(key: *const u8, key_len: u16, msg: *const u8, msg_len: u16, out: *mut u8);
    fn diff_sha256(msg: *const u8, len: u16, out: *mut u8);
    fn diff_pbkdf2_cmac(
        pw: *const u8,
        pw_len: u16,
        salt: *const u8,
        salt_len: u16,
        iterations: u32,
        key_len: u16,
        key: *mut u8,
    ) -> i32;
    fn diff_pskc(
        pass: *const core::ffi::c_char,
        name: *const u8,
        name_len: u8,
        ext_pan: *const u8,
        pskc: *mut u8,
    ) -> i32;
    fn diff_lowpan_configure(ml_prefix: *const u8, ctxs: *const Context, n: u32) -> i32;
    fn diff_lowpan_compress(
        src: *const MacAddr,
        dst: *const MacAddr,
        ip6: *const u8,
        len: u16,
        out: *mut u8,
        out_cap: u16,
        hdr_len: *mut u16,
        consumed: *mut u16,
    ) -> i32;
    fn diff_lowpan_decompress(
        src: *const MacAddr,
        dst: *const MacAddr,
        frame: *const u8,
        len: u16,
        datagram_len: u16,
        out: *mut u8,
        out_cap: u16,
        out_len: *mut u16,
        consumed: *mut u16,
    ) -> i32;
    fn diff_mac_build(p: *const MacBuild, out: *mut u8, cap: u16, len: *mut u16) -> i32;
    fn diff_mac_secure(key: *const u8, ext: *const u8, psdu: *mut u8, len: u16) -> i32;
    fn diff_dataset_roundtrip(tlvs: *const u8, len: u8, out: *mut u8, out_len: *mut u8) -> i32;
    fn diff_mac_parse(psdu: *const u8, len: u16, info: *mut MacInfo);
}

/// `DiffContext` of the shim.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub id: u8,
    pub compress: u8,
    pub prefix_len: u8,
    pub prefix: [u8; 16],
}

/// `DiffMacAddr` of the shim (`kind`: 0 none, 1 short, 2 extended).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacAddr {
    pub kind: u8,
    pub short_addr: [u8; 2],
    pub ext: [u8; 8],
}

/// `DiffMacInfo` of the shim.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacInfo {
    pub valid: u8,
    pub frame_type: u8,
    pub version: u8,
    pub security_enabled: u8,
    pub frame_pending: u8,
    pub ack_request: u8,
    pub pan_id_compressed: u8,
    pub ie_present: u8,
    pub has_seq: u8,
    pub seq: u8,
    pub has_dst_pan: u8,
    pub dst_pan: u16,
    pub dst: MacAddr,
    pub has_src_pan: u8,
    pub src_pan: u16,
    pub src: MacAddr,
    pub has_security: u8,
    pub sec_level: u8,
    pub key_id_mode: u8,
    pub has_counter: u8,
    pub counter: u32,
    pub has_key_id: u8,
    pub key_id: u8,
    pub header_len: u16,
    pub payload_len: u16,
    pub footer_len: u16,
}

/// `DiffMacBuild` of the shim.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacBuild {
    pub frame_type: u8,
    /// 0 = 2003, 1 = 2006, 2 = 2015.
    pub version: u8,
    pub sec_level: u8,
    pub key_id_mode: u8,
    pub suppress_seq: u8,
    pub cmd_id: u8,
    pub csl_ie: u8,
    pub empty_payload: u8,
    pub has_dst_pan: u8,
    pub has_src_pan: u8,
    pub dst_pan: u16,
    pub src_pan: u16,
    pub dst: MacAddr,
    pub src: MacAddr,
    pub seq: u8,
    pub key_index: u8,
    pub counter: u32,
}

static LOCK: Mutex<()> = Mutex::new(());
static INIT: OnceLock<bool> = OnceLock::new();

/// The OpenThread instance, held while a test talks to the shim.
#[derive(Debug)]
pub struct Ot {
    _guard: MutexGuard<'static, ()>,
}

/// Locks the shim; creates the instance on first use.
pub fn lock() -> Ot {
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    INIT.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("opentrust-difftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        std::env::set_current_dir(&dir).expect("chdir to scratch directory");
        unsafe { diff_init() == 1 }
    });
    assert!(INIT.get() == Some(&true), "OpenThread instance init failed");
    Ot { _guard: guard }
}

impl Ot {
    /// AES-CCM*: returns `(output, tag)`. For decryption `tag` is the tag
    /// computed over the recovered plaintext.
    pub fn aes_ccm(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        input: &[u8],
        tag_len: usize,
        encrypt: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut out = vec![0u8; input.len()];
        let mut tag = vec![0u8; 16];
        unsafe {
            diff_aes_ccm(
                key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len() as u32,
                input.as_ptr(),
                input.len() as u32,
                out.as_mut_ptr(),
                tag.as_mut_ptr(),
                tag_len as u8,
                encrypt as i32,
            );
        }
        tag.truncate(tag_len);
        (out, tag)
    }

    pub fn ccm_nonce(&self, ext: &[u8; 8], counter: u32, level: u8) -> [u8; 13] {
        let mut n = [0u8; 13];
        unsafe { diff_ccm_nonce(ext.as_ptr(), counter, level, n.as_mut_ptr()) };
        n
    }

    /// `(mle_key, [previous, current, next] MAC keys)` from `KeyManager`.
    pub fn thread_keys(&self, network_key: &[u8; 16], seq: u32) -> ([u8; 16], [[u8; 16]; 3]) {
        let (mut mle, mut mac) = ([0u8; 16], [[0u8; 16]; 3]);
        unsafe {
            diff_thread_keys(
                network_key.as_ptr(),
                seq,
                mle.as_mut_ptr(),
                mac.as_mut_ptr().cast(),
            )
        };
        (mle, mac)
    }

    pub fn trel_key(&self, network_key: &[u8; 16], seq: u32) -> [u8; 16] {
        let mut k = [0u8; 16];
        unsafe { diff_trel_key(network_key.as_ptr(), seq, k.as_mut_ptr()) };
        k
    }

    pub fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
        unsafe {
            diff_hkdf_sha256(
                salt.as_ptr(),
                salt.len() as u16,
                ikm.as_ptr(),
                ikm.len() as u16,
                info.as_ptr(),
                info.len() as u16,
                out.as_mut_ptr(),
                out.len() as u16,
            )
        }
    }

    pub fn hmac_sha256(&self, key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        unsafe {
            diff_hmac_sha256(
                key.as_ptr(),
                key.len() as u16,
                msg.as_ptr(),
                msg.len() as u16,
                o.as_mut_ptr(),
            )
        };
        o
    }

    pub fn sha256(&self, msg: &[u8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        unsafe { diff_sha256(msg.as_ptr(), msg.len() as u16, o.as_mut_ptr()) };
        o
    }

    /// PBKDF2 (AES-CMAC-PRF-128); `Err(ot_error)` for invalid arguments.
    pub fn pbkdf2_cmac(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8],
    ) -> Result<(), i32> {
        let e = unsafe {
            diff_pbkdf2_cmac(
                password.as_ptr(),
                password.len() as u16,
                salt.as_ptr(),
                salt.len() as u16,
                iterations,
                out.len() as u16,
                out.as_mut_ptr(),
            )
        };
        if e == 0 { Ok(()) } else { Err(e) }
    }

    /// PSKc of a passphrase (`passphrase` must not contain NUL).
    pub fn pskc(&self, passphrase: &[u8], name: &[u8], ext_pan: &[u8; 8]) -> Result<[u8; 16], i32> {
        let mut pass = passphrase.to_vec();
        pass.push(0);
        let mut out = [0u8; 16];
        let e = unsafe {
            diff_pskc(
                pass.as_ptr().cast(),
                name.as_ptr(),
                name.len() as u8,
                ext_pan.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        if e == 0 { Ok(out) } else { Err(e) }
    }

    /// Sets the mesh-local prefix and the Network Data contexts.
    pub fn lowpan_configure(&self, ml_prefix: &[u8; 8], ctxs: &[Context]) {
        let r =
            unsafe { diff_lowpan_configure(ml_prefix.as_ptr(), ctxs.as_ptr(), ctxs.len() as u32) };
        assert_eq!(r, 0, "diff_lowpan_configure");
    }

    /// `Ok((compressed_headers, consumed))` or `Err(ot_error)`.
    pub fn lowpan_compress(
        &self,
        src: &MacAddr,
        dst: &MacAddr,
        ip6: &[u8],
        cap: usize,
    ) -> Result<(Vec<u8>, usize), i32> {
        let mut out = vec![0u8; cap];
        let (mut hdr, mut consumed) = (0u16, 0u16);
        let e = unsafe {
            diff_lowpan_compress(
                src,
                dst,
                ip6.as_ptr(),
                ip6.len() as u16,
                out.as_mut_ptr(),
                cap as u16,
                &mut hdr,
                &mut consumed,
            )
        };
        if e != 0 {
            return Err(e);
        }
        out.truncate(hdr as usize);
        Ok((out, consumed as usize))
    }

    /// `Ok((datagram, consumed))` or `Err(ot_error)`.
    pub fn lowpan_decompress(
        &self,
        src: &MacAddr,
        dst: &MacAddr,
        frame: &[u8],
        datagram_len: u16,
    ) -> Result<(Vec<u8>, usize), i32> {
        let mut out = vec![0u8; 2048];
        let (mut n, mut consumed) = (0u16, 0u16);
        let e = unsafe {
            diff_lowpan_decompress(
                src,
                dst,
                frame.as_ptr(),
                frame.len() as u16,
                datagram_len,
                out.as_mut_ptr(),
                out.len() as u16,
                &mut n,
                &mut consumed,
            )
        };
        if e != 0 {
            return Err(e);
        }
        out.truncate(n as usize);
        Ok((out, consumed as usize))
    }

    /// Header built by `TxFrame::Info::PrepareHeadersIn` (no payload, zero MIC).
    pub fn mac_build(&self, p: &MacBuild) -> Option<Vec<u8>> {
        let mut out = vec![0u8; 256];
        let mut len = 0u16;
        let e = unsafe { diff_mac_build(p, out.as_mut_ptr(), out.len() as u16, &mut len) };
        (e == 0).then(|| {
            out.truncate(len as usize);
            out
        })
    }

    /// Secures `psdu` (without FCS, zero MIC area) like `ProcessTransmitAesCcm`.
    pub fn mac_secure(&self, key: &[u8; 16], ext: &[u8; 8], psdu: &mut [u8]) -> bool {
        unsafe {
            diff_mac_secure(
                key.as_ptr(),
                ext.as_ptr(),
                psdu.as_mut_ptr(),
                psdu.len() as u16,
            ) == 1
        }
    }

    /// `otDatasetParseTlvs` + `otDatasetConvertToTlvs`: `Err(ot_error)` for
    /// invalid TLVs, else the dataset TLVs OpenThread keeps.
    pub fn dataset_roundtrip(&self, tlvs: &[u8]) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; 256];
        let mut n = 0u8;
        let e = unsafe {
            diff_dataset_roundtrip(tlvs.as_ptr(), tlvs.len() as u8, out.as_mut_ptr(), &mut n)
        };
        if e != 0 {
            return Err(e);
        }
        out.truncate(n as usize);
        Ok(out)
    }

    pub fn mac_parse(&self, psdu: &[u8]) -> MacInfo {
        let mut info = MacInfo::default();
        unsafe { diff_mac_parse(psdu.as_ptr(), psdu.len() as u16, &mut info) };
        info
    }
}
