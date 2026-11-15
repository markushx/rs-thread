// C ABI over OpenThread's internal C++ classes, used by the OpenTrust
// differential tests (`crates/opentrust-difftest`). Every function takes byte
// buffers and returns byte buffers or fixed-layout structs; the struct layouts
// are mirrored in `crates/opentrust-difftest/src/ffi.rs`.
//
// Compiled by `build.rs` (feature `diff-shim`) with the flags of the
// OpenThread core library and linked in front of it.

#include "openthread-core-config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openthread/dataset.h>
#include <openthread/instance.h>
#include <openthread/netdata.h>
#include <openthread/platform/crypto.h>

#include "common/code_utils.hpp"
#include "common/message.hpp"
#include "crypto/aes_ccm.hpp"
#include "crypto/hkdf_sha256.hpp"
#include "crypto/hmac_sha256.hpp"
#include "crypto/sha256.hpp"
#include "instance/instance.hpp"
#include "mac/mac_frame.hpp"
#include "mac/sub_mac.hpp"
#include "thread/key_manager.hpp"
#include "thread/lowpan.hpp"
#include "thread/mle.hpp"
#include "thread/mle_tlvs.hpp"
#include "thread/network_data_leader.hpp"

using namespace ot;

namespace {

Instance *sInstance = nullptr;

Instance &Inst(void) { return *sInstance; }

} // namespace

extern "C" {

// ---------------------------------------------------------------------------
// Instance
// ---------------------------------------------------------------------------

// Creates the (single) OpenThread instance. Idempotent. Returns 1 on success.
int diff_init(void)
{
    if (sInstance == nullptr)
    {
        sInstance = static_cast<Instance *>(otInstanceInitSingle());
    }
    return sInstance != nullptr;
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

// AES-CCM* as used for MAC and MLE: `encrypt` != 0 encrypts `in` to `out`, else
// decrypts. `tag` receives the computed tag (for decryption: over the
// recovered plaintext, to be compared by the caller).
int diff_aes_ccm(const uint8_t *key,
                 const uint8_t *nonce,
                 const uint8_t *aad,
                 uint32_t       aad_len,
                 const uint8_t *in,
                 uint32_t       len,
                 uint8_t       *out,
                 uint8_t       *tag,
                 uint8_t        tag_len,
                 int            encrypt)
{
    Crypto::AesCcm ccm;

    ccm.SetKey(key, 16);
    ccm.Init(aad_len, len, tag_len, nonce, Crypto::AesCcm::kNonceSize);
    ccm.Header(aad, aad_len);
    if (encrypt)
    {
        ccm.Payload(const_cast<uint8_t *>(in), out, len, Crypto::AesCcm::kEncrypt);
    }
    else
    {
        ccm.Payload(out, const_cast<uint8_t *>(in), len, Crypto::AesCcm::kDecrypt);
    }
    ccm.Finalize(tag);
    return 0;
}

// `ext` is the extended address in canonical (big-endian) order.
void diff_ccm_nonce(const uint8_t *ext, uint32_t counter, uint8_t level, uint8_t *nonce)
{
    Mac::ExtAddress addr;

    memcpy(addr.m8, ext, 8);
    Crypto::AesCcm::GenerateNonce(addr, counter, level, nonce);
}

// MLE key and MAC keys (previous, current, next) of a key sequence, derived
// by `KeyManager` (`mac_keys` holds three 16-byte keys).
void diff_thread_keys(const uint8_t *network_key, uint32_t seq, uint8_t *mle_key, uint8_t *mac_keys)
{
    NetworkKey nk;
    Mac::Key   key;

    memcpy(nk.m8, network_key, 16);
    Inst().Get<KeyManager>().SetNetworkKey(nk);
    Inst().Get<KeyManager>().SetCurrentKeySequence(seq, KeyManager::kForceUpdate);
    Inst().Get<KeyManager>().GetCurrentMleKey().ExtractKey(key);
    memcpy(mle_key, key.m8, 16);
    Inst().Get<Mac::SubMac>().GetPreviousMacKey().ExtractKey(key);
    memcpy(mac_keys, key.m8, 16);
    Inst().Get<Mac::SubMac>().GetCurrentMacKey().ExtractKey(key);
    memcpy(mac_keys + 16, key.m8, 16);
    Inst().Get<Mac::SubMac>().GetNextMacKey().ExtractKey(key);
    memcpy(mac_keys + 32, key.m8, 16);
}

// The TREL key derivation of `KeyManager::ComputeTrelKey` (that function is
// only built with TREL enabled, so its body is repeated here with the same
// OpenThread HKDF class).
void diff_trel_key(const uint8_t *network_key, uint32_t seq, uint8_t *out)
{
    static const char kSalt[] = "ThreadSequenceMasterKey";
    static const char kInfo[] = "ThreadOverInfraKey";
    Crypto::HkdfSha256 hkdf;
    uint8_t            salt[4 + sizeof(kSalt) - 1];
    Crypto::Key        key;

    key.Set(network_key, 16);
    BigEndian::WriteUint32(seq, salt);
    memcpy(salt + 4, kSalt, sizeof(kSalt) - 1);
    hkdf.Extract(salt, sizeof(salt), key);
    hkdf.Expand(reinterpret_cast<const uint8_t *>(kInfo), sizeof(kInfo) - 1, out, 16);
}

void diff_hkdf_sha256(const uint8_t *salt,
                      uint16_t       salt_len,
                      const uint8_t *ikm,
                      uint16_t       ikm_len,
                      const uint8_t *info,
                      uint16_t       info_len,
                      uint8_t       *out,
                      uint16_t       out_len)
{
    Crypto::HkdfSha256 hkdf;
    Crypto::Key        key;

    key.Set(ikm, ikm_len);
    hkdf.Extract(salt, salt_len, key);
    hkdf.Expand(info, info_len, out, out_len);
}

void diff_hmac_sha256(const uint8_t *key, uint16_t key_len, const uint8_t *msg, uint16_t msg_len, uint8_t *out)
{
    Crypto::HmacSha256       hmac;
    Crypto::HmacSha256::Hash hash;
    Crypto::Key              k;

    k.Set(key, key_len);
    hmac.Start(k);
    hmac.Update(msg, msg_len);
    hmac.Finish(hash);
    memcpy(out, hash.GetBytes(), 32);
}

void diff_sha256(const uint8_t *msg, uint16_t len, uint8_t *out)
{
    Crypto::Sha256       sha;
    Crypto::Sha256::Hash hash;

    sha.Start();
    sha.Update(msg, len);
    sha.Finish(hash);
    memcpy(out, hash.GetBytes(), 32);
}

// PBKDF2 with AES-CMAC-PRF-128 (platform crypto API). Returns the OT error.
int diff_pbkdf2_cmac(const uint8_t *pw,
                     uint16_t       pw_len,
                     const uint8_t *salt,
                     uint16_t       salt_len,
                     uint32_t       iterations,
                     uint16_t       key_len,
                     uint8_t       *key)
{
    return otPlatCryptoPbkdf2GenerateKey(pw, pw_len, salt, salt_len, iterations, key_len, key);
}

// PSKc from a commissioning passphrase (`MeshCoP::GeneratePskc`), through the
// public API. `name` is `name_len` bytes (not NUL terminated). Returns the OT
// error.
int diff_pskc(const char *pass, const uint8_t *name, uint8_t name_len, const uint8_t *ext_pan, uint8_t *pskc)
{
    otNetworkName  n;
    otExtendedPanId e;
    otPskc          p;
    otError         err;

    memset(&n, 0, sizeof(n));
    memcpy(n.m8, name, name_len);
    memcpy(e.m8, ext_pan, 8);
    err = otDatasetGeneratePskc(pass, &n, &e, &p);
    if (err == OT_ERROR_NONE)
    {
        memcpy(pskc, p.m8, 16);
    }
    return static_cast<int>(err);
}

// ---------------------------------------------------------------------------
// 6LoWPAN
// ---------------------------------------------------------------------------

struct DiffContext
{
    uint8_t id;
    uint8_t compress;
    uint8_t prefix_len;
    uint8_t prefix[16];
};

struct DiffMacAddr
{
    uint8_t kind; // 0 none, 1 short, 2 extended
    uint8_t short_addr[2];
    uint8_t ext[8]; // canonical order
};

static void SetMacAddr(Mac::Address &aOut, const DiffMacAddr &aIn)
{
    switch (aIn.kind)
    {
    case 1:
        aOut.SetShort(static_cast<uint16_t>((aIn.short_addr[0] << 8) | aIn.short_addr[1]));
        break;
    case 2:
    {
        Mac::ExtAddress ext;
        memcpy(ext.m8, aIn.ext, 8);
        aOut.SetExtended(ext);
        break;
    }
    default:
        aOut.SetNone();
        break;
    }
}

// Sets the mesh-local prefix and replaces the Network Data by one stable
// prefix with a 6LoWPAN Context ID sub-TLV per context.
int diff_lowpan_configure(const uint8_t *ml_prefix, const DiffContext *ctxs, uint32_t n)
{
    uint8_t  buf[512];
    uint16_t len = 0;
    otMeshLocalPrefix ml;

    memcpy(ml.m8, ml_prefix, 8);
    Inst().Get<Mle::Mle>().SetMeshLocalPrefix(static_cast<Ip6::NetworkPrefix &>(ml));

    for (uint32_t i = 0; i < n; i++)
    {
        const DiffContext &c      = ctxs[i];
        uint8_t            nbytes = (c.prefix_len + 7) / 8;

        buf[len++] = 0x03;                  // Prefix TLV, stable
        buf[len++] = 1 + 1 + nbytes + 4;    // length
        buf[len++] = 0;                     // domain id
        buf[len++] = c.prefix_len;
        memcpy(buf + len, c.prefix, nbytes);
        len += nbytes;
        buf[len++] = 0x07; // 6LoWPAN Context ID sub-TLV, stable
        buf[len++] = 2;
        buf[len++] = static_cast<uint8_t>(c.id | (c.compress ? 0x10 : 0));
        buf[len++] = c.prefix_len;
    }

    Message *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);
    if (message == nullptr)
    {
        return -1;
    }
    message->AppendBytes(buf, len);
    OffsetRange range;
    range.Init(0, len);
    IgnoreError(Inst().Get<NetworkData::Leader>().SetNetworkData(0, 0, NetworkData::kStableSubset, *message, range));
    message->Free();
    return 0;
}

// Returns the OpenThread error code; on success `out`/`*hdr_len` hold the
// compressed headers and `*consumed` the number of datagram bytes they replace.
int diff_lowpan_compress(const DiffMacAddr *src,
                         const DiffMacAddr *dst,
                         const uint8_t     *ip6,
                         uint16_t           len,
                         uint8_t           *out,
                         uint16_t           out_cap,
                         uint16_t          *hdr_len,
                         uint16_t          *consumed)
{
    Mac::Addresses addrs;
    FrameBuilder   builder;
    Error          error;
    Message       *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);

    if (message == nullptr)
    {
        return -1;
    }
    message->AppendBytes(ip6, len);
    SetMacAddr(addrs.mSource, *src);
    SetMacAddr(addrs.mDestination, *dst);
    builder.Init(out, out_cap);
    error = Inst().Get<Lowpan::Lowpan>().Compress(*message, addrs, builder);
    if (error == kErrorNone)
    {
        *hdr_len  = builder.GetLength();
        *consumed = message->GetOffset();
    }
    message->Free();
    return static_cast<int>(error);
}

// Decompresses `frame` (IPHC and payload); `datagram_len` 0 means unfragmented.
int diff_lowpan_decompress(const DiffMacAddr *src,
                           const DiffMacAddr *dst,
                           const uint8_t     *frame,
                           uint16_t           len,
                           uint16_t           datagram_len,
                           uint8_t           *out,
                           uint16_t           out_cap,
                           uint16_t          *out_len,
                           uint16_t          *consumed)
{
    Mac::Addresses addrs;
    FrameData      data;
    Error          error;
    Message       *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);

    if (message == nullptr)
    {
        return -1;
    }
    SetMacAddr(addrs.mSource, *src);
    SetMacAddr(addrs.mDestination, *dst);
    data.Init(frame, len);
    error = Inst().Get<Lowpan::Lowpan>().Decompress(*message, addrs, data, datagram_len);
    if (error == kErrorNone)
    {
        // Like the mesh forwarder: the payload follows the decompressed headers.
        error = message->AppendBytes(data.GetBytes(), data.GetLength());
    }
    if (error == kErrorNone)
    {
        uint16_t l = message->GetLength();
        if (l > out_cap)
        {
            error = kErrorNoBufs;
        }
        else
        {
            message->ReadBytes(0, out, l);
            *out_len  = l;
            *consumed = static_cast<uint16_t>(data.GetBytes() - frame);
        }
    }
    message->Free();
    return static_cast<int>(error);
}

// ---------------------------------------------------------------------------
// IEEE 802.15.4 MAC frames
// ---------------------------------------------------------------------------

struct DiffMacInfo
{
    uint8_t  valid; // ValidatePsdu() succeeded
    uint8_t  frame_type;
    uint8_t  version; // FCF version bits (0..3)
    uint8_t  security_enabled;
    uint8_t  frame_pending;
    uint8_t  ack_request;
    uint8_t  pan_id_compressed;
    uint8_t  ie_present;
    uint8_t  has_seq;
    uint8_t  seq;
    uint8_t  has_dst_pan;
    uint16_t dst_pan;
    DiffMacAddr dst;
    uint8_t  has_src_pan;
    uint16_t src_pan;
    DiffMacAddr src;
    uint8_t  has_security;
    uint8_t  sec_level;
    uint8_t  key_id_mode;
    uint8_t  has_counter;
    uint32_t counter;
    uint8_t  has_key_id;
    uint8_t  key_id;
    uint16_t header_len;
    uint16_t payload_len;
    uint16_t footer_len;
};

static void FillAddr(DiffMacAddr &aOut, const Mac::Address &aIn)
{
    memset(&aOut, 0, sizeof(aOut));
    if (aIn.IsShort())
    {
        aOut.kind          = 1;
        aOut.short_addr[0] = aIn.GetShort() >> 8;
        aOut.short_addr[1] = aIn.GetShort() & 0xff;
    }
    else if (aIn.IsExtended())
    {
        aOut.kind = 2;
        memcpy(aOut.ext, aIn.GetExtended().m8, 8);
    }
}

// Parses a PSDU (with FCS space: the frame is taken as `len` bytes including
// the 2-byte FCS slot already stripped by the caller, as in OpenThread's
// receive path).
void diff_mac_parse(const uint8_t *psdu, uint16_t len, DiffMacInfo *info)
{
    Mac::RxFrame frame;
    uint8_t      buf[256];

    memset(info, 0, sizeof(*info));
    if (len + 2 > sizeof(buf))
    {
        return;
    }
    memset(buf, 0, sizeof(buf));
    memcpy(buf, psdu, len);
    memset(&frame, 0, sizeof(frame));
    frame.mPsdu = buf;
    // OpenThread frames carry their (here zero) 2-byte FCS.
    frame.mLength = len + 2;

    if (frame.ValidatePsdu() != kErrorNone)
    {
        return;
    }
    info->valid             = 1;
    info->frame_type        = frame.GetType();
    info->version           = static_cast<uint8_t>(frame.GetVersion() >> 12);
    info->security_enabled  = frame.GetSecurityEnabled();
    info->frame_pending     = frame.GetFramePending();
    info->ack_request       = frame.GetAckRequest();
    info->pan_id_compressed = frame.IsPanIdCompressed();
    info->ie_present        = frame.IsIePresent();

    if (frame.IsSequencePresent())
    {
        info->has_seq = 1;
        info->seq     = frame.GetSequence();
    }

    Mac::PanId   pan;
    Mac::Address addr;

    if (frame.GetDstPanId(pan) == kErrorNone)
    {
        info->has_dst_pan = 1;
        info->dst_pan     = pan;
    }
    if (frame.GetDstAddr(addr) == kErrorNone)
    {
        FillAddr(info->dst, addr);
    }
    if (frame.GetSrcPanId(pan) == kErrorNone)
    {
        info->has_src_pan = 1;
        info->src_pan     = pan;
    }
    if (frame.GetSrcAddr(addr) == kErrorNone)
    {
        FillAddr(info->src, addr);
    }

    if (info->security_enabled)
    {
        uint8_t  v8;
        uint32_t v32;

        info->has_security = 1;
        if (frame.GetSecurityLevel(v8) == kErrorNone)
        {
            info->sec_level = v8;
        }
        if (frame.GetKeyIdMode(v8) == kErrorNone)
        {
            info->key_id_mode = v8 >> 3; // reported in place (shifted by 3)
        }
        if (frame.GetFrameCounter(v32) == kErrorNone)
        {
            info->has_counter = 1;
            info->counter     = v32;
        }
        // For Key ID Mode 0 OpenThread's `GetKeyId()` returns whatever the
        // last byte of the security header is: there is no key identifier.
        if (info->key_id_mode != 0 && frame.GetKeyId(v8) == kErrorNone)
        {
            info->has_key_id = 1;
            info->key_id     = v8;
        }
    }
    info->header_len  = frame.GetHeaderLength();
    info->payload_len = frame.GetPayloadLength();
    info->footer_len  = frame.GetFooterLength() - 2;
}

struct DiffMacBuild
{
    uint8_t     type;     // frame type bits
    uint8_t     version;  // 0 = 2003, 1 = 2006, 2 = 2015
    uint8_t     sec_level;
    uint8_t     key_id_mode; // 0..3
    uint8_t     suppress_seq;
    uint8_t     cmd_id;
    uint8_t     csl_ie;
    uint8_t     empty_payload;
    uint8_t     has_dst_pan;
    uint8_t     has_src_pan;
    uint16_t    dst_pan;
    uint16_t    src_pan;
    DiffMacAddr dst;
    DiffMacAddr src;
    uint8_t     seq;
    uint8_t     key_index;
    uint32_t    counter;
};

// Builds the MAC header with `TxFrame::Info::PrepareHeadersIn` and fills the
// sequence number, frame counter and key identifier. The frame has no payload;
// the MIC area is zero. `*len` is the length without FCS.
int diff_mac_build(const DiffMacBuild *p, uint8_t *out, uint16_t cap, uint16_t *len)
{
    Mac::TxFrame       frame;
    Mac::TxFrame::Info info;
    uint8_t            buf[256];

    memset(buf, 0, sizeof(buf));
    memset(&frame, 0, sizeof(frame));
    frame.mPsdu = buf;
    frame.mLength = 0;

    info.mType          = static_cast<Mac::Frame::Type>(p->type);
    info.mVersion       = static_cast<Mac::Frame::Version>(static_cast<uint16_t>(p->version) << 12);
    info.mSecurityLevel = static_cast<Mac::Frame::SecurityLevel>(p->sec_level);
    info.mKeyIdMode     = static_cast<Mac::Frame::KeyIdMode>(p->key_id_mode << 3);
    info.mCommandId     = static_cast<Mac::Frame::CommandId>(p->cmd_id);
    info.mSuppressSequence = p->suppress_seq;
    info.mAppendCslIe      = p->csl_ie;
    info.mEmptyPayload     = p->empty_payload;
    if (p->has_dst_pan)
    {
        info.mPanIds.SetDestination(p->dst_pan);
    }
    if (p->has_src_pan)
    {
        info.mPanIds.SetSource(p->src_pan);
    }
    SetMacAddr(info.mAddrs.mDestination, p->dst);
    SetMacAddr(info.mAddrs.mSource, p->src);

    info.PrepareHeadersIn(frame);

    if (!p->suppress_seq)
    {
        frame.SetSequence(p->seq);
    }
    if (p->sec_level != 0)
    {
        if (p->key_id_mode == 2)
        {
            static const uint8_t kSource[4] = {0xff, 0xff, 0xff, 0xff};
            frame.SetKeySource(kSource);
        }
        frame.SetFrameCounter(p->counter);
        if (p->key_id_mode != 0)
        {
            frame.SetKeyId(p->key_index);
        }
    }
    // `mLength` includes the FCS.
    *len = frame.mLength - 2;
    if (*len > cap)
    {
        return -1;
    }
    memcpy(out, buf, *len);
    return 0;
}

// ---------------------------------------------------------------------------
// MeshCoP datasets
// ---------------------------------------------------------------------------

// `otDatasetParseTlvs` (framing, per-TLV validity, duplicates) followed by
// `otDatasetConvertToTlvs`: the TLVs OpenThread's operational dataset keeps.
// Returns the OT error; on success `out` holds the converted TLVs.
int diff_dataset_roundtrip(const uint8_t *tlvs, uint8_t len, uint8_t *out, uint8_t *out_len)
{
    otOperationalDatasetTlvs in, conv;
    otOperationalDataset     info;
    otError                  err;

    memset(&in, 0, sizeof(in));
    memcpy(in.mTlvs, tlvs, len);
    in.mLength = len;
    err        = otDatasetParseTlvs(&in, &info);
    if (err != OT_ERROR_NONE)
    {
        return static_cast<int>(err);
    }
    memset(&conv, 0, sizeof(conv));
    otDatasetConvertToTlvs(&info, &conv);
    memcpy(out, conv.mTlvs, conv.mLength);
    *out_len = conv.mLength;
    return 0;
}

// ---------------------------------------------------------------------------
// Network Data
// ---------------------------------------------------------------------------

static int PutHex(char *aOut, size_t aCap, const uint8_t *aBytes, size_t aLen)
{
    int n = 0;
    for (size_t i = 0; i < aLen && n + 2 < static_cast<int>(aCap); i++)
    {
        n += snprintf(aOut + n, aCap - n, "%02x", aBytes[i]);
    }
    return n;
}

static int PutPrefix(char *aOut, size_t aCap, const otIp6Prefix &aPrefix)
{
    // Bits behind the prefix length are not significant: mask them.
    uint8_t bytes[16];
    memcpy(bytes, aPrefix.mPrefix.mFields.m8, sizeof(bytes));
    for (unsigned i = 0; i < 16; i++)
    {
        if (i * 8 >= aPrefix.mLength)
        {
            bytes[i] = 0;
        }
        else if (i * 8 + 8 > aPrefix.mLength)
        {
            bytes[i] &= static_cast<uint8_t>(0xff << (i * 8 + 8 - aPrefix.mLength));
        }
    }
    int n = PutHex(aOut, aCap, bytes, (aPrefix.mLength + 7) / 8);
    return n + snprintf(aOut + n, aCap - n, "/%u", aPrefix.mLength);
}

// Loads `tlvs` as the Network Data of the instance (`mode` 0: full set,
// 1: stable subset, like a child receiving stable data only).
// Mode 0 writes a text dump of the entries OpenThread's public iterators
// return (on-mesh prefixes, routes, services, contexts); mode 1 writes the
// stored bytes (`RemoveTemporaryData` applied). Returns the output length or
// -1 if the data was refused.
int diff_netdata(const uint8_t *tlvs, uint16_t len, int mode, uint8_t *out, uint16_t cap)
{
    char                  *o = reinterpret_cast<char *>(out);
    int                    n = 0;
    Message               *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);
    OffsetRange            range;
    Error                  error;
    otNetworkDataIterator  it;
    otBorderRouterConfig   br;
    otExternalRouteConfig  rt;
    otServiceConfig        sv;
    otLowpanContextInfo    cx;

    if (message == nullptr)
    {
        return -1;
    }
    message->AppendBytes(tlvs, len);
    range.Init(0, len);
    error = Inst().Get<NetworkData::Leader>().SetNetworkData(
        0, 0, mode == 1 ? NetworkData::kStableSubset : NetworkData::kFullSet, *message, range);
    message->Free();
    if (error != kErrorNone)
    {
        return -1;
    }

    if (mode == 1)
    {
        uint8_t l = 255;
        uint8_t buf[255];
        if (otNetDataGet(&Inst(), false, buf, &l) != OT_ERROR_NONE || l > cap)
        {
            return -1;
        }
        memcpy(out, buf, l);
        return l;
    }

    it = OT_NETWORK_DATA_ITERATOR_INIT;
    while (otNetDataGetNextOnMeshPrefix(&Inst(), &it, &br) == OT_ERROR_NONE)
    {
        n += snprintf(o + n, cap - n, "B ");
        n += PutPrefix(o + n, cap - n, br.mPrefix);
        n += snprintf(o + n, cap - n, " pref=%d P%d S%d D%d C%d R%d O%d N%d DP%d stable=%d rloc=%04x\n", br.mPreference,
                      br.mPreferred, br.mSlaac, br.mDhcp, br.mConfigure, br.mDefaultRoute, br.mOnMesh, br.mNdDns,
                      br.mDp, br.mStable, br.mRloc16);
    }
    it = OT_NETWORK_DATA_ITERATOR_INIT;
    while (otNetDataGetNextRoute(&Inst(), &it, &rt) == OT_ERROR_NONE)
    {
        n += snprintf(o + n, cap - n, "R ");
        n += PutPrefix(o + n, cap - n, rt.mPrefix);
        n += snprintf(o + n, cap - n, " pref=%d nat64=%d adv=%d stable=%d rloc=%04x\n", rt.mPreference, rt.mNat64,
                      rt.mAdvPio, rt.mStable, rt.mRloc16);
    }
    it = OT_NETWORK_DATA_ITERATOR_INIT;
    while (otNetDataGetNextService(&Inst(), &it, &sv) == OT_ERROR_NONE)
    {
        n += snprintf(o + n, cap - n, "S id=%u ent=%u sd=", sv.mServiceId, sv.mEnterpriseNumber);
        n += PutHex(o + n, cap - n, sv.mServiceData, sv.mServiceDataLength);
        n += snprintf(o + n, cap - n, " srv=");
        n += PutHex(o + n, cap - n, sv.mServerConfig.mServerData, sv.mServerConfig.mServerDataLength);
        n += snprintf(o + n, cap - n, " stable=%d rloc=%04x\n", sv.mServerConfig.mStable, sv.mServerConfig.mRloc16);
    }
    it = OT_NETWORK_DATA_ITERATOR_INIT;
    while (otNetDataGetNextLowpanContextInfo(&Inst(), &it, &cx) == OT_ERROR_NONE)
    {
        n += snprintf(o + n, cap - n, "C id=%u comp=%d ", cx.mContextId, cx.mCompressFlag);
        n += PutPrefix(o + n, cap - n, cx.mPrefix);
        n += snprintf(o + n, cap - n, " stable=%d\n", cx.mStable);
    }
    return n;
}

// ---------------------------------------------------------------------------
// MLE TLVs
// ---------------------------------------------------------------------------

// `Tlv::FindTlvValueOffsetRange`: the value of the first TLV of `type` in
// `stream` (a message holding just the TLVs). Returns the OT error (0 found,
// 23 not found, 6 parse).
int diff_mle_find(const uint8_t *stream, uint16_t len, uint8_t type, uint8_t *out, uint16_t *out_len)
{
    Message    *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);
    OffsetRange range;
    Error       error;

    if (message == nullptr)
    {
        return -1;
    }
    message->AppendBytes(stream, len);
    error = Tlv::FindTlvValueOffsetRange(*message, type, range);
    if (error == kErrorNone)
    {
        message->ReadBytes(range.GetOffset(), out, range.GetLength());
        *out_len = range.GetLength();
    }
    message->Free();
    return static_cast<int>(error);
}

// Typed reads of fixed-size unsigned TLVs (`Tlv::Find<UintTlvInfo>`): the
// error of the read and, on success, the value.
int diff_mle_uint(const uint8_t *stream, uint16_t len, uint8_t type, uint32_t *value)
{
    Message *message = Inst().Get<MessagePool>().Allocate(Message::kTypeIp6);
    Error    error   = kErrorInvalidArgs;
    uint8_t  v8      = 0;
    uint16_t v16     = 0;
    uint32_t v32     = 0;

    if (message == nullptr)
    {
        return -1;
    }
    message->AppendBytes(stream, len);
    switch (type)
    {
    case Mle::Tlv::kSourceAddress:
        error = Tlv::Find<Mle::SourceAddressTlv>(*message, v16);
        *value = v16;
        break;
    case Mle::Tlv::kMode:
        error = Tlv::Find<Mle::ModeTlv>(*message, v8);
        *value = v8;
        break;
    case Mle::Tlv::kTimeout:
        error = Tlv::Find<Mle::TimeoutTlv>(*message, v32);
        *value = v32;
        break;
    case Mle::Tlv::kLinkFrameCounter:
        error = Tlv::Find<Mle::LinkFrameCounterTlv>(*message, v32);
        *value = v32;
        break;
    case Mle::Tlv::kMleFrameCounter:
        error = Tlv::Find<Mle::MleFrameCounterTlv>(*message, v32);
        *value = v32;
        break;
    case Mle::Tlv::kAddress16:
        error = Tlv::Find<Mle::Address16Tlv>(*message, v16);
        *value = v16;
        break;
    case Mle::Tlv::kLinkMargin:
        error = Tlv::Find<Mle::LinkMarginTlv>(*message, v8);
        *value = v8;
        break;
    case Mle::Tlv::kVersion:
        error = Tlv::Find<Mle::VersionTlv>(*message, v16);
        *value = v16;
        break;
    case Mle::Tlv::kPanId:
        error = Tlv::Find<Mle::PanIdTlv>(*message, v16);
        *value = v16;
        break;
    case Mle::Tlv::kSupervisionInterval:
        error = Tlv::Find<Mle::SupervisionIntervalTlv>(*message, v16);
        *value = v16;
        break;
    case Mle::Tlv::kCslTimeout:
        error = Tlv::Find<Mle::CslTimeoutTlv>(*message, v32);
        *value = v32;
        break;
    case Mle::Tlv::kXtalAccuracy:
        error = Tlv::Find<Mle::XtalAccuracyTlv>(*message, v16);
        *value = v16;
        break;
    default:
        break;
    }
    message->Free();
    return static_cast<int>(error);
}

// Secures a built frame in place with `TxFrame::ProcessTransmitAesCcm`.
// `psdu` is `len` bytes without FCS, MIC area included (zero). `ext` is the
// source extended address in canonical order. Returns 1 if OpenThread
// processed the frame.
int diff_mac_secure(const uint8_t *key, const uint8_t *ext, uint8_t *psdu, uint16_t len)
{
    Mac::TxFrame     frame;
    Mac::Key         k;
    Mac::KeyMaterial km;
    Mac::ExtAddress  addr;
    uint8_t          buf[256];

    memset(buf, 0, sizeof(buf));
    memcpy(buf, psdu, len);
    memset(&frame, 0, sizeof(frame));
    frame.mPsdu   = buf;
    frame.mLength = len + 2; // plus FCS
    memcpy(k.m8, key, 16);
    km.SetFrom(k);
    frame.SetAesKey(km);
    memcpy(addr.m8, ext, 8);
    frame.ProcessTransmitAesCcm(addr);
    memcpy(psdu, buf, len);
    return frame.IsSecurityProcessed();
}

} // extern "C"
