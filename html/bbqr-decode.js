/*
  Shared BBQr multi-part assembly/decode logic, used by both index.html
  (browser) and decode_cli.js (Node, for automated testing against this
  project's own real Python decoder). Ported directly from this project's
  own real implementation (src/seedsigner/models/decode_qr.py's
  _bbqr_decode_segments / BaseBBQrDecoder) -- not reverse-engineered from
  the spec, so it matches exactly what this device's BBQrEncoder produces.
  See https://github.com/coinkite/BBQr/blob/master/BBQr.md for the spec
  this mirrors.

  Works in both a <script> tag (globals) and Node (module.exports) without
  a bundler -- deliberately dependency-free except for the pako global,
  which both environments load separately (script tag / require).
*/
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./pako.min.js"));
  } else {
    root.BBQrDecode = factory(root.pako);
  }
})(typeof self !== "undefined" ? self : this, function (pako) {

const BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
function fromBase36Pair(pair) {
  return BASE36.indexOf(pair[0]) * 36 + BASE36.indexOf(pair[1]);
}

// ski(): the Subject Key Identifier -- SHA-256 of the RAW key bytes (not the
// hex string's own UTF-8 bytes), truncated to the first 20 bytes, hex-encoded
// (40 chars). Byte-for-byte port of 7fchain's x509::key_id() (RFC 7093
// method 1) / review_format.ski() (this device's own Python port): the id
// sf-wallet-gov prints and names every governance file by (7fchain ce04ae9).
// Uses the Web Crypto API (crypto.subtle),
// present natively in both browsers (secure context -- same requirement
// this page's camera access already has) and Node 19+, so no new
// dependency. Returns null for input that isn't well-formed hex.
async function sha256OfHex(hexText) {
  const clean = String(hexText).trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ski(hexText) {
  const digest = await sha256OfHex(hexText);
  return digest === null ? null : digest.slice(0, 40);  // 20 bytes
}

// pin(): the full SHA-256 of the raw key, 64 hex -- 7fchain's x509::vk_pin(),
// the "root pin" a federation member reports over a second channel
// (ceremony-federation-member.md Step 4). The ski is its first 40 hex.
async function pin(hexText) {
  return sha256OfHex(hexText);
}

// vkSummary(): a <ski>.txt record of one key for the holder: the bundle,
// its role, and for a Root key the reminder that the root pin is only a check
// when confirmed over a second channel (the .vk itself stays bare hex).
async function vkSummary(hexText, role) {
  const bundle = await vkBundle(hexText, role);
  if (bundle === null) return null;
  const id = bundle.split("\n")[0].slice("subject key id: ".length);
  const header = role === "root"
    ? "# Record only. Send the .vk file; confirm the root pin by phone -- a pin in a file proves nothing.\n"
    : "# Record only. Send the .vk file.\n";
  return { name: `${id}.txt`, text: header + `role: ${role || "unknown"}\n` + bundle };
}

// ─── Export envelopes from the device (models/sevenf/export_envelope.py) ───
// {"sf7_export": 1, "kind": ..., "file": ..., "body": <exact file contents>}.
// The page saves `body` verbatim under `file`, after checking `file` against
// `body` wherever the name can be derived from the content.

// No paths, no hidden files, no "..", bounded length.
const SAFE_FILE_NAME = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const OID_ML_DSA_65 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];  // 2.16.840.1.101.3.4.3.18

function bytesToHexStr(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pemCertToDer(pem) {
  const m = /^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?$/.exec(String(pem));
  if (!m) return null;
  try {
    const bin = atob(m[1].replace(/\n/g, ""));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch (e) {
    return null;  // malformed base64
  }
}

// PEM exactly as sf-wallet-gov (and the device's der_to_pem) writes it:
// 64-character lines and a trailing newline.
function derToPem(der) {
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  const lines = b64.match(/.{1,64}/g) || [];
  return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n") + "\n";
}

// Minimal DER reader: {tag, off (of the tag), start, end} of the TLV at `off`.
function readTlv(b, off) {
  if (off + 2 > b.length) return null;
  const tag = b[off];
  let len = b[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3 || p + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i];
    p += n;
  }
  if (p + len > b.length) return null;
  return { tag, off, start: p, end: p + len };
}

function derChildren(b, tlv) {
  const out = [];
  for (let o = tlv.start; o < tlv.end;) {
    const t = readTlv(b, o);
    if (!t || t.end > tlv.end) return null;
    out.push(t);
    o = t.end;
  }
  return out;
}

// The tbsCertificate's fields after the optional explicit version:
// serial, sigAlg, issuer, validity, subject, spki, then optional [1]/[2]/[3].
function tbsFields(der) {
  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== 0x30 || cert.end !== der.length) return null;
  const top = derChildren(der, cert);
  if (!top || top.length !== 3 || top[0].tag !== 0x30) return null;
  let tbs = derChildren(der, top[0]);
  if (!tbs) return null;
  if (tbs.length && tbs[0].tag === 0xa0) tbs = tbs.slice(1);
  return tbs.length >= 6 ? tbs : null;
}

const OID_AUTHORITY_KEY_ID = [0x06, 0x03, 0x55, 0x1d, 0x23];  // 2.5.29.35

// The AuthorityKeyIdentifier's keyIdentifier ([0]) as hex: the issuing
// key's ski (7fchain sets it to x509::key_id of the issuer). Null if absent.
function certAuthorityKeyId(der) {
  const tbs = tbsFields(der);
  const extsWrap = tbs && tbs.find((t) => t.tag === 0xa3);
  if (!extsWrap) return null;
  const extsSeq = derChildren(der, extsWrap);
  const exts = extsSeq && extsSeq.length === 1 && derChildren(der, extsSeq[0]);
  if (!exts) return null;
  for (const ext of exts) {
    const parts = derChildren(der, ext);
    if (!parts || parts.length < 2) continue;
    const oid = der.slice(parts[0].off, parts[0].end);
    if (oid.length !== OID_AUTHORITY_KEY_ID.length || !OID_AUTHORITY_KEY_ID.every((x, i) => oid[i] === x)) continue;
    const value = parts[parts.length - 1];  // OCTET STRING wrapping AuthorityKeyIdentifier
    if (value.tag !== 0x04) return null;
    const aki = readTlv(der, value.start);
    const fields = aki && aki.tag === 0x30 && derChildren(der, aki);
    const keyId = fields && fields.find((f) => f.tag === 0x80);
    return keyId ? bytesToHexStr(der.slice(keyId.start, keyId.end)) : null;
  }
  return null;
}

// The certificate's subject key, found by walking the structure (RFC 5280:
// Certificate -> tbsCertificate -> [version] serial sigAlg issuer validity
// subject subjectPublicKeyInfo) -- not by searching for a byte pattern,
// which a decoy earlier in the certificate could satisfy. Null unless the
// key is ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18) and 1952 bytes long.
function certSubjectVk(der) {
  const tbs = tbsFields(der);
  return tbs ? spkiMlDsa65Key(der, tbs[5]) : null;
}

// A PKCS#10 CSR's subject key (RFC 2986: CertificationRequest ->
// certificationRequestInfo -> version subject subjectPKInfo [0]attributes),
// with the same ML-DSA-65 checks as certSubjectVk. Shown so the Deputy's ski
// can be confirmed by voice before the file goes to the device.
function csrSubjectVk(der) {
  const req = readTlv(der, 0);
  if (!req || req.tag !== 0x30 || req.end !== der.length) return null;
  const top = derChildren(der, req);
  if (!top || top.length !== 3 || top[0].tag !== 0x30) return null;
  const info = derChildren(der, top[0]);
  if (!info || info.length < 3 || info[0].tag !== 0x02) return null;
  return spkiMlDsa65Key(der, info[2]);
}

function spkiMlDsa65Key(der, spki) {
  if (spki.tag !== 0x30) return null;
  const parts = derChildren(der, spki);
  if (!parts || parts.length !== 2 || parts[0].tag !== 0x30 || parts[1].tag !== 0x03) return null;
  const alg = derChildren(der, parts[0]);
  if (!alg || alg.length < 1) return null;
  const oid = der.slice(alg[0].off, alg[0].end);
  if (oid.length !== OID_ML_DSA_65.length || !OID_ML_DSA_65.every((x, i) => oid[i] === x)) return null;
  const bits = parts[1];
  if (bits.end - bits.start !== 1953 || der[bits.start] !== 0x00) return null;
  return der.slice(bits.start + 1, bits.end);
}

// Where sf-wallet-gov writes each file (main.rs governance dir,
// sign_ops.rs): ~/7fchain/<network>/governance/<role>/outbox. Root and
// dev-fund keys are both <ski>.vk, so the role is what says which folder;
// certificates and signatures are the Root's own output.
const ROOT_OUTBOX = "~/7fchain/<network>/governance/root/outbox";
const VK_KINDS = new Map([["root-vk", ROOT_OUTBOX], ["devfund-vk", "~/7fchain/<network>/governance/devfund/outbox"]]);
const SIGNATURE_KINDS = new Map([["genesis-sig", "genesis"], ["devfund-sig", "devfund"]]);

async function inspectExport(jsonText) {
  let obj;
  try {
    obj = JSON.parse(jsonText);
  } catch (e) {
    return null;
  }
  if (!obj || typeof obj !== "object" || !("sf7_export" in obj)) return null;  // not an envelope

  const out = {
    kind: obj.kind,
    file: obj.file,
    body: typeof obj.body === "string" ? obj.body : JSON.stringify(obj.body),
    ski: null,
    pin: null,
    error: null,
  };
  const fail = (msg) => ({ ...out, error: msg });
  if (obj.sf7_export !== 1) return fail(`unsupported export version ${JSON.stringify(obj.sf7_export)}`);
  if (typeof obj.file !== "string" || !SAFE_FILE_NAME.test(obj.file)) return fail(`unsafe file name ${JSON.stringify(obj.file)}`);
  if (typeof obj.body !== "string") return fail("export has no body");

  if (obj.kind === "root-cert" || obj.kind === "deputy-cert") {
    const der = pemCertToDer(obj.body);
    const vk = der && certSubjectVk(der);
    if (!vk) return fail("body is not an ML-DSA-65 certificate");
    if (derToPem(der) !== obj.body) return fail("body is not canonical PEM (64-character lines, trailing newline)");
    const vkHex = bytesToHexStr(vk);
    const digest = await pin(vkHex);
    out.ski = digest.slice(0, 40);
    out.pin = obj.kind === "root-cert" ? digest : null;   // the root pin is a Root key's only
    out.folder = ROOT_OUTBOX;
    let expected;
    if (obj.kind === "root-cert") {
      expected = `root-${out.ski}.pem`;
    } else {
      // sign-deputy-cert names it for the ISSUING Root (six Roots certify one
      // Deputy): the AuthorityKeyIdentifier carries that Root's ski.
      out.issuer_ski = certAuthorityKeyId(der);
      if (!out.issuer_ski || out.issuer_ski.length !== 40) return fail("certificate has no 20-byte AuthorityKeyIdentifier");
      expected = `deputy-${out.issuer_ski}.pem`;
    }
    if (obj.file !== expected) return fail(`file name ${obj.file} does not match the certificate (expected ${expected})`);
    return out;
  }
  const vkFolder = VK_KINDS.get(obj.kind);
  if (vkFolder) {
    // A role-tagged verification key: exactly sf-wallet-gov's .vk bytes.
    if (!/^[0-9a-f]{3904}\n$/.test(obj.body)) return fail("body is not a verification key (3904 lowercase hex + newline)");
    const digest = await pin(obj.body.trim());
    out.ski = digest.slice(0, 40);
    out.pin = obj.kind === "root-vk" ? digest : null;     // derive-vk prints no pin for a dev-fund key
    out.folder = vkFolder;
    if (obj.file !== `${out.ski}.vk`) return fail(`file name ${obj.file} does not match the key (expected ${out.ski}.vk)`);
    return out;
  }
  const sigExt = SIGNATURE_KINDS.get(obj.kind);  // a Map: no inherited names
  if (sigExt) {
    // A Root signature, as sf-wallet-gov sign-genesis/sign-devfund write it.
    // It carries no key, so the name can only be checked for shape (and
    // against the key if one is embedded); the coordinator verifies the
    // signature against <ski>.vk and refuses a misnamed file.
    const m = new RegExp(`^([0-9a-f]{40})\\.${sigExt}$`).exec(obj.file);
    if (!m) return fail(`file name ${obj.file} is not <subject key id>.${sigExt}`);
    out.ski = m[1];
    out.folder = ROOT_OUTBOX;
    let sig;
    try {
      sig = JSON.parse(obj.body);
    } catch (e) {
      return fail("body is not a signature (not JSON)");
    }
    const keys = sig && typeof sig === "object" ? Object.keys(sig) : [];
    if (keys.length !== 2 || keys[0] !== "signer_vk" || keys[1] !== "sig") return fail("body is not a signature {signer_vk, sig}");
    if (typeof sig.sig !== "string" || typeof sig.signer_vk !== "string") return fail("body is not a signature (signer_vk and sig must be strings)");
    if (!/^[0-9a-f]{6618}$/.test(sig.sig)) return fail("body is not a signature (sig must be 3309 bytes of lowercase hex)");
    if (sig.signer_vk !== "") {
      if (!/^[0-9a-f]{3904}$/.test(sig.signer_vk)) return fail("body's signer_vk is not a 1952-byte key");
      const keyPin = await pin(sig.signer_vk);
      if (keyPin.slice(0, 40) !== out.ski) return fail(`file name ${obj.file} does not match the embedded key`);
    }
    if (JSON.stringify(sig, null, 2) + "\n" !== obj.body) return fail("body is not canonical (sf-wallet-gov's pretty JSON plus a newline)");
    return out;
  }
  return fail(`unsupported export kind ${JSON.stringify(obj.kind)}`);
}

// saveMethod(): how the page saves a file under the name it computed.
// Desktop Chrome/Edge have a folder picker (save straight into
// governance/<role>/outbox); iPhone Safari has none but can share a named
// file (Save to Files, AirDrop, Mail); anything else gets a plain download.
function saveMethod({ hasSavePicker, canShareFiles }) {
  if (hasSavePicker) return "picker";
  if (canShareFiles) return "share";
  return "download";
}

// vkBundle(): everything a member hands the coordinator for one key, in one
// paste, labelled the way sf-wallet-gov prints it: the "root pin" only for a
// Root key (sign_ops.rs sign-root-cert; derive-vk prints none). null for
// non-hex input.
async function vkBundle(hexText, role) {
  const digest = await sha256OfHex(hexText);
  if (digest === null) return null;
  const id = digest.slice(0, 40);
  const pinLine = role === "root" ? `root pin: ${digest}\n` : "";
  return `subject key id: ${id}\n${pinLine}file: ${id}.vk\nvk: ${String(hexText).trim().toLowerCase()}\n`;
}

// RFC 4648 base32 decode, matching Python's base64.b32decode (uppercase
// alphabet, '=' padding). No built-in JS equivalent, so hand-rolled --
// this is the whole alphabet, nothing invented.
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  const clean = input.replace(/=+$/, "");
  let bits = "";
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch.toUpperCase());
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function hexDecode(input) {
  const bytes = new Uint8Array(input.length / 2);
  for (let i = 0; i < input.length; i += 2) {
    bytes[i / 2] = parseInt(input.slice(i, i + 2), 16);
  }
  return bytes;
}

function concatBytes(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

// Mirrors decode_qr.py's _bbqr_decode_segments() exactly: 'H' is hex per
// segment; otherwise base32 per segment, then (for 'Z') raw-deflate
// inflate of the concatenated bytes -- matching BBQrEncoder's own
// zlib.compressobj(level=9, wbits=-10) on the encode side.
const MAX_DECODED_BYTES = 1024 * 1024;  // = decode_qr.MAX_BBQR_DECODED_BYTES

function reconstructPayload(segmentsByIndex, encoding) {
  const ordered = [];
  for (let i = 0; i < segmentsByIndex.size; i++) {
    ordered.push(segmentsByIndex.get(i));
  }
  let raw;
  if (encoding === "H") {
    raw = concatBytes(ordered.map(hexDecode));
  } else {
    raw = concatBytes(ordered.map(base32Decode));
  }
  if (encoding === "Z") {
    // Bounded, like the device's decoder: a few hundred KB of frames could
    // otherwise inflate to hundreds of MB and crash the tab.
    const inflator = new pako.Inflate({ raw: true, chunkSize: 64 * 1024 });
    const chunks = [];
    let total = 0;
    inflator.onData = (chunk) => {
      total += chunk.length;
      if (total > MAX_DECODED_BYTES) throw new Error(`BBQr payload too large (over ${MAX_DECODED_BYTES} bytes decompressed)`);
      chunks.push(chunk);
    };
    inflator.push(raw, true);
    if (inflator.err) throw new Error(`BBQr decompression failed: ${inflator.msg}`);
    return concatBytes(chunks);
  }
  return raw;
}

class BBQrSession {
  constructor() {
    this.reset();
  }

  reset() {
    this.encoding = null;
    this.fileType = null;
    this.total = null;
    this.segments = new Map(); // 0-based index -> base32/hex payload string
  }

  // Returns a status object; throws on a malformed/inconsistent segment.
  addSegment(text) {
    if (!text.startsWith("B$") || text.length < 8) {
      return { kind: "not-bbqr" };
    }
    const encoding = text[2];
    const fileType = text[3];
    const total = fromBase36Pair(text.slice(4, 6));
    const index = fromBase36Pair(text.slice(6, 8));
    const payload = text.slice(8).trim();

    if (!"Z2H".includes(encoding)) {
      throw new Error(`unsupported BBQr encoding byte: ${encoding}`);
    }
    if (this.total !== null && (total !== this.total || encoding !== this.encoding || fileType !== this.fileType)) {
      throw new Error(
        `segment header changed mid-scan (was total=${this.total} enc=${this.encoding} type=${this.fileType}, ` +
        `got total=${total} enc=${encoding} type=${fileType}) -- reset and rescan from the start`
      );
    }
    this.encoding = encoding;
    this.fileType = fileType;
    this.total = total;
    const isNew = !this.segments.has(index);
    if (!isNew && this.segments.get(index) !== payload) {
      // First wins, like the device's decoder: a frame from a different code
      // must never splice into a payload already being collected.
      return { kind: "conflict", index, total };
    }
    this.segments.set(index, payload);
    return { kind: "segment", index, total, isNew };
  }

  get isComplete() {
    return this.total !== null && this.segments.size === this.total;
  }

  missingIndices() {
    if (this.total === null) return [];
    const missing = [];
    for (let i = 0; i < this.total; i++) {
      if (!this.segments.has(i)) missing.push(i);
    }
    return missing;
  }

  decode() {
    return reconstructPayload(this.segments, this.encoding);
  }
}

return { fromBase36Pair, base32Decode, hexDecode, concatBytes, reconstructPayload, BBQrSession, ski, pin, vkBundle, vkSummary, saveMethod, inspectExport, certSubjectVk, csrSubjectVk, certAuthorityKeyId, bytesToHexStr };

});
