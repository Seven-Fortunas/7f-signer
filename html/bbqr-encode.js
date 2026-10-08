/*
  Host-to-device half of the page: checks a ceremony file and turns it into
  the BBQr parts the device scans. A port of tools/file_to_bbqr.py
  (payload_for) and models/encode_qr.py's BBQrEncoder, so the device sees
  exactly what the Python tool would send. Tested against both in
  tests/test_bbqr_web_encoder.py through encode_cli.js.

  Works as a <script> tag (globals) and in Node (module.exports), like
  bbqr-decode.js, whose certificate helpers it reuses.
*/
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./pako.min.js"), require("./qrcode-generator.js"), require("./bbqr-decode.js"));
  } else {
    root.BBQrEncode = factory(root.pako, root.qrcode, root.BBQrDecode);
  }
})(typeof self !== "undefined" ? self : this, function (pako, qrcode, BBQrDecode) {

const BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MAX_BYTES_PER_SEGMENT = 300;  // = BBQrEncoder.max_bytes_per_segment
const MAX_FILE_BYTES = 64 * 1024;   // ceremony files are a few KB

function toBase36Pair(n) {
  if (n < 0 || n >= 36 * 36) throw new Error(`BBQr supports at most ${36 * 36} parts`);
  return BASE36[Math.floor(n / 36)] + BASE36[n % 36];
}

// RFC 4648 base32 without padding, as BBQrEncoder writes it.
function base32Encode(bytes) {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// BBQrEncoder._create_parts with bbqr_encoding="Z": raw deflate (level 9,
// 2^10 window, as zlib.compressobj(level=9, wbits=-10)), split into
// whole-byte chunks that each encode to at most 300 base32 characters.
function encodeParts(bytes, fileType) {
  if (!/^[A-Z0-9]$/.test(fileType)) throw new Error(`bad BBQr file type ${fileType}`);
  const underlying = pako.deflateRaw(bytes, { level: 9, windowBits: 10 });
  const chunkBytes = Math.floor((MAX_BYTES_PER_SEGMENT * 5) / 8);
  const chunks = [];
  for (let i = 0; i < underlying.length; i += chunkBytes) chunks.push(underlying.slice(i, i + chunkBytes));
  if (!chunks.length) chunks.push(new Uint8Array(0));
  const total = toBase36Pair(chunks.length);
  return chunks.map((chunk, i) => `B$Z${fileType}${total}${toBase36Pair(i)}${base32Encode(chunk)}`);
}

// One QR module grid per part (rows of "0"/"1"), error correction L like the
// device's qrencode. BBQr text is uppercase base32 plus the "B$" header, all
// inside QR alphanumeric mode.
function qrMatrix(text) {
  const qr = qrcode(0, "L");
  qr.addData(text, "Alphanumeric");
  qr.make();
  const size = qr.getModuleCount();
  const rows = [];
  for (let r = 0; r < size; r++) {
    let row = "";
    for (let c = 0; c < size; c++) row += qr.isDark(r, c) ? "1" : "0";
    rows.push(row);
  }
  return rows;
}

function groupHex(hex) {
  return hex.match(/.{1,4}/g).join(" ");
}

function utcText(seconds) {
  if (!Number.isSafeInteger(seconds) || seconds < 0) return String(seconds);
  return `${seconds} (${new Date(seconds * 1000).toISOString().replace("T", " ").replace(/\.000Z$/, " UTC")})`;
}

const PEM_TYPES = ["CERTIFICATE", "CERTIFICATE REQUEST"];

function pemBody(text) {
  const stripped = text.trim();
  for (const label of PEM_TYPES) {
    const begin = `-----BEGIN ${label}-----`;
    const end = `-----END ${label}-----`;
    if (stripped.startsWith(begin) && stripped.endsWith(end)) {
      const b64 = stripped.slice(begin.length, stripped.length - end.length).replace(/\s+/g, "");
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 !== 0) throw new Error("the PEM body is not valid base64");
      return { label, der: Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)) };
    }
  }
  return null;
}

// The fields an operator checks against the device's review screens. The
// device parses the file itself and is the authority; this only identifies
// the file and shows what to expect. Every shown value must read exactly as
// the encoded bytes say, so anything that would not (a number past 2^53, a
// fraction, a nested object) refuses the file instead of being rounded.
function text(v, what) {
  if (typeof v !== "string") throw new Error(`${what} is not a string`);
  return v;
}

function int(v, what) {
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${what} is not a whole number the page can show exactly`);
  return v;
}

function jsonFields(obj, raw) {
  if (/[0-9][.eE]/.test(raw.replace(/"(?:[^"\\]|\\.)*"/g, '""'))) throw new Error("it has a fractional or exponent number");
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  if ("recipient" in obj && "effective_block" in obj) {
    const r = obj.recipient;
    if (!r || typeof r !== "object" || Array.isArray(r)) throw new Error("recipient is not an object");
    const commitment = text(r.commitment, "recipient commitment");
    return {
      kind: "devfund-config",
      label: "Dev-fund definition (unsigned)",
      menu: "7F: Sign Devfund Config",
      fields: [
        ["Network", text(obj.network, "network")],
        ["Recipient kind", text(r.kind, "recipient kind")],
        ["Recipient (receives the ENTIRE genesis reward)", /^[0-9a-f]+$/.test(commitment) ? groupHex(commitment) : commitment],
        ["Effective block", String(int(obj.effective_block, "effective block"))],
        ["Timestamp", utcText(int(obj.timestamp, "timestamp"))],
      ],
    };
  }
  if ("consensus" in obj || "derivation_scheme" in obj) {
    const fields = [
      ["Chain", text(obj.chain_kind, "chain")],
      ["Timestamp", utcText(int(obj.timestamp, "timestamp"))],
      ["Message", JSON.stringify(text(obj.message, "message"))],
      ["Derivation scheme", text(obj.derivation_scheme, "derivation scheme")],
    ];
    const consensus = obj.consensus === undefined ? {} : obj.consensus;
    if (!consensus || typeof consensus !== "object" || Array.isArray(consensus)) throw new Error("consensus is not an object");
    for (const [k, v] of Object.entries(consensus)) fields.push([`Consensus: ${k}`, String(int(v, `consensus ${k}`))]);
    return { kind: "genesis-config", label: "Genesis config (unsigned)", menu: "7F: Sign Genesis Config", fields };
  }
  return null;
}

async function skiOf(vk) {
  return (await BBQrDecode.pin(BBQrDecode.bytesToHexStr(vk))).slice(0, 40);
}

// What the device would scan for this file, or {error}. Mirrors
// file_to_bbqr.payload_for: JSON goes byte-for-byte as BBQr 'J'; a
// CERTIFICATE or CERTIFICATE REQUEST PEM goes as its DER, as 'B'.
async function prepareFile(name, bytes) {
  if (bytes.length === 0) return { error: "the file is empty" };
  if (bytes.length > MAX_FILE_BYTES) return { error: `the file is ${bytes.length} bytes; ceremony files are under ${MAX_FILE_BYTES}` };
  if (!bytes.every((b) => b < 0x80)) return { error: "not a ceremony file (it is not plain text)" };
  const text = new TextDecoder().decode(bytes);

  if (text.trimStart().startsWith("{")) {
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (e) {
      return { error: `not valid JSON: ${e.message}` };
    }
    let info;
    try {
      info = jsonFields(obj, text);
    } catch (e) {
      return { error: `not sent as shown: ${e.message}` };
    }
    if (!info) return { error: "JSON, but not a genesis or dev-fund config" };
    if (Array.isArray(obj.signatures) && obj.signatures.length) info.fields.push(["Note", `already carries ${obj.signatures.length} signature(s)`]);
    return { ...info, name, fileType: "J", payload: bytes, parts: encodeParts(bytes, "J") };
  }

  let pem;
  try {
    pem = pemBody(text);
  } catch (e) {
    return { error: e.message };
  }
  if (!pem) return { error: "not a genesis or dev-fund config, Root certificate or Deputy CSR" };

  if (pem.label === "CERTIFICATE") {
    const vk = BBQrDecode.certSubjectVk(pem.der);
    if (!vk) return { error: "not an ML-DSA-65 certificate" };
    const ski = await skiOf(vk);
    const issuer = BBQrDecode.certAuthorityKeyId(pem.der);
    if (issuer && issuer !== ski) return { error: `a certificate issued by ${issuer}, not a Root self-certificate` };
    const fields = [["Root subject key id", groupHex(ski)]];
    if (name !== `root-${ski}.pem`) fields.push(["Note", `the file name is not root-${ski}.pem`]);
    return {
      kind: "root-cert", label: "Root certificate", menu: "7F: Cross-Certify Deputy (first scan)",
      fields, name, fileType: "B", payload: pem.der, parts: encodeParts(pem.der, "B"),
    };
  }
  const vk = BBQrDecode.csrSubjectVk(pem.der);
  if (!vk) return { error: "not an ML-DSA-65 certificate request" };
  return {
    kind: "deputy-csr", label: "Deputy certificate request", menu: "7F: Cross-Certify Deputy (second scan)",
    fields: [["Deputy subject key id (confirm by voice)", groupHex(await skiOf(vk))]],
    name, fileType: "B", payload: pem.der, parts: encodeParts(pem.der, "B"),
  };
}

return { encodeParts, qrMatrix, prepareFile, base32Encode, MAX_FILE_BYTES };

});
