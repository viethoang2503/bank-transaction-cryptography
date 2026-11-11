// Mirror of tba_core/encoding.py. Cross-checked by shared/vectors.json.
import { b64urlDecode } from "./b64.js";

export const FIELDS = ["amount", "currency", "exp", "from", "nonce", "to", "to_name", "tx_id", "v"];
export const QR_PREFIX = "tba1:";

const PATTERNS = {
  from: /^[0-9]{6,20}$/,
  to: /^[0-9]{6,20}$/,
  to_name: /^[A-Z0-9 ]{1,64}$/,
  nonce: /^[A-Za-z0-9_-]{22}$/,
  tx_id: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  currency: /^[A-Z]{3}$/,
};

export function validateTx(tx) {
  if (tx === null || typeof tx !== "object" || Array.isArray(tx)) throw new Error("transaction must be an object");
  const keys = Object.keys(tx).sort();
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i])) throw new Error("transaction fields mismatch");
  if (tx.v !== 1) throw new Error("unsupported version");
  for (const k of ["amount", "exp"]) {
    if (!Number.isSafeInteger(tx[k]) || tx[k] < 1) throw new Error(`invalid ${k}`);
  }
  for (const [k, re] of Object.entries(PATTERNS)) {
    if (typeof tx[k] !== "string" || !re.test(tx[k])) throw new Error(`invalid ${k}`);
  }
}

export function canonicalString(tx) {
  validateTx(tx);
  const ordered = {};
  for (const k of FIELDS) ordered[k] = tx[k];
  return JSON.stringify(ordered);
}

const encoder = new TextEncoder();

export function taggedMessage(tag, tx) {
  const t = encoder.encode(tag);
  const c = encoder.encode(canonicalString(tx));
  const out = new Uint8Array(t.length + 1 + c.length);
  out.set(t, 0);
  out[t.length] = 0;
  out.set(c, t.length + 1);
  return out;
}

export function decodeQrPayload(payload) {
  if (typeof payload !== "string" || !payload.startsWith(QR_PREFIX)) throw new Error("not a TBA transaction QR code");
  const bytes = b64urlDecode(payload.slice(QR_PREFIX.length));
  if (bytes.some((b) => b < 0x20 || b > 0x7e)) throw new Error("payload is not printable ASCII");
  const text = String.fromCharCode(...bytes);
  const tx = JSON.parse(text);
  if (canonicalString(tx) !== text) throw new Error("payload is not canonical");
  return tx;
}
