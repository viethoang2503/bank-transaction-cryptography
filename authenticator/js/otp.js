import { taggedMessage } from "./canonical.js";

export const HMAC_TAG = "TBA-HMAC-v1";

export function importHmacKey(raw, hash) {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash }, false, ["sign"]);
}

export function dynamicTruncate(mac, digits) {
  const off = mac[mac.length - 1] & 0x0f;
  const code = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(code % 10 ** digits).padStart(digits, "0");
}

export async function hotp(key, counter, digits = 6) {
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c % 256;
    c = Math.floor(c / 256);
  }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  return dynamicTruncate(mac, digits);
}

export function totp(key, unixSeconds, digits = 6, step = 30) {
  return hotp(key, Math.floor(unixSeconds / step), digits);
}

export async function txOtp(key, tx, digits = 8) {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, taggedMessage(HMAC_TAG, tx)));
  return dynamicTruncate(mac, digits);
}
