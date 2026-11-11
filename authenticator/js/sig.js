// Web Crypto ECDSA returns raw r||s (64 bytes); the server converts to DER.
import { taggedMessage } from "./canonical.js";

export const SIG_TAG = "TBA-SIG-v1";
const KEY_ALG = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_ALG = { name: "ECDSA", hash: "SHA-256" };

export function generateSigningKey() {
  // extractable=false applies to the private key; public keys are always exportable.
  return crypto.subtle.generateKey(KEY_ALG, false, ["sign", "verify"]);
}

export async function exportPublicKeyRaw(publicKey) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
}

export function importPublicKeyRaw(raw) {
  return crypto.subtle.importKey("raw", raw, KEY_ALG, true, ["verify"]);
}

export async function signTx(privateKey, tx) {
  return new Uint8Array(await crypto.subtle.sign(SIGN_ALG, privateKey, taggedMessage(SIG_TAG, tx)));
}

export function verifyTxSignature(publicKey, tx, signature) {
  return crypto.subtle.verify(SIGN_ALG, publicKey, signature, taggedMessage(SIG_TAG, tx));
}
