import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64urlDecode, b64urlEncode } from "../js/b64.js";
import { canonicalString, decodeQrPayload } from "../js/canonical.js";
import { importHmacKey, totp, txOtp } from "../js/otp.js";
import { exportPublicKeyRaw, generateSigningKey, importPublicKeyRaw, signTx, verifyTxSignature } from "../js/sig.js";

const V = JSON.parse(readFileSync(new URL("../../shared/vectors.json", import.meta.url), "utf8"));

test("base64url roundtrip", () => {
  const bytes = Uint8Array.from({ length: 16 }, (_, i) => i);
  assert.equal(b64urlEncode(bytes), "AAECAwQFBgcICQoLDA0ODw");
  assert.deepEqual(b64urlDecode("AAECAwQFBgcICQoLDA0ODw"), bytes);
  assert.throws(() => b64urlDecode("ab=="));
});

for (const [i, c] of V.transactions.entries()) {
  test(`transaction vector ${i}: canonical, QR, HMAC OTP, Python signature`, async () => {
    assert.equal(canonicalString(c.tx), c.canonical);
    assert.deepEqual(decodeQrPayload(c.qr_payload), c.tx);
    const k = await importHmacKey(b64urlDecode(V.hmac_key), "SHA-256");
    assert.equal(await txOtp(k, c.tx, 6), c.hmac_otp_6);
    assert.equal(await txOtp(k, c.tx, 8), c.hmac_otp_8);
    const pub = await importPublicKeyRaw(b64urlDecode(V.p256_public_key));
    assert.equal(await verifyTxSignature(pub, c.tx, b64urlDecode(c.signature)), true);
  });
}

test("TOTP RFC 6238 vectors", async () => {
  const k = await importHmacKey(b64urlDecode(V.totp_key), "SHA-1");
  for (const c of V.totp) assert.equal(await totp(k, c.t, c.digits), c.code);
});

for (const c of V.invalid_qr_payloads) {
  test(`rejects invalid payload: ${c.name}`, () => {
    assert.throws(() => decodeQrPayload(c.payload));
  });
}

test("sign/verify roundtrip, 64-byte raw signature, 65-byte public key", async () => {
  const kp = await generateSigningKey();
  const tx = V.transactions[0].tx;
  const sig = await signTx(kp.privateKey, tx);
  assert.equal(sig.length, 64);
  assert.equal((await exportPublicKeyRaw(kp.publicKey)).length, 65);
  assert.equal(await verifyTxSignature(kp.publicKey, tx, sig), true);
  assert.equal(await verifyTxSignature(kp.publicKey, { ...tx, to: "0999888777" }, sig), false);
  assert.equal(kp.privateKey.extractable, false);
});
