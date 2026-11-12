# Plan 03: Phone authenticator (web app)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Web app chạy trên điện thoại: đăng ký thiết bị, hiển thị TOTP (baseline), quét QR giao dịch, hiển thị chi tiết (hoặc ẩn ở `sig_blind`), tạo OTP gắn giao dịch hoặc ký ECDSA và gửi về server, cùng một nút benchmark ký.

**Architecture:** ES modules thuần, không build step. Các module mật mã (`b64`, `canonical`, `otp`, `sig`) không đụng DOM nên test được bằng `node --test` với `shared/vectors.json`. `app.js` chỉ lo giao diện. Server phục vụ thư mục này tại `/app/`.

**Tech Stack:** HTML, JavaScript ES2022, Web Crypto (`crypto.subtle`), IndexedDB, jsQR 1.4.0 (vendored), Node ≥ 20 cho test.

**Spec:** `docs/superpowers/specs/2026-11-06-tba-midterm-design.md` (mục 4.1-4.4)

## Global Constraints

- Encoding phải cho ra đúng chuỗi byte như `tba_core/encoding.py` (kiểm bằng `shared/vectors.json`).
- Domain tag `"TBA-HMAC-v1"` và `"TBA-SIG-v1"`, nối với canonical bằng byte `0x00`.
- Khóa ký P-256 sinh ngay trên điện thoại với `extractable = false`: khóa riêng không bao giờ được xuất ra qua Web Crypto API (bảo vệ ở mức API trình duyệt, không có phần cứng bảo vệ).
- `k_totp` và `k_hmac` là **khóa bí mật dùng chung**: server sinh, gửi dạng rõ trong JSON của `POST /api/device/enroll` (qua HTTPS) và lưu dạng rõ trong bảng `devices`. Điện thoại import chúng với `extractable = false`, nên chỉ *sau khi import* thì JS không đọc lại được byte khóa. Không được viết rằng khóa HMAC "không bao giờ rời thiết bị" (xem S10: lộ DB thì `hmac` bị phá).
- Chế độ `sig_blind` **không được** hiển thị bất kỳ trường nào của giao dịch.
- Giao diện tiếng Anh.

## File structure

| File | Trách nhiệm |
|---|---|
| `authenticator/package.json` | `{"type": "module"}` để Node coi `.js` là ES module |
| `authenticator/js/b64.js` | base64url |
| `authenticator/js/canonical.js` | validate, canonical, tagged message, decode QR |
| `authenticator/js/otp.js` | HOTP/TOTP, OTP gắn giao dịch |
| `authenticator/js/sig.js` | ECDSA P-256 |
| `authenticator/js/store.js` | IndexedDB key-value |
| `authenticator/js/app.js` | Giao diện |
| `authenticator/index.html`, `authenticator/app.css` | Trang |
| `authenticator/vendor/jsQR.js` | Thư viện quét QR |
| `authenticator/tests/vectors.test.mjs` | Test chéo với Python |

---

### Task 1: Module mật mã + test chéo (TV4)

**Files:**
- Create: `authenticator/package.json`, `authenticator/js/b64.js`, `authenticator/js/canonical.js`, `authenticator/js/otp.js`, `authenticator/js/sig.js`
- Test: `authenticator/tests/vectors.test.mjs`
- Modify: `Makefile` (thêm `test-js`)

**Interfaces:**
- Consumes: `shared/vectors.json` (plan 01 Task 7)
- Produces:
  - `b64urlEncode(bytes: Uint8Array) -> string`, `b64urlDecode(s: string) -> Uint8Array`
  - `FIELDS`, `QR_PREFIX`, `validateTx(tx)`, `canonicalString(tx) -> string`, `taggedMessage(tag: string, tx) -> Uint8Array`, `decodeQrPayload(payload: string) -> tx`
  - `HMAC_TAG`, `importHmacKey(raw, hash: "SHA-1"|"SHA-256") -> CryptoKey`, `dynamicTruncate(mac, digits) -> string`, `hotp(key, counter, digits) -> Promise<string>`, `totp(key, unixSeconds, digits=6, step=30) -> Promise<string>`, `txOtp(key, tx, digits=8) -> Promise<string>`
  - `SIG_TAG`, `generateSigningKey() -> CryptoKeyPair`, `exportPublicKeyRaw(publicKey) -> Uint8Array(65)`, `importPublicKeyRaw(raw) -> CryptoKey`, `signTx(privateKey, tx) -> Uint8Array(64)`, `verifyTxSignature(publicKey, tx, sig) -> boolean`

- [ ] **Step 1: Tạo `authenticator/package.json`**

```json
{ "name": "tba-authenticator", "private": true, "type": "module" }
```

- [ ] **Step 2: Viết test thất bại `authenticator/tests/vectors.test.mjs`**

```js
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
```

- [ ] **Step 3: Thêm target `test-js` vào `Makefile`** (thụt bằng TAB)

```make
.PHONY: test-js

test-js:
	node --test authenticator/tests/*.test.mjs
```

- [ ] **Step 4: Chạy để thấy test thất bại**

Run: `make test-js`
Expected: FAIL với `ERR_MODULE_NOT_FOUND` cho `../js/b64.js`

- [ ] **Step 5: Cài đặt `authenticator/js/b64.js`**

```js
export function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) {
    throw new Error("invalid base64url");
  }
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
```

- [ ] **Step 6: Cài đặt `authenticator/js/canonical.js`**

```js
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
```

- [ ] **Step 7: Cài đặt `authenticator/js/otp.js`**

```js
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
```

- [ ] **Step 8: Cài đặt `authenticator/js/sig.js`**

```js
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
```

- [ ] **Step 9: Chạy test**

Run: `make test-js`
Expected: mọi test pass, gồm 3 vector giao dịch, TOTP và 14 payload không hợp lệ

- [ ] **Step 10: Commit**

```bash
git add authenticator/package.json authenticator/js authenticator/tests Makefile
git commit -m "feat(authenticator): crypto modules cross-checked against Python vectors"
```

---

### Task 2: Giao diện app (TV4)

**Files:**
- Create: `authenticator/index.html`, `authenticator/app.css`, `authenticator/js/store.js`, `authenticator/js/app.js`, `authenticator/vendor/jsQR.js`

**Interfaces:**
- Consumes: Task 1; API `/api/config`, `/api/device/enroll`, `/api/device/confirm` (plan 02 Task 4)
- Produces: trang `/app/` dùng được trên điện thoại; mọi phần tử có `id` như dưới đây (dùng khi chụp ảnh cho report)

- [ ] **Step 1: Tải jsQR** (giấy phép Apache-2.0; ghi vào README)

Run: `mkdir -p authenticator/vendor && curl -fL -o authenticator/vendor/jsQR.js https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js && grep -c jsQR authenticator/vendor/jsQR.js`
Expected: một số > 0

- [ ] **Step 2: Viết `authenticator/js/store.js`**

```js
// Minimal IndexedDB key-value store. CryptoKey objects are structured-cloneable,
// so non-extractable keys can be persisted without ever exposing key bytes.
const DB_NAME = "tba-authenticator";
const STORE = "kv";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(req.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export const get = (key) => run("readonly", (s) => s.get(key));
export const put = (key, value) => run("readwrite", (s) => s.put(value, key));
export const clear = () => run("readwrite", (s) => s.clear());
```

- [ ] **Step 3: Viết `authenticator/index.html`**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TBA Authenticator</title>
<link rel="stylesheet" href="app.css">
<script src="vendor/jsQR.js"></script>
<script type="module" src="js/app.js"></script>
</head>
<body>
<header><h1>TBA Authenticator</h1><span id="mode-badge"></span></header>
<main>
  <section id="view-enroll" hidden>
    <p>This device is not enrolled. Log in to the bank website, open “Enroll authenticator” and scan the QR code.</p>
    <button id="btn-scan-enroll">Scan enrollment QR</button>
  </section>

  <section id="view-home" hidden>
    <p>Device <code id="device-id"></code></p>
    <div id="totp-box" hidden>
      <p>Your one-time code</p>
      <p class="code" id="totp-code"></p>
      <p id="totp-ttl"></p>
    </div>
    <button id="btn-scan-tx">Scan transaction QR</button>
    <button id="btn-bench" class="secondary">Run signing benchmark</button>
    <button id="btn-reset" class="danger">Forget this device</button>
  </section>

  <section id="view-scan" hidden>
    <video id="video" playsinline muted></video>
    <canvas id="canvas" hidden></canvas>
    <details><summary>Paste payload instead</summary>
      <textarea id="paste" rows="3"></textarea>
      <button id="btn-paste">Use pasted payload</button>
    </details>
    <button id="btn-cancel-scan" class="secondary">Cancel</button>
  </section>

  <section id="view-tx" hidden>
    <div id="tx-details">
      <h2>Confirm transfer</h2>
      <dl>
        <dt>Amount</dt><dd id="tx-amount" class="big"></dd>
        <dt>To account</dt><dd id="tx-to" class="big"></dd>
        <dt>Recipient</dt><dd id="tx-name"></dd>
        <dt>From</dt><dd id="tx-from"></dd>
        <dt>Expires in</dt><dd id="tx-exp"></dd>
      </dl>
    </div>
    <div id="tx-blind" hidden>
      <h2>Approve pending transaction?</h2>
      <p>A transaction is waiting for your approval.</p>
    </div>
    <div id="tx-otp" hidden>
      <p>Enter this code on the bank website:</p>
      <p class="code" id="tx-otp-code"></p>
    </div>
    <div id="tx-actions">
      <button id="btn-approve">Approve</button>
      <button id="btn-reject" class="danger">Reject</button>
    </div>
    <p id="tx-result"></p>
    <button id="btn-home" class="secondary">Back</button>
  </section>

  <section id="view-bench" hidden>
    <p id="bench-result"></p>
    <button id="btn-bench-back" class="secondary">Back</button>
  </section>

  <p id="error" class="error"></p>
</main>
</body>
</html>
```

- [ ] **Step 4: Viết `authenticator/app.css`**

```css
body { font-family: system-ui, sans-serif; margin: 0; color: #1a1a1a; }
header { display: flex; justify-content: space-between; align-items: center; padding: .5rem 1rem; background: #123; color: #fff; }
header h1 { font-size: 1.1rem; margin: 0; }
#mode-badge { font-family: monospace; background: #345; padding: .1rem .4rem; border-radius: .3rem; }
main { padding: 1rem; max-width: 30rem; margin: auto; }
button { display: block; width: 100%; font-size: 1.1rem; padding: .8rem; margin: .5rem 0; border: 0; border-radius: .5rem; background: #1565c0; color: #fff; }
button.secondary { background: #607d8b; }
button.danger { background: #c62828; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }
dt { color: #555; }
dd { margin: 0; font-weight: 600; }
.big { font-size: 1.4rem; }
.code { font-family: monospace; font-size: 2.2rem; letter-spacing: .15rem; text-align: center; }
.error { color: #b00020; }
video { width: 100%; border-radius: .5rem; background: #000; }
textarea { width: 100%; }
```

- [ ] **Step 5: Viết `authenticator/js/app.js`**

```js
import { b64urlDecode, b64urlEncode } from "./b64.js";
import { decodeQrPayload } from "./canonical.js";
import { importHmacKey, totp, txOtp } from "./otp.js";
import { exportPublicKeyRaw, generateSigningKey, signTx } from "./sig.js";
import * as store from "./store.js";

const $ = (id) => document.getElementById(id);
const VIEWS = ["enroll", "home", "scan", "tx", "bench"];
const money = new Intl.NumberFormat("en-US");
const state = { config: null, device: null, totpTimer: null, stopScan: null, tx: null };

function show(name) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== name;
  $("error").textContent = "";
}

function fail(err) {
  console.error(err);
  $("error").textContent = String(err?.message ?? err);
}

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function stopTotp() {
  if (state.totpTimer) clearInterval(state.totpTimer);
  state.totpTimer = null;
}

function startTotp() {
  stopTotp();
  const tick = async () => {
    const now = Math.floor(Date.now() / 1000);
    $("totp-code").textContent = await totp(state.device.kTotp, now, state.config.totp_digits);
    $("totp-ttl").textContent = `changes in ${30 - (now % 30)} s`;
  };
  tick().catch(fail);
  state.totpTimer = setInterval(() => tick().catch(fail), 1000);
}

function goHome() {
  if (state.stopScan) state.stopScan();
  state.tx = null;
  if (!state.device) { stopTotp(); show("enroll"); return; }
  const baseline = state.config.mode === "baseline";
  $("device-id").textContent = state.device.deviceId;
  $("totp-box").hidden = !baseline;
  $("btn-scan-tx").hidden = baseline;
  if (baseline) startTotp(); else stopTotp();
  show("home");
}

async function startScan(onPayload) {
  show("scan");
  $("paste").value = "";
  const deliver = (payload) => { if (state.stopScan) state.stopScan(); onPayload(payload); };
  $("btn-paste").onclick = () => { const v = $("paste").value.trim(); if (v) deliver(v); };
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  } catch (e) {
    fail(`Camera unavailable (${e.message}). Paste the payload instead.`);
    return;
  }
  const video = $("video");
  const canvas = $("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let active = true;
  state.stopScan = () => { active = false; stream.getTracks().forEach((t) => t.stop()); state.stopScan = null; };
  video.srcObject = stream;
  await video.play();
  const loop = () => {
    if (!active) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = globalThis.jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (code?.data) { deliver(code.data); return; }
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}

async function enroll(payload) {
  const prefix = "tbaenroll1:";
  if (!payload.startsWith(prefix)) throw new Error("Not an enrollment QR code");
  const keyPair = await generateSigningKey();
  const res = await api("/api/device/enroll", {
    token: payload.slice(prefix.length),
    public_key: b64urlEncode(await exportPublicKeyRaw(keyPair.publicKey)),
  });
  const device = {
    deviceId: res.device_id,
    signingKey: keyPair.privateKey,
    kTotp: await importHmacKey(b64urlDecode(res.k_totp), "SHA-1"),
    kHmac: await importHmacKey(b64urlDecode(res.k_hmac), "SHA-256"),
  };
  await store.put("device", device);
  state.device = device;
  goHome();
}

function showTx(payload) {
  const tx = decodeQrPayload(payload);
  const blind = state.config.mode === "sig_blind";
  state.tx = tx;
  $("tx-details").hidden = blind;
  $("tx-blind").hidden = !blind;
  $("tx-otp").hidden = true;
  $("tx-actions").hidden = false;
  $("tx-result").textContent = "";
  if (!blind) {
    $("tx-amount").textContent = `${money.format(tx.amount)} ${tx.currency}`;
    $("tx-to").textContent = tx.to;
    $("tx-name").textContent = tx.to_name;
    $("tx-from").textContent = tx.from;
    $("tx-exp").textContent = `${Math.max(0, tx.exp - Math.floor(Date.now() / 1000))} s`;
  }
  show("tx");
}

async function approve() {
  const tx = state.tx;
  $("tx-actions").hidden = true;
  if (state.config.mode === "hmac") {
    const code = await txOtp(state.device.kHmac, tx, state.config.otp_digits);
    $("tx-otp-code").textContent = code.replace(/(\d{4})(?=\d)/g, "$1 ");
    $("tx-otp").hidden = false;
    return;
  }
  const signature = await signTx(state.device.signingKey, tx);
  const res = await api("/api/device/confirm", {
    device_id: state.device.deviceId, tx_id: tx.tx_id, signature: b64urlEncode(signature),
  });
  $("tx-result").textContent = res.result === "ok"
    ? "Approved. The bank accepted the signature."
    : "The bank rejected the signature.";
}

function reject() {
  $("tx-actions").hidden = true;
  $("tx-result").textContent = "Rejected. Nothing was sent to the bank.";
}

async function bench() {
  show("bench");
  $("bench-result").textContent = "Running…";
  const kp = await generateSigningKey();
  const tx = { amount: 1000000, currency: "VND", exp: 1800000120, from: "0011223344",
    nonce: "AAECAwQFBgcICQoLDA0ODw", to: "0123456789", to_name: "TRAN THI B",
    tx_id: "3f2b8c1e-5a4d-4e7f-9b6a-1c2d3e4f5a6b", v: 1 };
  const n = 200;
  const samples = [];
  const start = performance.now();
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await signTx(kp.privateKey, tx);
    samples.push(performance.now() - t0);
  }
  // Browsers coarsen performance.now() (Safari: 1 ms), so single samples can read 0; the mean over the whole run is reliable.
  const mean = (performance.now() - start) / n;
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor(n / 2)];
  const p95 = samples[Math.floor(0.95 * (n - 1))];
  $("bench-result").textContent =
    `ECDSA P-256 sign, n=${n}: mean ${mean.toFixed(3)} ms, median ${median.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms. ${navigator.userAgent}`;
}

async function init() {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    fail("Not a secure context. Open this page over HTTPS.");
    return;
  }
  state.config = await api("/api/config");
  $("mode-badge").textContent = state.config.mode;
  state.device = (await store.get("device")) ?? null;
  goHome();
}

$("btn-scan-enroll").onclick = () => startScan((p) => enroll(p).catch(fail));
$("btn-scan-tx").onclick = () => startScan((p) => { try { showTx(p); } catch (e) { goHome(); fail(e); } });
$("btn-cancel-scan").onclick = goHome;
$("btn-home").onclick = goHome;
$("btn-approve").onclick = () => approve().catch(fail);
$("btn-reject").onclick = reject;
$("btn-bench").onclick = () => bench().catch(fail);
$("btn-bench-back").onclick = goHome;
$("btn-reset").onclick = async () => {
  if (!confirm("Forget this device? The bank will not let this account enroll again until its database is reset (make reset).")) return;
  await store.clear();
  state.device = null;
  goHome();
};

init().catch(fail);
```

- [ ] **Step 6: Kiểm tra thủ công trên laptop** (chưa cần điện thoại)

1. `make run MODE=hmac`, mở `https://localhost:8443/` → đăng nhập `alice` → mở **Enroll authenticator** → mở mục "Show payload" và copy.
2. Ở tab khác mở `https://localhost:8443/app/` → **Scan enrollment QR** → mở "Paste payload instead" → dán → **Use pasted payload**.
   Expected: chuyển sang màn hình home, hiện `Device <uuid>`.
3. Ở tab ngân hàng: chuyển `1000000` tới `0123456789` → trên trang xác nhận, chuột phải vào QR → Inspect → copy giá trị `data-payload`.
4. Ở tab app: **Scan transaction QR** → dán payload.
   Expected: hiện `1,000,000 VND`, `0123456789`, `TRAN THI B`.
5. **Approve** → nhập mã 8 chữ số vào trang ngân hàng.
   Expected: "Transfer completed".
6. Lặp lại với `make run MODE=sig_blind` (xóa thiết bị bằng **Forget this device** rồi đăng ký lại; mỗi chế độ có DB riêng nên lần đầu đăng ký được ngay, còn muốn đăng ký lại trong một chế độ đã dùng thì dừng server và chạy `make reset MODE=<mode>`, vì server không cho thay thiết bị qua web).
   Expected: màn hình chỉ có "Approve pending transaction?", không có số tiền hay tài khoản; sau Approve, trang ngân hàng tự chuyển sang "Transfer completed".

- [ ] **Step 7: Kiểm tra trên điện thoại thật** (sau spike HTTPS của plan 02 Task 5)

Làm lại bước 1-6 nhưng quét QR bằng camera. Ghi lại model điện thoại và trình duyệt cho report.

- [ ] **Step 8: Commit**

```bash
git add authenticator
git commit -m "feat(authenticator): phone UI with QR scanning, blind mode and signing benchmark"
```

---

### Task 3: Đo P2 trên điện thoại (TV4, sau M2)

- [ ] **Step 1:** Trên 2-3 điện thoại của các thành viên, mở `/app/` → **Run signing benchmark**, chụp màn hình kết quả.
- [ ] **Step 2:** Ghi vào `results/phone_bench.csv`:

```csv
device,browser,n,mean_ms,median_ms,p95_ms
iPhone 13,Safari 18,200,<mean>,<median>,<p95>
```

(mỗi dòng là một điện thoại; số liệu lấy từ màn hình kết quả)

- [ ] **Step 3:** Report ghi chú: `performance.now()` bị giảm độ phân giải trên một số trình duyệt, nên median và p95 dưới 1 ms chỉ mang tính tương đối (Safari iOS làm tròn về 1 ms, median có thể đọc là 0); dùng `mean_ms` (tổng thời gian chia n) làm số chính.
- [ ] **Step 4: Commit**

```bash
git add results/phone_bench.csv
git commit -m "data: phone signing benchmark"
```
