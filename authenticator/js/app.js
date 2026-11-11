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
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await signTx(kp.privateKey, tx);
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor(n / 2)];
  const p95 = samples[Math.floor(0.95 * (n - 1))];
  $("bench-result").textContent =
    `ECDSA P-256 sign, n=${n}: median ${median.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms. ${navigator.userAgent}`;
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
