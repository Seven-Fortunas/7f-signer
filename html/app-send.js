// "To device" tab: checks a ceremony file (bbqr-encode.js) and plays it as
// the animated BBQr the device scans, full-screen. Everything shown comes
// from the chosen file, so it is written with textContent, never innerHTML.

const sendFileEl = document.getElementById("sendFile");
const dropZone = document.getElementById("dropZone");
const sendInfoEl = document.getElementById("sendInfo");
const showQrBtn = document.getElementById("showQr");
const qrStage = document.getElementById("qrStage");
const qrCanvas = document.getElementById("qrCanvas");
const qrBar = document.getElementById("qrBar");
const qrCounter = document.getElementById("qrCounter");
const qrPauseBtn = document.getElementById("qrPause");
const qrSpeed = document.getElementById("qrSpeed");

const QR_QUIET_MODULES = 4;                       // = make_sevenf_test_qrs QR_BORDER
const INTERVALS_MS = [600, 900, 1200, 1800, 2500];
const QR_LIGHT = "#bdbdbd";                       // the proven slideshow background
const QR_DARK = "#000";

let prepared = null;     // the checked file: {label, parts, ...}
let lastFile = null;     // re-checked when the receiver changes
let matrices = [];       // QR module rows per part
let partIndex = 0;
let intervalIdx = 2;     // 1200 ms, the slideshow's proven default
let timer = null;
let paused = false;
let wakeLock = null;

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function showRefusal(name, message) {
  prepared = null;
  showQrBtn.hidden = true;
  sendInfoEl.replaceChildren(el("h2", `Not sent: ${name}`), el("p", message));
  sendInfoEl.className = "refused";
}

// Who scans the QR: a SeedSigner, or this page on another computer (an
// airgap laptop running sf-wallet-gov: CentCom and registrar files).
function sendTarget() {
  const checked = document.querySelector('input[name="sendTarget"]:checked');
  return checked ? checked.value : "device";
}

function showPrepared(p) {
  const toComputer = p.target === "computer";
  const dl = el("dl");
  const rows = [
    ["File", p.name],
    [toComputer ? "On the other computer" : "On the device", p.menu],
    ["QR parts", String(p.parts.length)],
    ...p.fields,
  ];
  for (const [k, v] of rows) dl.append(el("dt", k), el("dd", v));
  const check = toComputer
    ? "The other computer shows the same subject key id when it has scanned the file. Check it there before you use the file."
    : p.kind.endsWith("-config")
      ? "Check every field on the device. Compare its Canonical digest with the coordinator's before you confirm."
      : "Check the subject key id on the device against the one read to you by phone.";
  sendInfoEl.replaceChildren(el("h2", p.label), dl, el("p", check, "check"));
  sendInfoEl.className = "";
  showQrBtn.textContent = toComputer ? "Show QR to the other computer" : "Show QR to the device";
  showQrBtn.hidden = false;
}

let loadSeq = 0;  // only the most recently chosen file may land

async function loadFile(file) {
  if (!file) return;
  lastFile = file;
  const target = sendTarget();
  const seq = ++loadSeq;
  stopPlayer();
  prepared = null;
  showQrBtn.hidden = true;
  sendInfoEl.replaceChildren(el("p", `Checking ${file.name}...`));
  sendInfoEl.className = "";
  let result;
  if (file.size > BBQrEncode.MAX_FILE_BYTES) {
    result = { error: `the file is ${file.size} bytes; ceremony files are under ${BBQrEncode.MAX_FILE_BYTES}` };
  } else {
    try {
      result = await BBQrEncode.prepareFile(file.name, new Uint8Array(await file.arrayBuffer()), target);
    } catch (e) {
      result = { error: `could not read the file: ${e.message}` };
    }
  }
  if (seq !== loadSeq) return;  // a newer file was chosen meanwhile
  if (result.error) {
    showRefusal(file.name, result.error);
    return;
  }
  stopPlayer();
  prepared = { ...result, target };
  matrices = result.parts.map(BBQrEncode.qrMatrix);
  partIndex = 0;
  showPrepared(prepared);
}

sendFileEl.addEventListener("change", () => loadFile(sendFileEl.files[0]));
for (const radio of document.querySelectorAll('input[name="sendTarget"]')) {
  radio.addEventListener("change", () => { if (lastFile) loadFile(lastFile); });
}
dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("over");
  loadFile(e.dataTransfer.files[0]);
});

// Whole device pixels per module, so every module edge is sharp.
function drawPart() {
  const rows = matrices[partIndex];
  const n = rows.length + 2 * QR_QUIET_MODULES;
  const dpr = window.devicePixelRatio || 1;
  const cssSide = Math.min(window.innerWidth, window.innerHeight - qrBar.offsetHeight - 8);
  const module = Math.max(1, Math.floor((cssSide * dpr) / n));
  const side = module * n;
  qrCanvas.width = side;
  qrCanvas.height = side;
  qrCanvas.style.width = `${side / dpr}px`;
  qrCanvas.style.height = `${side / dpr}px`;
  const ctx = qrCanvas.getContext("2d");
  ctx.fillStyle = QR_LIGHT;
  ctx.fillRect(0, 0, side, side);
  ctx.fillStyle = QR_DARK;
  rows.forEach((row, r) => {
    for (let c = 0; c < row.length; c++) {
      if (row[c] === "1") ctx.fillRect((c + QR_QUIET_MODULES) * module, (r + QR_QUIET_MODULES) * module, module, module);
    }
  });
  qrCounter.textContent = `${partIndex + 1} / ${matrices.length}`;
}

function step(delta) {
  partIndex = (partIndex + delta + matrices.length) % matrices.length;
  drawPart();
}

function schedule() {
  clearInterval(timer);
  timer = null;
  qrSpeed.textContent = `${(INTERVALS_MS[intervalIdx] / 1000).toFixed(1)} s`;
  qrPauseBtn.textContent = paused ? "Play" : "Pause";
  if (!paused && matrices.length > 1) timer = setInterval(() => step(1), INTERVALS_MS[intervalIdx]);
}

async function acquireWakeLock() {
  if (!navigator.wakeLock || wakeLock) return;
  try {
    const lock = await navigator.wakeLock.request("screen");
    if (qrStage.hidden || wakeLock) {
      lock.release().catch(() => {});
      return;
    }
    wakeLock = lock;
    lock.addEventListener("release", () => { if (wakeLock === lock) wakeLock = null; });
  } catch (e) {
    // keep the screen on by hand if the browser won't
  }
}

async function startPlayer() {
  if (!prepared) return;
  partIndex = 0;
  paused = false;
  qrStage.hidden = false;
  try {
    if (qrStage.requestFullscreen) await qrStage.requestFullscreen();
  } catch (e) {
    // iPhone Safari has no element full-screen; the fixed overlay covers the page anyway.
  }
  if (qrStage.hidden) return;  // Done was pressed while full-screen was starting
  drawPart();
  schedule();
  acquireWakeLock();
}

function stopPlayer() {
  clearInterval(timer);
  timer = null;
  qrStage.hidden = true;
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  if (wakeLock) wakeLock.release().catch(() => {});
  wakeLock = null;
}

// The browser drops the wake lock whenever the page is hidden; take it back.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && !qrStage.hidden) acquireWakeLock();
});

showQrBtn.addEventListener("click", startPlayer);
document.getElementById("qrClose").addEventListener("click", stopPlayer);
document.getElementById("qrPrev").addEventListener("click", () => step(-1));
document.getElementById("qrNext").addEventListener("click", () => step(1));
qrPauseBtn.addEventListener("click", () => { paused = !paused; schedule(); });
document.getElementById("qrSlower").addEventListener("click", () => { intervalIdx = Math.min(intervalIdx + 1, INTERVALS_MS.length - 1); schedule(); });
document.getElementById("qrFaster").addEventListener("click", () => { intervalIdx = Math.max(intervalIdx - 1, 0); schedule(); });
window.addEventListener("resize", () => { if (!qrStage.hidden) drawPart(); });
document.addEventListener("fullscreenchange", () => { if (!document.fullscreenElement && !qrStage.hidden) drawPart(); });
document.addEventListener("keydown", (e) => {
  if (qrStage.hidden) return;
  if (e.key === "Escape") stopPlayer();
  else if (e.key === "ArrowLeft") step(-1);
  else if (e.key === "ArrowRight") step(1);
  else if (e.key === " ") { e.preventDefault(); paused = !paused; schedule(); }
});

window.SendTab = { stop: stopPlayer };
