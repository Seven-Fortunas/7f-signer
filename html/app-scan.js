// "From device" tab: scans the device's animated BBQr exports and saves
// the checked files. The camera runs only while this tab is shown.
const session = new BBQrDecode.BBQrSession();
const statusEl = document.getElementById("status");
const signalEl = document.getElementById("signal");
const progressEl = document.getElementById("progress");
const gridEl = document.getElementById("grid");
const missingEl = document.getElementById("missing");
const resultEl = document.getElementById("result");
const copyBtn = document.getElementById("copy");
const copyVkBtn = document.getElementById("copyVk");
const copyIdBtn = document.getElementById("copyId");
const copyAllBtn = document.getElementById("copyAll");
const saveExportBtn = document.getElementById("saveExport");
const saveSummaryBtn = document.getElementById("saveSummary");
const vkNoteEl = document.getElementById("vkNote");
const video = document.getElementById("video");
const overlay = document.getElementById("overlay");
const capture = document.getElementById("capture");

// Operator feedback for "am I in range," distinct from scan progress.
// Without this, a correctly-aimed camera re-reading a part it already has
// looks IDENTICAL to one that's out of focus and seeing nothing at all --
// both show no visible change. A re-read of an already-captured part is
// itself proof the framing/distance/focus is fine; the fix needed then is
// "show the next part," not "adjust the camera." This surfaces that
// distinction instead of leaving the operator to guess from a static screen.
const SIGNAL_WINDOW_MS = 1500;
const RECENT_RESULT_MS = 2000;
let cameraStarted = false;
let detectionTimestamps = []; // ms timestamps of ticks where jsQR found any code
let lastResult = null; // { index, isNew, at }
let lastVkText = null;
let lastIdText = null;
let lastBundleText = null;
let lastExport = null;  // a checked device export envelope: {file, body, ...}

function recordDetection(found, now) {
  if (found) detectionTimestamps.push(now);
  while (detectionTimestamps.length && now - detectionTimestamps[0] > SIGNAL_WINDOW_MS) {
    detectionTimestamps.shift();
  }
}

function renderSignal(now) {
  if (!cameraStarted) {
    signalEl.textContent = "";
    signalEl.className = "";
    return;
  }
  if (lastResult && now - lastResult.at < RECENT_RESULT_MS) {
    if (lastResult.isNew) {
      signalEl.textContent = `Captured part ${lastResult.index + 1} -- good range`;
    } else {
      signalEl.textContent = `Part ${lastResult.index + 1} already captured, still in range -- show the next part`;
    }
    signalEl.className = "good";
    return;
  }
  const detections = detectionTimestamps.length;
  if (detections === 0) {
    signalEl.textContent = "No QR detected -- move closer or check focus/lighting";
    signalEl.className = "weak";
  } else if (detections < 6) {
    signalEl.textContent = "Faint signal -- hold steadier";
    signalEl.className = "weak";
  } else {
    signalEl.textContent = "Good signal";
    signalEl.className = "good";
  }
}

function renderProgress(justGotIndex) {
  if (session.total === null) {
    progressEl.textContent = "";
    gridEl.innerHTML = "";
    missingEl.textContent = "";
    return;
  }
  progressEl.textContent = `${session.segments.size} / ${session.total} parts`;

  gridEl.innerHTML = "";
  for (let i = 0; i < session.total; i++) {
    const cell = document.createElement("div");
    const got = session.segments.has(i);
    cell.className = "cell" + (got ? " got" : "") + (i === justGotIndex ? " just-got" : "");
    cell.textContent = i + 1;
    gridEl.appendChild(cell);
  }

  const missing = session.missingIndices();
  missingEl.textContent = missing.length && missing.length <= 20
    ? `missing: ${missing.map(i => i + 1).join(", ")}`
    : "";
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// textContent + a class, never innerHTML: encoding/fileType (single chars)
// and error messages can include content read directly off a scanned QR
// (untrusted input by design for this tool), so there is no reason to give
// any of it a path into the DOM as markup, however narrow that path is
// today (see common/security.md's "never inject unsanitized HTML").
function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "";
}

// BBQrDecode.ski() (bbqr-decode.js, shared with decode_cli.js so it's
// covered by tests/test_bbqr_web_scanner.py) -- the same subject key id the
// device itself shows on its "Subject key id" screen before export, and the
// one sf-wallet-gov prints and names `<ski>.vk` by, so this is a genuine
// independent cross-check, not just redisplaying the input.

// A 1952-byte ML-DSA-65 verification key is the only payload this project's
// device ever exports as BBQr file_type 'U' (confirmed: the device's own
// views/sevenf_views/_root_cert.py and _genesis.py are the only two 'U'
// export sites, both vk hex) -- gate on that exact shape so a decoded value
// that happens to also be plain hex text, but isn't a vk, doesn't get a
// meaningless subject key id / pin shown next to it.
const VK_HEX_LEN = 1952 * 2;

async function renderResult(bytes) {
  let text;
  let vkInfo = null;    // {id, pin, bundle} for a well-formed vk
  let vkError = null;   // why vkInfo couldn't be computed
  let exportInfo = null;
  if (session.fileType === "J") {
    const raw = new TextDecoder().decode(bytes);
    try {
      exportInfo = await BBQrDecode.inspectExport(raw);
    } catch (e) {
      exportInfo = { error: `couldn't check this export: ${e.message}` };
    }
    try {
      const obj = JSON.parse(raw);
      text = exportInfo && typeof exportInfo.body === "string" ? exportInfo.body : JSON.stringify(obj, null, 2);
    } catch (e) {
      text = `(claimed JSON but failed to parse: ${e.message})\n\nhex:\n${bytesToHex(bytes)}`;
    }
  } else if (session.fileType === "U") {
    text = new TextDecoder().decode(bytes);
    if (text.trim().length === VK_HEX_LEN) {
      // A failure here (e.g. a stale cached bbqr-decode.js from before
      // ski() existed, or an unsupported crypto.subtle) must never
      // prevent the actual decoded result below from displaying -- that's
      // the primary thing this page exists to show. Found live 2026-10-07:
      // this was previously unguarded, and because renderResult() is
      // async, a thrown error here aborted the whole function before
      // resultEl.textContent was ever set, with no visible error at all --
      // the scan looked complete but nothing displayed.
      try {
        const [id, bundle] = await Promise.all([BBQrDecode.ski(text), BBQrDecode.vkBundle(text)]);
        if (id && bundle) vkInfo = { id, bundle };
      } catch (e) {
        console.warn("subject key id / pin computation failed:", e.message);
        vkError = `(subject key id and pin unavailable: ${e.message} -- try a hard refresh)`;
      }
    }
  } else {
    text = `file_type=${session.fileType}, ${bytes.length} bytes\n\nhex:\n${bytesToHex(bytes)}`;
  }
  if (exportInfo && exportInfo.error) {
    resultEl.textContent = `NOT SAVED -- this export failed its check: ${exportInfo.error}\n\n${text}`;
  } else if (exportInfo) {
    const label = {
      "root-vk": "ROOT verification key",
      "devfund-vk": "DEV-FUND verification key",
      "root-cert": "Root certificate",
      "deputy-cert": "Deputy certificate",
      "genesis-sig": "Genesis signature (Root key)",
      "devfund-sig": "Dev-fund definition signature (Root key)",
    }[exportInfo.kind] || exportInfo.kind;
    const pinLine = exportInfo.pin ? `\nRoot pin: ${exportInfo.pin}` : "";
    const keyNote = exportInfo.kind.endsWith("-sig") && !exportInfo.pin
      ? "\nKey not embedded: the coordinator pairs this with <subject key id>.vk." : "";
    const idLabel = exportInfo.kind.endsWith("-sig") ? "Signed by subject key id" : "Subject key id";
    const folderLine = exportInfo.folder ? `\nBelongs in: ${exportInfo.folder}` : "";
    const issuerLine = exportInfo.issuer_ski ? `\nIssued by Root subject key id: ${exportInfo.issuer_ski}` : "";
    resultEl.textContent = `${label}\nFile: ${exportInfo.file}\n${idLabel}: ${exportInfo.ski}${folderLine}${issuerLine}${pinLine}${keyNote}\n\n${text}`;
  } else if (vkInfo) {
    // A bare key carries no role, so it is shown but not saved: as a .vk it
    // could land in the wrong role's folder. The device exports keys tagged.
    resultEl.textContent = `Subject key id: ${vkInfo.id}\nNo role: not saved. Export it from the device's 7F: Enroll menu.\n\n${text}`;
  } else {
    resultEl.textContent = vkError ? `${vkError}\n\n${text}` : text;
  }
  setStatus(`Complete -- ${bytes.length} bytes decoded.`, "ok");

  // A vk result gets its own buttons: "Copy all" is everything a member
  // hands the coordinator for one key (ski, pin, file name, vk -- the
  // labels sf-wallet-gov prints), "Copy VK" is the bare hex for the .vk file,
  // "Copy ID" the 40-char ski to read aloud. Shown only when the ids were
  // actually computed, so no button can copy an error message.
  lastExport = exportInfo && !exportInfo.error ? exportInfo : null;
  saveExportBtn.hidden = !lastExport;
  if (lastExport) saveExportBtn.textContent = `Save ${lastExport.file}`;
  if (vkInfo) {
    // Exactly what sf-wallet-gov writes to a .vk file: lowercase hex plus a
    // trailing newline (main.rs: so `cat *.vk` can't join two keys).
    lastVkText = `${text.trim().toLowerCase()}\n`;
    lastIdText = vkInfo.id;
    lastBundleText = vkInfo.bundle;
    copyBtn.hidden = true;
    vkNoteEl.hidden = false;
    saveSummaryBtn.hidden = true;
    copyAllBtn.hidden = false;
    copyAllBtn.textContent = "Copy all";
    copyVkBtn.hidden = false;
    copyVkBtn.textContent = "Copy VK";
    copyIdBtn.hidden = false;
    copyIdBtn.textContent = "Copy ID";
  } else {
    copyBtn.hidden = !!(exportInfo && exportInfo.error);
    copyBtn.textContent = "Copy result";
    vkNoteEl.hidden = true;
    copyAllBtn.hidden = true;
    saveSummaryBtn.hidden = true;
    copyVkBtn.hidden = true;
    copyIdBtn.hidden = true;
  }
  // A role-tagged vk also offers the summary record, with its role.
  if (lastExport && lastExport.folder) saveSummaryBtn.hidden = false;
}

function handleDecodedText(text, now) {
  try {
    if (session.isComplete) {
      // Locked until Reset: the next code on screen must not mix with this one.
      setStatus("Done. Save what you need, then press Reset to scan the next code.", "ok");
      return;
    }
    const result = session.addSegment(text);
    if (result.kind === "conflict") {
      setStatus("A frame from a different code was seen. Press Reset and scan one code at a time.", "error");
      return;
    }
    if (result.kind === "not-bbqr") {
      return; // ignore non-BBQr QR content (e.g. a stray code in frame)
    }
    lastResult = { index: result.index, isNew: result.isNew, at: now };
    renderProgress(result.isNew ? result.index : undefined);
    if (session.isComplete) {
      const bytes = session.decode();
      // renderResult() is async -- a rejection from it is NOT caught by
      // this surrounding try/catch (that only covers the synchronous call
      // itself), so without this .catch() a later failure inside it would
      // fail silently: the scan would look complete with no result and no
      // visible error. Found live 2026-10-07.
      renderResult(bytes).catch((e) => setStatus(`Failed to render result: ${e.message}`, "error"));
    }
  } catch (e) {
    setStatus(e.message, "error");
  }
}

document.getElementById("reset").addEventListener("click", () => {
  session.reset();
  statusEl.textContent = "Scanning...";
  resultEl.textContent = "";
  lastResult = null;
  detectionTimestamps = [];
  renderProgress();
  copyBtn.hidden = true;
  copyVkBtn.hidden = true;
  copyIdBtn.hidden = true;
  copyAllBtn.hidden = true;
  saveSummaryBtn.hidden = true;
  saveExportBtn.hidden = true;
  lastExport = null;
  vkNoteEl.hidden = true;
  lastVkText = null;
  lastIdText = null;
  lastBundleText = null;
});

// For a long hex value (e.g. a 1952-byte ML-DSA-65 verification key, 3904 hex
// characters), manually selecting and copying on a phone is slow and
// error-prone -- this is specifically for pasting a decoded result into a
// message to send elsewhere. navigator.clipboard requires a secure context
// (HTTPS or localhost), same requirement this page's camera access already
// has (see README.md) -- no new deployment constraint.
//
// Shared by every copy button (generic "copy result", and the vk result's
// "copy all" / "copy just the vk" / "copy just the id") -- getText is
// called at click time, not bind time, so it always reads whatever the most
// recent scan produced rather than a stale closed-over value.
function wireCopyButton(btn, label, getText) {
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = label; }, 1500);
    } catch (e) {
      btn.textContent = "Copy failed";
      setTimeout(() => { btn.textContent = label; }, 1500);
    }
  });
}

wireCopyButton(copyBtn, "Copy result", () => resultEl.textContent);
wireCopyButton(copyVkBtn, "Copy VK", () => lastVkText);
wireCopyButton(copyIdBtn, "Copy ID", () => lastIdText);
wireCopyButton(copyAllBtn, "Copy all", () => lastBundleText);

// Saves exactly the bytes sf-wallet-gov would write (Copy VK's text) under
// the name the coordinator pairs by. application/octet-stream, not
// text/plain: iOS Safari appends ".txt" to text downloads.
async function saveFile(name, text) {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const method = BBQrDecode.saveMethod({
    hasSavePicker: typeof window.showSaveFilePicker === "function",
    canShareFiles: !!(navigator.canShare && navigator.canShare({ files: [new File([blob], name, { type: blob.type })] })),
  });
  if (method === "picker") {
    const handle = await window.showSaveFilePicker({ suggestedName: name });
    const out = await handle.createWritable();
    await out.write(blob);
    await out.close();
  } else if (method === "share") {
    await navigator.share({ files: [new File([blob], name, { type: blob.type })], title: name });
  } else {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  return method;
}

function wireSaveButton(btn, getLabel, getFile) {
  btn.addEventListener("click", async () => {
    const label = getLabel();
    try {
      const { name, text } = await getFile();
      const method = await saveFile(name, text);
      btn.textContent = method === "share" ? "Shared" : "Saved";
    } catch (e) {
      // AbortError: the person closed the picker or share sheet -- not a failure.
      btn.textContent = e.name === "AbortError" ? label : "Save failed";
    }
    // Re-read the label: a new scan may have replaced what this button saves.
    setTimeout(() => { btn.textContent = getLabel(); }, 1500);
  });
}

wireSaveButton(saveExportBtn, () => (lastExport ? `Save ${lastExport.file}` : "Save"), async () => ({ name: lastExport.file, text: lastExport.body }));
// Shown only for a role-tagged key export (lastExport.folder).
wireSaveButton(saveSummaryBtn, () => "Save summary", () =>
  BBQrDecode.vkSummary(lastExport.body, lastExport.kind.replace("-vk", "")));

// Continuous autofocus and torch are both device-gated (iPhones and most
// laptop webcams expose neither) -- every call here is guarded by a real
// getCapabilities() check first, never assumed, matching the documented
// MediaStreamTrack behavior (a bare applyConstraints call for an
// unsupported constraint throws OverconstrainedError).
let videoTrack = null;

async function enableContinuousFocus(track) {
  const caps = track.getCapabilities ? track.getCapabilities() : {};
  if (!caps.focusMode || !caps.focusMode.includes("continuous")) {
    return; // device doesn't support programmatic focus control -- leave it alone
  }
  try {
    await track.applyConstraints({ advanced: [{ focusMode: "continuous" }] });
  } catch (e) {
    // Non-fatal: scanning still works, just without the focus hint applied.
    console.warn("continuous focus request failed:", e.message);
  }
}

function setUpTorchToggle(track) {
  const caps = track.getCapabilities ? track.getCapabilities() : {};
  const torchBtn = document.getElementById("torch");
  if (!caps.torch) {
    torchBtn.hidden = true;
    return;
  }
  let torchOn = false;
  torchBtn.hidden = false;
  torchBtn.textContent = "Torch: off";
  torchBtn.onclick = async () => {
    torchOn = !torchOn;
    try {
      await track.applyConstraints({ advanced: [{ torch: torchOn }] });
      torchBtn.textContent = `Torch: ${torchOn ? "on" : "off"}`;
    } catch (e) {
      torchOn = !torchOn; // revert optimistic toggle on failure
      console.warn("torch toggle failed:", e.message);
    }
  };
}

let cameraStream = null;
let cameraGen = 0;  // bumped by every start and stop: a request from an older start is stale

async function startCamera() {
  if (cameraStream || cameraStarted) return;
  const gen = ++cameraGen;
  const stale = () => gen !== cameraGen;
  setStatus("Requesting camera...");
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
    });
    if (stale()) {
      stream.getTracks().forEach((t) => t.stop());
      return;
    }
    cameraStream = stream;
    video.srcObject = stream;
    await video.play();
    if (stale()) return;  // stopCamera() already stopped this stream
    videoTrack = stream.getVideoTracks()[0];
    if (videoTrack) {
      await enableContinuousFocus(videoTrack);
      setUpTorchToggle(videoTrack);
    }
    if (stale()) return;
    if (!session.isComplete) setStatus("Scanning...");
    cameraStarted = true;
    requestAnimationFrame(tick);
  } catch (e) {
    if (stale()) return;
    setStatus(`Camera error: ${e.message} (camera access needs HTTPS or localhost -- check the URL)`, "error");
  }
}

function stopCamera() {
  cameraGen++;
  cameraStarted = false;
  if (cameraStream) cameraStream.getTracks().forEach((t) => t.stop());
  cameraStream = null;
  video.srcObject = null;
  renderSignal(performance.now());
}

function tick() {
  if (!cameraStarted) return;
  const now = performance.now();
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    capture.width = video.videoWidth;
    capture.height = video.videoHeight;
    const ctx = capture.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, capture.width, capture.height);
    const imageData = ctx.getImageData(0, 0, capture.width, capture.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);
    recordDetection(!!code, now);
    if (code) {
      handleDecodedText(code.data, now);
    }
  } else {
    recordDetection(false, now);
  }
  renderSignal(now);
  requestAnimationFrame(tick);
}

window.ScanTab = { start: startCamera, stop: stopCamera };
