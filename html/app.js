// Tab switching by URL hash (#from-device / #to-device), so a link can open
// either direction. The camera runs only while "From device" is shown.
const TABS = { "from-device": "tabFrom", "to-device": "tabTo" };

function showTab() {
  const wanted = location.hash.slice(1);
  const current = wanted in TABS ? wanted : "from-device";
  for (const [id, tabId] of Object.entries(TABS)) {
    const on = id === current;
    document.getElementById(id).hidden = !on;
    const tab = document.getElementById(tabId);
    if (on) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  if (current === "from-device") {
    window.SendTab.stop();
    window.ScanTab.start();
  } else {
    window.ScanTab.stop();
  }
}

document.getElementById("version").textContent = window.SF7_TOOL_VERSION || "unknown";
window.addEventListener("hashchange", showTab);
showTab();
