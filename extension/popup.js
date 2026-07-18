/**
 * popup.js
 *
 * Logika interfejsu popup wtyczki MDDS.
 *
 * Odpowiedzialnosci modulu:
 *   inicjalizacja widoku i odpytanie chrome.storage.session o wynik z tla
 *   komunikacja z API (GET /classify, GET /health)
 *   renderowanie wyniku klasyfikacji i panelu cech infrastrukturalnych
 *   obsluga przyciskow "Odswiez" i "Szczegoly"
 */

const API_BASE = "http://127.0.0.1:8000";

// Skrot do getElementById
const $ = (id) => document.getElementById(id);

let _currentDomain = null;
let _currentUrl    = null;
let _detailsOpen   = false;
let _lastResult    = null;

/**
 * Przelacza widoczny stan interfejsu.
 * @param {"loading"|"error"|"idle"|"result"|null} state
 */
function showState(state) {
  ["stateLoading", "stateError", "stateIdle"].forEach(id => {
    $(`${id}`).classList.toggle("active", id === `state${capitalize(state)}`);
  });
  $("result").classList.toggle("active", state === "result");
  $("footer").classList.toggle("active", state === "result");
}

function capitalize(s) {
  return s ? s[0].toUpperCase() + s.slice(1) : "";
}

/**
 * Ekstrahuje nazwe domeny z adresu URL; usuwa prefiks www.
 * @param {string} url
 * @returns {string|null}
 */
function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
  } catch { return null; }
}

function isInternalUrl(url) {
  return !url || /^(chrome|edge|about|chrome-extension):/.test(url);
}

/**
 * Sprawdza stan serwera przez GET /health i aktualizuje wskaznik w naglowku.
 * Timeout: 2000 ms.
 * @returns {Promise<boolean>}
 */
async function checkServer() {
  try {
    const r = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(2000) });
    const ok = r.ok;
    $("statusDot").className    = `status-dot ${ok ? "online" : "offline"}`;
    $("statusLabel").textContent = ok ? "Online" : "Offline";
    return ok;
  } catch {
    $("statusDot").className    = "status-dot offline";
    $("statusLabel").textContent = "Offline";
    return false;
  }
}

/**
 * Wyznacza scheme kolorystyczny na podstawie p_malicious.
 * Progi: p < 0.30 bezpieczna, p in [0.30, 0.70) podejrzana, p >= 0.70 zlosliwa.
 * @param {number} p
 * @returns {{ fill: string, textClass: string, pillBg: string, pillBorder: string, pillText: string }}
 */
function getColorScheme(p) {
  if (p < 0.30) return {
    fill: "#16a34a", textClass: "good",
    pillBg: "var(--safe-bg)", pillBorder: "var(--safe-border)", pillText: "var(--safe)",
  };
  if (p < 0.70) return {
    fill: "#d97706", textClass: "warn",
    pillBg: "var(--warn-bg)", pillBorder: "var(--warn-border)", pillText: "var(--warn)",
  };
  return {
    fill: "#dc2626", textClass: "bad",
    pillBg: "var(--danger-bg)", pillBorder: "var(--danger-border)", pillText: "var(--danger)",
  };
}

/**
 * Renderuje wynik klasyfikacji w interfejsie popup.
 * @param {object} result Odpowiedz serwera API.
 */
function renderResult(result) {
  const p      = result.p_malicious ?? 0;
  const pct    = Math.round(p * 100);
  const scheme = getColorScheme(p);

  $("gaugeFill").style.width      = `${pct}%`;
  $("gaugeFill").style.background = scheme.fill;
  $("scoreValue").textContent     = `${pct}%`;
  $("scoreValue").style.color     = scheme.fill;
  $("domainName").textContent     = _currentDomain;

  const pill = $("verdictPill");
  pill.style.cssText = `
    background: ${scheme.pillBg};
    border-color: ${scheme.pillBorder};
    color: ${scheme.pillText};
  `;
  $("verdictText").textContent =
    p < 0.30 ? "Bezpieczna" :
    p < 0.70 ? "Podejrzana" :
               "Złośliwa";

  // elapsed_ms ukryte gdy wynik pochodzi z bufora
  $("footerMeta").textContent = result.cached ? "" : (result.elapsed_ms ? `${result.elapsed_ms}ms` : "");

  showState("result");
  _lastResult = result;
}

/**
 * Renderuje siatke cech infrastrukturalnych w panelu szczegolów.
 * @param {object} r Wynik klasyfikacji.
 */
function renderDetails(r) {
  const feats = [
    {
      key: "Wiek domeny",
      val: r.domain_age_days >= 0 ? `${r.domain_age_days} dni` : "nieznany",
      cls: r.domain_age_days > 365 ? "good" : r.domain_age_days >= 0 ? "warn" : "bad",
    },
    {
      key: "Tranco rank",
      val: r.tranco_rank > 0 ? `#${r.tranco_rank.toLocaleString("pl-PL")}` : "poza Top 1M",
      cls: r.tranco_rank > 0 ? (r.tranco_rank <= 10000 ? "good" : "warn") : "bad",
    },
    {
      key: "Rejestratorzy",
      val: r.whois_registrar_group ?? "brak",
      cls: r.whois_registrar_group === "Unknown" ? "bad"
         : r.whois_registrar_group === "Other"   ? "warn" : "good",
    },
    {
      key: "SPF",
      val: r.has_spf  ? "skonfigurowany" : "brak",
      cls: r.has_spf  ? "good" : "bad",
    },
    {
      key: "DMARC",
      val: r.has_dmarc ? "skonfigurowany" : "brak",
      cls: r.has_dmarc ? "good" : "bad",
    },
    {
      key: "DKIM",
      val: r.has_dkim  ? "skonfigurowany" : "brak",
      cls: r.has_dkim  ? "good" : "warn",
    },
    {
      key: "WAF / CDN",
      val: (r.waf_vendor && r.waf_vendor !== "None") ? r.waf_vendor : "nie wykryto",
      cls: r.has_waf ? "good" : "",
    },
    {
      key: "Typosquatting",
      val: r.lev_is_typosquat ? `wykryto (dist. ${r.lev_min_dist})` : "nie wykryto",
      cls: r.lev_is_typosquat ? "warn" : "good",
    },
  ];

  $("featGrid").innerHTML = feats.map(({ key, val, cls }) => `
    <div class="feat-card">
      <div class="feat-key">${key}</div>
      <div class="feat-val ${cls || ""}">${val}</div>
    </div>
  `).join("");
}

/**
 * Wysyla GET /classify do API i renderuje wynik.
 * @param {boolean} force Jesli true, pomija bufor serwera (force=true).
 */
async function classify(force = false) {
  showState("loading");

  try {
    const params   = new URLSearchParams({ domain: _currentDomain, url: _currentUrl, force });
    const response = await fetch(`${API_BASE}/classify?${params}`,
                                 { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Serwer zwrocil kod ${response.status}`);
    const result = await response.json();
    renderResult(result);

    // Przywrocenie otwartego panelu szczegolów po odswiezeniu
    if (_detailsOpen) renderDetails(result);
  } catch (err) {
    showState("error");
    $("errMsg").textContent = err.message;
  }
}

/**
 * Inicjalizuje popup: sprawdza serwer, odczytuje wynik z chrome.storage.session
 * lub wywoluje pelna klasyfikacje przy braku bufora.
 */
async function init() {
  checkServer(); // asynchronicznie, nie blokuje renderowania

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab?.url || isInternalUrl(tab.url)) {
    showState("idle");
    return;
  }

  _currentDomain = extractDomain(tab.url);
  _currentUrl    = tab.url;

  if (!_currentDomain) {
    showState("idle");
    return;
  }

  // Odczyt wyniku zapisanego przez service worker w chrome.storage.session
  const key    = `tab_${tab.id}`;
  const stored = await chrome.storage.session.get(key);
  if (stored[key]?.result && stored[key].domain === _currentDomain) {
    renderResult(stored[key].result);
    return;
  }

  await classify();
}

$("btnRefresh").addEventListener("click", () => classify(true));

$("btnDetails").addEventListener("click", () => {
  if (!_lastResult) return;
  _detailsOpen = !_detailsOpen;

  const panel = $("detailsPanel");
  panel.classList.toggle("open", _detailsOpen);
  $("btnDetails").textContent = _detailsOpen ? "Ukryj" : "Szczegoly";

  if (_detailsOpen) renderDetails(_lastResult);
});

init();
