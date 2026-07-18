/**
 * background.js
 *
 * Service worker wtyczki MDDS.
 *
 * Pasywny monitoring aktywnej karty przegladarki: przy kazdej zmianie karty
 * lub zaladowaniu strony wysyla zadanie klasyfikacji do lokalnego API
 * i aktualizuje odznake ikony kolorem oraz wartoscia procentowa p_malicious.
 *
 * Buforowanie: wyniki przechowywane w _cache (pamiec service workera, TTL 5 min)
 * i w chrome.storage.session (dostepne dla popup.js).
 */

const API_BASE  = "http://127.0.0.1:8000";
const CACHE_TTL = 5 * 60 * 1000; // [ms]

// Bufor w pamieci service workera: { domain: { result, timestamp } }
const _cache = {};

/**
 * Ekstrahuje nazwe domeny z adresu URL; usuwa prefiks www.
 * @param {string} url
 * @returns {string|null}
 */
function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Sprawdza waznosc wpisu w buforze wzgledem CACHE_TTL.
 * @param {{ result: object, timestamp: number }|undefined} entry
 * @returns {boolean}
 */
function isCacheValid(entry) {
  return !!entry && (Date.now() - entry.timestamp) < CACHE_TTL;
}

/**
 * Wysyla zadanie GET /classify do API; przy trafieniu w bufor pomija siec.
 * @param {string} domain
 * @param {string} url
 * @returns {Promise<object>} Wynik klasyfikacji lub { error }.
 */
async function classify(domain, url = "") {
  if (isCacheValid(_cache[domain])) {
    return _cache[domain].result;
  }
  try {
    const params   = new URLSearchParams({ domain, url });
    const response = await fetch(`${API_BASE}/classify?${params}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();
    _cache[domain] = { result, timestamp: Date.now() };
    return result;
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Aktualizuje odznake ikony wtyczki na podstawie wyniku klasyfikacji.
 * @param {number} tabId
 * @param {object} result
 */
function updateBadge(tabId, result) {
  if (result?.error) {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#94a3b8" });
    return;
  }
  const p     = result.p_malicious ?? 0;
  const pct   = Math.round(p * 100);
  const color = p < 0.30 ? "#22c55e" : p < 0.70 ? "#f59e0b" : "#ef4444";

  chrome.action.setBadgeText({ tabId, text: `${pct}%` });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

/**
 * Glowna procedura obslugi zmiany karty lub zaladowania strony.
 * Pomija strony wewnetrzne przegladarki (chrome://, edge://, about://).
 * @param {number} tabId
 * @param {string} url
 */
async function handleTab(tabId, url) {
  if (!url || /^(chrome|edge|about|chrome-extension):/.test(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  const domain = extractDomain(url);
  if (!domain) return;

  // Odznaka tymczasowa podczas oczekiwania na odpowiedz API
  chrome.action.setBadgeText({ tabId, text: "…" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#94a3b8" });

  const result = await classify(domain, url);

  try {
    await chrome.tabs.get(tabId); // weryfikacja czy karta nadal istnieje
    updateBadge(tabId, result);
    chrome.storage.session.set({ [`tab_${tabId}`]: { domain, url, result } });
  } catch {
    // karta zamknieta przed otrzymaniem odpowiedzi
  }
}

// Rejestracja listenerow zdarzen Chrome
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab?.url) handleTab(tabId, tab.url);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    handleTab(tabId, tab.url);
  }
});
