/**
 * SSL & Domain Monitor — DashStack Admin UI Application
 * Works on GitHub Pages (https://duongnvd.github.io/ssl-monitor/) and local environments.
 */

const STORAGE_KEYS = {
  GH_CONFIG: "ssl_monitor_gh_config_v1",
  LOCAL_DOMAINS: "ssl_monitor_local_domains_v1",
  LOCAL_RESULTS: "ssl_monitor_local_results_v1",
  THEME: "ssl_monitor_ds_theme_v1",
};

const BKNS_DEMO_API_KEY = "bkns_dmo_2376da23bd44858c8390aeeb93065404d21ede1ba2c5d59c0cffc33d6e83c2dd";

const MULTI_PART_TLDS = new Set([
  "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn", "ac.vn",
  "biz.vn", "info.vn", "name.vn", "pro.vn", "health.vn", "io.vn", "ai.vn",
  "co.uk", "org.uk", "com.au", "co.jp", "com.sg", "com.my", "co.kr",
]);

const state = {
  ghConfig: {
    owner: "duongnvd",
    repo: "ssl-monitor",
    branch: "main",
    token: "",
  },
  domainsConfig: {
    settings: {
      alert_days_ssl: 30,
      critical_days_ssl: 7,
      alert_days_domain: 30,
      critical_days_domain: 14,
      notify_mode: "alert_only",
      default_recipients: [],
      dashboard_url: window.location.href.split("?")[0].split("#")[0],
    },
    domains: [],
  },
  resultsData: {
    last_updated: null,
    summary: { total: 0, healthy: 0, warning: 0, critical: 0 },
    items: [],
  },
  domainsSha: null,
};

// Utility Functions
function cleanHostname(raw) {
  let h = String(raw || "").trim().toLowerCase();
  h = h.replace(/^https?:\/\//i, "");
  h = h.split("/")[0].split("?")[0].split("#")[0];
  if (h.includes(":")) h = h.split(":")[0];
  return h.replace(/^\.+|\.+$/g, "");
}

function extractRootDomain(hostname) {
  const host = cleanHostname(hostname);
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

function utf8ToBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function base64ToUtf8(b64) {
  return decodeURIComponent(escape(atob(b64.replace(/\s/g, ""))));
}

function showBanner(msg, isError = false) {
  const banner = document.getElementById("statusBanner");
  const text = document.getElementById("statusBannerText");
  banner.style.borderColor = isError ? "rgba(239,56,38,0.5)" : "rgba(72,128,255,0.4)";
  banner.style.background = isError ? "rgba(239,56,38,0.12)" : "rgba(72,128,255,0.12)";
  text.innerHTML = msg;
  banner.classList.remove("hidden");
}

function hideBanner() {
  document.getElementById("statusBanner").classList.add("hidden");
}

function classifyStatus(daysLeft, warnDays, critDays, hasError = false) {
  if (hasError || daysLeft === null || daysLeft === undefined) return "error";
  if (daysLeft < 0) return "expired";
  if (daysLeft <= critDays) return "critical";
  if (daysLeft <= warnDays) return "warning";
  return "ok";
}

function computeOverallStatus(sslStatus, domStatus) {
  const priority = ["expired", "error", "critical", "warning", "ok", "unknown", "skipped"];
  for (const p of priority) {
    if (sslStatus === p || domStatus === p) return p;
  }
  return "ok";
}

// Theme Handling (DashStack Light default + Dark Mode toggle)
function initTheme() {
  const savedTheme = localStorage.getItem(STORAGE_KEYS.THEME) || "light";
  applyTheme(savedTheme);
}

function applyTheme(theme) {
  const isDark = theme === "dark";
  document.body.classList.toggle("dark-theme", isDark);
  const iconEl = document.getElementById("themeIcon");
  if (iconEl) iconEl.textContent = isDark ? "☀️" : "🌙";
  localStorage.setItem(STORAGE_KEYS.THEME, isDark ? "dark" : "light");
}

// Auto-detect GitHub Repo from URL
function initGitHubConfig() {
  const saved = localStorage.getItem(STORAGE_KEYS.GH_CONFIG);
  if (saved) {
    try {
      state.ghConfig = { ...state.ghConfig, ...JSON.parse(saved) };
    } catch (_) {}
  } else {
    const host = window.location.hostname;
    const pathParts = window.location.pathname.split("/").filter(Boolean);
    if (host.endsWith(".github.io")) {
      state.ghConfig.owner = host.replace(".github.io", "");
      state.ghConfig.repo = pathParts.length > 0 ? pathParts[0] : `${state.ghConfig.owner}.github.io`;
    }
  }
  updateSyncBadge();
}

function updateSyncBadge() {
  const badge = document.getElementById("syncModeBadge");
  if (!badge) return;
  if (state.ghConfig.token) {
    badge.className = "ds-sync-pill mode-connected";
    badge.textContent = `● GitHub: ${state.ghConfig.owner}/${state.ghConfig.repo}`;
  } else {
    badge.className = "ds-sync-pill mode-readonly";
    badge.textContent = "⚡ Chưa gắn Token (Bấm để cấu hình)";
  }
}

// Fetch Data from Repo or GitHub API
async function loadAllData() {
  try {
    const cacheBust = `?t=${Date.now()}`;
    let domainsJson = null;
    let resultsJson = null;

    if (state.ghConfig.token) {
      try {
        const domFile = await githubGetFile("data/domains.json");
        if (domFile && domFile.content) {
          domainsJson = JSON.parse(base64ToUtf8(domFile.content));
          if (domFile.sha) state.domainsSha = domFile.sha;
        }
        const resFile = await githubGetFile("data/results.json");
        if (resFile && resFile.content) {
          resultsJson = JSON.parse(base64ToUtf8(resFile.content));
        }
      } catch (apiErr) {
        console.warn("GitHub API load fallback to static JSON:", apiErr);
      }
    }

    if (!domainsJson) {
      const r1 = await fetch(`./data/domains.json${cacheBust}`);
      if (r1.ok) domainsJson = await r1.json();
    }
    if (!resultsJson) {
      const r2 = await fetch(`./data/results.json${cacheBust}`);
      if (r2.ok) resultsJson = await r2.json();
    }

    if (!state.ghConfig.token) {
      const localDom = localStorage.getItem(STORAGE_KEYS.LOCAL_DOMAINS);
      const localRes = localStorage.getItem(STORAGE_KEYS.LOCAL_RESULTS);
      if (localDom) domainsJson = JSON.parse(localDom);
      if (localRes) resultsJson = JSON.parse(localRes);
    }

    if (domainsJson) state.domainsConfig = domainsJson;
    if (resultsJson) state.resultsData = resultsJson;

    mergeConfigIntoResults();
    renderAll();

    // Automatically resolve any domain missing WHOIS expiry date directly from the browser
    await autoResolveMissingDomains();
  } catch (err) {
    console.error("Failed to load data:", err);
    showBanner(`Không thể tải dữ liệu: ${err.message}`, true);
  }
}

async function autoResolveMissingDomains() {
  const entriesToResolve = [];
  for (const d of state.domainsConfig.domains || []) {
    if (d.check_domain === false) continue;
    const host = cleanHostname(d.domain);
    const port = Number(d.port || 443);
    const item = (state.resultsData.items || []).find(
      (x) => x.domain === host && Number(x.port || 443) === port
    );
    if (!item || !item.domain_expiry_date || item.domain_status === "unknown") {
      entriesToResolve.push(d);
    }
  }

  if (entriesToResolve.length === 0) return;

  let anyCacheUpdated = false;
  for (const entry of entriesToResolve) {
    const updatedCache = await performBrowserLiveCheck(entry);
    if (updatedCache) anyCacheUpdated = true;
  }

  if (anyCacheUpdated && state.ghConfig.token) {
    try {
      await saveDomainsConfig("chore(whois): đồng bộ dữ liệu WHOIS tên miền .vn", true);
    } catch (_) {}
  }
}

function mergeConfigIntoResults() {
  const existingMap = new Map();
  for (const item of state.resultsData.items || []) {
    existingMap.set(`${item.domain}:${item.port || 443}`, item);
  }

  const mergedItems = [];
  for (const d of state.domainsConfig.domains || []) {
    const host = cleanHostname(d.domain);
    const port = Number(d.port || 443);
    const key = `${host}:${port}`;
    const prev = existingMap.get(key);

    if (prev) {
      prev.id = d.id || prev.id;
      prev.group = d.group || "Default";
      prev.notes = d.notes || "";
      prev.notify_emails = d.notify_emails || [];
      prev.custom_domain_expiry = d.custom_domain_expiry || "";

      const overrideExp = d.custom_domain_expiry || (!prev.domain_expiry_date ? d.cached_domain_expiry : "");
      if (overrideExp) {
        const expDt = parseFlexibleDate(overrideExp);
        if (expDt) {
          const days = Math.floor((expDt.getTime() - Date.now()) / 86400000);
          prev.domain_days_left = days;
          prev.domain_expiry_date = expDt.toISOString().slice(0, 10);
          if (d.cached_creation_date && !prev.domain_creation_date) {
            prev.domain_creation_date = d.cached_creation_date;
          }
          if (d.cached_registrar && (!prev.domain_registrar || prev.domain_registrar === "—")) {
            prev.domain_registrar = d.cached_registrar;
          }
          prev.domain_error = null;
          prev.domain_status = classifyStatus(
            days,
            state.domainsConfig.settings.alert_days_domain || 30,
            state.domainsConfig.settings.critical_days_domain || 14
          );
          prev.overall_status = computeOverallStatus(prev.ssl_status, prev.domain_status);
        }
      }
      mergedItems.push(prev);
    } else {
      mergedItems.push({
        id: d.id || `dom-${Date.now()}`,
        domain: host,
        port,
        group: d.group || "Default",
        notes: d.notes || "",
        notify_emails: d.notify_emails || [],
        custom_domain_expiry: d.custom_domain_expiry || "",
        checked_at: "Đang chờ quét...",
        ssl_checked: d.check_ssl !== false,
        ssl_status: "unknown",
        ssl_days_left: null,
        ssl_valid_to: null,
        ssl_issuer: "Đang chờ GitHub Actions quét SSL...",
        domain_checked: d.check_domain !== false,
        domain_root: extractRootDomain(host),
        domain_status: "unknown",
        domain_days_left: null,
        domain_expiry_date: d.custom_domain_expiry || d.cached_domain_expiry || null,
        domain_registrar: d.cached_registrar || "Đang tra cứu VNNIC / RDAP...",
        overall_status: "unknown",
      });
    }
  }

  state.resultsData.items = mergedItems;
  recalculateSummary();
}

function recalculateSummary() {
  const items = state.resultsData.items || [];
  state.resultsData.summary = {
    total: items.length,
    healthy: items.filter((x) => x.overall_status === "ok").length,
    warning: items.filter((x) => x.overall_status === "warning").length,
    critical: items.filter((x) => ["critical", "expired", "error"].includes(x.overall_status)).length,
    ssl_expiring: items.filter((x) => ["warning", "critical", "expired", "error"].includes(x.ssl_status)).length,
    domain_expiring: items.filter((x) => ["warning", "critical", "expired"].includes(x.domain_status)).length,
  };
}

function parseFlexibleDate(raw) {
  if (!raw) return null;
  if (typeof raw === "number") {
    const ms = raw > 1e11 ? raw : raw * 1000;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? null : d;
  }
  const s = String(raw).trim();
  if (!s) return null;
  const mDmy = s.match(/(\d{1,2})[-/](\d{1,2})[-/](20\d{2}|19\d{2})/);
  if (mDmy) {
    const d = new Date(Date.UTC(Number(mDmy[3]), Number(mDmy[2]) - 1, Number(mDmy[1])));
    if (!isNaN(d.getTime())) return d;
  }
  const mYmd = s.match(/(20\d{2}|19\d{2})[-/](\d{1,2})[-/](\d{1,2})/);
  if (mYmd) {
    const d = new Date(Date.UTC(Number(mYmd[1]), Number(mYmd[2]) - 1, Number(mYmd[3])));
    if (!isNaN(d.getTime())) return d;
  }
  const dIso = new Date(s);
  return isNaN(dIso.getTime()) ? null : dIso;
}

function normalizeRegistrar(reg, nameservers = []) {
  const r = String(reg || "").trim();
  const rLow = r.toLowerCase();
  const nsStr = (nameservers || []).join(" ").toLowerCase();
  if (rLow.includes("mắt bão") || rLow.includes("mat bao") || rLow.includes("matbao")) {
    return rLow.includes("mắt bão") ? r : `Mắt Bão (${r})`;
  }
  if (rLow.includes("gmo-z.com") || rLow.includes("runsystem") || rLow.includes("tenten")) {
    return "Tenten.vn (GMO-Z.com RUNSYSTEM)";
  }
  if (rLow.includes("p.a việt nam") || rLow.includes("p.a viet nam") || rLow.includes("pavietnam")) {
    return "P.A Việt Nam";
  }
  if (rLow.includes("nhân hòa") || rLow.includes("nhan hoa") || rLow.includes("nhanhoa")) {
    return "Nhân Hòa";
  }
  if (!r) {
    if (nsStr.includes("matbao")) return "Mắt Bão (Theo Nameserver)";
    if (nsStr.includes("tenten") || nsStr.includes("z.com")) return "Tenten.vn (Theo Nameserver)";
    if (nsStr.includes("pavietnam")) return "P.A Việt Nam (Theo Nameserver)";
    if (nsStr.includes("nhanhoa")) return "Nhân Hòa (Theo Nameserver)";
  }
  return r || null;
}

function parseVnWhoisPayloadInBrowser(rawText, fallbackNs = []) {
  if (!rawText) return null;
  try {
    let data = JSON.parse(rawText);
    if (data && typeof data.contents === "string") {
      data = JSON.parse(data.contents);
    }
    if (data && typeof data === "object" && data.data && typeof data.data === "object") {
      data = data.data;
    }
    if (data && typeof data === "object") {
      const regObj = data.registration && typeof data.registration === "object" ? data.registration : {};
      let expDate = parseFlexibleDate(
        data.expiryDate ||
          data.expirationDate ||
          data.expireDate ||
          data.expiration_date ||
          data.registryExpiryDate ||
          data.expiredDate ||
          data.expiresAt ||
          data.expires_at ||
          regObj.expires_at ||
          regObj.expiration_date
      );
      let regDate = parseFlexibleDate(
        data.creationDate ||
          data.createDate ||
          data.creation_date ||
          data.issueDate ||
          data.registeredDate ||
          regObj.created_at
      );
      let registrar =
        (typeof data.registrar === "object" && data.registrar ? data.registrar.name : data.registrar) ||
        data.registrarName ||
        "";
      const rawNs = data.nameServer || data.nameServers || data.nameservers || data.DNS;
      const nsList = Array.isArray(rawNs)
        ? rawNs
            .map((n) => (typeof n === "object" && n ? String(n.ldhName || n.name || "") : String(n)))
            .map((s) => s.toLowerCase().trim())
            .filter(Boolean)
        : fallbackNs;

      const raw = String(data.rawtext || data.rawText || data.raw || "");
      if (!expDate && raw) {
        const m = raw.match(/(?:Expiration Date|Expiry Date|Expired Date|Ngày hết hạn|paid-till)\s*[:\-]?\s*([^\r\n]+)/i);
        if (m) expDate = parseFlexibleDate(m[1]);
      }
      if (!regDate && raw) {
        const m = raw.match(/(?:Creation Date|Created On|Issue Date|Ngày đăng ký|Ngày cấp)\s*[:\-]?\s*([^\r\n]+)/i);
        if (m) regDate = parseFlexibleDate(m[1]);
      }
      if (!registrar && raw) {
        const m = raw.match(/(?:Registrar|Nhà đăng ký quản lý|Nhà đăng ký)\s*[:\-]?\s*([^\r\n]+)/i);
        if (m) registrar = m[1].trim();
      }
      if (expDate) {
        return { expDate, regDate, registrar, nsList: nsList.length ? nsList : fallbackNs };
      }
    }
  } catch (_) {}

  const clean = String(rawText).replace(/<[^>]+>/g, "\n");
  const mExp = clean.match(/(?:Expiration Date|Expiry Date|Expired Date|Ngày hết hạn)\s*[:\-]?\s*([^\r\n]+)/i);
  if (!mExp) return null;
  const expDate = parseFlexibleDate(mExp[1]);
  if (!expDate) return null;

  const mReg = clean.match(/(?:Creation Date|Issue Date|Ngày đăng ký|Ngày cấp)\s*[:\-]?\s*([^\r\n]+)/i);
  const regDate = mReg ? parseFlexibleDate(mReg[1]) : null;
  const mRegistrar = clean.match(/(?:Registrar|Nhà đăng ký quản lý|Nhà đăng ký)\s*[:\-]?\s*([^\r\n]+)/i);
  const registrar = mRegistrar ? mRegistrar[1].trim() : "";

  return { expDate, regDate, registrar, nsList: fallbackNs };
}

async function performBrowserLiveCheck(domainEntry) {
  const host = cleanHostname(domainEntry.domain);
  const port = Number(domainEntry.port || 443);
  const rootDomain = extractRootDomain(host);
  const item = state.resultsData.items.find((x) => x.domain === host && Number(x.port || 443) === port);
  if (!item) return false;

  let cacheChanged = false;

  // 1. Resolve IP & Nameservers via Cloudflare DNS-over-HTTPS
  try {
    const dnsResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { Accept: "application/dns-json" },
    });
    if (dnsResp.ok) {
      const dnsData = await dnsResp.json();
      const aRec = (dnsData.Answer || []).find((a) => a.type === 1);
      if (aRec && aRec.data) {
        item.ssl_ip = aRec.data;
      }
    }
    const nsResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(rootDomain)}&type=NS`, {
      headers: { Accept: "application/dns-json" },
    });
    if (nsResp.ok) {
      const nsData = await nsResp.json();
      const nsList = (nsData.Answer || [])
        .filter((a) => a.type === 2 && a.data)
        .map((a) => String(a.data).toLowerCase().replace(/\.$/, ""));
      if (nsList.length > 0) {
        item.domain_nameservers = nsList.slice(0, 6);
        const inferredReg = normalizeRegistrar("", nsList);
        if (inferredReg && (!item.domain_registrar || item.domain_registrar === "—" || item.domain_registrar.includes("Đang tra cứu"))) {
          item.domain_registrar = inferredReg;
        }
      }
    }
  } catch (_) {}

  // 2. Query VNNIC / BKNS / VN-WHOIS & RDAP in browser
  if (domainEntry.check_domain !== false) {
    let foundWhois = false;
    const bknsUrl = `https://whois.bkns.vn/api/v1/whois?domain=${encodeURIComponent(rootDomain)}`;
    const inetUrl = `https://whois.inet.vn/api/whois/domainspecify/${encodeURIComponent(rootDomain)}`;
    const paUrl = `https://whois.pavietnam.vn/whois.php?domain=${encodeURIComponent(rootDomain)}&cmd=get_whois`;

    const candidateRequests = [
      { url: bknsUrl, headers: { Accept: "application/json", "X-API-Key": BKNS_DEMO_API_KEY } },
      { url: inetUrl, headers: { Accept: "application/json" } },
      { url: `https://api.allorigins.win/raw?url=${encodeURIComponent(inetUrl)}` },
      { url: `https://api.codetabs.com/v1/proxy?quest=${inetUrl}` },
      { url: `https://corsproxy.io/?${encodeURIComponent(inetUrl)}` },
      { url: `https://api.allorigins.win/raw?url=${encodeURIComponent(paUrl)}` },
      { url: `https://api.codetabs.com/v1/proxy?quest=${paUrl}` },
    ];

    for (const reqCfg of candidateRequests) {
      try {
        const resp = await fetch(reqCfg.url, reqCfg.headers ? { headers: reqCfg.headers } : undefined);
        if (!resp.ok) continue;
        const rawText = await resp.text();
        const parsed = parseVnWhoisPayloadInBrowser(rawText, item.domain_nameservers || []);
        if (parsed && parsed.expDate) {
          const daysLeft = Math.floor((parsed.expDate.getTime() - Date.now()) / 86400000);
          const expIso = parsed.expDate.toISOString().slice(0, 10);
          const regIso = parsed.regDate ? parsed.regDate.toISOString().slice(0, 10) : null;
          const normReg = normalizeRegistrar(parsed.registrar, parsed.nsList) || "VNNIC Verified";

          item.domain_days_left = daysLeft;
          item.domain_expiry_date = expIso;
          item.domain_creation_date = regIso;
          item.domain_registrar = normReg;
          item.domain_nameservers = (parsed.nsList || []).slice(0, 6);
          item.domain_source = "VNNIC / VN-WHOIS";
          item.domain_error = null;
          item.domain_status = classifyStatus(
            daysLeft,
            state.domainsConfig.settings.alert_days_domain || 30,
            state.domainsConfig.settings.critical_days_domain || 14
          );

          if (domainEntry.cached_domain_expiry !== expIso || domainEntry.cached_registrar !== normReg) {
            domainEntry.cached_domain_expiry = expIso;
            domainEntry.cached_creation_date = regIso || "";
            domainEntry.cached_registrar = normReg;
            cacheChanged = true;
          }
          foundWhois = true;
          break;
        }
      } catch (_) {}
    }

    if (!foundWhois && !rootDomain.endsWith(".vn")) {
      try {
        const rdapUrls = [`https://rdap.org/domain/${encodeURIComponent(rootDomain)}`];
        for (const url of rdapUrls) {
          const r = await fetch(url, { headers: { Accept: "application/rdap+json, application/json" } });
          if (!r.ok) continue;
          const data = await r.json();
          let expDate = null;
          let regDate = null;
          for (const ev of data.events || []) {
            const action = String(ev.eventAction || "").toLowerCase();
            if (action.includes("expir") && ev.eventDate) expDate = new Date(ev.eventDate);
            if (action.includes("registr") && ev.eventDate) regDate = new Date(ev.eventDate);
          }
          let registrar = null;
          for (const ent of data.entities || []) {
            const roles = (ent.roles || []).map((x) => x.toLowerCase());
            if (roles.includes("registrar") && Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1])) {
              for (const row of ent.vcardArray[1]) {
                if (Array.isArray(row) && (row[0] === "fn" || row[0] === "org") && row[3]) {
                  registrar = String(row[3]);
                  break;
                }
              }
            }
          }
          const nameservers = (data.nameservers || []).map((n) => String(n.ldhName || "").toLowerCase()).filter(Boolean);

          if (expDate && !isNaN(expDate.getTime())) {
            const daysLeft = Math.floor((expDate.getTime() - Date.now()) / 86400000);
            item.domain_days_left = daysLeft;
            item.domain_expiry_date = expDate.toISOString().slice(0, 10);
            item.domain_creation_date = regDate && !isNaN(regDate.getTime()) ? regDate.toISOString().slice(0, 10) : null;
            item.domain_registrar = normalizeRegistrar(registrar, nameservers) || "RDAP Verified";
            item.domain_nameservers = nameservers.slice(0, 6);
            item.domain_source = "RDAP (Live)";
            item.domain_error = null;
            item.domain_status = classifyStatus(
              daysLeft,
              state.domainsConfig.settings.alert_days_domain || 30,
              state.domainsConfig.settings.critical_days_domain || 14
            );
            break;
          }
        }
      } catch (_) {}
    }
  }

  // Manual domain expiry override
  if (domainEntry.custom_domain_expiry) {
    const manualMs = Date.parse(domainEntry.custom_domain_expiry);
    if (!isNaN(manualMs)) {
      const daysLeft = Math.floor((manualMs - Date.now()) / 86400000);
      item.domain_days_left = daysLeft;
      item.domain_expiry_date = domainEntry.custom_domain_expiry;
      item.domain_registrar = item.domain_registrar || "Cấu hình thủ công";
      item.domain_error = null;
      item.domain_status = classifyStatus(
        daysLeft,
        state.domainsConfig.settings.alert_days_domain || 30,
        state.domainsConfig.settings.critical_days_domain || 14
      );
    }
  }

  item.overall_status = computeOverallStatus(item.ssl_status, item.domain_status);
  recalculateSummary();
  renderAll();
  return cacheChanged;
}

// GitHub API Helpers (with Anti-409 Conflict Queue & Retry)
async function githubApiRequest(endpoint, options = {}) {
  const { owner, repo, token } = state.ghConfig;
  if (!token) throw new Error("Chưa cấu hình GitHub Personal Access Token");
  const url = `https://api.github.com/repos/${owner}/${repo}/${endpoint}`;
  const resp = await fetch(url, {
    cache: "no-store",
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {}),
    },
  });
  if (!resp.ok) {
    const errBody = await resp.text();
    throw new Error(`GitHub API (${resp.status}): ${errBody}`);
  }
  if (resp.status === 204) return null;
  return resp.json();
}

async function githubGetFile(path) {
  const { branch } = state.ghConfig;
  return githubApiRequest(`contents/${path}?ref=${encodeURIComponent(branch)}&_t=${Date.now()}`);
}

let saveQueuePromise = Promise.resolve();

function saveDomainsConfig(commitMessage, silent = false) {
  saveQueuePromise = saveQueuePromise
    .catch(() => {})
    .then(() => performSaveDomainsConfig(commitMessage, silent));
  return saveQueuePromise;
}

async function performSaveDomainsConfig(commitMessage, silent = false) {
  if (!state.ghConfig.token) {
    localStorage.setItem(STORAGE_KEYS.LOCAL_DOMAINS, JSON.stringify(state.domainsConfig));
    localStorage.setItem(STORAGE_KEYS.LOCAL_RESULTS, JSON.stringify(state.resultsData));
    if (!silent) {
      showBanner(
        "💡 Đã lưu tạm trên trình duyệt và tra cứu trực tiếp! Để lưu vĩnh viễn lên GitHub & quét SSL tự động + gửi Email, hãy bấm <strong>⚙️ Cấu hình & Email</strong> để gắn GitHub Token."
      );
    }
    return;
  }

  if (!silent) {
    showBanner("⏳ Đang đồng bộ danh sách tên miền lên GitHub Repository...");
  }
  let sha = state.domainsSha || undefined;
  try {
    const existing = await githubGetFile("data/domains.json");
    if (existing && existing.sha) {
      sha = existing.sha;
      state.domainsSha = existing.sha;
    }
  } catch (_) {}

  const contentFormatted = JSON.stringify(state.domainsConfig, null, 2) + "\n";
  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const putResp = await githubApiRequest("contents/data/domains.json", {
        method: "PUT",
        body: JSON.stringify({
          message: commitMessage || "chore(domains): cập nhật danh sách theo dõi từ Web UI",
          content: utf8ToBase64(contentFormatted),
          sha,
          branch: state.ghConfig.branch,
        }),
      });
      if (putResp && putResp.content && putResp.content.sha) {
        state.domainsSha = putResp.content.sha;
      }
      break;
    } catch (err) {
      const errMsg = String(err.message || "");
      const matchSha = errMsg.match(/does not match ([0-9a-f]{40})/i);
      if (matchSha && attempt < maxAttempts) {
        sha = matchSha[1];
        state.domainsSha = sha;
        continue;
      }
      if (errMsg.includes("409") && attempt < maxAttempts) {
        try {
          const fresh = await githubGetFile("data/domains.json");
          if (fresh && fresh.sha) {
            sha = fresh.sha;
            state.domainsSha = sha;
          }
        } catch (_) {}
        continue;
      }
      throw err;
    }
  }

  if (!silent) {
    showBanner(
      "✅ Đã lưu lên GitHub! GitHub Actions đang tự động quét chứng chỉ SSL & VNNIC WHOIS ngầm (sẽ cập nhật sau ~35-60 giây)..."
    );
  }
  scheduleAutoRefreshAfterAction();
}

async function triggerWorkflowDispatch(forceEmail = false, testEmail = false) {
  if (!state.ghConfig.token) {
    openModal("modalSettings");
    showBanner("⚠️ Vui lòng nhập GitHub Personal Access Token trong mục Cấu hình để kích hoạt GitHub Actions.", true);
    return;
  }
  try {
    showBanner("⏳ Đang gửi lệnh kích hoạt GitHub Actions...");
    await githubApiRequest("actions/workflows/monitor.yml/dispatches", {
      method: "POST",
      body: JSON.stringify({
        ref: state.ghConfig.branch,
        inputs: {
          force_email: String(forceEmail),
          test_email: String(testEmail),
        },
      }),
    });
    showBanner(
      testEmail
        ? "✉️ Đã kích hoạt gửi Email Test! Vui lòng kiểm tra hộp thư Groupware của bạn sau khoảng 30–45 giây."
        : "🔄 GitHub Actions đang chạy quét toàn bộ SSL & Domain! Kết quả sẽ tự động làm mới sau ~35-60 giây..."
    );
    scheduleAutoRefreshAfterAction();
  } catch (err) {
    showBanner(`Lỗi kích hoạt GitHub Actions: ${err.message}`, true);
  }
}

function scheduleAutoRefreshAfterAction() {
  [25000, 50000, 80000, 110000, 140000].forEach((delayMs) => {
    setTimeout(() => loadAllData(), delayMs);
  });
}

// Rendering UI
function renderAll() {
  renderKpis();
  renderGroupFilterOptions();
  renderTable();
}

function renderKpis() {
  const s = state.resultsData.summary || { total: 0, healthy: 0, warning: 0, critical: 0 };
  document.getElementById("kpiTotal").textContent = s.total || 0;
  document.getElementById("kpiHealthy").textContent = s.healthy || 0;
  document.getElementById("kpiWarning").textContent = s.warning || 0;
  document.getElementById("kpiCritical").textContent = s.critical || 0;

  const attentionCount = (s.warning || 0) + (s.critical || 0);
  const bellEl = document.getElementById("bellCount");
  if (bellEl) bellEl.textContent = attentionCount;

  const navAttEl = document.getElementById("navBadgeAttention");
  if (navAttEl) navAttEl.textContent = attentionCount;

  const navSslEl = document.getElementById("navBadgeSsl");
  if (navSslEl) navSslEl.textContent = s.ssl_expiring || 0;

  const navDomEl = document.getElementById("navBadgeDomain");
  if (navDomEl) navDomEl.textContent = s.domain_expiring || 0;

  const lastUpd = state.resultsData.last_updated;
  const lastUpdEl = document.getElementById("lastUpdatedText");
  if (lastUpd) {
    const dt = new Date(lastUpd);
    lastUpdEl.textContent = `Cập nhật lần cuối: ${isNaN(dt) ? lastUpd : dt.toLocaleString("vi-VN")} • Quét tự động 07:30 sáng hàng ngày`;
  } else {
    lastUpdEl.textContent = "Chưa có dữ liệu quét";
  }
}

function renderGroupFilterOptions() {
  const select = document.getElementById("filterGroup");
  const currentVal = select.value;
  const groups = Array.from(
    new Set((state.resultsData.items || []).map((x) => x.group || "Default").filter(Boolean))
  ).sort();

  select.innerHTML = `<option value="all">Tất cả nhóm (${groups.length})</option>`;
  for (const g of groups) {
    const opt = document.createElement("option");
    opt.value = g;
    opt.textContent = `Nhóm: ${g}`;
    select.appendChild(opt);
  }
  if (groups.includes(currentVal)) select.value = currentVal;
}

function formatStatusBadge(status, daysLeft, isAlreadyScanned = false) {
  const labelMap = {
    ok: "An toàn",
    warning: "Sắp hết hạn",
    critical: "Khẩn cấp",
    expired: "ĐÃ HẾT HẠN",
    error: "Lỗi kết nối",
    unknown: isAlreadyScanned ? "Chưa rõ hạn" : "Đang chờ quét",
    skipped: "Bỏ qua",
  };
  const st = status || "unknown";
  let text = labelMap[st] || st;
  if (daysLeft !== null && daysLeft !== undefined) {
    text = daysLeft < 0 ? `Quá hạn ${Math.abs(daysLeft)} ngày` : `Còn ${daysLeft} ngày`;
  }
  return `<span class="badge badge-${st}">${text}</span>`;
}

function formatProgressBar(status, daysLeft, maxDays = 90) {
  if (daysLeft === null || daysLeft === undefined) {
    return `<div class="progress-track"><div class="progress-fill" style="width:0%"></div></div>`;
  }
  const pct = Math.max(5, Math.min(100, Math.round((Math.max(0, daysLeft) / maxDays) * 100)));
  const st = status || "ok";
  return `<div class="progress-track"><div class="progress-fill fill-${st}" style="width:${pct}%"></div></div>`;
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderTable() {
  const tbody = document.getElementById("domainTableBody");
  const query = document.getElementById("searchInput").value.trim().toLowerCase();
  const statusFilter = document.getElementById("filterStatus").value;
  const groupFilter = document.getElementById("filterGroup").value;
  const sortBy = document.getElementById("sortBy").value;

  let list = [...(state.resultsData.items || [])];

  if (query) {
    list = list.filter((it) => {
      const hay = [
        it.domain,
        it.domain_root,
        it.group,
        it.notes,
        it.ssl_ip,
        it.ssl_issuer,
        it.domain_registrar,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(query);
    });
  }

  if (statusFilter === "attention") {
    list = list.filter((it) => ["warning", "critical", "expired", "error"].includes(it.overall_status));
  } else if (statusFilter === "ssl_expiring") {
    list = list.filter((it) => ["warning", "critical", "expired", "error"].includes(it.ssl_status));
  } else if (statusFilter === "domain_expiring") {
    list = list.filter((it) => ["warning", "critical", "expired"].includes(it.domain_status));
  } else if (statusFilter === "ok") {
    list = list.filter((it) => it.overall_status === "ok");
  }

  if (groupFilter !== "all") {
    list = list.filter((it) => (it.group || "Default") === groupFilter);
  }

  const statusRank = { expired: 0, error: 1, critical: 2, warning: 3, ok: 4, unknown: 5, skipped: 6 };
  list.sort((a, b) => {
    if (sortBy === "ssl_asc") {
      return (a.ssl_days_left ?? 99999) - (b.ssl_days_left ?? 99999);
    }
    if (sortBy === "domain_asc") {
      return (a.domain_days_left ?? 99999) - (b.domain_days_left ?? 99999);
    }
    if (sortBy === "domain_name") {
      return a.domain.localeCompare(b.domain);
    }
    const rA = statusRank[a.overall_status] ?? 9;
    const rB = statusRank[b.overall_status] ?? 9;
    if (rA !== rB) return rA - rB;
    const minA = Math.min(a.ssl_days_left ?? 99999, a.domain_days_left ?? 99999);
    const minB = Math.min(b.ssl_days_left ?? 99999, b.domain_days_left ?? 99999);
    return minA - minB;
  });

  const showingEl = document.getElementById("tableShowingText");
  if (showingEl) {
    showingEl.textContent = `Hiển thị ${list.length} / ${(state.resultsData.items || []).length} tên miền`;
  }

  if (list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="ds-empty-state">Không tìm thấy tên miền nào phù hợp với bộ lọc hiện tại.</td></tr>`;
    return;
  }

  tbody.innerHTML = list
    .map((it) => {
      const isScanned = Boolean(it.checked_at && !String(it.checked_at).includes("Đang chờ"));
      const sslBadge = formatStatusBadge(it.ssl_status, it.ssl_days_left, isScanned);
      const sslBar = formatProgressBar(it.ssl_status, it.ssl_days_left, 90);
      const domBadge = formatStatusBadge(it.domain_status, it.domain_days_left, isScanned);
      const domBar = formatProgressBar(it.domain_status, it.domain_days_left, 365);

      const sslExpText = it.ssl_valid_to
        ? `Hết hạn: <strong>${escapeHtml(it.ssl_valid_to)}</strong>`
        : it.ssl_error
        ? `<span style="color:var(--ds-red-fg)">${escapeHtml(it.ssl_error)}</span>`
        : "Đang chờ GitHub Actions quét SSL...";

      const domExpText = it.domain_expiry_date
        ? `Hết hạn: <strong>${escapeHtml(it.domain_expiry_date)}</strong>`
        : it.domain_error
        ? `<span style="color:#d97706">${escapeHtml(it.domain_error)}</span>`
        : "Đang chờ quét VNNIC / WHOIS...";

      return `
        <tr>
          <td>
            <div class="domain-title">
              <a href="https://${escapeHtml(it.domain)}" target="_blank" rel="noopener">
                ${escapeHtml(it.domain)}
              </a>
              <span class="port-tag">:${it.port || 443}</span>
            </div>
            <div class="meta-tags">
              ${it.ssl_ip ? `<span class="ip-pill" title="Địa chỉ IP">${escapeHtml(it.ssl_ip)}</span>` : ""}
              ${it.ssl_protocol ? `<span class="ip-pill">${escapeHtml(it.ssl_protocol)}</span>` : ""}
            </div>
            ${it.notes ? `<div class="notes-text">📝 ${escapeHtml(it.notes)}</div>` : ""}
          </td>

          <td>
            <span class="group-pill">${escapeHtml(it.group || "Default")}</span>
          </td>

          <td>
            <div class="status-cell-top">
              ${sslBadge}
              ${it.ssl_latency_ms ? `<span style="font-size:11.5px;color:var(--ds-text-muted)">⚡ ${it.ssl_latency_ms}ms</span>` : ""}
            </div>
            ${sslBar}
            <div class="cell-subinfo">
              <div>${sslExpText}</div>
              <div>CA: ${escapeHtml(it.ssl_issuer || "—")}</div>
            </div>
          </td>

          <td>
            <div class="status-cell-top">
              ${domBadge}
              <span style="font-size:11.5px;color:var(--ds-text-muted)">${escapeHtml(it.domain_root || extractRootDomain(it.domain))}</span>
            </div>
            ${domBar}
            <div class="cell-subinfo">
              <div>${domExpText}</div>
              <div>Registrar: <strong>${escapeHtml(it.domain_registrar || "—")}</strong></div>
            </div>
          </td>

          <td style="text-align: center">
            <div class="ds-action-group">
              <button class="ds-act-btn" onclick="openDetailModal('${escapeHtml(it.domain)}', ${it.port || 443})" title="Xem chi tiết chứng chỉ & WHOIS">
                🔍
              </button>
              <button class="ds-act-btn" onclick="openEditDomainModal('${escapeHtml(it.domain)}', ${it.port || 443})" title="Chỉnh sửa tên miền">
                ✏️
              </button>
              <button class="ds-act-btn act-delete" onclick="deleteDomain('${escapeHtml(it.domain)}', ${it.port || 443})" title="Xóa khỏi danh sách theo dõi">
                🗑️
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

// Modal Helpers
function openModal(id) {
  document.getElementById(id).classList.remove("hidden");
}

function closeModal(id) {
  document.getElementById(id).classList.add("hidden");
}

window.openDetailModal = function (domain, port) {
  const it = (state.resultsData.items || []).find(
    (x) => x.domain === domain && Number(x.port || 443) === Number(port || 443)
  );
  if (!it) return;

  const isScanned = Boolean(it.checked_at && !String(it.checked_at).includes("Đang chờ"));
  document.getElementById("detailTitle").textContent = `🔍 Chi tiết: ${it.domain}:${it.port || 443}`;
  const sans = (it.ssl_sans || []).join(", ") || "—";
  const ns = (it.domain_nameservers || []).join(", ") || "—";
  const emails =
    (it.notify_emails && it.notify_emails.length > 0
      ? it.notify_emails.join(", ")
      : (state.domainsConfig.settings.default_recipients || []).join(", ")) || "Mặc định theo GitHub Secrets (SMTP_TO)";

  document.getElementById("detailBody").innerHTML = `
    <div class="detail-grid">
      <div class="detail-card">
        <h4>🔒 Thông tin Chứng chỉ SSL / TLS</h4>
        <div class="kv-row"><span class="kv-key">Trạng thái:</span><span class="kv-val">${formatStatusBadge(it.ssl_status, it.ssl_days_left, isScanned)}</span></div>
        <div class="kv-row"><span class="kv-key">Subject (CN):</span><span class="kv-val">${escapeHtml(it.ssl_subject || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Tổ chức cấp (Issuer CA):</span><span class="kv-val">${escapeHtml(it.ssl_issuer || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Ngày cấp (Valid From):</span><span class="kv-val">${escapeHtml(it.ssl_valid_from || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Ngày hết hạn (Valid To):</span><span class="kv-val">${escapeHtml(it.ssl_valid_to || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Giao thức / Cipher:</span><span class="kv-val">${escapeHtml(it.ssl_protocol || "—")} / ${escapeHtml(it.ssl_cipher || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Serial Number:</span><span class="kv-val">${escapeHtml(it.ssl_serial || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Địa chỉ IP máy chủ:</span><span class="kv-val">${escapeHtml(it.ssl_ip || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">SANs (Tên miền phụ):</span><span class="kv-val">${escapeHtml(sans)}</span></div>
      </div>

      <div class="detail-card">
        <h4>🌍 Thông tin Tên miền (VNNIC / WHOIS / RDAP)</h4>
        <div class="kv-row"><span class="kv-key">Trạng thái:</span><span class="kv-val">${formatStatusBadge(it.domain_status, it.domain_days_left, isScanned)}</span></div>
        <div class="kv-row"><span class="kv-key">Tên miền gốc (Root):</span><span class="kv-val">${escapeHtml(it.domain_root || extractRootDomain(it.domain))}</span></div>
        <div class="kv-row"><span class="kv-key">Nhà đăng ký (Registrar):</span><span class="kv-val">${escapeHtml(it.domain_registrar || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Ngày đăng ký:</span><span class="kv-val">${escapeHtml(it.domain_creation_date || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Ngày hết hạn Domain:</span><span class="kv-val">${escapeHtml(it.domain_expiry_date || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Nameservers (DNS):</span><span class="kv-val">${escapeHtml(ns)}</span></div>
        <div class="kv-row"><span class="kv-key">Nguồn tra cứu:</span><span class="kv-val">${escapeHtml(it.domain_source || "—")}</span></div>
        <div class="kv-row"><span class="kv-key">Nhóm / Ghi chú:</span><span class="kv-val">${escapeHtml(it.group || "Default")} ${it.notes ? "• " + escapeHtml(it.notes) : ""}</span></div>
        <div class="kv-row"><span class="kv-key">Email nhận cảnh báo:</span><span class="kv-val">${escapeHtml(emails)}</span></div>
      </div>
    </div>
  `;
  openModal("modalDetail");
};

window.openEditDomainModal = function (domain, port) {
  const entry = (state.domainsConfig.domains || []).find(
    (d) => cleanHostname(d.domain) === domain && Number(d.port || 443) === Number(port || 443)
  );
  if (!entry) return;

  document.getElementById("modalDomainTitle").textContent = `✏️ Chỉnh sửa: ${domain}`;
  document.getElementById("domainId").value = entry.id || `${domain}:${port}`;
  document.getElementById("inputDomain").value = entry.domain;
  document.getElementById("inputPort").value = entry.port || 443;
  document.getElementById("inputGroup").value = entry.group || "";
  document.getElementById("inputCustomExpiry").value = entry.custom_domain_expiry || "";
  document.getElementById("inputNotes").value = entry.notes || "";
  document.getElementById("inputNotifyEmails").value = (entry.notify_emails || []).join(", ");
  document.getElementById("inputCheckSsl").checked = entry.check_ssl !== false;
  document.getElementById("inputCheckDomain").checked = entry.check_domain !== false;

  openModal("modalDomain");
};

window.deleteDomain = async function (domain, port) {
  if (!confirm(`Bạn có chắc chắn muốn xóa tên miền "${domain}:${port}" khỏi danh sách theo dõi?`)) {
    return;
  }
  state.domainsConfig.domains = (state.domainsConfig.domains || []).filter(
    (d) => !(cleanHostname(d.domain) === domain && Number(d.port || 443) === Number(port || 443))
  );
  state.resultsData.items = (state.resultsData.items || []).filter(
    (x) => !(x.domain === domain && Number(x.port || 443) === Number(port || 443))
  );
  recalculateSummary();
  renderAll();

  try {
    await saveDomainsConfig(`chore(monitor): xóa domain ${domain}`);
  } catch (err) {
    showBanner(`Lỗi khi lưu lên GitHub: ${err.message}`, true);
  }
};

function exportToCsv() {
  const items = state.resultsData.items || [];
  const headers = [
    "Domain",
    "Port",
    "Group",
    "IP",
    "SSL Status",
    "SSL Days Left",
    "SSL Expiry Date",
    "SSL Issuer",
    "Domain Status",
    "Domain Days Left",
    "Domain Expiry Date",
    "Registrar",
    "Notes",
  ];
  const rows = items.map((it) => [
    it.domain,
    it.port || 443,
    it.group || "",
    it.ssl_ip || "",
    it.ssl_status || "",
    it.ssl_days_left ?? "",
    it.ssl_valid_to || "",
    it.ssl_issuer || "",
    it.domain_status || "",
    it.domain_days_left ?? "",
    it.domain_expiry_date || "",
    it.domain_registrar || "",
    it.notes || "",
  ]);

  const csvContent =
    "\uFEFF" +
    [headers, ...rows]
      .map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
      .join("\r\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ssl-domain-report-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function setSidebarActiveFilter(filterVal) {
  document.querySelectorAll("[data-nav-filter]").forEach((li) => {
    li.classList.toggle("active", li.getAttribute("data-nav-filter") === filterVal);
  });
}

// Event Listeners Initialization
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initGitHubConfig();
  loadAllData();

  document.getElementById("btnToggleSidebar").addEventListener("click", () => {
    const layout = document.getElementById("appLayout");
    if (window.innerWidth <= 860) {
      layout.classList.toggle("sidebar-mobile-open");
    } else {
      layout.classList.toggle("sidebar-collapsed");
    }
  });

  document.getElementById("btnThemeToggle").addEventListener("click", () => {
    const isDark = document.body.classList.contains("dark-theme");
    applyTheme(isDark ? "light" : "dark");
  });

  document.querySelectorAll("[data-nav-filter]").forEach((li) => {
    li.addEventListener("click", (e) => {
      e.preventDefault();
      const f = li.getAttribute("data-nav-filter");
      document.getElementById("filterStatus").value = f;
      setSidebarActiveFilter(f);
      renderTable();
      if (window.innerWidth <= 860) {
        document.getElementById("appLayout").classList.remove("sidebar-mobile-open");
      }
    });
  });

  document.getElementById("btnBellAlert").addEventListener("click", () => {
    document.getElementById("filterStatus").value = "attention";
    setSidebarActiveFilter("attention");
    renderTable();
  });

  document.getElementById("btnResetFilter").addEventListener("click", () => {
    document.getElementById("searchInput").value = "";
    document.getElementById("filterStatus").value = "all";
    document.getElementById("filterGroup").value = "all";
    document.getElementById("sortBy").value = "urgency";
    setSidebarActiveFilter("all");
    renderTable();
  });

  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => closeModal(btn.getAttribute("data-close")));
  });

  document.getElementById("statusBannerClose").addEventListener("click", hideBanner);

  document.querySelectorAll(".ds-stat-card").forEach((card) => {
    card.addEventListener("click", () => {
      const f = card.getAttribute("data-filter");
      const sel = document.getElementById("filterStatus");
      if (f === "all") sel.value = "all";
      else if (f === "ok") sel.value = "ok";
      else sel.value = "attention";
      setSidebarActiveFilter(sel.value);
      renderTable();
    });
  });

  document.getElementById("searchInput").addEventListener("input", renderTable);
  document.getElementById("filterStatus").addEventListener("change", (e) => {
    setSidebarActiveFilter(e.target.value);
    renderTable();
  });
  document.getElementById("filterGroup").addEventListener("change", renderTable);
  document.getElementById("sortBy").addEventListener("change", renderTable);

  document.getElementById("btnExportCsv").addEventListener("click", exportToCsv);
  document.getElementById("sideBtnExportCsv").addEventListener("click", (e) => {
    e.preventDefault();
    exportToCsv();
  });

  const openAddDomainFn = (e) => {
    if (e) e.preventDefault();
    document.getElementById("modalDomainTitle").textContent = "➕ Thêm Tên miền theo dõi";
    document.getElementById("formDomain").reset();
    document.getElementById("domainId").value = "";
    document.getElementById("inputPort").value = "443";
    document.getElementById("inputCheckSsl").checked = true;
    document.getElementById("inputCheckDomain").checked = true;
    openModal("modalDomain");
  };
  document.getElementById("btnAddDomain").addEventListener("click", openAddDomainFn);
  document.getElementById("sideBtnAddDomain").addEventListener("click", openAddDomainFn);

  document.getElementById("formDomain").addEventListener("submit", async (e) => {
    e.preventDefault();
    const idVal = document.getElementById("domainId").value;
    const host = cleanHostname(document.getElementById("inputDomain").value);
    const port = Number(document.getElementById("inputPort").value || 443);
    const group = document.getElementById("inputGroup").value.trim() || "Default";
    const customExpiry = document.getElementById("inputCustomExpiry").value.trim();
    const notes = document.getElementById("inputNotes").value.trim();
    const notifyEmails = document
      .getElementById("inputNotifyEmails")
      .value.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const checkSsl = document.getElementById("inputCheckSsl").checked;
    const checkDomain = document.getElementById("inputCheckDomain").checked;

    if (!host || !host.includes(".")) {
      alert("Vui lòng nhập tên miền hợp lệ (VD: example.com hoặc mail.congty.com.vn)");
      return;
    }

    const list = state.domainsConfig.domains || [];
    const existingIdx = list.findIndex(
      (d) =>
        (idVal && d.id === idVal) ||
        (cleanHostname(d.domain) === host && Number(d.port || 443) === port)
    );
    const prevEntry = existingIdx >= 0 ? list[existingIdx] : {};

    const newEntry = {
      ...prevEntry,
      id: idVal || prevEntry.id || `dom-${Date.now()}`,
      domain: host,
      port,
      group,
      notes,
      check_ssl: checkSsl,
      check_domain: checkDomain,
      notify_emails: notifyEmails,
      custom_domain_expiry: customExpiry,
    };

    if (existingIdx >= 0) {
      list[existingIdx] = newEntry;
    } else {
      list.push(newEntry);
    }
    state.domainsConfig.domains = list;

    closeModal("modalDomain");
    mergeConfigIntoResults();
    renderAll();

    await performBrowserLiveCheck(newEntry);

    try {
      await saveDomainsConfig(`chore(monitor): cập nhật domain ${host}:${port}`);
    } catch (err) {
      showBanner(`Lỗi khi lưu lên GitHub: ${err.message}`, true);
    }
  });

  const openBulkFn = (e) => {
    if (e) e.preventDefault();
    document.getElementById("bulkTextarea").value = "";
    openModal("modalBulk");
  };
  document.getElementById("btnBulkAdd").addEventListener("click", openBulkFn);
  document.getElementById("sideBtnBulkAdd").addEventListener("click", openBulkFn);

  document.getElementById("formBulk").addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawLines = document.getElementById("bulkTextarea").value.split(/\r?\n/);
    const addedEntries = [];

    for (const line of rawLines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split(",").map((p) => p.trim());
      let hostPort = parts[0] || "";
      const group = parts[1] || "Default";
      const notes = parts.slice(2).join(", ") || "";

      hostPort = hostPort.replace(/^https?:\/\//i, "").split("/")[0];
      let host = hostPort;
      let port = 443;
      if (hostPort.includes(":")) {
        const [h, p] = hostPort.split(":");
        host = cleanHostname(h);
        port = Number(p) || 443;
      } else {
        host = cleanHostname(hostPort);
      }

      if (!host || !host.includes(".")) continue;
      const exists = (state.domainsConfig.domains || []).some(
        (d) => cleanHostname(d.domain) === host && Number(d.port || 443) === port
      );
      if (!exists) {
        const entry = {
          id: `dom-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          domain: host,
          port,
          group,
          notes,
          check_ssl: true,
          check_domain: true,
          notify_emails: [],
          custom_domain_expiry: "",
        };
        state.domainsConfig.domains.push(entry);
        addedEntries.push(entry);
      }
    }

    closeModal("modalBulk");
    if (addedEntries.length === 0) {
      showBanner("Không có tên miền mới nào được thêm (có thể đã tồn tại hoặc sai định dạng).");
      return;
    }

    mergeConfigIntoResults();
    renderAll();
    for (const ent of addedEntries) {
      await performBrowserLiveCheck(ent);
    }

    try {
      await saveDomainsConfig(`chore(monitor): thêm hàng loạt ${addedEntries.length} domain`);
    } catch (err) {
      showBanner(`Lỗi khi lưu lên GitHub: ${err.message}`, true);
    }
  });

  const openSettingsFn = (e) => {
    if (e) e.preventDefault();
    document.getElementById("cfgGhOwner").value = state.ghConfig.owner || "duongnvd";
    document.getElementById("cfgGhRepo").value = state.ghConfig.repo || "ssl-monitor";
    document.getElementById("cfgGhBranch").value = state.ghConfig.branch || "main";
    document.getElementById("cfgGhToken").value = state.ghConfig.token || "";

    const s = state.domainsConfig.settings || {};
    document.getElementById("cfgAlertSsl").value = s.alert_days_ssl ?? 30;
    document.getElementById("cfgCritSsl").value = s.critical_days_ssl ?? 7;
    document.getElementById("cfgAlertDomain").value = s.alert_days_domain ?? 30;
    document.getElementById("cfgCritDomain").value = s.critical_days_domain ?? 14;
    document.getElementById("cfgNotifyMode").value = s.notify_mode || "alert_only";
    document.getElementById("cfgDefaultEmails").value = (s.default_recipients || []).join(", ");

    openModal("modalSettings");
  };

  document.getElementById("btnSettings").addEventListener("click", openSettingsFn);
  document.getElementById("sideBtnSettings").addEventListener("click", openSettingsFn);
  document.getElementById("syncModeBadge").addEventListener("click", openSettingsFn);
  document.getElementById("profileTrigger").addEventListener("click", openSettingsFn);
  document.getElementById("linkOpenSetupGuide").addEventListener("click", openSettingsFn);

  document.getElementById("formSettings").addEventListener("submit", async (e) => {
    e.preventDefault();
    state.ghConfig = {
      owner: document.getElementById("cfgGhOwner").value.trim() || "duongnvd",
      repo: document.getElementById("cfgGhRepo").value.trim() || "ssl-monitor",
      branch: document.getElementById("cfgGhBranch").value.trim() || "main",
      token: document.getElementById("cfgGhToken").value.trim(),
    };
    localStorage.setItem(STORAGE_KEYS.GH_CONFIG, JSON.stringify(state.ghConfig));
    updateSyncBadge();

    state.domainsConfig.settings = {
      ...state.domainsConfig.settings,
      alert_days_ssl: Number(document.getElementById("cfgAlertSsl").value || 30),
      critical_days_ssl: Number(document.getElementById("cfgCritSsl").value || 7),
      alert_days_domain: Number(document.getElementById("cfgAlertDomain").value || 30),
      critical_days_domain: Number(document.getElementById("cfgCritDomain").value || 14),
      notify_mode: document.getElementById("cfgNotifyMode").value,
      default_recipients: document
        .getElementById("cfgDefaultEmails")
        .value.split(",")
        .map((x) => x.trim())
        .filter(Boolean),
    };

    closeModal("modalSettings");
    try {
      await saveDomainsConfig("chore(settings): cập nhật cấu hình cảnh báo & email");
      await loadAllData();
    } catch (err) {
      showBanner(`Lỗi khi lưu cấu hình: ${err.message}`, true);
    }
  });

  const runScanFn = (e) => {
    if (e) e.preventDefault();
    triggerWorkflowDispatch(false, false);
  };
  document.getElementById("btnRunCheckNow").addEventListener("click", runScanFn);
  document.getElementById("sideBtnRunScan").addEventListener("click", runScanFn);

  document.getElementById("btnTriggerTestEmail").addEventListener("click", () => {
    closeModal("modalSettings");
    triggerWorkflowDispatch(true, true);
  });
});
