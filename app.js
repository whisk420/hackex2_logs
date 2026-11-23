/* ==========================================================================
   DARKINDEX // TARGET INTELLIGENCE CONSOLE v2.0
   HackEx 2 Web Companion & Aggregator
   ========================================================================== */

// --- 1. Database Configuration & Constants ---
const DB_NAME = "TargetAggregatorMasterDB_v5";
const STORE_NAME = "targets";
const ARCHIVE_STORE_NAME = "ingestArchive";
const SIPHON_STORE_NAME = "siphonLog";
let db;

// In-Memory Global Log History & Snapshot System
let previousDatabaseSnapshot = null;
let lastPastedInputText = "";
const CHANGE_LOG_MAX = 50;

// Initialize IndexedDB v5
const dbReq = indexedDB.open(DB_NAME, 5);

dbReq.onupgradeneeded = (e) => {
  const d = e.target.result;
  if (!d.objectStoreNames.contains(STORE_NAME)) {
    d.createObjectStore(STORE_NAME, { keyPath: "ip" });
  }
  if (!d.objectStoreNames.contains(ARCHIVE_STORE_NAME)) {
    d.createObjectStore(ARCHIVE_STORE_NAME, { keyPath: "id", autoIncrement: true });
  }
  if (!d.objectStoreNames.contains(SIPHON_STORE_NAME)) {
    d.createObjectStore(SIPHON_STORE_NAME, { keyPath: "ip" });
  }
};

dbReq.onsuccess = (e) => {
  db = e.target.result;
  migrateLegacyStores().then(() => {
    reconcileDatabase().then(renderFromDB);
  });
};

dbReq.onerror = (e) => console.error("Database initialization failed:", e);

// --- 2. Software Classifications ---
const SOFTWARE_DEFENSE = ["Firewall", "Password Encryptor", "Antivirus", "Proxy", "Trace"];
const SOFTWARE_OFFENSE = ["Bypasser", "Password Cracker", "Keygen"];
const SOFTWARE_VIRUSES = ["Spam", "Siphon", "Rootkit"];

const SOFTWARE_ICONS = {
  "Antivirus": "💉", "Spam": "📧", "Rootkit": "🪱",
  "Firewall": "🛡️", "Bypasser": "🚪", "Password Cracker": "🔨",
  "Password Encryptor": "🔑", "Proxy": "🎭", "Trace": "📡",
  "Siphon": "🩸", "Keygen": "⚙️"
};

function getSoftwareIcon(name) {
  for (const [key, icon] of Object.entries(SOFTWARE_ICONS)) {
    if (name.toLowerCase().includes(key.toLowerCase())) return icon;
  }
  return "📦";
}

// --- 3. Regex Parsers Module ---
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

function extractIp(text) {
  if (!text || text.includes('[UNKNOWN]')) return null;
  const ipMatch = text.match(REGEX_IP);
  if (ipMatch) return ipMatch[0];
  const maskedIpMatch = text.match(REGEX_MASKED_IP);
  if (maskedIpMatch) return maskedIpMatch[0];
  return null;
}

function parseHomeScreen(text) {
  const ipMatch = text.match(/IP\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}|\.xxx){3})/i);
  if (!ipMatch) return null;
  const ip = ipMatch[1].trim();

  let username = null;
  const afterCaretMatch = text.match(/>\s*\n+([^\n\r]+)/i);
  if (afterCaretMatch) username = afterCaretMatch[1].trim();
  if (!username) {
    const compactUserMatch = text.match(/^\/\/\/\s*([^/]+?)\s*\//m);
    if (compactUserMatch) username = compactUserMatch[1].trim();
  }

  const clanMatch = text.match(/\[([a-zA-Z0-9_-]{2,8})\]/i);
  const clan = clanMatch ? clanMatch[1].trim() : null;

  const lvlMatch = text.match(/LVL\s*:?\s*(\d+)/i);
  const level = lvlMatch ? parseInt(lvlMatch[1], 10) : null;

  const devMatch = text.match(/DEVICE\s*:?\s*([^\n/]+)/i);
  const device = devMatch ? devMatch[1].trim() : null;

  const netMatch = text.match(/NETWORK\s*:?\s*([^\n/]+)/i);
  const network = netMatch ? netMatch[1].trim() : null;

  const fwMatch = text.match(/FIREWALL\s*:?\s*Lv\.?\s*(\d+)/i);
  const firewall = fwMatch ? parseInt(fwMatch[1], 10) : null;

  const encMatch = text.match(/ENCRYPTOR\s*:?\s*Lv\.?\s*(\d+)/i);
  const encryptor = encMatch ? parseInt(encMatch[1], 10) : null;

  return { ip, username, clan, level, hardware: device && network ? `${device} • ${network}` : (device || network || null), firewall, encryptor };
}

function parseSoftwareScreen(text) {
  const userMatch = text.match(/^([^\r\n]+?)['’]s installed software\s*$/im);
  const username = userMatch ? userMatch[1].trim() : null;
  const softwareItems = {};
  const validNames = [...SOFTWARE_DEFENSE, ...SOFTWARE_OFFENSE, ...SOFTWARE_VIRUSES];

  validNames.forEach((name) => {
    const pattern = new RegExp("\\b" + name.replace(/\s+/g, "\\s+") + "\\b[\\s\\S]*?LVL\\s*(\\d+)", "i");
    const match = text.match(pattern);
    if (match) softwareItems[name] = { level: parseInt(match[1], 10), status: "installed" };
  });

  return { username, softwareItems };
}

function parseVictimLogs(rawLines) {
  const updates = [];
  let lastAccess = null;

  const validLines = rawLines.filter(line => {
    if (!line.trim() || line.trim().length === 1) return false;
    return /^\[[0-9]{1,2}-[0-9]{1,2}\s+[0-9]{1,2}:[0-9]{2}\]/.test(line.trim());
  });

  for (let i = validLines.length - 1; i >= 0; i--) {
    const line = validLines[i].trim();
    if (!line) continue;

    const timeMatch = line.match(/^\[([^\]]+)\]/);
    const time = timeMatch ? timeMatch[1] : null;
    const timeParts = time && time.match(/^(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})$/);
    const eventMinute = timeParts ? (((parseInt(timeParts[1], 10) * 31 + parseInt(timeParts[2], 10)) * 24 + parseInt(timeParts[3], 10)) * 60 + parseInt(timeParts[4], 10)) : null;

    if (line.includes('[UNKNOWN]')) { lastAccess = null; continue; }

    const accessedMatch = line.match(/Device accessed from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i) ||
                          line.match(/Accessed device at\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
    if (accessedMatch) {
      const ip = extractIp(accessedMatch[1]);
      if (ip && ip !== '[UNKNOWN]') {
        lastAccess = { ip, eventMinute };
        updates.push({ ip, time, raw: line });
        continue;
      }
    }

    let action = null, level = null, softwareName = null, isOwned = false, targetIp = null;
    const fromMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)\s+from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
    const toMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)\s+to\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);

    if (fromMatch) {
      action = fromMatch[1].toLowerCase(); level = parseInt(fromMatch[2], 10); softwareName = fromMatch[3].trim(); targetIp = extractIp(fromMatch[4]); isOwned = action.startsWith("download");
    } else if (toMatch) {
      action = toMatch[1].toLowerCase(); level = parseInt(toMatch[2], 10); softwareName = toMatch[3].trim(); targetIp = extractIp(toMatch[4]); isOwned = action.startsWith("download");
    }

    const walletMatch = line.match(/(?:Stole\s+(\d[\d,]*)\s+Crypto\s+from|\d[\d,]*\s+Crypto\s+transferred\s+to)\s+(hx[a-zA-Z0-9.]+)/i);
    if (walletMatch) {
      const cryptoAmount = walletMatch[1] ? parseInt(walletMatch[1].replace(/,/g, ''), 10) : 0;
      const wallet = walletMatch[2];
      if (lastAccess && eventMinute !== null && lastAccess.eventMinute !== null && eventMinute >= lastAccess.eventMinute && eventMinute - lastAccess.eventMinute <= 2) {
        updates.push({ ip: lastAccess.ip, time, wallet, cryptoAmount, raw: line });
      }
      continue;
    }

    if (targetIp && softwareName) {
      updates.push({ ip: targetIp, time, software: { action, level, name: softwareName }, isOwnedSoftware: isOwned, raw: line });
    }
  }
  return updates;
}

// --- 4. Database Operations & Merging ---
function initializeRecord(ip) {
  return {
    ip: ip, username: null, clan: null, level: null, hardware: null,
    firewall: null, encryptor: null, wallets: [], downloads: {}, theftLogs: [],
    incomeEstimate: 0, siphonActive: false
  };
}

function getAllRecords(storeName) {
  return new Promise((resolve, reject) => {
    if (!db) return resolve([]);
    const tx = db.transaction(storeName, "readonly");
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

function mergeTargetRecords(base, incoming) {
  const canonicalIp = ((!incoming.ip.includes("xxx") && base.ip.includes("xxx")) || (base.ip.startsWith("unknown:") && !incoming.ip.includes("xxx"))) ? incoming.ip : base.ip;
  const merged = {
    ip: canonicalIp,
    username: incoming.username || base.username || null,
    clan: incoming.clan || base.clan || null,
    level: incoming.level || base.level || null,
    hardware: incoming.hardware || base.hardware || null,
    firewall: incoming.firewall || base.firewall || null,
    encryptor: incoming.encryptor || base.encryptor || null,
    wallets: Array.from(new Set([...(base.wallets || []), ...(incoming.wallets || [])])),
    downloads: { ...(base.downloads || {}), ...(incoming.downloads || {}) },
    theftLogs: [...(base.theftLogs || []), ...(incoming.theftLogs || [])],
    walletThefts: { ...(base.walletThefts || {}), ...(incoming.walletThefts || {}) },
    incomeEstimate: 0,
    siphonActive: Boolean(incoming.downloads?.["Siphon"] || base.downloads?.["Siphon"] || base.siphonActive || incoming.siphonActive)
  };

  // Recalculate income merging both sources
  merged.incomeEstimate = calculateIncomeFromLogs(merged.theftLogs, merged.walletThefts);

  return { merged, oldKeyToDelete: (canonicalIp !== base.ip) ? base.ip : ((canonicalIp !== incoming.ip) ? incoming.ip : null) };
}

async function mergeUpdates(updates) {
  if (!db || updates.length === 0) return;
  const existingMap = new Map((await getAllRecords(STORE_NAME)).map(r => [r.ip, r]));

  for (const item of updates) {
    if (!item || !item.ip) continue;
    let record = existingMap.get(item.ip) || initializeRecord(item.ip);

    if (item.wallet) {
      const prevOwner = Array.from(existingMap.values()).find(c => c.ip !== item.ip && (c.wallets || []).includes(item.wallet));
      if (prevOwner) {
        const merged = mergeTargetRecords(record, prevOwner).merged;
        merged.ip = item.ip;
        existingMap.delete(prevOwner.ip);
        record = merged;
      }
      if (!record.wallets.includes(item.wallet)) record.wallets.push(item.wallet);
      if (item.cryptoAmount) {
        if (!record.theftLogs) record.theftLogs = [];
        record.theftLogs.push({ time: item.time, amount: item.cryptoAmount });
        record.incomeEstimate = calculateIncomeFromLogs(record.theftLogs, record.walletThefts);
      }
    }

    if (item.software && item.isOwnedSoftware) {
      record.downloads[item.software.name] = { level: item.software.level, status: item.software.action, lastSeen: item.time };
      if (item.software.name.toLowerCase() === "siphon") record.siphonActive = true;
    }
    existingMap.set(item.ip, record);
  }

  return new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    for (const record of existingMap.values()) tx.objectStore(STORE_NAME).put(record);
    tx.oncomplete = resolve;
  });
}

async function reconcileDatabase() {
  if (!db) return;
  const records = await getAllRecords(STORE_NAME);
  const toDelete = new Set();
  const toPut = [];

  for (let i = 0; i < records.length; i++) {
    for (let j = i + 1; j < records.length; j++) {
      const a = records[i], b = records[j];
      const sharesUser = a.username && b.username && a.username.toLowerCase() === b.username.toLowerCase();
      const sharesWallet = (a.wallets || []).some((w) => (b.wallets || []).includes(w));
      if (sharesUser || sharesWallet) {
        const { merged, oldKeyToDelete } = mergeTargetRecords(a, b);
        toPut.push(merged);
        toDelete.add(oldKeyToDelete || (merged.ip === a.ip ? b.ip : a.ip));
        records[i] = merged; records.splice(j, 1); j--;
      }
    }
  }

  if (toPut.length > 0 || toDelete.size > 0) {
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      for (const key of toDelete) if (key) tx.objectStore(STORE_NAME).delete(key);
      for (const record of toPut) tx.objectStore(STORE_NAME).put(record);
      tx.oncomplete = resolve;
    });
  }
}

async function migrateLegacyStores() {
  const records = await getAllRecords(STORE_NAME);
  const legacy = records.filter((r) => r.history || r.uploads);
  if (legacy.length === 0) return;
  return new Promise((resolve) => {
    const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME], "readwrite");
    const targetStore = tx.objectStore(STORE_NAME);
    const archiveStore = tx.objectStore(ARCHIVE_STORE_NAME);
    for (const record of legacy) {
      if (Array.isArray(record.history)) {
        for (const raw of record.history) if (typeof raw === "string") archiveStore.add({ type: "logs", raw, importedAt: new Date().toISOString() });
      }
      delete record.history; delete record.uploads;
      targetStore.put(record);
    }
    tx.oncomplete = resolve;
  });
}

function archiveIngest(type, rawText) {
  if (!db || !rawText.trim()) return;
  db.transaction(ARCHIVE_STORE_NAME, "readwrite").objectStore(ARCHIVE_STORE_NAME).add({ type, raw: rawText, importedAt: new Date().toISOString() });
}

// --- 5. Game Mathematics & Income Estimator ---
function calculateIncomeFromLogs(theftLogs, walletThefts) {
  // Support both new `theftLogs` array and imported DarkIndex `walletThefts` map
  const allEvents = [...(theftLogs || [])];

  if (walletThefts && typeof walletThefts === "object") {
    Object.values(walletThefts).forEach(events => {
      if (Array.isArray(events)) {
        events.forEach(e => {
          if (e.timestampMs) allEvents.push({ timestampMs: e.timestampMs, amount: e.amount });
        });
      }
    });
  }

  if (allEvents.length < 2) return 0;

  // Sort by time
  allEvents.sort((a, b) => {
    const timeA = a.timestampMs ? a.timestampMs : (parseTimestampMinute(a.time) * 60000);
    const timeB = b.timestampMs ? b.timestampMs : (parseTimestampMinute(b.time) * 60000);
    return timeA - timeB;
  });

  const sessions = [];
  let currentSession = [allEvents[0]];

  for (let i = 1; i < allEvents.length; i++) {
    const t1 = allEvents[i - 1].timestampMs ? allEvents[i - 1].timestampMs : (parseTimestampMinute(allEvents[i - 1].time) * 60000);
    const t2 = allEvents[i].timestampMs ? allEvents[i].timestampMs : (parseTimestampMinute(allEvents[i].time) * 60000);

    const gapHours = Math.abs(t2 - t1) / 3600000.0;
    if (gapHours > 1) {
      sessions.push(currentSession);
      currentSession = [allEvents[i]];
    } else {
      currentSession.push(allEvents[i]);
    }
  }
  sessions.push(currentSession);

  let totalIncome = 0, totalHours = 0;
  for (const sess of sessions) {
    if (sess.length < 2) continue;
    const tStart = sess[0].timestampMs ? sess[0].timestampMs : (parseTimestampMinute(sess[0].time) * 60000);
    const tEnd = sess[sess.length - 1].timestampMs ? sess[sess.length - 1].timestampMs : (parseTimestampMinute(sess[sess.length - 1].time) * 60000);
    const durationHours = Math.max((tEnd - tStart) / 3600000.0, 0.25);

    // Sum everything except the very first theft (as that begins the timer)
    const sessionStolen = sess.slice(1).reduce((sum, entry) => sum + (entry.amount || 0), 0);

    totalIncome += sessionStolen;
    totalHours += durationHours;
  }

  return Math.min(totalHours > 0 ? (totalIncome / totalHours) : 0, 100);
}

function parseTimestampMinute(ts) {
  const m = ts?.match(/(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})/);
  // Estimate minutes from start of year
  return m ? (((parseInt(m[1]) * 31 + parseInt(m[2])) * 24 + parseInt(m[3])) * 60) + parseInt(m[4]) : 0;
}

// --- 6. Search & Filter Engine ---
function parseSoftwareQuery(query) {
  if (!query || !query.trim()) return null;
  return query.split("|").map((groupText) => {
    const tokens = groupText.trim().split(/\s+/).filter(Boolean);
    const conditions = [];
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i].toLowerCase();
      if (token === "siphon" || token === "siphons") { conditions.push({ type: "shortcut", value: "siphon" }); i++; continue; }
      if (token === "missing" || token === "incomplete") { conditions.push({ type: "shortcut", value: "missing" }); i++; continue; }
      if (token === "wallet" || token === "wallets") { conditions.push({ type: "shortcut", value: "wallet" }); i++; continue; }

      const lvlMatch = token.match(/^(?:lvl|level)\.?\s*(\d+)$/i) || ((token === "lvl" || token === "level") && tokens[i+1] ? [null, tokens[i+1]] : null);
      if (lvlMatch && /^\d+$/.test(lvlMatch[1])) { conditions.push({ type: "shortcut", value: "lvl", minLevel: parseInt(lvlMatch[1]) }); i += token.includes(lvlMatch[1]) ? 1 : 2; continue; }

      const fwMatch = token.match(/^(?:fw|firewall)\.?\s*(\d+)$/i) || ((token === "fw" || token === "firewall") && tokens[i+1] ? [null, tokens[i+1]] : null);
      if (fwMatch && /^\d+$/.test(fwMatch[1])) { conditions.push({ type: "shortcut", value: "fw", maxFw: parseInt(fwMatch[1]) }); i += token.includes(fwMatch[1]) ? 1 : 2; continue; }

      if (token === "spam" && tokens[i + 1] && /^\d+$/.test(tokens[i + 1])) { conditions.push({ type: "shortcut", value: "spam", minSpam: parseInt(tokens[i + 1]) }); i += 2; continue; }
      if (/^(?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx)$/i.test(token)) { conditions.push({ type: "ip", value: token }); i++; continue; }

      const known = [...SOFTWARE_DEFENSE, ...SOFTWARE_OFFENSE, ...SOFTWARE_VIRUSES].find(s => token.includes(s.toLowerCase()));
      if (known) {
        let lvl = null;
        if (tokens[i+1] && /^\d+$/.test(tokens[i+1])) { lvl = parseInt(tokens[i+1]); i++; }
        conditions.push({ type: "software", name: known.toLowerCase(), level: lvl });
      } else {
        conditions.push({ type: "text", value: token });
      }
      i++;
    }
    return conditions;
  }).filter((group) => group.length > 0);
}

function recordMatchesQuery(record, groups) {
  const dls = record.downloads || {};
  return groups.some((conditions) => conditions.every((c) => {
    if (c.type === "ip") return record.ip.toLowerCase().includes(c.value);
    if (c.type === "shortcut") {
      if (c.value === "siphon") return record.siphonActive || dls["Siphon"];
      if (c.value === "missing") return !record.firewall || !record.encryptor || !record.level;
      if (c.value === "wallet") return record.wallets && record.wallets.length > 0;
      if (c.value === "lvl") return (record.level || 0) >= c.minLevel;
      if (c.value === "fw") return (record.firewall || 99) <= c.maxFw;
      if (c.value === "spam") return dls["Spam"] && dls["Spam"].level >= c.minSpam;
    }
    if (c.type === "software") return Object.entries(dls).some(([n, data]) => n.toLowerCase().includes(c.name) && (c.level === null || data.level === c.level));
    if (c.type === "text") return record.ip.toLowerCase().includes(c.value) || (record.username || "").toLowerCase().includes(c.value) || (record.hardware || "").toLowerCase().includes(c.value);
    return false;
  }));
}

// --- 7. Snapshot & Undo System ---
async function captureSnapshot() {
  if (!db) return;
  previousDatabaseSnapshot = JSON.parse(JSON.stringify(await getAllRecords(STORE_NAME)));
  lastPastedInputText = document.getElementById("dataInput").value;
  const undoBtn = document.getElementById("undoBtn");
  if (undoBtn) { undoBtn.disabled = false; undoBtn.classList.replace("text-slate-500", "text-amber-300"); }
}

async function restoreSnapshot() {
  if (!previousDatabaseSnapshot || !db) return;
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  for (const record of previousDatabaseSnapshot) tx.objectStore(STORE_NAME).put(record);
  tx.oncomplete = () => {
    document.getElementById("dataInput").value = lastPastedInputText;
    previousDatabaseSnapshot = null;
    const undoBtn = document.getElementById("undoBtn");
    if (undoBtn) { undoBtn.disabled = true; undoBtn.classList.replace("text-amber-300", "text-slate-500"); }
    updateStatus("Restored database snapshot prior to last ingestion.");
    renderFromDB();
  };
}

// --- 8. UI Rendering ---
function renderSoftwareList(node, filterGroups, typeList, title) {
  const dls = node.downloads || {};
  let itemsHtml = "";
  let count = 0;

  typeList.forEach(swName => {
    if (dls[swName]) {
      count++;
      const data = dls[swName];
      const isMatch = filterGroups && filterGroups.some(cGroup => cGroup.some(c => c.type === 'software' && swName.toLowerCase().includes(c.name) && (c.level === null || data.level === c.level)));
      itemsHtml += `
        <div class="flex items-center justify-between w-full mb-1 px-1.5 py-0.5 rounded ${isMatch ? 'bg-amber-500/20 outline outline-1 outline-amber-500 animate-pulseGlow' : ''}">
          <span class="text-[10px] text-slate-300 font-mono tracking-wide">${getSoftwareIcon(swName)} ${escapeHtml(swName)}</span>
          <span class="text-[10px] font-bold ${swName === 'Siphon' ? 'text-rose-400' : 'text-sky-400'} font-mono">L${data.level}</span>
        </div>`;
    }
  });

  if (count === 0) return "";
  return `
    <div class="flex flex-col flex-1 min-w-[30%]">
      <span class="text-[9px] font-bold text-cyber-header font-condensed tracking-widest mb-1.5 border-b border-cyber-border pb-1">${title}</span>
      ${itemsHtml}
    </div>`;
}

function createCardElement(node, activeGroups) {
  const card = document.createElement("div");
  card.className = "node-card bg-cyber-card border border-cyber-border rounded-xl p-3 flex flex-col shadow-lg animate-fade-in relative group";

  const displayIp = node.ip.startsWith("unknown:") ? "UNKNOWN TARGET" : node.ip;
  const isMasked = node.ip.includes("xxx");

  // Row 1 Header components
  const userText = node.username ? escapeHtml(node.username) : "";
  const incomeTag = node.incomeEstimate > 0 ? `<span class="text-[10px] font-bold text-amber-400 font-mono ml-auto">~$${node.incomeEstimate.toFixed(0)}/hr</span>` : "";
  const wallets = (node.wallets && node.wallets.length > 0) ? `<span class="text-[10px] text-purple-400 font-mono text-right ml-auto flex flex-col gap-0.5">${node.wallets.map(w => `<span class="cursor-pointer hover:text-white" onclick="copyText('${escapeHtml(w)}')">${escapeHtml(w)}</span>`).join('')}</span>` : "";

  // Action Overlay (Shows on Hover)
  const actionOverlay = `
    <div class="action-overlay absolute inset-0 rounded-xl flex items-center justify-center gap-2 z-10">
      <button class="edit-btn px-4 py-1.5 rounded-md bg-cyber-border text-sky-400 font-bold text-xs tracking-wider border border-sky-900 hover:bg-sky-900 transition-colors">EDIT</button>
      <button class="share-btn px-4 py-1.5 rounded-md bg-cyber-border text-emerald-400 font-bold text-xs tracking-wider border border-emerald-900 hover:bg-emerald-900 transition-colors">SHARE</button>
      <button class="del-btn px-4 py-1.5 rounded-md bg-rose-950/80 text-rose-400 font-bold text-xs tracking-wider border border-rose-900 hover:bg-rose-900 transition-colors">DELETE</button>
    </div>
  `;

  // Row 2 Meta Chips (Hardware & Clan & Level)
  let rigChips = "";
  if (node.level) rigChips += `<span class="px-2 py-0.5 bg-indigo-950/50 border border-indigo-900 text-indigo-300 text-[10px] font-bold font-mono rounded">Lv.${node.level}</span>`;
  if (node.clan) rigChips += `<span class="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 text-[10px] font-bold font-mono rounded">[${escapeHtml(node.clan)}]</span>`;
  if (node.hardware) rigChips += `<span class="px-2 py-0.5 text-slate-400 text-[10px] font-mono tracking-tight truncate max-w-[200px]">${escapeHtml(node.hardware)}</span>`;

  if (node.siphonActive) rigChips += `<span class="px-2 py-0.5 bg-rose-950 border border-rose-900 text-rose-400 text-[10px] font-bold font-mono rounded animate-siphon-pulse shadow-[0_0_8px_rgba(244,63,94,0.3)]">SIPHON ACTIVE</span>`;

  // ROW 3: Intelligence (Bypass/Crack odds)
  let intelChips = "";
  if (node.firewall || node.encryptor) {
    intelChips += `<div class="flex items-center justify-center gap-2 w-full pt-1.5 pb-2 border-b border-cyber-border">`;
    if (node.firewall) intelChips += `<span class="text-[10px] font-mono font-bold text-amber-500 bg-amber-950/30 px-1.5 py-0.5 rounded border border-amber-900/50">FW Lv${node.firewall}</span>`;
    if (node.encryptor) intelChips += `<span class="text-[10px] font-mono font-bold text-purple-400 bg-purple-950/30 px-1.5 py-0.5 rounded border border-purple-900/50">ENC Lv${node.encryptor}</span>`;
    intelChips += `</div>`;
  }

  // Row 4 Software Layout
  const defHtml = renderSoftwareList(node, activeGroups, SOFTWARE_DEFENSE, "DEFENSE");
  const offHtml = renderSoftwareList(node, activeGroups, SOFTWARE_OFFENSE, "OFFENSE");
  const virHtml = renderSoftwareList(node, activeGroups, SOFTWARE_VIRUSES, "VIRUSES");

  const noSoftware = (!defHtml && !offHtml && !virHtml) ? `<div class="w-full text-center py-4 text-xs font-mono italic text-slate-600">No software detected</div>` : "";

  card.innerHTML = `
    ${actionOverlay}
    <!-- ROW 1: Header -->
    <div class="flex items-center justify-between w-full pb-1">
      <span class="ip-title flex-1 text-sm sm:text-base font-bold font-mono text-sky-400 truncate tracking-tight cursor-pointer hover:underline z-20 relative" onclick="copyText('${node.ip}')">${escapeHtml(displayIp)}</span>
      <span class="flex-1 text-center text-xs font-bold font-sans text-cyber-ident truncate px-2">${userText}</span>
      <div class="flex-1 flex flex-col items-end z-20 relative">
        ${incomeTag || wallets}
      </div>
    </div>

    <!-- ROW 2: Meta -->
    <div class="flex flex-wrap items-center justify-center gap-1.5 pb-1">
      ${rigChips}
    </div>

    <!-- ROW 3: Intelligence Divider -->
    ${intelChips}

    <!-- ROW 4: Body Columns -->
    <div class="flex items-start justify-between w-full pt-2 gap-2">
      ${defHtml}${offHtml}${virHtml}${noSoftware}
    </div>
  `;

  // Attach Hover Overlay Actions
  card.querySelector(".edit-btn").addEventListener("click", () => editTargetIp(node.ip));
  card.querySelector(".share-btn").addEventListener("click", () => shareTarget(node));
  card.querySelector(".del-btn").addEventListener("click", () => deleteTarget(node.ip, card));

  // Double click toggles active state on mobile since there is no hover
  card.addEventListener("dblclick", () => {
    card.querySelector(".action-overlay").classList.toggle("active");
  });

  return card;
}

// --- 10. Database Rendering Engine (Virtual Chunking) ---
let renderState = { fullIps: [], partialIps: [], fullRendered: 0, partialRendered: 0, activeGroups: null };
const CHUNK_SIZE = 50;

const lazyObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const sentinel = entry.target;
      lazyObserver.unobserve(sentinel);
      const containerId = sentinel.parentElement.id;
      sentinel.remove();
      if (containerId === "fullIpContainer") renderNextChunk('full');
      else if (containerId === "partialIpContainer") renderNextChunk('partial');
    }
  });
}, { rootMargin: "300px" });

function renderNextChunk(type) {
  const container = document.getElementById(type === 'full' ? 'fullIpContainer' : 'partialIpContainer');
  const ips = type === 'full' ? renderState.fullIps : renderState.partialIps;
  const rendered = type === 'full' ? renderState.fullRendered : renderState.partialRendered;

  const fragment = document.createDocumentFragment();
  const end = Math.min(rendered + CHUNK_SIZE, ips.length);

  for (let i = rendered; i < end; i++) {
    fragment.appendChild(createCardElement(ips[i], renderState.activeGroups));
  }

  container.appendChild(fragment);
  if (type === 'full') renderState.fullRendered = end;
  else renderState.partialRendered = end;

  if (end < ips.length) {
    const sentinel = document.createElement("div");
    sentinel.className = "col-span-full py-4 w-full flex items-center justify-center text-sky-500 font-mono text-xs loading-sentinel";
    sentinel.innerHTML = `<span class="animate-pulse">Loading more targets... (${end}/${ips.length})</span>`;
    container.appendChild(sentinel);
    lazyObserver.observe(sentinel);
  }
}

async function renderFromDB() {
  if (!db) return;

  const fullContainer = document.getElementById("fullIpContainer");
  const partialContainer = document.getElementById("partialIpContainer");
  const filterInput = document.getElementById("softwareFilterInput");
  const activeGroups = parseSoftwareQuery(filterInput.value);

  fullContainer.innerHTML = ""; partialContainer.innerHTML = "";

  const records = await getAllRecords(STORE_NAME);
  const fullIps = []; const partialIps = [];
  let totalWallets = 0, activeSiphons = 0, totalEstIncome = 0;

  records.forEach((rec) => {
    totalWallets += (rec.wallets || []).length;
    if (rec.siphonActive || (rec.downloads && rec.downloads["Siphon"])) activeSiphons++;
    if (rec.incomeEstimate) totalEstIncome += rec.incomeEstimate;

    if (activeGroups && !recordMatchesQuery(rec, activeGroups)) return;
    rec.ip.includes("xxx") ? partialIps.push(rec) : fullIps.push(rec);
  });

  document.getElementById("statTotalTargets").textContent = records.length;
  document.getElementById("statActiveSiphons").textContent = activeSiphons;
  document.getElementById("statTotalWallets").textContent = totalWallets;
  document.getElementById("statEstIncome").textContent = `$${totalEstIncome.toFixed(0)}/hr`;
  document.getElementById("fullTargetCount").textContent = fullIps.length;
  document.getElementById("partialTargetCount").textContent = partialIps.length;

  const ipSorter = (a, b) => {
    const oa = a.ip.split('.'), ob = b.ip.split('.');
    for (let i=0; i<4; i++) {
      const va = oa[i]==="xxx"?-1:parseInt(oa[i]||0), vb = ob[i]==="xxx"?-1:parseInt(ob[i]||0);
      if (va !== vb) return va - vb;
    }
    return 0;
  };

  fullIps.sort(ipSorter);
  partialIps.sort(ipSorter);

  renderState = { fullIps, partialIps, fullRendered: 0, partialRendered: 0, activeGroups };

  if (activeGroups && fullIps.length === 0 && partialIps.length === 0) {
    fullContainer.innerHTML = `<div class="col-span-full p-6 text-center text-amber-500 font-mono text-sm bg-amber-950/20 border border-amber-900/30 rounded-xl">No targets match filter criteria.</div>`;
    return;
  }

  if (fullIps.length > 0) renderNextChunk('full');
  else fullContainer.innerHTML = `<div class="col-span-full p-6 text-center text-slate-500 font-mono text-sm bg-cyber-card border border-cyber-border rounded-xl">No complete targets indexed yet. Paste logs or home screens to ingest data.</div>`;

  if (partialIps.length > 0) renderNextChunk('partial');
  else partialContainer.innerHTML = `<div class="col-span-full p-6 text-center text-slate-500 font-mono text-sm bg-cyber-card border border-cyber-border rounded-xl">No partial targets recorded.</div>`;
}

// --- 11. Knowledge Base Initialization ---
function initKnowledgeBase() {
  const modal = document.getElementById("kbModal");
  const closeBtn = document.getElementById("kbCloseBtn");
  const toggleBtn = document.getElementById("kbToggleBtn");
  const navArea = document.getElementById("kbNav");
  const contentArea = document.getElementById("kbContentArea");

  if (typeof KB_DATA === 'undefined' || !Array.isArray(KB_DATA)) {
    console.warn("Knowledge base data not found or invalid format.");
    return;
  }

  // Generate Navigation
  navArea.innerHTML = KB_DATA.map((topic, index) => `
    <button class="kb-nav-item w-full text-left flex items-center gap-3 ${index === 0 ? 'active' : ''}" data-kb-id="${topic.id}">
      <span class="text-xl">${topic.icon}</span>
      <span class="font-bold truncate">${escapeHtml(topic.title)}</span>
    </button>
  `).join("");

  function renderTopic(topicId) {
    const topic = KB_DATA.find(t => t.id === topicId);
    if (!topic) return;

    // Remove active state from all navs
    document.querySelectorAll(".kb-nav-item").forEach(el => el.classList.remove("active"));
    document.querySelector(`.kb-nav-item[data-kb-id="${topicId}"]`)?.classList.add("active");

    let html = `
      <div class="border-b border-cyber-border pb-4 mb-4">
        <h1 class="text-2xl font-bold text-indigo-400 font-mono flex items-center gap-3">
          <span>${topic.icon}</span> ${escapeHtml(topic.title)}
        </h1>
        <p class="text-slate-400 text-sm font-sans mt-2">${escapeHtml(topic.description)}</p>
      </div>
      <div class="space-y-4 font-sans text-sm text-slate-300 leading-relaxed">
    `;

    // Structured render of the extracted content blocks
    if (topic.content && Array.isArray(topic.content)) {
      topic.content.forEach(block => {
        if (!block || !block.type) return;

        switch (block.type) {
          case 'h':
            html += `<h3 class="text-sky-400 font-bold font-mono text-base mt-5 mb-2">${escapeHtml(block.text)}</h3>`;
            break;
          case 'p':
            html += `<p class="pl-3 border-l-2 ${block.source ? 'border-indigo-500' : 'border-slate-700'} text-slate-300">`;
            html += escapeHtml(block.text);
            if (block.source) {
              html += ` <span class="kb-source-badge ml-1 text-[9px] text-indigo-400 border-indigo-500/50">${escapeHtml(block.source)}</span>`;
            }
            html += `</p>`;
            break;
          case 'tip':
            html += `<div class="bg-emerald-950/20 border border-emerald-900/50 p-3 rounded-lg text-emerald-200 text-xs flex gap-2">
                       <span class="text-emerald-500 font-bold">💡 TIP:</span>
                       <span>${escapeHtml(block.text)}</span>
                     </div>`;
            break;
          case 'warn':
            html += `<div class="bg-amber-950/20 border border-amber-900/50 p-3 rounded-lg text-amber-200 text-xs flex gap-2">
                       <span class="text-amber-500 font-bold">⚠️ NOTE:</span>
                       <span>${escapeHtml(block.text)}</span>
                     </div>`;
            break;
          case 'bullets':
            html += `<ul class="list-disc list-inside space-y-1 ml-2 text-slate-300">`;
            if (block.items && Array.isArray(block.items)) {
              block.items.forEach(item => {
                html += `<li>${escapeHtml(item)}</li>`;
              });
            }
            html += `</ul>`;
            if (block.source) {
              html += `<div class="text-right mt-1"><span class="kb-source-badge text-[9px] text-indigo-400 border-indigo-500/50">${escapeHtml(block.source)}</span></div>`;
            }
            break;
          case 'facts':
            html += `<div class="grid grid-cols-1 gap-2 mt-2">`;
            if (block.items && Array.isArray(block.items)) {
              block.items.forEach(fact => {
                html += `
                  <div class="bg-cyber-bg border border-cyber-border rounded p-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span class="font-bold text-sky-300 font-mono text-xs w-1/3">${escapeHtml(fact.label)}</span>
                    <span class="text-slate-300 text-sm flex-1">${escapeHtml(fact.value)}</span>
                    ${fact.source ? `<span class="kb-source-badge text-[9px] text-indigo-400 border-indigo-500/50 flex-shrink-0">${escapeHtml(fact.source)}</span>` : ''}
                  </div>
                `;
              });
            }
            html += `</div>`;
            break;
          case 'table':
            html += `<div class="overflow-x-auto mt-3 border border-cyber-border rounded-lg shadow-inner bg-[#03050a]">
                       <table class="w-full text-left text-xs whitespace-nowrap">
                         <thead class="bg-slate-900/80 text-sky-400 font-mono border-b border-cyber-border">
                           <tr>`;
            if (block.header && Array.isArray(block.header)) {
              block.header.forEach(th => {
                html += `<th class="px-3 py-2 uppercase tracking-widest text-[10px] font-bold">${escapeHtml(th)}</th>`;
              });
            }
            html += `      </tr>
                         </thead>
                         <tbody class="divide-y divide-cyber-border bg-transparent text-slate-300 font-mono">`;

            if (block.rows && Array.isArray(block.rows)) {
                block.rows.forEach(row => {
                    html += `<tr class="hover:bg-indigo-950/20 transition-colors">`;
                    row.forEach(cell => {
                        html += `<td class="px-3 py-2 text-xs">${escapeHtml(cell)}</td>`;
                    });
                    html += `</tr>`;
                });
            } else {
                html += `<tr><td colspan="10" class="px-3 py-4 text-center italic text-slate-500 text-xs">No data available</td></tr>`;
            }

            html += `    </tbody>
                       </table>
                     </div>`;
            if (block.caption) html += `<div class="text-[10px] text-slate-500 mt-1.5 italic font-sans">${escapeHtml(block.caption)}</div>`;
            break;
        }
      });
    }

    html += `</div>`;
    contentArea.innerHTML = html;
  }

  // Initial render
  if (KB_DATA.length > 0) renderTopic(KB_DATA[0].id);

  // Nav click events
  navArea.addEventListener("click", (e) => {
    const btn = e.target.closest(".kb-nav-item");
    if (btn) renderTopic(btn.getAttribute("data-kb-id"));
  });

  // Modal Toggles
  toggleBtn.addEventListener("click", () => {
    modal.classList.remove("hidden");
    setTimeout(() => {
      modal.classList.remove("opacity-0");
      document.getElementById("kbModalContent").classList.remove("scale-95");
    }, 10);
  });

  function closeModal() {
    modal.classList.add("opacity-0");
    document.getElementById("kbModalContent").classList.add("scale-95");
    setTimeout(() => modal.classList.add("hidden"), 300);
  }

  closeBtn.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });
}

// --- 12. App Initialization & General Handlers ---
window.copyText = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    updateStatus(`Copied to clipboard`);
  } catch (e) {
    const ta = document.createElement("textarea"); ta.value = text;
    document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    updateStatus(`Copied to clipboard`);
  }
};

function escapeHtml(value) {
  if (value == null) return "";
  return String(value).replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

function updateStatus(text) {
  const el = document.getElementById("lastIngestStatus");
  if (el) { el.textContent = text; el.classList.add("text-emerald-400"); setTimeout(() => el.classList.remove("text-emerald-400"), 3000); }
}

async function shareTarget(node) {
  const lines = [`[DARKINDEX TARGET REPORT]`];
  lines.push(`IP: ${node.ip}`);
  if (node.username) lines.push(`User: ${node.username}`);
  if (node.clan) lines.push(`Clan: [${node.clan}]`);
  if (node.level) lines.push(`Level: ${node.level}`);
  if (node.firewall) lines.push(`Firewall: Lv.${node.firewall}`);
  if (node.encryptor) lines.push(`Encryptor: Lv.${node.encryptor}`);
  if (node.wallets && node.wallets.length) lines.push(`Wallets: ${node.wallets.join(", ")}`);

  const sw = Object.entries(node.downloads || {});
  if (sw.length) {
    lines.push("Software:");
    sw.forEach(([n, d]) => lines.push(` - ${n} Lv.${d.level}`));
  }
  await window.copyText(lines.join("\n"));
}

function deleteTarget(ip, cardEl) {
  if (!confirm(`Delete target ${ip}?`)) return;
  db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).delete(ip).onsuccess = () => {
    if (cardEl) cardEl.remove();
    renderFromDB();
  };
}

async function editTargetIp(oldIp) {
  const newIp = prompt(`New IP for ${oldIp}:`, oldIp);
  if (!newIp || !(extractIp(newIp))) return alert("Invalid IP");
  if (newIp === oldIp) return;
  await captureSnapshot();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  store.delete(oldIp);
  const existing = (await getAllRecords(STORE_NAME)).find(r => r.ip === newIp);
  const oldRec = (await getAllRecords(STORE_NAME)).find(r => r.ip === oldIp);
  if (oldRec) {
    oldRec.ip = newIp;
    store.put(existing ? mergeTargetRecords(existing, oldRec).merged : oldRec);
    tx.oncomplete = () => { reconcileDatabase().then(renderFromDB); };
  }
}

// --- 13. Data Bundle Import & Export ---
async function exportDataBundle() {
  const bundle = {
    format: "target-intelligence-console",
    version: 2,
    exportedAt: new Date().toISOString(),
    targets: await getAllRecords(STORE_NAME),
    ingests: await getAllRecords(ARCHIVE_STORE_NAME),
    stats: {
      totalTargets: document.getElementById("statTotalTargets").textContent,
      activeSiphons: document.getElementById("statActiveSiphons").textContent,
      exportedBy: "DarkIndex Web v2.0"
    }
  };

  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `darkindex_targets_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  updateStatus("Exported target intelligence bundle to JSON.");
}

async function importDataBundle(file) {
  const text = await file.text();
  const bundle = JSON.parse(text);

  if (!bundle || bundle.format !== "target-intelligence-console") {
    throw new Error("Invalid format: JSON file is not a Target Intelligence Console export.");
  }

  await captureSnapshot();

  const importedTargets = Array.isArray(bundle.targets) ? bundle.targets : [];
  const importedIngests = Array.isArray(bundle.ingests) ? bundle.ingests : [];
  const existingTargets = await getAllRecords(STORE_NAME);
  const targetsMap = new Map(existingTargets.map((r) => [r.ip, r]));

  for (const imported of importedTargets) {
    if (!imported || !imported.ip) continue;
    delete imported.history;
    delete imported.uploads;

    // Auto-calculate income for freshly imported legacy records
    if (!imported.incomeEstimate && (imported.walletThefts || imported.theftLogs)) {
      imported.incomeEstimate = calculateIncomeFromLogs(imported.theftLogs, imported.walletThefts);
    }

    const existing = targetsMap.get(imported.ip);
    targetsMap.set(imported.ip, existing ? mergeTargetRecords(existing, imported).merged : imported);
  }

  const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME], "readwrite");
  const targetStore = tx.objectStore(STORE_NAME);
  const archiveStore = tx.objectStore(ARCHIVE_STORE_NAME);

  for (const target of targetsMap.values()) targetStore.put(target);
  for (const ingest of importedIngests) {
    if (ingest && ingest.raw) {
      archiveStore.add({ type: ingest.type || "import", raw: ingest.raw, importedAt: ingest.importedAt || new Date().toISOString() });
    }
  }

  return new Promise((resolve, reject) => {
    tx.oncomplete = () => {
      reconcileDatabase().then(renderFromDB);
      updateStatus(`Imported ${importedTargets.length} targets from bundle.`);
      resolve();
    };
    tx.onerror = () => reject(tx.error);
  });
}

// --- 14. Event Listener Registration ---
document.addEventListener("DOMContentLoaded", () => {
  initKnowledgeBase();

  // Export / Import
  document.getElementById("exportBtn").addEventListener("click", exportDataBundle);
  document.getElementById("importBtn").addEventListener("click", () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = async (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) {
        try {
          await importDataBundle(file);
        } catch (err) {
          alert(`Import failed: ${err.message}`);
        }
      }
    };
    input.click();
  });

  document.getElementById("processDataBtn").addEventListener("click", async () => {
    const text = document.getElementById("dataInput").value;
    if (!text.trim()) return;

    if (parseHomeScreen(text) || parseSoftwareScreen(text).username) {
      await captureSnapshot();
      const h = parseHomeScreen(text);
      const s = parseSoftwareScreen(text);
      const targetUser = (h?.username || s?.username || "").toLowerCase();

      const all = await getAllRecords(STORE_NAME);
      let existing = all.find(r => (h && r.ip === h.ip) || (r.username && r.username.toLowerCase() === targetUser));

      let incoming = initializeRecord(h?.ip || `unknown:${targetUser}`);
      if (h) {
        incoming.username = h.username; incoming.clan = h.clan; incoming.level = h.level; incoming.hardware = h.hardware;
        if (h.firewall) { incoming.firewall = h.firewall; incoming.downloads["Firewall"] = {level: h.firewall}; }
        if (h.encryptor) { incoming.encryptor = h.encryptor; incoming.downloads["Password Encryptor"] = {level: h.encryptor}; }
      }
      if (s) {
        if(!incoming.username) incoming.username = s.username;
        Object.assign(incoming.downloads, s.softwareItems);
      }

      let finalRec = existing ? mergeTargetRecords(existing, incoming).merged : incoming;
      db.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(finalRec).onsuccess = () => {
        archiveIngest(h ? "home" : "software", text);
        document.getElementById("dataInput").value = "";
        reconcileDatabase().then(renderFromDB);
        updateStatus("Ingested profile intelligence.");
      };
      return;
    }

    await captureSnapshot();
    const updates = parseVictimLogs(text.split("\n"));
    if (updates.length > 0) {
      await mergeUpdates(updates);
      archiveIngest("logs", text);
      document.getElementById("dataInput").value = "";
      await reconcileDatabase();
      updateStatus(`Processed ${updates.length} log events.`);
      renderFromDB();
    } else {
      updateStatus("No recognizable data found.");
    }
  });

  document.getElementById("softwareFilterInput").addEventListener("input", renderFromDB);
  document.getElementById("clearFilterBtn").addEventListener("click", () => {
    document.getElementById("softwareFilterInput").value = ""; renderFromDB();
  });

  document.querySelectorAll(".chip-btn").forEach(chip => {
    chip.addEventListener("click", () => {
      document.getElementById("softwareFilterInput").value = chip.getAttribute("data-filter");
      renderFromDB();
    });
  });

  document.getElementById("undoBtn").addEventListener("click", restoreSnapshot);

  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!confirm("Wipe entire database?")) return;
    const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME, SIPHON_STORE_NAME], "readwrite");
    tx.objectStore(STORE_NAME).clear(); tx.objectStore(ARCHIVE_STORE_NAME).clear(); tx.objectStore(SIPHON_STORE_NAME).clear();
    tx.oncomplete = () => renderFromDB();
  });

  document.getElementById("partialToggleBtn").addEventListener("click", (e) => {
    const cont = document.getElementById("partialIpContainer");
    const icon = document.getElementById("partialToggleIcon");
    const isHid = cont.classList.toggle("hidden");
    icon.style.transform = isHid ? "rotate(0deg)" : "rotate(90deg)";
  });
});
