// --- 1. IndexedDB Initialization ---
const DB_NAME = "TargetAggregatorMasterDB_v4";
const STORE_NAME = "targets";
const ARCHIVE_STORE_NAME = "ingestArchive";
let db;

const dbReq = indexedDB.open(DB_NAME, 2);

dbReq.onupgradeneeded = (e) => {
  const d = e.target.result;
  if (!d.objectStoreNames.contains(STORE_NAME)) {
    d.createObjectStore(STORE_NAME, { keyPath: "ip" });
  }
  if (!d.objectStoreNames.contains(ARCHIVE_STORE_NAME)) {
    d.createObjectStore(ARCHIVE_STORE_NAME, { keyPath: "id", autoIncrement: true });
  }
};

dbReq.onsuccess = (e) => {
  db = e.target.result;
  migrateLegacyHistory().then(renderFromDB);
};

dbReq.onerror = (e) => console.error("Database initialization failed:", e);

// --- 2. Software Emojis Map ---
const SOFTWARE_ICONS = {
  "Antivirus": "💉",
  "Spam": "📧",
  "Rootkit": "🪱",
  "Firewall": "🛡️",
  "Bypasser": "🚪",
  "Password Cracker": "🔨",
  "Password Encryptor": "🔑",
  "Proxy": "🎭",
  "Trace": "📡",
  "Siphon": "🩸",
  "Keygen": "⚙️"
};

function getSoftwareIcon(name) {
  for (const [key, icon] of Object.entries(SOFTWARE_ICONS)) {
    if (name.toLowerCase().includes(key.toLowerCase())) return icon;
  }
  return "📦";
}

// --- 3. Regex Helpers ---
// These are already defined in your code, but let's make sure they're properly used:
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

// Add a more comprehensive pattern for line validation
const VALID_LOG_LINE_PATTERN = /^\[[0-9]{1,2}-[0-9]{1,2}\s+[0-9]{1,2}:[0-9]{2}\]/;


function extractIp(text) {
    // Handle [UNKNOWN] case specifically
    if (text.includes('[UNKNOWN]')) {
        return null; // Return null for unknown IPs instead of trying to parse them
    }
    
    // Try standard IP pattern first
    const ipMatch = text.match(REGEX_IP);
    if (ipMatch) {
        return ipMatch[0];
    }
    
    // Try masked IP pattern second
    const maskedIpMatch = text.match(REGEX_MASKED_IP);
    if (maskedIpMatch) {
        return maskedIpMatch[0];
    }
    
    return null;
}

// --- 4. Parsers ---
function parseMyLogs(rawLines) {
  let currentAccessedIp = null;
  const updates = [];

  for (let i = rawLines.length - 1; i >= 0; i--) {
    const line = rawLines[i].trim();
    if (!line) continue;

    const timeMatch = line.match(/^\[([^\]]+)\]/);
    const time = timeMatch ? timeMatch[1] : null;
    const isAccessed = line.includes("Accessed device at");
    const explicitIp = extractIp(line);

    if (isAccessed && explicitIp) {
      currentAccessedIp = explicitIp;
      updates.push({ ip: explicitIp, time, raw: line });
      continue;
    }

    let stolenWallet = null;
    if (line.includes("Stole") && line.includes("from hx")) {
      const wMatch = line.match(/\b(hx[a-zA-Z0-9.]+)\b/);
      if (wMatch) stolenWallet = wMatch[1];
    }

    const softMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)(?:\s+(?:from|to)\b|\.\.\.|$)/i);
    let software = null;
    let isOwned = false;

    if (softMatch) {
      const action = softMatch[1].toLowerCase();
      software = {
        action: action,
        level: parseInt(softMatch[2], 10),
        name: softMatch[3].trim()
      };
      isOwned = action.startsWith("download");
    }

    const targetIp = explicitIp || currentAccessedIp;
    if (targetIp) {
      updates.push({
        ip: targetIp,
        time,
        wallet: stolenWallet && targetIp === currentAccessedIp ? stolenWallet : null,
        software,
        isOwnedSoftware: isOwned,
        raw: line
      });
    }
  }
  return updates;
}

function parseVictimLogs(rawLines) {
    const updates = [];
  let lastAccess = null;
    
    // Filter out non-log lines (noise, graffiti)
    const validLines = rawLines.filter(line => {
        if (!line.trim()) return false;  // Skip empty lines
        
        // Filter out single character lines that are likely graffiti
        if (line.trim().length === 1) return false;
        
        // Only process lines that start with timestamp format [MM-DD HH:MM]
        const timestampPattern = /^\[[0-9]{1,2}-[0-9]{1,2}\s+[0-9]{1,2}:[0-9]{2}\]/;
        return timestampPattern.test(line.trim());
    });
    
    for (let i = validLines.length - 1; i >= 0; i--) {
        const line = validLines[i].trim();
        if (!line) continue;

      const timeMatch = line.match(/^\[([^\]]+)\]/);
        const time = timeMatch ? timeMatch[1] : null;
      const timeParts = time && time.match(/^(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})$/);
      const eventMinute = timeParts
        ? (((parseInt(timeParts[1], 10) * 31 + parseInt(timeParts[2], 10)) * 24 + parseInt(timeParts[3], 10)) * 60 + parseInt(timeParts[4], 10))
        : null;

      // Wallets are correlated only to the nearest preceding access in event time.
      if (line.includes('[UNKNOWN]')) {
        lastAccess = null;
        continue;
      }
        
        // Handle device access lines
        const accessedMatch = line.match(/Device accessed from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        if (accessedMatch) {
            const ip = extractIp(accessedMatch[1]);
            if (ip && ip !== '[UNKNOWN]') {
            lastAccess = { ip, eventMinute };
                updates.push({ ip: ip, time, raw: line });
                continue;
            }
        }

        const accessAtMatch = line.match(/Accessed device at\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        if (accessAtMatch) {
          const ip = extractIp(accessAtMatch[1]);
          if (ip) {
            lastAccess = { ip, eventMinute };
            updates.push({ ip, time, raw: line });
            continue;
          }
        }
        
        // Handle software ownership lines with "from" or "to"
        let softMatch = null;
        let targetIp = null;
        let action = null;
        let level = null;
        let softwareName = null;
        let isOwned = false;
        
        // First, try to match lines that have explicit IP references
        const fromMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)\s+from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        const toMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)\s+to\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        
        if (fromMatch) {
            action = fromMatch[1].toLowerCase();
            level = parseInt(fromMatch[2], 10);
            softwareName = fromMatch[3].trim();
            targetIp = extractIp(fromMatch[4]);
            isOwned = action.startsWith("download");
        } else if (toMatch) {
            action = toMatch[1].toLowerCase();
            level = parseInt(toMatch[2], 10);
            softwareName = toMatch[3].trim();
            targetIp = extractIp(toMatch[4]);
            isOwned = action.startsWith("download");
        } else {
            // Fallback to original pattern for lines without explicit IP references
            softMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)(?:\s+(?:from|to)\b|\.|\.\.|\s*$)/i);
            if (softMatch) {
                action = softMatch[1].toLowerCase();
                level = parseInt(softMatch[2], 10);
                softwareName = softMatch[3].trim();
                isOwned = action.startsWith("download");
                
                // Try to extract IP from the line for upload/download actions
                const ipFromLine = extractIp(line);
                if (ipFromLine && !line.includes('[UNKNOWN]')) {
                    targetIp = ipFromLine;
                }
            }
        }
        
        // Handle lines that don't match software patterns but have IPs
        if (!softMatch && !fromMatch && !toMatch) {
            const byMatch = line.match(/by\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
            if (byMatch) {
                targetIp = extractIp(byMatch[1]);
            }
        }

        const walletMatch = line.match(/(Stole\s+(\d[\d,]*)\s+Crypto\s+from|\d[\d,]*\s+Crypto\s+transferred\s+to)\s+(hx[a-zA-Z0-9.]+)/i);
        if (walletMatch) {
          const withinCorrelationWindow = lastAccess && eventMinute !== null && lastAccess.eventMinute !== null &&
            eventMinute >= lastAccess.eventMinute && eventMinute - lastAccess.eventMinute <= 2;
          if (withinCorrelationWindow) {
            const update = { ip: lastAccess.ip, time, wallet: walletMatch[3], raw: line };
            // Theft amount + time feed the passive wallet income estimator.
            if (walletMatch[2] && eventMinute !== null) {
              update.theft = { m: eventMinute, a: parseInt(walletMatch[2].replace(/,/g, ""), 10) };
            }
            updates.push(update);
          }
          continue;
        }
        
        // Handle crypto transfers and other actions
        const transferMatch = line.match(/(\d+)\s+Crypto\s+transferred\s+to\s+(hx[a-zA-Z0-9.]+)/);
        if (transferMatch) {
            updates.push({
                ip: targetIp,
                time,
                wallet: transferMatch[2],
                raw: line
            });
            continue;
        }
        
        // Handle password cracking actions  
        const crackMatch = line.match(/(Cracking|Cracked)\s+password\s+(?:on\s+)?((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        if (crackMatch) {
            targetIp = extractIp(crackMatch[2]);
            updates.push({
                ip: targetIp,
                time,
                raw: line
            });
            continue;
        }
        
        // Handle firewall actions
        const firewallMatch = line.match(/(Bypassed|Failed to bypass)\s+firewall\s+(?:on\s+)?((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
        if (firewallMatch) {
            targetIp = extractIp(firewallMatch[2]);
            updates.push({
                ip: targetIp,
                time,
                raw: line
            });
            continue;
        }
        
        // Handle software ownership with proper IP extraction
        if (softMatch || fromMatch || toMatch) {
            if (targetIp && !line.includes('[UNKNOWN]')) {
                updates.push({
                    ip: targetIp,
                    time,
                    software: {
                        action: action,
                        level: level,
                        name: softwareName
                    },
                    isOwnedSoftware: isOwned,
                    raw: line
                });
            }
        }
    }
    
    return updates;
}

function parseHomeScreen(text) {
  const ipMatch = text.match(/IP\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}|\.xxx){3})/i);
  if (!ipMatch) return null;
  const ip = ipMatch[1].trim();

  // 1. Clean Base Username (Line directly after ">")
  let username = null;
  const afterCaretMatch = text.match(/>\s*\n+([^\n\r]+)/i);
  if (afterCaretMatch) {
    username = afterCaretMatch[1].trim();
  }
  if (!username) {
    const compactUserMatch = text.match(/^\/\/\/\s*([^/]+?)\s*\//m);
    if (compactUserMatch) username = compactUserMatch[1].trim();
  }

  // 2. Clan Tag (Optional): Stored separately
  const clanMatch = text.match(/\[([a-zA-Z0-9_-]{2,6})\]/i);
  const clan = clanMatch ? clanMatch[1].trim() : null;

  // 3. Stats & Hardware
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

  return {
    ip,
    username,
    clan,
    level,
    hardware: device && network ? `${device} • ${network}` : (device || network || null),
    firewall,
    encryptor
  };
}

// --- 5. Data Merge & Snapshot Management ---
function initializeRecord(ip) {
  return {
    ip: ip,
    username: null,
    clan: null,
    level: null,
    hardware: null,
    firewall: null,
    encryptor: null,
    wallets: [],
    downloads: {},
    thefts: {} // wallet -> [{m: event minute, a: amount}]
  };
}

// Union of two wallet->theft-list maps, deduplicated by (minute, amount).
function mergeThefts(a, b) {
  const out = {};
  for (const src of [a || {}, b || {}]) {
    for (const [wallet, list] of Object.entries(src)) {
      const seen = new Set((out[wallet] || []).map((e) => `${e.m}:${e.a}`));
      out[wallet] = out[wallet] || [];
      for (const e of list || []) {
        const key = `${e.m}:${e.a}`;
        if (!seen.has(key)) { seen.add(key); out[wallet].push(e); }
      }
    }
  }
  return out;
}

// Best available income estimate across a record's wallets (highest per-hour wins).
function recordIncome(record) {
  let best = null;
  for (const list of Object.values(record.thefts || {})) {
    const est = Estimator.estimateIncome(list);
    if (!est) continue;
    const val = est.perHour !== undefined ? est.perHour : -1;
    const bestVal = best ? (best.perHour !== undefined ? best.perHour : -1) : -2;
    if (val > bestVal) best = est;
  }
  return best;
}

function archiveIngest(type, rawText) {
  if (!db || !rawText.trim()) return;
  const tx = db.transaction(ARCHIVE_STORE_NAME, "readwrite");
  tx.objectStore(ARCHIVE_STORE_NAME).add({
    type,
    raw: rawText,
    importedAt: new Date().toISOString()
  });
}

async function migrateLegacyHistory() {
  const records = await getAllRecords(STORE_NAME);
  const legacyRecords = records.filter((record) =>
    (Array.isArray(record.history) && record.history.length > 0) || Object.prototype.hasOwnProperty.call(record, "uploads")
  );
  if (legacyRecords.length === 0) return;

  return new Promise((resolve, reject) => {
    const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME], "readwrite");
    const targetStore = tx.objectStore(STORE_NAME);
    const archiveStore = tx.objectStore(ARCHIVE_STORE_NAME);
    for (const record of legacyRecords) {
      const legacyHistory = Array.isArray(record.history) ? record.history : [];
      for (const raw of legacyHistory) {
        if (typeof raw === "string") archiveStore.add({ type: "logs", raw, importedAt: new Date().toISOString() });
      }
      delete record.history;
      delete record.uploads;
      targetStore.put(record);
    }
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

function getAllRecords(storeName) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

function mergeTargetRecords(base, incoming) {
  const baseIsMasked = base.ip.includes("xxx");
  const incomingIsMasked = incoming.ip.includes("xxx");
  const baseIsTemporary = base.ip.startsWith("unknown:");
  const canonicalIp = ((!incomingIsMasked && baseIsMasked) || (baseIsTemporary && !incomingIsMasked))
    ? incoming.ip
    : base.ip;

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
    thefts: mergeThefts(base.thefts, incoming.thefts)
  };

  return {
    merged,
    oldKeyToDelete: (canonicalIp !== base.ip) ? base.ip : ((canonicalIp !== incoming.ip) ? incoming.ip : null)
  };
}

// Single-pass batch updater without async transaction stall
async function mergeUpdates(updates) {
  if (!db || updates.length === 0) return;

  // Read everything first
  const existingMap = await new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => {
      const map = new Map();
      (req.result || []).forEach((r) => map.set(r.ip, r));
      resolve(map);
    };
    req.onerror = () => resolve(new Map());
  });

  // Apply updates to in-memory records
  for (const item of updates) {
    if (!item || !item.ip) continue;

    let record = existingMap.get(item.ip);
    if (!record) {
      record = initializeRecord(item.ip);
      existingMap.set(item.ip, record);
    }

    if (item.wallet) {
      const previousOwner = Array.from(existingMap.values()).find((candidate) =>
        candidate.ip !== item.ip && (candidate.wallets || []).includes(item.wallet)
      );
      if (previousOwner) {
        const merged = mergeTargetRecords(record, previousOwner).merged;
        merged.ip = item.ip;
        existingMap.delete(previousOwner.ip);
        record = merged;
        existingMap.set(item.ip, record);
      }
      if (!record.wallets.includes(item.wallet)) record.wallets.push(item.wallet);
      if (item.theft) record.thefts = mergeThefts(record.thefts, { [item.wallet]: [item.theft] });
    }

    if (item.software && item.isOwnedSoftware) {
      record.downloads[item.software.name] = {
        level: item.software.level,
        status: item.software.action,
        lastSeen: item.time
      };
    }

  }

  // Write batch back cleanly in one atomic transaction
  return new Promise((resolve) => {
    const writeTx = db.transaction(STORE_NAME, "readwrite");
    const writeStore = writeTx.objectStore(STORE_NAME);
    for (const record of existingMap.values()) {
      writeStore.put(record);
    }
    writeTx.oncomplete = () => resolve();
    writeTx.onerror = (e) => {
      console.error("Write transaction error:", e);
      resolve();
    };
  });
}

// Deduplication Reconciliation
async function reconcileDatabase() {
  if (!db) return;

  const records = await new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => resolve([]);
  });

  if (!records || records.length < 2) return;

  const toDelete = new Set();
  const toPut = [];

  for (let i = 0; i < records.length; i++) {
    for (let j = i + 1; j < records.length; j++) {
      const recA = records[i];
      const recB = records[j];

      if (!recA || !recB) continue;

      const sharesUser = recA.username && recB.username &&
        recA.username.toLowerCase() === recB.username.toLowerCase();
      const sharesWallet = (recA.wallets || []).some((w) => (recB.wallets || []).includes(w));

      if (sharesUser || sharesWallet) {
        const mergeResult = mergeTargetRecords(recA, recB);
        const finalMerged = mergeResult.merged;

        toPut.push(finalMerged);
        const obsoleteKey = (finalMerged.ip === recA.ip) ? recB.ip : recA.ip;
        toDelete.add(obsoleteKey);

        records[i] = finalMerged;
        records.splice(j, 1);
        j--;
      }
    }
  }

  if (toPut.length > 0 || toDelete.size > 0) {
    return new Promise((resolve) => {
      const writeTx = db.transaction(STORE_NAME, "readwrite");
      const writeStore = writeTx.objectStore(STORE_NAME);

      for (const key of toDelete) writeStore.delete(key);
      for (const record of toPut) writeStore.put(record);

      writeTx.oncomplete = () => resolve();
      writeTx.onerror = () => resolve();
    });
  }
}

// --- 2b. Change Log (Confirmation Box) ---
const CHANGE_LOG_MAX = 60;
let changeLogEntries = []; // newest first: { time, text, kind }

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

function logChange(text, kind = "ok") {
  const stamp = new Date().toTimeString().slice(0, 8);
  changeLogEntries.unshift({ time: stamp, text, kind });
  if (changeLogEntries.length > CHANGE_LOG_MAX) changeLogEntries.length = CHANGE_LOG_MAX;
  renderChangeLog();
}

function clearChangeLog() {
  changeLogEntries = [];
  renderChangeLog();
}

function renderChangeLog() {
  const box = document.getElementById("changeLogList");
  if (!box) return;
  if (changeLogEntries.length === 0) {
    box.innerHTML = "<li class='cl-empty'>No changes yet — process a log to see what was updated.</li>";
    return;
  }
  box.innerHTML = changeLogEntries.map(e =>
    `<li class="cl-item cl-${e.kind}"><span class="cl-time">${e.time}</span><span class="cl-text">${escapeHtml(e.text)}</span></li>`
  ).join("");
}

// Human-readable diff between two target records (oldRec may be null for brand-new targets)
function describeRecordDiff(oldRec, newRec) {
  if (!newRec) return [];
  const parts = [];
  if (!oldRec) {
    parts.push("NEW TARGET");
  } else {
    const fieldFmt = [
      ["username", v => `user ${v}`],
      ["level", v => `Lv.${v}`],
      ["hardware", v => v],
      ["firewall", v => `Firewall Lv.${v}`],
      ["encryptor", v => `Encryptor Lv.${v}`]
    ];
    for (const [key, fmt] of fieldFmt) {
      const a = oldRec[key];
      const b = newRec[key];
      if (!a && b !== undefined && b !== null && b !== "") parts.push(`+${fmt(b)}`);
      else if (a && !b) parts.push(`-${fmt(a)}`);
      else if (String(a) !== String(b)) parts.push(`${key} ${fmt(a)}→${fmt(b)}`);
    }
  }
  const oldWallets = (oldRec && oldRec.wallets) || [];
  const newWallets = (newRec.wallets || []).filter(w => !oldWallets.includes(w));
  if (newWallets.length > 0) parts.push(`+${newWallets.length} wallet(s)`);
  for (const mapKey of ["downloads"]) {
    const aMap = (oldRec && oldRec[mapKey]) || {};
    const bMap = newRec[mapKey] || {};
    for (const name of Object.keys(bMap)) {
      if (!aMap[name]) parts.push(`+${name} Lv.${bMap[name].level}`);
      else if (String(aMap[name].level) !== String(bMap[name].level)) parts.push(`${name} Lv.${aMap[name].level}→Lv.${bMap[name].level}`);
    }
  }
  return parts;
}

// --- 2c. Undo / Snapshot System ---
let previousDatabaseSnapshot = null;
let lastPastedInputText = "";
const undoBtn = document.getElementById("undoBtn");

async function captureSnapshot() {
  if (!db) return;
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => {
      previousDatabaseSnapshot = JSON.parse(JSON.stringify(req.result || []));
      lastPastedInputText = document.getElementById("dataInput").value;
      if (undoBtn) {
        undoBtn.disabled = false;
      }
      resolve();
    };
    req.onerror = () => resolve();
  });
}

async function restoreSnapshot() {
  if (!previousDatabaseSnapshot || !db) return;

  const writeTx = db.transaction(STORE_NAME, "readwrite");
  const store = writeTx.objectStore(STORE_NAME);
  store.clear();

  for (const record of previousDatabaseSnapshot) {
    store.put(record);
  }

  writeTx.oncomplete = () => {
    document.getElementById("dataInput").value = lastPastedInputText;
    previousDatabaseSnapshot = null;
    if (undoBtn) {
      undoBtn.disabled = true;
    }
    renderFromDB();
    setIngestStatus("Last ingest undone", "warn");
    showToast("Undid last ingest", "warn");
  };
}

if (undoBtn) undoBtn.addEventListener("click", restoreSnapshot);

// --- 6. Card UI & Action Helpers ---
function deleteTarget(ip, cardElement) {
  if (!confirm(`Delete target ${ip}?`)) return;
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).delete(ip);
  tx.oncomplete = () => {
    showToast(`Deleted ${ip}`, "warn");
    renderFromDB();
  };
}

async function shareTarget(node) {
  const lines = [`TARGET: ${node.ip}`];
  if (node.username) lines.push(`User: ${node.username}`);
  if (node.firewall) lines.push(`Firewall: Lv.${node.firewall}`);
  if (node.encryptor) lines.push(`Encryptor: Lv.${node.encryptor}`);

  const softwareEntries = Object.entries(node.downloads || {});
  if (softwareEntries.length > 0) {
    lines.push("\nSoftware:");
    softwareEntries.forEach(([name, data]) => {
      lines.push(`• ${name} Lv.${data.level}`);
    });
  }

  const payload = lines.join("\n");
  try {
    await navigator.clipboard.writeText(payload);
    showToast(`Copied report for ${node.ip}`, "ok");
  } catch (err) {
    const ta = document.createElement("textarea");
    ta.value = payload;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    showToast(`Copied report for ${node.ip}`, "ok");
  }
}

async function editTargetIp(oldIp) {
  const newIpInput = prompt(`Enter new IP address for ${oldIp}:`, oldIp);
  if (!newIpInput) return;

  const validIp = extractIp(newIpInput.trim());
  if (!validIp) {
    showToast("Invalid IP format entered.", "error");
    return;
  }
  if (validIp === oldIp) return;

  await captureSnapshot();

  const allRecords = await new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => resolve(req.result || []);
  });

  const existing = allRecords.find((r) => r.ip === oldIp);
  if (!existing) return;

  const collision = allRecords.find((r) => r.ip === validIp);

  const writeTx = db.transaction(STORE_NAME, "readwrite");
  const store = writeTx.objectStore(STORE_NAME);

  store.delete(oldIp);

  if (collision) {
    existing.ip = validIp;
    const mergeResult = mergeTargetRecords(collision, existing);
    store.put(mergeResult.merged);
  } else {
    existing.ip = validIp;
    store.put(existing);
  }

  writeTx.oncomplete = async () => {
    await reconcileDatabase();
    renderFromDB();
  };
}

function parseSoftwareScreen(text) {
  // Capture the complete username from its own header line, including punctuation.
  const userMatch = text.match(/^([^\r\n]+?)['’]s installed software\s*$/im);
  const username = userMatch ? userMatch[1].trim() : null;

  const softwareItems = {};
  const validNames = [
    "Antivirus", "Spam", "Rootkit", "Firewall", "Bypasser",
    "Password Cracker", "Password Encryptor", "Proxy", "Trace",
    "Siphon"
  ];

  // 2. Normalize and scan by tool name
  validNames.forEach((name) => {
    const pattern = new RegExp(
      "\\b" + name.replace(/\s+/g, "\\s+") + "\\b[\\s\\S]*?LVL\\s*(\\d+)",
      "i"
    );
    const match = text.match(pattern);
    if (match) {
      softwareItems[name] = {
        level: parseInt(match[1], 10),
        status: "installed"
      };
    }
  });

  return { username, softwareItems };
}

function compareIps(ipA, ipB) {
  const octA = ipA.split(".");
  const octB = ipB.split(".");
  for (let i = 0; i < 4; i++) {
    const valA = octA[i] === "xxx" ? -1 : parseInt(octA[i], 10);
    const valB = octB[i] === "xxx" ? -1 : parseInt(octB[i], 10);
    if (valA !== valB) return valA - valB;
  }
  return 0;
}

// --- Software Filter Query Parsing & Matching ---
const KNOWN_SOFTWARE_NAMES = [
  "Password Cracker", "Password Encryptor",
  ...new Set(Object.keys(SOFTWARE_ICONS))
].sort((a, b) => b.length - a.length); // Longest first so multi-word names win

// Extracts a level from single tokens like "Lv.9", "LV3" or "LVL9" — null if not one.
function parseLevelToken(token) {
  const m = String(token).match(/^lv(?:l)?\.?\s*(\d+)$/i);
  return m ? parseInt(m[1], 10) : null;
}

// True for a bare "lv" / "lvl" word whose number arrives in the next token.
function isLevelWord(token) {
  return /^(?:lv|lvl)$/.test(String(token).toLowerCase());
}

function isIpToken(token) {
  return /^(?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx)$/i.test(String(token));
}

// DarkIndex-style aliases for app names.
const SOFTWARE_ALIASES = {
  fw: "Firewall", enc: "Password Encryptor", encryptor: "Password Encryptor", av: "Antivirus",
  bp: "Bypasser", bypass: "Bypasser", pc: "Password Cracker", crack: "Password Cracker", cracker: "Password Cracker",
  rk: "Rootkit"
};
// Apps you can steal (Firewall and Keygen excluded) — used by the "sw N" shortcut.
const LOOT_APPS = ["Password Encryptor", "Antivirus", "Proxy", "Trace", "Bypasser", "Password Cracker", "Spam", "Siphon", "Rootkit"];

// Parses a filter query into OR groups (split by "|"); each group is an AND list of conditions.
// Examples: "Bypasser Lv.9" | "Spam Lv.3 Bypasser" | "lvl 28-32" | "sw 20" | "fw 12" | "user:Bob" | "wallet:hx12"
function parseSoftwareQuery(query) {
  if (!query || !query.trim()) return null;

  const groups = query.split("|").map((groupText) => {
    const tokens = groupText.trim().split(/\s+/).filter(Boolean);
    const conditions = [];
    let i = 0;

    while (i < tokens.length) {
      const tok = tokens[i];
      const lower = tok.toLowerCase();

      // Prefixed text filters: user:Name, clan:TAG, wallet:hx...
      const prefixed = tok.match(/^(user|username|clan|wallet|hw|hardware):(.+)$/i);
      if (prefixed) {
        const field = { user: "username", username: "username", clan: "clan", wallet: "wallet", hw: "hardware", hardware: "hardware" }[prefixed[1].toLowerCase()];
        conditions.push({ type: "field", field, value: prefixed[2].toLowerCase() });
        i++;
        continue;
      }
      if (/^hx[a-z0-9.]{3,}$/i.test(tok)) {
        conditions.push({ type: "field", field: "wallet", value: lower });
        i++;
        continue;
      }

      // Player level: "lvl 30", "lvl28-32", "level 30"
      const lvlRange = (lower + (tokens[i + 1] && /^\d/.test(tokens[i + 1]) && /^(?:lvl|lv|level)\.?$/.test(lower) ? tokens[i + 1] : ""))
        .match(/^(?:lvl|lv|level)\.?(\d+)(?:-(\d+))?$/);
      if (lvlRange) {
        const lo = parseInt(lvlRange[1], 10);
        conditions.push({ type: "playerLevel", min: lo, max: lvlRange[2] ? parseInt(lvlRange[2], 10) : lo });
        i += /^(?:lvl|lv|level)\.?$/.test(lower) ? 2 : 1;
        continue;
      }

      // Any loot app at exactly level N: "sw 20", "all 20", "software 20"
      if (/^(?:sw|software|all)$/.test(lower) && tokens[i + 1]) {
        const lvl = parseLevelToken(tokens[i + 1]) ?? (/^\d+$/.test(tokens[i + 1]) ? parseInt(tokens[i + 1], 10) : null);
        if (lvl !== null) {
          conditions.push({ type: "anyLoot", level: lvl });
          i += 2;
          continue;
        }
      }

      // Alias + level with ±2 spread: "fw 12", "bp9", "spam 17"
      const aliasMatch = lower.match(/^([a-z]+?)(\d+)?$/);
      if (aliasMatch && SOFTWARE_ALIASES[aliasMatch[1]]) {
        let lvl = aliasMatch[2] ? parseInt(aliasMatch[2], 10) : null;
        i++;
        if (lvl === null && tokens[i]) {
          const next = parseLevelToken(tokens[i]) ?? (/^\d+$/.test(tokens[i]) ? parseInt(tokens[i], 10) : null);
          if (next !== null) { lvl = next; i++; }
        }
        conditions.push({ type: "software", name: SOFTWARE_ALIASES[aliasMatch[1]].toLowerCase(), level: lvl, spread: lvl !== null ? 2 : 0 });
        continue;
      }

      if (isIpToken(tokens[i])) {
        conditions.push({ type: "ip", value: tokens[i].toLowerCase() });
        i++;
        continue;
      }

      // Try to match a known software name greedily across consecutive tokens
      let matchedName = null;
      for (const candidate of KNOWN_SOFTWARE_NAMES) {
        const words = candidate.split(" ");
        if (i + words.length > tokens.length) continue;
        const slice = tokens.slice(i, i + words.length).join(" ").toLowerCase();
        if (slice === candidate.toLowerCase()) {
          matchedName = candidate;
          break;
        }
      }

      let level = null;
      if (matchedName) {
        i += matchedName.split(" ").length;
        // Optional level spec right after the name: "Lv.9", "LVL 3" or a bare number ("Bypasser 9")
        if (tokens[i]) {
          const single = parseLevelToken(tokens[i]);
          if (single !== null) {
            level = single;
            i++;
          } else if (isLevelWord(tokens[i]) && tokens[i + 1] && /^\d+$/.test(tokens[i + 1])) {
            // "Bypasser LVL 9" — word and number split across two tokens
            level = parseInt(tokens[i + 1], 10);
            i += 2;
          } else if (/^\d+$/.test(tokens[i])) {
            level = parseInt(tokens[i], 10);
            i++;
          }
        }
      } else {
        // Bare token: free text (username/clan/wallet/hardware) or a partial app name; stray level words / numbers are ignored
        const lvlOnly = parseLevelToken(tokens[i]) !== null || isLevelWord(tokens[i]);
        if (!lvlOnly && !/^\d+$/.test(tokens[i])) conditions.push({ type: "text", value: tokens[i].toLowerCase() });
        i++;
      }

      if (matchedName) conditions.push({ type: "software", name: matchedName.toLowerCase(), level, spread: 0 });
    }

    return conditions;
  }).filter((conditions) => conditions.length > 0);

  return groups.length > 0 ? groups : null;
}

function findDownload(record, name) {
  return Object.entries(record.downloads || {}).find(
    ([n]) => n.toLowerCase() === name || n.toLowerCase().includes(name)
  );
}

function levelInSpread(actual, wanted, spread) {
  return wanted === null || (actual != null && Math.abs(actual - wanted) <= (spread || 0));
}

function conditionMatches(record, cond) {
  switch (cond.type) {
    case "ip":
      return record.ip.toLowerCase().includes(cond.value);
    case "playerLevel":
      return record.level != null && record.level >= cond.min && record.level <= cond.max;
    case "anyLoot":
      return LOOT_APPS.some((app) => record.downloads && record.downloads[app] && record.downloads[app].level === cond.level);
    case "field": {
      if (cond.field === "wallet") return (record.wallets || []).some((w) => w.toLowerCase().includes(cond.value));
      return (record[cond.field] || "").toLowerCase().includes(cond.value);
    }
    case "text": {
      const v = cond.value;
      return ["username", "clan", "hardware"].some((f) => (record[f] || "").toLowerCase().includes(v)) ||
        (record.wallets || []).some((w) => w.toLowerCase().includes(v)) ||
        String(record.level || "") === v ||
        record.ip.toLowerCase().includes(v) ||
        !!findDownload(record, v);
    }
    case "software": {
      const entry = findDownload(record, cond.name);
      // Firewall / Encryptor also come from the Home screen fields when no download is recorded.
      let level = entry ? entry[1].level : null;
      if (!entry && cond.name === "firewall") level = record.firewall;
      if (!entry && cond.name === "password encryptor") level = record.encryptor;
      if (level == null) return false;
      return levelInSpread(level, cond.level, cond.spread);
    }
    default:
      return true;
  }
}

// A record matches if ANY OR group has ALL of its conditions satisfied.
function recordMatchesQuery(record, groups) {
  return groups.some((conditions) => conditions.every((cond) => conditionMatches(record, cond)));
}

// True if this single software entry satisfies at least one condition in any OR group (card highlighting).
function entryMatchesFilter(name, data, groups) {
  const n = name.toLowerCase();
  return groups.some((conditions) =>
    conditions.some((cond) => {
      if (cond.type === "anyLoot") return LOOT_APPS.includes(name) && data.level === cond.level;
      if (cond.type === "text") return n.includes(cond.value);
      if (cond.type !== "software") return false;
      return (n === cond.name || n.includes(cond.name)) && levelInSpread(data.level, cond.level, cond.spread);
    })
  );
}

// --- My Stats (used for odds and Good Spam ranking), persisted per browser ---
const MY_STATS_KEY = "tic.myStats";
function loadMyStats() {
  try { return JSON.parse(localStorage.getItem(MY_STATS_KEY)) || {}; } catch (e) { return {}; }
}
function saveMyStats(stats) {
  try { localStorage.setItem(MY_STATS_KEY, JSON.stringify(stats)); } catch (e) { /* private mode */ }
}
let myStats = loadMyStats();

function createCardElement(node) {
  const card = document.createElement("article");
  card.className = "node-card";
  const isUnknown = node.ip.startsWith("unknown:");
  const displayIp = isUnknown ? "UNKNOWN IP" : node.ip;
  const h = escapeHtml;

  // Identity tags
  const tags = [];
  if (node.level) tags.push(`<span class="tag-level">Lv.${node.level}</span>`);
  if (node.clan) tags.push(`<span class="tag-clan">[${h(node.clan)}]</span>`);
  if (node.firewall) tags.push(`<span class="tag-fw">🛡️ FW ${node.firewall}</span>`);
  if (node.encryptor) tags.push(`<span class="tag-enc">🔑 ENC ${node.encryptor}</span>`);
  const hwLine = node.hardware ? `<div class="truncate font-mono text-[11px] text-slate-500" title="${h(node.hardware)}">${h(node.hardware)}</div>` : "";

  // Intel strip: hack odds, Good Spam plan, missing scrape data.
  const theirFw = node.firewall ?? (node.downloads?.Firewall?.level ?? null);
  const theirEnc = node.encryptor ?? (node.downloads?.["Password Encryptor"]?.level ?? null);
  const intel = [];
  const bp = Estimator.hackOdds(myStats.bypasser || null, theirFw);
  const pc = Estimator.hackOdds(myStats.cracker || null, theirEnc);
  const oddsColor = (p) => (p >= 74 ? "text-emerald-300" : p >= 50 ? "text-amber-300" : "text-rose-300");
  if (bp !== null) intel.push(`<span class="intel-chip ${oddsColor(bp)}" title="Your Bypasser ${myStats.bypasser} vs Firewall ${theirFw}">🚪 Bypass ${bp}%</span>`);
  if (pc !== null) intel.push(`<span class="intel-chip ${oddsColor(pc)}" title="Your Cracker ${myStats.cracker} vs Encryptor ${theirEnc}">🔨 Crack ${pc}%</span>`);
  if (node.level) {
    const plan = Estimator.spamPlan(node.level, myStats.spam || 0);
    intel.push(`<span class="intel-chip" title="${plan.capReachable ? "Cheapest Spam that hits the ₵100/hr cap" : "Cap not reachable; best-earning level"}">📧 Spam Lv${plan.uploadLevel} → ₵${plan.income}/hr</span>`);
  }
  if (Estimator.needsAdvancedTargeting(node)) {
    intel.push(`<span class="intel-chip intel-missing" title="Advanced targeting: data still to scrape">⚠ Missing: ${Estimator.advancedTargetingMissing(node).map(h).join(", ")}</span>`);
  }
  const intelRow = intel.length ? `<div class="flex flex-wrap gap-1.5">${intel.join("")}</div>` : "";

  const walletList = node.wallets && node.wallets.length > 0
    ? `<div class="flex flex-col gap-1">${node.wallets.map((w) => {
        const est = Estimator.formatIncome(Estimator.estimateIncome((node.thefts || {})[w]));
        return `<button type="button" class="wallet-tag text-left" data-copy="${h(w)}" title="Copy wallet">👛 ${h(w)}${est ? ` <span class="income">${est}</span>` : ""}</button>`;
      }).join("")}</div>`
    : "";

  const downEntries = Object.entries(node.downloads || {});
  const activeGroups = parseSoftwareQuery(document.getElementById("softwareFilterInput").value);
  const downTags = downEntries.length > 0
    ? `<div class="grid grid-cols-2 gap-1.5">${downEntries.map(([name, data]) => `
        <div class="sw-card${activeGroups && entryMatchesFilter(name, data, activeGroups) ? " sw-match" : ""}" data-sw-name="${h(name.toLowerCase())}" data-sw-level="${data.level}">
          <span class="truncate">${getSoftwareIcon(name)} ${h(name)}</span>
          <strong class="pl-1">Lv${data.level}</strong>
        </div>`).join("")}</div>`
    : `<div class="font-mono text-xs italic text-slate-600">No target inventory known</div>`;

  card.innerHTML = `
    <div class="flex items-start justify-between gap-2">
      <div class="min-w-0">
        <button type="button" class="ip-title block truncate font-mono text-base font-bold tracking-tight text-sky-400 hover:underline${isUnknown ? " cursor-default text-slate-500 hover:no-underline" : ""}"${isUnknown ? " disabled" : ' title="Copy IP address"'}>${h(displayIp)}</button>
        ${node.username ? `<div class="truncate text-sm font-semibold text-cyber-ident">${h(node.username)}</div>` : ""}
      </div>
      <button type="button" class="toggle-btn btn-card shrink-0" aria-expanded="true">Hide</button>
    </div>
    ${tags.length ? `<div class="flex flex-wrap gap-1.5">${tags.join("")}</div>` : ""}
    ${hwLine}
    <div class="node-body flex flex-col gap-2.5">
      ${intelRow}
      ${walletList}
      <div class="card-label border-b border-cyber-border pb-1">Target software</div>
      ${downTags}
      <div class="flex gap-1.5 border-t border-cyber-border pt-2.5">
        <button type="button" class="edit-btn btn-card flex-1">Edit IP</button>
        <button type="button" class="share-btn btn-card flex-1">Share</button>
        <button type="button" class="del-btn btn-card-danger flex-1">Delete</button>
      </div>
    </div>
  `;

  const toggleBtn = card.querySelector(".toggle-btn");
  const bodySection = card.querySelector(".node-body");
  if (!isUnknown) {
    card.querySelector(".ip-title").addEventListener("click", () => copyText(node.ip, `Copied ${node.ip}`));
  }
  card.querySelectorAll("[data-copy]").forEach((el) =>
    el.addEventListener("click", () => copyText(el.dataset.copy, "Copied wallet"))
  );
  toggleBtn.addEventListener("click", () => {
    const show = bodySection.hidden;
    bodySection.hidden = !show;
    toggleBtn.textContent = show ? "Hide" : "Expand";
    toggleBtn.setAttribute("aria-expanded", String(show));
  });

  card.querySelector(".edit-btn").addEventListener("click", () => editTargetIp(node.ip));
  card.querySelector(".share-btn").addEventListener("click", () => shareTarget(node));
  card.querySelector(".del-btn").addEventListener("click", () => deleteTarget(node.ip, card));

  return card;
}

// --- Toast + clipboard + status helpers ---
let toastTimer = null;
function showToast(text, tone = "info") {
  const el = document.getElementById("toast");
  if (!el) return;
  const tones = { info: "border-sky-500/40 text-sky-200", ok: "border-emerald-500/40 text-emerald-200", warn: "border-amber-500/50 text-amber-200", error: "border-rose-500/50 text-rose-200" };
  el.className = el.className.replace(/border-\S+\/\d+ text-\S+-200/g, "").trim() + " " + (tones[tone] || tones.info);
  el.textContent = text;
  el.hidden = false;
  el.style.animation = "none"; void el.offsetWidth; el.style.animation = "";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
}

async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
  showToast(message || "Copied", "ok");
}

function setIngestStatus(text, tone = "ok") {
  const el = document.getElementById("lastIngestStatus");
  if (!el) return;
  el.textContent = `${new Date().toTimeString().slice(0, 5)} · ${text}`;
  el.classList.remove("italic", "text-slate-500", "text-emerald-400", "text-amber-400", "text-rose-400");
  el.classList.add({ ok: "text-emerald-400", warn: "text-amber-400", error: "text-rose-400" }[tone] || "text-slate-500");
}

function updateStatsBar(records) {
  let wallets = 0, income = 0, missing = 0;
  for (const r of records) {
    wallets += (r.wallets || []).length;
    const est = recordIncome(r);
    if (est && est.perHour !== undefined) income += est.perHour;
    if (Estimator.needsAdvancedTargeting(r)) missing++;
  }
  document.getElementById("statTotalTargets").textContent = records.length;
  document.getElementById("statTotalWallets").textContent = wallets;
  document.getElementById("statEstIncome").textContent = `₵${Estimator.formatAmount(income)}/hr`;
  document.getElementById("statMissing").textContent = missing;
}

function renderFromDB() {
  if (!db) return;

  const fullContainer = document.getElementById("fullIpContainer");
  const partialContainer = document.getElementById("partialIpContainer");
  const filterInput = document.getElementById("softwareFilterInput");
  const activeGroups = parseSoftwareQuery(filterInput.value);

  fullContainer.innerHTML = "";
  partialContainer.innerHTML = "";

  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const req = store.getAll();
  req.onsuccess = () => {
    const records = req.result || [];
    const fullIps = [];
    const partialIps = [];
    let matchCount = 0;

    updateStatsBar(records);
    const advanced = document.getElementById("advancedToggle").checked;
    records.forEach((rec) => {
      if (activeGroups && !recordMatchesQuery(rec, activeGroups)) return;
      if (advanced && !Estimator.needsAdvancedTargeting(rec)) return;
      matchCount++;
      if (rec.ip.includes("xxx")) partialIps.push(rec);
      else fullIps.push(rec);
    });

    const sortMode = document.getElementById("sortSelect").value;
    const sortList = (list) => {
      if (sortMode === "spam") {
        return Estimator.rankForSpam(list, myStats.spam || 0).map((x) => x.record);
      }
      if (sortMode === "income") {
        const val = (r) => { const e = recordIncome(r); return e ? (e.perHour ?? -1) : -2; };
        return list.slice().sort((a, b) => val(b) - val(a) || compareIps(a.ip, b.ip));
      }
      return list.slice().sort((a, b) => compareIps(a.ip, b.ip));
    };
    const sortedFull = sortList(fullIps);
    const sortedPartial = sortList(partialIps);
    fullIps.length = 0; fullIps.push(...sortedFull);
    partialIps.length = 0; partialIps.push(...sortedPartial);

    document.getElementById("resultCount").textContent =
      (activeGroups || advanced) ? `${matchCount} of ${records.length} targets` : `${records.length} targets`;

    document.getElementById("fullTargetCount").textContent = fullIps.length;
    document.getElementById("partialTargetCount").textContent = partialIps.length;

    if ((activeGroups || advanced) && matchCount === 0) {
      const noMatchMsg = advanced && !activeGroups
        ? `<div class="empty-state border-emerald-900/50 bg-emerald-950/20 text-emerald-400">Every full target has a wallet, Bypasser, Firewall and Encryptor recorded.</div>`
        : `<div class="empty-state border-amber-900/40 bg-amber-950/20 text-amber-400">No targets match your filter.</div>`;
      fullContainer.innerHTML = noMatchMsg;
      partialContainer.innerHTML = noMatchMsg;
      return;
    }

    if (fullIps.length === 0) {
      fullContainer.innerHTML = records.length === 0
        ? `<div class="empty-state">No targets indexed yet.<br><span class="text-xs text-slate-600">Paste victim logs, a Home screen or a Software screen above and press Process data.</span></div>`
        : `<div class="empty-state">No complete targets match.</div>`;
    } else fullIps.forEach((n) => fullContainer.appendChild(createCardElement(n)));

    if (partialIps.length === 0) partialContainer.innerHTML = `<div class="empty-state">No partial targets recorded.</div>`;
    else partialIps.forEach((n) => partialContainer.appendChild(createCardElement(n)));
  };
}

// Live software filtering
document.getElementById("softwareFilterInput").addEventListener("input", () => renderFromDB());
document.getElementById("clearFilterBtn").addEventListener("click", () => {
  document.getElementById("softwareFilterInput").value = "";
  renderFromDB();
});

// Quick chips mirror the advanced-targeting checkbox and the sort menu; filter chips fill the search box.
function syncChips() {
  const adv = document.getElementById("advancedToggle").checked;
  const sort = document.getElementById("sortSelect").value;
  document.querySelectorAll(".chip-btn[data-toggle=advanced]").forEach((c) => c.setAttribute("aria-pressed", String(adv)));
  document.querySelectorAll(".chip-btn[data-sort]").forEach((c) => c.setAttribute("aria-pressed", String(c.dataset.sort === sort)));
}
document.getElementById("advancedToggle").addEventListener("change", () => { syncChips(); renderFromDB(); });
document.getElementById("sortSelect").addEventListener("change", () => { syncChips(); renderFromDB(); });
document.querySelectorAll(".chip-btn").forEach((chip) => chip.addEventListener("click", () => {
  if (chip.dataset.toggle === "advanced") {
    const box = document.getElementById("advancedToggle");
    box.checked = !box.checked;
  } else if (chip.dataset.sort) {
    const sel = document.getElementById("sortSelect");
    sel.value = sel.value === chip.dataset.sort ? "ip" : chip.dataset.sort;
  } else if (chip.dataset.filter) {
    document.getElementById("softwareFilterInput").value = chip.dataset.filter;
  }
  syncChips();
  renderFromDB();
}));

// My Stats panel
(function initMyStats() {
  const panel = document.getElementById("statsPanel");
  const btn = document.getElementById("statsToggleBtn");
  const fields = ["bypasser", "cracker", "spam"];
  fields.forEach((f) => {
    const input = document.getElementById(`my-${f}`);
    input.value = myStats[f] || "";
    input.addEventListener("input", () => {
      const n = parseInt(input.value, 10);
      myStats[f] = Number.isFinite(n) && n > 0 ? n : null;
      saveMyStats(myStats);
      renderFromDB();
    });
  });
  btn.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    btn.setAttribute("aria-expanded", String(!panel.hidden));
  });
})();

document.getElementById("partialToggleBtn").addEventListener("click", () => {
  const partialContainer = document.getElementById("partialIpContainer");
  const isExpanded = partialContainer.hidden;
  partialContainer.hidden = !isExpanded;
  document.getElementById("partialToggleBtn").setAttribute("aria-expanded", String(isExpanded));
  document.getElementById("partialToggleIcon").style.transform = isExpanded ? "rotate(90deg)" : "";
});

document.getElementById("scrollTopBtn").addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
});

document.getElementById("scrollBottomBtn").addEventListener("click", () => {
  window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
});

// --- 7. Event Handlers ---
document.getElementById("processDataBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const homeData = parseHomeScreen(text);
  const softwareData = parseSoftwareScreen(text);
  if (homeData || (softwareData.username && Object.keys(softwareData.softwareItems).length > 0)) {
    await processVictimData();
    return;
  }

  await captureSnapshot();
  const updates = parseVictimLogs(text.split("\n"));
  await mergeUpdates(updates);
  archiveIngest("logs", text);
  document.getElementById("dataInput").value = "";
  await reconcileDatabase();
  renderFromDB();
  const ips = new Set(updates.filter((u) => u && u.ip).map((u) => u.ip)).size;
  const thefts = updates.filter((u) => u && u.theft).length;
  if (updates.length === 0) {
    setIngestStatus("No recognisable log lines found", "warn");
    showToast("Nothing recognised — expected lines like [11-20 10:01] …", "warn");
  } else {
    setIngestStatus(`Logs: ${updates.length} events · ${ips} IPs${thefts ? ` · ${thefts} thefts` : ""}`);
    showToast(`Processed ${updates.length} log events`, "ok");
  }
});

async function processVictimData() {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const parsed = parseHomeScreen(text);
  if (!parsed) {
    const software = parseSoftwareScreen(text);
    if (!software.username) {
      setIngestStatus("Could not identify Victim Home or Software data", "error");
      showToast("Could not identify Victim Home or Victim Software data.", "error");
      return;
    }
    if (Object.keys(software.softwareItems).length === 0) {
      setIngestStatus("No software levels found in that Software screen", "error");
      showToast("Could not detect any software levels in this Victim Software dump.", "error");
      return;
    }

    await captureSnapshot();
    const allRecords = await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () => resolve(req.result || []);
    });

    const targetUser = software.username.trim().toLowerCase();
    let record = allRecords.find((r) => r.username && r.username.trim().toLowerCase() === targetUser);
    if (!record) {
      record = initializeRecord(`unknown:${targetUser}`);
      record.username = software.username.trim();
    }

    for (const [name, data] of Object.entries(software.softwareItems)) {
      record.downloads[name] = data;
    }

    const writeTx = db.transaction(STORE_NAME, "readwrite");
    writeTx.objectStore(STORE_NAME).put(record);
    writeTx.oncomplete = () => {
      archiveIngest("software", text);
      document.getElementById("dataInput").value = "";
      renderFromDB();
      const n = Object.keys(software.softwareItems).length;
      setIngestStatus(`Software: ${n} apps for ${record.username}`);
      showToast(`Saved ${n} apps for ${record.username}`, "ok");
    };
    return;
  }

  await captureSnapshot();

  const allRecords = await new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => resolve(req.result || []);
  });

  const existing = allRecords.find((r) => r.ip === parsed.ip || (parsed.username && r.username && r.username.toLowerCase() === parsed.username.toLowerCase()));

  const incoming = initializeRecord(parsed.ip);
  incoming.username = parsed.username;
  incoming.clan = parsed.clan;
  incoming.level = parsed.level;
  incoming.hardware = parsed.hardware;
  if (parsed.firewall) {
    incoming.firewall = parsed.firewall;
    incoming.downloads["Firewall"] = { level: parsed.firewall, status: "installed" };
  }
  if (parsed.encryptor) {
    incoming.encryptor = parsed.encryptor;
    incoming.downloads["Password Encryptor"] = { level: parsed.encryptor, status: "installed" };
  }

  let finalRecord = incoming;
  let oldKeyToDelete = null;

  if (existing) {
    const mergeResult = mergeTargetRecords(existing, incoming);
    finalRecord = mergeResult.merged;
    oldKeyToDelete = mergeResult.oldKeyToDelete;
  }

  const writeTx = db.transaction(STORE_NAME, "readwrite");
  const store = writeTx.objectStore(STORE_NAME);

  if (oldKeyToDelete && oldKeyToDelete !== finalRecord.ip) {
    store.delete(oldKeyToDelete);
  }
  store.put(finalRecord);

  writeTx.oncomplete = async () => {
    archiveIngest("home", text);
    document.getElementById("dataInput").value = "";
    await reconcileDatabase();
    renderFromDB();
    setIngestStatus(`Home: ${finalRecord.ip}${finalRecord.username ? ` (${finalRecord.username})` : ""}`);
    showToast(`${existing ? "Updated" : "Added"} ${finalRecord.ip}`, "ok");
  };
}

document.getElementById("clearBtn").addEventListener("click", () => {
  if (!confirm("Are you sure you want to wipe the entire database?")) return;
  const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME], "readwrite");
  tx.objectStore(STORE_NAME).clear();
  tx.objectStore(ARCHIVE_STORE_NAME).clear();
  tx.oncomplete = () => renderFromDB();
});

// --- Export and Import ---
async function exportDataBundle() {
  const bundle = {
    format: "target-intelligence-console",
    version: 2,
    exportedAt: new Date().toISOString(),
    targets: await getAllRecords(STORE_NAME),
    ingests: await getAllRecords(ARCHIVE_STORE_NAME)
  };

  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `target_console_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function importDataBundle(file) {
  const bundle = JSON.parse(await file.text());
  if (!bundle || bundle.format !== "target-intelligence-console" || ![1, 2].includes(bundle.version)) {
    throw new Error("This is not a Target Intelligence Console export.");
  }

  const importedTargets = Array.isArray(bundle.targets) ? bundle.targets : [];
  const importedIngests = Array.isArray(bundle.ingests) ? bundle.ingests : [];
  const existingTargets = await getAllRecords(STORE_NAME);
  const targets = new Map(existingTargets.filter((record) => record && record.ip).map((record) => [record.ip, record]));

  for (const imported of importedTargets) {
    if (!imported || !imported.ip) continue;
    delete imported.history;
    delete imported.uploads;
    const existing = targets.get(imported.ip);
    targets.set(imported.ip, existing ? mergeTargetRecords(existing, imported).merged : imported);
  }

  const tx = db.transaction([STORE_NAME, ARCHIVE_STORE_NAME], "readwrite");
  const targetStore = tx.objectStore(STORE_NAME);
  const archiveStore = tx.objectStore(ARCHIVE_STORE_NAME);
  for (const target of targets.values()) targetStore.put(target);
  for (const ingest of importedIngests) {
    if (ingest && ["logs", "home", "software"].includes(ingest.type) && typeof ingest.raw === "string") {
      archiveStore.add({ type: ingest.type, raw: ingest.raw, importedAt: ingest.importedAt || new Date().toISOString() });
    }
  }

  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
  renderFromDB();
  return { targetCount: importedTargets.length, ingestCount: importedIngests.length };
}

// Export / Import buttons live in the header markup.
document.getElementById("exportBtn").addEventListener("click", async () => {
  try {
    await exportDataBundle();
    showToast("Exported database", "ok");
  } catch (error) {
    showToast(`Export failed: ${error.message}`, "error");
  }
});

document.getElementById("importBtn").addEventListener("click", () => {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".json,application/json";
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      const result = await importDataBundle(file);
      showToast(`Imported ${result.targetCount} targets, ${result.ingestCount} archived ingests`, "ok");
      setIngestStatus(`Import: ${result.targetCount} targets`);
    } catch (error) {
      showToast(`Import failed: ${error.message}`, "error");
    }
  });
  input.click();
});
