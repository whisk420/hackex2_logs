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

const dbReq = indexedDB.open(DB_NAME, 2);

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
    thefts: mergeThefts(base.thefts, incoming.thefts)
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
      if (item.theft) record.thefts = mergeThefts(record.thefts, { [item.wallet]: [item.theft] });
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
  return query.split("|").map((groupText) => {
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
        // Bare token: free text (username/clan/wallet/hardware) or a partial app name; stray level words / numbers are ignored
        const lvlOnly = parseLevelToken(tokens[i]) !== null || isLevelWord(tokens[i]);
        if (!lvlOnly && !/^\d+$/.test(tokens[i])) conditions.push({ type: "text", value: tokens[i].toLowerCase() });
        i++;
      }

      if (matchedName) conditions.push({ type: "software", name: matchedName.toLowerCase(), level, spread: 0 });
    }
    return conditions;
  }).filter((group) => group.length > 0);
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
  const card = document.createElement("div");
  card.className = "node-card";
  const displayIp = node.ip.startsWith("unknown:") ? "UNKNOWN" : node.ip;
  const h = escapeHtml;

  const userTag = node.username ? `<span class="user-tag">${h(node.username)}</span>` : "";
  const lvlTag = node.level ? `<span class="stat-badge" style="background:#1e3a8a; color:#93c5fd;">Lv.${node.level}</span>` : "";
  const fwBadge = node.firewall ? `<span class="stat-badge badge-fw">🛡️ FW: Lv${node.firewall}</span>` : "";
  const encBadge = node.encryptor ? `<span class="stat-badge badge-enc">🔑 ENC: Lv${node.encryptor}</span>` : "";
  const hwTag = node.hardware ? `<span class="hardware-tag">(${h(node.hardware)})</span>` : "";
  const clanBadge = node.clan ? `<span class="stat-badge" style="background:#334155; color:#38bdf8; border: 1px solid #475569;">[${h(node.clan)}]</span>` : "";

  const walletList = node.wallets && node.wallets.length > 0
    ? `<div class="wallet-container">${node.wallets.map((w) => {
        const est = Estimator.formatIncome(Estimator.estimateIncome((node.thefts || {})[w]));
        return `<span class="wallet-tag">Wallet: ${h(w)}${est ? ` <b class="income">${est}</b>` : ""}</span>`;
      }).join("")}</div>`
    : "";

  // Intel strip: hack odds, Good Spam plan, missing scrape data.
  const theirFw = node.firewall ?? (node.downloads?.Firewall?.level ?? null);
  const theirEnc = node.encryptor ?? (node.downloads?.["Password Encryptor"]?.level ?? null);
  const intel = [];
  const bp = Estimator.hackOdds(myStats.bypasser || null, theirFw);
  const pc = Estimator.hackOdds(myStats.cracker || null, theirEnc);
  if (bp !== null) intel.push(`<span class="intel-chip" title="Your Bypasser ${myStats.bypasser} vs Firewall ${theirFw}">🚪 Bypass ${bp}%</span>`);
  if (pc !== null) intel.push(`<span class="intel-chip" title="Your Cracker ${myStats.cracker} vs Encryptor ${theirEnc}">🔨 Crack ${pc}%</span>`);
  if (node.level) {
    const plan = Estimator.spamPlan(node.level, myStats.spam || 0);
    intel.push(`<span class="intel-chip" title="${plan.capReachable ? "Cheapest Spam that hits the ₵100/hr cap" : "Cap not reachable; best-earning level"}">📧 Spam Lv${plan.uploadLevel} → ₵${plan.income}/hr</span>`);
  }
  if (Estimator.needsAdvancedTargeting(node)) {
    intel.push(`<span class="intel-chip intel-missing" title="Advanced targeting: data still to scrape">⚠ Missing: ${Estimator.advancedTargetingMissing(node).map(h).join(", ")}</span>`);
  }
  const intelRow = intel.length ? `<div class="intel-row">${intel.join("")}</div>` : "";

  const downEntries = Object.entries(node.downloads || {});
  const activeGroups = parseSoftwareQuery(document.getElementById("softwareFilterInput").value);
  const downTags = downEntries.length > 0
    ? downEntries.map(([name, data]) => `
        <div class="sw-card sw-loot${activeGroups && entryMatchesFilter(name, data, activeGroups) ? " sw-match" : ""}" data-sw-name="${h(name.toLowerCase())}" data-sw-level="${data.level}">
          <span>${getSoftwareIcon(name)} ${h(name)}</span>
          <strong>Lv${data.level}</strong>
        </div>
      `).join("")
    : "<span style='color:#475569; font-size:12px; font-style: italic;'>No target inventory known</span>";

  card.innerHTML = `
    <div class="node-header">
    <div class="node-meta">
        <span class="ip-title">${displayIp}</span>
        ${clanBadge}
        ${userTag}
        ${lvlTag}
        ${fwBadge}
        ${encBadge}
        ${hwTag}
      </div>
      <div class="node-actions">
        <button class="action-btn toggle-btn">Hide</button>
        <button class="action-btn edit-btn">Edit IP</button>
        <button class="action-btn share-btn">Share</button>
        <button class="action-btn del-btn">Delete</button>
      </div>
    </div>

    <div class="node-body">
      ${intelRow}
      ${walletList}
      <div class="software-section-label">Target Software</div>
      <div class="software-grid">${downTags}</div>
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

  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const req = store.getAll();
  req.onsuccess = () => {
    const records = req.result || [];
    const fullIps = [];
    const partialIps = [];
    let matchCount = 0;

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

    if ((activeGroups || advanced) && matchCount === 0) {
      const noMatchMsg = advanced && !activeGroups
        ? "<p style='color:#4ade80; font-size:13px;'>Every full target has a wallet, Bypasser, Firewall and Encryptor recorded.</p>"
        : "<p style='color:#fbbf24; font-size:13px;'>No targets match your filter.</p>";
      fullContainer.innerHTML = noMatchMsg;
      partialContainer.innerHTML = noMatchMsg;
      return;
    }

    if (fullIps.length === 0) fullContainer.innerHTML = "<p style='color:#475569; font-size:13px;'>No full targets recorded.</p>";
    else fullIps.forEach((n) => fullContainer.appendChild(createCardElement(n)));

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

document.getElementById("advancedToggle").addEventListener("change", () => renderFromDB());
document.getElementById("sortSelect").addEventListener("change", () => renderFromDB());

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
});

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

// --- Export and Import ---
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
  const bundle = JSON.parse(await file.text());
  if (!bundle || bundle.format !== "target-intelligence-console" || ![1, 2].includes(bundle.version)) {
    throw new Error("This is not a Target Intelligence Console export.");
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

addArchiveButtons();
