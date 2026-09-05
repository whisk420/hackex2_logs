// --- 1. IndexedDB Initialization ---
const DB_NAME = "TargetAggregatorMasterDB_v4";
const STORE_NAME = "targets";
let db;

const dbReq = indexedDB.open(DB_NAME, 1);

dbReq.onupgradeneeded = (e) => {
  const d = e.target.result;
  if (!d.objectStoreNames.contains(STORE_NAME)) {
    d.createObjectStore(STORE_NAME, { keyPath: "ip" });
  }
};

dbReq.onsuccess = (e) => {
  db = e.target.result;
  renderFromDB();
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
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

function extractIp(text) {
  const match = text.match(REGEX_IP) || text.match(REGEX_MASKED_IP);
  return match ? match[0] : null;
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

  for (let i = rawLines.length - 1; i >= 0; i--) {
    const line = rawLines[i].trim();
    if (!line) continue;

    const timeMatch = line.match(/^\[([^\]]+)\]/);
    const time = timeMatch ? timeMatch[1] : null;

    const byMatch = line.match(/\bby\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))\b/i);
    if (byMatch) {
      const attackerIp = byMatch[1];
      const softMatch = line.match(/Lv(\d+)\s+(.+?)\s+being\s+(uploaded|downloaded)\s+by/i);
      let software = null;
      if (softMatch) {
        software = {
          level: parseInt(softMatch[1], 10),
          name: softMatch[2].trim(),
          action: softMatch[3].toLowerCase()
        };
      }

      updates.push({
        ip: attackerIp,
        time,
        software,
        isOwnedSoftware: true,
        raw: line
      });
      continue;
    }

    const accessedFromMatch = line.match(/Device accessed from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))\b/i);
    if (accessedFromMatch) {
      updates.push({ ip: accessedFromMatch[1], time, raw: line });
      continue;
    }

    const outboundIp = extractIp(line);
    if (outboundIp) {
      updates.push({ ip: outboundIp, time, raw: line });
    }
  }
  return updates;
}

function parseHomeScreen(text) {
  const ipMatch = text.match(/IP\s*([0-9]{1,3}(?:\.[0-9]{1,3}|\.xxx){3})/i);
  if (!ipMatch) return null;
  const ip = ipMatch[1].trim();

  // 1. Clean Base Username (Line directly after ">")
  let username = null;
  const afterCaretMatch = text.match(/>\s*\n+([^\n\r_]+)/i);
  if (afterCaretMatch) {
    username = afterCaretMatch[1].trim();
  }

  // 2. Clan Tag (Optional): Stored separately
  const clanMatch = text.match(/\[([a-zA-Z0-9_-]{2,6})\]/i);
  const clan = clanMatch ? clanMatch[1].trim() : null;

  // 3. Stats & Hardware
  const lvlMatch = text.match(/LVL\s*(\d+)/i);
  const level = lvlMatch ? parseInt(lvlMatch[1], 10) : null;

  const devMatch = text.match(/DEVICE\s*([^\n]+)/i);
  const device = devMatch ? devMatch[1].trim() : null;

  const netMatch = text.match(/NETWORK\s*([^\n]+)/i);
  const network = netMatch ? netMatch[1].trim() : null;

  const fwMatch = text.match(/FIREWALL\s*Lv\.?(\d+)/i);
  const firewall = fwMatch ? parseInt(fwMatch[1], 10) : null;

  const encMatch = text.match(/ENCRYPTOR\s*Lv\.?(\d+)/i);
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
    uploads: {},
    history: []
  };
}

function mergeTargetRecords(base, incoming) {
  const baseIsMasked = base.ip.includes("xxx");
  const incomingIsMasked = incoming.ip.includes("xxx");
  const canonicalIp = (!incomingIsMasked && baseIsMasked) ? incoming.ip : base.ip;

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
    uploads: { ...(base.uploads || {}), ...(incoming.uploads || {}) },
    history: Array.from(new Set([...(base.history || []), ...(incoming.history || [])]))
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
    let record = existingMap.get(item.ip);
    if (!record) {
      record = initializeRecord(item.ip);
      existingMap.set(item.ip, record);
    }

    if (item.wallet && !record.wallets.includes(item.wallet)) {
      record.wallets.push(item.wallet);
    }

    if (item.software) {
      const targetMap = item.isOwnedSoftware ? record.downloads : record.uploads;
      targetMap[item.software.name] = {
        level: item.software.level,
        status: item.software.action,
        lastSeen: item.time
      };
    }

    if (item.raw && !record.history.includes(item.raw)) {
      record.history.push(item.raw);
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

// Snapshot & Undo
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
        undoBtn.style.background = "#ca8a04";
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
      undoBtn.style.background = "#475569";
    }
    renderFromDB();
  };
}

if (undoBtn) undoBtn.addEventListener("click", restoreSnapshot);

// --- 6. Card UI & Action Helpers ---
function deleteTarget(ip, cardElement) {
  if (!confirm(`Delete target ${ip}?`)) return;
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).delete(ip);
  tx.oncomplete = () => {
    if (cardElement) cardElement.remove();
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
    alert(`Copied report for ${node.ip} to clipboard!`);
  } catch (err) {
    const ta = document.createElement("textarea");
    ta.value = payload;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert(`Copied report for ${node.ip} to clipboard!`);
  }
}

async function editTargetIp(oldIp) {
  const newIpInput = prompt(`Enter new IP address for ${oldIp}:`, oldIp);
  if (!newIpInput) return;

  const validIp = extractIp(newIpInput.trim());
  if (!validIp) {
    alert("Invalid IP format entered.");
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
  // 1. Support both standard (') and curly (’) apostrophes
  const userMatch = text.match(/([a-zA-Z0-9_-]+)['’]s installed software/i);
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

function createCardElement(node) {
  const card = document.createElement("div");
  card.className = "node-card";

  const userTag = node.username ? `<span class="user-tag">${node.username}</span>` : "";
  const lvlTag = node.level ? `<span class="stat-badge" style="background:#1e3a8a; color:#93c5fd;">Lv.${node.level}</span>` : "";
  const fwBadge = node.firewall ? `<span class="stat-badge badge-fw">🛡️ FW: Lv${node.firewall}</span>` : "";
  const encBadge = node.encryptor ? `<span class="stat-badge badge-enc">🔑 ENC: Lv${node.encryptor}</span>` : "";
  const hwTag = node.hardware ? `<span class="hardware-tag">(${node.hardware})</span>` : "";
  const clanBadge = node.clan ? `<span class="stat-badge" style="background:#334155; color:#38bdf8; border: 1px solid #475569;">[${node.clan}]</span>` : "";

  const walletList = node.wallets && node.wallets.length > 0
    ? `<div class="wallet-container">${node.wallets.map((w) => `<span class="wallet-tag">Wallet: ${w}</span>`).join("")}</div>`
    : "";

  const downEntries = Object.entries(node.downloads || {});
  const downTags = downEntries.length > 0
    ? downEntries.map(([name, data]) => `
        <div class="sw-card sw-loot">
          <span>${getSoftwareIcon(name)} ${name}</span>
          <strong>Lv${data.level}</strong>
        </div>
      `).join("")
    : "<span style='color:#475569; font-size:12px; font-style: italic;'>No target inventory known</span>";

  const upEntries = Object.entries(node.uploads || {});
  const upTags = upEntries.length > 0
    ? upEntries.map(([name, data]) => `
        <div class="sw-card sw-upload">
          <span>▲ ${name}</span>
          <strong>Lv${data.level}</strong>
        </div>
      `).join("")
    : "";

  const historyEntries = node.history.map((r) => `<div class="history-entry">${r}</div>`).join("");

  card.innerHTML = `
    <div class="node-meta">
        <span class="ip-title">${node.ip}</span>
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
      ${walletList}
      <div class="software-section-label">Target Software</div>
      <div class="software-grid">${downTags}</div>
      ${upTags ? `
        <div class="software-section-label">Active Deployments</div>
        <div class="software-grid">${upTags}</div>
      ` : ""}
      ${historyEntries ? `<div class="history-list">${historyEntries}</div>` : ""}
    </div>
  `;

  const toggleBtn = card.querySelector(".toggle-btn");
  const bodySection = card.querySelector(".node-body");
  toggleBtn.addEventListener("click", () => {
    const isHidden = bodySection.style.display === "none";
    bodySection.style.display = isHidden ? "block" : "none";
    toggleBtn.textContent = isHidden ? "Hide" : "Expand";
  });

  card.querySelector(".edit-btn").addEventListener("click", () => editTargetIp(node.ip));
  card.querySelector(".share-btn").addEventListener("click", () => shareTarget(node));
  card.querySelector(".del-btn").addEventListener("click", () => deleteTarget(node.ip, card));

  return card;
}

function renderFromDB() {
  if (!db) return;

  const fullContainer = document.getElementById("fullIpContainer");
  const partialContainer = document.getElementById("partialIpContainer");

  fullContainer.innerHTML = "";
  partialContainer.innerHTML = "";

  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const req = store.getAll();

  req.onsuccess = () => {
    const records = req.result || [];
    const fullIps = [];
    const partialIps = [];

    records.forEach((rec) => {
      if (rec.ip.includes("xxx")) partialIps.push(rec);
      else fullIps.push(rec);
    });

    fullIps.sort((a, b) => compareIps(a.ip, b.ip));
    partialIps.sort((a, b) => compareIps(a.ip, b.ip));

    if (fullIps.length === 0) fullContainer.innerHTML = "<p style='color:#475569; font-size:13px;'>No full targets recorded.</p>";
    else fullIps.forEach((n) => fullContainer.appendChild(createCardElement(n)));

    if (partialIps.length === 0) partialContainer.innerHTML = "<p style='color:#475569; font-size:13px;'>No partial targets recorded.</p>";
    else partialIps.forEach((n) => partialContainer.appendChild(createCardElement(n)));
  };
}

// --- 7. Event Handlers ---
document.getElementById("processMyLogsBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  await captureSnapshot();
  const updates = parseMyLogs(text.split("\n"));
  await mergeUpdates(updates);
  document.getElementById("dataInput").value = "";
  await reconcileDatabase();
  renderFromDB();
});

document.getElementById("processVictimLogsBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  await captureSnapshot();
  const updates = parseVictimLogs(text.split("\n"));
  await mergeUpdates(updates);
  document.getElementById("dataInput").value = "";
  await reconcileDatabase();
  renderFromDB();
});

document.getElementById("processHomeBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const parsed = parseHomeScreen(text);
  if (!parsed) {
    alert("Could not identify a valid IP address in this Home Screen dump.");
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
    document.getElementById("dataInput").value = "";
    await reconcileDatabase();
    renderFromDB();
  };
});

document.getElementById("processSoftwareBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const parsed = parseSoftwareScreen(text);
  if (!parsed.username) {
    alert("Could not find username in this Software dump (expected '<Username>'s installed software').");
    return;
  }

  if (Object.keys(parsed.softwareItems).length === 0) {
    alert("Could not detect any software levels in this dump.");
    return;
  }

  await captureSnapshot();

  const allRecords = await new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => resolve(req.result || []);
  });

  // Normalized matching (case-insensitive, trimmed)
  const targetUser = parsed.username.trim().toLowerCase();
  const record = allRecords.find((r) => r.username && r.username.trim().toLowerCase() === targetUser);

  if (!record) {
    alert(`No existing record found for username '${parsed.username}'. Please process their Home Screen first to register their IP.`);
    return;
  }

  // Merge discovered software into target inventory
  for (const [name, data] of Object.entries(parsed.softwareItems)) {
    record.downloads[name] = data;
  }

  const writeTx = db.transaction(STORE_NAME, "readwrite");
  writeTx.objectStore(STORE_NAME).put(record);

  writeTx.oncomplete = () => {
    document.getElementById("dataInput").value = "";
    renderFromDB();
  };
});

document.getElementById("clearBtn").addEventListener("click", () => {
  if (!confirm("Are you sure you want to wipe the entire database?")) return;
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  tx.oncomplete = () => renderFromDB();
});