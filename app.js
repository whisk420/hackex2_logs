// --- 1. IndexedDB Initialization ---
const DB_NAME = "TargetAggregatorMasterDB_v2";
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

dbReq.onerror = (e) => console.error("Database error:", e);

// --- 2. Regex Helpers ---
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

function extractIp(text) {
  const match = text.match(REGEX_IP) || text.match(REGEX_MASKED_IP);
  return match ? match[0] : null;
}

// --- 3. Parsers ---

// A. My Own Logs
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

// B. Victim Logs (Strict Inbound Attacker Profiling)
function parseVictimLogs(rawLines) {
  const updates = [];

  for (let i = rawLines.length - 1; i >= 0; i--) {
    const line = rawLines[i].trim();
    if (!line) continue;

    const timeMatch = line.match(/^\[([^\]]+)\]/);
    const time = timeMatch ? timeMatch[1] : null;

    // Inbound: Uploaded / Downloaded by Attacker
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

    // Inbound: Device accessed from Attacker
    const accessedFromMatch = line.match(/Device accessed from\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))\b/i);
    if (accessedFromMatch) {
      updates.push({ ip: accessedFromMatch[1], time, raw: line });
      continue;
    }

    // Discovery: Outbound Target IP
    const outboundIp = extractIp(line);
    if (outboundIp) {
      updates.push({ ip: outboundIp, time, raw: line });
    }
  }
  return updates;
}

// C. Victim Home Screen
function parseHomeScreen(text) {
  const ipMatch = text.match(/IP\s+((?:(?:\d{1,3}|xxx)\.){3}(?:\d{1,3}|xxx))/i);
  if (!ipMatch) return null;
  const ip = ipMatch[1];

  const userMatch = text.match(/(?:DISCONNECT\s*>\s*|\n)([a-zA-Z0-9_-]+)\s*\n_\s*\n\[SHOW\]/i);
  const username = userMatch ? userMatch[1].trim() : null;

  const lvlMatch = text.match(/badge\s*LVL\s*(\d+)/i);
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
    level,
    hardware: device && network ? `${device} • ${network}` : (device || network || null),
    firewall,
    encryptor
  };
}

// D. Victim Software Screen
function parseSoftwareScreen(text) {
  // Extract user: "Hammie's installed software"
  const userMatch = text.match(/([a-zA-Z0-9_-]+)'s installed software/i);
  const username = userMatch ? userMatch[1].trim() : null;

  // Extract slots: "0 / 2 slots"
  const slotMatch = text.match(/(\d+\s*\/\s*\d+)\s*slots/i);
  const slots = slotMatch ? slotMatch[1] : null;

  // Extract all software items (ignoring relative diff numbers)
  const softwareItems = {};
  const regex = /(?:^|\n)([a-zA-Z\s]+)\n(?:[^\n]+\n)*?LVL\s*(\d+)/gi;
  let match;

  while ((match = regex.exec(text)) !== null) {
    const rawName = match[1].trim();
    const lvl = parseInt(match[2], 10);

    // Normalize software name
    const validNames = [
      "Antivirus", "Spam", "Rootkit", "Firewall", "Bypasser",
      "Password Cracker", "Password Encryptor", "Proxy", "Trace",
      "Siphon", "Keygen"
    ];

    const matchedName = validNames.find((v) => rawName.toLowerCase().includes(v.toLowerCase()));
    if (matchedName) {
      softwareItems[matchedName] = { level: lvl, status: "installed" };
    }
  }

  return { username, slots, softwareItems };
}

// --- 4. Database Ingestion & Mutations ---
async function getRecordByIpOrUser(tx, ip, username) {
  const store = tx.objectStore(STORE_NAME);

  if (ip) {
    const req = store.get(ip);
    const rec = await new Promise((res) => (req.onsuccess = () => res(req.result || null)));
    if (rec) return rec;
  }

  if (username) {
    const all = await new Promise((res) => {
      const req = store.getAll();
      req.onsuccess = () => res(req.result || []);
    });
    const found = all.find((r) => r.username && r.username.toLowerCase() === username.toLowerCase());
    if (found) return found;
  }

  return null;
}

function initializeRecord(ip) {
  return {
    ip: ip,
    username: null,
    level: null,
    hardware: null,
    firewall: null,
    encryptor: null,
    slots: null,
    wallets: [],
    downloads: {}, // Known lootable software
    uploads: {},   // Temporary deployed payloads
    history: []
  };
}

async function mergeUpdates(updates) {
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);

  for (const item of updates) {
    const existing = await new Promise((res) => {
      const req = store.get(item.ip);
      req.onsuccess = () => res(req.result || null);
    });

    const record = existing || initializeRecord(item.ip);

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

    store.put(record);
  }

  return new Promise((res) => (tx.oncomplete = () => res()));
}

// --- 5. Sorting & Rendering ---
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

  // Header components
  const userTag = node.username ? `<span class="user-tag">${node.username}</span>` : "";
  const lvlTag = node.level ? `<span class="stat-badge" style="background:#1e3a8a; color:#93c5fd;">Lv.${node.level}</span>` : "";
  const hwTag = node.hardware ? `<span class="hardware-tag">(${node.hardware})</span>` : "";
  const fwBadge = node.firewall ? `<span class="stat-badge badge-fw">🛡️ FW: Lv${node.firewall}</span>` : "";
  const encBadge = node.encryptor ? `<span class="stat-badge badge-enc">🔑 ENC: Lv${node.encryptor}</span>` : "";
  const slotBadge = node.slots ? `<span class="stat-badge badge-slots">Slots: ${node.slots}</span>` : "";

  // Wallets
  const walletList = node.wallets && node.wallets.length > 0
    ? `<div class="wallet-container">${node.wallets.map((w) => `<span class="wallet-tag">Wallet: ${w}</span>`).join("")}</div>`
    : "";

  // Available Software
  const downEntries = Object.entries(node.downloads || {});
  const downTags = downEntries.length > 0
    ? downEntries.map(([name, data]) => `<span class="tag tag-software">📦 ${name} Lv${data.level}</span>`).join("")
    : "<span style='color:#64748b; font-size:12px;'>None identified</span>";

  // Uploaded Payloads
  const upEntries = Object.entries(node.uploads || {});
  const upTags = upEntries.length > 0
    ? upEntries.map(([name, data]) => `<span class="tag tag-uploaded">▲ ${name} Lv${data.level}</span>`).join("")
    : "";

  // Preserved raw history
  const historyEntries = node.history.map((r) => `<div class="history-entry">${r}</div>`).join("");

  card.innerHTML = `
    <div class="node-header">
      <span class="ip-title">${node.ip}</span>
      ${userTag}
      ${lvlTag}
      ${fwBadge}
      ${encBadge}
      ${slotBadge}
      ${hwTag}
    </div>
    ${walletList}
    <div class="software-container">${downTags}</div>
    ${upTags ? `<div class="software-container">${upTags}</div>` : ""}
    ${historyEntries ? `<div class="history-list">${historyEntries}</div>` : ""}
  `;
  return card;
}

function renderFromDB() {
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

    if (fullIps.length === 0) fullContainer.innerHTML = "<p style='color:#64748b; font-size:13px;'>No full targets recorded.</p>";
    else fullIps.forEach((n) => fullContainer.appendChild(createCardElement(n)));

    if (partialIps.length === 0) partialContainer.innerHTML = "<p style='color:#64748b; font-size:13px;'>No partial targets recorded.</p>";
    else partialIps.forEach((n) => partialContainer.appendChild(createCardElement(n)));
  };
}

// --- 6. Event Handlers ---

// 1. My Logs
document.getElementById("processMyLogsBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const updates = parseMyLogs(text.split("\n"));
  await mergeUpdates(updates);
  document.getElementById("dataInput").value = "";
  renderFromDB();
});

// 2. Victim Logs
document.getElementById("processVictimLogsBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const updates = parseVictimLogs(text.split("\n"));
  await mergeUpdates(updates);
  document.getElementById("dataInput").value = "";
  renderFromDB();
});

// 3. Victim Home Screen
document.getElementById("processHomeBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const parsed = parseHomeScreen(text);
  if (!parsed) {
    alert("Could not identify a valid IP address in this Home Screen dump.");
    return;
  }

  const tx = db.transaction(STORE_NAME, "readwrite");
  const record = (await getRecordByIpOrUser(tx, parsed.ip, parsed.username)) || initializeRecord(parsed.ip);

  record.ip = parsed.ip;
  if (parsed.username) record.username = parsed.username;
  if (parsed.level) record.level = parsed.level;
  if (parsed.hardware) record.hardware = parsed.hardware;
  if (parsed.firewall) {
    record.firewall = parsed.firewall;
    record.downloads["Firewall"] = { level: parsed.firewall, status: "installed" };
  }
  if (parsed.encryptor) {
    record.encryptor = parsed.encryptor;
    record.downloads["Password Encryptor"] = { level: parsed.encryptor, status: "installed" };
  }

  tx.objectStore(STORE_NAME).put(record);
  tx.oncomplete = () => {
    document.getElementById("dataInput").value = "";
    renderFromDB();
  };
});

// 4. Victim Software Screen
document.getElementById("processSoftwareBtn").addEventListener("click", async () => {
  const text = document.getElementById("dataInput").value;
  if (!text.trim()) return;

  const parsed = parseSoftwareScreen(text);
  if (!parsed.username) {
    alert("Could not find the target's username in this Software dump (e.g. '<Username>'s installed software').");
    return;
  }

  const tx = db.transaction(STORE_NAME, "readwrite");
  const record = await getRecordByIpOrUser(tx, null, parsed.username);

  if (!record) {
    alert(`No existing record found for username '${parsed.username}'. Please process their Home Screen or logs first to associate an IP.`);
    return;
  }

  if (parsed.slots) record.slots = parsed.slots;

  // Populate all software (ignoring relative level diff numbers)
  for (const [name, data] of Object.entries(parsed.softwareItems)) {
    record.downloads[name] = data;
  }

  tx.objectStore(STORE_NAME).put(record);
  tx.oncomplete = () => {
    document.getElementById("dataInput").value = "";
    renderFromDB();
  };
});

// Clear DB
document.getElementById("clearBtn").addEventListener("click", () => {
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  tx.oncomplete = () => renderFromDB();
});