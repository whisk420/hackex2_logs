// --- 1. IndexedDB Initialization ---
const DB_NAME = "TargetAggregatorDB";
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

dbReq.onerror = (e) => console.error("Database open failure:", e);

// --- 2. Log Line Parsing & Ingestion Engine ---
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

function parseLine(line) {
  line = line.trim();
  if (!line) return null;

  const timeMatch = line.match(/^\[([^\]]+)\]/);
  const time = timeMatch ? timeMatch[1] : null;

  const ipMatch = line.match(REGEX_IP) || line.match(REGEX_MASKED_IP);
  const explicitIp = ipMatch ? ipMatch[0] : null;

  const isAccessed = line.includes("Accessed device at");

  // Only extract stolen crypto wallets
  let wallet = null;
  if (line.includes("Stole") && line.includes("from hx")) {
    const walletMatch = line.match(/\b(hx[a-zA-Z0-9.]+)\b/);
    if (walletMatch) wallet = walletMatch[1];
  }

  // Extract software
  const softMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+(.+?)(?:\s+(?:from|to)\b|\.\.\.|$)/i);
  let software = null;
  if (softMatch) {
    software = {
      action: softMatch[1].toLowerCase(),
      level: parseInt(softMatch[2], 10),
      name: softMatch[3].trim()
    };
  }

  return { time, explicitIp, isAccessed, wallet, software, raw: line };
}

function associateLogs(rawLines) {
  const parsed = rawLines.map(parseLine).filter(Boolean);

  let currentAccessedIp = null;
  const processedEntries = [];

  // Iterate chronologically (bottom to top)
  for (let i = parsed.length - 1; i >= 0; i--) {
    const entry = parsed[i];

    // Only 'Accessed device at' sets the active machine session
    if (entry.isAccessed && entry.explicitIp) {
      currentAccessedIp = entry.explicitIp;
    }

    // Determine target: prefer the line's own explicit IP, otherwise fallback to the accessed device
    const targetIp = entry.explicitIp || currentAccessedIp;

    if (targetIp) {
      processedEntries.push({
        ip: targetIp,
        time: entry.time,
        // Only assign the stolen wallet if it resolves to the accessed session
        wallet: entry.wallet && targetIp === currentAccessedIp ? entry.wallet : null,
        software: entry.software,
        raw: entry.raw
      });
    }
  }

  return processedEntries;
}

// --- 3. Database Merging Logic ---
// --- Updated DB Merging Logic ---
async function mergeLogs(entries) {
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);

  for (const item of entries) {
    const existing = await new Promise((resolve) => {
      const getReq = store.get(item.ip);
      getReq.onsuccess = () => resolve(getReq.result || null);
    });

    const record = existing || {
      ip: item.ip,
      wallets: [],
      downloads: {}, // Software naturally found on the target
      uploads: {},   // Software deployed to the target (AV-volatile)
      history: []
    };

    // Wallet linking
    if (item.wallet && !record.wallets.includes(item.wallet)) {
      record.wallets.push(item.wallet);
    }

    // Software separation
    if (item.software) {
      const isDownload = item.software.action.startsWith("download");
      const targetMap = isDownload ? record.downloads : record.uploads;

      targetMap[item.software.name] = {
        level: item.software.level,
        status: item.software.action, // 'downloaded', 'uploading', etc.
        lastSeen: item.time
      };
    }

    // Raw log history
    if (!record.history.includes(item.raw)) {
      record.history.push(item.raw);
    }

    store.put(record);
  }

  return new Promise((resolve) => {
    tx.oncomplete = () => resolve();
  });
}

// --- 4. Helpers: Sorting & Rendering ---
function compareIps(ipA, ipB) {
  const octetsA = ipA.split(".");
  const octetsB = ipB.split(".");

  for (let i = 0; i < 4; i++) {
    const valA = octetsA[i] === "xxx" ? -1 : parseInt(octetsA[i], 10);
    const valB = octetsB[i] === "xxx" ? -1 : parseInt(octetsB[i], 10);

    if (valA !== valB) return valA - valB;
  }
  return 0;
}

function createCardElement(node) {
  const card = document.createElement("div");
  card.className = "node-card";

  // Wallets
  const walletList = node.wallets && node.wallets.length > 0
    ? `<div class="wallet-container">${node.wallets.map((w) => `<span class="wallet-tag">Wallet: ${w}</span>`).join("")}</div>`
    : "";

  // 1. Target Native Software (Downloads) - Highlighted in Cyan/Green
  const downloadEntries = Object.entries(node.downloads || {});
  const downloadTags = downloadEntries.length > 0
    ? downloadEntries.map(([name, data]) => 
        `<span class="tag" style="color: #4ade80; border-color: #166534; background: #052e16;">📦 ${name} Lv${data.level}</span>`
      ).join("")
    : "<span style='color:#71717a; font-size:12px;'>None identified</span>";

  // 2. Deployed Software (Uploads) - Muted/Orange to denote temporary status
  const uploadEntries = Object.entries(node.uploads || {});
  const uploadTags = uploadEntries.length > 0
    ? uploadEntries.map(([name, data]) => 
        `<span class="tag" style="color: #fb923c; border-color: #9a3412; background: #271406;">▲ ${name} Lv${data.level} (${data.status})</span>`
      ).join("")
    : "<span style='color:#71717a; font-size:12px;'>None</span>";

  // 3. History Stream
  const historyEntries = node.history
    .map((raw) => `<div class="history-entry">${raw}</div>`)
    .join("");

  card.innerHTML = `
    <div class="node-header">${node.ip}</div>
    ${walletList}
    <div class="node-details" style="margin-bottom: 6px;">
      <div style="font-size: 11px; text-transform: uppercase; color: #a1a1aa; margin-bottom: 3px;">Target Software:</div>
      ${downloadTags}
    </div>
    <div class="node-details">
      <div style="font-size: 11px; text-transform: uppercase; color: #a1a1aa; margin-bottom: 3px;">Uploaded / Active:</div>
      ${uploadTags}
    </div>
    <div class="history-list">
      ${historyEntries}
    </div>
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
  const getAllReq = store.getAll();

  getAllReq.onsuccess = () => {
    const records = getAllReq.result || [];
    const fullIps = [];
    const partialIps = [];

    records.forEach((record) => {
      if (record.ip.includes("xxx")) {
        partialIps.push(record);
      } else {
        fullIps.push(record);
      }
    });

    fullIps.sort((a, b) => compareIps(a.ip, b.ip));
    partialIps.sort((a, b) => compareIps(a.ip, b.ip));

    if (fullIps.length === 0) {
      fullContainer.innerHTML = "<p style='color:#71717a; font-size:14px;'>No full IPs recorded.</p>";
    } else {
      fullIps.forEach((node) => fullContainer.appendChild(createCardElement(node)));
    }

    if (partialIps.length === 0) {
      partialContainer.innerHTML = "<p style='color:#71717a; font-size:14px;'>No partial IPs recorded.</p>";
    } else {
      partialIps.forEach((node) => partialContainer.appendChild(createCardElement(node)));
    }
  };
}

// --- 5. Event Listeners ---
document.getElementById("processBtn").addEventListener("click", async () => {
  const text = document.getElementById("logInput").value;
  if (!text.trim()) return;

  const lines = text.split("\n");
  const entries = associateLogs(lines);

  await mergeLogs(entries);
  document.getElementById("logInput").value = "";
  renderFromDB();
});

document.getElementById("clearBtn").addEventListener("click", () => {
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  tx.oncomplete = () => renderFromDB();
});