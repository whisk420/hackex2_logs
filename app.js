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

// --- 2. Log Line Parsing Engine ---
const REGEX_IP = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
const REGEX_MASKED_IP = /\b(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\.(?:\d{1,3}|xxx)\b/;

function parseLine(line) {
  line = line.trim();
  if (!line) return null;

  // Extract timestamp: [9-4 20:14]
  const timeMatch = line.match(/^\[([^\]]+)\]/);
  const time = timeMatch ? timeMatch[1] : null;

  // Extract IP (standard or masked)
  const ipMatch = line.match(REGEX_IP) || line.match(REGEX_MASKED_IP);
  if (!ipMatch) return null; // Skip lines without an IP for now (e.g. pure wallet transfers)
  const ip = ipMatch[0];

  // Detect Software interactions: Uploaded/Downloaded/Uploading/Downloading Lv[X] [Name]
  const softMatch = line.match(/(Downloaded|Uploaded|Downloading|Uploading)\s+Lv(\d+)\s+([^.from|to]+?)(?:\s+(?:to|from|\.\.\.|$))/i);
  let software = null;
  if (softMatch) {
    software = {
      action: softMatch[1].toLowerCase(),
      level: parseInt(softMatch[2], 10),
      name: softMatch[3].trim()
    };
  }

  // Detect Security status
  const cracked = line.includes("Cracked password on");
  const bypassed = line.includes("Bypassed firewall on");

  return { time, ip, software, cracked, bypassed, raw: line };
}

// --- 3. Database Merging Logic ---
async function mergeLogs(parsedLines) {
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);

  for (const item of parsedLines) {
    if (!item) continue;

    const existing = await new Promise((resolve) => {
      const getReq = store.get(item.ip);
      getReq.onsuccess = () => resolve(getReq.result || null);
    });

    const record = existing || {
      ip: item.ip,
      firstSeen: item.time,
      lastSeen: item.time,
      software: {},
      status: { cracked: false, bypassed: false },
      history: []
    };

    record.lastSeen = item.time || record.lastSeen;

    if (item.cracked) record.status.cracked = true;
    if (item.bypassed) record.status.bypassed = true;

    if (item.software) {
      record.software[item.software.name] = {
        level: item.software.level,
        action: item.software.action
      };
    }

    if (!record.history.includes(item.raw)) {
      record.history.push(item.raw);
    }

    store.put(record);
  }

  return new Promise((resolve) => {
    tx.oncomplete = () => resolve();
  });
}

// --- 4. Render Interface ---
function renderFromDB() {
  const container = document.getElementById("outputContainer");
  container.innerHTML = "";

  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const cursorReq = store.openCursor();

  cursorReq.onsuccess = (e) => {
    const cursor = e.target.result;
    if (cursor) {
      const node = cursor.value;
      const card = document.createElement("div");
      card.className = "node-card";

      // Render tags for software
      const softTags = Object.entries(node.software)
        .map(([name, data]) => `<span class="tag">${name} Lv${data.level} (${data.action})</span>`)
        .join("");

      // Render tags for security status
      const secTags = [
        node.status.cracked ? `<span class="tag" style="color:#4ade80">Password Cracked</span>` : "",
        node.status.bypassed ? `<span class="tag" style="color:#4ade80">Firewall Bypassed</span>` : ""
      ].join("");

      card.innerHTML = `
        <div class="node-header">${node.ip}</div>
        <div class="node-details">
          ${softTags || "<span style='color:#71717a'>No software noted</span>"}
          ${secTags}
        </div>
      `;
      container.appendChild(card);
      cursor.continue();
    }
  };
}

// --- 5. Event Listeners ---
document.getElementById("processBtn").addEventListener("click", async () => {
  const text = document.getElementById("logInput").value;
  if (!text.trim()) return;

  const lines = text.split("\n");
  const parsed = lines.map(parseLine).filter(Boolean);

  await mergeLogs(parsed);
  document.getElementById("logInput").value = "";
  renderFromDB();
});

document.getElementById("clearBtn").addEventListener("click", () => {
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  tx.oncomplete = () => renderFromDB();
});