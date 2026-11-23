// Knowledge Base: reference topics + calculators ported from DarkIndex (KnowledgeBase*.kt, GameFormulas.kt).
// Rendering is plain DOM, wired once on load. Depends on estimator.js (window.Estimator).
(function () {
  "use strict";
  const E = window.Estimator;

  // Source labels, as used by DarkIndex.
  const SOURCES = {
    measured:   { label: "Measured",   color: "#22c55e", tip: "Measured in-game / verified to the crypto" },
    calculated: { label: "Calculated", color: "#38bdf8", tip: "Formula that reproduces every published or measured number" },
    guide:      { label: "Guide",      color: "#fbbf24", tip: "Stated by the hackex.net guide, not yet checked in-game" },
    confirmed:  { label: "Confirmed",  color: "#a3e635", tip: "Confirmed in-game from play" },
    empirical:  { label: "Empirical",  color: "#fb923c", tip: "Older data, not re-verified" },
    unknown:    { label: "Unknown",    color: "#94a3b8", tip: "Still open / not measured" }
  };

  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
  const fmt = (n) => Math.round(n).toLocaleString("en-US");

  // ---------------- Topics ----------------
  // item: { text, source } | { table: {head, rows}, source, text? } | { list: [...], source }
  const TOPICS = [
    {
      id: "spam", title: "📧 Spam", items: [
        { text: "Spam earns passive crypto per hour from a victim, capped at ₵100/hr per Spam.", source: "measured" },
        { text: "Max income at level L: 13.9 + 4.3·L + 0.0645·L². Base income = max ÷ 1.475.", source: "calculated" },
        { text: "Level gap (victim − Spam): if positive, ×(1 + 0.04·gap) up to ×1.475; if negative, ×(1 + 0.05·gap) down to ×0.10.", source: "calculated" },
        { text: "Decay: full income through day 21, then a linear drop to a 10% floor at day 100. Scythe halves the effective days.", source: "calculated" },
        { table: { head: ["Spam Lv", "Same-level ₵/hr", "Max ₵/hr (+12 victim)"],
                   rows: [1, 5, 10, 15, 16, 17, 20, 25, 30].map((l) => [l, E.spamIncome(l, l), E.spamIncome(l, l + 12)]) },
          source: "calculated" },
        { table: { head: ["Day", "Income kept"],
                   rows: [0, 21, 30, 50, 70, 100].map((d) => [d, Math.round(E.spamDecayFactor(d) * 100) + "%"]) },
          source: "calculated" },
        { text: "Good Spam: rank targets by ₵/hr (highest first), then lowest Firewall. Upload the cheapest Spam level that hits the ₵100/hr cap.", source: "calculated" }
      ]
    },
    {
      id: "botnet", title: "🕸️ Botnet", items: [
        { text: "Fee = 0.5% × (active Spam − 2), max 30%. Hacker pass −25%, Elite pass −50% of the fee.", source: "calculated" },
        { table: { head: ["Tier", "Slots", "Cost"],
                   rows: [["Free", 2, "free"], ["Node", 4, "800 (Lv3)"], ["Cluster", 8, "3,500"], ["Grid", 16, "15,000"],
                          ["Farm", 28, "42,000"], ["Hive", 44, "95,000"], ["Nexus", 64, "180,000"]] },
          source: "guide" }
      ]
    },
    {
      id: "siphon", title: "🩸 Siphon", items: [
        { text: "Siphon takes a percentage of the victim's income: min(0.75 + 0.25·L, 6%).", source: "calculated" },
        { table: { head: ["Siphon Lv", "% taken"], rows: [1, 2, 5, 6, 13, 17, 20, 25].map((l) => [l, E.siphonPercent(l) + "%"]) },
          source: "measured" },
        { text: "DarkIndex flags a siphon that vanishes from your earnings list, unless it had run over 24h and earned under ₵1,000 (a bad install). An amount that drops means someone reinstalled it.", source: "confirmed" }
      ]
    },
    {
      id: "hacking", title: "🚪 Hacking odds", items: [
        { text: "Bypass odds use your Bypasser vs their Firewall. Crack odds use your Password Cracker vs their Password Encryptor.", source: "measured" },
        { table: { head: ["Your lvl − theirs", "Success"],
                   rows: [6, 5, 4, 3, 2, 1, 0, -1, -2, -3, -4].map((d) => [d >= 6 ? "+6 or more" : d <= -4 ? "−4 or less" : (d > 0 ? "+" + d : d), E.hackOdds(d, 0) + "%"]) },
          source: "measured" },
        { text: "Hack rep scales with level gap: full up to a gap of 5, zero at 10+, linear (10 − gap)/5 in between.", source: "calculated" },
        { text: "Hardening block chance: min(90%, 3% × (level − 2)).", source: "calculated" }
      ]
    },
    {
      id: "rootkit", title: "🪱 Rootkit", items: [
        { table: { head: ["Rootkit Lv", "Debuff to victim defence"], rows: [["1–2", "−1"], ["3–5", "−2 (Lv4–5 inferred)"], ["6+", "−3 (cap)"]] },
          source: "measured" }
      ]
    },
    {
      id: "virus", title: "☣️ Virus rules & reputation", items: [
        { text: "Virus rep loss for the victim: min(500, 25 × virus level). Daily loss cap 500; rep floor is 50% of your peak.", source: "guide" },
        { text: "Defence rep: 15 + ceil(attacker software level / 5).", source: "calculated" },
        { text: "Trace detection rep: 15 + (level − 1), clamped to 15–25.", source: "calculated" },
        { text: "Score = floor(Level × Rep^0.75).", source: "calculated" }
      ]
    },
    {
      id: "upload", title: "⏫ Upload times", items: [
        { text: "A Lv20 virus on a 1.0× network takes the base time below, by victim device tier. Divide by your network boost.", source: "empirical" },
        { table: { head: ["Device tier", "Lv20 upload @1.0×"], rows: E.UPLOAD_BASE_SECONDS.map((s, i) => [i, E.formatDuration(s)]) },
          source: "empirical" },
        { text: "Other levels: time(Lv20) × (level / 20)^2.25. Harvest Node halves it. Pooled processes: ×(1 + 0.75·(n − 1)).", source: "calculated" }
      ]
    },
    {
      id: "antivirus", title: "💉 Antivirus", items: [
        { text: "Removal chance per scan, d = AV − virus: d ≥ 5 → 95%, d ≥ 0 → 50 + 10d %, d = −1 → 20%, lower → max(5, 20 − 2(−d − 1))%.", source: "calculated" },
        { table: { head: ["Device lvl", "Scan minutes"], rows: [[1, 180], [3, 120], [5, 90], [8, 63], [10, 53], ["12+", 45]] },
          source: "measured" },
        { text: "Running n scans together: ×(1 + 0.75·(n − 1)). Ads cut 10/9/8/7% (max 4). Overclock skips 90s.", source: "guide" }
      ]
    },
    {
      id: "proxy", title: "🎭 Proxy", items: [
        { table: { head: ["Proxy Lv", "Octets masked"], rows: [["1–5", 1], ["6–10", 2], ["11–15", 3], ["16+", 4], ["20", "Stealth"]] }, source: "guide" },
        { text: "Activation cost = ceil(10 × √level × hours × (1 − discount)). Discounts: 2h 0%, 6h 5%, 12h 10%, 24h 15%.", source: "calculated" }
      ]
    },
    {
      id: "store", title: "⚙️ Store & Keygen", items: [
        { text: "Store price at level L = (−L³ + 147L² + 6814L − 10212)/6 × base/600, ×0.85 for defensive apps (rounded up). Offensive apps round to nearest. The fit is meant for mid/high levels and goes negative at Lv1–2.", source: "calculated" },
        { table: { head: ["App", "Base", "Type"],
                   rows: [["Firewall", 800, "def"], ["Bypasser", 800, "off"], ["Password Cracker", 1100, "off"], ["Password Encryptor", 1100, "def"],
                          ["Antivirus", 1000, "def"], ["Spam", 1800, "off"], ["Siphon", 1600, "off"], ["Rootkit", 1400, "off"],
                          ["Proxy", 900, "def"], ["Trace", 900, "def"], ["Keygen", 600, "off"]] },
          source: "calculated" },
        { text: "Keygen fee ratio = min(50%, 15% + (jump − 1) × 35%/19) of the target level's store price.", source: "calculated" },
        { text: "Software XP ≈ 0.1717 × crypto spent.", source: "calculated" }
      ]
    },
    {
      id: "hardware", title: "🖥️ Devices & network", items: [
        { table: { head: ["Device speed", "Price"],
                   rows: [["1.0× (Raider)", "free"], ["1.5×", "4,000"], ["2.25×", "10,000"], ["3.5×", "18,000"], ["5.0×", "28,000"], ["7.0×", "40,000"],
                          ["9.0×", "56,000"], ["11.0×", "82,000"], ["14.0×", "120,000"], ["17.0×", "160,000"], ["20.0×", "220,000"], ["23.0×", "300,000"]] },
          source: "guide" },
        { text: "Network prices by tier: 0, 3,000, 7,000, 12,000, 20,000, 30,000, 44,000, 60,000, 85,000, 120,000, 170,000.", source: "guide" }
      ]
    },
    {
      id: "wallet", title: "👛 Wallet & leveling", items: [
        { text: "Crypto → Credits: 250 crypto per Credit.", source: "guide" },
        { table: { head: ["Level", "XP to next", "Cold storage cap"],
                   rows: [[1, "589", "3,000"], [5, "2,605", "8,841"], [10, "5,919", "29,124"], [20, "14,209", "121,891"], [30, "24,079", "294,147"],
                          [35, "29,484", "—"], [38, "32,860", "—"], [44, "39,888", "—"]] },
          source: "measured" },
        { text: "Income estimate on cards: thefts from a wallet are grouped into sessions (a gap over 1 hour starts a new one). Rate = crypto after the first theft ÷ session hours, averaged over sessions. With only single thefts, the last amount is shown instead.", source: "calculated" }
      ]
    },
    {
      id: "daily", title: "📅 Daily missions", items: [
        { table: { head: ["Mission", "XP", "Rep", "Crypto", "OC", "Spawn"],
                   rows: [["Easy", 100, 30, 250, 3, "80%"], ["Medium", 150, 55, 500, 7, "50%"], ["Hard", 200, 90, "1,000", 15, "20%"]] },
          source: "guide" }
      ]
    },
    {
      id: "consumables", title: "🧪 Consumables", items: [
        { table: { head: ["Item", "Credits"],
                   rows: [["Log Lock", 12], ["Backdoor", 40], ["Exploit Kit", 50], ["EMP Pulse", 80], ["System Purge", 85], ["Wallet Shield", 150], ["IP Scrambler", 200]] },
          source: "guide" }
      ]
    },
    {
      id: "crews", title: "👥 Crews", items: [
        { text: "Crew part upgrade to level k costs base × k². Bases: CPU 70,000, NIC 70,000, RAM 120,000, Uplink 45,000, Storage 60,000.", source: "calculated" },
        { text: "Upkeep/day = base × L(L+1)(2L+1)/6 / 200 (Storage has none).", source: "calculated" },
        { text: "Surge = (next two levels' prices) × hours / 1200, −5% for 12h or −10% for 24h. Not available for RAM or Storage.", source: "calculated" }
      ]
    },
    {
      id: "console", title: "🔎 Using this console", items: [
        { list: [
            "Paste victim logs, a victim Home screen, or a victim Software screen, then press Process Data.",
            "Filter: Firewall Lv.10 · Bypasser 9 · 27.61.93.149 (space = AND, | = OR).",
            "Shortcuts: lvl 30 / lvl 28-32 (player level), sw 20 (any loot app at exactly Lv20).",
            "Aliases search ±2 levels: fw 12, enc 10, av 8, bp 9, pc 9, rk 5. Full names are exact: Spam 17, Firewall Lv.12.",
            "Prefixes: user:, clan:, wallet:, hw:. Any other word matches username, clan, wallet, hardware, IP or app.",
            "Advanced Targeting shows only real targets missing a wallet, Bypasser, Firewall or Password Encryptor.",
            "Sort by Good Spam to rank by Spam ₵/hr using your Spam level from ⚙ My Stats."
          ], source: "confirmed" }
      ]
    }
  ];

  // ---------------- Calculators ----------------
  // field: [id, label, default, {type:"check"|"select", options}]
  const CALCS = [
    {
      id: "spam", title: "Spam income",
      fields: [["spamLv", "Spam level", 17], ["victimLv", "Victim level", 20], ["days", "Days since upload", 0], ["scythe", "Scythe", false, { type: "check" }]],
      run: (v) => {
        const fresh = E.spamIncome(v.spamLv, v.victimLv);
        const decay = E.spamDecayFactor(v.days, v.scythe);
        const gap = v.victimLv - v.spamLv;
        const cap = E.spamCapLevel(v.victimLv, 60);
        return [
          `Gap ${gap >= 0 ? "+" : ""}${gap} → ×${E.spamGapMultiplier(v.victimLv, v.spamLv).toFixed(2)}`,
          `Fresh: ₵${fresh}/hr (₵${fmt(fresh * 24)}/day)`,
          `After ${v.days}d: ₵${Math.round(fresh * decay)}/hr (${Math.round(decay * 100)}%)`,
          cap ? `Cheapest Spam that caps on this victim: Lv${cap}` : "₵100/hr cap not reachable on this victim (≤ Lv60)"
        ];
      }
    },
    {
      id: "odds", title: "Bypass / crack odds",
      fields: [["mine", "Your Bypasser / Cracker", 10], ["theirs", "Their Firewall / Encryptor", 10], ["rootkit", "Rootkit level on them", 0],
               ["apex", "Apex (+3 you)", false, { type: "check" }], ["cipher", "Cipher (+3 them)", false, { type: "check" }]],
      run: (v) => {
        const debuff = v.rootkit >= 6 ? 3 : v.rootkit >= 3 ? 2 : v.rootkit >= 1 ? 1 : 0;
        const me = v.mine + (v.apex ? 3 : 0);
        const them = Math.max(0, v.theirs - debuff + (v.cipher ? 3 : 0));
        return [`Effective: you ${me} vs them ${them}`, `Success: ${E.hackOdds(me, them)}%`];
      }
    },
    {
      id: "upload", title: "Virus upload time",
      fields: [["virusLv", "Virus level", 20], ["tier", "Victim device tier (0–9)", 3], ["boost", "Your network boost (×)", 1],
               ["procs", "Processes in pool", 1], ["harvest", "Harvest Node", false, { type: "check" }]],
      run: (v) => {
        let s = E.uploadSecondsForLevel(v.tier, v.boost, v.virusLv) * (v.harvest ? 0.5 : 1);
        const pooled = s * (1 + 0.75 * (Math.max(1, v.procs) - 1));
        return [`Solo: ${E.formatDuration(Math.round(s))}`, v.procs > 1 ? `With ${v.procs} in pool: ${E.formatDuration(Math.round(pooled))}` : null];
      }
    },
    {
      id: "av", title: "Antivirus removal",
      fields: [["av", "AV level", 10], ["virus", "Virus level", 10], ["harvest", "Attacker on Harvest Node (+2)", false, { type: "check" }], ["scans", "Scans", 1]],
      run: (v) => {
        const p = E.avRemovalPercent(v.av, v.virus + (v.harvest ? 2 : 0)) / 100;
        return [`Per scan: ${Math.round(p * 100)}%`, `After ${v.scans} scans: ${Math.round((1 - Math.pow(1 - p, Math.max(1, v.scans))) * 100)}%`];
      }
    },
    {
      id: "proxy", title: "Proxy cost",
      fields: [["lvl", "Proxy level", 10], ["hours", "Duration", 6, { type: "select", options: [2, 6, 12, 24] }]],
      run: (v) => {
        const disc = { 2: 0, 6: 0.05, 12: 0.10, 24: 0.15 }[v.hours] || 0;
        const octets = v.lvl >= 16 ? 4 : v.lvl >= 11 ? 3 : v.lvl >= 6 ? 2 : 1;
        return [`Cost: ${fmt(E.proxyCost(v.lvl, v.hours, disc))} crypto`, `Masks ${octets} octet${octets > 1 ? "s" : ""}${v.lvl >= 20 ? " + Stealth" : ""}`];
      }
    },
    {
      id: "store", title: "Store price",
      fields: [["app", "Software", "Spam", { type: "select", options: ["Firewall", "Bypasser", "Password Cracker", "Password Encryptor", "Antivirus", "Spam", "Siphon", "Rootkit", "Proxy", "Trace", "Keygen"] }],
               ["lvl", "Level", 20]],
      run: (v) => {
        const BASE = { Firewall: [800, 1], Bypasser: [800, 0], "Password Cracker": [1100, 0], "Password Encryptor": [1100, 1], Antivirus: [1000, 1],
                       Spam: [1800, 0], Siphon: [1600, 0], Rootkit: [1400, 0], Proxy: [900, 1], Trace: [900, 1], Keygen: [600, 0] };
        const [base, def] = BASE[v.app];
        const price = E.storePrice(base, v.lvl, !!def);
        return [`Lv${v.lvl} ${v.app}: ${fmt(price)} crypto`, `≈ ${fmt(price * 0.1717)} software XP`, v.lvl < 3 ? "Formula is unreliable below Lv3" : null];
      }
    },
    {
      id: "siphon", title: "Siphon take",
      fields: [["lvl", "Siphon level", 10], ["income", "Victim income ₵/hr", 500]],
      run: (v) => {
        const pct = E.siphonPercent(v.lvl);
        return pct == null ? ["Level must be ≥ 1"] : [`${pct}% → ₵${(v.income * pct / 100).toFixed(1)}/hr`];
      }
    }
  ];

  // ---------------- Rendering ----------------
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function badge(src) {
    const s = SOURCES[src] || SOURCES.unknown;
    return `<span class="kb-src" style="color:${s.color};border-color:${s.color}" title="${esc(s.tip)}">${s.label}</span>`;
  }
  function itemText(it) {
    const parts = [it.text || ""];
    if (it.list) parts.push(...it.list);
    if (it.table) parts.push(it.table.head.join(" "), ...it.table.rows.map((r) => r.join(" ")));
    return parts.join(" ").toLowerCase();
  }
  function renderItem(it) {
    let body = "";
    if (it.text) body += `<p>${esc(it.text)}</p>`;
    if (it.list) body += `<ul>${it.list.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
    if (it.table) {
      body += `<div class="kb-table-wrap"><table class="kb-table"><thead><tr>${it.table.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>` +
        `<tbody>${it.table.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    }
    return `<div class="kb-item">${badge(it.source)}${body}</div>`;
  }

  function renderTopics(query) {
    const q = (query || "").trim().toLowerCase();
    const host = document.getElementById("kbTopics");
    let shown = 0;
    host.innerHTML = TOPICS.map((t) => {
      const items = q ? t.items.filter((it) => t.title.toLowerCase().includes(q) || itemText(it).includes(q)) : t.items;
      if (!items.length) return "";
      shown++;
      return `<details class="kb-topic"${q ? " open" : ""}><summary>${esc(t.title)}</summary>${items.map(renderItem).join("")}</details>`;
    }).join("");
    if (!shown) host.innerHTML = `<p class="kb-empty">Nothing matches “${esc(query)}”.</p>`;
  }

  function renderCalculators() {
    const host = document.getElementById("kbCalcs");
    host.innerHTML = CALCS.map((c) => {
      const inputs = c.fields.map(([id, label, def, opt]) => {
        const name = `${c.id}-${id}`;
        if (opt && opt.type === "check") {
          return `<label class="kb-check"><input type="checkbox" data-f="${id}" ${def ? "checked" : ""}> ${esc(label)}</label>`;
        }
        if (opt && opt.type === "select") {
          return `<label>${esc(label)}<select data-f="${id}" id="${name}">${opt.options.map((o) => `<option${o === def ? " selected" : ""}>${esc(o)}</option>`).join("")}</select></label>`;
        }
        return `<label>${esc(label)}<input type="number" inputmode="decimal" step="any" data-f="${id}" id="${name}" value="${def}"></label>`;
      }).join("");
      return `<details class="kb-calc" data-calc="${c.id}"><summary>🧮 ${esc(c.title)}</summary><div class="kb-calc-fields">${inputs}</div><div class="kb-calc-out"></div></details>`;
    }).join("");

    host.querySelectorAll(".kb-calc").forEach((el) => {
      const calc = CALCS.find((c) => c.id === el.dataset.calc);
      const update = () => {
        const v = {};
        el.querySelectorAll("[data-f]").forEach((inp) => {
          const field = calc.fields.find((f) => f[0] === inp.dataset.f);
          if (inp.type === "checkbox") v[inp.dataset.f] = inp.checked;
          else if (inp.tagName === "SELECT") v[inp.dataset.f] = typeof field[2] === "number" ? Number(inp.value) : inp.value;
          else v[inp.dataset.f] = Number(inp.value) || 0;
        });
        let lines;
        try { lines = calc.run(v).filter(Boolean); } catch (err) { lines = ["Error: " + err.message]; }
        el.querySelector(".kb-calc-out").innerHTML = lines.map((l) => `<div>${esc(l)}</div>`).join("");
      };
      el.addEventListener("input", update);
      el.addEventListener("change", update);
      update();
    });
  }

  function init() {
    const panel = document.getElementById("kbPanel");
    const btn = document.getElementById("kbToggleBtn");
    if (!panel || !btn) return;
    renderCalculators();
    renderTopics("");
    btn.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      btn.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) panel.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    document.getElementById("kbCloseBtn").addEventListener("click", () => { panel.hidden = true; btn.setAttribute("aria-expanded", "false"); });
    document.getElementById("kbSearch").addEventListener("input", (e) => renderTopics(e.target.value));
  }

  window.KnowledgeBase = { TOPICS, CALCS, SOURCES };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
