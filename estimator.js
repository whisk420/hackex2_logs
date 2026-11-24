// Pure game-math helpers ported from DarkIndex (GameFormulas.kt, TargetRecord.kt, GoodSpamUtils.kt).
// No DOM / DB access here so it can be unit-tested in Node.
(function (root) {
  "use strict";

  // ---------- Hack odds (measured by DarkIndex's author) ----------
  function hackOdds(myLevel, theirLevel) {
    if (myLevel == null || theirLevel == null) return null;
    const d = myLevel - theirLevel;
    if (d >= 6) return 95;
    const table = { 5: 90, 4: 82, 3: 74, 2: 66, 1: 58, 0: 50, "-1": 42, "-2": 34, "-3": 18 };
    return table[d] !== undefined ? table[d] : 5;
  }

  // ---------- Spam income model ----------
  const SPAM_CAP_PER_HOUR = 100;
  const SPAM_MAX_BONUS = 1.475;

  function spamMaxIncome(L) {
    return L <= 0 ? 0 : 13.9 + 4.3 * L + 0.0645 * L * L;
  }
  function spamGapMultiplier(victimLevel, spamLevel) {
    const gap = victimLevel - spamLevel;
    if (gap > 0) return Math.min(1 + 0.04 * gap, SPAM_MAX_BONUS);
    if (gap < 0) return Math.max(1 + 0.05 * gap, 0.10);
    return 1.0;
  }
  // Fresh (undecayed) ₵/hr for a Spam of `spamLevel` on a victim of `victimLevel`.
  function spamIncome(spamLevel, victimLevel) {
    if (spamLevel <= 0 || victimLevel == null) return 0;
    const base = spamMaxIncome(spamLevel) / SPAM_MAX_BONUS;
    return Math.min(Math.round(base * spamGapMultiplier(victimLevel, spamLevel)), SPAM_CAP_PER_HOUR);
  }
  function spamDecayFactor(days, scythe) {
    const d = scythe ? days / 2 : days;
    if (d <= 21) return 1.0;
    return Math.max(0.10, 1 - ((d - 21) * 0.90) / 79);
  }
  // First level (lowest on ties) with the strictly highest income, searching 1..max.
  function spamBestLevel(victimLevel, max) {
    let best = 1, bestInc = -1;
    for (let l = 1; l <= max; l++) {
      const inc = spamIncome(l, victimLevel);
      if (inc > bestInc) { bestInc = inc; best = l; }
    }
    return best;
  }
  // Cheapest Spam level that reaches the $100/hr cap, or null.
  function spamCapLevel(victimLevel, max) {
    for (let l = 1; l <= (max || 60); l++) {
      if (spamIncome(l, victimLevel) >= SPAM_CAP_PER_HOUR) return l;
    }
    return null;
  }
  // installed = the Spam level you own (0 = unknown / don't clamp).
  function spamPlan(victimLevel, installed) {
    installed = installed || 0;
    if (victimLevel == null) return { uploadLevel: 20, income: null, capReachable: false, recommended: 20 };
    const searchTop = Math.max(30, installed);
    const minCap = spamCapLevel(victimLevel, searchTop);
    const recommended = minCap != null ? minCap : spamBestLevel(victimLevel, searchTop);
    const top = installed > 0 ? Math.min(recommended, installed) : recommended;
    const uploadLevel = spamBestLevel(victimLevel, top);
    return { uploadLevel, income: spamIncome(uploadLevel, victimLevel), capReachable: minCap != null, recommended };
  }
  // Seconds to upload this target's Spam plan with your network, or null if their device is unknown.
  function spamUploadSeconds(record, plan, networkBoost) {
    const tier = uploadTier(record.hardware);
    return tier == null ? null : uploadSecondsForLevel(tier, networkBoost || 1, plan.uploadLevel);
  }
  // records -> [{record, plan, uploadSeconds}] ranked like DarkIndex: income (highest first, unknown last),
  // then fastest upload (unknown device last), then lowest Firewall.
  function rankForSpam(records, installed, networkBoost) {
    return records
      .map((record) => {
        const plan = spamPlan(record.level, installed);
        return { record, plan, uploadSeconds: spamUploadSeconds(record, plan, networkBoost) };
      })
      .sort((a, b) => {
        const ai = a.plan.income == null ? -1 : a.plan.income;
        const bi = b.plan.income == null ? -1 : b.plan.income;
        if (bi !== ai) return bi - ai;
        const au = a.uploadSeconds == null ? Infinity : a.uploadSeconds;
        const bu = b.uploadSeconds == null ? Infinity : b.uploadSeconds;
        if (au !== bu) return au - bu;
        return (a.record.firewall || 0) - (b.record.firewall || 0);
      });
  }

  // ---------- Virus upload time ----------
  // Seconds to upload a Lv20 virus on a 1.0x network by victim hardware tier (DarkIndex empirical table).
  const UPLOAD_BASE_SECONDS = [45285, 60390, 75480, 90585, 105720, 120825, 135930, 151035, 166140, 181245];
  function uploadSecondsLv20(tier, networkBoost) {
    const base = UPLOAD_BASE_SECONDS[tier] !== undefined ? UPLOAD_BASE_SECONDS[tier] : 90585;
    return Math.max(1, Math.trunc(base / (networkBoost || 1)));
  }
  function uploadSecondsForLevel(tier, networkBoost, virusLevel) {
    const t20 = uploadSecondsLv20(tier, networkBoost);
    return Math.max(1, Math.trunc(t20 * Math.pow(Math.max(virusLevel, 1) / 20, 2.25)));
  }
  function formatDuration(sec) {
    const m = Math.floor(sec / 60);
    if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`;
    if (m >= 1) return `${m}m ${sec % 60}s`;
    return `${sec}s`;
  }

  // ---------- Siphon ----------
  function siphonPercent(L) {
    return L <= 0 ? null : Math.min(0.75 + 0.25 * L, 6.0);
  }

  // ---------- Wallet income estimator ----------
  // thefts: [{m: minutesSinceEpoch-ish, a: amount}]. Sessions split on gaps > 60 min; sessions longer
  // than 7 days are re-split into fixed 7-day windows. Rate = (sum of amounts except first) / hours.
  function theftClusters(thefts) {
    const ev = (thefts || []).slice().sort((x, y) => x.m - y.m);
    const raw = [];
    let cur = [];
    for (const e of ev) {
      if (cur.length && e.m - cur[cur.length - 1].m > 60) { raw.push(cur); cur = []; }
      cur.push(e);
    }
    if (cur.length) raw.push(cur);

    const WEEK = 7 * 24 * 60;
    const out = [];
    for (const c of raw) {
      if (c[c.length - 1].m - c[0].m <= WEEK) { out.push(c); continue; }
      let win = [], start = null;
      for (const e of c) {
        if (start === null) start = e.m;
        if (e.m - start <= WEEK) win.push(e);
        else { out.push(win); win = [e]; start = e.m; }
      }
      if (win.length) out.push(win);
    }
    return out;
  }
  // -> {perHour:number}|{single:number}|null
  function estimateIncome(thefts) {
    const clusters = theftClusters(thefts);
    if (!clusters.length) return null;
    const rates = [];
    for (const c of clusters) {
      if (c.length < 2) continue;
      const hours = (c[c.length - 1].m - c[0].m) / 60;
      if (hours < 0.1) continue;
      const income = c.slice(1).reduce((s, e) => s + e.a, 0);
      rates.push(income / hours);
    }
    if (rates.length) return { perHour: Math.trunc(rates.reduce((s, r) => s + r, 0) / rates.length) };
    const latest = (thefts || []).reduce((b, e) => (!b || e.m > b.m ? e : b), null);
    return latest ? { single: latest.a } : null;
  }
  function formatAmount(n) {
    return n >= 10000 ? (n / 1000).toFixed(1) + "k" : Math.trunc(n).toLocaleString("en-US");
  }
  function formatIncome(est) {
    if (!est) return null;
    return est.perHour !== undefined ? `₵${formatAmount(est.perHour)}/hr` : `₵${formatAmount(est.single)}`;
  }

  // ---------- Advanced targeting ----------
  // True when a real (unmasked, non-temporary) target is missing data a hacker needs.
  function needsAdvancedTargeting(r) {
    if (!r || !r.ip || r.ip.includes("xxx") || r.ip.startsWith("unknown:")) return false;
    const d = r.downloads || {};
    return !(r.wallets && r.wallets.length) || !d["Bypasser"] || !d["Firewall"] || !d["Password Encryptor"];
  }
  function advancedTargetingMissing(r) {
    const d = r.downloads || {}, out = [];
    if (!(r.wallets && r.wallets.length)) out.push("wallet");
    for (const k of ["Bypasser", "Firewall", "Password Encryptor"]) if (!d[k]) out.push(k);
    return out;
  }

  // ---------- Misc formulas used by the knowledge-base calculators ----------
  function proxyCost(level, hours, discount) {
    return Math.ceil(10 * Math.sqrt(level) * hours * (1 - (discount || 0)));
  }
  function avRemovalPercent(av, virus) {
    const d = av - virus;
    if (d >= 5) return 95;
    if (d >= 0) return 50 + 10 * d;
    if (d === -1) return 20;
    return Math.max(5, 20 - 2 * (-d - 1));
  }
  function keygenCubic(L) { return (-L * L * L + 147 * L * L + 6814 * L - 10212) / 6; }
  function storePrice(base, level, defensive) {
    const raw = Math.max(0, keygenCubic(level)) * base / 600 * (defensive ? 0.85 : 1);
    return defensive ? Math.ceil(raw) : Math.round(raw);
  }

  // ---------- Hardware (DarkIndex HardwareCatalog / GameFormulas) ----------
  const DEVICES = ["Raider", "Raider II", "Raider III", "Bolt", "Bolt II", "Bolt III", "Nova", "Nova II", "Nova III", "Nova S", "Nova X", "Nova Ultra"];
  const DEVICE_SPEED = [1.0, 1.5, 2.25, 3.5, 5.0, 7.0, 9.0, 11.0, 14.0, 17.0, 20.0, 23.0];
  const DEVICE_PRICES = [0, 4000, 10000, 18000, 28000, 40000, 56000, 82000, 120000, 160000, 220000, 300000];
  const NETWORKS = ["DSL", "Cable", "Cable+", "4G LTE", "5G", "5G+", "Fiber", "Fiber+", "10G Fiber", "10G Fiber+", "Quantum Link"];
  const NETWORK_BOOST = [1.0, 1.5, 2.25, 3.5, 5.0, 7.0, 9.5, 12.0, 15.0, 18.0, 21.0];
  const NETWORK_PRICES = [0, 3000, 7000, 12000, 20000, 30000, 44000, 60000, 85000, 120000, 170000];
  // Upload difficulty tier 0–9: Raider I–III are all tier 0, then one tier per device level.
  function uploadTierForDeviceIndex(i) { return Math.max(0, i - 2); }

  // Reboot (prestige) hardware: "<Line> <Roman numeral>", same speed as the standard item at that level.
  // A bare line name ("Vector") counts as I. (DarkIndex HardwareCatalog)
  const REBOOT_DEVICES = ["Ghost", "Vector", "Scythe", "Cipher", "Apex"];
  const REBOOT_NETWORKS = ["Ghost Link", "Contra Band", "Harvest Node", "Void Net", "Null Route"];
  const ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"];

  // Level (1-based) of a device or network name, or null if unknown.
  function hardwareLevel(name, standard, lines) {
    const n = String(name || "").trim().replace(/\s+/g, " ").toLowerCase();
    if (!n) return null;
    const std = standard.findIndex((x) => x.toLowerCase() === n || (x === "4G LTE" && n === "4g"));
    if (std >= 0) return std + 1;
    for (const line of lines) {
      const l = line.toLowerCase();
      if (n === l) return 1;
      if (n.startsWith(l + " ")) {
        const lvl = ROMAN.indexOf(n.slice(l.length + 1).trim().toUpperCase()) + 1;
        if (lvl >= 1 && lvl <= standard.length) return lvl;
      }
    }
    return null;
  }
  // A target's hardware is stored as "<Device> • <Network>" (or just one of them).
  function deviceLevel(hardware) {
    return hardwareLevel(String(hardware || "").split("•")[0], DEVICES, REBOOT_DEVICES);
  }
  function networkLevel(name) {
    const s = String(name || "");
    return hardwareLevel(s.includes("•") ? s.split("•")[1] : s, NETWORKS, REBOOT_NETWORKS);
  }
  // Upload tier 0–9 for a target's hardware string, or null if the device is unknown.
  function uploadTier(hardware) {
    const lvl = deviceLevel(hardware);
    return lvl == null ? null : uploadTierForDeviceIndex(lvl - 1);
  }

  // ---------- Reputation & score ----------
  function score(level, rep) { return Math.floor(level * Math.pow(Math.max(0, rep), 0.75)); }
  function repLossFromVirus(virusLevel) { return Math.min(500, 25 * virusLevel); }
  function hardeningBlock(level) { return Math.max(0, Math.min(90, 3 * (level - 2))); }

  const api = {
    DEVICES, DEVICE_SPEED, DEVICE_PRICES, NETWORKS, NETWORK_BOOST, NETWORK_PRICES, uploadTierForDeviceIndex,
    REBOOT_DEVICES, REBOOT_NETWORKS, hardwareLevel, deviceLevel, networkLevel, uploadTier, spamUploadSeconds,
    score, repLossFromVirus, hardeningBlock,
    hackOdds, SPAM_CAP_PER_HOUR, spamMaxIncome, spamGapMultiplier, spamIncome, spamDecayFactor,
    spamBestLevel, spamCapLevel, spamPlan, rankForSpam,
    UPLOAD_BASE_SECONDS, uploadSecondsLv20, uploadSecondsForLevel, formatDuration,
    siphonPercent, theftClusters, estimateIncome, formatAmount, formatIncome,
    needsAdvancedTargeting, advancedTargetingMissing,
    proxyCost, avRemovalPercent, keygenCubic, storePrice
  };
  root.Estimator = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
