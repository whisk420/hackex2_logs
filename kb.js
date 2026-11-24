// Knowledge Base: reference topics + calculators ported from DarkIndex (KnowledgeBase*.kt, GameFormulas.kt).
// Rendering is plain DOM, wired once on load. Depends on estimator.js (window.Estimator).
(function () {
  "use strict";
  const E = window.Estimator;

  // Source labels. Each entry uses the same label as DarkIndex's own in-app Knowledge Base
  // (KnowledgeBaseContent.kt); "app" marks how this website itself behaves.
  const SOURCES = {
    measured:   { label: "Measured",   color: "#22c55e", tip: "Measured in-game by the DarkIndex developer" },
    calculated: { label: "Calculated", color: "#38bdf8", tip: "Worked out from a formula that reproduces the measured or guide numbers" },
    guide:      { label: "Guide",      color: "#fbbf24", tip: "From the official hackex.net guide, not yet checked in-game" },
    confirmed:  { label: "Confirmed",  color: "#a3e635", tip: "Confirmed in-game by the DarkIndex developer" },
    empirical:  { label: "Empirical",  color: "#fb923c", tip: "Older measurement, not re-checked since" },
    unknown:    { label: "Unknown",    color: "#94a3b8", tip: "Not measured yet" },
    app:        { label: "This app",   color: "#c084fc", tip: "How this website behaves" }
  };

  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
  const fmt = (n) => Math.round(n).toLocaleString("en-US");
  const pct = (n) => `${n}%`;
  const STORE_APPS = {
    Firewall: [800, 1], Bypasser: [800, 0], "Password Cracker": [1100, 0], "Password Encryptor": [1100, 1], Antivirus: [1000, 1],
    Spam: [1800, 0], Siphon: [1600, 0], Rootkit: [1400, 0], Proxy: [900, 1], Trace: [900, 1], Keygen: [600, 0]
  };
const SHOT = (name, alt, caption) => ({ src: `docs/kb/${name}.webp`, alt, caption });
  const CREW_PARTS = [["CPU", 70000], ["NIC", 70000], ["RAM", 120000], ["Uplink", 45000], ["Storage", 60000]];
  const compact = (v) => (v >= 1e6 ? +(v / 1e6).toFixed(2) + "M" : v >= 1e3 ? +(v / 1e3).toFixed(1) + "K" : String(v));
  const rootkitDebuff = (lvl) => (lvl >= 6 ? 3 : lvl >= 3 ? 2 : lvl >= 1 ? 1 : 0);
  const keyFee = (jump) => Math.min(0.5, 0.15 + (jump - 1) * 0.35 / 19);

  // ---------------- Topics ----------------
  // item: { text, source } | { table: {head, rows, caption?}, source } | { list: [...], source } | { tip } | { warn }
  const TOPICS = [
    {
      id: "hacking", title: "🔓 Hacking: bypass & crack", items: [
        { list: [
            "Bypass their Firewall with your Bypasser. That alone lets you open the device, download software and upload viruses.",
            "Crack their Password Encryptor with your Password Cracker. That's only needed to get into their hot wallet.",
            "Then steal from the hot wallet, download better software (unlock it with Keygen), or upload Spam, Siphon or a Rootkit."
          ], source: "guide" },
        { text: "Success chance depends only on the gap between your level and theirs (Bypasser vs Firewall, Cracker vs Encryptor). The game doesn't publish this; DarkIndex worked it out from logged attempts, and the bypass/crack chips on each card use it.", source: "measured" },
        { table: { head: ["Your level − theirs", "Success"],
                   rows: [6, 5, 4, 3, 2, 1, 0, -1, -2, -3, -4].map((d) => [d >= 6 ? "+6 or more" : d <= -4 ? "−4 or less" : (d > 0 ? "+" + d : String(d)), pct(E.hackOdds(d, 0))]) },
          source: "measured" },
        { text: "A Rootkit on them (yours or a crewmate's) makes their Firewall and Encryptor count 1–3 levels lower; see Rootkit.", source: "measured" },
        { table: { head: ["Modifier", "Effect"],
                   rows: [["Apex device (reboot loadout)", "Your Bypasser and Cracker count +3"],
                          ["Cipher device (reboot loadout)", "Their Firewall and Encryptor count +3"]],
                   caption: "Modifiers simply add up: Apex +3 against a −3 rootkit is an effective +6." },
          source: "guide" },
        { text: "Your device speeds up bypasses and cracks. Running several at once slows them all down (each extra one adds 75% to the time).", source: "guide" },
        { list: [
            "They upgrade their Firewall: your bypass and crack both stop working, and they get 4 hours of protection.",
            "They upgrade their Encryptor past your crack: only the crack stops working.",
            "IP Scrambler: they get a new IP and all your processes against them are cancelled.",
            "EMP Pulse: cancels your processes on them and blocks new ones for 1 hour."
          ], source: "guide" },
        { tip: "Use the Bypass / crack odds calculator to check a target with rootkits or reboot perks in play." }
      ]
    },
    {
      id: "scanning", title: "📡 Scanning & matchmaking", items: [
        { list: [
            "Scan Random shows 10 targets near your level, widening the range until the list is full. The usual window is about ±10 levels.",
            "Each crew-server Uplink level adds 1 target: an Uplink giving +2 shows 12.",
            "Players with Proxy on still appear, with their IP masked.",
            "Your level decides who you see: levelling up shows you tougher players."
          ], source: "confirmed" },
        { list: [
            "Players with Stealth on never appear in random scans, though anyone with their IP can still look them up.",
            "The Ghost reboot device hides the last part of its IP in scans even without Proxy.",
            "The Apex reboot shows each target's Encryptor level in scans, not just their Firewall."
          ], source: "guide" },
        { text: "Exactly how far above and below your level a scan reaches.", source: "unknown" },
        { tip: "For Spam, any victim Lv 27 or higher pays the full ₵100/hr with Spam Lv 17. Look for low Firewalls among them." }
      ]
    },
    {
      id: "spam", title: "📧 Spam", items: [
        { text: "Spam is your main passive income: up to ₵100/hr from each victim it's on. Income builds up continuously and you collect it whenever you like.", source: "confirmed" },
        { text: "What decides the rate is the victim's level compared with the Spam's level. Your own level plays no part. A victim well above the Spam level pays more; a Spam above the victim's level pays less.", source: "measured" },
        { text: "The rate is locked in when you upload. Levelling up later doesn't change it; to upgrade, uninstall and upload again.", source: "confirmed" },
        { table: { head: ["Spam Lv", "Victim Lv 2", "Victim 10", "Victim 20", "Victim 30", "Victim 40+"],
                   rows: [1, 3, 5, 7, 9, 11, 13, 15, 16, 17, 20].map((l) => ["Lv " + l, ...[2, 10, 20, 30, 40].map((v) => E.spamIncome(l, v))]),
                   caption: "₵/hr for a fresh upload. Matches all 17 in-game measurements." },
          source: "calculated" },
        { tip: "On victims Lv 28+, Spam Lv 16 pays ₵99/hr and uploads faster than Lv 17, the lowest level that hits the full ₵100." },
        { tip: "On low-level victims don't upload your highest Spam: it earns less and takes longer. The Spam chip on each card shows the best level for that target and how long it takes to upload." },
        { text: "Decay: every Spam slowly loses income. Full rate for 21 days, then a steady drop to 10% at day 100. A fresh upload resets the clock.", source: "guide" },
        { table: { head: ["Day", "Income kept"], rows: [1, 21, 30, 50, 70, 100].map((d) => [d, pct(Math.round(E.spamDecayFactor(d) * 100))]) },
          source: "guide" },
        { list: [
            "To replace an old Spam, uninstall it from the victim's own Apps page and upload the new one in the same visit. Uninstalling from your own Apps page first risks losing access if they've upgraded since.",
            "The Scythe reboot device makes Spam decay half as fast."
          ], source: "guide" }
      ]
    },
    {
      id: "botnet", title: "🕸️ Botnet & Spam fees", items: [
        { text: "Your botnet tier sets how many Spam you can run at once. Running more than 2 adds a fee to every collection: 0.5% for each Spam beyond 2, up to 30%. Empty slots cost nothing.", source: "guide" },
        { table: { head: ["Tier", "Spam slots", "Cost", "Fee when full"],
                   rows: [["Free", 2, "free"], ["Node", 4, "800 (needs Lv 3)"], ["Cluster", 8, "3,500"], ["Grid", 16, "15,000"],
                          ["Farm", 28, "42,000"], ["Hive", 44, "95,000"], ["Nexus", 64, "180,000"]]
                          .map(([t, s, c]) => [t, s, c, (Math.min(30, 0.5 * Math.max(0, s - 2))).toFixed(1) + "%"]) },
          source: "guide" },
        { text: "Hacker Pass cuts the fee by a quarter, Elite Pass by half. Each crew-server RAM level adds 1 extra Spam slot.", source: "guide" },
        { tip: "Going from 44 to 64 Spam raises the fee on everything from 21% to 30%, so the last 20 slots add much less than they seem." }
      ]
    },
    {
      id: "siphon", title: "🩸 Siphon", items: [
        { text: "A Siphon skims a cut of crypto coming into the victim's hot wallet.", source: "guide" },
        { text: "Exactly which income it skims is still open. Play suggests only what the victim steals from other players, and Spam collections don't seem to be skimmed, but that hasn't been re-checked with a fresh Siphon and the guide contradicts itself.", source: "unknown" },
        { table: { head: ["Siphon Lv", "Cut"], rows: [1, 2, 5, 6, 10, 13, 15, 17, 20, 21, 25].map((l) => ["Lv " + l, pct(E.siphonPercent(l))]),
                   caption: "Goes up 0.25% per level and stops at 6% from Lv 21." },
          source: "measured" },
        { list: ["Never loses income over time (unlike Spam).", "You can run up to 700 Siphons in total."], source: "confirmed" },
        { list: ["All attackers together can take at most 30% from one victim.", "Wallet Shield doesn't stop a Siphon."], source: "guide" },
        { text: "Money that skips the hot wallet is never skimmed: daily missions, login streaks, Watch & Earn, Black Market Crypto Stash, subscription crypto and the victim's own hot → cold transfers.", source: "guide" },
        { text: "When a victim's Antivirus removes your Siphon, its row (and its total) vanishes from your SIPHON EARNINGS with no trace.", source: "confirmed" },
        { tip: "Siphons pay best on active, high-level players who steal a lot. Pair one with a Spam on the same victim: they use your 2 virus slots there." }
      ]
    },
    {
      id: "rootkit", title: "🪱 Rootkit", items: [
        { text: "A Rootkit doesn't earn anything. It makes the victim easier to hack: their Firewall and Password Encryptor count as up to 3 levels lower against you and every member of your crew.", source: "guide" },
        { table: { head: ["Rootkit Lv", "Their defences count as"], rows: [["1–2", "1 level lower"], ["3–5", "2 levels lower"], ["6 or higher", "3 levels lower (the most it does)"]],
                   caption: "Measured at Lv 1, 2, 3 and 6; Lv 4–5 must be 2 since they sit between 3 and 6." },
          source: "measured" },
        { list: [
            "Only the highest Rootkit on a victim counts. A second, lower one (yours or a crewmate's) adds nothing.",
            "It also lowers their level for hardening, so your Backdoors and Exploit Kits get blocked less often.",
            "It takes one of your 2 virus slots on that victim, so it competes with Spam and Siphon there."
          ], source: "guide" },
        { tip: "Lv 6 already gives the full effect. A higher Rootkit only costs more and uploads slower." },
        { tip: "Best timing: upload it after the bypass and before the crack, so the crack is up to 3 levels easier." },
        { tip: "In a crew, let one person put a Lv 6+ Rootkit on shared targets and spend your own slots on Spam or Siphon." }
      ]
    },
    {
      id: "viruses", title: "🦠 Virus rules (all types)", items: [
        { list: [
            "You get 2 virus slots on each victim (any 2 of Spam, Siphon, Rootkit). Other attackers have their own slots.",
            "You can upload any level up to the one you have installed. Lower levels upload faster.",
            "An uploaded virus stays at the level you uploaded; uninstall and re-upload to upgrade it."
          ], source: "confirmed" },
        { shots: [SHOT("apps", "A target's Apps screen", "A target's Apps page. UPLOAD VIRUS shows how many of your 2 slots you've used there; the small number under each level compares it with yours (+6 = 6 above you).")] },
        { text: "Each virus on a device slows that device by 1%, up to 40%. It affects bypasses, cracks, transfers and even its own Antivirus scans.", source: "guide" },
        { text: "Viruses also cost the victim reputation when they land; see Reputation & score.", source: "guide" },
        { warn: "The only way to see which viruses are on you is an Antivirus scan. Its report lists every virus it found, removed or not." }
      ]
    },
    {
      id: "transfers", title: "⏫ Uploads & downloads", items: [
        { text: "Your network speeds up every upload and download. Upload time also depends on the virus level and on the victim's device: better devices take longer to upload to.", source: "guide" },
        { table: { head: ["Victim device", "Lv 20 upload on DSL"],
                   rows: [["Raider, Raider II, Raider III", E.formatDuration(E.UPLOAD_BASE_SECONDS[0])],
                          ...E.DEVICES.slice(3).map((d, i) => [d, E.formatDuration(E.UPLOAD_BASE_SECONDS[i + 1])])],
                   caption: "From one older benchmark (a Lv 20 virus on a 15× network). Divide by your network's speed (see Devices & networks)." },
          source: "empirical" },
        { text: "Raider, Raider II and Raider III are all equally quick to upload to.", source: "confirmed" },
        { text: "Lower virus levels upload much faster: Lv 10 takes about a fifth as long as Lv 20, Lv 15 about half.", source: "measured" },
        { text: "How long downloads take by software level isn't known yet.", source: "unknown" },
        { list: [
            "Uploads and downloads slow each other down; bypasses and cracks don't affect them.",
            "Each extra transfer running adds 75% to the time.",
            "Harvest Node network (reboot): uploads take half as long. Crew-server NIC: up to 15% faster."
          ], source: "guide" },
        { tip: "Upload the lowest Spam level that still pays the full ₵100/hr on that victim. On a Nova Ultra it can save hours." }
      ]
    },
    {
      id: "antivirus", title: "💉 Antivirus", items: [
        { text: "Each scan has a chance to remove each virus on you. The chance depends on your Antivirus level compared with the virus's level.", source: "guide" },
        { table: { head: ["Your AV − virus level", "Removed per scan"],
                   rows: [5, 3, 2, 1, 0, -1, -2, -3, -5, -9].map((d) => [d >= 5 ? "+5 or more" : d <= -9 ? "−9 or less" : (d > 0 ? "+" + d : String(d)), pct(E.avRemovalPercent(d, 0))]) },
          source: "guide" },
        { text: "Your device sets how long a scan takes. Scans share the processor with bypasses and cracks, so hacking at the same time slows them.", source: "guide" },
        { table: { head: ["Device", "Scan time"], rows: [["Raider", "3h"], ["Raider III", "2h"], ["Bolt II", "1h 30m"], ["Nova II", "~1h 03m"], ["Nova S", "~53m"], ["Nova Ultra", "45m"]] },
          source: "guide" },
        { text: "Scan times on Nova II, Nova S and Nova Ultra are unconfirmed: the guide's text and table disagree by a few minutes.", source: "unknown" },
        { list: [
            "Each removal gives back 90% of the reputation that virus cost you.",
            "Viruses from a Harvest Node attacker count 2 levels higher against your AV.",
            "System Purge (Black Market) removes everything instantly."
          ], source: "guide" },
        { tip: "One level behind drops you from 50% to 20% per scan, so keep your AV at least level with the viruses you see. Behind anyway? Repeated scans still clear them over time." }
      ]
    },
    {
      id: "consumables", title: "🧨 Consumables & hardening", items: [
        { table: { head: ["Item", "What it does", "Cooldown", "Credits"],
                   rows: [["Backdoor", "Instant firewall bypass", "—", 40], ["Exploit Kit", "Instant password crack", "—", 50],
                          ["IP Scrambler", "New IP; cancels everything running against you", "—", 200], ["Log Lock", "Nobody can edit your log for 8h", "12h", 12],
                          ["Wallet Shield", "Blocks theft for 24h (not Siphons)", "48h", 150], ["System Purge", "Removes all viruses", "—", 85],
                          ["EMP Pulse", "Cancels incoming processes and blocks new ones for 1h", "2h", 80]] },
          source: "guide" },
        { text: "From Lv 3, a Firewall can block Backdoors and an Encryptor can block Exploit Kits. A blocked item is still used up.", source: "guide" },
        { table: { head: ["Their Firewall / Encryptor", "Chance your item is blocked"], rows: [3, 5, 10, 15, 20, 25, 30, 32].map((l) => ["Lv " + l, pct(E.hardeningBlock(l))]) },
          source: "guide" },
        { tip: "Against a Lv 30 Firewall, 84% of Backdoors are wasted. Save them for low-level targets, and put a Rootkit on first." }
      ]
    },
    {
      id: "proxy", title: "🎭 Proxy, Stealth & Trace", items: [
        { text: "Proxy hides part of your IP in other players' logs and scans. It isn't always on: you pay crypto to switch it on for 2, 6, 12 or 24 hours.", source: "guide" },
        { table: { head: ["Proxy Lv", "You show up as"], rows: [["1–5", "192.168.1.xxx"], ["6–10", "192.168.xxx.xxx"], ["11–15", "192.xxx.xxx.xxx"], ["16+", "xxx.xxx.xxx.xxx"]] },
          source: "guide" },
        { table: { head: ["Proxy Lv", "2h", "6h", "12h", "24h"],
                   rows: [1, 5, 10, 15, 20, 25, 30].map((l) => ["Lv " + l, ...[[2, 0], [6, 0.05], [12, 0.10], [24, 0.15]].map(([h, d]) => fmt(E.proxyCost(l, h, d)))]),
                   caption: "Activation cost in crypto. Longer activations are discounted (up to 15% for 24h)." },
          source: "calculated" },
        { list: [
            "Activations stack: two 24h buys give 48h.",
            "An activation keeps the level it started at. Upgrading your Proxy only takes effect on your next activation."
          ], source: "guide" },
        { text: "Stealth unlocks at Proxy Lv 20. It's a separate switch you turn on and off, not a permanent state. While it's on you never appear in other players' random scans, but anyone who already has your IP can still find you.", source: "guide" },
        { list: [
            "Stealth runs on a reserve of up to 170 hours. It drains hour for hour while Stealth is on.",
            "It refills 1 hour for every 1.5 hours it's off, so over time you can be stealthed about 40% of the time.",
            "You need at least 15 minutes banked to switch it on. The switch itself is free.",
            "When the reserve runs out Stealth turns off, but your Proxy masking keeps working.",
            "Your cracks, downloads and uploads still show in victims' logs, as xxx.xxx.xxx.xxx. Backdoors and Exploit Kits leave no line at all."
          ], source: "guide" },
        { text: "Trace is the counter to Proxy. Your Trace gets one roll to reveal a victim's real IP when you bypass them. Their Trace gets a roll on you every time you enter their device; if it lands, your real IP appears in their log tagged [TRACED].", source: "guide" },
        { tip: "Each visit gives their Trace another roll. Get in, do everything, get out. A Log Lock stops an attacker editing a [TRACED] line out of your log." }
      ]
    },
    {
      id: "logs", title: "📜 Logs", items: [
        { shots: [SHOT("log", "Your log screen", "Your log. The xxx lines are a target with Proxy on; the box is editable, hence SAVE. Real IPs blurred.")] },
        { list: [
            "Logs keep only the last 100 lines, graffiti and messages included. Paste them here often or steals fall off the end.",
            "Times are UTC, written as [M-D H:MM]. Newest first, but not strictly in time order: each line carries the time the device was accessed, so a [16:38] line can sit below [17:40] lines.",
            "Anyone who has bypassed a device can edit its log, so odd lines in victim logs may be fake. Log Lock blocks editing for 8h."
          ], source: "confirmed" },
        { table: { head: ["Line", "Where", "Means"],
                   rows: [["Accessed device at <ip>", "Your log", "You entered a target"],
                          ["Device accessed from <ip>", "Victim's log", "Someone entered (may be masked, [UNKNOWN] or [TRACED])"],
                          ["Stole N Crypto from <wallet>", "Your log", "You stole N"],
                          ["N Crypto transferred to <wallet>", "Victim's log", "They were robbed; the wallet is the thief's"],
                          ["Downloaded / Uploaded LvN <App> from / to <ip>", "Your log", "Transfers"],
                          ["Backdoor blocked by <ip>'s firewall", "Your log", "Hardening blocked you"]] },
          source: "confirmed" },
        { list: [
            "A steal is linked to the last access only if it's within 3 minutes of it, and only the first steal after an access counts. The game sometimes skips an 'accessed' line, so a second steal in a row stays unlinked rather than handing one target another's wallet.",
            "A [UNKNOWN] attacker is using the Ghost reboot loadout."
          ], source: "app" }
      ]
    },
    {
      id: "keygen", title: "🔑 Keygen & software prices", items: [
        { list: [
            "Download software from a victim you've bypassed. It arrives locked.",
            "Unlock it with your Keygen for a fee: much cheaper than the Store, and you still get the full XP for that level plus 5 rep.",
            "You can only unlock levels above what you already have. Keygen itself can't be downloaded; buy it in the Store."
          ], source: "guide" },
        { shots: [SHOT("locked", "Your Apps page with locked downloads", "Your Apps page: each LOCKED row is a downloaded level waiting to be unlocked, with its key price.")] },
        { table: { head: ["Levels jumped", "Fee (share of Store price)"], rows: [1, 2, 3, 5, 10, 15, 20].map((j) => ["+" + j + (j === 20 ? " or more" : ""), (keyFee(j) * 100).toFixed(0) + "%"]),
                   caption: "Matches 6 real key prices to within 1% (jumps of 2–13, Lv 33–42). The jump counts from the level shown on your Apps page, including any (+3) bonus." },
          source: "measured" },
        { tip: "One big jump beats several small ones: each step pays a fee on its own level's price. Find the highest copy you can and unlock it directly." },
        { table: { head: ["App", "Lv 15", "Lv 20", "Lv 25", "Lv 30"],
                   rows: Object.entries(STORE_APPS).map(([app, [base, def]]) => [app, ...[15, 20, 25, 30].map((l) => fmt(E.storePrice(base, l, !!def)))]),
                   caption: "Store prices in crypto. The formula behind them matched 5 real prices to the crypto (Lv 19–25); it drifts from the guide below Lv 15. Defensive apps (Firewall, Encryptor, Antivirus, Proxy, Trace) are 15% cheaper." },
          source: "calculated" }
      ]
    },
    {
      id: "hardware", title: "🖥️ Devices & networks", items: [
        { text: "Your device speeds up bypasses, cracks and Antivirus scans. Your network speeds up uploads and downloads. A victim's device decides how slow uploads to them are.", source: "guide" },
        { table: { head: ["Device", "Speed", "Price"], rows: E.DEVICES.map((d, i) => [d, E.DEVICE_SPEED[i] + "×", i ? fmt(E.DEVICE_PRICES[i]) : "free"]) },
          source: "guide" },
        { table: { head: ["Network", "Speed", "Price"], rows: E.NETWORKS.map((n, i) => [n, E.NETWORK_BOOST[i] + "×", i ? fmt(E.NETWORK_PRICES[i]) : "free"]) },
          source: "guide" }
      ]
    },
    {
      id: "wallet", title: "👛 Wallet, Credits & levelling", items: [
        { list: [
            "Hot wallet: your spending balance. Anyone who has cracked you can steal from it.",
            "Cold storage: safe from theft and Siphons, but capped by your level.",
            "Theft loses 10% to gas: the victim loses the full amount, the thief gets 90%. 'Stole N' in your log is what the victim lost."
          ], source: "guide" },
        { shots: [SHOT("wallet", "A target's wallet screen", "A Lv 36 target's wallet: nothing in the hot wallet to steal, and a 439,280 cold storage cap. Name and address blurred.")] },
        { table: { head: ["Level", "Cold storage cap"], rows: [[1, "3,000"], [5, "8,841"], [10, "29,124"], [20, "121,891"], [30, "294,147"], [36, "439,280"]],
                   caption: "Lv 36 confirmed in-game; the rest from the guide. Mission, streak, ad and Crypto Stash rewards go to cold storage even past the cap." },
          source: "guide" },
        { text: "There's no minimum or maximum per steal: you can take a whole hot wallet in one go.", source: "confirmed" },
        { text: "There seems to be a daily steal limit; the amount isn't known.", source: "unknown" },
        { text: "Crypto → Credits: 250 crypto buys 1 Credit. Minimum 5 Credits per exchange, at most 750 Credits a month (resets on the 1st, UTC). It takes from your hot wallet first, then cold storage.", source: "guide" },
        { text: "Credits → Crypto: the Black Market's Crypto Stash sells 10,000 crypto for 100 Credits and 40,000 for 400 Credits, each once a day. It goes straight to cold storage, so it can't be stolen or siphoned on the way.", source: "guide" },
        { tip: "Move crypto to cold storage right after every steal: tap the Wallet badge at the top of any page." },
        { text: "XP only comes from spending crypto (software, Keygen unlocks, hardware), missions and login streaks. Hacking itself gives no XP.", source: "confirmed" },
        { table: { head: ["Level", "XP to next level"], rows: [[1, "589"], [5, "2,605"], [10, "5,919"], [20, "14,209"], [30, "24,079"], [35, "29,484"], [36, "30,599"], [38, "32,860"], [44, "39,888"]],
                   caption: "Lv 35, 36, 38 and 44 confirmed in-game." },
          source: "guide" },
        { text: "Software (Store or Keygen) gives about 0.17 XP per crypto of its Store price; your current device or network line gives 0.25 XP per crypto, older hardware 0.20.", source: "measured" },
        { text: "Each level gives +10 Overclocks, +10 Credits and a bigger cold storage cap.", source: "guide" },
        { tip: "Levelling up makes scans show you tougher players. Spend on what you actually use (Bypasser, Cracker, Spam, Keygen, device) rather than upgrading everything for XP." }
      ]
    },
    {
      id: "reputation", title: "⭐ Reputation & score", items: [
        { text: "Your leaderboard score grows with both level and reputation. Doubling your level doubles your score; doubling your rep raises it by about 68%. The Score calculator works it out.", source: "measured" },
        { shots: [SHOT("home", "A target's Home screen", "Lv 36 with 25 rep shows score 402, exactly what the formula gives.")] },
        { table: { head: ["How you earn rep", "Rep", "Limit"],
                   rows: [["Successful bypass or crack", "Up to ~105, more on tougher targets", "Once per victim per type per 24h"],
                          ["Download or upload", "5 (+10 with Proxy on)", "Once per victim per type per 24h"],
                          ["Backdoor / Exploit Kit", "At least 5", "Same 24h limit"],
                          ["Someone fails to hack you", "15 + 1 per 5 levels of their software", "Once per attacker per 24h"],
                          ["Your Trace catches someone", "15–25, more with higher Trace", "—"],
                          ["Keygen unlock", "5", "—"],
                          ["Daily missions", "30 / 55 / 90", "Daily"]],
                   caption: "The 24h limits only apply to rep: you can still steal, download and upload as often as you like." },
          source: "guide" },
        { text: "Hacking someone whose defences are far below your offence earns less: full rep up to 5 levels above them, dropping to nothing at 10 levels above. This compares software levels, not player levels.", source: "guide" },
        { table: { head: ["Your software − theirs", "Rep you get"], rows: [["+5 or less", "100%"], ["+6", "80%"], ["+7", "60%"], ["+8", "40%"], ["+9", "20%"], ["+10 or more", "0%"]],
                   caption: "The guide only says it falls off steadily; the exact steps are assumed." },
          source: "guide" },
        { text: "The exact rep a bypass or crack gives isn't known yet; the guide only says it scales with their defence, up to about 105.", source: "unknown" },
        { table: { head: ["Virus that lands on you", "Rep lost"], rows: [1, 5, 10, 15, 20].map((l) => ["Lv " + l, "−" + E.repLossFromVirus(l)]) },
          source: "guide" },
        { list: [
            "You lose at most 500 rep a day, and never drop below half your highest-ever rep.",
            "Antivirus or System Purge gives back 90% of a virus's rep loss; 10% is lost for good.",
            "If the attacker removes their own virus, you get all of it back."
          ], source: "guide" }
      ]
    },
    {
      id: "daily", title: "📅 Missions, streaks & passes", items: [
        { table: { head: ["Mission", "XP", "Rep", "Reward", "Spawn chance"],
                   rows: [["Easy", 100, 30, "250 crypto or 3 OC", "80%"], ["Medium", 150, 55, "500 crypto or 7 OC", "50%"], ["Hard", 200, 90, "1,000 crypto or 15 OC", "20%"]],
                   caption: "Hacking missions (bypass, crack, download) pay crypto; upload missions (Spam, Siphon, Rootkit) pay Overclocks." },
          source: "guide" },
        { list: ["3 missions a day, reset at midnight UTC.", "The same victim only counts once per mission within 48h."], source: "guide" },
        { table: { head: ["Login day", "Reward", "With a pass"],
                   rows: [[1, "100 XP", "200 XP"], [2, "5 OC", "10 OC"], [3, "500 crypto", "1,000 crypto"], [4, "5 Credits", "10 Credits"],
                          [5, "1,000 crypto", "2,000 crypto"], [6, "10 OC", "20 OC"], [7, "15 Credits", "30 Credits"]],
                   caption: "Miss a day and it starts again from day 1." },
          source: "guide" },
        { text: "Watch & Earn (Store → Credits tab): 12 ads a day, 4 for each reward. Each pays 3 Credits, 250 crypto or 5 Overclocks.", source: "guide" },
        { table: { head: ["", "Hacker Pass", "Elite Pass"],
                   rows: [["Price", "$4.99/month", "$9.99/month"], ["Every day", "5 Credits, 5 OC, 500 crypto", "10 Credits, 10 OC, 1,000 crypto"],
                          ["Spam fee", "−25%", "−50%"], ["Pause & resume", "Bypasses and cracks", "Any process"], ["Also", "Weekly consumables, double login streak", "More drops, double login streak"]] },
          source: "guide" }
      ]
    },
    {
      id: "crews", title: "👥 Crews", items: [
        { list: [
            "Up to 30 members (40 with crew-server Storage). One crew at a time.",
            "A crewmate's Rootkit helps everyone in the crew hack that victim.",
            "Anyone who hacks one member can read the crew chat and roster, IPs included. Message Encryptor blanks the chat for them."
          ], source: "guide" },
        { table: { head: ["Server part", "Each level gives", "At max (Lv 5)"],
                   rows: [["CPU", "+3% bypass & crack speed", "+15%"], ["NIC", "+3% upload & download speed", "+15%"], ["RAM", "+1 Spam slot", "+5 slots"],
                          ["Uplink", "+1 target per scan", "15 targets"], ["Storage", "+2 member slots", "40 members"]] },
          source: "confirmed" },
        { list: [
            "Upgrades and daily upkeep come out of the crew treasury. Each member can put in up to 2,000 × their level a day, at most 50,000.",
            "New members wait 24h before they get the server's buffs."
          ], source: "confirmed" },
        { text: "If the treasury runs dry the server goes offline and its buffs pause (Spam in RAM slots too), but levels are never lost.", source: "guide" },
        { text: "Server costs below were checked against a crew's full server log, to the crypto.", source: "measured" },
        { table: { head: ["Part", "Lv 1", "Lv 2", "Lv 3", "Lv 4", "Lv 5"],
                   rows: CREW_PARTS.map(([p, b]) => [p, ...[1, 2, 3, 4, 5].map((k) => compact(b * k * k))]),
                   caption: "Price to upgrade a part to each level." },
          source: "measured" },
        { table: { head: ["Part", "Lv 1", "Lv 2", "Lv 3", "Lv 4", "Lv 5"],
                   rows: CREW_PARTS.filter(([p]) => p !== "Storage").map(([p, b]) => [p, ...[1, 2, 3, 4, 5].map((L) => fmt(b * 0.005 * L * (L + 1) * (2 * L + 1) / 6))]),
                   caption: "Upkeep per day: 0.5% of everything spent on that part. Storage has none, and a switched-off part costs nothing. Billed about once a day for the hours since the last charge." },
          source: "measured" },
        { text: "A surge gives CPU, NIC or Uplink +2 levels for 6, 12 or 24 hours (12h is 5% off, 24h is 10% off). Extending costs the same as starting a new surge; ending early gives no refund.", source: "measured" },
        { table: { head: ["Surge on", "6h", "12h", "24h"],
                   rows: [["CPU", 70000], ["NIC", 70000], ["Uplink", 45000]].flatMap(([p, b]) => [1, 3, 5].map((L) =>
                     [`${p} at Lv ${L}`, ...[[6, 0], [12, 0.05], [24, 0.1]].map(([h, d]) => fmt(b * ((L + 1) ** 2 + (L + 2) ** 2) * h / 1200 * (1 - d)))])),
                   caption: "In crypto. Other levels: the price of the next two levels × hours ÷ 1,200." },
          source: "measured" }
      ]
    },
    {
      id: "reboot", title: "♻️ Reboot loadouts", items: [
        { text: "From Lv 50 you can reboot: your run resets for a loadout with permanent perks. Several tools here mention these perks.", source: "guide" },
        { table: { head: ["Reset", "Kept"],
                   rows: [["Level (to 1) and rep", "R-tier and badges"], ["Software (back to starter)", "Credits, Overclocks and inventory"], ["Crypto and botnet", "Notepad and Message Encryptor"],
                          ["Your Siphons, Rootkits and cracks", "Your crew"], ["Processes and your IP", "Lifetime score and this month's leaderboard progress"]] },
          source: "guide" },
        { text: "R1 to R5 must each use a different loadout. From R6 you can mix any device line with any network line.", source: "guide" },
        { table: { head: ["Loadout", "Device perk", "Network perk"],
                   rows: [["Ghost", "[UNKNOWN] in logs, can't be Traced", "Proxy lasts twice as long, +5 vs Trace, Stealth refills 1h per hour off"],
                          ["Vector", "Half-price Overclocks on hacks, 50% chance to keep consumables", "Half-price Overclocks on transfers, a free consumable daily"],
                          ["Scythe", "Siphons earn double, Spam loses income half as fast", "Harvest Node: uploads twice as fast, your viruses +2 vs AV"],
                          ["Cipher", "Your Firewall and Encryptor +3", "Blocks every Backdoor and Exploit Kit"],
                          ["Apex", "Your Bypasser and Cracker +3", "Scans show Encryptor levels, downloads 40% faster"]] },
          source: "guide" },
        { text: "Reboot hardware (e.g. Apex VII, Null Route IX) is as fast as the standard item at the same level. This app reads those names, so upload times work for reboot players too.", source: "measured" }
      ]
    },
    {
      id: "console", title: "🔎 Using this console", items: [
        { shots: [{ src: "docs/demo.gif", alt: "Copying a target's Home screen and pasting it into the console", caption: "Long-press the game screen, Select all, Copy, then paste here and press Process data." }] },
        { text: "Copy the text from any of these game screens and paste it into the console. Names and IPs are blurred in the screenshots below.", source: "app" },
        { shots: [
            SHOT("home", "A target's Home screen", "Target's Home: IP, username, clan, level, device, network, Firewall, Encryptor"),
            SHOT("apps", "A target's Apps screen", "Target's Apps: their software levels"),
            SHOT("log", "Your log screen", "A log (yours or a target's): accesses, transfers, steals")
          ] },
        { list: [
            "Paste victim logs, a victim Home screen, or a victim Software screen, then press Process data.",
            "Filter: Firewall Lv.10 · Bypasser 9 · 27.61.93.149 (space = AND, | = OR).",
            "Shortcuts: lvl 30 / lvl 28-32 (player level), sw 20 (any stealable app at exactly Lv 20).",
            "Short names search ±2 levels: fw 12, enc 10, av 8, bp 9, pc 9, rk 5. Full names are exact: Spam 17, Firewall Lv.12.",
            "Prefixes: user:, clan:, wallet:, hw:. Any other word matches username, clan, wallet, hardware, IP or app.",
            "Missing data (Advanced targeting) shows only real targets missing a wallet, Bypasser, Firewall or Password Encryptor.",
            "Good Spam ranks targets by Spam ₵/hr, then fastest upload, then lowest Firewall. Set your Spam level and network in ⚙ My Stats.",
            "Wallet income: each wallet's steals are grouped into sessions (a gap over 1 hour starts a new one) and averaged into ₵/hr."
          ], source: "app" }
      ]
    }
  ];

  // ---------------- Calculators ----------------
  // field: [id, label, default, {type:"check"|"select", options}]
  const deviceOptions = E.DEVICES;
  const networkOptions = E.NETWORKS;
  const CALCS = [
    {
      id: "spam", title: "Spam income",
      fields: [["spamLv", "Spam level", 17], ["victimLv", "Victim level", 20], ["days", "Days since upload", 0], ["scythe", "Scythe device", false, { type: "check" }]],
      run: (v) => {
        const fresh = E.spamIncome(v.spamLv, v.victimLv);
        const decay = E.spamDecayFactor(v.days, v.scythe);
        const now = Math.round(fresh * decay);
        const cap = E.spamCapLevel(v.victimLv, 60);
        const best = E.spamBestLevel(v.victimLv, 30);
        return [
          `Earns ₵${fresh}/hr fresh (₵${fmt(fresh * 24)}/day)`,
          v.days > 21 ? `After ${v.days} days: ₵${now}/hr (${Math.round(decay * 100)}% of fresh)` : null,
          cap ? `Cheapest Spam that hits ₵100/hr here: Lv ${cap}` : `₵100/hr isn't reachable on this victim. Best: Lv ${best} for ₵${E.spamIncome(best, v.victimLv)}/hr`
        ];
      }
    },
    {
      id: "odds", title: "Bypass / crack odds",
      fields: [["mine", "Your Bypasser / Cracker", 10], ["theirs", "Their Firewall / Encryptor", 10], ["rootkit", "Rootkit level on them", 0],
               ["apex", "Apex device (+3 you)", false, { type: "check" }], ["cipher", "Cipher device (+3 them)", false, { type: "check" }]],
      run: (v) => {
        const me = v.mine + (v.apex ? 3 : 0);
        const them = Math.max(0, v.theirs - rootkitDebuff(v.rootkit) + (v.cipher ? 3 : 0));
        return [`Success: ${E.hackOdds(me, them)}%`, `Counts as your ${me} vs their ${them}`];
      }
    },
    {
      id: "upload", title: "Virus upload time",
      fields: [["virusLv", "Virus level", 17], ["device", "Victim's device", "Bolt III", { type: "select", options: deviceOptions }],
               ["network", "Your network", "DSL", { type: "select", options: networkOptions }],
               ["procs", "Transfers running", 1], ["harvest", "Harvest Node", false, { type: "check" }]],
      run: (v) => {
        const tier = E.uploadTierForDeviceIndex(E.DEVICES.indexOf(v.device));
        const boost = E.NETWORK_BOOST[E.NETWORKS.indexOf(v.network)] || 1;
        const solo = E.uploadSecondsForLevel(tier, boost, v.virusLv) * (v.harvest ? 0.5 : 1);
        const n = Math.max(1, v.procs);
        return [`Takes ${E.formatDuration(Math.round(solo * (1 + 0.75 * (n - 1))))}`, n > 1 ? `(${E.formatDuration(Math.round(solo))} if it ran alone)` : null];
      }
    },
    {
      id: "av", title: "Antivirus removal",
      fields: [["av", "Your AV level", 10], ["virus", "Virus level", 10], ["harvest", "Attacker on Harvest Node", false, { type: "check" }], ["scans", "Number of scans", 1]],
      run: (v) => {
        const p = E.avRemovalPercent(v.av, v.virus + (v.harvest ? 2 : 0)) / 100;
        const n = Math.max(1, v.scans);
        return [`${Math.round(p * 100)}% chance per scan`, n > 1 ? `${Math.round((1 - Math.pow(1 - p, n)) * 100)}% chance it's gone after ${n} scans` : null];
      }
    },
    {
      id: "proxy", title: "Proxy cost",
      fields: [["lvl", "Proxy level", 10], ["hours", "Duration (hours)", 6, { type: "select", options: [2, 6, 12, 24] }]],
      run: (v) => {
        const disc = { 2: 0, 6: 0.05, 12: 0.10, 24: 0.15 }[v.hours] || 0;
        const shown = ["", "192.168.1.xxx", "192.168.xxx.xxx", "192.xxx.xxx.xxx", "xxx.xxx.xxx.xxx"][v.lvl >= 16 ? 4 : v.lvl >= 11 ? 3 : v.lvl >= 6 ? 2 : 1];
        return [`Costs ${fmt(E.proxyCost(v.lvl, v.hours, disc))} crypto`, `You show up as ${shown}`, v.lvl >= 20 ? "Stealth switch unlocked" : null];
      }
    },
    {
      id: "store", title: "Store price & Keygen fee",
      fields: [["app", "Software", "Spam", { type: "select", options: Object.keys(STORE_APPS) }], ["have", "Level you have (as shown, incl. bonus)", 15], ["lvl", "Level you want", 20]],
      run: (v) => {
        const [base, def] = STORE_APPS[v.app];
        const price = E.storePrice(base, v.lvl, !!def);
        const jump = v.lvl - v.have;
        return [
          `Store: ${fmt(price)} crypto (≈ ${fmt(price * 0.17)} XP)`,
          jump >= 1 ? `Keygen unlock: ~${fmt(price * keyFee(jump))} crypto (${Math.round(keyFee(jump) * 100)}% for +${jump})` : "Keygen only unlocks levels above yours",
          v.lvl < 15 ? "Prices below Lv 15 are less reliable" : null
        ];
      }
    },
    {
      id: "siphon", title: "Siphon cut",
      fields: [["lvl", "Siphon level", 10], ["income", "Crypto they steal per day", 20000]],
      run: (v) => {
        const p = E.siphonPercent(v.lvl);
        return p == null ? ["Siphon level must be 1 or more"] : [`Takes ${p}% → about ${fmt(v.income * p / 100)} crypto a day for you`];
      }
    },
    {
      id: "score", title: "Leaderboard score",
      fields: [["level", "Level", 30], ["rep", "Reputation", 20000]],
      run: (v) => [`Score: ${fmt(E.score(v.level, v.rep))}`, `+1 level → ${fmt(E.score(v.level + 1, v.rep))} · +1,000 rep → ${fmt(E.score(v.level, v.rep + 1000))}`]
    }
  ];

  // ---------------- Rendering ----------------
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function badge(src) {
    const s = SOURCES[src] || SOURCES.unknown;
    return `<span class="kb-src" style="color:${s.color};border-color:${s.color}66;background:${s.color}14" title="${esc(s.tip)}">${s.label}</span>`;
  }
  function itemText(it) {
    const parts = [it.text || it.tip || it.warn || "", ...(it.shots || []).map((sh) => sh.caption || "")];
    if (it.list) parts.push(...it.list);
    if (it.table) parts.push(it.table.head.join(" "), it.table.caption || "", ...it.table.rows.map((r) => r.join(" ")));
    return parts.join(" ").toLowerCase();
  }
  // Game screenshots: { shots: [{ src, alt, caption }] }, shown side by side and opening full size on tap.
  function renderShots(shots) {
    const one = shots.length === 1;
    return `<div class="kb-shots ${one ? "kb-shots-one" : ""}">` + shots.map((sh) =>
      `<figure class="kb-shot"><a href="${esc(sh.src)}" target="_blank" rel="noopener" title="Open full size">` +
      `<img src="${esc(sh.src)}" alt="${esc(sh.alt)}" loading="lazy"></a>` +
      (sh.caption ? `<figcaption>${esc(sh.caption)}</figcaption>` : "") + `</figure>`
    ).join("") + `</div>`;
  }
  function renderItem(it) {
    if (it.shots) return renderShots(it.shots);
    if (it.tip) return `<div class="kb-tip"><span class="kb-tip-label">Tip</span>${esc(it.tip)}</div>`;
    if (it.warn) return `<div class="kb-warn"><span class="kb-warn-label">Note</span>${esc(it.warn)}</div>`;
    let body = "";
    if (it.text) body += `<p>${esc(it.text)}</p>`;
    if (it.list) body += `<ul>${it.list.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
    if (it.table) {
      body += `<div class="kb-table-wrap"><table class="kb-table"><thead><tr>${it.table.head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead>` +
        `<tbody>${it.table.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` +
        (it.table.caption ? `<p class="kb-caption">${esc(it.table.caption)}</p>` : "");
    }
    return `<div class="kb-item">${badge(it.source)}${body}</div>`;
  }
  function topicHeading(title) {
    return `<h3 class="border-b border-cyber-border pb-3 font-mono text-lg font-bold text-indigo-300">${esc(title)}</h3>`;
  }
  const legend = () =>
    `<div class="flex flex-wrap items-center gap-1.5 pt-2 font-mono text-[10px] text-slate-500">Sources: ${["measured", "confirmed", "calculated", "empirical", "guide", "unknown", "app"].map(badge).join("")}</div>`;

  // ---- Calculators view ----
  function calculatorsHtml() {
    return topicHeading("🧮 Calculators") + `<div class="grid grid-cols-1 gap-3 lg:grid-cols-2">` + CALCS.map((c) => {
      const inputs = c.fields.map(([id, label, def, opt]) => {
        if (opt && opt.type === "check") {
          return `<label class="kb-check"><input type="checkbox" class="check" data-f="${id}" ${def ? "checked" : ""}> ${esc(label)}</label>`;
        }
        if (opt && opt.type === "select") {
          return `<label class="field-label">${esc(label)}<select class="input py-2" data-f="${id}">${opt.options.map((o) => `<option${o === def ? " selected" : ""}>${esc(o)}</option>`).join("")}</select></label>`;
        }
        return `<label class="field-label">${esc(label)}<input class="input py-2" type="number" inputmode="decimal" step="any" data-f="${id}" value="${def}"></label>`;
      }).join("");
      return `<div class="kb-calc" data-calc="${c.id}"><div class="kb-calc-title">${esc(c.title)}</div><div class="kb-calc-fields">${inputs}</div><div class="kb-calc-out"></div></div>`;
    }).join("") + `</div>`;
  }
  function wireCalculators(host) {
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

  // ---- Navigation / views ----
  const CALC_ID = "__calcs";
  let current = CALC_ID;

  function renderNav() {
    const nav = document.getElementById("kbNav");
    const entries = [[CALC_ID, "🧮 Calculators"], ...TOPICS.map((t) => [t.id, t.title])];
    nav.innerHTML = entries.map(([id, title]) =>
      `<button class="kb-nav-item${id === current ? " active" : ""}" data-kb-id="${id}"${id === current ? ' aria-current="true"' : ""}>${esc(title)}</button>`
    ).join("");
  }

  function show(id) {
    current = id;
    document.getElementById("kbSearch").value = "";
    renderNav();
    const area = document.getElementById("kbContentArea");
    if (id === CALC_ID) {
      area.innerHTML = calculatorsHtml();
      wireCalculators(area);
    } else {
      const t = TOPICS.find((x) => x.id === id);
      area.innerHTML = topicHeading(t.title) + t.items.map(renderItem).join("") + legend();
    }
    area.scrollTop = 0;
    const active = document.querySelector("#kbNav .active");
    if (active) active.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  function search(query) {
    const q = query.trim().toLowerCase();
    if (!q) return show(current);
    document.querySelectorAll("#kbNav .kb-nav-item").forEach((b) => b.classList.remove("active"));
    const area = document.getElementById("kbContentArea");
    const hits = TOPICS.map((t) => ({ t, items: t.items.filter((it) => t.title.toLowerCase().includes(q) || itemText(it).includes(q)) }))
      .filter((x) => x.items.length);
    area.innerHTML = hits.length
      ? hits.map(({ t, items }) => topicHeading(t.title) + items.map(renderItem).join("")).join("")
      : `<p class="py-10 text-center font-mono text-sm text-slate-500">Nothing matches “${esc(query)}”.</p>`;
    area.scrollTop = 0;
  }

  function open() {
    const modal = document.getElementById("kbModal");
    modal.hidden = false;
    document.body.style.overflow = "hidden";
    show(current);
    document.getElementById("kbCloseBtn").focus();
  }
  function close() {
    document.getElementById("kbModal").hidden = true;
    document.body.style.overflow = "";
    document.getElementById("kbToggleBtn").focus();
  }

  function init() {
    const modal = document.getElementById("kbModal");
    if (!modal) return;
    document.getElementById("kbToggleBtn").addEventListener("click", open);
    document.getElementById("kbCloseBtn").addEventListener("click", close);
    modal.addEventListener("click", (e) => { if (e.target === modal) close(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !modal.hidden) close(); });
    document.getElementById("kbNav").addEventListener("click", (e) => {
      const btn = e.target.closest("[data-kb-id]");
      if (btn) show(btn.dataset.kbId);
    });
    document.getElementById("kbSearch").addEventListener("input", (e) => search(e.target.value));
    renderNav();
  }

  window.KnowledgeBase = { TOPICS, CALCS, SOURCES, open, close };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
