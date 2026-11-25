// HyperSoar console v3. Fills the static pages from /api/*. Writes are JSON POSTs with the session's CSRF
// token and an Idempotency-Key; the broker behind them checks the role, the password and the policy.
// CSP is script-src 'self' and style-src 'self': nodes are built with createElement and textContent only,
// no HTML string parsing, and per-element values go through CSSOM (el.style.x / setProperty), never style="".
(() => {
  "use strict";
  const body = document.body;
  const screen = body.dataset.screen;
  if (!screen) return;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NS = "http://www.w3.org/2000/svg";
  const fmt = new Intl.NumberFormat("en-US");
  const $ = (s, r = document) => r.querySelector(s);
  const byId = id => document.getElementById(id);
  const POLL_MS = 10000;

  // -- DOM helpers ----------------------------------------------------------------------------------------
  function setAttrs(e, a) {
    for (const k in a || {}) {
      const v = a[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === "text") e.textContent = v;
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    return e;
  }
  function el(tag, attrs, ...kids) {
    const e = setAttrs(document.createElement(tag), attrs);
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : String(k));
    return e;
  }
  function sv(tag, attrs, parent) {
    const e = setAttrs(document.createElementNS(NS, tag), attrs);
    if (parent) parent.append(e);
    return e;
  }
  function fill(target, ...kids) {
    const e = typeof target === "string" ? byId(target) : target;
    if (e) e.replaceChildren(...kids.flat().filter(k => k !== null && k !== undefined && k !== false));
    return e;
  }
  function txt(id, t) { const e = byId(id); if (e) e.textContent = t; return e; }
  const width = (e, frac) => { e.style.width = `${Math.max(0, Math.min(1, frac || 0)) * 100}%`; return e; };
  const clip = (s, n) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s || "");

  // -- time, numbers, words -------------------------------------------------------------------------------
  let TZ = "Asia/Jakarta";
  let TZL = "WIB";
  let skew = 0;  // server clock minus browser clock, so countdowns follow the server
  const TZ_LABEL = { "Asia/Jakarta": "WIB", "Asia/Pontianak": "WIB", "Asia/Makassar": "WITA", "Asia/Jayapura": "WIT" };
  const now = () => Date.now() + skew;
  const ms = iso => (iso ? Date.parse(iso) : NaN);
  const tfmt = (iso, o) => (iso ? new Date(iso).toLocaleTimeString("en-GB", { timeZone: TZ, hour12: false, ...o }) : "–");
  const hms = iso => tfmt(iso);
  const hm = iso => tfmt(iso, { hour: "2-digit", minute: "2-digit" });
  const dayOf = iso => new Date(iso).toLocaleDateString("en-GB", { timeZone: TZ, day: "numeric", month: "short" });
  const when = iso => (!iso ? "–" : dayOf(iso) === dayOf(new Date(now()).toISOString()) ? hm(iso) : `${dayOf(iso)} ${hm(iso)}`);
  function span(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return `${sec} s`;
    if (sec < 3600) return `${Math.round(sec / 60)} min`;
    if (sec < 86400) return `${Math.round(sec / 3600)} h`;
    return `${Math.round(sec / 86400)} d`;
  }
  const ago = iso => (iso ? span((now() - ms(iso)) / 1000) : "–");
  const dur = m => (m === null || m === undefined ? "–" : m < 1000 ? `${m} ms` : `${(m / 1000).toFixed(1)} s`);
  function secs(s) {
    if (s === null || s === undefined) return "–";
    return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`;
  }
  const n = v => (v === null || v === undefined ? "–" : fmt.format(v));
  const plural = (k, w) => `${n(k)} ${w}${k === 1 ? "" : "s"}`;
  const cap = s => (s ? s[0].toUpperCase() + s.slice(1) : "");
  const lower = s => (s && !/^[A-Z0-9]{2}/.test(s) ? s[0].toLowerCase() + s.slice(1) : s || "");
  const BUCKET = { critical: "hi", high: "hi", medium: "md", low: "lo", info: "lo" };
  const bucket = s => BUCKET[s] || "lo";
  const sevTag = (p, sev) => el("span", { class: `sev ${sev || "low"}`, text: p ? `${p} ${sev}` : sev || "–" });
  const KIND = { ip: "Source IP", user: "Principal", ak: "AccessKey", asset: "Asset" };
  const VERDICT_TAG = { malicious: "hot", suspicious: "wait", benign: "ok" };
  // Plain-language request titles, as in the mockup ("Disable AccessKey ... owned by ...").
  const ACTION_TITLE = {
    "case.close_benign": "Close case as benign", "itsm.create_ticket": "Create ITSM ticket",
    "waf.ip_blacklist.add": "Block source IP", "waf.rate_limit.tighten": "Tighten WAF rate limit on",
    "ram.user.console_session.revoke": "Revoke console sessions of", "ram.access_key.disable": "Disable AccessKey",
    "ram.policy.detach": "Detach RAM policy from", "ecs.security_group.isolate": "Isolate ECS instance",
  };
  const callTarget = call => {
    const m = /^[^(]*\(([^,)]*)/.exec(call || "");
    return m ? m[1].split("=").pop().trim() : "";
  };
  const requestTitle = r => ACTION_TITLE[r.action] ? `${ACTION_TITLE[r.action]} ${callTarget(r.would_execute)}`.trim()
    : r.would_execute || r.action;

  // -- API ------------------------------------------------------------------------------------------------
  class LoginRequired extends Error {}
  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
    if (r.status === 401) { location.assign("/login"); throw new LoginRequired("login required"); }
    if (!r.ok) throw new Error(`${path} answered ${r.status}`);
    return r.json();
  }
  function showError(msg) {
    const b = byId("error");
    if (!b) return;
    b.hidden = !msg;
    b.textContent = msg || "";
  }
  function poll(fn, every = POLL_MS) {
    const run = async () => {
      if (!document.hidden) {
        try { await fn(); showError(""); } catch (e) {
          if (!(e instanceof LoginRequired)) showError(`Could not refresh this screen (${e.message}). Retrying in ${every / 1000} s.`);
        }
      }
      setTimeout(run, every);
    };
    return run();
  }

  // -- writes ---------------------------------------------------------------------------------------------
  const newKey = () => crypto.randomUUID();
  const canWrite = () => !!(shellData && shellData.meta && shellData.meta.writes);
  // {ok, status, data}. A refused write is a normal answer with a message, not an exception.
  async function post(path, payload, key, method = "POST") {
    let r;
    try {
      r = await fetch(path, {
        method, credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", Accept: "application/json", "Idempotency-Key": key,
                   "X-HyperSoar-CSRF": shellData && shellData.meta ? shellData.meta.csrf : "" },
        body: JSON.stringify(payload || {}),
      });
    } catch (e) { return { ok: false, status: 0, data: { detail: "network error, try again" } }; }
    if (r.status === 401) { location.assign("/login"); throw new LoginRequired("login required"); }
    let data = {};
    try { data = await r.json(); } catch (e) { data = {}; }
    return { ok: r.ok, status: r.status, data };
  }
  const why = res => {
    const d = res.data && res.data.detail;
    return typeof d === "string" ? d : `answered ${res.status}`;
  };
  function say(id, msg, bad) {
    const e = byId(id);
    if (!e) return;
    e.textContent = msg || "";
    e.classList.add("note");
    e.classList.toggle("bad", !!bad);
  }
  // A write that needs the password again (approve, reject, kill switch, revoke, integration settings). One
  // dialog, one key per opening: a double click or a retry after a network error is the same write.
  // o.noReason drops the reason box, o.reasonKey sends it under another name (an integration's version note),
  // o.extra adds inputs [{key, label, attrs, required}] whose values go into the body as typed.
  function confirmWrite(o) {
    const pw = el("input", { type: "password", id: "rw-pw", name: "password", autocomplete: "current-password", required: true, maxlength: 1024 });
    const reason = o.noReason ? null : el("textarea", { id: "rw-reason", name: "reason", rows: 3, maxlength: o.reasonMax || 500, required: o.reasonRequired ? true : null });
    const extra = (o.extra || []).map((x, i) => ({ ...x, input: el("input", { id: `rw-x${i}`, ...x.attrs }) }));
    const err = el("p", { class: "err", role: "alert" });
    const ok = el("button", { class: "btn pri", type: "submit", text: o.confirm });
    const cancel = el("button", { class: "btn ghost", type: "button", text: "Cancel" });
    const form = el("form", { class: "gate-form", novalidate: true },
      el("h2", { class: "h2", id: "rw-h", text: o.title }), o.text ? el("p", { class: "k", text: o.text }) : null,
      extra.map(x => [el("label", { for: x.input.id, text: x.label }), x.input]),
      reason ? [el("label", { for: "rw-reason", text: o.reasonLabel || (o.reasonRequired ? "Reason (required, kept in the audit trail)" : "Reason (optional, kept in the audit trail)") }), reason] : null,
      el("label", { for: "rw-pw", text: "Your password, to confirm it is you" }), pw, err,
      el("div", { class: "pill-row" }, ok, cancel));
    const dlg = el("dialog", { class: "rw", "aria-labelledby": "rw-h" }, form);
    body.append(dlg);
    const key = newKey();
    cancel.addEventListener("click", () => dlg.close());
    dlg.addEventListener("close", () => dlg.remove());
    form.addEventListener("submit", async ev => {
      ev.preventDefault();
      const r = reason ? reason.value.trim() : "";
      if (o.reasonRequired && r.length < 3) { err.textContent = "Write a reason of at least 3 characters."; reason.focus(); return; }
      const missing = extra.find(x => x.required && !x.input.value.trim());
      if (missing) { err.textContent = `Fill in ${missing.label.toLowerCase()}.`; missing.input.focus(); return; }
      if (!pw.value) { err.textContent = "Type your password."; pw.focus(); return; }
      ok.disabled = true;
      err.textContent = "";
      const payload = { ...o.body, password: pw.value };
      if (r) payload[o.reasonKey || "reason"] = r;
      for (const x of extra) payload[x.key] = x.input.value.trim() || null;
      try {
        const res = await post(o.path, payload, key, o.method);
        if (res.ok) { dlg.close(); o.done(res); return; }
        err.textContent = res.status === 403 && /re-authentication/.test(why(res)) ? "Wrong password." : why(res);
        pw.value = "";
        pw.focus();
      } finally { ok.disabled = false; }
    });
    dlg.showModal();
    (extra.length ? extra[0].input : o.reasonRequired ? reason : pw).focus();
  }
  // A plain write (assign, status, comment, ask AI): the button is disabled while it runs.
  async function quickWrite(btn, path, payload, key) {
    if (btn) btn.disabled = true;
    try { return await post(path, payload, key || newKey()); } finally { if (btn) btn.disabled = false; }
  }

  // -- shell: header, mode bar, footer --------------------------------------------------------------------
  let shellData = null;
  const TABS = [
    ["overview", "Overview", "/", null],
    ["map", "Threat map", "/map", null],
    ["cases", "Cases", "/cases", "cnt-cases"],
    ["approvals", "Approvals", "/approvals", "cnt-approvals"],
    ["automation", "Automation", "/automation", null],
    ["integrations", "Integrations", "/integrations", null],
    ["scenarios", "Scenario tests", "/scenarios", "cnt-scn", "sbx-only"],
  ];

  function buildShell() {
    const mark = sv("svg", { class: "mark", viewBox: "0 0 32 32", "aria-hidden": "true" });
    sv("path", { d: "M6 6.5 10 5v9.5h12V5l4 1.5v19L22 27v-9.5H10V27l-4-1.5z", fill: "#e3000f" }, mark);
    sv("rect", { x: 3, y: 12.5, width: 26, height: 2.4, fill: "#0b0b0c" }, mark);
    sv("rect", { x: 7, y: 12.5, width: 21, height: 2.4, fill: "#f4f4f4" }, mark);
    const header = el("header", { class: "top" },
      el("a", { class: "brand", href: "/", "aria-label": "HyperSoar home" }, mark, el("span", { class: "word", text: "HyperSoar" })),
      el("nav", { class: "tabs", "aria-label": "Screens" }, TABS.filter(t => !(t[4] === "sbx-only" && body.classList.contains("prod"))).map(([id, label, href, cnt, cls]) =>
        el("a", { href, class: cls, "aria-current": id === screen ? "page" : null }, label,
          cnt ? el("span", { class: "cnt", id: cnt }) : null))),
      el("div", { class: "top-r" },
        el("span", { class: "flag sbx-only", text: "Synthetic data" }),
        el("span", { class: "meta-item" }, el("span", { class: "dot", id: "led-dot" }), "Audit trail ", el("strong", { id: "led-txt", text: "–" })),
        el("span", { class: "meta-item num" }, el("span", { id: "clock", text: "--:--:--" }), " ", el("span", { id: "tzl", text: TZL })),
        el("form", { class: "who", method: "post", action: "/logout" },
          el("span", { id: "who", text: "" }), el("button", { class: "btn ghost", type: "submit", text: "Sign out" }))));
    const mode = el("div", { class: "mode", role: "status" },
      el("span", { class: "slice", "aria-hidden": "true" }),
      el("span", { class: "entity", id: "entity", text: "–" }), el("span", { class: "sep" }),
      el("span", { class: "env sbx sbx-only", text: "Sandbox" }), el("span", { class: "env prd prd-only", text: "Production" }),
      el("strong", { text: "Decisions are live" }),
      el("span", { class: "sbx-only mtx", text: "Seeding bot is generating attacks. Approvals and changes are recorded in the audit trail." }),
      el("span", { class: "prd-only mtx", text: "Approvals and changes are recorded in the audit trail. No cloud executor is connected yet." }),
      el("span", { class: "sp" }),
      el("span", { class: "kill", id: "kill", text: "Kill switch –" }));
    body.prepend(header, mode);
    body.append(el("footer", { class: "status num" },
      el("span", { id: "f-ingest", text: "Last ingest –" }), el("span", { text: "Temporal 1.32.2, mTLS" }),
      el("span", { id: "f-ai", text: "AI: 9router AI DECA" }), el("span", { id: "f-audit", text: "Audit trail –" }),
      el("span", { class: "sp" }), el("span", { id: "f-build", text: "" })));
    const tick = () => txt("clock", new Date(now()).toLocaleTimeString("en-GB", { timeZone: TZ, hour12: false }));
    tick();
    setInterval(tick, 1000);
  }

  function applyShell(s) {
    shellData = s;
    skew = ms(s.now) - Date.now() || 0;
    if (s.entity && s.entity.timezone) {
      TZ = s.entity.timezone;
      TZL = TZ_LABEL[TZ] || new Intl.DateTimeFormat("en-US", { timeZone: TZ, timeZoneName: "short" })
        .formatToParts(new Date()).find(p => p.type === "timeZoneName").value;
      txt("tzl", TZL);
    }
    body.classList.toggle("prod", s.mode === "production");
    const killed = !!(s.kill_switch && s.kill_switch.global_engaged);
    body.classList.toggle("killed", killed);
    txt("kill", killed ? "Kill switch ON · all automatic actions stopped" : "Kill switch off");
    document.querySelectorAll("[data-ks-state]").forEach(e => { e.textContent = killed ? "On" : "Off"; });
    document.querySelectorAll("[data-ks-btn]").forEach(e => {
      e.textContent = killed ? "Turn off kill switch" : "Turn on kill switch";
      e.disabled = !canWrite();
      e.title = canWrite() ? "" : "Writes are not configured on this console";
    });
    txt("entity", s.entity ? s.entity.name : s.entity_id || "No entity configured");
    txt("who", s.meta ? s.meta.user : "");
    const cnt = (id, v, hot) => { const e = txt(id, v); if (e) e.className = hot ? "cnt hot" : "cnt"; };
    cnt("cnt-cases", n(s.open_cases), s.open_cases > 0);
    cnt("cnt-approvals", n(s.pending), s.pending > 0);
    cnt("cnt-scn", s.scenarios ? `${s.scenarios.passed}/${s.scenarios.total}` : "–", s.scenarios && s.scenarios.passed < s.scenarios.total);
    const led = s.ledger || {};
    const dot = byId("led-dot");
    if (dot) dot.className = led.ok === false ? "dot bad" : "dot ok";
    txt("led-txt", led.ok === true ? "valid" : led.ok === false ? "broken" : "checking");
    txt("f-ingest", s.last_ingest ? `Last ingest ${ago(s.last_ingest)} ago` : "No alerts ingested yet");
    txt("f-ai", s.ai ? `AI: 9router AI DECA · ${s.ai.model || "no model"}${s.ai.target === "mock" ? " (mock)" : ""}` : "AI: not configured");
    txt("f-audit", led.checked_at ? `Audit trail ${n(led.entries)} entries, checked ${hm(led.checked_at)} ${TZL}` : "Audit trail not checked yet");
    txt("f-build", s.meta && s.meta.sha ? `build ${s.meta.sha}` : "");
  }
  const refreshShell = async () => applyShell(await api("/api/shell"));

  // -- integrations list (overview, automation) -----------------------------------------------------------
  const INTEG = { lark: ["LK", "Lark"], jira: ["JR", "Jira"], ai: ["9R", "9router AI DECA"], webhook: ["WH", "Webhook source"],
    syslog: ["SY", "Syslog / CEF source"], sls: ["AC", "Alibaba Cloud SLS"] };
  const HEALTH = { healthy: ["ok", "Healthy"], error: ["hot", "Errors"], untested: ["wait", "Not tested"], off: ["", "Off"] };
  function integItems(list, long) {
    const items = (list || []).map(i => {
      const [logo, name] = INTEG[i.name] || ["··", i.name];
      const [cls, label] = HEALTH[i.health] || ["", i.health];
      let d = i.detail;
      if (long) {
        const last = i.last_call ? `Last ${i.last_call.op} ${ago(i.last_call.at)} ago${i.last_call.ref ? `, ${i.last_call.ref}` : ""}.` : "No calls yet.";
        d = `${i.detail}. ${last} ${plural(i.calls_24h, "call")}, ${plural(i.errors_24h, "error")} in 24 h${i.p95_ms !== null ? `, p95 ${dur(i.p95_ms)}` : ""}.`;
      } else if (i.p95_ms !== null) d = `${i.detail} · p95 ${dur(i.p95_ms)}`;
      return el("li", {}, el("span", { class: "logo", text: logo }),
        el("span", { class: "nm", text: long ? `${name} · config v${i.version}` : name }), el("span", { class: "d", text: d }),
        el("span", { class: "r" }, el("span", { class: `tag ${cls}`, text: label }),
          i.target === "mock" ? el("span", { class: "code sbx-only", text: i.name === "ai" ? "mock model" : "mock endpoint" }) : null));
    });
    if (!items.length) items.push(el("li", {}, el("span", { class: "d", text: "No integration configured for this install. Set one up with hypersoar integration." })));
    return items;
  }

  // -- live attack map (overview and threat map) ----------------------------------------------------------
  const WINDOW_TEXT = { "15m": "15 minutes", "1h": "hour", "24h": "24 hours" };
  function liveMap(card) {
    const war = card.hasAttribute("data-war");
    const svg = sv("svg", { class: "mapsvg", viewBox: "0 0 1200 508", preserveAspectRatio: "xMidYMid meet", role: "img", "aria-label": "Map of alert origins" });
    card.prepend(svg);
    sv("image", { href: "/static/worldmap.svg", x: 0, y: 0, width: 1200, height: 508, class: "land" }, svg);
    const gBase = sv("g", { class: "routes" }, svg);
    const gArc = sv("g", {}, svg);
    const gOrg = sv("g", {}, svg);
    const gTgt = sv("g", { class: "tgt" }, svg);
    const feedEl = $(card.dataset.feed || "#none");
    const olist = $(card.dataset.origins || "#none");
    const drawer = $(".drawer", card);
    let target = [915.5, 317.2];
    let targetKey = "";
    let data = null;
    let selected = null;
    let opener = null;
    let replay = [];
    let ri = 0;
    let fresh = [];
    const seenArcs = new Set();
    const seenFeed = new Set();

    const arcD = xy => {
      const [x1, y1] = xy;
      const [x2, y2] = target;
      const dx = x2 - x1;
      const dy = y2 - y1;
      const d = Math.hypot(dx, dy);
      return `M${x1} ${y1}Q${(x1 + x2) / 2 - dy * 0.12} ${(y1 + y2) / 2 - d * 0.32} ${x2} ${y2}`;
    };
    const orgClass = o => (o.n && o.hi / o.n >= 0.4 ? "hi" : o.n && o.hi / o.n >= 0.2 ? "md" : "lo");

    function drawTarget(entity) {
      const key = JSON.stringify(entity || {});
      if (key === targetKey) return;
      targetKey = key;
      if (entity && Array.isArray(entity.map_xy)) target = entity.map_xy;
      gTgt.replaceChildren();
      [0, 1].forEach(i => sv("circle", { class: i ? "ring p p2" : "ring p", cx: target[0], cy: target[1], r: 10 }, gTgt));
      sv("circle", { cx: target[0], cy: target[1], r: 4, fill: "#f4f4f4" }, gTgt);
      sv("text", { x: target[0] + 14, y: target[1] + 22, text: entity ? entity.region_label : "Cloud region" }, gTgt);
      sv("text", { x: target[0] + 14, y: target[1] + 36, class: "sub", text: entity ? `${entity.region || entity.short} · ${plural(entity.assets, "asset")}` : "" }, gTgt);
    }

    function openDrawer(o, g) {
      if (!drawer) return;
      opener = document.activeElement;
      selected = o.city;
      gOrg.querySelectorAll(".sel").forEach(x => x.classList.remove("sel"));
      if (g) g.classList.add("sel");
      $("h2", drawer).textContent = o.city || "Unknown origin";
      $(".sub", drawer).textContent = `${[o.asn, o.as_name].filter(Boolean).join(" ")}${o.tor ? " · Tor exit" : ""} · ${plural(o.n, "alert")} in this window`;
      fill($("ul", drawer), o.cases.length ? o.cases.map(c => el("li", {},
        el("span", { class: "pill-row" }, el("span", { class: `sev ${c.sev}`, text: c.sev }), el("span", { class: "code", text: c.case_id })),
        el("a", { class: "ttl", href: `/cases#${c.case_id}`, text: c.title }),
        el("span", { class: "k", text: c.status === "open" ? "Open case" : "Closed case" })))
        : [el("li", {}, el("span", { class: "ttl", text: "No case linked in this window" }),
          el("span", { class: "k", text: `${plural(o.n, "alert")} from this origin.` }))]);
      drawer.classList.add("open");
      $("button", drawer).focus();
    }
    if (drawer) {
      $("button", drawer).addEventListener("click", () => {
        drawer.classList.remove("open");
        selected = null;
        gOrg.querySelectorAll(".sel").forEach(x => x.classList.remove("sel"));
        if (opener && opener.focus) opener.focus();
      });
    }

    function drawOrigins() {
      const os = data.origins;
      const max = Math.max(1, ...os.map(o => o.n));
      const labelled = new Set(os.slice(0, war ? 40 : 6).map(o => o.city));
      gBase.replaceChildren();
      gOrg.replaceChildren();
      os.forEach(o => {
        const r = sv("path", { d: arcD(o.xy), class: `arc base ${orgClass(o) === "hi" ? "hi" : "md"}` }, gBase);
        r.style.strokeWidth = (0.4 + (o.n / max) * 1.4).toFixed(2);
        const g = sv("g", { class: `org ${orgClass(o)}${o.city === selected ? " sel" : ""}`, tabindex: 0, role: "button",
          "aria-label": `${o.city}, ${plural(o.n, "alert")}. Open related cases.` }, gOrg);
        const k = Math.sqrt(o.n / max);
        sv("circle", { class: "halo", cx: o.xy[0], cy: o.xy[1], r: (4 + 12 * k).toFixed(1) }, g);
        sv("circle", { class: "pin", cx: o.xy[0], cy: o.xy[1], r: 2.2 }, g);
        if (labelled.has(o.city)) {
          const left = o.xy[0] > 860;
          sv("text", { x: (o.xy[0] + (left ? -1 : 1) * (6 + 6 * k)).toFixed(1), y: o.xy[1] + 4, "text-anchor": left ? "end" : "start", text: o.city }, g);
        }
        g.addEventListener("click", () => openDrawer(o, g));
        g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(o, g); } });
      });
      const top = os[0];
      svg.setAttribute("aria-label", `Map of ${plural(data.total, "alert")} in the last ${WINDOW_TEXT[data.window]}` +
        (top ? `. Largest origin: ${top.city} with ${plural(top.n, "alert")}.` : "."));
    }

    function drawSide() {
      if (olist) {
        const os = data.origins.slice(0, 8);
        const max = Math.max(1, ...os.map(o => o.n));
        fill(olist, os.length ? os.map(o => {
          const li = el("li", { class: orgClass(o) === "hi" ? "hi" : null, tabindex: 0, role: "button" },
            el("span", {}, `${o.city} `, el("span", { class: "code", text: o.asn })), el("span", { class: "n", text: n(o.n) }),
            el("span", { class: "bar" }, width(el("span", { class: "fill" }), o.n / max)));
          const open = () => openDrawer(o, [...gOrg.children].find(g => g.getAttribute("aria-label").startsWith(`${o.city},`)));
          li.addEventListener("click", open);
          li.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
          return li;
        }) : el("li", { class: "empty-note", text: "No alert with a known origin in this window." }));
      }
      if (byId("wm-cat")) {
        fill("wm-cat", data.categories.length ? data.categories.map(c => el("li", {}, el("span", { text: c.category }),
          el("span", { class: "n num", text: `${c.pct}%` }),
          el("span", { class: "bar" }, width(el("span", { class: bucket(c.sev) === "hi" ? "hi" : null }), c.pct / 100))))
          : el("li", { class: "empty-note", text: "No alerts in this window." }));
      }
      if (byId("wm-assets")) {
        const max = Math.max(1, ...data.assets.map(a => a.n));
        fill("wm-assets", data.assets.length ? data.assets.map((a, i) => el("li", { class: a.hi ? "hot" : null },
          el("span", { class: "rk", text: String(i + 1).padStart(2, "0") }), el("span", { class: "nm", text: a.asset }),
          el("span", { class: "num", text: n(a.n) }), el("span", { class: "bar" }, width(el("span", { class: "fill" }), a.n / max))))
          : el("li", {}, el("span", { class: "empty", text: "No asset hit in this window." })));
      }
      txt("wm-total", n(data.total));
      txt("wm-origins", n(data.origins.length));
      txt("wm-cases", n(new Set(data.origins.flatMap(o => o.cases.map(c => c.case_id))).size));
    }

    function feedItem(f) {
      const b = bucket(f.sev);
      return el("li", { class: b },
        el("span", { class: "tm", text: hms(f.at) }),
        f.case_id ? el("a", { class: "nm", href: `/cases#${f.case_id}`, text: f.rule }) : el("span", { class: "nm", text: f.rule }),
        el("span", { class: `sev ${f.sev}`, text: f.sev }),
        el("span", { class: "where", text: `${f.src || "no source"} · ${f.city || "unknown origin"} → ${f.asset || "–"}${f.case_id ? ` · ${f.case_id}` : ""}` }));
    }
    function drawFeed(feed) {
      if (!feedEl) return;
      const max = war ? 18 : 7;
      if (!seenFeed.size) {
        fill(feedEl, feed.length ? feed.slice(0, max).map(feedItem) : el("li", { class: "empty-note", text: "No alerts yet." }));
      } else {
        const add = feed.filter(f => !seenFeed.has(f.id)).reverse();
        if (add.length && feedEl.querySelector(".empty-note")) feedEl.replaceChildren();
        add.forEach(f => feedEl.prepend(feedItem(f)));
        while (feedEl.children.length > max) feedEl.lastChild.remove();
      }
      feed.forEach(f => seenFeed.add(f.id));
    }

    function fire() {
      const a = fresh.shift() || (replay.length ? replay[ri++ % replay.length] : null);
      if (!a) return;
      const sev = bucket(a.sev);
      const d = arcD(a.xy);
      const tr = sv("path", { d, class: `arc trail ${sev}`, pathLength: 1 }, gArc);
      const hd = sv("path", { d, class: `arc head ${sev}`, pathLength: 1 }, gArc);
      setTimeout(() => {
        const h = sv("circle", { class: "hit", cx: target[0], cy: target[1], r: 8 }, gTgt);
        if (sev !== "hi") h.style.stroke = sev === "md" ? "#f4f4f4" : "#8a8a8e";
        setTimeout(() => h.remove(), 1000);
      }, 1300);
      setTimeout(() => { tr.remove(); hd.remove(); }, 3300);
    }
    if (!reduce) setInterval(fire, war ? 650 : 1100);

    return {
      update(d, entity) {
        drawTarget(entity);
        const first = !data || data.window !== d.window;
        data = d;
        if (first) {
          seenArcs.clear();
          fresh = [];
          ri = 0;
        } else {
          fresh.push(...d.arcs.filter(a => !seenArcs.has(a.id)).reverse());
        }
        d.arcs.forEach(a => seenArcs.add(a.id));
        replay = d.arcs.slice().reverse();  // oldest first: the loop replays the window in the order it happened
        drawOrigins();
        drawSide();
        drawFeed(d.feed);
        if (first && !reduce) for (let i = 0; i < (war ? 6 : 4); i++) setTimeout(fire, i * 250);
      },
    };
  }

  // -- 01 overview ----------------------------------------------------------------------------------------
  function drawChart(timeline) {
    const c = byId("chart");
    if (!c) return;
    const title = c.querySelector("title");
    c.replaceChildren(title);
    const tot = timeline.map(h => h.high + h.medium + h.low);
    const max = Math.max(4, ...tot) * 1.1;
    const w = 960 / timeline.length;
    [55, 110, 165].forEach(y => sv("line", { class: "grid", x1: 0, x2: 960, y1: y, y2: y }, c));
    timeline.forEach((h, i) => {
      let y = 220;
      [["b-lo", h.low], ["b-md", h.medium], ["b-hi", h.high]].forEach(([k, v]) => {
        const ht = (v / max) * 210;
        y -= ht;
        if (ht > 0) sv("rect", { class: k, x: (i * w + 8).toFixed(1), width: (w - 16).toFixed(1), y: y.toFixed(1), height: ht.toFixed(1) }, c);
      });
    });
    sv("rect", { class: "now", x: ((timeline.length - 1) * w + 4).toFixed(1), width: (w - 8).toFixed(1), y: 4, height: 216 }, c);
    title.textContent = `Hourly alert volume for the last 24 hours, peak ${n(Math.max(0, ...tot))} alerts in one hour`;
    fill("axis", timeline.map((h, i) => el("span", { text: i % 3 === 0 ? hm(h.hour) : "" })));
  }

  function verdictCell(v, conf) {
    return v ? [el("span", { class: `tag ${VERDICT_TAG[v] || ""}`, text: cap(v) }), el("div", { class: "small", text: conf !== null ? conf.toFixed(2) : "" })]
      : el("span", { class: "k", text: "No verdict yet" });
  }
  const BROKER = {
    pending_approval: ["wait", "Needs approval"], validated: ["act", "Passed policy"], rejected: ["hot", "Blocked by policy"],
    executed: ["ok", "Executed"], expired: ["", "Expired"], approved: ["ok", "Approved"], denied: ["", "Rejected"],
    rolled_back: ["", "Revoked"],
  };
  function brokerTag(b) {
    if (!b) return el("span", { class: "k", text: "–" });
    const [cls, label] = BROKER[b.status] || ["", cap(b.status)];
    return [el("span", { class: `tag ${cls}`, text: label }), " ", el("span", { class: "tag lv", text: b.level })];
  }

  function overview() {
    const map = liveMap($(".mapcard[data-live]"));
    const flow = (label, v, max, cls) => el("li", { class: cls || (v ? null : "zero") }, el("span", { class: "lbl", text: label }),
      el("span", { class: "n num", text: n(v) }),
      el("span", { class: "bar" }, width(el("span", { class: "fill" }), v ? Math.log10(v + 1) / Math.log10(max + 1) : 0)));
    poll(async () => {
      const [o, m] = await Promise.all([api("/api/overview"), api("/api/map?w=1h")]);
      const s = o.stats;
      txt("s-alerts", n(s.alerts_24h));
      txt("s-alerts-t", `${n(s.events_24h)} raw events behind them`);
      txt("s-cases", n(s.open_cases));
      txt("s-cases-t", `${n(s.critical_cases)} critical · ${plural(s.alerts_in_open, "alert")} grouped`);
      txt("s-decisions", n(s.decisions_24h));
      txt("s-pending", n(s.pending));
      txt("s-pending-t", s.oldest_pending ? `Oldest waiting ${ago(s.oldest_pending)}` : "Nothing waiting");
      txt("s-median", secs(s.median_verdict_s));
      txt("r-alerts", n(s.alerts_1h));
      const max = Math.max(1, s.events_24h, s.alerts_24h);
      fill("flow", flow("Log events", s.events_24h, max), flow("Alerts after dedup", s.alerts_24h, max),
        flow("Cases opened", s.cases_24h, max), flow("Broker decisions", s.decisions_24h, max),
        flow("Blocked by policy", s.blocked_24h, max, s.blocked_24h ? "hot" : "zero"), flow("Executed", s.executed_24h, max));
      drawChart(o.timeline);
      fill("ov-cases", o.open_cases.length ? o.open_cases.map(c => el("tr", {},
        el("td", {}, sevTag(c.p, c.severity)),
        el("td", {}, el("div", { class: "ttl" }, el("a", { href: `/cases#${c.case_id}`, text: c.title })),
          el("div", { class: "mono", text: `${c.case_id} · ${c.primary.value || "–"} · ${ago(c.last_seen_at)} ago` })),
        el("td", { class: "num", text: n(c.alerts) }),
        el("td", {}, verdictCell(c.verdict, c.confidence)),
        el("td", {}, brokerTag(c.broker)),
        el("td", { class: "mono", text: c.jira || "–" })))
        : el("tr", {}, el("td", { colspan: 6, class: "k", text: "No open case." })));
      const rmax = Math.max(1, ...o.top_rules.map(r => r.n));
      fill("rules", o.top_rules.length ? o.top_rules.map((r, i) => el("li", { class: bucket(r.severity) === "hi" ? "hot" : null },
        el("span", { class: "rk", text: String(i + 1).padStart(2, "0") }), el("span", { class: "nm", text: r.rule_id }),
        el("span", { class: "num", text: n(r.n) }), el("span", { class: "bar" }, width(el("span", { class: "fill" }), r.n / rmax))))
        : el("li", {}, el("span", { class: "empty", text: "No alerts in the last 24 hours." })));
      fill("integ", integItems(o.integrations, false));
      txt("map-sub", `${plural(m.total, "alert")} in the last hour, ${n(m.placed)} with a known origin`);
      map.update(m, shellData && shellData.entity);
    });
  }

  // -- 02 threat map --------------------------------------------------------------------------------------
  function threatMap() {
    const card = $(".mapcard[data-live]");
    const map = liveMap(card);
    let w = "1h";
    const seg = $(card.dataset.window);
    const load = async () => {
      const m = await api(`/api/map?w=${encodeURIComponent(w)}`);
      if (m.window !== w) return;
      const region = shellData && shellData.entity ? shellData.entity.region_label : "the cloud region";
      txt("map-sub", `Alerts reaching ${region} in the last ${WINDOW_TEXT[w]}. ${plural(m.arcs.length, "arc")} replayed in order (max 200), new alerts fire first.`);
      map.update(m, shellData && shellData.entity);
    };
    seg.addEventListener("click", e => {
      const b = e.target.closest("button[data-w]");
      if (!b || b.dataset.w === w) return;
      w = b.dataset.w;
      seg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      load().catch(err => showError(`Could not load this window (${err.message}).`));
    });
    poll(load);
  }

  // -- 03 cases -------------------------------------------------------------------------------------------
  const GLYPH = {
    ip: g => sv("path", { class: "glyph", d: "M-68 -8L-60 0L-68 8L-76 0Z" }, g),
    user: g => sv("circle", { class: "glyph", cx: -68, cy: 0, r: 7 }, g),
    ak: g => sv("path", { class: "glyph", d: "M-72 -5a5 5 0 1 0 .1 0ZM-68 -1H-58V3H-61V6H-64V3H-68Z" }, g),
    asset: g => sv("rect", { class: "glyph", x: -75, y: -6, width: 14, height: 12 }, g),
  };
  const REL = { targets: "targets", uses_key: "uses", moves_to: "moves to", authenticates_as: "logs in as", owns_key: "owns" };

  function attackPath(d) {
    const steps = d.steps.filter(s => s.src && s.dst);
    const tactics = [];
    steps.forEach(s => { const t = s.tactic_name || s.tactic || "Unmapped"; if (!tactics.includes(t)) tactics.push(t); });
    const cols = 1 + tactics.length;
    const W = Math.max(1200, 240 * cols);
    const nodes = new Map();
    const perCol = Array.from({ length: cols }, () => []);
    const place = (ent, col, at, cls) => {
      const k = `${ent.kind}:${ent.value}`;
      if (!nodes.has(k)) { nodes.set(k, { ...ent, col, row: perCol[col].length, at, cls, hits: [] }); perCol[col].push(k); }
      return nodes.get(k);
    };
    const edges = steps.map((s, i) => {
      const col = 1 + tactics.indexOf(s.tactic_name || s.tactic || "Unmapped");
      const a = place(s.src, i === 0 || s.src.kind === "ip" ? 0 : Math.max(0, col - 1), i, i === 0 ? "src" : "hit");
      const b = place(s.dst, col, i, "hit");
      b.hits.push(s.outcome);
      return { a, b, s, i };
    });
    const rows = Math.max(1, ...perCol.map(c => c.length));
    const H = Math.max(400, 96 * rows + 150);
    const yc = 40 + (H - 40) / 2;
    nodes.forEach(nd => {
      nd.x = 240 * nd.col + 100;
      nd.y = Math.round(yc + (nd.row - (perCol[nd.col].length - 1) / 2) * 96);
      if (nd.cls === "hit" && nd.hits.length && nd.hits.every(o => o === "blocked")) nd.cls = "amb";
    });
    const STEP = 1.4;
    const delay = i => `${(0.2 + i * STEP).toFixed(1)}s`;
    const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, role: "img",
      "aria-label": `Attack path for ${d.case.case_id}: ${steps.map(s => `${s.title} (${s.outcome})`).join(", then ") || "no linked steps"}.` });
    const defs = sv("defs", {}, svg);
    const pat = sv("pattern", { id: "hatch", width: 8, height: 8, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" }, defs);
    sv("rect", { width: 4, height: 8, fill: "#e3000f" }, pat);
    const tac = sv("g", { class: "tac" }, svg);
    ["Source", ...tactics].forEach((t, i) => {
      sv("text", { x: 20 + 240 * i, y: 24, text: clip(t, 26) }, tac);
      if (i) sv("line", { x1: 240 * i - 20, y1: 12, x2: 240 * i - 20, y2: H - 10 }, tac);
    });
    edges.forEach(({ a, b, s, i }) => {
      let p;
      if (a.col < b.col) { const m = (a.x + 88 + b.x - 88) / 2; p = `M${a.x + 88} ${a.y}C${m} ${a.y} ${m} ${b.y} ${b.x - 88} ${b.y}`; }
      else if (a.col === b.col) p = a.y < b.y ? `M${a.x} ${a.y + 24}V${b.y - 24}` : `M${a.x} ${a.y - 24}V${b.y + 24}`;
      else { const top = Math.min(a.y, b.y) - 60; p = `M${a.x} ${a.y - 24}C${a.x} ${top} ${b.x} ${top} ${b.x} ${b.y - 24}`; }
      const g = sv("g", {}, svg);
      g.style.setProperty("--d", delay(i));
      sv("path", { class: "ed", d: p }, g);
      sv("path", { class: s.outcome === "blocked" ? "run amb" : "run", pathLength: 1, d: p }, g);
      sv("path", { class: "pk", pathLength: 1, d: p }, g);
    });
    const origin = d.case.origin || {};
    nodes.forEach(nd => {
      const g = sv("g", { class: `nd ${nd.cls}`, transform: `translate(${nd.x} ${nd.y})` }, svg);
      g.style.setProperty("--d", delay(nd.at));
      sv("title", { text: `${KIND[nd.kind] || nd.kind}: ${nd.value}` }, g);
      if (nd.cls === "hit") sv("rect", { class: "ring", x: -88, y: -24, width: 176, height: 48 }, g);
      sv("rect", { class: "core", x: -88, y: -24, width: 176, height: 48 }, g);
      (GLYPH[nd.kind] || GLYPH.asset)(g);
      sv("text", { x: -50, y: -3, text: clip(nd.value, 18) }, g);
      const sub = nd.kind === "ip" && nd.cls === "src" ? [origin.city, origin.asn].filter(Boolean).join(" · ") || "Source IP"
        : nd.cls === "amb" ? `${KIND[nd.kind] || nd.kind} · blocked` : KIND[nd.kind] || nd.kind;
      sv("text", { class: "t2", x: -50, y: 13, text: clip(sub, 22) }, g);
    });
    edges.filter(e => e.s.outcome === "blocked").forEach(({ b, s, i }) => {
      const g = sv("g", { class: "stop" }, svg);
      g.style.setProperty("--d", delay(i + 0.6));
      sv("rect", { x: b.x - 88, y: b.y + 30, width: 176, height: 10, fill: "url(#hatch)" }, g);
      sv("text", { x: b.x - 88, y: b.y + 56, text: clip(`Blocked: ${s.title}`, 32) }, g);
    });
    if (d.also_in.length) {
      const x = d.also_in[0];
      const g = sv("g", { class: "xcase" }, svg);
      g.style.setProperty("--d", delay(steps.length));
      sv("rect", { x: 20, y: H - 60, width: 160, height: 40 }, g);
      sv("text", { x: 32, y: H - 44, text: `Also in ${x.case_id}` }, g);
      sv("text", { class: "t2", x: 32, y: H - 28, text: `same ${x.match}, ${ago(x.opened_at)} ago` }, g);
    }
    return { svg, total: 0.2 + steps.length * STEP + 1 };
  }

  function replay(wrap) {
    const lm = $(".lm", wrap);
    wrap.classList.remove("play");
    lm.classList.remove("play");
    void wrap.offsetWidth;  // restart the CSS animations
    wrap.classList.add("play");
    lm.classList.add("play");
  }

  function renderCase(d) {
    const c = d.case;
    const pend = d.requests.some(r => r.status === "pending_approval");
    txt("c-id", c.case_id);
    fill("c-pills", el("span", { class: "eyebrow mono", id: "c-id", text: c.case_id }), sevTag(c.p, c.severity),
      c.status === "closed" ? el("span", { class: "tag", text: `Closed${c.close_reason ? ` · ${clip(c.close_reason, 40)}` : ""}` })
        : pend ? el("span", { class: "tag wait", text: "Waiting for approval" })
          : c.status === "waiting" ? el("span", { class: "tag wait", text: "Waiting" }) : el("span", { class: "tag", text: "Open" }),
      el("span", { class: "sp" }), el("span", { class: "k", text: "Jira" }), el("span", { class: "mono", text: d.jira ? d.jira.key : "none yet" }),
      el("span", { class: "k", text: "Lark" }), el("span", { class: "mono", text: plural(d.lark.messages, "message") }));
    txt("c-title", c.title);
    fill("c-keys", c.keys.map(k => el("span", { class: "tag", text: `${KIND[k.kind] || k.kind} ${k.value}` })),
      c.assets.map(a => el("span", { class: "tag", text: a })));
    const reached = d.steps.filter(s => s.outcome !== "blocked");
    const blocked = d.steps.filter(s => s.outcome === "blocked");
    const spanS = (ms(c.closed_at || c.last_seen_at) - ms(c.opened_at)) / 1000;
    const score = (k, v, t, cls) => el("div", {}, el("span", { class: "k", text: k }), el("span", { class: cls || "v", text: v }), el("span", { class: "k", text: t }));
    fill("c-score",
      score("Priority", c.p, `${cap(c.severity)} severity × criticality ${c.criticality}`, "v red"),
      score("Alerts in this case", n(c.alerts), `From ${plural(c.sources.length, "source")}: ${c.sources.join(", ")}`, "v num"),
      score("Time span", `${hm(c.opened_at)} → ${hm(c.closed_at || c.last_seen_at)}`, `${span(spanS)}, ${c.status === "closed" ? "closed" : "still open"}`, "v num"),
      score("Furthest reach", reached.length ? reached[reached.length - 1].tactic_name || "–" : "–",
        blocked.length ? `${plural(blocked.length, "step")} blocked` : "Nothing blocked"));

    const wrap = byId("ap");
    const ap = attackPath(d);
    fill("lm", ap.svg);
    wrap.style.setProperty("--total", `${ap.total.toFixed(1)}s`);
    txt("ap-span", d.steps.length ? `${hms(d.steps[0].at)} → ${hms(d.steps[d.steps.length - 1].at)} ${TZL}` : "No steps");
    fill("steps", d.steps.length ? d.steps.map((s, i) => {
      const li = el("li", { class: s.outcome === "blocked" ? "blk" : null },
        el("span", { class: "tm", text: hms(s.at) }),
        el("span", { class: "ttl" }, s.title, s.technique ? el("span", { class: "tech", text: s.technique }) : null),
        el("span", { class: "d", text: `Rule ${s.rule}. ${s.src && s.dst ? `${KIND[s.src.kind] || s.src.kind} ${s.src.value} ${REL[s.rel] || s.rel} ${s.dst.value}. ` : ""}${plural(s.events, "event")}, ${s.outcome}.` }));
      li.style.setProperty("--d", `${(0.2 + i * 1.4).toFixed(1)}s`);
      return li;
    }) : el("li", { class: "empty-note", text: "No attack step recorded for this case." }));
    if (reduce) { wrap.classList.add("play"); $(".lm", wrap).classList.add("play"); } else replay(wrap);

    const counts = {};
    d.alerts.forEach(a => a.match.forEach(m => { counts[m] = (counts[m] || 0) + 1; }));
    const parts = Object.entries(counts).map(([m, k]) => [el("strong", { text: `Same ${m}` }), ` on ${plural(k, "alert")}`]);
    fill("why", parts.length ? parts.flatMap((p, i) => (i ? [" and ", ...p] : p)) : "The first alert opened this case.",
      parts.length ? " within the 30 min window." : "",
      ` Priority is the highest severity (${c.severity}) times asset criticality (${c.criticality}).`);
    txt("g1-sub", plural(c.alerts, "alert"));
    fill("grp", d.alerts.map(a => el("li", {}, el("span", { class: "mono", text: hms(a.at) }), el("span", { class: "nm mono", text: a.rule }),
      el("span", { class: `sev ${a.sev}`, text: a.sev }), el("span"),
      el("span", { class: "r", text: a.match.length ? `match: ${a.match.join(", ")}` : "opened the case" }))));

    const ai = d.ai;
    txt("v-model", ai && ai.model ? `9router AI DECA · ${ai.model}` : "9router AI DECA");
    const vv = txt("v-v", ai ? cap(ai.verdict) : "No verdict yet");
    vv.style.color = ai && ai.verdict === "benign" ? "var(--ok)" : ai ? "" : "var(--tx-3)";
    txt("v-c", ai && ai.confidence !== null ? ai.confidence.toFixed(2) : "–");
    width(byId("v-bar"), ai ? ai.confidence : 0);
    fill("v-ev", ai && ai.evidence_refs.length ? ai.evidence_refs.map(x => el("li", { text: x })) : el("li", { text: "No evidence cited." }));
    txt("v-why", ai && ai.rationale ? ai.rationale : "");

    const trace = d.trace.slice().reverse();
    let no = 0;
    fill("trace", trace.length ? trace.flatMap(t => [
      ...t.attempts.map(a => el("li", {}, el("span", { class: "no", text: String(++no) }), el("span", { class: "tool", text: `9router ${a.model}` }),
        el("span", { class: "k num", text: dur(a.ms) }),
        el("span", { class: "out", text: a.ok ? `Answer ${a.schema_ok ? "matches" : "does not match"} the verdict schema · ${plural(a.tokens, "token")}` : `Failed: ${a.error || "no answer"}` }),
        el("span", { class: "meta" }, el("span", { text: t.prompt_version || "" }), el("a", { href: "/automation", text: `audit #${t.seq}` })))),
      el("li", {}, el("span", { class: "no", text: String(++no) }), el("span", { class: "tool", text: t.type === "ai.escalated" ? "escalated" : "verdict" }),
        el("span", { class: "k num", text: hms(t.at) }),
        el("span", { class: "out", text: `${cap(t.verdict) || "No verdict"}${t.confidence !== null && t.confidence !== undefined ? ` ${t.confidence.toFixed(2)}` : ""}.${t.escalated ? ` Escalated: ${t.escalated}.` : ""}${t.fallback_used ? " Fallback model used." : ""}` }),
        el("span", { class: "meta" }, el("span", { text: `${t.model || ""}${t.target === "mock" ? " (mock)" : ""}` }), el("a", { href: "/automation", text: `audit #${t.seq}` }))),
    ]) : el("li", { class: "empty-note", text: "No AI triage recorded for this case yet." }));

    const CALL = { ok: ["ok", "Done"], duplicate: ["", "Duplicate skipped"], error: ["hot", "Error"] };
    const rows = [
      ...d.calls.map(x => { const [cls, label] = CALL[x.status] || ["", cap(x.status)];
        return el("tr", {}, el("td", { class: "mono", text: x.op }), el("td", {}, "Automatic ", el("span", { class: "tag lv", text: "L0" })),
          el("td", {}, el("span", { class: `tag ${cls}`, text: label }), " ", el("span", { class: "mono", text: x.ref || "" }),
            el("div", { class: "small", text: `${hms(x.at)} · ${x.target}` }))); }),
      ...d.requests.map(r => {
        const [cls, label] = BROKER[r.status] || ["", cap(r.status)];
        const note = r.status === "rejected" ? r.reasons[0] : r.rollback_at ? `Would expire ${hm(r.rollback_at)} ${TZL}`
          : r.status === "pending_approval" && r.expires_at ? `Request expires ${hm(r.expires_at)} ${TZL}` : r.would_execute;
        return el("tr", {}, el("td", { class: "mono", text: r.action }), el("td", {}, `${r.level_text} `, el("span", { class: "tag lv", text: r.level })),
          el("td", {}, r.status === "pending_approval" ? el("a", { class: `tag ${cls}`, href: `/approvals#${r.id}`, text: label }) : el("span", { class: `tag ${cls}`, text: label }),
            note ? el("div", { class: "small", text: note }) : null));
      }),
    ];
    fill("resp", rows.length ? rows : el("tr", {}, el("td", { colspan: 3, class: "k", text: "No broker decision yet." })));

    renderTriage(d);

    const req = d.requests.find(r => r.status === "pending_approval") || d.requests[d.requests.length - 1];
    txt("pol-sub", req ? req.action : "");
    const li = (cls, a, b) => el("li", { class: cls }, el("span", { text: a }), el("span", { class: "v", text: b }));
    const killed = shellData && shellData.kill_switch && shellData.kill_switch.global_engaged;
    fill("pol", !req ? li("pend", "No action proposed for this case", "–")
      : req.status === "rejected" ? (req.reasons.length ? req.reasons : ["Rejected by the broker"]).map(r => li("no", r, "blocked"))
        : [li(null, "Target is not on the protected list", "protected.yaml"),
          li(killed ? "no" : null, killed ? "Kill switch is on" : "Kill switch is off", "checked by the broker"),
          li(null, "Rate limit for this action", "within limit"),
          li(null, "AI verdict has evidence and is above 0.80", ai && ai.confidence !== null ? ai.confidence.toFixed(2) : "–"),
          req.level === "L2" || req.level === "L3" ? li(req.status === "pending_approval" ? "pend" : null, `Level ${req.level.slice(1)} needs one human approval`,
            req.status === "pending_approval" ? "waiting" : req.status) : null]);
  }

  // Assignee, open/waiting/closed and comments of the case on screen.
  function renderTriage(d) {
    const c = d.case;
    const sel = byId("tr-assignee");
    const names = d.people.includes(c.assignee) || !c.assignee ? d.people : [...d.people, c.assignee];
    fill(sel, el("option", { value: "", text: "Nobody" }), names.map(p => el("option", { value: p, text: p })));
    sel.value = c.assignee || "";
    sel.disabled = !canWrite();
    document.querySelectorAll("#tr-status button").forEach(b => {
      b.setAttribute("aria-pressed", String(b.dataset.st === c.status));
      b.disabled = !canWrite();
    });
    txt("tr-sub", c.status_by ? `Status set by ${c.status_by.replace(/^principal:/, "")}` : "");
    fill("cm", d.comments.length ? d.comments.map(m => el("li", {}, el("span", { class: "tm", text: when(m.at) }),
      el("span", { class: "au", text: m.author }), el("p", { class: "body", text: m.body })))
      : el("li", { class: "empty-note", text: "No comment yet." }));
    const f = byId("cm-form");
    if (f) $("button", f).disabled = !canWrite();
  }

  function cases() {
    let status = "open";
    let shown = "";
    let current = null;
    const seg = byId("q-seg");
    const want = () => (/^#CS-\d{1,9}$/.test(location.hash) ? location.hash.slice(1) : null);
    const loadList = async () => {
      const l = await api(`/api/cases?status=${status}`);
      if (l.status !== status) return;
      txt("q-sub", `${n(l.cases.length)} ${status}`);
      const sel = want();
      fill("queue", l.cases.length ? l.cases.map(c => {
        const [cls, label] = c.status === "closed" ? ["", c.close_reason || "Closed"] : c.pending ? ["wait", "Needs approval"]
          : c.broker ? BROKER[c.broker.status] || ["", cap(c.broker.status)] : ["", "Monitoring"];
        return el("li", { class: c.case_id === sel ? "sel" : null },
          el("a", { href: `#${c.case_id}`, "aria-current": c.case_id === sel ? "true" : null },
            el("span", { class: "id" }, el("span", { text: c.case_id }), el("span", { text: ago(c.last_seen_at) })),
            el("span", { class: "nm", text: c.title }),
            el("span", { class: "pill-row" }, sevTag(c.p, c.severity), el("span", { class: `tag ${cls}`, text: label }),
              el("span", { class: "k", text: plural(c.alerts, "alert") }))));
      }) : el("li", { class: "empty-note", text: `No ${status} case.` }));
      if (!sel && l.cases.length) { history.replaceState(null, "", `#${l.cases[0].case_id}`); current = null; }
    };
    const loadCase = async () => {
      const id = want();
      if (!id) return;
      let d;
      try { d = await api(`/api/cases/${id}`); } catch (e) {
        if (e instanceof LoginRequired) throw e;
        txt("c-title", `Case ${id} was not found`);
        return;
      }
      const key = JSON.stringify(d);
      if (id === current && key === shown) return;  // unchanged: keep the replay where it is
      current = id;
      shown = key;
      renderCase(d);
    };
    $("[data-replay]").addEventListener("click", () => replay(byId("ap")));
    const reload = async () => { shown = ""; await loadCase(); await loadList(); };
    const done = (res, msg) => {
      say("tr-msg", res.ok ? msg : `Not saved: ${why(res)}`, !res.ok);
      return reload();
    };
    byId("tr-assignee").addEventListener("change", async e => {
      const id = want();
      if (!id) return;
      const who = e.target.value || null;
      const res = await quickWrite(e.target, `/api/cases/${id}/assign`, { assignee: who });
      await done(res, who ? `Assigned to ${who}.` : "Unassigned.");
    });
    byId("tr-status").addEventListener("click", async e => {
      const b = e.target.closest("button[data-st]");
      const id = want();
      if (!b || !id || b.getAttribute("aria-pressed") === "true") return;
      const res = await quickWrite(b, `/api/cases/${id}/status`, { status: b.dataset.st });
      await done(res, `Case is now ${b.dataset.st}.`);
    });
    let cmKey = newKey();
    byId("cm-form").addEventListener("submit", async e => {
      e.preventDefault();
      const id = want();
      const t = byId("cm-body");
      const text = t.value.trim();
      if (!id) return;
      if (!text) { say("tr-msg", "Write a comment first.", true); t.focus(); return; }
      const res = await quickWrite($("button", e.target), `/api/cases/${id}/comments`, { body: text }, cmKey);
      if (res.ok) { t.value = ""; cmKey = newKey(); }
      await done(res, "Comment added.");
    });
    seg.addEventListener("click", e => {
      const b = e.target.closest("button[data-s]");
      if (!b || b.dataset.s === status) return;
      status = b.dataset.s;
      seg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      loadList().catch(err => showError(`Could not load cases (${err.message}).`));
    });
    addEventListener("hashchange", () => {
      document.querySelectorAll("#queue li").forEach(li => {
        const on = $("a", li) && $("a", li).getAttribute("href") === location.hash;
        li.classList.toggle("sel", on);
        if ($("a", li)) { if (on) $("a", li).setAttribute("aria-current", "true"); else $("a", li).removeAttribute("aria-current"); }
      });
      loadCase().catch(err => showError(`Could not load the case (${err.message}).`));
    });
    poll(async () => { await loadList(); await loadCase(); });
  }

  // -- 04 approvals ---------------------------------------------------------------------------------------
  function approvals() {
    let data = null;
    let curId = null;
    const shortId = id => `REQ-${id.slice(0, 8)}`;
    const left = r => Math.max(0, (ms(r.expires_at) - now()) / 1000);
    const want = () => (data && data.pending.find(r => `#${r.id}` === location.hash)) || (data && data.pending[0]) || null;
    function timer() {
      const r = want();
      const t = byId("a-timer");
      if (!r || !t || !r.expires_at) return;
      const s = left(r);
      t.textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
      width(byId("a-ttl"), s / Math.max(1, (ms(r.expires_at) - ms(r.created_at)) / 1000));
    }
    function render() {
      const r = want();
      fill("aq", data.pending.length ? data.pending.map(q => el("li", { class: r && q.id === r.id ? "sel" : null },
        el("a", { href: `#${q.id}`, "aria-current": r && q.id === r.id ? "true" : null },
          el("span", { class: "id" }, el("span", { text: shortId(q.id) }), el("span", { text: q.expires_at ? `${span(left(q))} left` : "no expiry" })),
          el("span", { class: "nm", text: requestTitle(q), title: `${q.action} · ${q.case_id || "no case"}` }))))
        : el("li", { class: "empty-note", text: "Nothing waiting." }));
      txt("aq-sub", `${n(data.pending.length)} waiting`);
      fill("recent", data.recent.length ? data.recent.map(x => el("li", {}, el("span", { class: "tm", text: when(x.at) }),
        el("span", { class: "ev", text: `${cap(x.status)} · ${lower(requestTitle(x))}` }),
        el("span", { class: "mono", text: `${x.case_id || "–"}${x.reason ? ` · ${x.reason}` : ""}` })))
        : el("li", {}, el("span", { class: "ev k", text: "No decision yet." })));
      if (!r) {
        curId = null;
        fill("a-pills", el("span", { class: "eyebrow mono", text: "Approvals" }));
        txt("a-title", "Nothing is waiting for approval");
        txt("a-lede", "Level 2 and 3 actions that pass the broker's policy appear here with a countdown.");
        ["a-score", "a-diff", "chain", "a-ev"].forEach(id => fill(id));
        ["a-approve", "a-reject", "a-ask"].forEach(id => { byId(id).disabled = true; });
        return;
      }
      ["a-approve", "a-reject", "a-ask"].forEach(id => { byId(id).disabled = !canWrite(); });
      if (r.id === curId && byId("a-timer")) { timer(); return; }
      curId = r.id;
      say("a-msg", "");
      fill("a-pills", el("span", { class: "eyebrow mono", text: shortId(r.id) }), el("span", { class: "tag wait", text: "Needs approval" }),
        el("span", { class: "tag lv", text: r.level }), el("span", { class: "sp" }), el("span", { class: "k", text: "From case" }),
        r.case_id ? el("a", { class: "mono", href: `/cases#${r.case_id}`, text: r.case_id }) : el("span", { class: "mono", text: "–" }));
      txt("a-title", requestTitle(r));
      txt("a-lede", `Proposed by AI triage, checked by the broker. ${r.case_id ? `Case ${r.case_id}: ${r.case_title}.` : ""}`);
      const ai = r.ai || {};
      fill("a-score",
        el("div", {}, el("span", { class: "k", text: "Time left to decide" }), el("span", { class: "timer", id: "a-timer", text: r.expires_at ? "--:--" : "no expiry" }),
          el("div", { class: "ttlbar" }, el("i", { id: "a-ttl" }))),
        el("div", {}, el("span", { class: "k", text: "AI verdict" }), el("span", { class: "v red", text: cap(ai.verdict) || "–" }),
          el("span", { class: "k", text: ai.confidence !== null && ai.confidence !== undefined ? `${ai.confidence.toFixed(2)} confidence` : "no confidence" })),
        el("div", {}, el("span", { class: "k", text: "Policy check" }), el("span", { class: "v okc", text: "Passed" }), el("span", { class: "k", text: "Every broker check" })),
        el("div", {}, el("span", { class: "k", text: "If nobody decides" }), el("span", { class: "v", text: "No action" }),
          el("span", { class: "k", text: r.expires_at ? `Request expires at ${hm(r.expires_at)} ${TZL}` : "Request has no expiry" })));
      fill("a-diff",
        el("div", {}, el("span", { class: "k", text: "What happens if approved" }), el("span", { text: `${r.would_execute || r.action}.${r.rollback_plan ? ` ${r.rollback_plan}` : ""}` })),
        el("div", {}, el("span", { class: "k", text: "Business impact" }), el("span", { text: r.impact || "Not described by the catalog." })));
      let t = ms(r.created_at);
      const lvl = r.escalation_level || 0;
      const chain = data.ladder.map((s, i) => {
        const start = t;
        t += (s.timeout_min || 0) * 60000;
        const cls = i < lvl ? "done" : i === lvl ? "now" : null;
        const iso = new Date(start).toISOString();
        return el("li", { class: cls }, el("span", { class: "st", text: cls === "done" ? `${hm(iso)} · sent` : cls === "now" ? `Now · ${ago(iso)}` : `At ${hm(iso)}` }),
          el("strong", { text: s.role }), el("span", { class: "k", text: s.approvers.length ? `${s.approvers.join(", ")}, via Lark` : "via Lark" }));
      });
      if (!chain.length) chain.push(el("li", { class: "now" }, el("span", { class: "st", text: "Now" }), el("strong", { text: "No escalation ladder" }), el("span", { class: "k", text: "Set one in the Lark settings" })));
      chain.push(el("li", {}, el("span", { class: "st", text: r.expires_at ? `At ${hm(r.expires_at)}` : "–" }), el("strong", { text: "Expires" }),
        el("span", { class: "k", text: "No action taken, case stays open" })));
      fill("chain", chain);
      fill("a-ev", r.evidence.length ? r.evidence.map(x => el("li", { text: x })) : el("li", { text: "No evidence attached." }));
      timer();
    }
    const refresh = async () => { data = await api("/api/approvals"); render(); };
    const decide = approve => {
      const r = want();
      if (!r) return;
      const l3 = r.level === "L3";
      confirmWrite({
        title: `${approve ? "Approve" : "Reject"}: ${requestTitle(r)}`,
        text: approve ? `${l3 ? "Level 3 needs a written reason. " : ""}The decision and your name go into the audit trail. No cloud executor is connected yet, so an approved action is recorded, not applied.`
          : "The request is closed and nothing is done. The decision goes into the audit trail.",
        reasonRequired: approve && l3, confirm: approve ? "Approve" : "Reject",
        path: `/api/approvals/${r.id}/decision`, body: { approve },
        done: async res => {
          say("a-msg", `${approve ? "Approved" : "Rejected"} ${shortId(r.id)} (${cap(res.data.status || "")})${res.data.idempotent_replay ? ", already recorded" : ""}.`);
          history.replaceState(null, "", location.pathname);
          curId = null;
          await refresh();
          await refreshShell();
        },
      });
    };
    byId("a-approve").addEventListener("click", () => decide(true));
    byId("a-reject").addEventListener("click", () => decide(false));
    byId("a-ask").addEventListener("click", async e => {
      const r = want();
      if (!r) return;
      say("a-msg", "Asking the AI to look at the alert again…");
      const res = await quickWrite(e.currentTarget, `/api/approvals/${r.id}/ask-ai`, {});
      const v = res.data;
      say("a-msg", res.ok ? `AI verdict ${v.verdict}${typeof v.confidence === "number" ? ` (${v.confidence.toFixed(2)})` : ""}${v.evidence_refs && v.evidence_refs.length ? `, evidence: ${v.evidence_refs.slice(0, 3).join(", ")}` : ""}.`
        : `AI triage failed: ${why(res)}`, !res.ok);
    });
    addEventListener("hashchange", () => { if (data) render(); });
    setInterval(timer, 1000);
    poll(refresh);
  }

  // -- 05 automation --------------------------------------------------------------------------------------
  function automation() {
    let load = null;
    const ksBtn = $("[data-ks-btn]");
    ksBtn.addEventListener("click", () => {
      const on = !(shellData && shellData.kill_switch && shellData.kill_switch.global_engaged);
      confirmWrite({
        title: on ? "Turn on the kill switch" : "Turn off the kill switch",
        text: on ? "Every automatic action stops at once. Approvals still queue." : "Automatic actions that pass the policy run again.",
        reasonRequired: true, confirm: on ? "Turn on" : "Turn off", path: "/api/kill-switch", body: { engaged: on },
        done: async () => { say("ks-msg", `Kill switch is ${on ? "on" : "off"}.`); await refreshShell(); if (load) await load(); },
      });
    });
    load = async () => {
      const a = await api("/api/automation");
      fill("acts", !a.catalog_loaded ? el("tr", {}, el("td", { colspan: 6, class: "k", text: "The policy catalog could not be loaded. Nothing can run until it is fixed." }))
        : a.actions.map(x => {
          const lv = Number(x.level.slice(1));
          const bar = el("span", { class: `lvl${lv >= 2 ? ` l${lv}` : ""}` }, [0, 1, 2, 3].map(i => el("i", { class: i <= lv ? "on" : null })));
          return el("tr", {}, el("td", { class: "mono", text: x.id }),
            el("td", {}, bar, `${x.level_text} `, el("span", { class: "tag lv", text: x.level })),
            el("td", {}, el("span", { class: "tag", text: x.target_mode === "approval" ? "With approval" : "Automatic" })),
            x.total ? el("td", {}, el("div", { class: "promo" }, el("span", { class: "bar" }, width(el("i"), x.passed / x.total)),
              el("span", { class: "k", text: `${n(x.passed)} of ${n(x.total)} passed policy · ${n(x.blocked)} blocked` })))
              : el("td", { class: "k", text: "No decision yet" }),
            el("td", { class: "mono" }, x.rate_per_hour ? `${x.rate_per_hour} per hour` : "–", x.rollback ? el("div", { class: "small", text: `undo: ${x.rollback}` }) : null),
            el("td", { class: "num", text: n(x.n24) }));
        }));
      fill("ttl", a.expiring.length ? a.expiring.map(x => {
        const total = ms(x.until) - ms(x.from);
        return el("div", { class: "ttl-row" },
          el("span", {}, el("span", { class: "mono", text: x.action }), ` ${x.what || ""} `, el("span", { class: "k", text: `· ${x.case_id || "–"}` })),
          el("span", { class: "r" }, `expires ${hm(x.until)} ${TZL} `,
            el("button", { class: "btn ghost", type: "button", "data-revoke": x.id, disabled: !canWrite(), text: "Revoke" })),
          el("span", { class: "ttlbar" }, width(el("i"), total > 0 ? (ms(x.until) - now()) / total : 0)));
      }) : el("p", { class: "empty-note", text: "No reversible action is active." }));
      fill("integ", integItems(a.integrations, true));
      fill("changes", a.changes.length ? a.changes.map(x => el("li", {}, el("span", { class: "tm", text: dayOf(x.at) }),
        el("span", { class: "ev", text: `${INTEG[x.integration] ? INTEG[x.integration][1] : x.integration} config v${x.version} · target ${x.target}` }),
        el("span", { class: "mono", text: `${x.by || "–"}${x.note ? ` · ${x.note}` : ""}` })))
        : el("li", {}, el("span", { class: "ev k", text: "No configuration change recorded." })));
      const l = a.ledger;
      txt("led-n", plural(l.entries, "entry").replace("entrys", "entries"));
      const st = txt("led-state", l.ok === true ? "Audit trail valid" : l.ok === false ? "Audit trail broken" : "Audit trail not checked yet");
      st.className = l.ok === true ? "state ok" : l.ok === false ? "state bad" : "state";
      txt("led-k", l.checked_at ? `Checked ${hm(l.checked_at)} ${TZL} · head #${l.head_seq}${l.errors && l.errors.length ? ` · ${l.errors[0]}` : ""}` : "");
      txt("led-hash", l.head_hash || "");
      fill("led", l.tail.map(x => el("li", {}, el("span", { class: "tm", text: `#${x.seq}` }), el("span", { class: "ev", text: x.event_type }),
        el("span", { class: "mono", text: `${hms(x.recorded_at)} · ${x.actor}` }))));
    };
    byId("ttl").addEventListener("click", e => {
      const b = e.target.closest("button[data-revoke]");
      if (!b) return;
      const row = b.closest(".ttl-row");
      confirmWrite({
        title: "Revoke this action now", text: `${row ? row.firstChild.textContent.trim() : ""}. It ends now instead of at its expiry.`,
        reasonRequired: true, confirm: "Revoke", path: `/api/requests/${b.dataset.revoke}/revoke`, body: {},
        done: async () => { say("ttl-msg", "Revoked. Recorded in the audit trail."); await load(); },
      });
    });
    poll(load);
  }

  // -- 08 integrations ------------------------------------------------------------------------------------
  // Settings are read from and written to the broker. The form is built from each integration's settings
  // schema, so a field the broker adds shows up here without a console change. Secrets are write-only: the
  // broker answers set / rotated / expiry, never a value, and a value typed here goes out once and is dropped.
  const STATE = { connected: ["ok", "Connected"], warning: ["wait", "Warning"], error: ["hot", "Test failed"],
    not_tested: ["wait", "Not tested"], disabled: ["", "Off"], not_configured: ["", "Not set up"] };
  const GROUP = { source: "Data sources · alerts in", notify: "Notifications and approvals", ticketing: "Ticketing", ai: "AI triage" };
  const BLURB = { lark: "Notifications and approvals", jira: "One ticket per case", ai: "AI model for triage",
    webhook: "Any SIEM that can POST JSON", syslog: "Firewalls and on-prem SIEM, CEF", sls: "Alibaba Cloud Log Service" };
  const FIELD = { base_url: "Base URL", app_id: "App ID", chat_id: "Chat ID", chat_name: "Chat name", oncall_dm: "Also message the on-call person",
    delivery: "Delivery", routing: "Where alerts go", ladder: "Who can approve", role: "Step", approvers: "Approvers",
    lark_user_id: "Lark user ID", timeout_min: "Wait before the next step (min)", site: "Site URL", email: "Account email",
    issue_type: "Issue type", title_template: "Issue title", priority_map: "Jira priority per severity", sync: "Keeping it in sync",
    comment_on_update: "Comment on the issue when the case changes", done_on_close: "Move the issue to Done when the case is closed",
    close_case_on_done: "Close the case when the issue is moved to Done in Jira", triage_model: "Triage model",
    fallback_model: "Fallback model", timeout_s: "Timeout (s)", daily_token_limit: "Daily token limit", max_tokens: "Max tokens per answer",
    prompt_version: "Prompt version", mock_fault: "Mock fault (sandbox tests)", source_type: "Source type", rule_prefix: "Rule prefix",
    fields: "Field mapping", severity_map: "Severity mapping", max_body_kb: "Max body (KB)", max_skew_s: "Max clock skew (s)",
    allowed_senders: "Allowed senders (IP or CIDR)", endpoint: "Endpoint", logstore: "Logstore", query: "Query", window_s: "Window (s)",
    lag_s: "Lag (s)", page: "Page size", src_ip: "Source IP", ua: "User agent", uri: "URI", dst_asset: "Destination asset",
    access_key_id: "AccessKey ID", detected_at: "Detected at", rule_id: "Rule ID", events: "Event count" };
  const SECRET = { app_secret: "App secret", verification_token: "Verification token", encrypt_key: "Encrypt key", api_token: "API token",
    webhook_secret: "Webhook secret", api_key: "API key" };
  const words = k => k.replace(/_/g, " ").replace(/^./, c => c.toUpperCase());
  const clone = v => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

  // A schema node with $ref followed and "X or null" unwrapped: [node, nullable].
  function resolve(s, root) {
    let nullable = false;
    for (let i = 0; s && i < 8; i++) {
      const outer = { default: s.default, title: s.title };
      if (s.$ref) s = { ...root.$defs[s.$ref.split("/").pop()] };
      else if (s.anyOf) {
        const non = s.anyOf.filter(x => x.type !== "null");
        nullable = nullable || non.length < s.anyOf.length;
        s = { ...non[0] };
      } else break;
      for (const k in outer) if (outer[k] !== undefined) s[k] = outer[k];
    }
    return [s || {}, nullable];
  }
  function skeleton(s0, root) {
    const [s, nullable] = resolve(s0, root);
    if (s.default !== undefined) return clone(s.default);
    if (nullable) return null;
    if (s.const !== undefined) return s.const;
    if (s.enum) return s.enum[0];
    if (s.type === "object") {
      const o = {};
      for (const k of Object.keys(s.properties || {})) o[k] = skeleton(s.properties[k], root);
      return o;
    }
    if (s.type === "array") return Array.from({ length: s.minItems || 0 }, () => skeleton(s.items, root));
    if (s.type === "boolean") return false;
    if (s.type === "integer" || s.type === "number") return s.minimum !== undefined ? s.minimum : 0;
    return "";
  }

  function integrations() {
    let data = null;
    let item = null;
    let schema = null;
    let draft = null;
    let dirty = false;
    let jsonMode = false;
    let listKey = "";
    let fid = 0;
    const writable = () => canWrite() && !!(data && data.writes_enabled);
    const sel = () => decodeURIComponent(location.hash.slice(1));
    const isSource = () => item && item.category === "source";
    const fixedTarget = () => (data && data.mode === "production") || isSource();

    function changed() {
      dirty = true;
      byId("s-save").disabled = !writable();
      say("s-msg", "Unsaved changes.");
    }

    // -- the settings form, one control per schema node; obj[key] is the value it edits ------------------
    function fld(label, control, wide) {
      return el("label", { class: wide ? "fld wide" : "fld", for: control.id }, el("span", { text: label }), control);
    }
    function node(obj, key, s0, label, optional) {
      const [s, nullable] = resolve(s0, schema);
      const id = `f${++fid}`;
      const v = obj[key];
      const set = x => {
        if (optional && (x === "" || x === null)) delete obj[key];
        else obj[key] = x;
        changed();
      };
      if (s.const !== undefined) return el("div", { class: "fld" }, el("span", { text: label }), el("code", { class: "mono", text: String(s.const) }));
      if (s.enum) {
        const c = el("select", { id }, nullable || optional ? el("option", { value: "", text: "None" }) : null,
          s.enum.map(e => el("option", { value: String(e), selected: e === v, text: String(e) })));
        c.addEventListener("change", () => set(c.value === "" ? null : s.type === "integer" ? Number(c.value) : c.value));
        return fld(label, c);
      }
      if (s.type === "boolean") {
        const c = el("input", { type: "checkbox", id, checked: !!v });
        c.addEventListener("change", () => set(c.checked));
        return el("label", { class: "tg wide", for: id }, c, el("span", { text: label }));
      }
      if (s.type === "integer" || s.type === "number") {
        const c = el("input", { type: "number", id, inputmode: "numeric", step: s.type === "integer" ? 1 : "any", min: s.minimum, max: s.maximum,
          value: v === null || v === undefined ? "" : v });
        c.addEventListener("input", () => set(c.value === "" ? (nullable ? null : "") : Number(c.value)));
        return fld(label, c);
      }
      if (s.type === "array") {
        const list = Array.isArray(v) ? v : (obj[key] = []);
        const max = s.maxItems || 64;
        const rows = list.map((_, i) => el("div", { class: "arr-item" }, node(list, i, s.items, `${label} ${i + 1}`),
          el("button", { class: "btn ghost", type: "button", disabled: list.length <= (s.minItems || 0), "data-del": i, text: "Remove" })));
        const add = el("button", { class: "btn ghost", type: "button", disabled: list.length >= max, text: `Add ${label.toLowerCase().replace(/s$/, "")}` });
        const box = el("fieldset", { class: "fset wide" }, el("legend", { text: label }), rows, el("div", { class: "pill-row" }, add));
        box.addEventListener("click", e => {
          const b = e.target.closest("button");
          if (!b || b.closest("fieldset") !== box) return;
          if (b === add) list.push(skeleton(s.items, schema));
          else list.splice(Number(b.dataset.del), 1);
          changed();
          drawForm();
        });
        return box;
      }
      if (s.type === "object") {
        const o = v && typeof v === "object" ? v : (obj[key] = {});
        if (s.properties) {
          return el("fieldset", { class: "fset wide" }, el("legend", { text: label }),
            el("div", { class: "form" }, Object.keys(s.properties).map(k => node(o, k, s.properties[k], FIELD[k] || words(k)))));
        }
        const [vs] = resolve(s.additionalProperties || {}, schema);
        if (s.propertyNames && s.propertyNames.enum) {
          // A fixed set of keys (severities): scalar values may be left empty, an object value is switched on per key.
          return el("fieldset", { class: "fset wide" }, el("legend", { text: label }), el("div", { class: "form" },
            s.propertyNames.enum.map(k => {
              if (vs.type !== "object") return node(o, k, s.additionalProperties, words(k), true);
              const on = el("input", { type: "checkbox", id: `f${++fid}`, checked: o[k] !== undefined });
              on.addEventListener("change", () => {
                if (on.checked) o[k] = skeleton(s.additionalProperties, schema); else delete o[k];
                changed();
                drawForm();
              });
              return el("div", { class: "fld wide" }, el("label", { class: "tg", for: on.id }, on, el("span", { text: words(k) })),
                o[k] !== undefined ? node(o, k, s.additionalProperties, `${words(k)} alerts`) : null);
            })));
        }
        // Free keys (severity names as a source sends them): one row each, renamed in place.
        const keys = Object.keys(o);
        const rows = keys.map(k => {
          const name = el("input", { id: `f${++fid}`, value: k, spellcheck: "false", maxlength: 64, "aria-label": `${label}: source value` });
          name.addEventListener("change", () => {
            const nk = name.value.trim();
            if (!nk || nk === k || nk in o) { name.value = k; return; }
            const copy = Object.entries(o).map(([a, b]) => [a === k ? nk : a, b]);
            for (const a of Object.keys(o)) delete o[a];
            for (const [a, b] of copy) o[a] = b;
            changed();
            drawForm();
          });
          return el("div", { class: "arr-item kvrow" }, name, node(o, k, s.additionalProperties, `${k} becomes`),
            el("button", { class: "btn ghost", type: "button", "data-del": k, text: "Remove" }));
        });
        const add = el("button", { class: "btn ghost", type: "button", disabled: keys.length >= (s.maxProperties || 64), text: "Add row" });
        const box = el("fieldset", { class: "fset wide" }, el("legend", { text: label }), rows, el("div", { class: "pill-row" }, add));
        box.addEventListener("click", e => {
          const b = e.target.closest("button");
          if (!b || b.closest("fieldset") !== box) return;
          if (b === add) { let i = 1; while (`value${i}` in o) i++; o[`value${i}`] = skeleton(s.additionalProperties, schema); }
          else delete o[b.dataset.del];
          changed();
          drawForm();
        });
        return box;
      }
      const c = el("input", { id, value: v === null || v === undefined ? "" : String(v), maxlength: s.maxLength || 1000, spellcheck: "false",
        type: key === "email" ? "email" : "text", autocomplete: "off" });
      c.addEventListener("input", () => set(c.value === "" && nullable ? null : c.value));
      return fld(label, c, (s.maxLength || 0) > 120 || /url|template|query|site|endpoint/.test(String(key)));
    }

    function drawForm() {
      fid = 0;
      const wrap = { settings: draft.settings };
      const props = schema.properties || {};
      const enabled = el("input", { type: "checkbox", id: "f-enabled", checked: draft.enabled });
      enabled.addEventListener("change", () => { draft.enabled = enabled.checked; changed(); });
      const f = el("fieldset", { class: "fset bare", disabled: !writable() },
        el("legend", { class: "vh", text: `${item.label} settings` }),
        el("label", { class: "tg", for: "f-enabled" }, enabled, el("span", { text: "Enabled. Off keeps the settings but nothing is sent or received." })),
        el("div", { class: "form" }, Object.keys(props).map(k => node(wrap.settings, k, props[k], FIELD[k] || words(k)))));
      fill("i-form", f);
      byId("i-json-text").value = JSON.stringify(draft.settings, null, 2);
      byId("i-json-text").disabled = !writable();
      byId("i-json-apply").disabled = !writable();
    }
    function drawTarget() {
      if (fixedTarget()) { fill("i-tgt", el("span", { class: "tag act", text: "Live" })); return; }
      const b = t => {
        const x = el("button", { type: "button", "aria-pressed": draft.target === t ? "true" : "false", disabled: !writable(), text: t === "mock" ? "Mock" : "Live" });
        x.addEventListener("click", () => { draft.target = t; changed(); drawTarget(); });
        return x;
      };
      fill("i-tgt", el("span", { class: "seg", role: "group", "aria-label": "Target" }, b("mock"), b("live")));
    }

    function drawState() {
      const [cls, label] = STATE[item.state] || ["", item.state];
      const row = (k, ...v) => [el("dt", { text: k }), el("dd", {}, ...v)];
      fill("i-state",
        row("State", el("span", { class: `tag ${cls}`, text: label })),
        row("Saved", item.version ? `v${item.version} · target ${item.target} · ${when(item.updated_at)} ${TZL} by ${item.updated_by || "–"}` : "Not set up yet"),
        row("Active", item.active_version ? `v${item.active_version}${item.active_version === item.version ? "" : " (the saved version is waiting for a passing test)"}` : "None yet. A passing test activates the saved version."),
        row("Errors, 24 h", n(item.errors_24h)));
    }
    function drawSecrets() {
      const names = Object.keys(item.secrets || {});
      fill("i-secrets", names.length ? names.map(k => {
        const st = item.secrets[k];
        const label = SECRET[k] || words(k);
        const btn = el("button", { class: "btn ghost", type: "button", "data-secret": k, disabled: !writable() || !item.version,
          title: !item.version ? "Save the settings first: a secret is sealed for the saved host" : null, text: st.set ? "Replace" : "Set" });
        const info = st.set ? `rotated ${when(st.rotated_at)} ${TZL} by ${st.rotated_by || "–"}${st.expires_at ? ` · expires ${String(st.expires_at).slice(0, 10)}` : ""}`
          : st.required ? "required" : "optional";
        return el("div", { class: "fld" }, el("span", { text: label }),
          el("div", { class: "secret" }, el("span", { class: st.set ? "set" : "unset", text: st.set ? "Set" : "Not set" }), el("span", { class: "k", text: info }), btn));
      }) : el("p", { class: "k", text: "This integration needs no secret." }));
    }
    function drawSteps(t, fresh) {
      if (!t) { fill("t-out", el("li", { class: "idle" }, el("span", { class: "st", text: "–" }), el("span", { text: "No test has run for this integration yet." }))); return; }
      fill("t-out", el("li", { class: t.status === "pass" ? "ok" : "bad" }, el("span", { class: "st", text: t.status === "pass" ? "PASS" : "FAIL" }),
        el("span", { text: `${fresh ? "Just now" : `Last test ${when(t.finished_at)} ${TZL}`} · version ${t.config_version} · target ${t.target || item.target}` })),
        (t.steps || []).map(x => el("li", { class: x.ok ? "ok" : "bad" }, el("span", { class: "st", text: x.ok ? "ok" : "fail" }),
          el("span", {}, x.step, x.detail ? el("span", { class: "k", text: ` · ${x.detail}` }) : null))));
    }
    async function drawVersions() {
      const name = item.integration;
      const h = item.version ? await api(`/api/integrations/${encodeURIComponent(name)}/history`) : { versions: [] };
      if (!item || item.integration !== name) return;
      fill("v-list", h.versions.length ? h.versions.map(x => el("li", { class: "ver" }, el("span", { class: "tm", text: `v${x.version}` }),
        el("span", { class: "ev" }, `target ${x.target} · ${x.enabled ? "on" : "off"}`,
          x.version === item.version ? el("span", { class: "tag", text: "saved" }) : null,
          x.version === item.active_version ? el("span", { class: "tag ok", text: "active" }) : null),
        el("span", { class: "mono", text: `${when(x.changed_at)} ${TZL} · ${x.changed_by}${x.note ? ` · ${x.note}` : ""}` }),
        x.version === item.version ? null : el("button", { class: "btn ghost", type: "button", "data-ver": x.version, disabled: !writable(), text: `Roll back to v${x.version}` })))
        : el("li", {}, el("span", { class: "ev k", text: "No version saved yet." })));
    }

    function select(name, force) {
      const next = data.integrations.find(i => i.integration === name) || data.integrations[0];
      if (!next) return;
      const switching = !item || item.integration !== next.integration;
      item = next;
      schema = data.schemas[item.integration] || { properties: {} };
      document.querySelectorAll("#i-list [role=tab]").forEach(b => {
        const on = b.dataset.int === item.integration;
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
      });
      byId("i-panel").setAttribute("aria-labelledby", `tab-${item.integration}`);
      txt("i-h", item.label);
      txt("i-sub", BLURB[item.integration] || "");
      if (switching || force || !dirty) {
        draft = { target: fixedTarget() ? "live" : item.target || "mock", enabled: item.version ? item.enabled : true,
          settings: item.settings ? clone(item.settings) : skeleton(schema, schema) };
        dirty = false;
        byId("s-save").disabled = true;
        if (switching) { say("s-msg", ""); say("t-msg", ""); say("v-msg", ""); say("i-sec-msg", ""); }
        drawForm();
        drawTarget();
      }
      drawState();
      drawSecrets();
      if (switching || force) drawSteps(item.last_test);
      byId("t-run").disabled = !writable() || !item.version;
      if (switching || force) drawVersions().catch(e => say("v-msg", `Could not load versions (${e.message}).`, true));
    }

    function drawList() {
      const key = JSON.stringify(data.integrations.map(i => [i.integration, i.state]));
      if (key === listKey) return;
      listKey = key;
      let last = null;
      fill("i-list", data.integrations.flatMap(i => {
        const [cls, label] = STATE[i.state] || ["", i.state];
        const logo = INTEG[i.integration] ? INTEG[i.integration][0] : i.integration.slice(0, 2).toUpperCase();
        const out = [];
        if (i.category !== last) { last = i.category; out.push(el("li", { class: "grp", role: "presentation", text: GROUP[i.category] || words(i.category) })); }
        out.push(el("li", { role: "presentation" }, el("button", { type: "button", role: "tab", id: `tab-${i.integration}`, "data-int": i.integration,
          "aria-controls": "i-panel", "aria-selected": "false", tabindex: -1 },
          el("span", { class: "logo", text: logo }), el("span", { class: "nm", text: i.label }),
          el("span", { class: "d", text: BLURB[i.integration] || "" }), el("span", { class: `tag ${cls}`, text: label }))));
        return out;
      }));
    }

    async function load(force) {
      data = await api("/api/integrations");
      const order = ["source", "notify", "ticketing", "ai"];
      data.integrations.sort((a, b) => order.indexOf(a.category) - order.indexOf(b.category));
      drawList();
      const ro = byId("i-ro");
      ro.hidden = writable();
      ro.textContent = !canWrite() ? "Writes are not configured on this console, so these settings are read-only."
        : "Settings are read-only here: the broker in this mode keeps the settings write API off. Change them on the host with hypersoar integration, then test.";
      byId("i-lock").hidden = !writable();
      byId("s-bar").hidden = !writable();
      select(sel() || (item && item.integration), force);
    }

    byId("i-list").addEventListener("click", e => {
      const b = e.target.closest("button[data-int]");
      if (!b || (item && b.dataset.int === item.integration)) return;
      if (dirty && !confirm("Discard the unsaved changes?")) return;
      history.replaceState(null, "", `#${b.dataset.int}`);
      select(b.dataset.int);
    });
    byId("i-list").addEventListener("keydown", e => {
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      const tabs = [...document.querySelectorAll("#i-list [role=tab]")];
      const i = tabs.indexOf(document.activeElement);
      const j = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowDown" ? 1 : -1) + tabs.length) % tabs.length;
      e.preventDefault();
      tabs[j].focus();
      tabs[j].click();
    });
    byId("i-json-btn").addEventListener("click", () => {
      jsonMode = !jsonMode;
      byId("i-json-btn").setAttribute("aria-pressed", jsonMode ? "true" : "false");
      byId("i-json").hidden = !jsonMode;
      byId("i-form").hidden = jsonMode;
      drawForm();
    });
    const applyJson = () => {
      try {
        const v = JSON.parse(byId("i-json-text").value);
        if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("settings must be a JSON object");
        draft.settings = v;
        changed();
        drawForm();
        return true;
      } catch (e) { say("s-msg", `The JSON is not valid: ${e.message}`, true); return false; }
    };
    byId("i-json-apply").addEventListener("click", applyJson);
    byId("s-discard").addEventListener("click", () => { select(item.integration, true); say("s-msg", "Changes discarded."); });
    byId("s-save").addEventListener("click", () => {
      if (jsonMode && !applyJson()) return;
      const name = item.integration;
      confirmWrite({
        title: `Save ${item.label} settings`, method: "PUT", path: `/api/integrations/${encodeURIComponent(name)}`,
        text: `Saved as a new version on target ${draft.target}${draft.enabled ? "" : ", switched off"}. It becomes active after a passing test.`,
        reasonKey: "note", reasonMax: 200, reasonLabel: "Note (optional, kept with the version)", confirm: "Save",
        body: { target: draft.target, enabled: draft.enabled, settings: draft.settings },
        done: async res => {
          dirty = false;
          await load(true);
          say("s-msg", `Saved as version ${res.data.version}. Run the test to make it active.`);
        },
      });
    });
    byId("i-secrets").addEventListener("click", e => {
      const b = e.target.closest("button[data-secret]");
      if (!b) return;
      const k = b.dataset.secret;
      const label = SECRET[k] || words(k);
      confirmWrite({
        title: `${item.secrets[k].set ? "Replace" : "Set"} ${label.toLowerCase()}`, method: "PUT", noReason: true, confirm: "Save secret",
        path: `/api/integrations/${encodeURIComponent(item.integration)}/secrets/${encodeURIComponent(k)}`, body: {},
        text: `For ${item.label}, sealed for the saved host. It cannot be shown again after you save it.`,
        extra: [{ key: "value", label: `New ${label.toLowerCase()}`, required: true, attrs: { type: "password", autocomplete: "new-password", maxlength: 4096, spellcheck: "false" } },
                { key: "expires_at", label: "Expires on (optional)", attrs: { type: "date" } }],
        done: async () => { await load(); say("i-sec-msg", `${label} saved. Run the test to check it.`); },
      });
    });
    byId("t-run").addEventListener("click", () => {
      const name = item.integration;
      confirmWrite({
        title: `Test ${item.label}`, noReason: true, confirm: "Run test", path: `/api/integrations/${encodeURIComponent(name)}/test`, body: {},
        text: `Calls saved version ${item.version} on target ${item.target}. A pass makes it the active version; a fail leaves v${item.active_version || "–"} active.`,
        done: async res => {
          const r = res.data || {};
          await load(true);
          say("s-msg", "");
          if (item.integration === name) {
            drawSteps({ status: r.status, config_version: r.config_version, steps: r.steps, target: item.target }, true);
            say("t-msg", r.status === "pass" ? `Passed. Version ${r.config_version} is active.` : "Failed. The saved version stays inactive.", r.status !== "pass");
          }
        },
      });
    });
    byId("v-list").addEventListener("click", e => {
      const b = e.target.closest("button[data-ver]");
      if (!b) return;
      const v = Number(b.dataset.ver);
      if (dirty && !confirm("Discard the unsaved changes?")) return;
      confirmWrite({
        title: `Roll back ${item.label} to v${v}`, noReason: true, confirm: "Roll back",
        path: `/api/integrations/${encodeURIComponent(item.integration)}/rollback`, body: { version: v },
        text: `Saves the settings of v${v} again as a new version. Run the test to make it active.`,
        done: async res => { dirty = false; await load(true); say("s-msg", ""); say("v-msg", `Rolled back: v${v} saved again as v${res.data.version}. Run the test to make it active.`); },
      });
    });
    window.addEventListener("hashchange", () => { if (data && sel() !== (item && item.integration) && (!dirty || confirm("Discard the unsaved changes?"))) select(sel()); });
    window.addEventListener("beforeunload", e => { if (dirty) e.preventDefault(); });
    poll(load);
  }

  // -- 06 scenario tests (sandbox only) -------------------------------------------------------------------
  function scenarios() {
    const RES = { pass: ["pass", "PASS"], fail: ["fail", "FAIL"], error: ["fail", "ERROR"] };
    poll(async () => {
      const s = await api("/api/scenarios");
      const run = s.run;
      const failed = run ? run.scenarios.filter(x => x.status !== "pass") : [];
      txt("r-at", run ? hm(run.finished_at) : "–");
      txt("r-dur", run ? `hypersoar scenario run · ${secs((ms(run.finished_at) - ms(run.started_at)) / 1000)}` : "No run recorded yet");
      txt("r-pass", run ? n(run.passed) : "–");
      txt("r-of", run ? `of ${plural(run.total, "scenario")}` : "–");
      txt("r-fail", run ? n(run.total - run.passed) : "–");
      txt("r-failt", failed.length ? clip(failed.map(x => x.id).join(", "), 40) : run ? "None failed" : "–");
      txt("r-hist", n(s.history.length));
      txt("r-sha", run && run.git_sha ? run.git_sha : "–");
      fill("sc", !run ? el("tr", {}, el("td", { colspan: 5, class: "k", text: "No scenario run recorded yet. Run hypersoar scenario run in the sandbox." }))
        : run.scenarios.flatMap(x => {
          const [cls, label] = RES[x.status] || ["fail", x.status.toUpperCase()];
          const names = x.checks.map(c => c.name);
          const row = el("tr", { class: x.status === "pass" ? null : "failrow" }, el("td", { class: "mono", text: x.id }), el("td", { class: "ttl", text: x.title }),
            el("td", { class: "k", text: names.length > 3 ? `${names.slice(0, 3).join(", ")} +${names.length - 3}` : names.join(", ") || "–" }),
            el("td", { class: "num k", text: secs(x.ms / 1000) }), el("td", {}, el("span", { class: `res ${cls}`, text: label })));
          if (x.status === "pass" || !x.failures.length) return [row];
          return [row, el("tr", { class: "detail" }, el("td", { colspan: 5 }, el("div", { class: "expect" },
            el("div", {}, el("span", { class: "k", text: "Expected" }), x.failures.map(f => el("span", { text: `${f.name}: ${f.expected}` }))),
            el("div", {}, el("span", { class: "k", text: "Got" }), x.failures.map(f => el("span", { class: "bad", text: `${f.name}: ${f.got}` }))))))];
        }));
      const sd = s.seeding;
      txt("bot-n", String(sd.per_min_10m));
      const bs = txt("bot-st", sd.per_min_10m > 0 ? "Running" : "Idle");
      bs.className = sd.per_min_10m > 0 ? "r tag ok" : "r tag";
      const max = Math.max(1, ...sd.spark);
      const step = 200 / Math.max(1, sd.spark.length - 1);
      $("#spark path").setAttribute("d", sd.spark.length ? `M${sd.spark.map((v, i) => `${(i * step).toFixed(1)} ${(38 - (v / max) * 34).toFixed(1)}`).join("L")}` : "M0 40H200");
      byId("spark").setAttribute("aria-label", `Seeded alerts per minute over the last hour, peak ${max}`);
      fill("mix", sd.mix.length ? sd.mix.map(m => el("li", {}, el("span", { text: m.category }), el("span", { class: "v", text: `${m.pct}%` })))
        : el("li", { class: "pend" }, el("span", { text: "No seeded alert in the last 24 hours" }), el("span", { class: "v", text: "–" })));
      const gate = (cls, a, b) => el("li", { class: cls }, el("span", { text: a }), el("span", { class: "v", text: b }));
      fill("gates",
        gate(run && run.passed === run.total ? null : "no", "All scenarios pass", run ? `${run.passed} / ${run.total}` : "no run"),
        gate("pend", "No synthetic rows in the production database", "preflight --production"),
        gate("pend", "Secrets present for Lark, Jira, 9router", "preflight --production"),
        gate("pend", "protected.yaml filled with real assets", "preflight --production"),
        gate("pend", "Integrations reachable from production", "connection test"));
    });
  }

  // -- start ----------------------------------------------------------------------------------------------
  buildShell();
  const SCREENS = { overview, map: threatMap, cases, approvals, automation, integrations, scenarios };
  (async () => {
    try { await refreshShell(); } catch (e) { if (e instanceof LoginRequired) return; showError(`Could not load the header (${e.message}).`); }
    setInterval(() => { if (!document.hidden) refreshShell().catch(() => {}); }, POLL_MS);
    (SCREENS[screen] || (() => {}))();
  })();
})();
