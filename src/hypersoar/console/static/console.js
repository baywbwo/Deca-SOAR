"use strict";
// Read-only console: polls /api/state and renders with textContent only (alert fields are untrusted).
(function () {
  var POLL_MS = 5000;
  var SVG = "http://www.w3.org/2000/svg";
  var $ = function (id) { return document.getElementById(id); };
  var tz = { timeZone: "Asia/Jakarta", hour12: false };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function svg(tag, attrs) {
    var e = document.createElementNS(SVG, tag);
    Object.keys(attrs).forEach(function (k) { e.setAttribute(k, String(attrs[k])); });
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function time(iso) { return iso ? new Date(iso).toLocaleTimeString("en-GB", tz) : "–"; }
  function hour(iso) { return new Date(iso).toLocaleTimeString("en-GB", { timeZone: "Asia/Jakarta", hour: "2-digit", minute: "2-digit", hour12: false }); }
  function n(v) { return v === undefined || v === null ? 0 : v; }
  function fmt(v) { return n(v).toLocaleString("en-US"); }
  function short(h) { return h ? h.slice(0, 12) + "…" : "–"; }
  function pct(v, max) { return max > 0 ? Math.max(v > 0 ? 2 : 0, Math.round(v / max * 100)) + "%" : "0%"; }

  var VERDICT = { malicious: ["hot", "Malicious"], suspicious: ["wait", "Suspicious"], benign: ["ok", "Benign"] };
  var BROKER = {
    validated: ["ok", "Passed policy, not executed"],
    rejected: ["hot", "Blocked by policy"],
    pending_approval: ["wait", "Needs approval"],
    expired: ["", "Expired"]
  };
  var GATEWAY = { forwarded: ["act", "Forwarded"], pending: ["wait", "Queued"], dead: ["hot", "Failed"] };

  function row(a) {
    var tr = el("tr");
    var t = el("td");
    t.appendChild(el("div", "tm", time(a.ingested_at)));
    t.appendChild(el("div", "small", "detected " + time(a.detected_at)));
    tr.appendChild(t);

    var al = el("td");
    al.appendChild(el("div", "ttl", a.rule_id));
    var m = el("div", "row");
    m.appendChild(el("span", "sev " + (a.severity || ""), a.severity));
    m.appendChild(el("span", "tag", a.source));
    m.appendChild(el("span", "small", a.event_count + (a.event_count === 1 ? " event" : " events")));
    al.appendChild(m);
    if (a.src_token) {
      var src = el("div", "mono");
      src.appendChild(el("span", "src", "src"));
      src.appendChild(document.createTextNode(a.src_token));
      al.appendChild(src);
    }
    if (a.uri) al.appendChild(el("div", "mono", a.uri));
    tr.appendChild(al);

    var g = GATEWAY[a.gateway_status] || ["", a.gateway_status];
    var gw = el("td");
    gw.appendChild(el("span", "tag " + g[0], g[1]));
    if (a.forwarded_at) gw.appendChild(el("div", "small", "to Temporal " + time(a.forwarded_at)));
    tr.appendChild(gw);

    var tri = el("td");
    if (a.triage) {
      var v = VERDICT[a.triage.verdict] || ["", a.triage.verdict];
      tri.appendChild(el("span", "tag " + v[0], v[1]));
      var c = typeof a.triage.confidence === "number" ? a.triage.confidence.toFixed(2) : "–";
      tri.appendChild(el("div", "small", "confidence " + c + ", " + (a.triage.model || "unknown model")));
    } else {
      tri.appendChild(el("span", "small", a.source === "waf" ? "Waiting for worker" : "Not sent to broker (non-WAF)"));
    }
    tr.appendChild(tri);

    var br = el("td");
    if (a.broker) {
      var b = BROKER[a.broker.status] || ["", a.broker.status];
      var bm = el("div", "row");
      bm.appendChild(el("span", "tag " + b[0], b[1]));
      bm.appendChild(el("span", "tag", a.broker.level + ", " + a.broker.mode));
      br.appendChild(bm);
      br.appendChild(el("div", "mono", a.broker.action));
      if (a.broker.would_execute) br.appendChild(el("div", "mono", "would run " + a.broker.would_execute));
      if (a.broker.reasons && a.broker.reasons.length) br.appendChild(el("div", "reasons", a.broker.reasons.join("; ")));
    } else {
      br.appendChild(el("span", "small", "–"));
    }
    tr.appendChild(br);
    return tr;
  }

  function chart(series) {
    var root = $("chart"), axis = $("axis");
    var W = 960, H = 220, top = 8, base = H - 4;
    Array.prototype.slice.call(root.childNodes).forEach(function (c) { if (c.nodeName !== "title") root.removeChild(c); });
    clear(axis);
    var max = 0;
    series.forEach(function (h) { max = Math.max(max, h.high + h.medium + h.low); });
    var scale = max > 0 ? (base - top) / max : 0;
    [0.25, 0.5, 0.75, 1].forEach(function (f) {
      var y = Math.round(base - (base - top) * f) + 0.5;
      root.appendChild(svg("line", { x1: 0, x2: W, y1: y, y2: y, "class": "grid" }));
    });
    root.appendChild(svg("line", { x1: 0, x2: W, y1: base + 0.5, y2: base + 0.5, "class": "grid" }));
    var slot = W / Math.max(series.length, 1), bw = Math.max(4, Math.floor(slot * 0.62));
    series.forEach(function (h, i) {
      var x = Math.round(i * slot + (slot - bw) / 2), y = base;
      [["low", "b-lo"], ["medium", "b-md"], ["high", "b-hi"]].forEach(function (k) {
        var v = h[k[0]];
        if (!v) return;
        var hgt = Math.max(2, v * scale);
        y -= hgt;
        root.appendChild(svg("rect", { x: x, y: y.toFixed(1), width: bw, height: hgt.toFixed(1), "class": k[1] }));
      });
      var lab = el("span", null, i % 3 === 0 ? hour(h.hour) : "");
      axis.appendChild(lab);
    });
    if (series.length) {
      var last = series.length - 1, cx = Math.round(last * slot + slot / 2);
      root.appendChild(svg("rect", { x: cx - bw / 2 - 3, y: top, width: bw + 6, height: base - top, "class": "now" }));
    }
    var hi = 0;
    series.forEach(function (h) { hi += h.high; });
    $("chart-t").textContent = "Hourly alert volume for the last 24 hours, peak " + max + " per hour, " + hi + " high or critical";
  }

  function flow(c, inbox, req) {
    var steps = [
      ["Alerts received", c.alerts_total, ""],
      ["Forwarded to Temporal", inbox.forwarded, ""],
      ["Broker decisions, shadow", c.decisions, ""],
      ["Passed policy", req.validated, ""],
      ["Blocked by policy", req.rejected, "hot"],
      ["Executed", req.executed, "hot"]
    ];
    var max = n(c.alerts_total), list = $("flow");
    clear(list);
    steps.forEach(function (s) {
      var v = n(s[1]);
      var li = el("li", (s[2] + (v ? "" : " zero")).trim());
      li.appendChild(el("span", "lbl", s[0]));
      li.appendChild(el("span", "n num", fmt(v)));
      var bar = el("span", "bar"), fill = el("span", "fill");
      fill.style.width = pct(v, max);
      bar.appendChild(fill); li.appendChild(bar);
      list.appendChild(li);
    });
  }

  function rules(list) {
    var ol = $("rules");
    clear(ol);
    if (!list.length) { ol.appendChild(el("li", "empty", "No alerts in the last 24 hours")); return; }
    var max = list[0].n;
    list.forEach(function (r, i) {
      var li = el("li", r.severity === "high" || r.severity === "critical" ? "hot" : "");
      li.appendChild(el("span", "rk", String(i + 1).padStart(2, "0")));
      li.appendChild(el("span", "nm", r.rule_id));
      li.appendChild(el("span", "num", fmt(r.n)));
      var bar = el("span", "bar"), fill = el("span", "fill");
      fill.style.width = pct(r.n, max);
      bar.appendChild(fill); li.appendChild(bar);
      ol.appendChild(li);
    });
  }

  function render(s) {
    var meta = s.meta || {};
    $("synthetic").hidden = !meta.synthetic;
    $("who-name").textContent = meta.user || "";
    $("f-sha").textContent = "build " + (meta.sha || "–").slice(0, 12);

    var c = s.counts, inbox = c.inbox || {}, req = c.requests || {};
    $("r-alerts").textContent = fmt(c.alerts_last_hour);
    $("r-total").textContent = fmt(c.alerts_total);
    $("r-total-t").textContent = "Last at " + time(c.last_ingest);
    $("r-forwarded").textContent = fmt(inbox.forwarded);
    $("r-forwarded-t").textContent = fmt(inbox.pending) + " queued, " + fmt(inbox.dead) + " failed";
    $("r-decisions").textContent = fmt(c.decisions);
    $("r-validated").textContent = fmt(req.validated);
    $("r-rejected").textContent = fmt(req.rejected);
    $("f-ingest").textContent = "Last ingest " + time(c.last_ingest);
    var tri = (s.feed || []).filter(function (a) { return a.triage; })[0];
    $("f-triage").textContent = "Triage " + (tri ? tri.triage.model || "unknown" : "idle");

    chart(s.timeline || []);
    flow(c, inbox, req);
    rules(s.top_rules || []);

    var L = s.ledger, ok = !!L.ok;
    $("chain-word").textContent = ok ? "intact" : "broken";
    $("chain-dot").className = "dot " + (ok ? "ok" : "bad");
    $("ledger-sub").textContent = "Checked " + time(L.checked_at);
    var head = $("ledger-head");
    clear(head);
    head.appendChild(el("div", "state " + (ok ? "ok" : "bad"), ok ? "Hash chain verified" : "Hash chain failed verification"));
    head.appendChild(el("div", "small", fmt(L.entries) + " entries, head #" + (L.head_seq === null ? "–" : L.head_seq)));
    head.appendChild(el("div", "mono", L.head_hash || "–"));
    (L.errors || []).forEach(function (e) { head.appendChild(el("div", "reasons", e)); });
    var led = $("ledger");
    clear(led);
    (L.tail || []).forEach(function (e) {
      var li = el("li");
      li.appendChild(el("span", "tm", "#" + e.seq));
      li.appendChild(el("span", "ev", e.event_type));
      li.appendChild(el("span", "mono", time(e.recorded_at) + "  " + e.actor));
      li.appendChild(el("span", "mono", short(e.prev_hash) + " → " + short(e.hash)));
      led.appendChild(li);
    });

    var K = s.kill_switch;
    document.body.classList.toggle("killed", !!K.any_engaged);
    $("kill").textContent = "Kill switch " + (K.global_engaged ? "engaged, global" : K.any_engaged ? "engaged, partial" : "off");
    var ks = $("ks");
    clear(ks);
    if (!K.scopes.length) ks.appendChild(el("li", "small", "Never changed. Every action follows policy"));
    K.scopes.forEach(function (k) {
      var li = el("li");
      li.appendChild(el("span", "tag " + (k.engaged ? "hot" : "ok"), k.engaged ? "Engaged" : "Off"));
      li.appendChild(el("span", "mono", k.scope + ", " + time(k.changed_at)));
      ks.appendChild(li);
    });

    var feed = $("feed");
    clear(feed);
    if (!s.feed.length) {
      var tr = el("tr"), td = el("td", "muted", "No alerts yet");
      td.colSpan = 5; tr.appendChild(td); feed.appendChild(tr);
    }
    s.feed.forEach(function (a) { feed.appendChild(row(a)); });
    $("updated").textContent = "Updated " + time(s.now);
    $("error").hidden = true;
  }

  function poll() {
    fetch("/api/state", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        if (r.status === 401) { window.location.assign("/login"); return null; }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (s) { if (s) render(s); })
      .catch(function (e) {
        var b = $("error");
        b.textContent = "Could not load data (" + e.message + "). Retrying";
        b.hidden = false;
      })
      .finally(function () { setTimeout(poll, POLL_MS); });
  }

  function tick() { $("clock").textContent = new Date().toLocaleTimeString("en-GB", tz); }
  document.addEventListener("DOMContentLoaded", function () { tick(); setInterval(tick, 1000); poll(); });
})();
