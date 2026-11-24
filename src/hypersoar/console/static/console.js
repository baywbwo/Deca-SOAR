"use strict";
// Read-only console: polls /api/state and renders with textContent only (alert fields are untrusted).
(function () {
  var POLL_MS = 5000;
  var $ = function (id) { return document.getElementById(id); };
  var tz = { timeZone: "Asia/Jakarta", hour12: false };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function time(iso) {
    if (!iso) return "–";
    return new Date(iso).toLocaleTimeString("id-ID", tz);
  }
  function n(v) { return v === undefined || v === null ? "0" : String(v); }
  function short(h) { return h ? h.slice(0, 12) + "…" : "–"; }

  var VERDICT = { malicious: ["hot", "berbahaya"], suspicious: ["wait", "mencurigakan"], benign: ["ok", "aman"] };
  var BROKER = {
    validated: ["ok", "Lolos kebijakan, tidak dieksekusi"],
    rejected: ["hot", "Ditolak kebijakan"],
    pending_approval: ["wait", "Perlu persetujuan"],
    expired: ["sh", "Kedaluwarsa"]
  };
  var GATEWAY = { forwarded: ["act", "diteruskan"], pending: ["wait", "antre"], dead: ["hot", "gagal"] };

  function row(a) {
    var tr = el("tr");
    var t = el("td"); t.appendChild(el("div", "tm", time(a.ingested_at)));
    t.appendChild(el("div", "small", "deteksi " + time(a.detected_at)));
    tr.appendChild(t);

    var al = el("td");
    al.appendChild(el("div", "ttl", a.rule_id));
    var m = el("div", "meta");
    m.appendChild(el("span", "sev " + (a.severity || ""), a.severity));
    m.appendChild(el("span", "tag sh", a.source));
    m.appendChild(el("span", "small", a.event_count + " event"));
    al.appendChild(m);
    if (a.src_token) al.appendChild(el("div", "mono", "src " + a.src_token));
    if (a.uri) al.appendChild(el("div", "mono", a.uri));
    tr.appendChild(al);

    var g = GATEWAY[a.gateway_status] || ["sh", a.gateway_status];
    var gw = el("td"); gw.appendChild(el("span", "tag " + g[0], g[1]));
    if (a.forwarded_at) gw.appendChild(el("div", "small", "→ Temporal " + time(a.forwarded_at)));
    tr.appendChild(gw);

    var tri = el("td");
    if (a.triage) {
      var v = VERDICT[a.triage.verdict] || ["sh", a.triage.verdict];
      tri.appendChild(el("span", "tag " + v[0], v[1]));
      var c = typeof a.triage.confidence === "number" ? a.triage.confidence.toFixed(2).replace(".", ",") : "–";
      tri.appendChild(el("div", "small", "keyakinan " + c + " · " + (a.triage.model || "–")));
    } else {
      tri.appendChild(el("span", "small", a.source === "waf" ? "menunggu worker" : "tidak diajukan ke broker (non-WAF)"));
    }
    tr.appendChild(tri);

    var br = el("td");
    if (a.broker) {
      var b = BROKER[a.broker.status] || ["sh", a.broker.status];
      var bm = el("div", "meta");
      bm.appendChild(el("span", "tag " + b[0], b[1]));
      bm.appendChild(el("span", "tag sh", a.broker.level + " · " + a.broker.mode));
      br.appendChild(bm);
      br.appendChild(el("div", "mono", a.broker.action));
      if (a.broker.would_execute) br.appendChild(el("div", "mono", "akan: " + a.broker.would_execute));
      if (a.broker.reasons && a.broker.reasons.length) br.appendChild(el("div", "reasons", a.broker.reasons.join("; ")));
    } else {
      br.appendChild(el("span", "small", "–"));
    }
    tr.appendChild(br);
    return tr;
  }

  function render(s) {
    var meta = s.meta || {};
    $("synthetic").hidden = !meta.synthetic;
    $("who-name").textContent = meta.user || "";
    $("f-sha").textContent = "build " + (meta.sha || "–").slice(0, 12);

    var c = s.counts, inbox = c.inbox || {}, req = c.requests || {};
    $("r-alerts").textContent = n(c.alerts_last_hour);
    $("r-alerts-t").textContent = "total " + n(c.alerts_total);
    $("r-forwarded").textContent = n(inbox.forwarded);
    $("r-forwarded-t").textContent = "antre " + n(inbox.pending) + " · gagal " + n(inbox.dead);
    $("r-decisions").textContent = n(c.decisions);
    $("r-validated").textContent = n(req.validated);
    $("r-rejected").textContent = n(req.rejected);
    $("f-ingest").textContent = "Ingest terakhir " + time(c.last_ingest);

    var flow = $("flow"); clear(flow);
    [["Alert masuk gateway", c.alerts_total], ["Diteruskan ke Temporal", inbox.forwarded],
     ["Keputusan broker (shadow)", c.decisions], ["Lolos kebijakan", req.validated],
     ["Ditolak kebijakan", req.rejected], ["Dieksekusi", req.executed]].forEach(function (p) {
      var li = el("li"); li.appendChild(el("span", null, p[0])); li.appendChild(el("span", null, n(p[1]))); flow.appendChild(li);
    });

    var L = s.ledger;
    var ok = !!L.ok;
    $("chain-word").textContent = ok ? "utuh" : "RUSAK";
    $("chain-dot").className = "dot " + (ok ? "ok" : "bad");
    $("ledger-sub").textContent = "dicek " + time(L.checked_at);
    var head = $("ledger-head"); clear(head);
    head.appendChild(el("div", "big " + (ok ? "ok" : "bad"), ok ? "Rantai hash valid" : "Rantai hash tidak valid"));
    head.appendChild(el("div", "small", L.entries + " entri · head #" + (L.head_seq === null ? "–" : L.head_seq)));
    head.appendChild(el("div", "mono", "head " + (L.head_hash || "–")));
    (L.errors || []).forEach(function (e) { head.appendChild(el("div", "reasons", e)); });
    var led = $("ledger"); clear(led);
    (L.tail || []).forEach(function (e) {
      var li = el("li");
      li.appendChild(el("span", "tm", "#" + e.seq));
      li.appendChild(el("span", null, e.event_type));
      li.appendChild(el("span", "mono", time(e.recorded_at) + " · " + e.actor));
      li.appendChild(el("span", "mono", "prev " + short(e.prev_hash) + " → " + short(e.hash)));
      led.appendChild(li);
    });

    var K = s.kill_switch;
    document.body.classList.toggle("killed", !!K.any_engaged);
    $("kill").textContent = "Kill switch: " + (K.global_engaged ? "AKTIF (global)" : K.any_engaged ? "aktif sebagian" : "tidak aktif");
    var ks = $("ks"); clear(ks);
    if (!K.scopes.length) ks.appendChild(el("li", "small", "Belum pernah diubah. Semua aksi mengikuti kebijakan."));
    K.scopes.forEach(function (k) {
      var li = el("li", "meta");
      li.appendChild(el("span", "tag " + (k.engaged ? "hot" : "ok"), k.engaged ? "aktif" : "tidak aktif"));
      li.appendChild(el("span", "mono", k.scope + " · " + time(k.changed_at)));
      ks.appendChild(li);
    });

    var feed = $("feed"); clear(feed);
    if (!s.feed.length) {
      var tr = el("tr"), td = el("td", "small", "Belum ada alert."); td.colSpan = 5; tr.appendChild(td); feed.appendChild(tr);
    }
    s.feed.forEach(function (a) { feed.appendChild(row(a)); });
    $("updated").textContent = "diperbarui " + time(s.now);
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
        var b = $("error"); b.textContent = "Gagal memuat data (" + e.message + "). Mencoba lagi…"; b.hidden = false;
      })
      .finally(function () { setTimeout(poll, POLL_MS); });
  }

  function tick() { $("clock").textContent = new Date().toLocaleTimeString("id-ID", tz); }
  document.addEventListener("DOMContentLoaded", function () { tick(); setInterval(tick, 1000); poll(); });
})();
