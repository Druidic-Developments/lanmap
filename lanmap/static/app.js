/* lanmap dashboard — vanilla JS, no build step. All editing is in place. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const DEVICE_TYPES = ["", "router", "switch", "access point", "server", "nas", "desktop",
    "laptop", "phone", "tablet", "tv", "console", "iot", "camera", "printer", "vm",
    "container", "other"];

  const state = {
    devices: [], ports: [], events: [], scans: [], status: null, localports: null,
    expanded: null,
    sort: { devices: { key: "ip", asc: true }, ports: { key: "port", asc: true } },
    filters: { devices: "", ports: "", onlineOnly: false, eventKinds: "" },
    lastScanId: null, wasRunning: false,
    map: { network: null, nodes: null, edges: null },
    editing: false,
  };

  // ------------------------------------------------------------------ utils
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (_) { /* ignore */ }
      throw new Error(detail);
    }
    return res.json();
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function rel(iso) {
    if (!iso) return "";
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return iso;
    const s = Math.round((Date.now() - t) / 1000);
    if (s < 0) return "now";
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function full(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function shortTs(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const sameDay = d.toDateString() === new Date().toDateString();
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return sameDay ? time : `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
  }

  function ipKey(ip) {
    if (!ip) return 0;
    const p = ip.split(".").map(Number);
    return p.length === 4 ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : 0;
  }

  function sortRows(rows, { key, asc }, table) {
    const dir = asc ? 1 : -1;
    return rows.slice().sort((a, b) => {
      let va = a[key], vb = b[key];
      if (table === "devices" && key === "name") { va = displayName(a); vb = displayName(b); }
      if (key === "ip") { va = ipKey(va); vb = ipKey(vb); }
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true }) * dir;
    });
  }

  function displayName(d) { return d.label || ""; }

  function toast(msg, isError = false) {
    const bar = $("#scan-text");
    bar.textContent = msg;
    $("#scan-dot").className = "dot " + (isError ? "error" : "running");
    setTimeout(refreshStatus, 2500);
  }

  // ------------------------------------------------------------------ tabs
  $$(".tab").forEach(btn => btn.addEventListener("click", () => {
    $$(".tab").forEach(b => b.classList.toggle("active", b === btn));
    $$(".panel").forEach(p => p.classList.toggle("active", p.id === "tab-" + btn.dataset.tab));
    if (btn.dataset.tab === "map") renderMap(true);
    if (btn.dataset.tab === "host") loadHost();
  }));

  function showTab(name) { $(`.tab[data-tab="${name}"]`).click(); }

  // ---------------------------------------------------------------- status
  async function refreshStatus() {
    try {
      const st = await api("/api/status");
      state.status = st;
      const s = st.stats, sc = st.scanner, cfg = st.settings;
      $("#s-online").textContent = s.devices_online;
      $("#s-total").textContent = s.devices_total;
      $("#s-ports").textContent = s.open_ports;
      $("#s-events").textContent = s.events_24h;
      $("#subnet-label").textContent = (cfg.subnets || []).join(", ") || "no subnet configured";
      $("#foot-nmap").textContent = sc.nmap_version || "nmap not found";
      $("#foot-root").textContent = sc.is_root ? "root: SYN + ARP scans" : "unprivileged: connect scans only";
      $("#foot-ver").textContent = "lanmap " + st.version;

      const dot = $("#scan-dot"), text = $("#scan-text"), q = $("#scan-queue"), nxt = $("#scan-next");
      if (sc.running) {
        dot.className = "dot running";
        text.textContent = `${sc.current.label} — ${sc.elapsed_seconds}s`;
      } else if (sc.last_error) {
        dot.className = "dot error";
        text.textContent = "Last scan failed: " + sc.last_error;
      } else {
        dot.className = "dot idle";
        text.textContent = s.last_scan ? `Idle — last scan ${rel(s.last_scan)}` : "Idle — no scans yet";
      }
      q.textContent = sc.queue.length ? `· ${sc.queue.length} queued` : "";
      const parts = [];
      if (sc.next_discovery_in_seconds != null) parts.push(`discovery in ${fmtDur(sc.next_discovery_in_seconds)}`);
      if (sc.next_port_scan_in_seconds != null) parts.push(`port scan in ${fmtDur(sc.next_port_scan_in_seconds)}`);
      nxt.textContent = parts.join(" · ");
      $("#btn-discover").disabled = !cfg.subnets || !cfg.subnets.length;

      // A scan just finished → refresh data.
      if (state.wasRunning && !sc.running) await refreshData();
      state.wasRunning = sc.running;
    } catch (e) {
      $("#scan-dot").className = "dot error";
      $("#scan-text").textContent = "API unreachable: " + e.message;
    }
  }

  function fmtDur(sec) {
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.round(sec / 60)}m`;
    return `${Math.floor(sec / 3600)}h${Math.round((sec % 3600) / 60)}m`;
  }

  async function refreshData() {
    if (state.editing) return;  // don't yank an input out from under the user
    const [devices, ports, events] = await Promise.all([
      api("/api/devices"), api("/api/ports"),
      api("/api/events?limit=300" + (state.filters.eventKinds ? "&kinds=" + state.filters.eventKinds : "")),
    ]);
    state.devices = devices; state.ports = ports; state.events = events;
    renderDevices(); renderPorts(); renderEvents();
    if ($("#tab-map").classList.contains("active")) renderMap(false);
  }

  // --------------------------------------------------------------- devices
  function deviceMatches(d, q) {
    if (!q) return true;
    const hay = [d.ip, d.label, d.hostname, d.mac, d.vendor, d.device_type, d.os_guess, d.notes]
      .map(x => (x || "").toLowerCase()).join(" ");
    return q.split(/\s+/).every(w => hay.includes(w));
  }

  function renderDevices() {
    const q = state.filters.devices.toLowerCase().trim();
    let rows = state.devices.filter(d => deviceMatches(d, q));
    if (state.filters.onlineOnly) rows = rows.filter(d => d.status === "online");
    rows = sortRows(rows, state.sort.devices, "devices");
    const gw = state.status?.settings?.gateway, me = state.status?.settings?.local_ip;
    const body = $("#dev-body");
    body.innerHTML = rows.map(d => {
      const tags = [];
      if (d.ip === gw) tags.push('<span class="tag gateway">gateway</span>');
      if (d.ip === me) tags.push('<span class="tag self">this host</span>');
      if (d.skip_ports) tags.push('<span class="tag skip" title="excluded from port scans">no scan</span>');
      const name = displayName(d);
      return `<tr class="row ${d.status} ${state.expanded === d.id ? "open" : ""}" data-id="${d.id}">
        <td class="c-status"><span class="sdot ${d.status}" title="${d.status}"></span></td>
        <td class="mono">${esc(d.ip)} ${tags.join(" ")}</td>
        <td><span class="editable ${d.label ? "" : "placeholder"}" data-edit="label" data-id="${d.id}">${esc(d.label || "name it")}</span></td>
        <td class="mono">${esc(d.hostname || "")}</td>
        <td class="mono muted">${esc(d.mac || "")}</td>
        <td>${esc(d.vendor || "")}</td>
        <td><span class="editable ${d.device_type ? "" : "placeholder"}" data-edit="device_type" data-id="${d.id}">${esc(d.device_type || "set type")}</span></td>
        <td class="num mono">${d.open_port_count || ""}</td>
        <td class="muted" title="${esc(full(d.last_seen))}">${rel(d.last_seen)}</td>
        <td class="muted" title="${esc(full(d.last_port_scan))}">${d.last_port_scan ? rel(d.last_port_scan) + (d.last_port_scan_kind === "deep" ? " (deep)" : "") : "never"}</td>
        <td class="c-actions"><button class="btn small" data-act="quick" data-id="${d.id}" ${d.skip_ports ? "disabled" : ""}>Quick scan</button></td>
      </tr>${state.expanded === d.id ? detailRow(d) : ""}`;
    }).join("");
    $("#dev-empty").hidden = rows.length > 0;
    $$("#dev-table th[data-sort]").forEach(th => {
      th.classList.toggle("sorted", th.dataset.sort === state.sort.devices.key);
      th.classList.toggle("asc", th.dataset.sort === state.sort.devices.key && state.sort.devices.asc);
    });
    if (state.expanded != null) loadDetail(state.expanded);
  }

  function detailRow(d) {
    return `<tr class="detail" data-detail="${d.id}"><td colspan="11"><div class="detail" id="detail-${d.id}"><span class="muted">loading…</span></div></td></tr>`;
  }

  async function loadDetail(id) {
    const el = $(`#detail-${id}`);
    if (!el) return;
    let d;
    try { d = await api(`/api/devices/${id}`); } catch (e) { el.innerHTML = `<span class="muted">${esc(e.message)}</span>`; return; }
    if (state.editing) return;
    const ports = d.ports.length
      ? `<table class="ports-mini"><thead><tr><th>Port</th><th>Service</th><th>What's running</th><th>First seen</th></tr></thead><tbody>
          ${d.ports.map(p => `<tr><td class="mono">${p.port}/${p.protocol}</td><td>${esc(p.service || "")}</td><td>${esc(summary(p))}</td><td class="muted" title="${esc(full(p.first_seen))}">${rel(p.first_seen)}</td></tr>`).join("")}
         </tbody></table>`
      : `<p class="muted">${d.last_port_scan ? "No open ports found." : "Not port-scanned yet."}</p>`;
    const evs = d.events.length
      ? `<ul class="feed-mini">${d.events.map(e => `<li><span class="muted mono">${rel(e.ts)}</span> ${esc(e.message)}</li>`).join("")}</ul>`
      : `<p class="muted">No changes recorded.</p>`;
    el.innerHTML = `
      <div class="detail-grid">
        <div>
          <h4>Open ports ${d.ports.length ? `(${d.ports.length})` : ""}</h4>
          ${ports}
          <div class="detail-actions">
            <button class="btn small" data-act="quick" data-id="${d.id}" ${d.skip_ports ? "disabled" : ""}>Quick scan (top 1000)</button>
            <button class="btn small" data-act="deep" data-id="${d.id}" ${d.skip_ports ? "disabled" : ""}>Deep scan (all ports + OS)</button>
            <input type="text" placeholder="custom ports e.g. 1-1024,8080" data-custom="${d.id}">
            <button class="btn small" data-act="custom" data-id="${d.id}" ${d.skip_ports ? "disabled" : ""}>Scan</button>
          </div>
          <label class="chk"><input type="checkbox" data-act="skip" data-id="${d.id}" ${d.skip_ports ? "checked" : ""}> exclude from port scans (fragile device)</label>
        </div>
        <div>
          <h4>Details</h4>
          <dl class="kv">
            <dt>Status</dt><dd><span class="sdot ${d.status}"></span> ${d.status}${d.misses ? ` <span class="muted">(${d.misses} missed sweep${d.misses > 1 ? "s" : ""})</span>` : ""}</dd>
            <dt>IP</dt><dd class="mono">${esc(d.ip)} <span class="muted">${esc(d.subnet || "")}</span></dd>
            <dt>MAC</dt><dd class="mono">${esc(d.mac || "—")} ${d.vendor ? `<span class="muted">${esc(d.vendor)}</span>` : ""}</dd>
            <dt>Hostname</dt><dd class="mono">${esc(d.hostname || "—")}</dd>
            <dt>OS guess</dt><dd>${d.os_guess ? `${esc(d.os_guess)} <span class="muted">${d.os_accuracy}%</span>` : '<span class="muted">run a deep scan</span>'}</dd>
            <dt>Latency</dt><dd>${d.latency_ms != null ? d.latency_ms + " ms" : "—"}</dd>
            <dt>First seen</dt><dd title="${esc(full(d.first_seen))}">${rel(d.first_seen)}</dd>
            <dt>Last seen</dt><dd title="${esc(full(d.last_seen))}">${rel(d.last_seen)}</dd>
            <dt>Port scan</dt><dd title="${esc(full(d.last_port_scan))}">${d.last_port_scan ? `${rel(d.last_port_scan)} (${d.last_port_scan_kind})` : "never"}</dd>
          </dl>
          <h4>Notes</h4>
          <textarea class="inline-input" data-notes="${d.id}" placeholder="click to add notes…">${esc(d.notes || "")}</textarea>
          <h4 style="margin-top:12px">Recent changes</h4>
          ${evs}
          <div class="detail-actions" style="margin-top:12px">
            <button class="btn small danger" data-act="forget" data-id="${d.id}">Forget device</button>
            <span class="muted">removes it and its history; it will reappear if seen again</span>
          </div>
        </div>
      </div>`;
  }

  function summary(p) {
    const parts = [p.product, p.version].filter(Boolean);
    let s = parts.length ? parts.join(" ") : (p.service || "unknown");
    if (p.extrainfo) s += ` (${p.extrainfo})`;
    return s;
  }

  // in-place editing -------------------------------------------------------
  function startEdit(span) {
    const id = Number(span.dataset.id), field = span.dataset.edit;
    const device = state.devices.find(d => d.id === id);
    if (!device) return;
    const td = span.closest("td");
    let input;
    if (field === "device_type") {
      input = document.createElement("select");
      input.className = "inline-input";
      DEVICE_TYPES.forEach(t => {
        const o = document.createElement("option");
        o.value = t; o.textContent = t || "(none)";
        if ((device.device_type || "") === t) o.selected = true;
        input.appendChild(o);
      });
    } else {
      input = document.createElement("input");
      input.type = "text"; input.className = "inline-input";
      input.value = device[field] || "";
      input.placeholder = device.hostname || "name";
    }
    state.editing = true;
    td.innerHTML = ""; td.appendChild(input); input.focus();
    if (input.select) input.select();
    let done = false;
    const finish = async (save) => {
      if (done) return; done = true; state.editing = false;
      if (save) {
        const value = input.value;
        if ((device[field] || "") !== value) {
          try {
            await api(`/api/devices/${id}`, { method: "PATCH", body: { [field]: value } });
            device[field] = value || null;
          } catch (e) { toast("Save failed: " + e.message, true); }
        }
      }
      renderDevices();
    };
    input.addEventListener("keydown", e => {
      if (e.key === "Enter") { e.preventDefault(); finish(true); }
      if (e.key === "Escape") finish(false);
    });
    input.addEventListener("blur", () => finish(true));
    if (field === "device_type") input.addEventListener("change", () => finish(true));
  }

  $("#dev-body").addEventListener("click", async e => {
    const edit = e.target.closest(".editable");
    if (edit) { e.stopPropagation(); startEdit(edit); return; }
    const act = e.target.closest("[data-act]");
    if (act && act.tagName === "BUTTON") {
      e.stopPropagation();
      await runAction(act.dataset.act, Number(act.dataset.id), act);
      return;
    }
    if (e.target.closest("input, select, textarea, label")) return;
    const row = e.target.closest("tr.row");
    if (!row) return;
    const id = Number(row.dataset.id);
    state.expanded = state.expanded === id ? null : id;
    renderDevices();
  });

  $("#dev-body").addEventListener("change", async e => {
    const skip = e.target.closest('input[data-act="skip"]');
    if (skip) {
      const id = Number(skip.dataset.id);
      try {
        await api(`/api/devices/${id}`, { method: "PATCH", body: { skip_ports: skip.checked } });
        const d = state.devices.find(x => x.id === id); if (d) d.skip_ports = skip.checked;
        renderDevices();
      } catch (err) { toast("Save failed: " + err.message, true); }
    }
  });

  $("#dev-body").addEventListener("focusin", e => { if (e.target.matches("textarea[data-notes]")) state.editing = true; });
  $("#dev-body").addEventListener("focusout", async e => {
    const ta = e.target.closest("textarea[data-notes]");
    if (!ta) return;
    state.editing = false;
    const id = Number(ta.dataset.notes);
    const d = state.devices.find(x => x.id === id);
    if (d && (d.notes || "") !== ta.value) {
      try { await api(`/api/devices/${id}`, { method: "PATCH", body: { notes: ta.value } }); d.notes = ta.value; }
      catch (err) { toast("Save failed: " + err.message, true); }
    }
  });

  async function runAction(act, id, btn) {
    try {
      if (act === "quick" || act === "deep") {
        const r = await api("/api/scan/ports", { method: "POST", body: { device_ids: [id], deep: act === "deep" } });
        toast("Queued: " + r.queued.label);
      } else if (act === "custom") {
        const input = $(`input[data-custom="${id}"]`);
        const spec = (input?.value || "").trim();
        if (!spec) { input?.focus(); return; }
        const r = await api("/api/scan/ports", { method: "POST", body: { device_ids: [id], ports: spec } });
        toast("Queued: " + r.queued.label + " (" + spec + ")");
      } else if (act === "forget") {
        if (btn.dataset.confirm !== "1") {
          btn.dataset.confirm = "1"; btn.textContent = "Click again to confirm"; return;
        }
        await api(`/api/devices/${id}`, { method: "DELETE" });
        state.expanded = null;
        await refreshData(); await refreshStatus();
      }
    } catch (e) { toast(e.message, true); }
  }

  $("#dev-filter").addEventListener("input", e => { state.filters.devices = e.target.value; renderDevices(); });
  $("#dev-online-only").addEventListener("change", e => { state.filters.onlineOnly = e.target.checked; renderDevices(); });
  $("#dev-table thead").addEventListener("click", e => {
    const th = e.target.closest("th[data-sort]"); if (!th) return;
    const s = state.sort.devices;
    if (s.key === th.dataset.sort) s.asc = !s.asc; else { s.key = th.dataset.sort; s.asc = true; }
    renderDevices();
  });

  // ----------------------------------------------------------------- ports
  function renderPorts() {
    const q = state.filters.ports.toLowerCase().trim();
    let rows = state.ports.map(p => ({ ...p, summary: summary(p), name: p.label || p.hostname || "" }));
    if (q) rows = rows.filter(p => {
      const hay = [p.port, p.protocol, p.service, p.summary, p.ip, p.name].map(x => String(x ?? "").toLowerCase()).join(" ");
      return q.split(/\s+/).every(w => hay.includes(w));
    });
    rows = sortRows(rows, state.sort.ports, "ports");
    $("#port-body").innerHTML = rows.map(p => `<tr class="${p.device_status}">
      <td class="num mono">${p.port}</td><td class="mono">${p.protocol}</td>
      <td>${esc(p.service || "")}</td><td>${esc(p.summary)}</td>
      <td class="mono"><a href="#" data-goto="${p.device_id}">${esc(p.ip)}</a> ${p.name ? `<span class="muted">${esc(p.name)}</span>` : ""}</td>
      <td class="muted">${esc(p.state)}</td>
      <td class="muted" title="${esc(full(p.first_seen))}">${rel(p.first_seen)}</td>
      <td class="muted" title="${esc(full(p.last_seen))}">${rel(p.last_seen)}</td></tr>`).join("");
    $("#port-empty").hidden = rows.length > 0;
    $("#port-count").textContent = `${rows.length} open port${rows.length === 1 ? "" : "s"} across ${new Set(rows.map(r => r.device_id)).size} device${new Set(rows.map(r => r.device_id)).size === 1 ? "" : "s"}`;
    $$("#port-table th[data-sort]").forEach(th => {
      th.classList.toggle("sorted", th.dataset.sort === state.sort.ports.key);
      th.classList.toggle("asc", th.dataset.sort === state.sort.ports.key && state.sort.ports.asc);
    });
  }
  $("#port-filter").addEventListener("input", e => { state.filters.ports = e.target.value; renderPorts(); });
  $("#port-table thead").addEventListener("click", e => {
    const th = e.target.closest("th[data-sort]"); if (!th) return;
    const s = state.sort.ports;
    if (s.key === th.dataset.sort) s.asc = !s.asc; else { s.key = th.dataset.sort; s.asc = true; }
    renderPorts();
  });
  $("#port-body").addEventListener("click", e => {
    const a = e.target.closest("[data-goto]"); if (!a) return;
    e.preventDefault(); gotoDevice(Number(a.dataset.goto));
  });

  function gotoDevice(id) {
    state.expanded = id; state.filters.devices = ""; $("#dev-filter").value = "";
    showTab("devices"); renderDevices();
    setTimeout(() => $(`tr.row[data-id="${id}"]`)?.scrollIntoView({ block: "center" }), 50);
  }

  // ------------------------------------------------------------------- map
  const COLORS = {
    gateway: "#ffb347", self: "#c58cff", online: "#3ddc84", offline: "#5d6b7c", subnet: "#5d6b7c",
  };
  // Only shapes that draw the label *below* the node (box/ellipse put it inside).
  const SHAPES = { router: "diamond", switch: "square", "access point": "triangle", server: "square",
    nas: "square", vm: "square", container: "square", printer: "hexagon", camera: "triangleDown",
    phone: "star", tablet: "star", laptop: "star" };

  function mapLabel(n) {
    if (n.kind === "subnet") return n.label;
    if (n.label && n.label !== n.ip) return `${n.label}\n${n.ip}`;
    const vendor = (n.vendor || "").split(/[\s,]+/)[0];
    return vendor ? `${vendor}\n${n.ip}` : n.ip;
  }

  async function renderMap(fit) {
    let data;
    try { data = await api("/api/map"); } catch (e) { return; }
    const nodes = data.nodes.map(n => {
      const col = n.kind === "subnet" ? COLORS.subnet : n.kind === "gateway" ? COLORS.gateway :
        n.kind === "self" ? COLORS.self : (n.status === "online" ? COLORS.online : COLORS.offline);
      const shape = n.kind === "subnet" ? "box" : n.kind === "gateway" ? "diamond" : (SHAPES[n.kind] || "dot");
      const title = n.kind === "subnet" ? n.label :
        `${n.label}\n${n.ip}${n.vendor ? "\n" + n.vendor : ""}\n${n.open_port_count} open port(s)\n${n.status}`;
      return {
        id: n.id, label: mapLabel(n), shape, title,
        color: { background: col, border: col, highlight: { background: "#fff", border: col } },
        font: { color: "#d7dee7", size: 11, face: "system-ui", multi: false },
        size: n.kind === "gateway" ? 26 : (n.kind === "subnet" ? 20 : 12 + Math.min(10, n.open_port_count)),
        mass: n.kind === "gateway" || n.kind === "subnet" ? 4 : 1,
        _raw: n,
      };
    });
    const edges = data.edges.map(e => ({ ...e, color: { color: "#2a3441", highlight: "#4cc2ff" }, width: 1 }));
    if (!state.map.network) {
      state.map.nodes = new vis.DataSet(nodes);
      state.map.edges = new vis.DataSet(edges);
      state.map.network = new vis.Network($("#map"), { nodes: state.map.nodes, edges: state.map.edges }, {
        physics: { enabled: $("#map-physics").checked, solver: "forceAtlas2Based",
          forceAtlas2Based: { gravitationalConstant: -60, springLength: 90, avoidOverlap: 0.6 },
          stabilization: { iterations: 200 } },
        interaction: { hover: true, tooltipDelay: 150 },
        nodes: { borderWidth: 1 },
        edges: { smooth: false },
      });
      state.map.network.on("click", params => {
        const id = params.nodes[0];
        const side = $("#map-side");
        if (!id) { side.hidden = true; return; }
        const n = state.map.nodes.get(id)._raw;
        if (n.kind === "subnet") { side.hidden = true; return; }
        const d = state.devices.find(x => x.id === n.device_id);
        side.hidden = false;
        side.innerHTML = `<h4>${esc(n.label)}</h4>
          <dl class="kv">
            <dt>IP</dt><dd class="mono">${esc(n.ip)}</dd>
            <dt>Status</dt><dd><span class="sdot ${n.status}"></span> ${n.status}</dd>
            <dt>Vendor</dt><dd>${esc(n.vendor || "—")}</dd>
            <dt>MAC</dt><dd class="mono">${esc(d?.mac || "—")}</dd>
            <dt>Ports</dt><dd>${n.open_port_count} open</dd>
            <dt>Type</dt><dd>${esc(d?.device_type || "—")}</dd>
          </dl>
          <button class="btn small" data-goto="${n.device_id}">Open in Devices</button>`;
      });
      $("#map-side").addEventListener("click", e => {
        const b = e.target.closest("[data-goto]"); if (b) gotoDevice(Number(b.dataset.goto));
      });
    } else {
      // Update in place so positions survive refreshes.
      const existing = new Set(state.map.nodes.getIds());
      nodes.forEach(n => existing.has(n.id) ? state.map.nodes.update(n) : state.map.nodes.add(n));
      state.map.nodes.getIds().forEach(id => { if (!nodes.find(n => n.id === id)) state.map.nodes.remove(id); });
      state.map.edges.clear(); state.map.edges.add(edges);
    }
    if (fit) setTimeout(() => state.map.network.fit({ animation: false }), 300);
  }
  $("#map-physics").addEventListener("change", e => state.map.network?.setOptions({ physics: { enabled: e.target.checked } }));
  $("#map-fit").addEventListener("click", () => state.map.network?.fit());

  // ---------------------------------------------------------------- events
  function renderEvents() {
    const list = $("#ev-list");
    list.innerHTML = state.events.map(e => `<li class="sev-${e.severity} k-${e.kind}">
      <span class="ts" title="${esc(full(e.ts))}">${esc(shortTs(e.ts))}</span>
      <span class="kind">${esc(e.kind.replace(/_/g, " "))}</span>
      <span>${e.device_id ? `<a href="#" data-goto="${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</span>
    </li>`).join("");
    $("#ev-empty").hidden = state.events.length > 0;
  }
  $("#ev-list").addEventListener("click", e => {
    const a = e.target.closest("[data-goto]"); if (!a) return;
    e.preventDefault(); gotoDevice(Number(a.dataset.goto));
  });
  $("#ev-kind").addEventListener("change", async e => { state.filters.eventKinds = e.target.value; await refreshData(); });
  $("#btn-scans").addEventListener("click", async () => {
    const box = $("#scan-history");
    box.hidden = !box.hidden;
    if (box.hidden) return;
    const scans = await api("/api/scans?limit=100");
    $("#scan-body").innerHTML = scans.map(s => `<tr>
      <td class="mono">${s.id}</td><td>${esc(s.kind)}</td>
      <td class="${s.status === "failed" ? "mono" : "muted"}">${esc(s.status)}</td>
      <td class="mono muted">${esc(s.targets.length > 3 ? s.targets.length + " hosts" : s.targets.join(", "))}</td>
      <td class="num">${s.hosts_up ?? ""}</td><td class="num">${s.event_count}</td>
      <td class="muted">${esc(full(s.started_at))}</td><td class="muted">${esc(full(s.finished_at))}</td>
      <td class="muted">${esc(s.error || "")}</td></tr>`).join("");
  });

  // ------------------------------------------------------------------ host
  async function loadHost() {
    try {
      const r = await api("/api/localports");
      const msg = r.error || r.hint;
      $("#host-error").hidden = !msg;
      $("#host-error").textContent = msg || "";
      $("#host-body").innerHTML = r.sockets.map(s => `<tr>
        <td class="num mono">${s.port}</td><td class="mono">${s.protocol}</td>
        <td class="mono">${esc(s.local_addr)}</td>
        <td>${esc(s.process || "")}${!s.process ? '<span class="muted">unknown</span>' : ""}</td>
        <td class="mono muted">${s.pid ?? ""}</td>
        <td>${s.exposed ? "yes" : '<span class="muted">localhost only</span>'}</td></tr>`).join("");
    } catch (e) { $("#host-error").hidden = false; $("#host-error").textContent = e.message; }
  }

  // --------------------------------------------------------------- buttons
  $("#btn-discover").addEventListener("click", async () => {
    try { const r = await api("/api/scan/discovery", { method: "POST" }); toast("Queued: " + r.queued.label); }
    catch (e) { toast(e.message, true); }
  });
  $("#btn-scan-all").addEventListener("click", async () => {
    try { const r = await api("/api/scan/ports", { method: "POST", body: { all_online: true } }); toast("Queued: " + r.queued.label); }
    catch (e) { toast(e.message, true); }
  });

  // ------------------------------------------------------------------ boot
  (async () => {
    await refreshStatus();
    await refreshData();
    setInterval(refreshStatus, 3000);
    setInterval(refreshData, 30000);
  })();
})();
