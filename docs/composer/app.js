(() => {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

  const form = $("#form");
  const meshRows = $("#meshRows");
  const branchRows = $("#branchRows");
  const satRows = $("#satRows");
  const preview = $("#preview");
  const previewWrap = $("#previewWrap");
  const copyBtn = $("#copyBtn");
  const dlSat = $("#dlSat");
  const behind = $("#behindSwitch");
  const sameSegWrap = $("#sameSegWrap");

  let lastCoord = "";
  let lastSats = []; // [{name, text}, ...]

  function escYaml(s) {
    return String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  function sanitizeBranchId(raw) {
    let id = String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "_")
      .replace(/^_+|_+$/g, "");
    if (!id) id = "spur";
    if (/^[0-9]/.test(id)) id = "g_" + id;
    return id.slice(0, 48);
  }

  function randToken() {
    const a = new Uint8Array(24);
    crypto.getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function addMesh(ip = "") {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="fields">
        <label>IP <input data-k="ip" value="${escAttr(ip)}" placeholder="192.168.1.2" /></label>
      </div>
      <button type="button" class="linkish" data-rm>remove</button>`;
    meshRows.appendChild(row);
  }

  function addBranch(id = "", hosts = "", attach = "gateway") {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="fields">
        <label>Group id <input data-k="id" value="${escAttr(id)}" placeholder="living_room" /></label>
        <label>Host IPs <input data-k="hosts" value="${escAttr(hosts)}" placeholder="192.168.1.10, 192.168.1.11" /></label>
        <label>Attach
          <select data-k="attach">
            <option value="gateway"${attach === "gateway" ? " selected" : ""}>gateway</option>
            <option value="local_switch"${attach === "local_switch" ? " selected" : ""}>local_switch</option>
          </select>
        </label>
      </div>
      <button type="button" class="linkish" data-rm>remove</button>`;
    branchRows.appendChild(row);
  }

  function addSat(vals = {}) {
    const row = document.createElement("div");
    row.className = "row";
    const link = vals.link || "ethernet";
    const avail = vals.availability || (link === "wifi" ? "intermittent" : "always");
    const place = vals.placement || "router";
    row.innerHTML = `
      <div class="fields">
        <label>Id <input data-k="id" value="${escAttr(vals.id || "sat-wired-1")}" /></label>
        <label>Link
          <select data-k="link">
            <option value="ethernet"${link === "ethernet" ? " selected" : ""}>ethernet</option>
            <option value="wifi"${link === "wifi" ? " selected" : ""}>wifi</option>
          </select>
        </label>
        <label>Availability
          <select data-k="availability">
            <option value="always"${avail === "always" ? " selected" : ""}>always</option>
            <option value="intermittent"${avail === "intermittent" ? " selected" : ""}>intermittent</option>
          </select>
        </label>
        <label>Placement
          <select data-k="placement">
            <option value="router"${place === "router" ? " selected" : ""}>router</option>
            <option value="other"${place === "other" ? " selected" : ""}>other</option>
          </select>
        </label>
        <label>Satellite IFACE <input data-k="iface" value="${escAttr(vals.iface || "eth0")}" /></label>
      </div>
      <button type="button" class="linkish" data-rm>remove</button>`;
    satRows.appendChild(row);
  }

  function escAttr(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;");
  }

  function readRows(container) {
    return $$(".row", container).map((row) => {
      const o = {};
      $$("[data-k]", row).forEach((el) => {
        o[el.getAttribute("data-k")] = el.value.trim();
      });
      return o;
    });
  }

  function splitIps(s) {
    return String(s || "")
      .split(/[,\s]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function yamlList(ips) {
    return "[" + ips.map((ip) => `"${escYaml(ip)}"`).join(", ") + "]";
  }

  function indentBlock(text, n) {
    const pad = " ".repeat(n);
    return text
      .split("\n")
      .map((line) => (line.length ? pad + line : pad))
      .join("\n");
  }

  function buildConfigYaml(d) {
    const meshes = readRows(meshRows).filter((r) => r.ip);
    const branches = readRows(branchRows).filter((r) => r.id && r.hosts);
    const sats = readRows(satRows).filter((r) => r.id);
    const ext = splitIps(d.externalIps);
    const wifi = (d.wifiIp || "").trim();

    let groups = "";
    groups += `  - id: router\n    role: gateway\n    hosts: ${yamlList([d.gatewayIp])}\n`;
    meshes.forEach((m, i) => {
      groups += `\n  - id: mesh_${i + 1}\n    role: mesh\n    hosts: ${yamlList([m.ip])}\n`;
    });
    branches.forEach((b) => {
      const hosts = splitIps(b.hosts);
      const id = sanitizeBranchId(b.id);
      groups += `\n  - id: ${id}\n    role: branch\n    attach: ${b.attach || "gateway"}\n    hosts: ${yamlList(hosts)}\n`;
    });
    if (d.behindSwitch && d.sameSegmentIp) {
      groups += `\n  - id: same_switch_as_probe\n    role: same_segment\n    hosts: ${yamlList([d.sameSegmentIp])}\n`;
    }
    if (wifi) {
      groups += `\n  - id: wifi_sample\n    role: wifi\n    hosts: ${yamlList([wifi])}\n`;
    }
    groups += `\n  - id: internet\n    role: external\n    hosts: ${yamlList(ext.length ? ext : ["1.1.1.1", "8.8.8.8"])}\n`;

    let satBlock = "satellites: []\n";
    if (sats.length) {
      satBlock = "satellites:\n";
      sats.forEach((s) => {
        satBlock += `  - id: ${s.id}\n    link: ${s.link}\n    availability: ${s.availability}\n    placement: ${s.placement}\n`;
      });
    }

    const behindYaml = d.behindSwitch
      ? "  behind_switch: true\n"
      : "  # behind_switch: true\n";

    return `site:
  name: "${escYaml(d.siteName)}"
  timezone: ${d.timezone}

vantage:
  id: coordinator
  link: ethernet
  availability: always
${behindYaml}  note: "main probe on the home LAN"

capture:
  iface: ${d.iface}
  snaplen: ${d.snaplen}
  rotate_hours: 1
  keep_hours: ${d.keepHours}

ingest:
  enabled: true
  host: "0.0.0.0"
  port: 8787
  token: "${escYaml(d.token)}"

${satBlock}
groups:
${groups}
dhcp:
  expected_server_mac: ""

dns:
  resolvers: ${yamlList([d.gatewayIp])}
  names: ["example.com", "cloudflare.com", "google.com"]

thresholds:
  ping_interval_s: ${d.pingInterval}
  incident_clear_s: 60
  warmup_s: ${d.warmup}
  loss_threshold_pct: ${d.lossPct}
  fail_rounds: 2
  confirm_rounds: ${d.confirmRounds}
  dns_interval_s: 30
  dns_timeout_ms: 1500
  path_interval_s: 300
  bcast_pps_warn: 200
  satellite_stale_s: 45
  satellite_offline_after_s: 1200
  report_interval_s: 60
  csv_keep_days: ${d.csvKeep}
  incident_html_keep_days: ${d.incKeep}
`;
  }

  function buildCoordinatorCompose(d) {
    const cfg = buildConfigYaml(d);
    const indented = indentBlock(cfg.trimEnd(), 8);
    return `# Generated by netdiag compose builder (client-side only).
# Edit as needed, then: docker compose up -d
# Image: ghcr.io/emil007/netdiag:latest

services:
  analyzer:
    image: ghcr.io/emil007/netdiag:latest
    container_name: netdiag-analyzer
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      TZ: ${d.timezone}
      IFACE: ${d.iface}
      NETDIAG_INGEST_TOKEN: ${d.token}
      NETDIAG_DATA: /data
      NETDIAG_CONFIG_YAML: |
${indented}
    volumes:
      - ./data:/data
    restart: unless-stopped

  capture:
    image: ghcr.io/emil007/netdiag:latest
    container_name: netdiag-capture
    command: ["capture"]
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      TZ: ${d.timezone}
      IFACE: ${d.iface}
      NETDIAG_DATA: /data
      # Keep identical to analyzer capture.snaplen / keep_hours
      NETDIAG_SNAPLEN: "${d.snaplen}"
      NETDIAG_KEEP_HOURS: "${d.keepHours}"
      NETDIAG_ROTATE_HOURS: "1"
    volumes:
      - ./data:/data
    restart: unless-stopped
`;
  }

  function buildSatelliteCompose(d, sat) {
    const url = d.coordIp
      ? `http://${d.coordIp}:8787/ingest`
      : "http://192.168.1.10:8787/ingest";
    const cfg = `site:
  name: "${escYaml(d.siteName)}"
  timezone: ${d.timezone}

vantage:
  id: ${sat.id}
  link: ${sat.link}
  availability: ${sat.availability}
  note: "satellite vantage"

capture:
  iface: ${sat.iface || d.iface}

coordinator:
  url: "${escYaml(url)}"
  token: "${escYaml(d.token)}"

groups:
  - id: router
    role: gateway
    hosts: ${yamlList([d.gatewayIp])}
  - id: internet
    role: external
    hosts: ${yamlList(splitIps(d.externalIps).length ? splitIps(d.externalIps) : ["1.1.1.1", "8.8.8.8"])}

dns:
  resolvers: ${yamlList([d.gatewayIp])}
  names: ["example.com", "cloudflare.com"]

thresholds:
  ping_interval_s: ${d.pingInterval}
  dns_interval_s: 30
  dns_timeout_ms: 1500
`;
    return `# Generated satellite compose for ${sat.id}
# List this id under satellites: on the coordinator (placement: ${sat.placement}).
# docker compose -f docker-compose.satellite.yml up -d

services:
  satellite:
    image: ghcr.io/emil007/netdiag:latest
    container_name: netdiag-satellite-${sat.id}
    command: ["satellite"]
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      TZ: ${d.timezone}
      IFACE: ${sat.iface || d.iface}
      NETDIAG_COORDINATOR_TOKEN: ${d.token}
      NETDIAG_DATA: /data
      NETDIAG_CONFIG_YAML: |
${indentBlock(cfg.trimEnd(), 8)}
    volumes:
      - ./data:/data
    restart: unless-stopped
`;
  }

  function formData() {
    const fd = new FormData(form);
    return {
      siteName: fd.get("siteName"),
      timezone: fd.get("timezone"),
      iface: fd.get("iface"),
      behindSwitch: !!fd.get("behindSwitch"),
      sameSegmentIp: (fd.get("sameSegmentIp") || "").trim(),
      gatewayIp: fd.get("gatewayIp"),
      wifiIp: fd.get("wifiIp"),
      externalIps: fd.get("externalIps"),
      token: fd.get("token"),
      coordIp: (fd.get("coordIp") || "").trim(),
      pingInterval: fd.get("pingInterval"),
      warmup: fd.get("warmup"),
      lossPct: fd.get("lossPct"),
      confirmRounds: fd.get("confirmRounds"),
      csvKeep: fd.get("csvKeep"),
      incKeep: fd.get("incKeep"),
      keepHours: fd.get("keepHours"),
      snaplen: fd.get("snaplen"),
    };
  }

  function download(filename, text) {
    const blob = new Blob([text], { type: "text/yaml;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  behind.addEventListener("change", () => {
    sameSegWrap.classList.toggle("hidden", !behind.checked);
  });

  $("#genToken").addEventListener("click", () => {
    $("#token").value = randToken();
  });

  document.body.addEventListener("click", (e) => {
    const t = e.target;
    if (t.matches("[data-add]")) {
      const kind = t.getAttribute("data-add");
      if (kind === "mesh") addMesh();
      if (kind === "branch") addBranch();
      if (kind === "sat") addSat();
    }
    if (t.matches("[data-rm]")) {
      t.closest(".row")?.remove();
    }
  });

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const d = formData();
    if (!d.token || d.token === "change-me") {
      alert("Generate a real ingest token first (do not leave change-me).");
      return;
    }
    if (d.behindSwitch && !d.sameSegmentIp) {
      alert("Behind a switch: enter a same-segment canary IP.");
      return;
    }
    lastCoord = buildCoordinatorCompose(d);
    const sats = readRows(satRows).filter((r) => r.id);
    lastSats = sats.map((s) => ({
      name: `docker-compose.satellite-${sanitizeBranchId(s.id)}.yml`,
      text: buildSatelliteCompose(d, s),
    }));
    preview.textContent = lastCoord;
    previewWrap.classList.remove("hidden");
    copyBtn.disabled = false;
    dlSat.disabled = !lastSats.length;
    download("docker-compose.yml", lastCoord);
  });

  copyBtn.addEventListener("click", async () => {
    if (!lastCoord) return;
    await navigator.clipboard.writeText(lastCoord);
    copyBtn.textContent = "Copied";
    setTimeout(() => (copyBtn.textContent = "Copy to clipboard"), 1200);
  });

  dlSat.addEventListener("click", () => {
    lastSats.forEach((s, i) => {
      setTimeout(() => download(s.name, s.text), i * 200);
    });
  });

  // Defaults
  $("#token").value = randToken();
  addBranch("living_room", "192.168.1.10, 192.168.1.11", "gateway");
})();
