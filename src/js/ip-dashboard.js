/* ═══════════════════════════════════════════════════
   CyberSpace — IP Dashboard Module
   ipapi.co + Shodan InternetDB integration
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  let ipData = null;
  let hasFetched = false;

  // ── Fetch IP data from ipapi.co ──
  async function fetchIpData() {
    const loadingEl = document.getElementById('ip-loading');
    const dataEl = document.getElementById('ip-data');
    const errorEl = document.getElementById('ip-error');
    const statusDot = document.getElementById('ip-status');

    try {
      const response = await fetch('https://ipapi.co/json/');
      if (!response.ok) throw new Error('IP API returned ' + response.status);

      ipData = await response.json();

      // Build grid
      const grid = document.getElementById('ip-grid');
      const fields = [
        { label: 'IP Address', value: ipData.ip, icon: '📍' },
        { label: 'City', value: ipData.city || 'Unknown', icon: '🏙️' },
        { label: 'Region', value: ipData.region || 'Unknown', icon: '🗺️' },
        { label: 'Country', value: `${ipData.country_name || 'Unknown'} (${ipData.country_code || '??'})`, icon: '🌍' },
        { label: 'ISP', value: ipData.org || 'Unknown', icon: '🏢' },
        { label: 'ASN', value: ipData.asn || 'N/A', icon: '🔗' },
        { label: 'Timezone', value: ipData.timezone || 'Unknown', icon: '🕐' },
        { label: 'Coordinates', value: `${ipData.latitude || '?'}, ${ipData.longitude || '?'}`, icon: '🧭' },
      ];

      grid.innerHTML = fields
        .map(
          (f) => `
        <div class="data-item">
          <div class="data-label">${f.icon} ${f.label}</div>
          <div class="data-value ${f.label === 'IP Address' ? '' : 'small'}">${f.value}</div>
        </div>
      `
        )
        .join('');

      loadingEl.classList.add('hidden');
      dataEl.classList.remove('hidden');
      statusDot.classList.add('online');
      statusDot.classList.remove('offline');

      // Now fetch Shodan data
      fetchShodanData(ipData.ip);

      // Update terminal
      updateTerminal(ipData);
    } catch (err) {
      console.error('IP fetch error:', err);
      loadingEl.classList.add('hidden');
      errorEl.classList.remove('hidden');
      statusDot.classList.add('offline');
      statusDot.classList.remove('online');

      // Hide Shodan loading too
      document.getElementById('shodan-loading').classList.add('hidden');
      document.getElementById('shodan-error').classList.remove('hidden');
    }
  }

  // ── Fetch Shodan InternetDB data ──
  async function fetchShodanData(ip) {
    const loadingEl = document.getElementById('shodan-loading');
    const dataEl = document.getElementById('shodan-data');
    const emptyEl = document.getElementById('shodan-empty');
    const errorEl = document.getElementById('shodan-error');

    try {
      const response = await fetch('https://internetdb.shodan.io/' + ip);

      if (response.status === 404) {
        // No data found for this IP — that's actually good
        loadingEl.classList.add('hidden');
        emptyEl.classList.remove('hidden');
        appendTerminalLine('[ SHODAN ] No exposed services found — clean profile ✓', 'ok');
        return;
      }

      if (!response.ok) throw new Error('Shodan returned ' + response.status);

      const data = await response.json();

      const hasPorts = data.ports && data.ports.length > 0;
      const hasHostnames = data.hostnames && data.hostnames.length > 0;
      const hasCves = data.vulns && data.vulns.length > 0;
      const hasTags = data.tags && data.tags.length > 0;

      if (!hasPorts && !hasHostnames && !hasCves && !hasTags) {
        loadingEl.classList.add('hidden');
        emptyEl.classList.remove('hidden');
        appendTerminalLine('[ SHODAN ] No exposed services found — clean profile ✓', 'ok');
        return;
      }

      // Ports
      const portsEl = document.getElementById('shodan-ports');
      if (hasPorts) {
        portsEl.innerHTML = data.ports
          .map((p) => `<span class="badge port">:${p}</span>`)
          .join('');
        appendTerminalLine(`[ SHODAN ] Open ports: ${data.ports.join(', ')}`, 'warn');
      } else {
        portsEl.innerHTML = '<span class="badge safe">None detected</span>';
      }

      // Hostnames
      const hostnamesEl = document.getElementById('shodan-hostnames');
      if (hasHostnames) {
        hostnamesEl.innerHTML = data.hostnames
          .map((h) => `<span class="badge hostname">${h}</span>`)
          .join('');
      } else {
        hostnamesEl.innerHTML = '<span class="badge safe">None</span>';
      }

      // CVEs
      const cvesEl = document.getElementById('shodan-cves');
      if (hasCves) {
        cvesEl.innerHTML = data.vulns
          .map((c) => `<span class="badge cve">⚠ ${c}</span>`)
          .join('');
        appendTerminalLine(`[ SHODAN ] ⚠ ${data.vulns.length} CVE(s) found!`, 'danger');
      } else {
        cvesEl.innerHTML = '<span class="badge safe">No known CVEs</span>';
        appendTerminalLine('[ SHODAN ] No known vulnerabilities', 'ok');
      }

      // Tags
      const tagsEl = document.getElementById('shodan-tags');
      if (hasTags) {
        tagsEl.innerHTML = data.tags
          .map((t) => `<span class="badge tag">${t}</span>`)
          .join('');
      } else {
        tagsEl.innerHTML = '<span class="badge safe">None</span>';
      }

      loadingEl.classList.add('hidden');
      dataEl.classList.remove('hidden');
    } catch (err) {
      console.error('Shodan fetch error:', err);
      loadingEl.classList.add('hidden');
      errorEl.classList.remove('hidden');
      appendTerminalLine('[ SHODAN ] Error: could not reach InternetDB', 'danger');
    }
  }

  // ── Terminal Output ──
  function updateTerminal(data) {
    const terminal = document.getElementById('terminal-output');
    terminal.innerHTML = '';

    const lines = [
      { label: 'scan', value: 'target acquired', cls: '' },
      { label: 'ip', value: data.ip, cls: '' },
      { label: 'loc', value: `${data.city}, ${data.region}, ${data.country_name}`, cls: '' },
      { label: 'isp', value: data.org || 'Unknown', cls: '' },
      { label: 'asn', value: data.asn || 'N/A', cls: '' },
      { label: 'tz', value: data.timezone || 'Unknown', cls: '' },
      { label: 'coord', value: `${data.latitude}, ${data.longitude}`, cls: '' },
    ];

    lines.forEach((l) => {
      const div = document.createElement('div');
      div.innerHTML = `<span class="prompt">$ </span><span class="label">${l.label}:</span> <span class="value ${l.cls}">${l.value}</span>`;
      terminal.appendChild(div);
    });
  }

  function appendTerminalLine(text, cls) {
    const terminal = document.getElementById('terminal-output');
    const div = document.createElement('div');
    div.innerHTML = `<span class="prompt">$ </span><span class="value ${cls || ''}">${text}</span>`;
    terminal.appendChild(div);
  }

  // ── Init on boot ready ──
  document.addEventListener('cyberspace:ready', () => {
    if (!hasFetched) {
      hasFetched = true;
      fetchIpData();
    }
  });
})();
