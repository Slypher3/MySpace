/* ═══════════════════════════════════════════════════
   CyberSpace — Email Recon Module
   Gravatar + XposedOrNot breach check + DNS security
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  const form = document.getElementById('email-recon-form');
  const input = document.getElementById('email-recon-input');
  const btn = document.getElementById('email-recon-btn');
  const resultContainer = document.getElementById('email-recon-result');

  // ══════════════════════════════════════
  // Minimal MD5 implementation (RFC 1321)
  // crypto.subtle doesn't support MD5
  // ══════════════════════════════════════
  function md5(string) {
    function cmn(q, a, b, x, s, t) {
      a = (a + q + (x >>> 0) + t) & 0xffffffff;
      return (((a << s) | (a >>> (32 - s))) + b) & 0xffffffff;
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

    const bytes = [];
    for (let i = 0; i < string.length; i++) {
      const code = string.charCodeAt(i);
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      }
    }

    const n = bytes.length;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    const bitLen = n * 8;
    bytes.push(bitLen & 0xff, (bitLen >> 8) & 0xff, (bitLen >> 16) & 0xff, (bitLen >> 24) & 0xff);
    bytes.push(0, 0, 0, 0);

    let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

    for (let i = 0; i < bytes.length; i += 64) {
      const w = [];
      for (let j = 0; j < 16; j++) {
        w[j] = bytes[i + j * 4] | (bytes[i + j * 4 + 1] << 8) |
               (bytes[i + j * 4 + 2] << 16) | (bytes[i + j * 4 + 3] << 24);
      }
      let aa = a, bb = b, cc = c, dd = d;

      a=ff(a,b,c,d,w[0],7,-680876936);d=ff(d,a,b,c,w[1],12,-389564586);c=ff(c,d,a,b,w[2],17,606105819);b=ff(b,c,d,a,w[3],22,-1044525330);
      a=ff(a,b,c,d,w[4],7,-176418897);d=ff(d,a,b,c,w[5],12,1200080426);c=ff(c,d,a,b,w[6],17,-1473231341);b=ff(b,c,d,a,w[7],22,-45705983);
      a=ff(a,b,c,d,w[8],7,1770035416);d=ff(d,a,b,c,w[9],12,-1958414417);c=ff(c,d,a,b,w[10],17,-42063);b=ff(b,c,d,a,w[11],22,-1990404162);
      a=ff(a,b,c,d,w[12],7,1804603682);d=ff(d,a,b,c,w[13],12,-40341101);c=ff(c,d,a,b,w[14],17,-1502002290);b=ff(b,c,d,a,w[15],22,1236535329);

      a=gg(a,b,c,d,w[1],5,-165796510);d=gg(d,a,b,c,w[6],9,-1069501632);c=gg(c,d,a,b,w[11],14,643717713);b=gg(b,c,d,a,w[0],20,-373897302);
      a=gg(a,b,c,d,w[5],5,-701558691);d=gg(d,a,b,c,w[10],9,38016083);c=gg(c,d,a,b,w[15],14,-660478335);b=gg(b,c,d,a,w[4],20,-405537848);
      a=gg(a,b,c,d,w[9],5,568446438);d=gg(d,a,b,c,w[14],9,-1019803690);c=gg(c,d,a,b,w[3],14,-187363961);b=gg(b,c,d,a,w[8],20,1163531501);
      a=gg(a,b,c,d,w[13],5,-1444681467);d=gg(d,a,b,c,w[2],9,-51403784);c=gg(c,d,a,b,w[7],14,1735328473);b=gg(b,c,d,a,w[12],20,-1926607734);

      a=hh(a,b,c,d,w[5],4,-378558);d=hh(d,a,b,c,w[8],11,-2022574463);c=hh(c,d,a,b,w[11],16,1839030562);b=hh(b,c,d,a,w[14],23,-35309556);
      a=hh(a,b,c,d,w[1],4,-1530992060);d=hh(d,a,b,c,w[4],11,1272893353);c=hh(c,d,a,b,w[7],16,-155497632);b=hh(b,c,d,a,w[10],23,-1094730640);
      a=hh(a,b,c,d,w[13],4,681279174);d=hh(d,a,b,c,w[0],11,-358537222);c=hh(c,d,a,b,w[3],16,-722521979);b=hh(b,c,d,a,w[6],23,76029189);
      a=hh(a,b,c,d,w[9],4,-640364487);d=hh(d,a,b,c,w[12],11,-421815835);c=hh(c,d,a,b,w[15],16,530742520);b=hh(b,c,d,a,w[2],23,-995338651);

      a=ii(a,b,c,d,w[0],6,-198630844);d=ii(d,a,b,c,w[7],10,1126891415);c=ii(c,d,a,b,w[14],15,-1416354905);b=ii(b,c,d,a,w[5],21,-57434055);
      a=ii(a,b,c,d,w[12],6,1700485571);d=ii(d,a,b,c,w[3],10,-1894986606);c=ii(c,d,a,b,w[10],15,-1051523);b=ii(b,c,d,a,w[1],21,-2054922799);
      a=ii(a,b,c,d,w[8],6,1873313359);d=ii(d,a,b,c,w[15],10,-30611744);c=ii(c,d,a,b,w[6],15,-1560198380);b=ii(b,c,d,a,w[13],21,1309151649);
      a=ii(a,b,c,d,w[4],6,-145523070);d=ii(d,a,b,c,w[11],10,-1120210379);c=ii(c,d,a,b,w[2],15,718787259);b=ii(b,c,d,a,w[9],21,-343485551);

      a = (a + aa) & 0xffffffff;
      b = (b + bb) & 0xffffffff;
      c = (c + cc) & 0xffffffff;
      d = (d + dd) & 0xffffffff;
    }

    function toHex(n) {
      let s = '';
      for (let i = 0; i < 4; i++) {
        s += ((n >> (i * 8 + 4)) & 0xf).toString(16) + ((n >> (i * 8)) & 0xf).toString(16);
      }
      return s;
    }
    return toHex(a) + toHex(b) + toHex(c) + toHex(d);
  }

  // ══════════════════════════════════════
  // DNS lookup via Cloudflare DoH
  // ══════════════════════════════════════
  async function dnsLookup(domain, type) {
    try {
      const resp = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' } }
      );
      if (!resp.ok) return null;
      const data = await resp.json();
      return data.Answer || [];
    } catch {
      return null;
    }
  }

  // ══════════════════════════════════════
  // XposedOrNot — Email Breach Check
  // ══════════════════════════════════════
  async function checkBreaches(email) {
    try {
      const resp = await fetch(
        `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`
      );
      if (resp.status === 404) return { found: false, breaches: [], summary: null };
      if (!resp.ok) return { found: false, breaches: [], summary: null, error: true };
      const data = await resp.json();

      const breachDetails = data.ExposedBreaches?.breaches_details || [];
      const metrics = data.BreachesSummary || null;

      return {
        found: breachDetails.length > 0,
        breaches: breachDetails,
        summary: metrics,
      };
    } catch {
      return { found: false, breaches: [], summary: null, error: true };
    }
  }

  // ══════════════════════════════════════
  // Main recon function
  // ══════════════════════════════════════
  async function runEmailRecon(email) {
    btn.disabled = true;
    btn.textContent = 'Scanning...';

    const emailLower = email.trim().toLowerCase();
    const domain = emailLower.split('@')[1];
    const hash = md5(emailLower);

    resultContainer.innerHTML = `
      <div class="loader mt-md">
        <div class="loader-spinner"></div>
        <span>Running email reconnaissance...</span>
      </div>
    `;

    // Run all checks in parallel
    const [mxRecords, txtRecords, gravatarExists, breachData] = await Promise.all([
      dnsLookup(domain, 'MX'),
      dnsLookup(domain, 'TXT'),
      checkGravatarAvatar(hash),
      checkBreaches(emailLower),
    ]);

    // Parse DNS security
    const hasMX = mxRecords && mxRecords.length > 0;
    const txtData = txtRecords || [];
    const spfRecord = txtData.find((r) => r.data && r.data.includes('v=spf1'));
    const dmarcRecords = await dnsLookup('_dmarc.' + domain, 'TXT');
    const dmarcRecord = dmarcRecords
      ? dmarcRecords.find((r) => r.data && r.data.includes('v=DMARC1'))
      : null;

    // Build results HTML
    let html = '';

    // ══════════════════════════════════════
    // SECTION 1: Breach Check (most important — show first)
    // ══════════════════════════════════════
    html += `
      <div class="cyber-card">
        <div class="card-header">
          <span class="card-icon">🚨</span>
          <h2>Data Breach Report</h2>
        </div>
    `;

    if (breachData.error) {
      html += `
        <div class="result-box" style="border-color: var(--text-dim); background: rgba(255,255,255,0.02);">
          <div class="result-icon">⚠️</div>
          <div class="result-title" style="color: var(--orange);">Service Unavailable</div>
          <div class="result-detail">Could not reach the XposedOrNot breach database. Try again later.</div>
        </div>
      `;
    } else if (!breachData.found) {
      html += `
        <div class="result-box safe">
          <div class="result-icon">✅</div>
          <div class="result-title">No Breaches Found</div>
          <div class="result-detail">This email was not found in any known data breaches. Stay vigilant!</div>
        </div>
      `;
    } else {
      const count = breachData.breaches.length;
      html += `
        <div class="result-box breached">
          <div class="result-icon">🚨</div>
          <div class="result-title">Found in ${count} Breach${count > 1 ? 'es' : ''}</div>
          <div class="result-detail">This email appeared in <strong class="text-red">${count}</strong> known data breach${count > 1 ? 'es' : ''}.</div>
        </div>

        <div class="section-title mt-lg">Breach Timeline</div>
        <div class="breach-list">
      `;

      // Sort breaches by date (newest first)
      const sorted = [...breachData.breaches].sort((a, b) => {
        const da = a.xposed_date || '0000';
        const db = b.xposed_date || '0000';
        return db.localeCompare(da);
      });

      // Show top 15 breaches, collapse rest
      const showCount = 15;
      const visible = sorted.slice(0, showCount);
      const hidden = sorted.slice(showCount);

      visible.forEach((b) => {
        html += buildBreachCard(b);
      });

      if (hidden.length > 0) {
        html += `
          <div class="breach-expand-wrap">
            <button class="cyber-btn" id="show-more-breaches" style="width:100%; margin-top: var(--space-sm);">
              Show ${hidden.length} More Breach${hidden.length > 1 ? 'es' : ''}
            </button>
            <div class="breach-hidden" id="hidden-breaches" style="display:none;">
        `;
        hidden.forEach((b) => {
          html += buildBreachCard(b);
        });
        html += `
            </div>
          </div>
        `;
      }

      html += '</div>'; // .breach-list
    }

    html += '</div>'; // .cyber-card

    // ══════════════════════════════════════
    // SECTION 2: Gravatar
    // ══════════════════════════════════════
    html += `
      <div class="cyber-card">
        <div class="card-header">
          <span class="card-icon">👤</span>
          <h2>Gravatar Profile</h2>
        </div>
    `;

    if (gravatarExists) {
      html += `
        <div class="gravatar-profile">
          <div class="gravatar-avatar-wrap">
            <img
              src="https://gravatar.com/avatar/${hash}?s=200&d=404"
              alt="Gravatar avatar"
              class="gravatar-avatar"
            >
            <div class="gravatar-glow"></div>
          </div>
          <div class="gravatar-info">
            <div class="data-item">
              <div class="data-label">📧 Email Hash (MD5)</div>
              <div class="data-value small">${hash}</div>
            </div>
            <div class="data-item mt-sm">
              <div class="data-label">🔗 Profile URL</div>
              <div class="data-value small">
                <a href="https://gravatar.com/${hash}" target="_blank" rel="noopener" style="color: var(--cyan); text-decoration: none; border-bottom: 1px solid var(--cyan-glow);">
                  gravatar.com/${hash.substring(0, 12)}...
                </a>
              </div>
            </div>
            <div class="badge-list mt-md">
              <span class="badge safe">Profile Found</span>
              <span class="badge hostname">Public Avatar</span>
            </div>
          </div>
        </div>
      `;
    } else {
      html += `
        <div class="result-box" style="border-color: var(--text-dim); background: rgba(255,255,255,0.02);">
          <div class="result-icon">👻</div>
          <div class="result-title" style="color: var(--text-secondary);">No Gravatar Found</div>
          <div class="result-detail">No public Gravatar profile is associated with this email address.</div>
        </div>
      `;
    }

    html += '</div>';

    // ══════════════════════════════════════
    // SECTION 3: DNS & Email Security
    // ══════════════════════════════════════
    html += `
      <div class="cyber-card">
        <div class="card-header">
          <span class="card-icon">🛡️</span>
          <h2>Email Domain Security</h2>
        </div>

        <div class="section-title">Domain: ${escapeHtml(domain)}</div>

        <div class="dns-checks">
    `;

    html += buildCheckRow(
      'MX Records (Mail Server)',
      hasMX,
      hasMX
        ? `Mail handled by: ${mxRecords.map((r) => escapeHtml(r.data)).join(', ')}`
        : 'No MX records — this domain cannot receive email'
    );

    html += buildCheckRow(
      'SPF (Sender Policy Framework)',
      !!spfRecord,
      spfRecord
        ? `<code class="text-dim" style="font-size:0.75rem; word-break:break-all;">${escapeHtml(spfRecord.data)}</code>`
        : 'No SPF record — emails from this domain can be easily spoofed'
    );

    html += buildCheckRow(
      'DMARC (Anti-Spoofing Policy)',
      !!dmarcRecord,
      dmarcRecord
        ? `<code class="text-dim" style="font-size:0.75rem; word-break:break-all;">${escapeHtml(dmarcRecord.data)}</code>`
        : 'No DMARC policy — domain is vulnerable to email impersonation'
    );

    const score = (hasMX ? 1 : 0) + (spfRecord ? 1 : 0) + (dmarcRecord ? 1 : 0);
    let verdict, verdictClass, verdictIcon;
    if (score === 3) {
      verdict = 'Well Protected';
      verdictClass = 'safe';
      verdictIcon = '✅';
    } else if (score >= 1) {
      verdict = 'Partially Protected';
      verdictClass = '';
      verdictIcon = '⚠️';
    } else {
      verdict = 'Not Protected';
      verdictClass = 'breached';
      verdictIcon = '🚨';
    }

    html += `
        </div>
        <div class="result-box ${verdictClass} mt-lg">
          <div class="result-icon">${verdictIcon}</div>
          <div class="result-title">${verdict}</div>
          <div class="result-detail">${score}/3 email security checks passed for <strong>${escapeHtml(domain)}</strong></div>
        </div>
      </div>
    `;

    // ══════════════════════════════════════
    // SECTION 4: Terminal Output
    // ══════════════════════════════════════
    html += `
      <div class="cyber-card">
        <div class="card-header">
          <span class="card-icon">💻</span>
          <h2>Raw Output</h2>
        </div>
        <div class="terminal">
          <div class="terminal-header">
            <span class="terminal-dot red"></span>
            <span class="terminal-dot yellow"></span>
            <span class="terminal-dot green"></span>
            <span class="terminal-title">cyberspace://email-recon</span>
          </div>
          <div class="terminal-body">
            <div><span class="prompt">$ </span><span class="label">target:</span> <span class="value">${escapeHtml(emailLower)}</span></div>
            <div><span class="prompt">$ </span><span class="label">domain:</span> <span class="value">${escapeHtml(domain)}</span></div>
            <div><span class="prompt">$ </span><span class="label">md5:</span> <span class="value">${hash}</span></div>
            <div><span class="prompt">$ </span><span class="label">gravatar:</span> <span class="value ${gravatarExists ? '' : 'warn'}">${gravatarExists ? 'FOUND' : 'NOT FOUND'}</span></div>
            <div><span class="prompt">$ </span><span class="label">breaches:</span> <span class="value ${breachData.found ? 'danger' : ''}">${breachData.found ? breachData.breaches.length + ' FOUND' : 'NONE'}</span></div>
            <div><span class="prompt">$ </span><span class="label">mx:</span> <span class="value ${hasMX ? '' : 'danger'}">${hasMX ? mxRecords.map((r) => r.data).join(', ') : 'NONE'}</span></div>
            <div><span class="prompt">$ </span><span class="label">spf:</span> <span class="value ${spfRecord ? '' : 'danger'}">${spfRecord ? 'PRESENT' : 'MISSING'}</span></div>
            <div><span class="prompt">$ </span><span class="label">dmarc:</span> <span class="value ${dmarcRecord ? '' : 'danger'}">${dmarcRecord ? 'PRESENT' : 'MISSING'}</span></div>
            <div><span class="prompt">$ </span><span class="label">verdict:</span> <span class="value ${score === 3 ? '' : 'warn'}">${verdict.toUpperCase()} (${score}/3)</span></div>
          </div>
        </div>
      </div>
    `;

    resultContainer.innerHTML = html;

    // Attach "show more" button handler
    const showMoreBtn = document.getElementById('show-more-breaches');
    if (showMoreBtn) {
      showMoreBtn.addEventListener('click', () => {
        const hiddenEl = document.getElementById('hidden-breaches');
        if (hiddenEl.style.display === 'none') {
          hiddenEl.style.display = 'block';
          showMoreBtn.textContent = 'Show Less';
        } else {
          hiddenEl.style.display = 'none';
          showMoreBtn.textContent = `Show ${hiddenEl.children.length} More Breaches`;
        }
      });
    }

    btn.disabled = false;
    btn.textContent = 'Scan';
  }

  // ── Build a breach card ──
  function buildBreachCard(breach) {
    const name = escapeHtml(breach.breach || breach.domain || 'Unknown');
    const date = breach.xposed_date || 'Unknown';
    const domain = escapeHtml(breach.domain || '');
    const records = breach.xposed_records ? breach.xposed_records.toLocaleString() : '?';
    const dataTypes = breach.xposed_data ? breach.xposed_data.split(';').map((d) => d.trim()) : [];
    const industry = escapeHtml(breach.industry || '');
    const risk = breach.password_risk || '';
    const logoUrl = breach.logo || '';

    let riskBadge = '';
    if (risk === 'plaintext') {
      riskBadge = '<span class="badge cve">🔓 Plaintext</span>';
    } else if (risk === 'easytocrack') {
      riskBadge = '<span class="badge tag">⚠ Easy to Crack</span>';
    } else if (risk === 'hardtocrack') {
      riskBadge = '<span class="badge safe">🔒 Hard to Crack</span>';
    }

    return `
      <div class="breach-card">
        <div class="breach-card-header">
          ${logoUrl ? `<img src="${escapeHtml(logoUrl)}" alt="" class="breach-logo" onerror="this.style.display='none'">` : ''}
          <div class="breach-card-info">
            <div class="breach-name">${name}</div>
            <div class="breach-meta">
              ${domain ? `<span>${domain}</span>` : ''}
              <span>📅 ${escapeHtml(date)}</span>
              <span>👥 ${records} records</span>
              ${industry ? `<span>🏢 ${industry}</span>` : ''}
            </div>
          </div>
        </div>
        <div class="badge-list mt-sm">
          ${dataTypes.map((d) => `<span class="badge port">${escapeHtml(d)}</span>`).join('')}
          ${riskBadge}
        </div>
      </div>
    `;
  }

  // ── Check if Gravatar avatar exists ──
  function checkGravatarAvatar(hash) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => resolve(true);
      img.onerror = () => resolve(false);
      img.src = `https://gravatar.com/avatar/${hash}?d=404&s=1`;
    });
  }

  // ── Build a DNS check row ──
  function buildCheckRow(label, passed, detail) {
    const icon = passed ? '✅' : '❌';
    const cls = passed ? 'text-green' : 'text-red';
    return `
      <div class="dns-check-row">
        <div class="dns-check-status ${cls}">${icon}</div>
        <div class="dns-check-content">
          <div class="dns-check-label">${label}</div>
          <div class="dns-check-detail">${detail}</div>
        </div>
      </div>
    `;
  }

  // ── HTML escape ──
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ── Form submit ──
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const email = input.value.trim();
    if (!email || !email.includes('@')) return;
    runEmailRecon(email);
  });
})();
