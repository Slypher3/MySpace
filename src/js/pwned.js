/* ═══════════════════════════════════════════════════
   CyberSpace — Password Breach Checker Module
   Have I Been Pwned — k-Anonymity model
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  const form = document.getElementById('pwned-form');
  const input = document.getElementById('pwned-input');
  const btn = document.getElementById('pwned-btn');
  const resultContainer = document.getElementById('pwned-result');
  const toggleBtn = document.getElementById('toggle-pw-visibility');

  // ── Toggle password visibility ──
  toggleBtn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggleBtn.textContent = isPassword ? '🙈' : '👁️';
  });

  // ── SHA-1 hash using Web Crypto API ──
  async function sha1(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  // ── Check password against HIBP ──
  async function checkPassword(password) {
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    resultContainer.innerHTML = `
      <div class="loader mt-md">
        <div class="loader-spinner"></div>
        <span>Hashing & querying breach database...</span>
      </div>
    `;

    try {
      const hash = await sha1(password);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);

      const response = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
      if (!response.ok) throw new Error('HIBP returned ' + response.status);

      const text = await response.text();
      const lines = text.split('\n');

      let count = 0;
      for (const line of lines) {
        const [hashSuffix, hashCount] = line.split(':');
        if (hashSuffix.trim() === suffix) {
          count = parseInt(hashCount.trim(), 10);
          break;
        }
      }

      if (count === 0) {
        resultContainer.innerHTML = `
          <div class="result-box safe">
            <div class="result-icon">✅</div>
            <div class="result-title">Not Compromised</div>
            <div class="result-detail">
              This password was <strong>not found</strong> in any known data breaches.
              <br>This doesn't guarantee it's strong — use a password manager for best security.
            </div>
          </div>
        `;
      } else {
        const formatted = count.toLocaleString();
        resultContainer.innerHTML = `
          <div class="result-box breached">
            <div class="result-icon">🚨</div>
            <div class="result-title">Breached!</div>
            <div class="result-detail">
              This password has been seen <strong class="text-red">${formatted}</strong> time${count > 1 ? 's' : ''}
              in data breaches.
              <br><strong>Do not use this password.</strong> Change it immediately wherever it's used.
            </div>
          </div>
        `;
      }
    } catch (err) {
      console.error('HIBP check error:', err);
      resultContainer.innerHTML = `
        <div class="result-box breached">
          <div class="result-icon">⚠️</div>
          <div class="result-title">Check Failed</div>
          <div class="result-detail">
            Could not reach the Have I Been Pwned service. Please try again later.
          </div>
        </div>
      `;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Scan';
    }
  }

  // ── Form submission ──
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const password = input.value;
    if (!password) return;
    checkPassword(password);
  });
})();
