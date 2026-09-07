/* ═══════════════════════════════════════════════════
   CyberSpace — Cyber Jokes Module
   JokeAPI v2 — Programming category
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  const container = document.getElementById('joke-container');
  const jokeBtn = document.getElementById('joke-btn');
  let hasLoaded = false;
  let isLoading = false;

  // ── Fetch a random programming joke ──
  async function fetchJoke() {
    if (isLoading) return;
    isLoading = true;
    jokeBtn.disabled = true;

    container.innerHTML = `
      <div class="loader">
        <div class="loader-spinner"></div>
        <span>Decrypting joke database...</span>
      </div>
    `;

    try {
      const response = await fetch(
        'https://v2.jokeapi.dev/joke/Programming?blacklistFlags=nsfw,religious,political,racist,sexist,explicit'
      );
      if (!response.ok) throw new Error('JokeAPI returned ' + response.status);

      const data = await response.json();

      if (data.error) throw new Error(data.message || 'API Error');

      if (data.type === 'twopart') {
        container.innerHTML = `
          <div class="joke-setup">${escapeHtml(data.setup)}</div>
          <div class="joke-delivery">${escapeHtml(data.delivery)}</div>
          <div class="joke-category">${data.category} • #${data.id}</div>
        `;
      } else {
        container.innerHTML = `
          <div class="joke-single">${escapeHtml(data.joke)}</div>
          <div class="joke-category">${data.category} • #${data.id}</div>
        `;
      }
    } catch (err) {
      console.error('Joke fetch error:', err);
      container.innerHTML = `
        <div class="joke-single text-orange">
          // Error 418: Humor module offline.<br>
          // The joke compiler threw an unhandled exception.<br>
          // Please try again.
        </div>
      `;
    } finally {
      isLoading = false;
      jokeBtn.disabled = false;
    }
  }

  // ── HTML escape utility ──
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ── Button click ──
  jokeBtn.addEventListener('click', fetchJoke);

  // ── Load first joke when tab is shown or on boot ──
  document.addEventListener('cyberspace:tab-change', (e) => {
    if (e.detail.tab === 'jokes' && !hasLoaded) {
      hasLoaded = true;
      fetchJoke();
    }
  });

  // Also load if jokes tab is somehow the first tab (unlikely but safe)
  document.addEventListener('cyberspace:ready', () => {
    const jokesPanel = document.getElementById('panel-jokes');
    if (jokesPanel && jokesPanel.classList.contains('active') && !hasLoaded) {
      hasLoaded = true;
      fetchJoke();
    }
  });
})();
