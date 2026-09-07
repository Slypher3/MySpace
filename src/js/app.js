/* ═══════════════════════════════════════════════════
   CyberSpace — Core App Logic
   Tab switching, boot sequence, initialization
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Boot Sequence ──
  function runBootSequence() {
    const bootScreen = document.getElementById('boot-screen');
    const progressBar = document.getElementById('boot-progress');
    const lines = bootScreen.querySelectorAll('.boot-line');

    let completed = 0;
    const total = lines.length;

    lines.forEach((line) => {
      const delay = parseInt(line.dataset.delay, 10) || 0;

      setTimeout(() => {
        line.classList.add('active');
        completed++;
        const pct = Math.round((completed / total) * 100);
        progressBar.style.width = pct + '%';

        // When all lines are done, fade out boot screen
        if (completed === total) {
          setTimeout(() => {
            bootScreen.classList.add('hidden');
            // Start loading data after boot
            document.dispatchEvent(new CustomEvent('cyberspace:ready'));
          }, 600);
        }
      }, delay);
    });
  }

  // ── Tab Switching ──
  function initTabs() {
    const tabNav = document.getElementById('tab-nav');
    const tabBtns = tabNav.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.tab-panel');

    tabNav.addEventListener('click', (e) => {
      const btn = e.target.closest('.tab-btn');
      if (!btn || btn.classList.contains('active')) return;

      const targetTab = btn.dataset.tab;

      // Update buttons
      tabBtns.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      // Update panels
      panels.forEach((p) => {
        p.classList.remove('active');
      });
      const targetPanel = document.getElementById('panel-' + targetTab);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }

      // Dispatch custom event for lazy loading
      document.dispatchEvent(
        new CustomEvent('cyberspace:tab-change', { detail: { tab: targetTab } })
      );
    });

    // Keyboard navigation for accessibility
    tabNav.addEventListener('keydown', (e) => {
      const tabs = Array.from(tabBtns);
      const currentIndex = tabs.indexOf(document.activeElement);

      let newIndex = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        newIndex = (currentIndex + 1) % tabs.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        newIndex = (currentIndex - 1 + tabs.length) % tabs.length;
      } else if (e.key === 'Home') {
        e.preventDefault();
        newIndex = 0;
      } else if (e.key === 'End') {
        e.preventDefault();
        newIndex = tabs.length - 1;
      }

      if (newIndex >= 0) {
        tabs[newIndex].focus();
        tabs[newIndex].click();
      }
    });
  }

  // ── Init ──
  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    runBootSequence();
  });
})();
