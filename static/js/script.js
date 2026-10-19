/**
 * script.js
 * =============================================================================
 * CipherHash Lab — Shared Client-Side JavaScript
 * Academic Project: B.Tech Computer Science (Cyber Security)
 * =============================================================================
 * Contains:
 * 1. Theme toggle (dark/light) with localStorage persistence
 * 2. Mobile nav toggle
 * 3. API helper (apiPost) with CSRF token support
 * 4. Toast notification helper (showToast)
 * 5. HTML escaping helper (escHtml)
 * 6. Active nav link highlighting
 */

/* ============================================================
   1. THEME TOGGLE
   ============================================================ */
(function initTheme() {
  const stored = localStorage.getItem('cipherhash_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', stored);
  updateThemeIcons(stored);
})();

function updateThemeIcons(theme) {
  const sunIcon  = document.getElementById('themeIconSun');
  const moonIcon = document.getElementById('themeIconMoon');
  if (!sunIcon || !moonIcon) return;
  if (theme === 'light') {
    sunIcon.style.display  = 'none';
    moonIcon.style.display = 'block';
  } else {
    sunIcon.style.display  = 'block';
    moonIcon.style.display = 'none';
  }
}

document.addEventListener('DOMContentLoaded', function () {

  /* ---------- Theme Toggle Button ---------- */
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('cipherhash_theme', next);
      updateThemeIcons(next);
      showToast(`Switched to ${next} mode`);
    });
  }

  /* ---------- Mobile Nav Toggle ---------- */
  const mobileToggle = document.getElementById('mobileToggle');
  const navMenu      = document.getElementById('navMenu');
  if (mobileToggle && navMenu) {
    mobileToggle.addEventListener('click', function () {
      navMenu.classList.toggle('open');
    });
    // Close nav on link click (mobile UX)
    navMenu.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        navMenu.classList.remove('open');
      });
    });
    // Close on outside click
    document.addEventListener('click', function (e) {
      if (!mobileToggle.contains(e.target) && !navMenu.contains(e.target)) {
        navMenu.classList.remove('open');
      }
    });
  }

  /* ---------- Active Nav Link Highlighting ---------- */
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(function (link) {
    const href = link.getAttribute('href');
    if (href && href !== '/' && currentPath.startsWith(href)) {
      link.classList.add('active');
    } else if (href === '/' && currentPath === '/') {
      link.classList.add('active');
    }
  });

});


/* ============================================================
   2. API HELPER
   ============================================================ */

/**
 * apiPost — Send a JSON POST request to a local Flask API endpoint.
 * Automatically includes the CSRF token from the session cookie if available.
 *
 * @param {string} url     - API endpoint path (e.g. '/api/analyze')
 * @param {object} data    - Request body as a plain JS object
 * @param {boolean} ignoreHttpError - If true, returns the parsed JSON even on 4xx/5xx
 * @returns {Promise<object|null>}  Parsed JSON response, or null on network error
 */
async function apiPost(url, data = {}, ignoreHttpError = false) {
  try {
    const response = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(data),
      credentials: 'same-origin'
    });

    const json = await response.json();

    if (!response.ok && !ignoreHttpError) {
      const errMsg = json.error || json.message || 'An error occurred.';
      showToast(errMsg, 'danger');
      return json;
    }

    return json;

  } catch (err) {
    console.error('[apiPost] Network or parse error:', err);
    showToast('Network error. Is the Flask server running?', 'danger');
    return null;
  }
}


/* ============================================================
   3. TOAST NOTIFICATION HELPER
   ============================================================ */

/**
 * showToast — Display a transient notification banner.
 *
 * @param {string} message  - Text to display
 * @param {'success'|'danger'|'warning'} type - Visual style
 * @param {number} duration - Auto-dismiss time in ms (default 3000)
 */
function showToast(message, type = 'success', duration = 3200) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const icons = { success: '✓', danger: '✕', warning: '⚠' };
  const toast = document.createElement('div');
  toast.className = `toast ${type !== 'success' ? type : ''}`;
  toast.innerHTML = `<span>${icons[type] || '✓'}</span><span>${escHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(function () {
    toast.style.opacity     = '0';
    toast.style.transform   = 'translateY(10px)';
    toast.style.transition  = 'opacity 0.3s, transform 0.3s';
    setTimeout(() => toast.remove(), 320);
  }, duration);
}


/* ============================================================
   4. HTML ESCAPE HELPER
   ============================================================ */

/**
 * escHtml — Escape special HTML characters to prevent XSS.
 * Must be used whenever inserting user-provided strings into innerHTML.
 *
 * @param {string} str - Raw string that may contain HTML special characters
 * @returns {string}   - Safely escaped string
 */
function escHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
