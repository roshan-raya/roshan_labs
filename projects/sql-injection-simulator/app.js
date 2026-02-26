(function () {
  'use strict';

  const DUMMY_USER = { username: 'admin', password: 'admin123' };

  const PATTERNS = [
    /\s+or\s+/i,
    /'or\s/i,
    /"or\s/i,
    /1\s*=\s*1/,
    /--/,
    /\/\*/,
    /\*\//,
    /'\s*or\s*'/i,
    /'\s*or\s*"\s*=\s*"/i,
  ];

  function isInjectionLike(text) {
    if (!text || typeof text !== 'string') return false;
    const t = text.toLowerCase().trim();
    return PATTERNS.some(function (p) { return p.test(t); });
  }

  function getInjectionSegment(text) {
    if (!text || typeof text !== 'string') return null;
    for (var i = 0; i < PATTERNS.length; i++) {
      var m = text.match(PATTERNS[i]);
      if (m) return m[0];
    }
    return null;
  }

  function escapeHtml(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function highlightInjectionInQuery(query, segment) {
    if (!segment) return escapeHtml(query);
    var idx = query.indexOf(segment);
    if (idx === -1) return escapeHtml(query);
    return escapeHtml(query.slice(0, idx)) +
      '<span class="highlight">' + escapeHtml(segment) + '</span>' +
      escapeHtml(query.slice(idx + segment.length));
  }

  function getQueryPreview(vulnerable, username, password) {
    var u = username || '';
    var p = password || '';
    if (vulnerable) {
      return "SELECT * FROM users WHERE username = '" + u + "' AND password = '" + p + "';";
    }
    return {
      query: "SELECT * FROM users WHERE username = ? AND password = ?;",
      bound: [u, p]
    };
  }

  function renderQueryPreview(vulnerable, username, password) {
    var container = document.getElementById('query-preview-content');
    if (!container) return;

    var usernameVal = (username || '').trim();
    var passwordVal = (password || '').trim();
    var prev = getQueryPreview(vulnerable, usernameVal, passwordVal);

    if (vulnerable) {
      var segment = getInjectionSegment(usernameVal) || getInjectionSegment(passwordVal);
      var html = highlightInjectionInQuery(prev, segment);
      container.innerHTML = html;
      container.classList.add('query-preview__raw');
    } else {
      var lines = prev.query + '\nBound values: ' + JSON.stringify(prev.bound);
      container.textContent = lines;
      container.classList.remove('query-preview__raw');
    }
  }

  function getVulnExplanation(vulnerable, username, password, resultKind) {
    var u = (username || '').trim();
    var p = (password || '').trim();
    if (vulnerable && resultKind === 'bypass') {
      if (isInjectionLike(u) || isInjectionLike(p)) {
        return 'The input contained SQL-like patterns (e.g. <code>OR</code>, <code>1=1</code>, <code>--</code>). ' +
          'In a vulnerable app, this is concatenated into the query and changes its logic—e.g. the condition becomes always true, so the login is bypassed.';
      }
    }
    if (vulnerable && (isInjectionLike(u) || isInjectionLike(p)) && resultKind !== 'bypass') {
      return 'Your input looks like an injection attempt. In this simulation, such input is treated as a bypass when in Vulnerable mode. Try one of the example payloads.';
    }
    if (!vulnerable && (isInjectionLike(u) || isInjectionLike(p))) {
      return 'In Secure mode, inputs are passed as bound parameters. The query structure never changes, so injection fails and the input is treated only as data.';
    }
    if (vulnerable) {
      return 'In Vulnerable mode, your input is concatenated directly into the SQL string. Use the example payloads to see how an attacker could change the query logic.';
    }
    return 'In Secure mode, only the exact credentials (admin / admin123) succeed. User input is never concatenated into the query.';
  }

  function runLogin(vulnerable, username, password) {
    var u = (username || '').trim();
    var p = (password || '').trim();
    var exactMatch = u === DUMMY_USER.username && p === DUMMY_USER.password;

    if (vulnerable) {
      if (isInjectionLike(u) || isInjectionLike(p)) {
        return { kind: 'bypass', message: 'The query logic was altered by the input; login bypass simulated.' };
      }
      if (exactMatch) {
        return { kind: 'success', message: 'Credentials matched the simulated user.' };
      }
      return { kind: 'fail', message: 'No match. Try admin / admin123 or use an example payload in Vulnerable mode.' };
    }

    if (exactMatch) {
      return { kind: 'success', message: 'Credentials matched. Parameterized query kept the query structure safe.' };
    }
    return { kind: 'fail', message: 'Invalid credentials. In Secure mode, injection cannot bypass login.' };
  }

  function showResult(result) {
    var panel = document.getElementById('result-panel');
    var statusEl = document.getElementById('result-status');
    var messageEl = document.getElementById('result-message');
    if (!panel || !statusEl || !messageEl) return;

    panel.hidden = false;
    panel.classList.remove('result-panel--success', 'result-panel--bypass', 'result-panel--fail');
    if (result.kind === 'success') {
      panel.classList.add('result-panel--success');
      statusEl.textContent = '\u2705 Login success';
    } else if (result.kind === 'bypass') {
      panel.classList.add('result-panel--bypass');
      statusEl.textContent = '\u2705 Login bypassed (simulated)';
    } else {
      panel.classList.add('result-panel--fail');
      statusEl.textContent = '\u274C Login failed';
    }
    messageEl.textContent = result.message;
  }

  function setModeHint(vulnerable) {
    var hint = document.getElementById('mode-hint');
    if (hint) {
      hint.textContent = vulnerable
        ? 'String concatenation — injection possible'
        : 'Parameterized queries — input treated as data only';
    }
  }

  function bindSimulator() {
    var form = document.getElementById('login-form');
    var usernameInput = document.getElementById('username');
    var passwordInput = document.getElementById('password');
    if (!usernameInput || !passwordInput) return;

    var segmented = document.querySelector('.segmented');
    var vulnerable = true;

    function updateUi() {
      renderQueryPreview(vulnerable, usernameInput.value, passwordInput.value);
      setModeHint(vulnerable);
      var expl = document.getElementById('vuln-explanation');
      if (expl) {
        var result = runLogin(vulnerable, usernameInput.value, passwordInput.value);
        expl.innerHTML = '<p>' + getVulnExplanation(vulnerable, usernameInput.value, passwordInput.value, result.kind) + '</p>';
      }
    }

    if (segmented) {
      segmented.addEventListener('click', function (e) {
        var btn = e.target.closest('.segmented__opt');
        if (!btn) return;
        var mode = btn.getAttribute('data-mode');
        vulnerable = mode === 'vulnerable';
        segmented.querySelectorAll('.segmented__opt').forEach(function (b) {
          b.classList.remove('segmented__opt--active');
          b.setAttribute('aria-pressed', 'false');
        });
        btn.classList.add('segmented__opt--active');
        btn.setAttribute('aria-pressed', 'true');
        updateUi();
      });
    }

    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var result = runLogin(vulnerable, usernameInput.value, passwordInput.value);
        showResult(result);
        var expl = document.getElementById('vuln-explanation');
        if (expl) {
          expl.innerHTML = '<p>' + getVulnExplanation(vulnerable, usernameInput.value, passwordInput.value, result.kind) + '</p>';
        }
        renderQueryPreview(vulnerable, usernameInput.value, passwordInput.value);
      });
    }

    usernameInput.addEventListener('input', updateUi);
    usernameInput.addEventListener('change', updateUi);
    passwordInput.addEventListener('input', updateUi);
    passwordInput.addEventListener('change', updateUi);

    document.querySelectorAll('.chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        var payload = chip.getAttribute('data-payload');
        var field = chip.getAttribute('data-field');
        if (field === 'username') {
          usernameInput.value = payload;
          usernameInput.focus();
        } else {
          passwordInput.value = payload;
          passwordInput.focus();
        }
        updateUi();
      });
    });

    updateUi();
  }

  function bindTabs() {
    var tabList = document.querySelector('.tabs');
    var tabs = document.querySelectorAll('.tabs__btn');
    var panels = document.querySelectorAll('.tab-panel');

    function switchTo(index) {
      var i = Number(index);
      if (i < 0 || i >= tabs.length) return;
      tabs.forEach(function (t, j) {
        t.classList.toggle('tabs__btn--active', j === i);
        t.setAttribute('aria-selected', j === i);
        t.setAttribute('tabindex', j === i ? 0 : -1);
      });
      panels.forEach(function (p, j) {
        p.classList.toggle('tab-panel--active', j === i);
        p.hidden = j !== i;
      });
    }

    tabs.forEach(function (tab, index) {
      tab.addEventListener('click', function () {
        switchTo(index);
      });
      tab.addEventListener('keydown', function (e) {
        var idx = Array.prototype.indexOf.call(tabs, e.target);
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
          e.preventDefault();
          switchTo((idx + 1) % tabs.length);
          tabs[(idx + 1) % tabs.length].focus();
        } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
          e.preventDefault();
          switchTo((idx - 1 + tabs.length) % tabs.length);
          tabs[(idx - 1 + tabs.length) % tabs.length].focus();
        } else if (e.key === 'Home') {
          e.preventDefault();
          switchTo(0);
          tabs[0].focus();
        } else if (e.key === 'End') {
          e.preventDefault();
          switchTo(tabs.length - 1);
          tabs[tabs.length - 1].focus();
        }
      });
    });

    switchTo(0);
  }

  function bindCopyButtons() {
    document.querySelectorAll('.code-block__copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.getAttribute('data-target');
        var pre = id ? document.getElementById(id) : null;
        if (!pre) return;
        var code = pre.querySelector('code');
        var text = code ? code.textContent : pre.textContent;
        navigator.clipboard.writeText(text)
          .then(function () {
            var label = btn.getAttribute('aria-label') || 'Copy';
            btn.textContent = 'Copied!';
            btn.setAttribute('aria-label', 'Copied');
            setTimeout(function () {
              btn.textContent = 'Copy';
              btn.setAttribute('aria-label', label);
            }, 2000);
          })
          .catch(function () {
            alert('Copy blocked by browser. Select the code and copy manually.');
          });
      });
    });
  }

  function init() {
    bindSimulator();
    bindTabs();
    bindCopyButtons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
