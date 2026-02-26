(function () {
  const btn = document.getElementById('themeBtn');
  const key = 'roshan_theme';

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem(key, t);
  }

  const saved = localStorage.getItem(key);
  if (saved === 'light' || saved === 'dark') setTheme(saved);

  btn?.addEventListener('click', function () {
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    setTheme(cur === 'dark' ? 'light' : 'dark');
  });
})();
