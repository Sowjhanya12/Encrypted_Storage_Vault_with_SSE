// Runs before style.css applies, so there is no dark->light flash.
// A separate file (not inline) because the trusted client sends a
// Content-Security-Policy that forbids inline scripts.
(function () {
  var theme = 'dark';
  try {
    theme = localStorage.getItem('vaultTheme') || 'dark';
  } catch (e) { /* storage unavailable: keep the default */ }
  document.documentElement.setAttribute('data-theme', theme);
})();
