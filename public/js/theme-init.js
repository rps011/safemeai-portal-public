/* SafeMeAI theme: light by default, dark only if the user chose it. Loaded synchronously in <head> (CSP: script-src 'self'). */
(function () {
  var KEY = 'safemeai_theme';
  var COLORS = { light: '#f3f5f9', dark: '#070a13' };
  var L = {
    Dark: 'डार्क', Light: 'लाइट',
    'Switch to dark theme': 'डार्क थीम चालू करें',
    'Switch to light theme': 'लाइट थीम चालू करें'
  };
  function stored() { try { var v = localStorage.getItem(KEY); return v === 'dark' || v === 'light' ? v : null; } catch (e) { return null; } }
  function current() { return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light'; }
  function isHi() {
    var l = document.documentElement.lang;
    if (l) return l === 'hi';
    try { return localStorage.getItem('safemeai_lang') === 'hi'; } catch (e) { return false; }
  }
  function tr(s) { return isHi() && L[s] ? L[s] : s; }
  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', COLORS[theme]);
  }
  function refresh() {
    var dark = current() === 'dark';
    var btns = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      var ico = b.querySelector('.theme-ico'), lbl = b.querySelector('.theme-label');
      if (ico) ico.textContent = dark ? '☀️' : '🌙';
      if (lbl) lbl.textContent = tr(dark ? 'Light' : 'Dark');
      b.setAttribute('aria-pressed', dark ? 'true' : 'false');
      b.setAttribute('aria-label', tr(dark ? 'Switch to light theme' : 'Switch to dark theme'));
    }
  }
  function set(theme) {
    apply(theme);
    try { localStorage.setItem(KEY, theme); } catch (e) { /* storage blocked */ }
    refresh();
  }
  apply(stored() || 'light');
  window.SafeTheme = { set: set, refresh: refresh, current: current };
  document.addEventListener('DOMContentLoaded', function () {
    var btns = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < btns.length; i++) btns[i].addEventListener('click', function () { set(current() === 'dark' ? 'light' : 'dark'); });
    refresh();
  });
})();
