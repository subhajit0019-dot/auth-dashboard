/**
 * Advanced Client-Side Security Armor & Anti-Inspection Shield
 * Disables DevTools, Right-Click, Source Shortcuts & Debugging
 */
(function() {
  'use strict';

  // 1. Disable Right Click Context Menu
  document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    return false;
  }, { capture: true });

  // 2. Disable Keyboard Shortcuts (F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C, Ctrl+U, Ctrl+S)
  document.addEventListener('keydown', function(e) {
    // F12
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    // Ctrl + Shift + I / J / C
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c' || e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    // Ctrl + U (View Source)
    if ((e.ctrlKey || e.metaKey) && (e.key === 'U' || e.key === 'u' || e.keyCode === 85)) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    // Ctrl + S (Save Page)
    if ((e.ctrlKey || e.metaKey) && (e.key === 'S' || e.key === 's' || e.keyCode === 83)) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  }, { capture: true });

  // 3. Neutralize Console & Logs
  try {
    const noop = function() {};
    const methods = ['log', 'debug', 'info', 'warn', 'error', 'table', 'dir', 'trace'];
    for (let i = 0; i < methods.length; i++) {
      window.console[methods[i]] = noop;
    }
    setInterval(function() {
      try { window.console.clear(); } catch(e) {}
    }, 1500);
  } catch(e) {}

  // 4. Anti-Debugging Loop (Freezes DevTools Sources tab if opened)
  setInterval(function() {
    try {
      (function() {
        return false;
      })['constructor']('debugger')();
    } catch(err) {}
  }, 350);

})();
