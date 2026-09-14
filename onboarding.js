// Minimal onboarding i18n only
(function(){
  function applyI18n() {
    try {
      const els = document.querySelectorAll('[data-i18n]');
      els.forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (!key) return;
        const msg = chrome.i18n?.getMessage ? chrome.i18n.getMessage(key) : '';
        if (msg) {
          if (msg.includes('<') && msg.includes('>')) el.innerHTML = msg; else el.textContent = msg;
        }
      });
    } catch (_) {}
  }
  applyI18n();
})();
