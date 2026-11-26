// Installable / offline app (PWA). Registers public/sw.js on the hosted static site only: never against the local
// server (it has /api and, in `npm run dev`, live reload that a cache would break). Shows a persistent
// "Update available" prompt when a new version has installed and is waiting.
(() => {
  if (!('serviceWorker' in navigator)) return;
  let reloading = false, prompt = null;

  function showUpdate(reg) {
    if (prompt) return;
    prompt = document.createElement('div');
    prompt.className = 'pwa-update';
    prompt.setAttribute('role', 'status');
    prompt.innerHTML = '<span>Update available</span><button type="button" class="pwa-reload">Reload</button><button type="button" class="pwa-dismiss" aria-label="Dismiss update notice">×</button>';
    prompt.querySelector('.pwa-reload').addEventListener('click', () => {
      if (!reg.waiting) { location.reload(); return; }
      reg.waiting.postMessage({ type: 'SKIP_WAITING' });
    });
    prompt.querySelector('.pwa-dismiss').addEventListener('click', () => { prompt.remove(); prompt = null; });
    document.body.appendChild(prompt);
  }

  function watch(reg) {
    if (reg.waiting && navigator.serviceWorker.controller) showUpdate(reg);
    reg.addEventListener('updatefound', () => {
      const w = reg.installing; if (!w) return;
      w.addEventListener('statechange', () => { if (w.state === 'installed' && navigator.serviceWorker.controller) showUpdate(reg); });
    });
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') reg.update().catch(() => {}); });
  }

  function register() {
    if (!window.isSecureContext) return;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (reloading || !prompt) return; // first install claims the page silently; only reload when the user asked
      reloading = true; location.reload();
    });
    navigator.serviceWorker.register('sw.js').then(watch).catch((e) => console.warn('Service worker not registered:', e.message));
  }

  const onReady = (e) => { if (e.detail && e.detail.static) register(); };
  if (document.documentElement.hasAttribute('data-static')) register();
  else document.addEventListener('sb:ready', onReady, { once: true });
})();
