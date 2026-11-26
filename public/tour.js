// Scam Bunker: first-visit tour (docs/PRODUCT.md, "The tour"). Five steps: input, examples, verdict + reasons,
// what to do now, mode switch. Targets [data-tour=...] from the shell, with fallbacks for the classic layout; a step
// whose target is missing or hidden is skipped. Non-modal: no backdrop, the page stays usable; Tab is kept inside the
// card while focus is in it, Esc closes. Remembered in localStorage['scambunker.tour'] (try/catch).
// Started from any [data-tour-start] control or index.html#tour. Pure helpers are exported for test/guide.test.js.
(function () {
  'use strict';
  const KEY = 'scambunker.tour';
  const read = s => { try { return s ? s.getItem(KEY) : null; } catch (e) { return null; } };
  const shouldOffer = s => read(s) !== 'done';
  const markDone = s => { try { if (!s) return false; s.setItem(KEY, 'done'); return true; } catch (e) { return false; } };

  const STEPS = [
    { key: 'input', fallback: [() => { const t = document.getElementById('text'); return t && t.closest('label'); }], title: 'Paste anything suspicious here',
      body: 'A message, a link, a phone number or email, or a screenshot, photo or video. It is checked on your device and nothing is uploaded unless you choose to.' },
    { key: 'examples', fallback: [() => document.querySelector('.samples')], loads: true, title: 'Or try an example',
      body: 'Each example is an invented scam message. Pick one, or press Next and we will load one for you.' },
    { key: ['verdict', 'reasons'], fallback: [() => document.getElementById('verdict')], needsCase: true, title: 'Here is the answer and why',
      body: 'The answer comes first, in plain words, with how risky it looks. Under it are the reasons, strongest first, each pointing at the exact words or detail it is about. It is a warning about the message, not a judgement about a person.' },
    { key: 'actions', fallback: [() => document.querySelector('#panel-deduction .advice')], needsCase: true, title: 'Here is what to do now',
      body: 'A short list of safe next steps for this kind of message: do not pay or click, block and report it, and call your bank or mobile-money provider on their real number if you sent money.' },
    { key: 'mode', fallback: [], title: 'Need more? Switch to Investigator mode',
      body: 'Investigator mode shows every check, the evidence grades, the image timeline and tools for fact-checkers. You can switch back at any time.' },
  ];
  const keysOf = s => [].concat(s.key);

  // Index of the next step (in direction dir) whose target exists, or -1.
  function nextIndex(steps, from, dir, exists) {
    for (let i = from + dir; i >= 0 && i < steps.length; i += dir) if (exists(steps[i], i)) return i;
    return -1;
  }

  const api = { KEY, shouldOffer, markDone, STEPS, nextIndex };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  window.ScamBunkerTour = api;

  const SB = () => window.ScamBunker;
  const store = (() => { try { return window.localStorage; } catch (e) { return null; } })();
  const reduce = () => !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  const visible = el => !!el && !el.closest('[hidden]') && el.getClientRects().length > 0;
  let card = null, step = -1, marked = [], returnFocus = null, loading = false;

  function targetsFor(s) {
    const tagged = keysOf(s).map(k => document.querySelector(`[data-tour="${k}"]`)).filter(visible);
    if (tagged.length) return tagged;
    for (const f of s.fallback) { const el = f(); if (visible(el)) return [el]; }
    return [];
  }
  const hasCase = () => !!(SB() && SB().current);
  const exists = s => !(s.needsCase && !hasCase()) && targetsFor(s).length > 0;
  // Steps that will show: present now, or waiting for a case to be loaded.
  const planned = () => STEPS.map((s, i) => (s.needsCase && !hasCase()) || exists(s) ? i : -1).filter(i => i >= 0);

  function clearMarks() { marked.forEach(el => el.classList.remove('tour-target')); marked = []; }

  // Never overwrite what the visitor has already entered: an example replaces the text and link but keeps attachments.
  function hasDraft() {
    const filled = [...document.querySelectorAll('#text, #url, [data-tour="input"] textarea, [data-tour="input"] input:not([type=file])')].some(el => el.value && el.value.trim());
    const file = document.getElementById('drop-full');
    return filled || !!(file && !file.hidden);
  }

  function loadExample() {
    const chip = document.querySelector('[data-tour="examples"] button, [data-tour="examples"] [data-sample], .samples [data-sample]');
    if (!chip || hasCase() || hasDraft()) return Promise.resolve();
    loading = true;
    return new Promise(resolve => {
      let done = false;
      const finish = () => { if (done) return; done = true; loading = false; document.removeEventListener('sb:case', finish); resolve(); };
      document.addEventListener('sb:case', finish);
      setTimeout(finish, 5000);
      chip.click();
    });
  }

  function show(i, focus = true) {
    step = i; clearMarks();
    const s = STEPS[i];
    if (s.needsCase && SB() && SB().showTab && document.getElementById('tab-deduction') && !document.querySelector('[data-tour="reasons"], [data-tour="actions"]')) SB().showTab('deduction');
    marked = targetsFor(s);
    marked.forEach(el => el.classList.add('tour-target'));
    if (marked[0]) marked[0].scrollIntoView({ block: 'start', behavior: reduce() ? 'auto' : 'smooth' });
    const prev = nextIndex(STEPS, i, -1, exists), next = nextIndex(STEPS, i, 1, exists);
    const nextNeedsLoad = s.loads && !hasCase() && !hasDraft();
    const last = next < 0 && !nextNeedsLoad;
    const plan = planned(), pos = Math.max(1, plan.filter(j => j <= i).length), total = Math.max(pos, plan.length);
    card.innerHTML = `<p class="tour-step">Tour · step ${pos} of ${total}</p><h2 id="tour-h" tabindex="-1">${s.title}</h2><p id="tour-p">${s.body}</p>`
      + (last ? '<p>The <a href="guide.html">user guide</a> explains more, including how to date a photo and where to report a scam.</p>' : '')
      + `<div class="tour-actions"><button type="button" class="link" data-tour-act="end">${last ? 'Close' : 'Skip tour'}</button>${prev >= 0 ? '<button type="button" class="ghost" data-tour-act="back">Back</button>' : ''}<button type="button" class="primary sm" data-tour-act="next">${last ? 'Finish' : nextNeedsLoad ? 'Load an example' : 'Next'}</button></div>`;
    if (focus) card.querySelector('#tour-h').focus({ preventScroll: true });
  }

  async function go(dir) {
    if (dir > 0 && STEPS[step].loads && !hasCase() && !hasDraft()) {
      card.querySelector('[data-tour-act="next"]').disabled = true;
      await loadExample();
      if (!card) return;
    }
    const i = nextIndex(STEPS, step, dir, exists);
    if (i < 0) { if (dir > 0) end(); return; }
    show(i);
  }

  function start(e) {
    if (card) { card.querySelector('#tour-h').focus(); return; }
    const first = nextIndex(STEPS, -1, 1, exists);
    if (first < 0) return;
    returnFocus = (e && e.currentTarget && e.currentTarget.focus) ? e.currentTarget : document.activeElement;
    card = document.createElement('div');
    card.className = 'tour'; card.id = 'tour';
    card.setAttribute('role', 'dialog'); card.setAttribute('aria-modal', 'false');
    card.setAttribute('aria-labelledby', 'tour-h'); card.setAttribute('aria-describedby', 'tour-p');
    card.addEventListener('click', ev => {
      const b = ev.target.closest('[data-tour-act]'); if (!b) return;
      const a = b.dataset.tourAct;
      if (a === 'next') go(1); else if (a === 'back') go(-1); else end();
    });
    card.addEventListener('keydown', ev => {
      if (ev.key !== 'Tab') return;
      const f = [...card.querySelectorAll('a[href], button:not([disabled])')];
      if (!f.length) return;
      const i = f.indexOf(document.activeElement);
      if (ev.shiftKey && i <= 0) { ev.preventDefault(); f[f.length - 1].focus(); }
      else if (!ev.shiftKey && i === f.length - 1) { ev.preventDefault(); f[0].focus(); }
    });
    document.body.appendChild(card);
    show(first);
  }

  function end() {
    markDone(store); clearMarks();
    if (card) { card.remove(); card = null; }
    step = -1;
    const back = returnFocus && document.contains(returnFocus) && returnFocus !== document.body ? returnFocus : document.querySelector('[data-tour-start]');
    if (back) back.focus({ preventScroll: true });
  }

  // When the visitor loads an example themselves during step 2, move on to the answer.
  document.addEventListener('sb:case', () => {
    if (!card || loading || !STEPS[step] || !STEPS[step].loads) return;
    setTimeout(() => { if (card) { const i = nextIndex(STEPS, step, 1, exists); if (i >= 0) show(i); } }, 0);
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || !card || document.querySelector('dialog[open]')) return;
    e.preventDefault(); end();
  });
  document.addEventListener('click', e => { const b = e.target.closest('[data-tour-start]'); if (b) { e.preventDefault(); start({ currentTarget: b }); } });

  function init() {
    if (location.hash === '#tour') {
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { }
      start(); return;
    }
    if (shouldOffer(store) && !hasCase()) start();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
