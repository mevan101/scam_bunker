// Captures PR screenshots. Not part of the suite: run with SCREENSHOTS=dir npx playwright test screens.spec.js
const path = require('node:path');
const { test, openApp, runSample, runImage, aiPng } = require('./fixtures');
test.skip(!process.env.SCREENSHOTS, 'set SCREENSHOTS=<dir> to capture');
const out = (name, info) => path.resolve(process.env.SCREENSHOTS || '.', `${info.project.name}-${name}.png`);
test('report, dark theme, mobile', async ({ page, browser }, info) => {
  await openApp(page); await runSample(page, 'crypto');
  await page.screenshot({ path: out('crypto-light', info), fullPage: false });
  await page.click('[data-theme-set="dark"]'); await runImage(page, { name: 'invented-ai.png', mimeType: 'image/png', buffer: aiPng() }, '');
  await page.click('#tab-image'); await page.screenshot({ path: out('png-image-lab-dark', info) });
  const m = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, baseURL: info.project.use.baseURL });
  await m.goto('./'); await m.waitForFunction(() => document.querySelector('#pill-local.on')); await m.click('[data-sample="viral"]');
  await m.waitForSelector('#v-title:not(:empty)'); await m.waitForTimeout(800); await m.screenshot({ path: out('viral-390', info) });
});
