// End-to-end checks of the Scam Bunker UI. Runs in both projects: `server` (node server.js) and
// `static` (the GitHub Pages build under /scam_bunker/, where there is no /api).
const path = require('path');
const { AxeBuilder } = require('@axe-core/playwright');
const { test, expect, INVENTED_WALLET, INVENTED_PHOTO, SAMPLE_VERDICTS, aiPng, gpsJpeg, openApp, runSample, runText, runImage, visibleTabs } = require('./fixtures');
const { AGENTS } = require(path.resolve(__dirname, '../../public/shared/prompt.js'));

test.beforeEach(async ({ page }) => { await openApp(page); });

test('runs in the expected mode', async ({ page }, info) => {
  const isStatic = info.project.name === 'static';
  expect(await page.evaluate(() => window.ScamBunker.isStatic())).toBe(isStatic);
  await expect(page.locator('#static-notice')).toBeVisible({ visible: isStatic });
});

test.describe('samples', () => {
  for (const [key, family] of Object.entries(SAMPLE_VERDICTS)) {
    test(`"${key}" sample → ${family.join(' / ')}`, async ({ page }) => {
      await runSample(page, key);
      const verdict = (await page.locator('#v-title').textContent()).trim();
      expect(family).toContain(verdict);
      await expect(page.locator('#panel-deduction .obs .ob:not(.ob-head)').first()).toBeVisible();
    });
  }
});

test.describe('images', () => {
  test('PNG with an embedded tEXt "parameters" prompt → AI confirmed', async ({ page }) => {
    await runImage(page, { name: 'invented-render.png', mimeType: 'image/png', buffer: aiPng() });
    await expect(page.locator('#v-title')).toHaveText('AI-generated content');
    // The file-level engine says "confirmed". The verdict tag may show "likely": grading.js only allows
    // "confirmed" when two independent sources agree, and every signal here comes from the one file.
    await expect(page.locator('#v-tags')).toContainText(/AI: (confirmed|likely)/);
    expect(await page.evaluate(() => window.ScamBunker.current.forensics.ai.verdict)).toBe('confirmed');
    await expect(page.locator('#panel-deduction')).toContainText('PNG "parameters" chunk holds the generation prompt');
    await page.click('#tab-image');
    await expect(page.locator('#panel-image .box', { hasText: 'AI verdict' }).locator('.big')).toHaveText('confirmed');
    await expect(page.locator('#panel-image')).toContainText('Embedded generation prompt');
    await expect(page.locator('#panel-image .prompt')).toContainText('invented-model-v1');
  });

  test('JPEG with EXIF GPS + DateTimeOriginal → hidden info and timeline', async ({ page }) => {
    const buffer = await gpsJpeg(page, INVENTED_PHOTO);
    await runImage(page, { name: 'invented-photo.jpg', mimeType: 'image/jpeg', buffer });
    const ded = page.locator('#panel-deduction');
    await expect(ded.getByRole('heading', { name: 'Hidden in the file' })).toBeVisible();
    await expect(ded).toContainText('GPS location: 12.5, -30.25');
    await expect(ded).toContainText('Device: InventedCam IC-1');
    await expect(ded.locator('.box', { hasText: 'Image dates back to' })).toContainText('2021-06-14');
    await page.click('#tab-timeline');
    const tl = page.locator('#panel-timeline .tl');
    await expect(tl.locator('.tl-item', { hasText: 'Shutter pressed / image captured' })).toContainText('2021-06-14 · 09:30:12');
    await expect(tl.locator('.tl-item', { hasText: 'GPS satellite date' })).toContainText('2021-06-14');
    await page.click('#tab-image');
    await expect(page.locator('#panel-image')).toContainText('Hidden information exposed');
  });
});

test.describe('report sections', () => {
  const cases = {
    'a text case': page => runSample(page, 'crypto'),
    'an image case': async page => runImage(page, { name: 'invented-photo.jpg', mimeType: 'image/jpeg', buffer: await gpsJpeg(page, INVENTED_PHOTO) }, 'Is this photo from the flood last week? Share before it is deleted!'),
  };
  for (const [label, open] of Object.entries(cases)) {
    test(`every visible section opens without errors (${label})`, async ({ page }) => {
      await open(page);
      const tabs = visibleTabs(page);
      const n = await tabs.count();
      expect(n).toBeGreaterThanOrEqual(10);
      for (let i = 0; i < n; i++) {
        const tab = tabs.nth(i);
        const id = await tab.getAttribute('aria-controls');
        await tab.click();
        await expect(tab).toHaveAttribute('aria-selected', 'true');
        const panel = page.locator(`#${id}`);
        await expect(panel).toBeVisible();
        await expect(page.locator('[data-panel]:not([hidden])')).toHaveCount(1);
        await expect.poll(() => panel.evaluate(el => el.innerText.trim().length), { message: `${id} has content` }).toBeGreaterThan(0);
        await expect(panel.locator('.shimmer')).toHaveCount(0);
      }
    });
  }
});

test('section nav is keyboard operable', async ({ page }) => {
  await runSample(page, 'phish');
  const ids = await visibleTabs(page).evaluateAll(ts => ts.map(t => t.id));
  const selected = () => page.locator('#tabs [aria-selected="true"]').getAttribute('id');
  const focused = () => page.evaluate(() => document.activeElement.id);
  const at = async id => {
    expect(await focused()).toBe(id);
    expect(await selected()).toBe(id);
    await expect(page.locator(`#${await page.locator('#' + id).getAttribute('aria-controls')}`)).toBeVisible();
  };
  // Roving tabindex: only the selected tab is in the Tab order.
  await expect(page.locator('#tabs [role=tab][tabindex="0"]')).toHaveCount(1);
  await page.locator('#tab-deduction').focus();
  await at(ids[0]);
  await page.keyboard.press('ArrowDown'); await at(ids[1]);
  await page.keyboard.press('ArrowRight'); await at(ids[2]);
  await page.keyboard.press('ArrowUp'); await at(ids[1]);
  await page.keyboard.press('ArrowLeft'); await at(ids[0]);
  await page.keyboard.press('ArrowLeft'); await at(ids[ids.length - 1]); // wraps
  await page.keyboard.press('Home'); await at(ids[0]);
  await page.keyboard.press('End'); await at(ids[ids.length - 1]);
  // Walking the whole list visits every visible tab once and skips hidden ones.
  await page.keyboard.press('Home');
  const walked = [];
  for (let i = 0; i < ids.length; i++) { walked.push(await focused()); await page.keyboard.press('ArrowDown'); }
  expect(walked).toEqual(ids);
  // Tab moves from the selected tab into its panel.
  await page.keyboard.press('Home');
  await page.keyboard.press('Tab');
  expect(await focused()).toBe('panel-deduction');
  await expect(page.locator('#panel-deduction')).toBeFocused();
});

test('"Investigate with Claude" builds a prompt with every agent role', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await runSample(page, 'crypto');
  const popupP = context.waitForEvent('page');
  await page.locator('[data-handoff]').first().click();
  const popup = await popupP;
  const url = new URL(popup.url());
  expect(url.origin + url.pathname).toBe('https://claude.ai/new');
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('Scam Bunker');
  const prompt = await page.evaluate(() => navigator.clipboard.readText());
  for (const a of Object.values(AGENTS)) {
    expect(prompt, a.name).toContain(a.name);
    expect(prompt, `${a.name} brief`).toContain(a.brief.slice(0, 80));
  }
  expect(prompt).toContain('### Lead investigator');
  expect(prompt).toContain('expert trader'); // the case itself is included
  if (url.searchParams.has('q')) expect(url.searchParams.get('q')).toBe(prompt);
  await expect(page.locator('#toast')).toContainText(/Claude|Case copied/);
});

test('repeat offender: two cases sharing a wallet are linked', async ({ page }) => {
  await runText(page, `Sorry, wrong number. My uncle is an expert trader, guaranteed 30% daily profit on USDT. Send to ${INVENTED_WALLET}. Act now!`);
  expect(['Scam', 'Likely scam']).toContain((await page.locator('#v-title').textContent()).trim());
  await expect(page.locator('#panel-deduction .offender')).toHaveCount(0);

  await runText(page, `Congratulations, you won 5,000 USDT in the InventedCoin anniversary giveaway! Send the 50 USDT verification fee to ${INVENTED_WALLET} to claim your prize.`);
  const off = page.locator('#panel-deduction .offender');
  await expect(off.getByRole('heading', { name: 'Repeat offender' })).toBeVisible();
  await expect(off.locator('.linkcard', { hasText: INVENTED_WALLET })).toContainText('1× before');
  expect(['Scam', 'Likely scam']).toContain((await page.locator('#v-title').textContent()).trim());
  await expect(page.locator('#panel-deduction .deduction')).toContainText('We have met this actor before');

  await page.click('#btn-history');
  const dlg = page.locator('#dlg-history');
  await expect(dlg).toBeVisible();
  await expect(dlg.locator('#offender-index')).toContainText('Repeat offenders across your cases');
  await expect(dlg.locator('#offender-index li', { hasText: INVENTED_WALLET })).toContainText('in 2 cases');
  await expect(dlg.locator('.hist')).toHaveCount(2);
});

test('theme toggle switches light and dark and persists', async ({ page }) => {
  const bg = () => page.evaluate(() => {
    const [r, g, b] = getComputedStyle(document.body).backgroundColor.match(/\d+(\.\d+)?/g).map(Number);
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  });
  const html = page.locator('html');
  await page.click('[data-theme-set="dark"]');
  await expect(html).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('[data-theme-set="dark"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('[data-theme-set="light"]')).toHaveAttribute('aria-pressed', 'false');
  await expect.poll(bg).toBeLessThan(0.3);
  await page.reload(); await openApp(page);
  await expect(html).toHaveAttribute('data-theme', 'dark');

  await page.click('[data-theme-set="light"]');
  await expect(html).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('[data-theme-set="light"]')).toHaveAttribute('aria-pressed', 'true');
  await expect.poll(bg).toBeGreaterThan(0.7);
  await page.reload(); await openApp(page);
  await expect(html).toHaveAttribute('data-theme', 'light');

  await page.click('[data-theme-set="system"]');
  await expect(html).not.toHaveAttribute('data-theme', /./);
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect.poll(bg).toBeLessThan(0.3);
  await page.emulateMedia({ colorScheme: 'light' });
  await expect.poll(bg).toBeGreaterThan(0.7);
});

test.describe('390px viewport', () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  test('no horizontal scroll on the intake or any report section', async ({ page }) => {
    // Returns [] when nothing sticks out; otherwise the overflow in px and the offending elements.
    const overflow = () => page.evaluate(() => {
      const W = document.documentElement.clientWidth, over = Math.max(document.documentElement.scrollWidth, document.body.scrollWidth) - W;
      if (over <= 0) return [];
      const clipped = e => { for (let a = e.parentElement; a; a = a.parentElement) if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(a).overflowX)) return true; return false; };
      return [`${over}px`, ...[...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > W + 0.5 && !clipped(e)).slice(0, 5).map(e => `${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}${e.className ? '.' + String(e.className).split(' ').join('.') : ''}: ${(e.textContent || '').trim().slice(0, 80)}`)];
    });
    expect(await overflow()).toEqual([]);
    await runSample(page, 'crypto');
    const tabs = visibleTabs(page);
    for (let i = 0, n = await tabs.count(); i < n; i++) {
      await tabs.nth(i).click();
      await expect.poll(overflow, { message: `section ${await tabs.nth(i).getAttribute('id')}`, timeout: 3000 }).toEqual([]);
    }
  });
});

test.describe('accessibility (axe-core)', () => {
  const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
  for (const theme of ['light', 'dark']) {
    test(`zero violations in the ${theme} theme`, async ({ page }) => {
      await page.click(`[data-theme-set="${theme}"]`);
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      const scan = async where => {
        const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
        expect(violations.map(v => `${where}: ${v.id} (${v.impact}) ${v.help}\n  ${v.nodes.slice(0, 5).map(n => n.target.join(' ')).join('\n  ')}`)).toEqual([]);
      };
      await scan('intake');
      await runSample(page, 'crypto');
      const tabs = visibleTabs(page);
      for (let i = 0, n = await tabs.count(); i < n; i++) {
        await tabs.nth(i).click();
        await scan(`section ${await tabs.nth(i).getAttribute('id')}`);
      }
    });
  }
});
