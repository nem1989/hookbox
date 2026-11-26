// The CI process starts the packaged Manager with a loopback-only debugging
// port. Production starts WebView2 with its default options.
import assert from 'node:assert/strict'
import { chromium } from 'playwright'
import { setTimeout as delay } from 'node:timers/promises'

const endpoint = 'http://127.0.0.1:18784'
let browser
try {
  for (let i = 0; i < 120; i++) {
    if (await fetch(endpoint + '/json/version').then(r => r.ok, () => false)) {
      browser = await chromium.connectOverCDP(endpoint)
      break
    }
    await delay(500)
  }
  assert.ok(browser, 'Packaged Manager did not initialize WebView2')
  const context = browser.contexts()[0]
  const page = context.pages()[0] || await context.waitForEvent('page')
  await page.getByLabel('Токен администратора').fill(process.env.HOOKBOX_MANAGER_TEST_TOKEN)
  await page.getByRole('button', { name: 'Подключиться' }).click()
  await page.getByRole('heading', { name: 'Вебхуки' }).waitFor()
  assert.equal(new URL(page.url()).origin, 'http://127.0.0.1:8081')
} finally {
  if (browser) await browser.close()
}
