import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { once } from 'node:events'
import { chromium } from 'playwright'

const dir = await mkdtemp(join(tmpdir(), 'hookbox-ui-'))
const file = join(dir, 'config.yaml')
const original = '# untouched comment\ngeneral: {host: 127.0.0.1, port: 18780, admin_port: 18781}\nwebhook: {}\nsecurity: {}\n'
await writeFile(file, original)
const key = 'temporary-ui-test-key'
const svc = spawn(resolve(process.argv[2]), ['--config',file], {
  env: {...process.env, HOOKBOX_ADMIN_SHA256:createHash('sha256').update(key).digest('hex')},
  stdio: ['ignore','inherit','inherit'],
})
const address = 'http://127.0.0.1:18781'
const stopped = once(svc,'exit')
let browser
try {
  for (let i=0;i<100;i++) {
    if (svc.exitCode !== null) throw Error('Hookbox exited during startup')
    if (await fetch(address).then(r=>r.ok,()=>false)) break
    await new Promise(r=>setTimeout(r,100))
  }
  assert.equal((await fetch(address+'/api/config')).status,401)
  assert.equal((await fetch('http://127.0.0.1:18780/api/config')).status,404)
  browser=await chromium.launch(process.env.CHROMIUM_EXECUTABLE ? {executablePath:process.env.CHROMIUM_EXECUTABLE} : {channel:'chrome'})
  const page=await browser.newPage()
  const errors=[]
  page.on('pageerror',e=>errors.push(e.message))
  await page.goto(address)
  await page.getByLabel('Токен администратора').fill(key)
  await page.getByRole('button',{name:'Подключиться'}).click()
  await page.getByRole('button',{name:'Добавить',exact:true}).click()
  await page.getByLabel('Идентификатор').fill('sample')
  await page.getByLabel('Команда и аргументы').fill('example\n--literal')
  await page.getByRole('button',{name:'Применить'}).click()
  await page.getByRole('button',{name:'Сохранить конфигурацию'}).click()
  await page.getByText('Сохранено.',{exact:false}).waitFor()
  const source=await readFile(file,'utf8')
  assert.ok(source.includes('sample') && source.includes('--literal') && source.includes('# untouched comment'))
  const inspector=page.getByRole('complementary',{name:'Свойства записи'})
  await inspector.getByRole('heading',{name:'sample'}).waitFor()
  assert.ok((await inspector.textContent()).includes('example --literal'))
  await page.getByRole('textbox',{name:'Фильтр записей'}).fill('absent-route')
  await page.getByText('Совпадений нет').waitFor()
  await page.getByRole('button',{name:'Очистить фильтр'}).click()
  await inspector.getByRole('button',{name:'Редактировать'}).click()
  assert.equal(await page.getByLabel('Идентификатор').inputValue(),'sample')
  await page.keyboard.press('Escape')
  await page.getByRole('button',{name:'Роли'}).click()
  await page.getByRole('button',{name:'Добавить',exact:true}).click()
  await page.getByLabel('Идентификатор').fill('r')
  await page.getByRole('button',{name:'Применить'}).click()
  // Concurrent change by another administrator must survive a stale save.
  await writeFile(file, source+'\n# changed outside the panel\n')
  await page.getByRole('button',{name:'Сохранить конфигурацию'}).click()
  await page.getByText('Configuration changed.',{exact:false}).waitFor()
  assert.ok((await readFile(file,'utf8')).includes('# changed outside the panel'))
  assert.deepEqual(errors,[])
} finally {
  if(browser) await browser.close()
  if(svc.exitCode===null) svc.kill()
  await stopped
  await rm(dir,{recursive:true,force:true})
}
