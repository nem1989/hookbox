import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Alert, Badge, Button, Checkbox, Group, MantineProvider, Modal, MultiSelect, PasswordInput, Select, Stack, Text, Textarea, TextInput, Title } from '@mantine/core'
import { parse, parseDocument, stringify } from 'yaml'
import '@mantine/core/styles.css'
import './panel.css'

type Kind = 'webhook' | 'roles' | 'users' | 'tokens'
type Fields = Record<string, any>
type Model = { webhook?: Record<string, Fields>, security?: {roles?: Record<string, string[]>, users?: Record<string, Fields>, tokens?: Record<string, Fields>} }
const sections: Record<Kind, string> = {webhook: 'Вебхуки', roles: 'Роли', users: 'Пользователи', tokens: 'Токены'}
const newAction = () => ({type: 'command', command: [] as string[], timeout_seconds: 30, max_output_bytes: 65536})
const newItem = (kind: Kind): any => ({webhook: {methods: ['POST'], actions: [newAction()]}, roles: [], users: {roles: []}, tokens: {user: '', sha256: ''}}[kind])

function decode(source: string) {
  const doc = parseDocument(source)
  if (doc.errors.length) throw new Error(doc.errors[0].message)
  return doc
}
function validateItem(kind: Kind, value: any) {
  const object = (item: unknown) => !!item && typeof item === 'object' && !Array.isArray(item)
  const strings = (items: unknown) => Array.isArray(items) && items.every(s => typeof s === 'string')
  if (kind === 'roles') {
    if (!strings(value)) throw new Error('Роль должна содержать список идентификаторов вебхуков.')
    return
  }
  if (!object(value)) throw new Error('Запись должна быть объектом YAML.')
  if (kind === 'webhook') {
    if ((value.methods != null && !strings(value.methods)) || !Array.isArray(value.actions) ||
        value.actions.some((a: any) => !object(a) || (a.type === 'command' && !strings(a.command)))) {
      throw new Error('Проверь списки методов, действий и аргументов команды.')
    }
  } else if (value.roles != null && !strings(value.roles)) {
    throw new Error('Поле roles должно содержать список идентификаторов ролей.')
  }
}
function metadata(kind: Kind, id: string, item: any): string {
  if (kind === 'webhook') return (item.methods || ['POST']).join(', ') + '   ' + (item.path || '/hooks/' + id)
  if (kind === 'roles') return item.join(', ') || 'Нет доступных хуков'
  if (kind === 'tokens') return item.user || '—'
  return (item.roles || []).join(', ') || 'Без ролей'
}
function itemPath(kind: Kind, id: string) { return kind === 'webhook' ? [kind, id] : ['security', kind, id] }
const symbol: Record<Kind | 'yaml', string> = {webhook: '↗', roles: '◇', users: '◎', tokens: '⌁', yaml: '{ }'}

function ActionForm({value, onChange}: {value: Fields, onChange: (v: Fields) => void}) {
  const field = (k: string, v: any) => { const next = {...value}; if (v === undefined) delete next[k]; else next[k] = v; onChange(next) }
  return <Stack gap="sm">
    <Select label="Тип действия" value={value.type} allowDeselect={false} data={['command','http']}
      onChange={v => v && onChange(v === 'command' ? newAction() : {type:'http', url:'', method:'POST', forward_payload:true})}/>
    {value.type === 'command' ? <>
      <Textarea label="Команда и аргументы" description="Исполняемый файл на первой строке, затем по одному аргументу на строку." autosize minRows={2}
        value={(value.command || []).join('\n')} onChange={e => field('command', e.target.value.split('\n'))}/>
      <TextInput label="Рабочий каталог" value={value.cwd || ''} onChange={e => field('cwd', e.target.value || undefined)}/>
      <Checkbox label="Передавать JSON в stdin" checked={value.stdin_from_payload !== false} onChange={e => field('stdin_from_payload', e.target.checked)}/>
    </> : <>
      <TextInput label="URL" value={value.url || ''} onChange={e => field('url', e.target.value)}/>
      <Select label="Метод" data={['GET','POST','PUT','PATCH','DELETE']} value={value.method || 'POST'} allowDeselect={false} onChange={v => field('method',v)}/>
      <Checkbox label="Пересылать входящий JSON" checked={!!value.forward_payload} onChange={e => field('forward_payload', e.target.checked)}/>
    </>}
    <Group grow align="start">
      <TextInput type="number" label="Таймаут, с" value={value.timeout_seconds ?? 30} onChange={e => field('timeout_seconds', Number(e.target.value))}/>
      <TextInput type="number" label="Лимит вывода, байт" value={value.max_output_bytes ?? 65536} onChange={e => field('max_output_bytes', Number(e.target.value))}/>
    </Group>
  </Stack>
}

function Editor({kind, id, model, initial, close, apply}: {kind: Kind, id: string | null, model: Model, initial: any, close: () => void, apply: (id:string, item:any) => void}) {
  const [name, setName] = useState(id || '')
  const [v, set] = useState<any>(() => structuredClone(initial))
  const [raw, setRaw] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [generated, setGenerated] = useState('')
  const roles = Object.keys(model.security?.roles || {})
  const users = Object.keys(model.security?.users || {})
  const setField = (k: string, value: any) => {
    const next = {...v}
    if (value === undefined) delete next[k]; else next[k] = value
    set(next)
  }
  function editActions(i: number, replace: Fields | null, move = 0) {
    const rows = [...v.actions]
    if (move) [rows[i], rows[i+move]] = [rows[i+move], rows[i]]
    else if (replace) rows[i] = replace
    else rows.splice(i, 1)
    setField('actions', rows)
  }
  async function generate() {
    try {
      const buf = crypto.getRandomValues(new Uint8Array(32))
      const token = Array.from(buf, x => x.toString(16).padStart(2,'0')).join('')
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
      setField('sha256', Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2,'0')).join(''))
      setGenerated(token)
    } catch { setError('Для генерации токена открой панель через HTTPS или localhost.') }
  }
  return <Modal opened onClose={close} size="lg" title={id ? 'Редактирование · ' + id : 'Новая запись'} centered>
    <form onSubmit={e => { e.preventDefault(); try { apply(name, raw === null ? v : parse(raw)) } catch (err) { setError(String(err)) } }}>
    <Stack>
      <TextInput label="Идентификатор" required disabled={id !== null} pattern="[A-Za-z0-9][A-Za-z0-9_.\-]*" value={name} onChange={e => setName(e.target.value)}/>
      {raw !== null ? <Textarea label="YAML записи" className="mono" autosize minRows={9} value={raw} onChange={e => setRaw(e.target.value)}/> : <>
        {kind === 'webhook' && <>
          <TextInput label="Путь" placeholder={'/hooks/' + (name || 'id')} value={v.path || ''} onChange={e => setField('path',e.target.value || undefined)}/>
          <MultiSelect label="Методы" data={['POST','PUT','PATCH']} value={v.methods || ['POST']} onChange={x => setField('methods',x)}/>
          <Checkbox label="Возвращать вывод клиенту" checked={!!v.expose_output} onChange={e => setField('expose_output',e.target.checked)}/>
          {(v.actions || []).map((a: Fields, i: number) => <section className="action" key={i}>
            <Group justify="space-between"><b>Действие {i+1}</b><Group gap={4}>
              <Button variant="subtle" size="compact-xs" aria-label="Переместить выше" disabled={!i} onClick={() => editActions(i,null,-1)}>↑</Button>
              <Button variant="subtle" size="compact-xs" aria-label="Переместить ниже" disabled={i===v.actions.length-1} onClick={() => editActions(i,null,1)}>↓</Button>
              <Button variant="subtle" color="red" size="compact-xs" onClick={() => editActions(i,null)}>Удалить</Button>
            </Group></Group><ActionForm value={a} onChange={x => editActions(i,x)}/></section>)}
          <Button variant="light" onClick={() => setField('actions',[...(v.actions||[]),newAction()])}>Добавить действие</Button>
        </>}
        {kind === 'roles' && <MultiSelect label="Разрешённые вебхуки" data={['*',...Object.keys(model.webhook || {})]} value={v} onChange={set}/>}
        {kind === 'users' && <MultiSelect label="Роли" data={roles} value={v.roles || []} onChange={x => setField('roles',x)}/>}
        {kind === 'tokens' && <>
          <Select label="Пользователь" data={users} value={v.user} onChange={x => set({...v, user:x, roles:undefined})}/>
          <Checkbox label="Наследовать роли пользователя" checked={v.roles == null} onChange={e => setField('roles',e.target.checked ? undefined : [])}/>
          {v.roles != null && <MultiSelect label="Роли токена" data={model.security?.users?.[v.user]?.roles || []} value={v.roles} onChange={x => setField('roles',x)}/>}
          <TextInput label="SHA-256 токена" value={v.sha256 || ''} onChange={e => setField('sha256',e.target.value)}/>
          <Button variant="light" onClick={generate}>Сгенерировать токен</Button>
          {generated && <TextInput label="Скопируй токен до закрытия окна" readOnly value={generated} onFocus={e => e.target.select()}/>}
        </>}
        {kind !== 'roles' && <Checkbox label="Включён" checked={v.enabled !== false} onChange={e => setField('enabled',e.target.checked)}/>}
      </>}
      {error && <Alert color="red">{error}</Alert>}
      <Group justify="space-between"><Button variant="subtle" onClick={() => {
        try { if (raw === null) setRaw(stringify(v)); else { set(parse(raw)); setRaw(null) } } catch(err){setError(String(err))}
      }}>{raw === null ? 'Все поля в YAML' : 'Форма'}</Button><Button type="submit">Применить</Button></Group>
    </Stack></form>
  </Modal>
}

function Panel() {
  const [key, setKey] = useState(''), [source, setSource] = useState(''), [saved, setSaved] = useState(''), [etag, setTag] = useState('')
  const [section, setSection] = useState<Kind | 'yaml'>('webhook'), [edit, setEdit] = useState<{id:string|null}|null>(null)
  const [error, setError] = useState(''), [notice, setNotice] = useState(''), [busy, setBusy] = useState(false), [remove, setRemove] = useState<string|null>(null)
  const [conflict, setConflict] = useState(false)
  const dirty = source !== saved
  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => { if (dirty) e.preventDefault() }
    window.addEventListener('beforeunload',warn)
    return () => window.removeEventListener('beforeunload',warn)
  },[dirty])
  async function load() {
    setBusy(true); setError('')
    try {
      const r = await fetch('/api/config',{headers:{Authorization: 'Bearer '+key},cache:'no-store'})
      if (!r.ok) throw new Error(r.status === 401 ? 'Неверный токен администратора' : await r.text())
      const s = await r.text(); setSource(s); setSaved(s); setTag(r.headers.get('ETag')!); setConflict(false); setNotice('')
    } catch(err) { setError(String(err)) } finally { setBusy(false) }
  }
  async function save() {
    setBusy(true); setError(''); setNotice('')
    try {
      const r = await fetch('/api/config',{method:'PUT',headers:{Authorization:'Bearer '+key,'If-Match':etag,'Content-Type':'text/plain;charset=utf-8'},body:source})
      if (!r.ok) { if(r.status===412) setConflict(true); throw new Error(await r.text()) }
      setTag(r.headers.get('ETag')!); setSaved(source); setNotice('Сохранено. Перезапусти службу, чтобы применить конфигурацию.')
    } catch(err) { setError(String(err)) } finally { setBusy(false) }
  }
  if (!etag) return <main className="login"><div className="brand"><span>H</span> Hookbox</div><form onSubmit={e=>{e.preventDefault();load()}}>
    <Title order={1}>Вход в панель</Title><PasswordInput label="Токен администратора" required value={key} onChange={e=>setKey(e.target.value)} autoComplete="off"/>
    {error && <Alert color="red">{error}</Alert>}<Button type="submit" loading={busy}>Подключиться</Button>
  </form></main>
  let model: Model = {}, parseError = ''
  try {
    const candidate = decode(source).toJS() || {}
    for (const k of Object.keys(sections) as Kind[]) {
      const entries = k === 'webhook' ? candidate.webhook : candidate.security?.[k]
      for (const v of Object.values(entries || {})) validateItem(k, v)
    }
    model = candidate
  } catch(err){parseError = String(err)}
  const items: Record<string,any> = section === 'webhook' ? model.webhook || {} : section === 'yaml' ? {} : model.security?.[section] || {}
  function apply(id: string, value: any) {
    if (section === 'yaml') return
    if (!edit?.id && Object.hasOwn(items,id)) throw new Error('Такой идентификатор уже существует')
    validateItem(section,value)
    const d = decode(source); d.setIn(itemPath(section,id), value); setSource(d.toString()); setEdit(null); setNotice('')
  }
  return <div className="shell"><aside><div className="brand"><span>H</span> Hookbox</div><nav>
    {([...Object.entries(sections),['yaml','Конфигурация']] as [Kind|'yaml',string][]).map(([id,label])=><button key={id} className={section===id?'selected':''} onClick={()=>{setSection(id);setEdit(null)}}><i>{symbol[id]}</i>{label}</button>)}
  </nav><button className="logout" onClick={()=>{if(!dirty || window.confirm('Выйти и потерять несохранённые изменения?')) {setKey('');setTag('');setSaved('');setSource('');setError('');setNotice('')}}}>Выйти</button></aside>
  <main className="work"><header><div><Text size="sm" c="dimmed">{location.host}</Text><Title order={1}>{section==='yaml'?'Конфигурация':sections[section]}</Title></div>
    <Button disabled={!dirty || busy} onClick={save}>Сохранить конфигурацию</Button></header>
    {(error || parseError) && <Alert color="red" mb="md">{error || parseError}{conflict && <Button variant="subtle" onClick={()=>{if(window.confirm('Загрузить серверную версию и потерять локальные правки?'))load()}}>Загрузить серверную версию</Button>}</Alert>}
    {notice && <Alert color="teal" mb="md">{notice}</Alert>}
    {section==='yaml' ? <Textarea className="mono" label="YAML" autosize minRows={18} value={source} onChange={e=>{setSource(e.target.value);setNotice('')}}/> : <>
      <div className="listbar"><Text fw={600}>Всего · {Object.keys(items).length}</Text><Button variant="light" disabled={!!parseError} onClick={()=>setEdit({id:null})}>Добавить</Button></div>
      <div className="entries">{Object.entries(items).map(([id,item])=><div className="entry" key={id}><button className="entity" onClick={()=>setEdit({id})}><strong>{id}</strong><small>{metadata(section,id,item)}</small></button>
        {section!=='roles' && <Badge variant="light" color={item.enabled===false?'gray':'teal'}>{item.enabled===false?'Выключен':'Включён'}</Badge>}
        <Button variant="subtle" color="gray" size="compact-xs" onClick={()=>setRemove(id)}>Удалить</Button></div>)}
        {!Object.keys(items).length && <Text c="dimmed" p="xl">Пока нет записей</Text>}</div>
      {edit && <Editor key={section+(edit.id||'')} kind={section} id={edit.id} model={model} initial={edit.id ? items[edit.id] : newItem(section)} close={()=>setEdit(null)} apply={apply}/>}
      <Modal opened={remove!==null} onClose={()=>setRemove(null)} title={'Удалить '+remove+'?'} centered><Group justify="end"><Button variant="default" onClick={()=>setRemove(null)}>Отмена</Button><Button color="red" onClick={()=>{if(remove){const d=decode(source);d.deleteIn(itemPath(section,remove));setSource(d.toString());setRemove(null);setNotice('')}}}>Удалить</Button></Group></Modal>
    </>}
  </main></div>
}

createRoot(document.getElementById('root')!).render(<MantineProvider theme={{primaryColor:'teal',defaultRadius:'md',fontFamily:'Inter, Segoe UI, sans-serif'}}><Panel/></MantineProvider>)
