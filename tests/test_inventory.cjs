'use strict';
const fs = require('node:fs');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
const start = source.indexOf('  function parseInventoryCSV(');
const end = source.indexOf('  function renderInventory(', start);
assert.ok(start >= 0 && end > start, 'production CSV parser must be present');
const parse = new Function('flow', source.slice(start, end) + '\nreturn parseInventoryCSV;')((key, values = []) => `${key}${values.length ? ':' + values.join(',') : ''}`);
const headers = ['url', 'business_name', 'business_email', 'technical_name', 'technical_email'];
let checks = 0;
function check(name, run) { run(); console.log(`ok ${++checks} - ${name}`); }
function csvRow(values) { return values.map(value => /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value).join(','); }
function csv(values) { return headers.join(',') + '\n' + csvRow(values); }
function errorKeys(row) { return row.errors.map(error => `${error.column}:${error.message}`); }

check('BOM, CRLF, quoted commas and escaped quotes preserve all five literal values', () => {
  const raw = ['https://one.example/a,b', 'A "Quoted" Name', 'a@example.com', 'Tech Two', 'tech@example.com'];
  const rows = parse('\uFEFF' + headers.join(',') + '\r\n' + csvRow(raw) + '\r\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].line, 2);
  assert.deepEqual(rows[0].values, Object.fromEntries(headers.map((header, index) => [header, raw[index]])));
  assert.equal(rows[0].contacts[0].name, 'A "Quoted" Name');
  assert.equal(rows[0].error, '');
  assert.deepEqual(rows[0].errors, []);
  assert.deepEqual(rows[0].invalidFields, []);
  assert.deepEqual(rows[0].extraValues, []);
  assert.equal(rows[0].result, null);
  assert.equal(rows[0].imported, false);
});
check('physical row numbers account for leading blanks and quoted multiline fields', () => {
  const text = '\r\n' + headers.join(',') + '\r\n\r\n' + csvRow(['https://one.example', 'Tech\r\nTwo', 'tech@example.com', '', '']) + '\r\n\r\n' + csvRow(['second.example', '', '', '', '']);
  const rows = parse(text);
  assert.deepEqual(rows.map(row => row.line), [4, 7]);
  assert.equal(rows[0].values.business_name, 'Tech\r\nTwo');
  assert.ok(errorKeys(rows[0]).includes('business_name:csv_name_control'));
  assert.equal(rows[1].error, '');
});
check('raw whitespace remains visible while targets and individual contacts are trimmed', () => {
  const row = parse(csv([' example.com ', ' Alice ; Bob ', ' a@example.com ; b@example.com ', '', '']))[0];
  assert.equal(row.values.url, ' example.com ');
  assert.equal(row.values.business_name, ' Alice ; Bob ');
  assert.equal(row.target, 'example.com');
  assert.deepEqual(row.contacts.map(contact => [contact.name, contact.email]), [['Alice', 'a@example.com'], ['Bob', 'b@example.com']]);
  assert.equal(row.error, '');
});
check('optional or reordered columns map to stable five-field values', () => {
  const row = parse('technical_email,url\ntech@example.com,example.com')[0];
  assert.deepEqual(row.values, { url: 'example.com', business_name: '', business_email: '', technical_name: '', technical_email: 'tech@example.com' });
  assert.deepEqual(row.contacts, [{ role: 'technical', name: '', email: 'tech@example.com' }]);
  assert.equal(row.error, '');
});
check('quoted multiline data is parsed exactly even when its contact value is invalid', () => {
  const row = parse(csv(['example.com', 'Line\nBreak', 'a@example.com', '', '']))[0];
  assert.equal(row.values.business_name, 'Line\nBreak');
  assert.equal(row.contacts[0].name, 'Line\nBreak');
  assert.deepEqual(row.invalidFields, ['business_name']);
  assert.equal(row.error, 'csv_name_control');
});
check('fatal malformed quoting reports its physical line and never returns guessed rows', () => {
  assert.throws(() => parse('\nurl\n"unclosed'), /csv_quote_line:3/);
  assert.throws(() => parse('url\n"valid"extra'), /csv_quote_line:2/);
  assert.throws(() => parse('\r\nurl\r\n\r\n"bad\r\nquote"x'), /csv_quote_line:5/);
  assert.throws(() => parse('url\n unquoted"quote'), /csv_quote_line:2/);
});
check('missing, duplicate and unknown headers are rejected globally', () => {
  for (const text of ['url,url\na,b', 'url,misspelled_email\na,b', 'business_email\na@example.com']) assert.throws(() => parse(text), /csv_header/);
  assert.throws(() => parse('url\n\n'), /csv_empty/);
});
check('extra and missing columns have row errors without losing the original extra cells', () => {
  const extra = parse('url,business_email\nexample.com,a@example.com,"EXTRA, CELL"')[0];
  assert.equal(extra.error, 'csv_columns');
  assert.deepEqual(extra.extraValues, ['EXTRA, CELL']);
  assert.deepEqual(extra.invalidFields, headers);
  assert.deepEqual(extra.errors[0], { column: '_row', message: 'csv_columns' });
  const missing = parse('url,business_email\nexample.com')[0];
  assert.equal(missing.values.business_email, '');
  assert.equal(missing.error, 'csv_columns');
  assert.deepEqual(missing.extraValues, []);
  const explicitEmpty = parse(headers.join(',') + '\n,,,,')[0];
  assert.equal(explicitEmpty.line, 2);
  assert.equal(explicitEmpty.error, 'csv_target_error');
});
check('URL validation accepts concrete backend targets and rejects unsafe or malformed targets', () => {
  for (const target of ['example.com', 'localhost:8443', 'https://one.example/path?q=a,b', 'https://[::1]:8443', '2001:db8::1', 'https://example.com./']) assert.equal(parse(csv([target, '', '', '', '']))[0].error, '', target);
  for (const target of ['http://example.com', 'ftp://example.com', 'https://u:p@example.com', '*.example.com', 'https://bad_host.example', 'https://-bad.example', 'https://example.com:0', 'https://example.com:65536', 'example.com/path', 'https://example.com\\evil', 'https://[::1]:', 'https://host\u007f.test']) assert.equal(parse(csv([target, '', '', '', '']))[0].error, 'csv_target_error', target);
});
check('multiple field errors are collected while the compatibility error keeps the first failure', () => {
  const row = parse(csv(['http://bad.example', 'Alice;Bob;Extra', 'bad@-domain;invalid', 'x'.repeat(121), 'tech@bad_domain']))[0];
  assert.equal(row.error, 'csv_target_error');
  for (const key of ['url:csv_target_error', 'business_name:csv_name_count', 'business_email:csv_email_error', 'technical_name:csv_name_length', 'technical_email:csv_email_error']) assert.ok(errorKeys(row).includes(key), key);
  assert.deepEqual(new Set(row.invalidFields), new Set(headers));
  assert.equal(row.errors.filter(error => error.column === 'business_email' && error.message === 'csv_email_error').length, 1);
});
check('email slots and corresponding name order are never shifted past empty addresses', () => {
  const row = parse(csv(['example.com', 'Alice;Bob;Carol', 'a@example.com; ;c@example.com', '', '']))[0];
  assert.equal(row.error, 'csv_empty_email');
  assert.deepEqual(row.contacts.map(contact => [contact.name, contact.email]), [['Alice', 'a@example.com'], ['Bob', ''], ['Carol', 'c@example.com']]);
  for (const emails of [';a@example.com', 'a@example.com;']) assert.equal(parse(csv(['example.com', '', emails, '', '']))[0].error, 'csv_empty_email');
});
check('names are optional but supplied name counts must match their own role emails', () => {
  const unnamed = parse(csv(['example.com', '', 'a@example.com;b@example.com', '', '']))[0];
  assert.equal(unnamed.error, '');
  assert.deepEqual(unnamed.contacts.map(contact => contact.name), ['', '']);
  const partial = parse(csv(['example.com', ';Bob', 'a@example.com;b@example.com', '', '']))[0];
  assert.equal(partial.error, '');
  assert.deepEqual(partial.contacts.map(contact => contact.name), ['', 'Bob']);
  for (const [names, emails] of [['Alice;Extra', 'a@example.com'], ['Alice', 'a@example.com;b@example.com'], ['Alice', '']]) {
    const row = parse(csv(['example.com', names, emails, '', '']))[0];
    assert.equal(row.error, 'csv_name_count');
    assert.ok(row.invalidFields.includes('business_email'));
  }
});
check('email validation follows backend local-part, domain-label and length limits', () => {
  for (const email of ['a@localhost', 'first.last+tag_1%box@example.test', 'a@x', 'a'.repeat(64) + '@example.test']) assert.equal(parse(csv(['example.com', '', email, '', '']))[0].error, '', email);
  for (const email of ['.a@example.test', 'a.@example.test', 'a..b@example.test', 'a!b@example.test', 'a@example..test', 'a@-example.test', 'a@example-.test', 'a@under_score.test', 'a'.repeat(65) + '@example.test', 'a@' + 'x'.repeat(64) + '.test', 'ü@example.test', 'a@example.test.']) assert.equal(parse(csv(['example.com', '', email, '', '']))[0].error, 'csv_email_error', email);
});
check('same-role case-insensitive duplicates are rejected while two different roles are allowed', () => {
  assert.equal(parse(csv(['example.com', '', 'A@example.test;a@EXAMPLE.test', '', '']))[0].error, 'csv_duplicate_email');
  assert.equal(parse(csv(['example.com', '', 'a@example.test', '', 'A@example.test']))[0].error, '');
});
check('name length follows the backend UTF-8 byte limit without changing names', () => {
  for (const name of ['a'.repeat(120), '証'.repeat(40)]) assert.equal(parse(csv(['example.com', name, 'a@example.test', '', '']))[0].error, '');
  for (const name of ['a'.repeat(121), '証'.repeat(41)]) {
    const row = parse(csv(['example.com', name, 'a@example.test', '', '']))[0];
    assert.equal(row.error, 'csv_name_length');
    assert.equal(row.values.business_name, name);
  }
});
check('the 100-contact maximum covers both roles together', () => {
  const business = Array.from({ length: 50 }, (_, i) => `b${i}@example.test`).join(';');
  const technical = Array.from({ length: 50 }, (_, i) => `t${i}@example.test`).join(';');
  const allowed = parse(csv(['example.com', '', business, '', technical]))[0];
  assert.equal(allowed.error, '');
  assert.equal(allowed.contacts.length, 100);
  const tooMany = parse(csv(['example.com', '', business, '', technical + ';extra@example.test']))[0];
  assert.equal(tooMany.error, 'csv_contact_count');
  assert.deepEqual(tooMany.invalidFields, ['business_email', 'technical_email']);
});
check('blank physical lines do not count toward the 100-record maximum', () => {
  const rows = parse('url\n' + Array(100).fill('\nexample.com\n').join(''));
  assert.equal(rows.length, 100);
  assert.equal(rows[99].line, 201);
  assert.throws(() => parse('url\n' + Array(101).fill('example.com').join('\n')), /csv_limit/);
});
check('explicit mapping supports semicolon and quoted multi-contact cells', () => {
  const text='Host;Owner;Email;Extra\r\nexample.com;"Anna;Marco";"a@example.test;b@example.test";ignored';
  const rows=parse(text,{delimiter:';',mapping:['url','business_name','business_email','']});
  assert.equal(rows[0].error,'');assert.deepEqual(rows[0].contacts.map(p=>p.name),['Anna','Marco']);
  assert.deepEqual(parse(text,{delimiter:';',headersOnly:true}),['Host','Owner','Email','Extra']);
});
check('mapped duplicate targets remain invalid while explicit ignored columns are allowed', () => {
  assert.throws(()=>parse('Host,Other\na,b',{mapping:['url','url']}),/csv_header/);
  assert.equal(parse('Host,Ignored\nexample.com,a',{mapping:['url','']})[0].target,'example.com');
  assert.throws(()=>parse('Host,Ignored\nexample.com,a',{mapping:['','']}),/csv_header/);
});
check('tab-delimited imports preserve original physical lines', () => {
  const row=parse('\nHost\tEmail\r\nexample.com\ta@example.test',{delimiter:'\t',mapping:['url','technical_email']})[0];
  assert.equal(row.line,3);assert.equal(row.contacts[0].role,'technical');assert.equal(row.error,'');
});
check('persisted batch outcomes match original physical lines despite URL normalization', () => {
  const marker="    window.addEventListener('certificate-batch-update'";const start=source.indexOf(marker);assert.ok(start>0);const end=source.indexOf('\n',start);
  let handler;const row={line:2,target:'EXAMPLE.test/path'};let rendered=0;
  const runtime=new Function('window','row','renderInventory',`let inventoryBatchId=23,inventoryBatchData=null;const inventoryRows=[row];${source.slice(start,end)}`);
  runtime({addEventListener:(event,callback)=>{handler=callback;}},row,()=>rendered++);
  const plan={certificate:{fingerprint:'abc'}};
  handler({detail:{id:23,rows:[{id:91,line:2,target:'https://example.test:443',status:'imported',plan,error:''}]}});
  assert.equal(row.imported,true);assert.equal(row.batchRowId,91);assert.equal(row.plan,plan);assert.equal(rendered,1);
  handler({detail:{id:24,rows:[{line:2,error:'unrelated'}]}});assert.equal(row.error,'');assert.equal(rendered,1);
});
console.log(`CSV inventory parser: ${checks} checks passed.`);

// Exercise the actual file/input handlers and button renderer with controlled File.text promises.
class InventoryNode {
  constructor() { this.children = []; this.parent = null; this.value = ''; this.textContent = ''; this.disabled = false; this.hidden = false; }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this[name] = value; }
  addEventListener() {}
  insertBefore(node, reference) {
    const index = reference ? this.children.indexOf(reference) : -1;
    node.parent = this;
    if (index < 0) this.children.push(node); else this.children.splice(index, 0, node);
  }
  get nextSibling() { return this.parent ? this.parent.children[this.parent.children.indexOf(this) + 1] || null : null; }
}
function inventoryRuntime() {
  const ids = new Map();
  const handlers = new Map();
  const byId = id => { if (!ids.has(id)) ids.set(id, new InventoryNode()); return ids.get(id); };
  const on = (id, event, handler) => handlers.set(`${id}:${event}`, handler);
  const element = (tag, className, text) => { const node = new InventoryNode(); node.tag = tag; node.className = className || ''; node.textContent = text === undefined ? '' : text; return node; };
  const renderStart = source.indexOf('  function renderInventory(');
  const jobsStart = source.indexOf('  function jobStatusLabel(', renderStart);
  const inputStart = source.indexOf("  on('inventory-text', 'input'");
  const inputEnd = source.indexOf("  on('preview-chain-files'", inputStart);
  const fileStart = source.indexOf("  on('inventory-file', 'change'");
  const fileEnd = source.indexOf("  window.addEventListener('beforeunload'", fileStart);
  assert.ok(renderStart >= 0 && jobsStart > renderStart && inputStart >= 0 && inputEnd > inputStart && fileStart >= 0 && fileEnd > fileStart);
  const create = new Function('on', 'byId', 'element', 'flow', 'parseInventoryCSV', `
    let inventoryRows = [], inventoryRunning = false, inventoryStopped = false;
    let inventoryReadGeneration = 0, inventoryReading = false, uploading = false;
    let inventoryMapping=null, inventoryDelimiter=',', inventoryBatchId=null, inventoryBatchData=null;
    const window={};
    const action=(label,handler)=>element('button','',label);
    let requests = 0;
    const request = async () => { requests++; return { token: 'mock-token' }; };
    const refresh = async () => true;
    const msg = key => key, name = cert => cert.common_name || '', date = value => String(value);
    const addDetail = () => {};
    ${source.slice(renderStart, jobsStart)}
    ${source.slice(inputStart, inputEnd)}
    ${source.slice(fileStart, fileEnd)}
    return {
      preview: previewInventory, run: runInventory,
      seed(rows) { inventoryRows = rows; inventoryBatchId=1;inventoryBatchData={status:'review',rows:[{status:'ready'}]};renderInventory(); },
      current() { return { rows: inventoryRows, reading: inventoryReading, requests }; }
    };
  `);
  const runtime = create(on, byId, element, (key, values = []) => `${key}${values.length ? ':' + values.join(',') : ''}`, parse);
  return { ...runtime, byId, emit: (id, event, value = {}) => handlers.get(`${id}:${event}`)(value) };
}
function deferredFile(name) {
  let resolve, reject;
  const pending = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { file: { name, size: 100, text: () => pending }, resolve, reject };
}
function selectFile(runtime, file) {
  const input = runtime.byId('inventory-file');
  input.value = file ? file.name : '';
  return runtime.emit('inventory-file', 'change', { target: { files: file ? [file] : [] } });
}
async function asyncCheck(name, run) { await run(); console.log(`ok ${++checks} - ${name}`); }

(async () => {
  await asyncCheck('selecting an oversized file immediately invalidates previously verified rows', async () => {
    const runtime = inventoryRuntime();
    const old = parse('url\nold.example'); old[0].result = { token: 'old-token' };
    runtime.seed(old);
    runtime.byId('inventory-text').value = 'url\nold.example';
    assert.equal(runtime.byId('inventory-import').disabled, false);
    await selectFile(runtime, { name: 'large.csv', size: 1024 * 1024 + 1, text: () => { throw new Error('must not read oversized file'); } });
    assert.deepEqual(runtime.current().rows, []);
    assert.equal(runtime.byId('inventory-text').value, '');
    assert.equal(runtime.byId('inventory-file').value, '');
    assert.equal(runtime.byId('inventory-feedback').textContent, 'csv_size');
    assert.equal(runtime.byId('inventory-import').disabled, true);
    assert.equal(runtime.byId('inventory-check').disabled, true);
  });
  await asyncCheck('pending reads block validation and network work while keeping text and file selection editable', async () => {
    const runtime = inventoryRuntime(); const pending = deferredFile('pending.csv');
    const operation = selectFile(runtime, pending.file);
    assert.equal(runtime.current().reading, true);
    for (const id of ['inventory-preview', 'inventory-check', 'inventory-import']) assert.equal(runtime.byId(id).disabled, true, id);
    for (const id of ['inventory-text', 'inventory-file']) assert.equal(runtime.byId(id).disabled, false, id);
    runtime.byId('inventory-text').value = 'url\nnot-yet-validated.example';
    runtime.preview();
    assert.equal(runtime.current().rows.length, 0);
    // Even a programmatically supplied old result cannot bypass the read guard.
    const old = parse('url\nold.example'); old[0].result = { token: 'old-token' }; runtime.seed(old);
    await runtime.run(false); await runtime.run(true);
    assert.equal(runtime.current().requests, 0);
    pending.resolve('url\ncurrent.example'); await operation;
    assert.equal(runtime.current().rows[0].target, 'current.example');
    assert.equal(runtime.current().reading, false);
  });
  await asyncCheck('newer file selection wins even if an older read resolves later', async () => {
    const runtime = inventoryRuntime(); const first = deferredFile('first.csv'); const second = deferredFile('second.csv');
    const firstRead = selectFile(runtime, first.file); const secondRead = selectFile(runtime, second.file);
    second.resolve('url\nsecond.example'); await secondRead;
    first.resolve('url\nfirst.example'); await firstRead;
    assert.equal(runtime.byId('inventory-text').value, 'url\nsecond.example');
    assert.equal(runtime.current().rows[0].target, 'second.example');
    assert.equal(runtime.byId('inventory-file').value, 'second.csv');
    assert.equal(runtime.current().reading, false);
  });
  await asyncCheck('a stale read cannot unlock buttons or replace a newer pending read', async () => {
    const runtime = inventoryRuntime(); const first = deferredFile('first.csv'); const second = deferredFile('second.csv');
    const firstRead = selectFile(runtime, first.file); const secondRead = selectFile(runtime, second.file);
    first.resolve('url\nfirst.example'); await firstRead;
    assert.equal(runtime.current().reading, true);
    assert.equal(runtime.current().rows.length, 0);
    assert.equal(runtime.byId('inventory-preview').disabled, true);
    second.resolve('url\nsecond.example'); await secondRead;
    assert.equal(runtime.current().rows[0].target, 'second.example');
  });
  await asyncCheck('editing the CSV cancels a pending file read and removes its filename association', async () => {
    const runtime = inventoryRuntime(); const pending = deferredFile('pending.csv'); const operation = selectFile(runtime, pending.file);
    runtime.byId('inventory-text').value = 'url\nmanual.example';
    runtime.emit('inventory-text', 'input');
    assert.equal(runtime.current().reading, false);
    assert.equal(runtime.byId('inventory-file').value, '');
    runtime.preview();
    assert.equal(runtime.current().rows[0].target, 'manual.example');
    pending.resolve('url\nobsolete.example'); await operation;
    assert.equal(runtime.byId('inventory-text').value, 'url\nmanual.example');
    assert.equal(runtime.current().rows[0].target, 'manual.example');
  });
  await asyncCheck('a read failure clears stale rows and filename and shows a localized error', async () => {
    const runtime = inventoryRuntime(); const old = parse('url\nold.example'); old[0].result = { token: 'old-token' }; runtime.seed(old);
    const pending = deferredFile('unreadable.csv'); const operation = selectFile(runtime, pending.file);
    pending.reject(new Error('untrusted file-system diagnostic')); await operation;
    assert.equal(runtime.current().reading, false);
    assert.equal(runtime.current().rows.length, 0);
    assert.equal(runtime.byId('inventory-file').value, '');
    assert.equal(runtime.byId('inventory-text').value, '');
    assert.equal(runtime.byId('inventory-feedback').textContent, 'csv_read_error');
    assert.equal(runtime.byId('inventory-import').disabled, true);
  });
  await asyncCheck('obsolete failures cannot erase a newer successfully loaded CSV', async () => {
    const runtime = inventoryRuntime(); const first = deferredFile('first.csv'); const second = deferredFile('second.csv');
    const firstRead = selectFile(runtime, first.file); const secondRead = selectFile(runtime, second.file);
    second.resolve('url\nsecond.example'); await secondRead;
    first.reject(new Error('stale read failure')); await firstRead;
    assert.equal(runtime.current().rows[0].target, 'second.example');
    assert.equal(runtime.byId('inventory-file').value, 'second.csv');
    assert.notEqual(runtime.byId('inventory-feedback').textContent, 'csv_read_error');
  });
  await asyncCheck('rejecting a new oversized selection also invalidates an older pending read', async () => {
    const runtime = inventoryRuntime(); const first = deferredFile('first.csv'); const firstRead = selectFile(runtime, first.file);
    await selectFile(runtime, { name: 'oversized.csv', size: 2 * 1024 * 1024 });
    first.resolve('url\nobsolete.example'); await firstRead;
    assert.equal(runtime.current().rows.length, 0);
    assert.equal(runtime.byId('inventory-text').value, '');
    assert.equal(runtime.byId('inventory-feedback').textContent, 'csv_size');
    assert.equal(runtime.current().reading, false);
  });
  console.log(`CSV parser and file handlers: ${checks} checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
