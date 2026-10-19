#!/usr/bin/env node
// Protocol fixture, not a scanner. Exercises the real child process and HTTP boundaries.
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
const args = process.argv.slice(2);
let url, method = 'GET', body;
if (args.includes('-autorun')) {
  const plan = JSON.parse(await readFile(args[args.indexOf('-autorun') + 1], 'utf8'));
  ({ url, method, data: body } = plan.jobs.find(job => job.type === 'requestor').requests[0]);
} else if (args.includes('-r')) {
  const text = await readFile(args[args.indexOf('-r') + 1], 'utf8');
  const [first] = text.split('\r\n'), [verb, path] = first.split(' ');
  method = verb; url = `http://${text.match(/Host: ([^\r\n]+)/)[1]}${path}`;
  body = text.split('\r\n\r\n')[1] || undefined;
} else {
  url = (await readFile(args.includes('-l') ? args[args.indexOf('-l') + 1] : args[3], 'utf8')).trim();
}
const received = await fetch(url, { method, ...(body !== undefined ? { body } : {}) });
await received.text();
if (args.includes('-autorun')) {
  await writeFile(join(process.cwd(), 'zap-report.json'), JSON.stringify({ site: [{ alerts: [{ pluginid: '10011',
    riskcode: '1', confidence: '2', cweid: '1004', instances: [{ uri: url, evidence: 'PRIVATE_SESSION' }] }] }] }));
} else if (args.includes('-r')) {
  process.stdout.write('[INFO] testing connection to the target URL\n[WARNING] all tested parameters do not appear to be injectable\n');
} else if (args[0] === 'scan') {
  process.stdout.write(JSON.stringify({ meta: { incomplete: false }, findings: [] }));
} else {
  process.stdout.write(JSON.stringify({ 'template-id': 'fixture', type: 'http', 'matched-at': url,
    info: { severity: 'info' }, request: 'PRIVATE_REQUEST', response: 'PRIVATE_BODY' }));
}
