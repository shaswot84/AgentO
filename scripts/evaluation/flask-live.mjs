import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { TesterArmyE2EAdapter, FormLoginStrategy } from '../../plugins/tools/e2e-browser/dist/index.js';
import { AuthorizationProbe, CookieSecurityProbe, CrossOriginProbe, CapabilityRegistry,
  DeterministicRequestExecutor, NormalizedResponseCollector, NormalizedResponseComparator,
  NormalizedCookieAnalyzer, NormalizedHeaderAnalyzer, RuntimeAuthenticationManager,
  SessionCookieInspector, WorkflowBrowserController } from '../../packages/runtime/dist/index.js';
import { CWE639Plugin, CWE1004Plugin, CWE942Plugin, toCoreEvidence } from '../../plugins/cwe/dist/index.js';
import { MemoryEvidenceStore } from '../../packages/evidence/dist/index.js';

const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== '--repo' || args[2] !== '--python' || args[4] !== '--output') {
  throw new Error('Usage: node scripts/evaluation/flask-live.mjs --repo /path/to/flask --python /venv/bin/python --output /new/result.json');
}
const repository = resolve(args[1]), output = resolve(args[5]);
const git = (...values) => execFileSync('git', ['-C', repository, ...values], { encoding: 'utf8' }).trim();
const expected = JSON.parse(await readFile(new URL('./realworld-cases.json', import.meta.url), 'utf8')).cases.find(item => item.id === 'flask');
assert.equal(git('rev-parse', 'HEAD'), expected.revision);
assert.equal(git('status', '--porcelain', '--untracked-files=all'), '');
await writeFile(output, '', { flag: 'wx', mode: 0o600 });
const directory = await mkdtemp(join(tmpdir(), 'agento-flask-live-'));
// Use an unchanged source copy and fresh SQLite data. No upstream server or database is used.
const python = `
import importlib.metadata, json, pathlib, secrets, shutil, sys
checkout, work = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
source = work / 'tutorial'
shutil.copytree(checkout / 'examples' / 'tutorial', source)
sys.path.insert(0, str(source))
from flaskr import create_app
from flaskr.db import init_db, get_db
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server
passwords = {name: secrets.token_urlsafe(24) for name in ('alice', 'bob')}
marker = secrets.token_hex(24)
app = create_app({'DATABASE': str(work / 'flaskr.sqlite'), 'SECRET_KEY': secrets.token_hex(32)})
with app.app_context():
    init_db()
    db = get_db()
    for name, password in passwords.items():
        db.execute('INSERT INTO user (username, password) VALUES (?, ?)', (name, generate_password_hash(password)))
    db.execute('INSERT INTO post (title, body, author_id) VALUES (?, ?, ?)', ('AgentO compatibility post', marker, 1))
    db.commit()
server = make_server('127.0.0.1', 0, app)
(work / 'ready.json').write_text(json.dumps({'origin': 'http://127.0.0.1:' + str(server.server_port), 'passwords': passwords, 'marker': marker, 'flaskVersion': importlib.metadata.version('flask')}))
server.serve_forever()
`;
const server = spawn(resolve(args[3]), ['-u', '-c', python, repository, directory], { stdio: 'ignore' });
let serverError;
server.on('error', error => { serverError = error; });
let manager, report, stage = 'server-start';
try {
  let ready;
  for (let attempt = 0; attempt < 150; attempt++) {
    if (serverError || server.exitCode !== null) throw new Error('server-start-failed');
    try { ready = JSON.parse(await readFile(join(directory, 'ready.json'), 'utf8')); break; }
    catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  if (!ready) throw new Error('server-start-timeout');
  const identities = ['alice', 'bob'].map(id => ({ id, label: id, roles: ['author'], authentication: 'session-cookie' }));
  const anonymous = { id: 'anonymous', label: 'Anonymous', roles: [], authentication: 'anonymous' };
  const project = { id: 'flask-live', name: 'Upstream Flask tutorial', mode: 'black-box', repositoryPath: join(repository, 'examples/tutorial'),
    languages: ['python'], baseUrl: ready.origin, allowedOrigins: [ready.origin] };
  const context = { project, identities: [...identities, anonymous], components: [], endpoints: [], resources: [], signals: [], evidence: [] };
  const target = { id: 'upstream-flask', baseOrigins: [ready.origin], personas: context.identities,
    authentication: [new FormLoginStrategy({ loginUrl: '/auth/login', usernameSelector: '#username', passwordSelector: '#password',
      submitSelector: 'input[type=submit]', response: { url: '/auth/login', method: 'POST', status: 302 }, successUrl: '/',
      verification: persona => ({ url: '/', identitySelector: 'nav ul li span', expectedIdentity: persona.id }) }, 'flask-form')],
    defaultAuthenticationStrategyId: 'flask-form' };
  const adapter = new TesterArmyE2EAdapter({ target, credentials: async persona => ({ username: persona.id, password: ready.passwords[persona.id] }),
    resolveGoal: () => [{ action: 'navigate', url: '/auth/login' }, { action: 'wait-visible', selector: '#username' }] });
  const executor = new DeterministicRequestExecutor({ baseUrl: ready.origin, allowedOrigins: [ready.origin] });
  const collector = new NormalizedResponseCollector();
  stage = 'http';
  const responses = [];
  for (const [path, expectedStatus] of [['/', 200], ['/auth/login', 200], ['/create', 302]]) {
    const response = await executor.execute({ url: path });
    assert.equal(response.status, expectedStatus);
    responses.push(collector.evidence(response));
  }
  await assert.rejects(executor.execute({ url: 'http://127.0.0.1:1/outside' }), { code: 'scope-denied' });
  stage = 'anonymous-browser';
  const observation = await adapter.observe(context, { id: 'flask-login-form', identityId: 'anonymous', goal: 'inspect login form' });
  assert.equal(observation.outcome, 'COMPLETED');
  assert.equal(observation.diagnostics.length, 0);
  const browser = new WorkflowBrowserController({ driver: adapter, context });
  manager = new RuntimeAuthenticationManager({ browser, identities, http: { baseUrl: ready.origin, allowedOrigins: [ready.origin] } });
  const capabilities = new CapabilityRegistry().register('request-executor', executor).register('response-collector', collector)
    .register('response-comparator', new NormalizedResponseComparator()).register('authentication-manager', manager)
    .register('cookie-analyzer', new NormalizedCookieAnalyzer()).register('cookie-inspector', new SessionCookieInspector())
    .register('header-analyzer', new NormalizedHeaderAnalyzer());
  const common = { project, capabilities };
  stage = 'authorization';
  const access = await new AuthorizationProbe().execute({ ...common, owner: identities[0], attacker: identities[1],
    resource: { id: 'seeded-post-1', ownerIdentityId: 'alice', request: { url: '/1/update' }, ownerMarkers: [ready.marker] } });
  assert.deepEqual([access.owner.status, access.attacker.status, access.anonymous.status], [200, 403, 302]);
  assert.equal(access.attackerComparison.ownerMarkersMatch, false);
  const accessVerdict = await new CWE639Plugin().evaluate([access], { projectId: project.id, targetUrl: `${ready.origin}/1/update`, method: 'GET',
    identityIds: ['alice', 'bob'], authorization: { resourceId: 'seeded-post-1', ownerIdentityId: 'alice', attackerIdentityId: 'bob',
      attackerIsUnauthorized: true, anonymousIsUnauthorized: true } });
  assert.equal(accessVerdict.status, 'REJECTED');
  stage = 'cookies';
  const cookies = await new CookieSecurityProbe().execute({ ...common, request: { url: '/' }, identities: [identities[0]] });
  assert(cookies.observations.some(item => item.cookies.some(cookie => cookie.name === 'session' && cookie.httpOnly)));
  const cookieVerdict = await new CWE1004Plugin().evaluate([cookies], { projectId: project.id, targetUrl: ready.origin + '/', method: 'GET',
    identityIds: ['alice'], sensitiveCookieNames: ['session'] });
  assert.equal(cookieVerdict.status, 'REJECTED');
  stage = 'cors';
  const cors = await new CrossOriginProbe().execute({ ...common, request: { url: '/' }, origins: ['https://unapproved.invalid'] });
  const corsVerdict = await new CWE942Plugin().evaluate([cors], { projectId: project.id, targetUrl: ready.origin + '/', method: 'GET',
    untrustedOrigins: ['https://unapproved.invalid'] });
  assert.equal(corsVerdict.status, 'REJECTED');
  stage = 'evidence-retention';
  const store = new MemoryEvidenceStore({ secrets: [...Object.values(ready.passwords), ready.marker] });
  store.capture(observation.evidence, { project, capabilityIds: ['browser-controller'] });
  for (const probe of [access, cookies, cors]) store.capture([toCoreEvidence(probe)], { project, capabilityIds: ['probe:' + probe.probeId], probeId: probe.probeId });
  report = { schemaVersion: 1, generatedAt: new Date().toISOString(), repository: expected.repository, revision: expected.revision,
    flaskVersion: ready.flaskVersion, nodeVersion: process.version, status: 'completed', scope: 'standalone-black-box-primitives-and-rules',
    sourcePipelineUsed: false, verificationJudgeUsed: false, modelCalls: 0,
    checks: { httpStatus: [200, 200, 302], explicitScopeEscapeDenied: true, anonymousBrowser: observation.outcome,
      isolatedAuthorizationStatus: { owner: access.owner.status, secondUser: access.attacker.status, anonymous: access.anonymous.status },
      ownerMarkerDisclosedToSecondUser: access.attackerComparison.ownerMarkersMatch, cookieHttpOnly: true,
      ruleVerdicts: [accessVerdict, cookieVerdict, corsVerdict], secureCookieAssessed: false }, httpResponses: responses, evidence: store.list() };
  const publicText = JSON.stringify(report);
  assert([...Object.values(ready.passwords), ready.marker].every(secret => !publicText.includes(secret)));
  store.close();
  assert.equal(git('status', '--porcelain', '--untracked-files=all'), '');
} catch (error) {
  report = { schemaVersion: 1, status: 'failed', stage, code: error.code ?? error.name, repository: expected.repository, revision: expected.revision };
  process.exitCode = 1;
} finally {
  await manager?.close();
  if (server.exitCode === null && !serverError) { const stopped = once(server, 'exit'); server.kill('SIGTERM'); await stopped; }
  await rm(directory, { recursive: true, force: true });
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
}
console.log(JSON.stringify({ status: report.status, stage: report.stage, checks: report.checks }));
