import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

/** Small, dependency-free SPA fixture with signed JWTs in localStorage and bearer requests. */
export function createPurchasesFixture({ forbiddenOrigin = 'http://127.0.0.1:1' } = {}) {
  const key = randomBytes(32);
  const accounts = [
    { id: 'buyer-one', handle: 'buyer.one', passphrase: 'BuyerOne!42', role: 'buyer', purchase: 'BUY-302' },
    { id: 'buyer-two', handle: 'buyer.two', passphrase: 'BuyerTwo!42', role: 'buyer', purchase: 'BUY-711' },
    { id: 'manager', handle: 'purchase.manager', passphrase: 'Manager!42', role: 'manager', purchase: 'MGR-900' },
  ];
  const counters = { logins: 0, requests: [] };
  const sign = payload => {
    const message = `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    return `${message}.${createHmac('sha256', key).update(message).digest('base64url')}`;
  };
  const identify = request => {
    try {
      const token = request.headers.authorization?.replace(/^Bearer /, '');
      const [header, payload, signature] = token.split('.');
      const expected = createHmac('sha256', key).update(`${header}.${payload}`).digest();
      const actual = Buffer.from(signature, 'base64url');
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return undefined;
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
      if (decoded.exp < Date.now() / 1000) return undefined;
      return accounts.find(account => account.id === decoded.sub);
    } catch { return undefined; }
  };
  const server = createServer(async (request, response) => {
    const path = new URL(request.url, 'http://fixture').pathname;
    counters.requests.push({ path, method: request.method });
    const json = (value, status = 200) => {
      response.writeHead(status, { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' });
      response.end(JSON.stringify(value));
    };
    if (path === '/api/v1/session' && request.method === 'POST') {
      let body = '';
      for await (const chunk of request) { body += chunk; if (body.length > 4096) { json({}, 413); return; } }
      let input;
      try { input = JSON.parse(body); } catch { json({}, 400); return; }
      const account = accounts.find(entry => entry.handle === input.handle && entry.passphrase === input.passphrase);
      if (!account) { json({}, 401); return; }
      counters.logins++;
      json({ token: sign({ sub: account.id, exp: Math.floor(Date.now() / 1000) + 3600 }) }); return;
    }
    if (path.startsWith('/api/')) {
      const account = identify(request);
      if (!account) { json({}, 401); return; }
      if (path === '/api/v1/whoami') { json({ persona: account.id, role: account.role }); return; }
      if (path === '/api/v1/purchases') { json({ entries: [{ purchaseId: account.purchase }] }); return; }
      if (path === `/api/v1/purchases/${account.purchase}`) { json({ purchaseId: account.purchase }); return; }
      json({}, 404); return;
    }
    if (path === '/escape/redirect') { response.writeHead(302, { location: `${forbiddenOrigin}/purchase-escape` }); response.end(); return; }
    if (path === '/escape/chain') { response.writeHead(302, { location: '/escape/redirect' }); response.end(); return; }
    if (path.startsWith('/escape/')) {
      const scripts = {
        fetch: `fetch(${JSON.stringify(forbiddenOrigin + '/purchase-fetch')}).catch(() => {}).finally(done)`,
        popup: `window.open('/escape/chain'); setTimeout(done, 250)`,
        frame: `const f = document.createElement('iframe'); f.src = '/escape/chain'; document.body.append(f); setTimeout(done, 250)`,
        worker: `const w = new Worker('/worker.js'); setTimeout(done, 250)`,
        'service-worker': `navigator.serviceWorker.register('/sw.js').catch(() => {}).finally(done)`,
        websocket: `const w = new WebSocket(${JSON.stringify(forbiddenOrigin.replace('http:', 'ws:') + '/purchase-socket')}); w.onerror = done; setTimeout(done, 250)`,
      };
      response.end(`<body><script>const done = () => document.body.dataset.done = 'true'; ${scripts[path.slice(8)] ?? ''}</script></body>`); return;
    }
    if (path === '/worker.js' || path === '/sw.js') { response.setHeader('content-type', 'text/javascript'); response.end(`fetch(${JSON.stringify(forbiddenOrigin + '/worker-escape')})`); return; }
    response.setHeader('content-type', 'text/html');
    if (path === '/sign-in') {
      response.end(`<!doctype html><main><h1>Purchase Hub</h1><form data-auth>
        <label>Handle<input name="handle" autocomplete="username"></label>
        <label>Passphrase<input name="passphrase" type="password" autocomplete="current-password"></label>
        <button>Sign in</button></form></main><script>
        document.querySelector('form').onsubmit = async e => { e.preventDefault();
          const r = await fetch('/api/v1/session', { method: 'POST', headers: {'content-type':'application/json'},
            body: JSON.stringify({handle:e.target.handle.value,passphrase:e.target.passphrase.value}) });
          if (r.ok) {localStorage.setItem('purchase-session', (await r.json()).token); location.href='/workspace';}
        };</script>`); return;
    }
    response.end(`<!doctype html><main><h1>Purchase Hub</h1><header><span data-account></span><span data-role></span></header>
      <a href="/purchases">My purchases</a><section data-entries></section><section data-detail></section></main><script>
      const api = path => fetch(path, {headers: {Authorization:'Bearer '+localStorage.getItem('purchase-session')}});
      const ready = api('/api/v1/whoami').then(async r => {
        if (!r.ok) { location.href='/sign-in'; return; }
        const account = await r.json(); document.querySelector('[data-account]').textContent=account.persona;
        document.querySelector('[data-role]').textContent=account.role;
      });
      if (location.pathname==='/purchases') ready.then(async () => {
        const list = await (await api('/api/v1/purchases')).json();
        const button = document.createElement('button'); button.textContent='Open latest purchase';
        button.onclick = async () => {const item = await (await api('/api/v1/purchases/'+list.entries[0].purchaseId)).json();
          const done = document.createElement('button'); done.disabled=true; done.textContent='Purchase opened';
          document.querySelector('[data-detail]').replaceChildren(done); document.querySelector('[data-detail]').dataset.purchase=item.purchaseId;
        }; document.querySelector('[data-entries]').append(button);
      });</script>`);
  });
  return { server, counters };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server } = createPurchasesFixture();
  server.listen(3100, '127.0.0.1', () => process.stdout.write('Purchase fixture: http://127.0.0.1:3100\n'));
}
