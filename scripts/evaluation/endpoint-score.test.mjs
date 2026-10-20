import assert from 'node:assert/strict';
import { test } from 'node:test';
import { routePath, scoreRoutes, scoreParameters, inventoryDigest, systematicSample } from './endpoint-score.mjs';

const endpoint = (path, extra = {}) => ({ method: 'GET', path, parameters: [], sources: [], ...extra });
test('retains mount prefixes, parameter names, methods and trailing slash distinctions', () => {
  const reference = { method: 'GET', path: '/api/users/:id' };
  for (const wrong of [endpoint('/users/:id'), endpoint('/api/users/:other'), endpoint('/api/users/:id/'), endpoint('/api/users/:id', { method: 'POST' })]) {
    assert.equal(scoreRoutes([wrong], [reference])[0].matched, false);
  }
  assert.equal(scoreRoutes([endpoint('/api/users/{id}')], [reference])[0].matched, true);
  assert.equal(routePath('/<int:id>/update'), '/:id/update');
});
test('does not credit a parameter from the wrong route, method, name or location', () => {
  const reference = { method: 'POST', path: '/login', name: 'password', location: 'body' };
  const target = endpoint('/login', { method: 'POST', parameters: [{ name: 'password', location: 'json' }] });
  assert.equal(scoreParameters([target], [reference])[0].matched, true);
  for (const wrong of [{ ...target, path: '/other' }, { ...target, method: 'GET' },
    { ...target, parameters: [{ name: 'password', location: 'query' }] }, { ...target, parameters: [{ name: 'email', location: 'json' }] }]) {
    assert.equal(scoreParameters([wrong], [reference])[0].matched, false);
  }
});
test('inventory fingerprint ignores output order but detects changed parameters and sources', () => {
  const first = endpoint('/a'), second = endpoint('/b', { sources: [{ file: 'app.js', line: 2 }] });
  assert.equal(inventoryDigest([first, second]), inventoryDigest([second, first]));
  assert.notEqual(inventoryDigest([first, second]), inventoryDigest([first, { ...second, sources: [{ file: 'app.js', line: 3 }] }]));
  assert.notEqual(inventoryDigest([first]), inventoryDigest([{ ...first, parameters: [{ name: 'q', location: 'query' }] }]));
});
test('audit sampling is deterministic, spreads across sorted output and does not duplicate pairs', () => {
  const data = Array.from({ length: 20 }, (_, index) => endpoint('/' + String(index).padStart(2, '0')));
  assert.deepEqual(systematicSample([...data].reverse()).map(item => item.path), ['/00', '/04', '/09', '/14', '/19']);
  assert.equal(systematicSample([data[0], data[0]]).length, 1);
});
