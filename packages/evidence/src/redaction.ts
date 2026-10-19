import type { JsonValue } from '@agento/core';
import { EvidenceError } from './contracts.js';
import { jsonCopy, object } from './value.js';

export const REDACTED = '[REDACTED]';
const compact = (key: string) => key.toLowerCase().replace(/[^a-z0-9]/g, '');
const sensitive = (key: string) => /^(?:password|passwd|pwd|passphrase|secret|sessionsecret|clientsecret|privatekey|apikey|xapikey|authorization|proxyauthorization|credential|credentials|accesstoken|refreshtoken|idtoken|csrftoken|xcsrftoken|xsrftoken|token|sessionref|sessioncookie|sessionkey|sessiontoken|sessionidvalue|jwt|bearer)$/.test(compact(key))
  || /(?:password|passwd|privatekey|apikey|authtoken|accesstoken|refreshtoken|securitytoken|sessionsecret|clientsecret|secretkey|secretaccesskey|signingkey|encryptionkey|cookievalue|tokenvalue)$/.test(compact(key));
const opaque = (key: string) => /^(?:raw|rawoutput|rawbody|stdout|stderr|data|base64|image|imagedata|pixels|html|dom|domsnapshot|console|consolelogs|logs|requestbody|responsebody)$/.test(compact(key));
const browserContainer = (key: string) => /^(?:dom|domsnapshot|console|consolelogs|logs)$/.test(compact(key));

/** Redaction precedes hashing and all writes. Arbitrary private values must also be supplied by the host. */
export class Redactor {
  readonly #secrets: readonly string[];
  constructor(secrets: readonly string[] = []) {
    if (!Array.isArray(secrets) || secrets.length > 1000 || secrets.some(value => typeof value !== 'string' || !value || value.length > 16_384)) {
      throw new EvidenceError('invalid-options');
    }
    this.#secrets = [...new Set(secrets.flatMap(value => [value, encodeURIComponent(value),
      Buffer.from(value).toString('base64'), Buffer.from(value).toString('base64url')]))].sort((a, b) => b.length - a.length);
  }
  text(input: string): string {
    let output = input;
    for (const secret of this.#secrets) output = output.split(secret).join(REDACTED);
    output = output.replace(/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g, REDACTED)
      .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.~-]+/gi, REDACTED)
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, REDACTED)
      .replace(/\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b/g, REDACTED)
      .replace(/\b((?:password|passwd|pwd|passphrase|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|session[_-]?secret|secret|token)\s*["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&<>]+)/gi, `$1${REDACTED}`)
      .replace(/https?:\/\/[^\s<>"']+/gi, value => this.url(value));
    return output;
  }
  url(input: string): string {
    try {
      const url = new URL(input);
      if (!['http:', 'https:'].includes(url.protocol)) return REDACTED;
      const changed = !!(url.username || url.password || url.hash || url.search);
      url.username = ''; url.password = ''; url.hash = '';
      for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, REDACTED);
      // Apply host secrets to paths, names, and origin labels without recursing through URL matching.
      let output = changed ? url.href : input;
      for (const secret of this.#secrets) output = output.split(secret).join(REDACTED);
      return output;
    } catch { return REDACTED; }
  }
  json(value: JsonValue, key = '', parent?: Readonly<Record<string, JsonValue>>, browser = false): JsonValue {
    browser ||= browserContainer(key);
    if (sensitive(key)) return REDACTED;
    if (key === 'value' && parent && (parent.httpOnly !== undefined || parent.secure !== undefined
      || typeof parent.name === 'string' && sensitive(parent.name)
      || parent.type === 'password' || parent.inputType === 'password')) return REDACTED;
    if (compact(key) === 'cookie' && !object(value)) return REDACTED;
    if (compact(key) === 'setcookie') {
      // Raw Set-Cookie can contain quoted, malformed or nonstandard secret-bearing attributes.
      // Keep parsed flags in normalized cookie observations instead.
      if (Array.isArray(value)) return value.map(() => REDACTED);
      return REDACTED;
    }
    if (browser && typeof value === 'string' && /^(?:value|text|textcontent|innertext|message|html|innerhtml|outerhtml|dom|domsnapshot|console|consolelogs|logs)$/.test(compact(key))) return REDACTED;
    if (opaque(key) && !(browserContainer(key) && typeof value === 'object' && value !== null)) {
      // Keep hash/length-only body records. Opaque payloads have no safe generic decoder.
      return REDACTED;
    }
    if (typeof value === 'string') {
      if (compact(key) === 'body') {
        try { return this.json(jsonCopy(JSON.parse(value))); } catch { return REDACTED; }
      }
      if (/(?:url|uri)$/i.test(key)) {
        if (/^https?:\/\//i.test(value)) return this.url(value);
        if (value.startsWith('/')) {
          return this.url(new URL(value, 'http://evidence.invalid').href).replace('http://evidence.invalid', '');
        }
      }
      return this.text(value);
    }
    if (Array.isArray(value)) return value.map(item => this.json(item, key, undefined, browser));
    if (object(value)) {
      const output: Record<string, JsonValue> = Object.create(null);
      for (const [name, item] of Object.entries(value)) {
        const safe = this.text(name);
        if (Object.hasOwn(output, safe)) throw new EvidenceError('invalid-evidence');
        output[safe] = this.json(item, name, value, browser);
      }
      return output;
    }
    return value;
  }
}
