/* Typed display helpers only: never mutate canonical IDs or evidence. */
(() => {
  'use strict';
  const element = document.getElementById('ton-display-map');
  let mapping = {};
  try { mapping = JSON.parse(element?.textContent || '{}'); } catch (_) { /* no invented fallback */ }
  const plain = value => String(value ?? '').replace(/^(?:wallet:ton:|ton:)/, '');
  function address(value) {
    if (value == null) return '';
    const input = String(value), candidate = plain(input), key = /^-?\d+:[0-9a-fA-F]{64}$/.test(candidate) ? candidate.toLowerCase() : candidate;
    return mapping[input] || mapping[key] || input;
  }
  const pattern = /(?<![A-Za-z0-9_])(?:(?:wallet:ton:|ton:)?-?\d+:[0-9A-Fa-f]{64}|[A-Za-z0-9_+/-]{48})(?![A-Za-z0-9_])/g;
  function text(value) {
    if (value == null) return '';
    return address(value).replace(pattern, token => address(token));
  }
  function short(value, head = 10, tail = 7) {
    const result = text(value);
    return result.length > head + tail + 3 ? result.slice(0, head) + '…' + result.slice(-tail) : result;
  }
  function href(value) {
    if (!value) return '';
    try {
      const result = new URL(value);
      if (!['https:', 'http:'].includes(result.protocol)) return '';
      if (!['tonviewer.com', 'tonscan.org', 'tonscan.com', 'ton.cx', 'gram.org', 'getgems.io', 'tonapi.io'].includes(result.hostname.replace(/^www\./, '')) || result.pathname.startsWith('/v2/')) return value;
      result.pathname = result.pathname.split('/').map(part => {
        const decoded = decodeURIComponent(part), shown = address(decoded);
        return shown !== decoded ? shown : part;
      }).join('/');
      return result.href;
    } catch (_) { return value; }
  }
  function amount(value) {
    if (value == null || value === '') return '';
    const original = String(value), match = /^([+-]?)(\d+)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/.exec(original.replace(/,/g, ''));
    if (!match) return original;
    const exponent = Number(match[4] || 0);
    if (!Number.isSafeInteger(exponent) || Math.abs(exponent) > 1024) return original;
    const digits = match[2] + (match[3] || ''), point = match[2].length + exponent;
    let fixed = point <= 0 ? '0.' + '0'.repeat(-point) + digits : point >= digits.length ? digits + '0'.repeat(point - digits.length) : digits.slice(0, point) + '.' + digits.slice(point);
    fixed = fixed.replace(/^0+(?=\d)/, '');
    if (fixed.includes('.')) fixed = fixed.replace(/0+$/, '').replace(/\.$/, '');
    return match[1] + fixed;
  }
  window.GansarTonPresentation = Object.freeze({address, text, short, href, amount, decimal: amount});
})();
