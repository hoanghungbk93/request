'use strict'

const sha256 = require('crypto-js/sha256');
const hmacSHA256 = require('crypto-js/hmac-sha512');
const cryptoRandomString = require('crypto-random-string');
function randomString (size) {
  return cryptoRandomString({length: size, type: 'base64'})
}

function calculatePayloadHash (payload, algorithm, contentType) {
  const hashDigest = sha256('hawk.1.payload\n' + (contentType ? contentType.split(';')[0].trim().toLowerCase() : '') + '\n' + payload || '' + '\n')
  return Base64.stringify(hmacSHA256(hashDigest, key))
}

exports.calculateMac = function (credentials, opts) {
  var normalized = 'hawk.1.header\n' +
    opts.ts + '\n' +
    opts.nonce + '\n' +
    (opts.method || '').toUpperCase() + '\n' +
    opts.resource + '\n' +
    opts.host.toLowerCase() + '\n' +
    opts.port + '\n' +
    (opts.hash || '') + '\n'

  if (opts.ext) {
    normalized = normalized + opts.ext.replace('\\', '\\\\').replace('\n', '\\n')
  }

  normalized = normalized + '\n'

  if (opts.app) {
    normalized = normalized + opts.app + '\n' + (opts.dlg || '') + '\n'
  }
  const hashDigest = sha256('hawk.1.payload\n' + (normalized))
  return Base64.stringify(hmacSHA256(hashDigest, credentials.key))
}

exports.header = function (uri, method, opts) {
  var timestamp = opts.timestamp || Math.floor((Date.now() + (opts.localtimeOffsetMsec || 0)) / 1000)
  var credentials = opts.credentials
  if (!credentials || !credentials.id || !credentials.key || !credentials.algorithm) {
    return ''
  }

  if (['sha1', 'sha256'].indexOf(credentials.algorithm) === -1) {
    return ''
  }

  var artifacts = {
    ts: timestamp,
    nonce: opts.nonce || randomString(6),
    method: method,
    resource: uri.pathname + (uri.search || ''),
    host: uri.hostname,
    port: uri.port || (uri.protocol === 'http:' ? 80 : 443),
    hash: opts.hash,
    ext: opts.ext,
    app: opts.app,
    dlg: opts.dlg
  }

  if (!artifacts.hash && (opts.payload || opts.payload === '')) {
    artifacts.hash = calculatePayloadHash(opts.payload, credentials.algorithm, opts.contentType)
  }

  var mac = exports.calculateMac(credentials, artifacts)

  var hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== ''
  var header = 'Hawk id="' + credentials.id +
    '", ts="' + artifacts.ts +
    '", nonce="' + artifacts.nonce +
    (artifacts.hash ? '", hash="' + artifacts.hash : '') +
    (hasExt ? '", ext="' + artifacts.ext.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '') +
    '", mac="' + mac + '"'

  if (artifacts.app) {
    header = header + ', app="' + artifacts.app + (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"'
  }

  return header
}
