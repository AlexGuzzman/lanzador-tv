// Compara el ChaCha20-Poly1305, HKDF y OPACK del puente con la implementación de Node moderno.
process.env.LANZADOR_NO_SERVER = '1';
var b = require('../service.js'), c = require('crypto'), assert = require('assert');
for (var i = 0; i < 50; i++) {
  var key = c.randomBytes(32), nonce = c.randomBytes(12), aad = c.randomBytes(i % 7), msg = c.randomBytes(i * 13);
  var ci = c.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  ci.setAAD(aad); var ref = Buffer.concat([ci.update(msg), ci.final(), ci.getAuthTag()]);
  assert.deepStrictEqual(b._test.seal(key, nonce, msg, aad), ref);
  assert.deepStrictEqual(b._test.open(key, nonce, ref, aad), msg);
}
var ikm = c.randomBytes(32);
assert.deepStrictEqual(b._test.hkdf('Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info', ikm),
  Buffer.from(c.hkdfSync('sha512', ikm, 'Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info', 32)));
assert.deepStrictEqual(b._test.hkdf('', 'ClientEncrypt-main', ikm), Buffer.from(c.hkdfSync('sha512', ikm, '', 'ClientEncrypt-main', 32)));
var o = { _i: '_launchApp', _t: 2, _c: { _bundleID: 'com.netflix.Netflix' }, _x: 1234, arr: [1, 'a', true, null] };
assert.deepStrictEqual(b._test.opackUnpack(b._test.opackPack(o)), o);
console.log('cripto OK');
