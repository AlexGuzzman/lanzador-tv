// Puente del lanzador: corre dentro de TizenBrew (Node antiguo, a veces v4.4.3),
// así que todo es ES5 y solo usa módulos internos de Node + tweetnacl (incluido en el build).
//
// HTTP en el puerto 8095:
//   GET  /status                 -> estado y si hay credenciales
//   POST /config  {atvHost, atvCreds, tvToken}   (se puede llamar desde la red de casa)
//   GET  /atv/launch?id=<bundle> -> abre una app en el Apple TV   (solo desde la propia tele)
//   GET  /tv/key?k=<KEY_...>     -> pulsa una tecla del mando de la tele (solo desde la tele)
//   GET  /tv/source?pos=<n>      -> elige la entrada n del menú Fuentes (solo desde la tele)
//   GET  /tv/input?to=<entrada>  -> cambia directamente a tv/hdmi1..hdmi4 con Vetro (solo desde la tele)
//   GET  /tv/settings            -> abre la Configuración de la tele con Vetro (solo desde la tele)
//   GET  /webcam?id=<n>          -> imagen actual de una webcam de Windy (solo desde la tele)
//   GET  /launcher?state=<s>     -> la interfaz avisa de si está cargada o se va a un módulo (solo desde la tele)
'use strict';

var G = this; // objeto global del contexto que crea TizenBrew para el servicio
var net = require('net');
var tls = require('tls');
var http = require('http');
var crypto = require('crypto');
var os = require('os');

var PORT = 8095;
var VERSION = '0.0.0'; // build.sh pone aquí la versión de package.json
var config = { atvHost: '192.168.1.35', atvPort: 49153, atvCreds: '', tvHost: '127.0.0.1', tvPort: 8002, tvTls: true, tvToken: '', windyKey: '',
  homeGuard: false };

// La tele rechaza al instante las conexiones del mando que llegan por 127.0.0.1,
// así que el puente se conecta a su propia IP de la red de casa.
function lanAddress() {
  try {
    var ifs = os.networkInterfaces();
    for (var name in ifs) {
      for (var i = 0; i < ifs[name].length; i++) {
        var a = ifs[name][i];
        if ((a.family === 'IPv4' || a.family === 4) && !a.internal) return a.address;
      }
    }
  } catch (e) {}
  return '127.0.0.1';
}
config.tvHost = lanAddress();

// Si venimos de una autoactualización, recuperamos la configuración (credenciales incluidas)
var previous = G && G.__lanzadorState;
if (previous) {
  for (var key in previous.config) config[key] = previous.config[key];
}

// Registro corto para diagnosticar desde la red de casa (GET /status)
var logLines = [];
function log(msg) {
  logLines.push(new Date().toISOString().slice(11, 19) + ' ' + msg);
  if (logLines.length > 40) logLines.shift();
}

// ---------------------------------------------------------------- Buffers (Node 4 y modernos)
function buf(x) {
  if (typeof x === 'number') { var b = new Buffer(x); b.fill(0); return b; }
  return new Buffer(x);
}
function u8(b) { return new Uint8Array(b); }
function fromU8(a) { return buf(Array.prototype.slice.call(a)); }
function concat(list) { return Buffer.concat(list); }
function hex(h) { return new Buffer(h, 'hex'); }

// ---------------------------------------------------------------- HKDF-SHA512
function hkdf(salt, info, ikm) {
  var prk = crypto.createHmac('sha512', buf(salt)).update(ikm).digest();
  var t = crypto.createHmac('sha512', prk).update(concat([buf(info), buf([1])])).digest();
  return t.slice(0, 32);
}

// ---------------------------------------------------------------- ChaCha20-Poly1305 (RFC 8439)
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function quarter(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}
function chachaBlock(key, counter, nonce) {
  var st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  var i;
  for (i = 0; i < 8; i++) st.push(key.readUInt32LE(i * 4));
  st.push(counter >>> 0);
  for (i = 0; i < 3; i++) st.push(nonce.readUInt32LE(i * 4));
  var w = st.slice();
  for (i = 0; i < 10; i++) {
    quarter(w, 0, 4, 8, 12); quarter(w, 1, 5, 9, 13); quarter(w, 2, 6, 10, 14); quarter(w, 3, 7, 11, 15);
    quarter(w, 0, 5, 10, 15); quarter(w, 1, 6, 11, 12); quarter(w, 2, 7, 8, 13); quarter(w, 3, 4, 9, 14);
  }
  var out = buf(64);
  for (i = 0; i < 16; i++) out.writeUInt32LE((w[i] + st[i]) >>> 0, i * 4);
  return out;
}
function chachaXor(key, counter, nonce, data) {
  var out = buf(data.length);
  for (var off = 0; off < data.length; off += 64) {
    var ks = chachaBlock(key, counter++, nonce);
    for (var j = 0; j < 64 && off + j < data.length; j++) out[off + j] = data[off + j] ^ ks[j];
  }
  return out;
}
function pad16(n) { return buf((16 - (n % 16)) % 16); }
function le64(n) { var b = buf(8); b.writeUInt32LE(n >>> 0, 0); return b; }
function poly1305(msg, key) {
  var out = new Uint8Array(16);
  nacl.lowlevel.crypto_onetimeauth(out, 0, u8(msg), 0, msg.length, u8(key));
  return fromU8(out);
}
function aeadTag(key, nonce, aad, ct) {
  var otk = chachaBlock(key, 0, nonce).slice(0, 32);
  var mac = concat([aad, pad16(aad.length), ct, pad16(ct.length), le64(aad.length), le64(ct.length)]);
  return poly1305(mac, otk);
}
function seal(key, nonce, plain, aad) {
  aad = aad || buf(0);
  var ct = chachaXor(key, 1, nonce, plain);
  return concat([ct, aeadTag(key, nonce, aad, ct)]);
}
function open(key, nonce, sealed, aad) {
  aad = aad || buf(0);
  var ct = sealed.slice(0, sealed.length - 16);
  var tag = sealed.slice(sealed.length - 16);
  var expected = aeadTag(key, nonce, aad, ct);
  var diff = 0;
  for (var i = 0; i < 16; i++) diff |= tag[i] ^ expected[i];
  if (diff !== 0) throw new Error('etiqueta de cifrado incorrecta');
  return chachaXor(key, 1, nonce, ct);
}
function nonceText(txt) { return concat([buf(4), buf(txt)]); }
function nonceCounter(n) { var b = buf(12); b.writeUInt32LE(n >>> 0, 0); return b; }

// ---------------------------------------------------------------- TLV8
function writeTlv(items) {
  var parts = [];
  for (var i = 0; i < items.length; i++) {
    var tag = items[i][0], val = items[i][1], pos = 0;
    do {
      var size = Math.min(255, val.length - pos);
      parts.push(buf([tag, size]), val.slice(pos, pos + size));
      pos += size;
    } while (pos < val.length);
  }
  return concat(parts);
}
function readTlv(data) {
  var res = {}, pos = 0;
  while (pos < data.length) {
    var tag = data[pos], len = data[pos + 1], val = data.slice(pos + 2, pos + 2 + len);
    res[tag] = res[tag] ? concat([res[tag], val]) : val;
    pos += 2 + len;
  }
  return res;
}

// ---------------------------------------------------------------- OPACK (lo justo para Companion)
function opackPack(v) {
  if (v === null || v === undefined) return buf([0x04]);
  if (v === true) return buf([0x01]);
  if (v === false) return buf([0x02]);
  if (Buffer.isBuffer(v)) {
    if (v.length <= 0x20) return concat([buf([0x70 + v.length]), v]);
    if (v.length <= 0xff) return concat([buf([0x91, v.length]), v]);
    var l2 = buf(2); l2.writeUInt16LE(v.length, 0);
    return concat([buf([0x92]), l2, v]);
  }
  if (v && typeof v.__double === 'number') { var d = buf(9); d[0] = 0x36; d.writeDoubleLE(v.__double, 1); return d; }
  if (typeof v === 'number') {
    if (v < 0x28) return buf([v + 8]);
    if (v <= 0xff) return buf([0x30, v]);
    if (v <= 0xffff) { var b2 = buf(3); b2[0] = 0x31; b2.writeUInt16LE(v, 1); return b2; }
    var b4 = buf(5); b4[0] = 0x32; b4.writeUInt32LE(v >>> 0, 1); return b4;
  }
  if (typeof v === 'string') {
    var s = buf(v);
    if (s.length <= 0x20) return concat([buf([0x40 + s.length]), s]);
    return concat([buf([0x61, s.length]), s]);
  }
  if (Array.isArray(v)) {
    var la = [buf([0xd0 + Math.min(v.length, 0xf)])];
    for (var i = 0; i < v.length; i++) la.push(opackPack(v[i]));
    if (v.length >= 0xf) la.push(buf([0x03]));
    return concat(la);
  }
  var keys = Object.keys(v);
  var ld = [buf([0xe0 + Math.min(keys.length, 0xf)])];
  for (var k = 0; k < keys.length; k++) ld.push(opackPack(keys[k]), opackPack(v[keys[k]]));
  if (keys.length >= 0xf) ld.push(buf([0x03]));
  return concat(ld);
}
function readUIntLE(b, off, n) { var v = 0; for (var i = n - 1; i >= 0; i--) v = v * 256 + b[off + i]; return v; }
function opackUnpack(data) {
  var objs = [];
  function un(p) {
    var t = data[p], v, len, n, i, add = true;
    if (t === 0x01) return [true, p + 1];
    if (t === 0x02) return [false, p + 1];
    if (t === 0x04) return [null, p + 1];
    if (t === 0x05) { v = data.slice(p + 1, p + 17); p += 17; }
    else if (t === 0x06) { v = readUIntLE(data, p + 1, 8); p += 9; }
    else if (t >= 0x08 && t <= 0x2f) return [t - 8, p + 1];
    else if (t === 0x35) { v = data.readFloatLE(p + 1); p += 5; }
    else if (t === 0x36) { v = data.readDoubleLE(p + 1); p += 9; }
    else if ((t & 0xf0) === 0x30) { n = Math.pow(2, t & 0xf); v = readUIntLE(data, p + 1, n); p += 1 + n; }
    else if (t >= 0x40 && t <= 0x60) { len = t - 0x40; v = data.slice(p + 1, p + 1 + len).toString('utf8'); p += 1 + len; }
    else if (t > 0x60 && t <= 0x64) { n = t & 0xf; len = readUIntLE(data, p + 1, n); v = data.slice(p + 1 + n, p + 1 + n + len).toString('utf8'); p += 1 + n + len; }
    else if (t >= 0x70 && t <= 0x90) { len = t - 0x70; v = data.slice(p + 1, p + 1 + len); p += 1 + len; }
    else if (t >= 0x91 && t <= 0x94) { n = 1 << ((t & 0xf) - 1); len = readUIntLE(data, p + 1, n); v = data.slice(p + 1 + n, p + 1 + n + len); p += 1 + n + len; }
    else if ((t & 0xf0) === 0xd0) {
      var count = t & 0xf, arr = [], r; p += 1;
      if (count === 0xf) { while (data[p] !== 0x03) { r = un(p); arr.push(r[0]); p = r[1]; } p += 1; }
      else for (i = 0; i < count; i++) { r = un(p); arr.push(r[0]); p = r[1]; }
      return [arr, p];
    }
    else if ((t & 0xe0) === 0xe0) {
      var cnt = t & 0xf, obj = {}, rk, rv; p += 1;
      if (cnt === 0xf) { while (data[p] !== 0x03) { rk = un(p); rv = un(rk[1]); obj[rk[0]] = rv[0]; p = rv[1]; } p += 1; }
      else for (i = 0; i < cnt; i++) { rk = un(p); rv = un(rk[1]); obj[rk[0]] = rv[0]; p = rv[1]; }
      return [obj, p];
    }
    else if (t >= 0xa0 && t <= 0xc0) return [objs[t - 0xa0], p + 1];
    else if (t >= 0xc1 && t <= 0xc4) { n = t - 0xc0; return [objs[readUIntLE(data, p + 1, n)], p + 1 + n]; }
    else throw new Error('OPACK desconocido 0x' + t.toString(16));
    if (add && objs.indexOf(v) < 0) objs.push(v);
    return [v, p];
  }
  return un(0)[0];
}

// ---------------------------------------------------------------- Companion (Apple TV)
var FRAME = { PV_Start: 5, PV_Next: 6, E_OPACK: 8 };

function companionLaunch(bundleId, done) {
  var parts = config.atvCreds.split(':');
  if (parts.length !== 4) return done(new Error('faltan las credenciales del Apple TV'));
  var ltpk = hex(parts[0]), ltsk = hex(parts[1]), atvId = hex(parts[2]), clientId = hex(parts[3]);

  var sock = net.connect(config.atvPort, config.atvHost);
  var inbuf = buf(0), keys = null, outCount = 0, inCount = 0, waiting = null, finished = false;
  var xid = Math.floor(Math.random() * 60000) + 1;
  var priv = fromU8(nacl.randomBytes(32));
  var pub = fromU8(nacl.scalarMult.base(u8(priv)));
  var shared = null;

  var timer = setTimeout(function () { finish(new Error('el Apple TV no responde')); }, 15000);
  function finish(err) {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    try { sock.destroy(); } catch (e) {}
    done(err || null);
  }
  function send(type, obj) {
    var body = opackPack(obj);
    var len = body.length + (keys ? 16 : 0);
    var header = buf([type, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
    if (keys) body = seal(keys.out, nonceCounter(outCount++), body, header);
    sock.write(concat([header, body]));
  }
  function expect(fn) { waiting = fn; }

  sock.on('error', function (e) { finish(e); });
  sock.on('close', function () { finish(new Error('conexión cerrada por el Apple TV')); });
  sock.on('data', function (chunk) {
    inbuf = concat([inbuf, chunk]);
    while (inbuf.length >= 4) {
      var len = (inbuf[1] << 16) | (inbuf[2] << 8) | inbuf[3];
      if (inbuf.length < 4 + len) break;
      var header = inbuf.slice(0, 4), payload = inbuf.slice(4, 4 + len);
      inbuf = inbuf.slice(4 + len);
      try {
        if (keys && payload.length > 0) payload = open(keys.in, nonceCounter(inCount++), payload, header);
        var msg = opackUnpack(payload);
        if (waiting) waiting(header[0], msg);
      } catch (e) { finish(e); }
    }
  });

  sock.on('connect', function () {
    // Pair-Verify M1: nuestra clave efímera
    send(FRAME.PV_Start, { _pd: writeTlv([[6, buf([1])], [3, pub]]), _auTy: 4, _x: xid++ });
    expect(function (type, msg) {
      var tlv = readTlv(msg._pd);
      var serverPub = tlv[3];
      shared = fromU8(nacl.scalarMult(u8(priv), u8(serverPub)));
      var sessionKey = hkdf('Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info', shared);
      var inner = readTlv(open(sessionKey, nonceText('PV-Msg02'), tlv[5]));
      if (inner[1].toString('hex') !== atvId.toString('hex')) return finish(new Error('Apple TV inesperado'));
      var signed = concat([serverPub, inner[1], pub]);
      if (!nacl.sign.detached.verify(u8(signed), u8(inner[10]), u8(ltpk))) return finish(new Error('firma del Apple TV incorrecta'));

      // Pair-Verify M3: firmamos con nuestra clave de emparejamiento
      var secret = nacl.sign.keyPair.fromSeed(u8(ltsk)).secretKey;
      var sig = fromU8(nacl.sign.detached(u8(concat([pub, clientId, serverPub])), secret));
      var enc = seal(sessionKey, nonceText('PV-Msg03'), writeTlv([[1, clientId], [10, sig]]));
      send(FRAME.PV_Next, { _pd: writeTlv([[6, buf([3])], [5, enc]]), _x: xid++ });
      expect(function (type2, msg2) {
        var t2 = readTlv(msg2._pd || buf(0));
        if (t2[7]) return finish(new Error('el Apple TV rechazó las credenciales'));
        keys = { out: hkdf('', 'ClientEncrypt-main', shared), in: hkdf('', 'ServerEncrypt-main', shared) };
        // "Despertar" enciende el Apple TV si estaba en reposo y "Inicio" hace que la tele
        // cambie a su entrada por HDMI-CEC aunque ya estuviera encendido.
        var steps = [
          // Sin una sesión de mando abierta, el Apple TV responde a los botones pero no los ejecuta
          { i: '_systemInfo', c: { _bf: 0, _cf: 512, _clFl: 128, _i: clientId.toString('hex').slice(0, 12), _idsID: clientId,
                                   _pubID: 'AA:BB:CC:DD:EE:FF', _sf: 256, _sv: '170.18', model: 'iPhone14,3', name: 'Lanzador' }, wait: 0 },
          { i: '_touchStart', c: { _height: { __double: 1000 }, _tFl: 0, _width: { __double: 1000 } }, wait: 0 },
          { i: '_sessionStart', c: { _srvT: 'com.apple.tvremoteservices', _sid: Math.floor(Math.random() * 4294967295) }, wait: 0 },
          { i: 'TVRCSessionStart', c: { ProtocolVersionKey: '1.2' }, wait: 0, optional: true },
          { i: '_tiStart', c: {}, wait: 0, optional: true },
          { i: '_hidC', c: { _hBtS: 2, _hidC: 13 }, wait: 1500 },
          { i: '_hidC', c: { _hBtS: 1, _hidC: 7 }, wait: 80 },
          { i: '_hidC', c: { _hBtS: 2, _hidC: 7 }, wait: 1200 }
        ];
        if (bundleId) steps.push({ i: '_launchApp', c: { _bundleID: bundleId }, wait: 0 });
        var n = 0;
        (function next() {
          if (n >= steps.length) return finish(null);
          var step = steps[n++], stepXid = xid++;
          log('atv: ' + step.i + ' ' + JSON.stringify(step.c));
          send(FRAME.E_OPACK, { _i: step.i, _t: 2, _c: step.c, _x: stepXid });
          expect(function (type3, msg3) {
            if (msg3._t !== 3 || msg3._x !== stepXid) return; // eventos u otras respuestas
            if (msg3._em && !step.optional) return finish(new Error(String(msg3._em)));
            if (msg3._em) log('atv: ' + step.i + ' rechazado: ' + msg3._em);
            setTimeout(next, step.wait);
          });
        })();
      });
    });
  });
}

// ---------------------------------------------------------------- Mando de la tele (WebSocket local)
// steps: [{k: 'KEY_SOURCE', wait: 1800}, ...] se envían en orden por la misma conexión.
function tvKeys(steps, done) {
  var name = buf('Lanzador').toString('base64');
  var path = '/api/v2/channels/samsung.remote.control?name=' + name + (config.tvToken ? '&token=' + config.tvToken : '');
  var opts = { host: config.tvHost, port: config.tvPort, rejectUnauthorized: false };
  var sock = config.tvTls ? tls.connect(opts) : net.connect(opts);
  log('tv: conectando a ' + config.tvHost + ':' + config.tvPort + (config.tvTls ? ' (tls)' : '') + (config.tvToken ? ' con token' : ' sin token'));
  var wsKey = crypto.randomBytes(16).toString('base64');
  var data = buf(0), upgraded = false, finished = false;
  var timer = setTimeout(function () { finish(new Error('la tele no responde')); }, 30000);
  function finish(err) {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    log('tv: fin ' + (err ? err.message : 'ok'));
    try { sock.end(); } catch (e) {}
    done(err || null);
  }
  function sendText(txt) {
    var payload = buf(txt), mask = crypto.randomBytes(4), header;
    if (payload.length < 126) header = buf([0x81, 0x80 | payload.length]);
    else { header = buf(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(payload.length, 2); }
    for (var i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    sock.write(concat([header, mask, payload]));
  }
  sock.on('error', function (e) { finish(e); });
  sock.on('close', function () { log('tv: conexión cerrada'); });
  sock.on(config.tvTls ? 'secureConnect' : 'connect', function () {
    log('tv: conectado');
    sock.write('GET ' + path + ' HTTP/1.1\r\nHost: ' + config.tvHost + ':' + config.tvPort + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      'Sec-WebSocket-Key: ' + wsKey + '\r\nSec-WebSocket-Version: 13\r\n\r\n');
  });
  sock.on('data', function (chunk) {
    data = concat([data, chunk]);
    if (!upgraded) {
      var end = data.toString('binary').indexOf('\r\n\r\n');
      if (end < 0) return;
      log('tv: respuesta ' + data.slice(0, 40).toString('binary').split('\r\n')[0]);
      upgraded = true;
      data = data.slice(end + 4);
    }
    // Leemos los mensajes de texto que manda la tele (sin máscara)
    while (data.length >= 2) {
      var len = data[1] & 0x7f, off = 2;
      if (len === 126) { if (data.length < 4) return; len = data.readUInt16BE(2); off = 4; }
      if (data.length < off + len) return;
      var text = data.slice(off, off + len).toString('utf8');
      log('tv: mensaje (op ' + (data[0] & 0x0f) + ') ' + text.slice(0, 120));
      data = data.slice(off + len);
      var msg;
      try { msg = JSON.parse(text); } catch (e) { continue; }
      if (msg.event === 'ms.channel.connect') {
        if (msg.data && msg.data.token) config.tvToken = msg.data.token;
        var i = 0;
        (function next() {
          if (i >= steps.length) return setTimeout(function () { finish(null); }, 300);
          var step = steps[i++];
          sendText(JSON.stringify({ method: 'ms.remote.control', params: { Cmd: 'Click', DataOfCmd: step.k, Option: 'false', TypeOfRemote: 'SendRemoteKey' } }));
          setTimeout(next, step.wait || 350);
        })();
      } else if (msg.event === 'ms.channel.unauthorized') {
        finish(new Error('la tele no ha dado permiso'));
      } else if (msg.event === 'ms.channel.timeOut') {
        finish(new Error('nadie aceptó el aviso de permiso en la tele'));
      }
    }
  });
}

// Elige una entrada del menú Fuentes por su posición (0 = TV, 1 = Apple TV, 3 = Movistar, 4 = USB):
// abre el menú, va al principio de la lista y avanza.
function tvSource(pos, done) {
  var steps = [{ k: 'KEY_SOURCE', wait: 1800 }];
  for (var i = 0; i < 8; i++) steps.push({ k: 'KEY_LEFT', wait: 300 });
  for (var j = 0; j < pos; j++) steps.push({ k: 'KEY_RIGHT', wait: 400 });
  steps.push({ k: 'KEY_ENTER', wait: 300 });
  tvKeys(steps, done);
}

// Cambio directo de entrada. Una app no puede cambiar de entrada, pero Vetro (servicio con root
// en la propia tele) puede pulsar las teclas de entrada directa del sistema. Solo se usan estas.
var VETRO = { host: '127.0.0.1', port: 9000 };
var INPUT_KEYS = { tv: 'XF86DiscretSourceTV', hdmi1: 'XF86DiscretHDMI1', hdmi2: 'XF86DiscretHDMI2',
  hdmi3: 'XF86DiscretHDMI3', hdmi4: 'XF86DiscretHDMI4' };
function vetroPost(path, obj, what, done) {
  var body = JSON.stringify(obj);
  var finished = false;
  function finish(err, d) { if (!finished) { finished = true; done(err, d); } }
  var req = http.request({ host: VETRO.host, port: VETRO.port, method: 'POST', path: path,
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, function (res) {
    var out = '';
    res.setEncoding('utf8');
    res.on('data', function (c) { out += c; });
    res.on('end', function () {
      var d;
      try { d = JSON.parse(out); } catch (e) { return finish(new Error('respuesta de Vetro no válida')); }
      if (!d.ok) return finish(new Error('Vetro no pudo ' + what + (d.error ? ': ' + d.error : '')));
      finish(null, d);
    });
  });
  req.setTimeout(10000, function () { req.abort(); finish(new Error('Vetro no responde')); });
  req.on('error', function (e) { finish(new Error('Vetro no responde (' + e.message + ')')); });
  req.end(body);
}
function tvInput(to, done) {
  var key = INPUT_KEYS.hasOwnProperty(to) ? INPUT_KEYS[to] : null;
  if (!key) return done(new Error('entrada desconocida: ' + to));
  vetroPost('/exec', { cmd: '/usr/bin/input_keyevent ' + key }, 'cambiar de entrada', function (err) {
    if (!err) log('entrada: ' + to);
    done(err);
  });
}
// Configuración de la tele: el Home de Samsung ya no está en la tecla Home, así que se abre su menú
// (org.tizen.menu) con la función de abrir apps de Vetro, que comprueba que la app existe.
function tvSettings(done) {
  vetroPost('/apps/launch', { appId: 'org.tizen.menu' }, 'abrir la Configuración', function (err) {
    if (!err) log('configuración abierta');
    done(err);
  });
}

// Home de Samsung -> nuestro lanzador, sin capturar el mando. El Home de Samsung (csfs) está siempre en
// marcha en segundo plano (estado 4); al pulsar Home pasa a primer plano (2 o 3). Cada segundo se pregunta
// a Vetro por su estado y, si está delante, se abre TizenBrew encima. Si TizenBrew no tiene el lanzador
// cargado (por ejemplo, está en YouTube), se cierra antes para que arranque en él con su Auto launch.
var HOME_APP = 'com.samsung.tv.csfs', BREW_APP = 'xvvl3S1bvH.TizenBrewStandalone';
var HOME_STATUS_CMD = 'aul_test getallappstatus 2>&1 | grep -A3 "appid: ' + HOME_APP + '$" | grep status';
var launcherLoaded = false, homeBusy = false, homeLastTakeover = 0, homeTimer = null;
function checkHome() {
  if (!config.homeGuard || homeBusy) return;
  homeBusy = true;
  vetroPost('/exec', { cmd: HOME_STATUS_CMD }, 'leer el estado del Home', function (err, d) {
    var m = !err && d && /status:\s*(\d+)/.exec(d.output || '');
    if (!m || (m[1] !== '2' && m[1] !== '3') || Date.now() - homeLastTakeover < 4000) { homeBusy = false; return; }
    homeLastTakeover = Date.now();
    var kill = launcherLoaded ? null : 'app_launcher -k ' + BREW_APP;
    log('home: Home de Samsung delante, abriendo el lanzador' + (kill ? ' (reiniciando TizenBrew)' : ''));
    function launch() {
      vetroPost('/apps/launch', { appId: BREW_APP }, 'abrir TizenBrew', function (err2) {
        if (err2) log('home: ' + err2.message);
        homeBusy = false;
      });
    }
    if (!kill) return launch();
    vetroPost('/exec', { cmd: kill }, 'cerrar TizenBrew', function () { setTimeout(launch, 600); });
  });
}
function startHomeGuard() { stopHomeGuard(); homeTimer = setInterval(checkHome, 1000); }
function stopHomeGuard() { if (homeTimer) clearInterval(homeTimer); homeTimer = null; }

// Webcams de Windy. La clave llega por POST /config y nunca está en el repositorio. Las URL de las
// imágenes caducan a los 10 minutos en el plan gratuito, así que se piden de nuevo pasados 5.
var webcamCache = {};
function webcam(id, done) {
  if (!config.windyKey) return done(new Error('falta la clave de Windy'));
  var cached = webcamCache[id];
  if (cached && Date.now() - cached.at < 5 * 60 * 1000) return done(null, cached.data);
  var finished = false;
  function finish(err, data) { if (!finished) { finished = true; done(err, data); } }
  var req = require('https').request({ host: 'api.windy.com', method: 'GET',
    path: '/webcams/api/v3/webcams/' + id + '?include=images,urls&lang=es',
    headers: { 'x-windy-api-key': config.windyKey, 'Accept': 'application/json' } }, function (res) {
    var out = '';
    res.setEncoding('utf8');
    res.on('data', function (c) { out += c; });
    res.on('end', function () {
      if (res.statusCode !== 200) return finish(new Error('Windy respondió ' + res.statusCode));
      var w;
      try { w = JSON.parse(out); } catch (e) { return finish(new Error('respuesta de Windy no válida')); }
      var img = w.images && w.images.current && w.images.current.preview;
      if (!img) return finish(new Error('la webcam no tiene imagen'));
      var data = { image: img, updated: w.lastUpdatedOn || null, status: w.status || null,
        link: (w.urls && w.urls.detail) || ('https://www.windy.com/webcams/' + id) };
      webcamCache[id] = { at: Date.now(), data: data };
      finish(null, data);
    });
  });
  req.setTimeout(15000, function () { req.abort(); finish(new Error('Windy no responde')); });
  req.on('error', function (e) { finish(new Error('Windy no responde (' + e.message + ')')); });
  req.end();
}

// ---------------------------------------------------------------- Servidor HTTP
function reply(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
  res.end(JSON.stringify(obj));
}
function isLocal(req) {
  var a = req.socket.remoteAddress || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}
function startServer() {
  var server = http.createServer(function (req, res) {
    var u = require('url').parse(req.url, true);
    if (req.method === 'OPTIONS') return reply(res, 204, {});
    if (u.pathname === '/status') {
      return reply(res, 200, { ok: true, version: VERSION, atvHost: config.atvHost, tvHost: config.tvHost, hasCreds: !!config.atvCreds, tvToken: config.tvToken,
        tvPort: config.tvPort, tvTls: config.tvTls, log: logLines, atvCreds: isLocal(req) ? config.atvCreds : undefined,
        hasWindy: !!config.windyKey, homeGuard: config.homeGuard, windyKey: isLocal(req) ? config.windyKey : undefined });
    }
    if (u.pathname === '/config' && req.method === 'POST') {
      var body = '';
      req.on('data', function (c) { body += c; });
      req.on('end', function () {
        try {
          var c = JSON.parse(body);
          if (c.atvHost) config.atvHost = c.atvHost;
          if (c.tvHost) config.tvHost = c.tvHost;
          if (c.atvCreds) config.atvCreds = c.atvCreds;
          if (c.tvToken !== undefined) config.tvToken = c.tvToken;
          if (c.tvPort) config.tvPort = c.tvPort;
          if (c.tvTls !== undefined) config.tvTls = !!c.tvTls;
          if (c.homeGuard !== undefined) config.homeGuard = !!c.homeGuard;
          if (typeof c.windyKey === 'string' && /^[A-Za-z0-9]{0,64}$/.test(c.windyKey)) { config.windyKey = c.windyKey; webcamCache = {}; }
          reply(res, 200, { ok: true });
        } catch (e) { reply(res, 400, { ok: false, error: 'JSON no válido' }); }
      });
      return;
    }
    if (u.pathname === '/debug/apps') {
      try {
        return tizen.application.getAppsInfo(function (list) {
          reply(res, 200, { ok: true, apps: list.map(function (a) { return a.id + ' | ' + a.name; }) });
        }, function (e) { reply(res, 500, { ok: false, error: String(e && e.message) }); });
      } catch (e) { return reply(res, 500, { ok: false, error: String(e && e.message) }); }
    }
    // Exploración de apps internas de la tele (solo abre apps, no ejecuta código arbitrario)
    // Autoactualización: carga el puente de una versión concreta (commit) de este repositorio
    if (u.pathname === '/debug/reload') {
      var sha = String(u.query.sha || '');
      if (!/^[0-9a-f]{7,40}$/.test(sha)) return reply(res, 400, { ok: false, error: 'sha no válido' });
      return selfUpdate(sha, function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true, sha: sha });
      });
    }
    if (u.pathname === '/debug/meta') {
      try {
        var info = tizen.application.getAppInfo(String(u.query.app));
        var meta = [];
        try { meta = tizen.application.getAppMetaData(String(u.query.app)).map(function (m) { return m.key + '=' + m.value; }); } catch (e) { meta = ['(sin metadatos: ' + e.message + ')']; }
        return reply(res, 200, { ok: true, info: { id: info.id, name: info.name, packageId: info.packageId, show: info.show, categories: info.categories }, meta: meta });
      } catch (e) { return reply(res, 500, { ok: false, error: String(e && e.message) }); }
    }
    if (u.pathname === '/debug/launch') {
      try {
        var data = [];
        if (u.query.data) {
          var obj = JSON.parse(String(u.query.data));
          for (var k in obj) data.push(new tizen.ApplicationControlData(k, [String(obj[k])]));
        }
        var ctrl = new tizen.ApplicationControl(String(u.query.op || 'http://tizen.org/appcontrol/operation/default'),
          u.query.uri ? String(u.query.uri) : null, null, null, data);
        log('debug: launchAppControl ' + u.query.app + ' ' + (u.query.data || ''));
        return tizen.application.launchAppControl(ctrl, u.query.app ? String(u.query.app) : null,
          function () { reply(res, 200, { ok: true }); },
          function (e) { reply(res, 500, { ok: false, error: String(e && e.message) }); });
      } catch (e) { return reply(res, 500, { ok: false, error: String(e && e.message) }); }
    }
    if (!isLocal(req)) return reply(res, 403, { ok: false, error: 'solo desde la tele' });
    if (u.pathname === '/atv/show') {
      return companionLaunch('', function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true });
      });
    }
    if (u.pathname === '/atv/launch') {
      return companionLaunch(String(u.query.id || ''), function (err) {
        if (err) return reply(res, 500, { ok: false, error: err.message });
        // El Apple TV ya está despierto y con la app abierta: la tele pasa a su entrada
        tvInput('hdmi1', function (err2) {
          reply(res, 200, { ok: true, input: err2 ? err2.message : 'hdmi1' });
        });
      });
    }
    if (u.pathname === '/launcher') {
      launcherLoaded = u.query.state === 'loaded';
      return reply(res, 200, { ok: true });
    }
    if (u.pathname === '/webcam') {
      var camId = String(u.query.id || '');
      if (!/^[0-9]{6,12}$/.test(camId)) return reply(res, 400, { ok: false, error: 'id no válido' });
      return webcam(camId, function (err, data) {
        reply(res, err ? 502 : 200, err ? { ok: false, error: err.message } : { ok: true, webcam: data });
      });
    }
    if (u.pathname === '/tv/settings') {
      return tvSettings(function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true });
      });
    }
    if (u.pathname === '/tv/input') {
      return tvInput(String(u.query.to || ''), function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true });
      });
    }
    if (u.pathname === '/tv/key') {
      return tvKeys([{ k: String(u.query.k || '') }], function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true, tvToken: config.tvToken });
      });
    }
    if (u.pathname === '/tv/source') {
      return tvSource(parseInt(u.query.pos, 10) || 0, function (err) {
        reply(res, err ? 500 : 200, err ? { ok: false, error: err.message } : { ok: true, tvToken: config.tvToken });
      });
    }
    reply(res, 404, { ok: false });
  });
  server.on('error', function (e) { log('servidor: ' + e.message); }); // ya en marcha (TizenBrew reinicia servicios)
  server.listen(PORT, '0.0.0.0');
  currentServer = server;
}
var currentServer = null;

function selfUpdate(sha, done) {
  var url = 'https://cdn.jsdelivr.net/gh/AlexGuzzman/lanzador-tv@' + sha + '/service.js';
  log('actualizando a ' + sha);
  require('https').get(url, function (resp) {
    var code = '';
    resp.setEncoding('utf8');
    resp.on('data', function (c) { code += c; });
    resp.on('end', function () {
      if (resp.statusCode !== 200 || code.indexOf('companionLaunch') < 0) return done(new Error('descarga fallida (' + resp.statusCode + ')'));
      done(null);
      // Cerramos este servidor y arrancamos el nuevo código en un contexto limpio
      setTimeout(function () {
        stopHomeGuard();
        currentServer.close();
        try { currentServer._handle && currentServer._handle.close(); } catch (e) {}
        setTimeout(function () {
          var vm = require('vm');
          var sandbox = {};
          Object.getOwnPropertyNames(G).forEach(function (k) { if (k !== 'module' && k !== '__lanzadorState') sandbox[k] = G[k]; });
          sandbox.module = { exports: {} };
          sandbox.__lanzadorState = { config: config };
          try { vm.runInContext(code, vm.createContext(sandbox)); }
          catch (e) { log('error al arrancar la versión nueva: ' + e.message); startServer(); startHomeGuard(); }
        }, 500);
      }, 200);
    });
  }).on('error', function (e) { done(e); });
}

module.exports = {
  config: config,
  companionLaunch: companionLaunch,
  tvKeys: tvKeys,
  tvSource: tvSource,
  tvInput: tvInput,
  tvSettings: tvSettings,
  webcam: webcam,
  checkHome: checkHome,
  _home: function (v) { if (v !== undefined) launcherLoaded = v; return { launcherLoaded: launcherLoaded, busy: homeBusy }; },
  VETRO: VETRO,
  _test: { seal: seal, open: open, hkdf: hkdf, opackPack: opackPack, opackUnpack: opackUnpack }
};

if (typeof process === 'undefined' || !process.env || !process.env.LANZADOR_NO_SERVER) { startServer(); startHomeGuard(); }
