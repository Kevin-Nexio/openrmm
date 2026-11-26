// Native remote session wire format shared with internal/e2e.
const RemoteCrypto = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const utf8 = (s) => encoder.encode(s);
  const subtle = () => globalThis.crypto.subtle;
  const random = (size) => globalThis.crypto.getRandomValues(new Uint8Array(size));
  const encode = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  function decode(s, size) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('invalid base64url');
    const bytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    if ((size !== undefined && bytes.length !== size) || encode(bytes) !== s) throw new Error('invalid base64url');
    return bytes;
  }
  const point = (s) => {
    const raw = decode(s, 65);
    if (raw[0] !== 4) throw new Error('invalid P-256 point');
    return raw;
  };
  function concat(...parts) {
    const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let at = 0;
    for (const part of parts) { result.set(part, at); at += part.length; }
    return result;
  }
  function uint64(n) {
    const raw = new Uint8Array(8);
    new DataView(raw.buffer).setBigUint64(0, BigInt(n));
    return raw;
  }
  function lengthPrefixed(field) {
    const raw = typeof field === 'string' ? utf8(field) : field;
    const size = new Uint8Array(4);
    new DataView(size.buffer).setUint32(0, raw.length);
    return concat(size, raw);
  }
  const tuple = (domain, ...fields) => concat(utf8(domain + '\0'), ...fields.map(lengthPrefixed));
  const digest = async (raw) => new Uint8Array(await subtle().digest('SHA-256', raw));
  const fingerprint = async (pub) => encode((await digest(point(pub))).subarray(0, 16));
  // Store only verified public identity keys. The check before connecting
  // also prevents returning to legacy mode for a previously pinned device.
  function deviceIdentity(agentID, deviceKey, remember = false) {
    if (!agentID) return false;
    try {
      const name = 'rmm-device-key:' + agentID;
      const known = globalThis.localStorage.getItem(name);
      if (known && known !== deviceKey) return false;
      if (remember && !known && deviceKey) {
        point(deviceKey);
        globalThis.localStorage.setItem(name, deviceKey);
      }
      return true;
    } catch {
      return !deviceKey && !remember;
    }
  }
  // The key this browser remembered for a device, or '' when it has none.
  function knownDeviceKey(agentID) {
    try { return (agentID && globalThis.localStorage.getItem('rmm-device-key:' + agentID)) || ''; } catch { return ''; }
  }
  // Replace a remembered key only when it is still the one the technician saw
  // and accepted to change, and the new one is a valid point.
  function rememberDeviceKey(agentID, deviceKey, previous) {
    try {
      const name = 'rmm-device-key:' + agentID;
      if (!agentID || !deviceKey || globalThis.localStorage.getItem(name) !== previous) return false;
      point(deviceKey);
      globalThis.localStorage.setItem(name, deviceKey);
      return true;
    } catch { return false; }
  }
  // XXXX-XXXX-XXXX-XXXX: the first 64 bits of SHA-256 over the key, the same
  // fingerprint the server shows and `rmm-agent -fingerprint` prints.
  async function displayFingerprint(pub) {
    const hex = Array.from((await digest(point(pub))).subarray(0, 8), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{4}/g).join('-');
  }
  const aes = (raw) => subtle().importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const expiry = (exp) => Number.isSafeInteger(exp) && exp > Math.floor(Date.now() / 1000);
  const signature = { name: 'ECDSA', hash: 'SHA-256' };
  async function keyPair(name, extractable = false) {
    const pair = await subtle().generateKey({ name, namedCurve: 'P-256' }, extractable, name === 'ECDH' ? ['deriveBits'] : ['sign', 'verify']);
    return { pub: encode(new Uint8Array(await subtle().exportKey('raw', pair.publicKey))), key: pair.privateKey };
  }
  async function verify(pub, message, sig) {
    const key = await subtle().importKey('raw', point(pub), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return subtle().verify(signature, key, decode(sig, 64), message);
  }
  const sign = async (key, message) => encode(new Uint8Array(await subtle().sign(signature, key, message)));
  async function sharedKey(privateKey, peerPoint) {
    const peer = await subtle().importKey('raw', peerPoint, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const bits = await subtle().deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
    return subtle().importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  }
  const hkdf = async (key, salt, info, size) => new Uint8Array(await subtle().deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt, info: utf8(info),
  }, key, size * 8));

  async function sessionKeys(ephemeral, viewerNonce, hello, context) {
    const { id, agentID, kind, guestMode, deviceKey, inviteFP } = context;
    if (hello.t !== 'e2e_hello' || hello.v !== 1 || hello.role !== 'agent' ||
        !hello.agent_id || (agentID && hello.agent_id !== agentID) ||
        hello.kind !== kind || (hello.guest_mode || '') !== guestMode ||
        !expiry(hello.exp) || (!deviceKey && !inviteFP) ||
        (deviceKey && hello.ik !== deviceKey) ||
        (inviteFP && await fingerprint(hello.ik) !== inviteFP)) throw new Error('invalid endpoint identity');
    const endpointPoint = point(hello.ek);
    const fields = [id, hello.agent_id, kind, guestMode];
    const delegation = concat(tuple('rmm-e2e-del-v1', ...fields, endpointPoint), uint64(hello.exp));
    if (!await verify(hello.ik, delegation, hello.sig)) throw new Error('invalid endpoint delegation');
    const transcript = concat(tuple('rmm-e2e-hs-v1', ...fields, point(hello.ik), point(ephemeral.pub),
      viewerNonce, endpointPoint, decode(hello.nonce, 32)), uint64(hello.exp), lengthPrefixed(decode(hello.sig, 64)));
    const salt = await digest(transcript);
    const key = await sharedKey(ephemeral.key, endpointPoint);
    async function direction(label) {
      const [material, iv] = await Promise.all([
        hkdf(key, salt, 'rmm-e2e-v1 k ' + label, 32),
        hkdf(key, salt, 'rmm-e2e-v1 iv ' + label, 12),
      ]);
      return { key: await aes(material), iv };
    }
    const [outbound, inbound] = await Promise.all([direction('v2a'), direction('a2v')]);
    return { outbound, inbound };
  }

  const frameHeader = (seq) => concat(Uint8Array.of(0xe0), uint64(seq));
  function frameParams(dir, header, id) {
    const iv = dir.iv.slice();
    for (let i = 0; i < 8; i++) iv[i + 4] ^= header[i + 1];
    return { name: 'AES-GCM', iv, additionalData: concat(header, utf8(id)) };
  }
  async function seal(dir, seq, id, data) {
    const header = frameHeader(seq);
    const text = typeof data === 'string';
    const payload = text ? utf8(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
    const plain = concat(Uint8Array.of(text ? 1 : 2), payload);
    const cipher = await subtle().encrypt(frameParams(dir, header, id), dir.key, plain);
    return concat(header, new Uint8Array(cipher));
  }
  async function open(dir, seq, id, data) {
    const raw = new Uint8Array(data);
    const header = frameHeader(seq);
    if (raw.length < 26 || header.some((v, i) => raw[i] !== v)) throw new Error('invalid frame sequence');
    const plaintext = new Uint8Array(await subtle().decrypt(frameParams(dir, header, id), dir.key, raw.subarray(header.length)));
    if (plaintext[0] === 1) return decoder.decode(plaintext.subarray(1));
    if (plaintext[0] === 2) return plaintext.slice(1).buffer;
    throw new Error('invalid frame type');
  }

  function connect(raw, context) {
    let keys, viewerNonce, peer, ready = false, closing = false, failed = false;
    let nextIn = 1n, nextOut = 1n, inBytes = 0, outBytes = 0;
    let input = Promise.resolve(), output = Promise.resolve();
    const maxFrame = 32 * 1024 * 1024;
    const maxQueue = 2 * maxFrame;
    const lastSequence = 0xffffffffffffffffn;
    const timeout = setTimeout(() => fail(), 60_000);
    const facade = {
      encrypted: true,
      get readyState() { return ready && !closing && raw.readyState === 1 ? 1 : closing ? 3 : 0; },
      get identity() { return ready ? { deviceKey: peer.ik, agentID: peer.agent_id } : null; },
      close() { closing = true; clearTimeout(timeout); raw.close(); },
      send(data) {
        if (this.readyState !== 1) return;
        const size = typeof data === 'string' ? data.length * 3 + 26 : data.byteLength + 26;
        outBytes += size;
        if (size > maxFrame || outBytes + raw.bufferedAmount > maxQueue) { fail(); return; }
        output = output.then(async () => {
          if (closing) return;
          if (nextOut === lastSequence) throw new Error('outbound sequence exhausted');
          const frame = await seal(keys.outbound, nextOut++, context.id, data);
          if (!closing && raw.readyState === 1) raw.send(frame);
        }).catch(fail).finally(() => { outBytes -= size; });
      },
      async flush() {
        await output;
        while (this.readyState === 1 && raw.bufferedAmount > 2 * 1024 * 1024) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        if (this.readyState !== 1) throw new Error('remote session closed');
      },
    };
    function fail() {
      if (closing) return;
      failed = true;
      facade.close();
    }
    async function receive(data) {
      if (closing) return;
      if (typeof data === 'string') {
        if (keys || !viewerNonce || data.length > 4096) throw new Error('unexpected cleartext frame');
        const packet = JSON.parse(data);
        keys = await sessionKeys(context.ephemeral, viewerNonce, packet, context);
        peer = packet;
        const confirm = await seal(keys.outbound, 0n, context.id, '{"t":"e2e_ready"}');
        if (!closing) raw.send(confirm);
        return;
      }
      if (!keys || nextIn === lastSequence) throw new Error('unexpected encrypted frame');
      const payload = await open(keys.inbound, ready ? nextIn++ : 0n, context.id, data);
      if (closing) return;
      if (!ready) {
        if (typeof payload !== 'string' || JSON.parse(payload).t !== 'e2e_ready') throw new Error('unconfirmed endpoint key');
        ready = true;
        clearTimeout(timeout);
        facade.onopen?.();
      } else {
        facade.onmessage?.({ data: payload });
      }
    }
    raw.binaryType = 'arraybuffer';
    raw.onopen = () => {
      try {
        viewerNonce = random(32);
        raw.send(JSON.stringify({ t: 'e2e_hello', v: 1, role: 'viewer', ek: context.ephemeral.pub, nonce: encode(viewerNonce) }));
      } catch (e) { fail(); }
    };
    raw.onmessage = ({ data }) => {
      const size = Math.max(26, typeof data === 'string' ? data.length * 3 : data.byteLength);
      inBytes += size;
      if (size > maxFrame || inBytes > maxQueue) { fail(); return; }
      input = input.then(() => receive(data)).catch(fail).finally(() => { inBytes -= size; });
    };
    raw.onclose = (event) => {
      closing = true;
      clearTimeout(timeout);
      facade.onclose?.({ code: event.code, cryptoFailed: failed });
    };
    raw.onerror = () => facade.onerror?.();
    return facade;
  }

  return { utf8, decoder, random, encode, decode, point, concat, uint64, tuple, fingerprint, displayFingerprint, deviceIdentity, knownDeviceKey, rememberDeviceKey, aes, expiry, keyPair, verify, sign, sharedKey, hkdf, connect };
})();

globalThis.RemoteCrypto = RemoteCrypto;
