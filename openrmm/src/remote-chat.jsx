// A remote desktop chat room spans the technician's and their guests' relays.
// It uses a separate key so sharing the room never shares desktop session keys.
const RemoteChat = (() => {
  const { utf8, decoder, random, encode, decode, point, concat, uint64, tuple,
    fingerprint, aes, expiry, keyPair, verify, sign, sharedKey, hkdf } = globalThis.RemoteCrypto;
  const curve = (name) => ({ name, namedCurve: 'P-256' });
  const subtle = () => globalThis.crypto.subtle;
  const clean = (raw, max) => Array.from(raw.replace(/\p{White_Space}+/gu, ' ')
    .replace(/[^\p{L}\p{M}\p{N}\p{P}\p{S} ]|\uFFFD/gu, '').replace(/ +/g, ' ').trim()).slice(0, max).join('').trim();
  const cleanText = (raw) => clean(raw, 1000);

  async function guestKeys() {
    const [wrap, signing] = await Promise.all([keyPair('ECDH', true), keyPair('ECDSA', true)]);
    const [wrapKey, signKey] = await Promise.all([
      subtle().exportKey('jwk', wrap.key), subtle().exportKey('jwk', signing.key),
    ]);
    return { wrapKey, signKey, publicKeys: { guest_public_key: wrap.pub, guest_sign_key: signing.pub } };
  }

  const grantBytes = (grant) => concat(tuple('rmm-chat-grant-v1', grant.kid, grant.agent_id,
    grant.share_id, grant.name, point(grant.guest_sign_pub)), uint64(grant.exp));
  const certBytes = (cert) => tuple('rmm-chat-user-v1', cert.kid, cert.agent_id, point(cert.user_pub));
  const msgBytes = (room, from, name, text, seq) => concat(tuple('rmm-chat-msg-v2', room.kid, room.agentID, from, name, text), uint64(seq));
  const chatAAD = (room) => tuple('rmm-e2e-chat-v1', room.kid, room.agentID);
  const gcm = (iv, aad) => ({ name: 'AES-GCM', iv, additionalData: aad });

  const counterKey = (requestID) => 'rmm-guest-chat:' + requestID;
  const newCounters = (kid) => ({ kid, sent: 0, received: [] });

  function roomCounters(room) {
    if (!room.requestID) return room.counters;
    const counters = JSON.parse(globalThis.sessionStorage.getItem(counterKey(room.requestID)) || 'null');
    if (!counters || counters.kid !== room.kid) throw new Error('chat epoch changed');
    return counters;
  }

  function saveCounters(room, counters) {
    if (room.requestID) globalThis.sessionStorage.setItem(counterKey(room.requestID), JSON.stringify(counters));
  }

  function forget(requestID) {
    if (requestID) globalThis.sessionStorage.removeItem(counterKey(requestID));
  }

  async function create(agentID, deviceKey) {
    const material = random(32);
    const signing = await keyPair('ECDSA');
    const kid = encode(random(16));
    return { kid, key: await aes(material), material, signing, techPub: signing.pub, agentID, deviceKey, counters: newCounters(kid) };
  }

  async function userCert(room, userPub) {
    const cert = { kid: room.kid, agent_id: room.agentID, user_pub: userPub };
    return { ...cert, sig: await sign(room.signing.key, certBytes(cert)) };
  }

  async function wrapCipher(privateKey, peer, publicPoint, iv) {
    const shared = await sharedKey(privateKey, peer);
    const key = await aes(await hkdf(shared, publicPoint, 'rmm-chat-wrap-v1', 32));
    return { key, params: gcm(iv, concat(utf8('rmm-chat-wrap-v1\0'), publicPoint)) };
  }

  async function wrap(room, guest) {
    const grant = {
      kid: room.kid, agent_id: room.agentID, share_id: guest.id, name: clean(guest.guest_name, 60),
      guest_sign_pub: guest.guest_sign_key, exp: Math.floor(Date.parse(guest.expires_at) / 1000),
    };
    if (guest.agent_id !== room.agentID || !grant.name || !expiry(grant.exp)) throw new Error('invalid guest');
    grant.sig = await sign(room.signing.key, grantBytes(grant));
    const ephemeral = await keyPair('ECDH');
    const iv = random(12);
    const { key, params } = await wrapCipher(ephemeral.key, point(guest.guest_public_key), point(ephemeral.pub), iv);
    const contents = {
      v: 1, kid: room.kid, k: encode(room.material), tech_pub: room.techPub,
      agent_id: room.agentID, share_id: guest.id, name: grant.name, exp: grant.exp, grant, dev_ik: room.deviceKey,
    };
    const ct = await subtle().encrypt(params, key, utf8(JSON.stringify(contents)));
    const blob = { v: 1, epk: ephemeral.pub, iv: encode(iv), ct: encode(new Uint8Array(ct)) };
    return { chat_key_id: room.kid, wrapped_chat_key: encode(utf8(JSON.stringify(blob))) };
  }

  async function validGrant(room, grant) {
    return grant && grant.kid === room.kid && grant.agent_id === room.agentID && grant.share_id &&
      grant.name && clean(grant.name, 60) === grant.name && expiry(grant.exp) &&
      await verify(room.techPub, grantBytes(grant), grant.sig);
  }

  async function unwrap(status, guest, identity) {
    if (!status.wrapped_chat_key || status.wrapped_chat_key.length > 4096) throw new Error('invalid sealed room');
    const blob = JSON.parse(decoder.decode(decode(status.wrapped_chat_key)));
    if (blob.v !== 1) throw new Error('invalid sealed room');
    const privateKey = await subtle().importKey('jwk', guest.keys.wrapKey, curve('ECDH'), false, ['deriveBits']);
    const publicPoint = point(blob.epk);
    const { key, params } = await wrapCipher(privateKey, publicPoint, publicPoint, decode(blob.iv, 12));
    const contents = JSON.parse(decoder.decode(await subtle().decrypt(params, key, decode(blob.ct))));
    const room = { kid: contents.kid, agentID: contents.agent_id, techPub: contents.tech_pub, requestID: guest.requestId };
    const grant = contents.grant;
    if (contents.v !== 1 || !room.kid || room.kid !== status.chat_key_id ||
        room.agentID !== identity.agentID || contents.dev_ik !== identity.deviceKey ||
        await fingerprint(contents.dev_ik) !== guest.fingerprint || contents.share_id !== guest.requestId ||
        contents.exp !== Math.floor(Date.parse(status.expires_at) / 1000) ||
        !await validGrant(room, grant) || grant.share_id !== guest.requestId ||
        grant.guest_sign_pub !== guest.keys.publicKeys.guest_sign_key || contents.name !== grant.name ||
        contents.exp !== grant.exp) throw new Error('room does not match the approved invitation');
    room.key = await aes(decode(contents.k, 32));
    room.signing = { key: await subtle().importKey('jwk', guest.keys.signKey, curve('ECDSA'), false, ['sign']) };
    room.grant = grant;
    const old = JSON.parse(globalThis.sessionStorage.getItem(counterKey(guest.requestId)) || 'null');
    if (old?.kid !== room.kid) saveCounters(room, newCounters(room.kid));
    return room;
  }

  async function encrypt(room, text) {
    const grant = room.grant;
    if (grant && !expiry(grant.exp)) throw new Error('chat invitation expired');
    const from = grant ? 'guest' : 'tech';
    const name = grant?.name || '';
    const counters = roomCounters(room);
    const seq = counters.sent + 1;
    if (!Number.isSafeInteger(seq) || seq < 1) throw new Error('invalid chat sequence');
    counters.sent = seq;
    saveCounters(room, counters);
    const sig = await sign(room.signing.key, msgBytes(room, from, name, text, seq));
    const iv = random(12);
    const ct = await subtle().encrypt(gcm(iv, chatAAD(room)), room.key, utf8(JSON.stringify({ from, name, text, seq, sig, grant })));
    return { t: 'e2e_chat', v: 1, kid: room.kid, iv: encode(iv), ct: encode(new Uint8Array(ct)) };
  }

  async function decrypt(room, envelope, source) {
    if (envelope.v !== 1 || envelope.kid !== room.kid) return null;
    const { from, text, seq, sig, grant, user_cert: cert } = JSON.parse(decoder.decode(await subtle().decrypt(
      gcm(decode(envelope.iv, 12), chatAAD(room)), room.key, decode(envelope.ct))));
    if (typeof text !== 'string' || !text || cleanText(text) !== text || !Number.isSafeInteger(seq) || seq < 1 ||
        (source && (source.from !== from || (from === 'guest' && source.share_id !== grant?.share_id)))) return null;
    let name = '', pub = room.techPub;
    if (from === 'guest') {
      if (!await validGrant(room, grant) || room.revoked?.has(grant.share_id)) return null;
      name = grant.name;
      pub = grant.guest_sign_pub;
    } else if (from === 'user') {
      if (!cert || cert.kid !== room.kid || cert.agent_id !== room.agentID ||
          !await verify(room.techPub, certBytes(cert), cert.sig)) return null;
      pub = cert.user_pub;
    } else if (from !== 'tech') return null;
    if (!await verify(pub, msgBytes(room, from, name, text, seq), sig)) return null;
    const counters = roomCounters(room);
    const sender = counters.received.find((entry) => entry[0] === pub);
    if (sender) {
      if (seq <= sender[1]) return null;
      sender[1] = seq;
    } else {
      if (counters.received.length >= 256) return null;
      counters.received.push([pub, seq]);
    }
    saveCounters(room, counters);
    return { from, name, text };
  }

  return { cleanText, guestKeys, create, userCert, wrap, unwrap, encrypt, decrypt, forget };
})();

globalThis.RemoteChat = RemoteChat;
