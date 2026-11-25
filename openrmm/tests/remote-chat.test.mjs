import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const source = ['remote-crypto', 'remote-chat'].map((file) =>
  '{\n' + readFileSync(new URL('../src/' + file + '.jsx', import.meta.url), 'utf8') + '\n}').join('\n');
const { RemoteCrypto, RemoteChat } = runInNewContext(source + '\n({ RemoteCrypto: globalThis.RemoteCrypto, RemoteChat: globalThis.RemoteChat });', {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob,
});

async function conversation() {
  const { pub: deviceKey } = await RemoteCrypto.keyPair('ECDSA');
  const identity = { agentID: 'test-endpoint', deviceKey };
  const tech = await RemoteChat.create(identity.agentID, identity.deviceKey);
  const expires = new Date(Date.now() + 60_000).toISOString();
  async function invite(requestId, name) {
    const keys = await RemoteChat.guestKeys();
    const guest = { keys, requestId, fingerprint: await RemoteCrypto.fingerprint(deviceKey) };
    const share = { id: requestId, agent_id: identity.agentID, guest_name: name, expires_at: expires, ...keys.publicKeys };
    const status = { ...await RemoteChat.wrap(tech, share), expires_at: expires };
    return { guest, share, status, room: await RemoteChat.unwrap(status, guest, identity) };
  }
  return { tech, identity, invite };
}

test('approved guests and technician share encrypted chat with distinct signed identities', async () => {
  const { tech, invite } = await conversation();
  const [alice, bob] = await Promise.all([invite('share-1', 'Alice'), invite('share-2', '봅')]);
  const techLine = await RemoteChat.encrypt(tech, 'Hello');
  assert.ok(!JSON.stringify(techLine).includes('Hello'));
  assert.equal((await RemoteChat.decrypt(alice.room, techLine)).from, 'tech');
  const reply = await RemoteChat.encrypt(alice.room, RemoteChat.cleanText('Olá\n 👋'));
  const shown = await RemoteChat.decrypt(bob.room, reply);
  assert.deepEqual({ ...shown }, { from: 'guest', name: 'Alice', text: 'Olá 👋' });
  assert.equal(await RemoteChat.decrypt(bob.room, reply), null, 'replayed line');
  tech.revoked = new Set(['share-1']);
  assert.equal(await RemoteChat.decrypt(tech, reply), null, 'revoked guest');
});

test('guest wrapping is bound to the approved invite, endpoint and expiry', async () => {
  const { tech, identity, invite } = await conversation();
  const [alice, bob] = await Promise.all([invite('share-1', 'Alice'), invite('share-2', 'Bob')]);
  await assert.rejects(RemoteChat.unwrap(alice.status, bob.guest, identity));
  await assert.rejects(RemoteChat.unwrap(alice.status, { ...alice.guest, requestId: bob.guest.requestId }, identity));
  await assert.rejects(RemoteChat.unwrap(alice.status, alice.guest, { ...identity, agentID: 'wrong-device' }));
  await assert.rejects(RemoteChat.unwrap({ ...alice.status, expires_at: '2000-01-01T00:00:00Z' }, alice.guest, identity));

  const forged = await RemoteChat.encrypt({ ...alice.room, grant: undefined }, 'Forged technician');
  assert.equal(await RemoteChat.decrypt(tech, forged), null);
  await assert.rejects(RemoteChat.encrypt({ ...alice.room, grant: { ...alice.room.grant, exp: 1 } }, 'Expired'));
});
