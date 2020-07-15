const test = require('tape')
const Identity = require('.')

test('generate serializable identity', t => {
  const id = Identity.generate()
  t.ok(id.hasSecret, 'Should have generated a pair')
  const serialized = Identity.encode(id)
  t.equals(serialized.length, 64)
  t.ok(serialized.equals(id.secretKey), 'secret should be packed')
  const id2 = Identity.decode(serialized)
  t.ok(id2.hasSecret, 'pair deserialized')
  t.ok(id.secretKey.equals(id2.secretKey), 'secret correctly deserialized')
  t.ok(id.key.equals(id2.key), 'public correctly deserialized')
  t.end()
})

test('Serialize pubkey identity', t => {
  // In order to be abstract encoding compliant we always
  // return a copy of the secret key that is 64 bytes.
  // even when the secret is missing we return a 64 byte buffer.
  const id = Identity.generate()
  id.secretKey = null
  t.notOk(id.hasSecret, 'Secret removed')
  const serialized = Identity.encode(id)
  t.equals(serialized.length, 64)
  t.ok(serialized.slice(32).equals(id.key), 'pk should be packed')
  const a = Identity.decode(serialized)
  const b = new Identity(serialized)
  t.notOk(a.hasSecret, 'A-no secret')
  t.notOk(b.hasSecret, 'B-no secret')
  t.ok(a.key.equals(id.key))
  t.ok(b.key.equals(id.key))
  t.end()
})

test('produce and validate signatures', t => {
  const msg = Buffer.from('Roses are red, violets are blue')
  const id = Identity.generate()
  const signature = id.sign(msg)
  t.ok(id.verify(msg, signature), 'Signature verified')
  t.end()
})
