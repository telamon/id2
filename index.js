// SPDX-License-Identifier: AGPL-3.0-or-later

/* eslint-disable camelcase */
const {
  crypto_sign_BYTES,
  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_keypair,
  crypto_sign_detached,
  crypto_sign_verify_detached
} = require('sodium-universal')

const SIZE_PUBLIC = crypto_sign_PUBLICKEYBYTES
const SIZE_SECRET = crypto_sign_SECRETKEYBYTES
/* eslint-enable camelcase */

const BLANK32 = Buffer.alloc(32).fill(0)

class Identity {
  constructor (key) {
    if (typeof key === 'string') key = Buffer.from(key, 'hex')
    // Slice off the public key from the secret
    if (key && key.length === SIZE_SECRET) {
      this.key = key.slice(32)
      this.secretKey = key
      // Set secret to null if the secret bytes are all 0x00.
      if (BLANK32.equals(key.slice(0, 32))) this.secretKey = null
    } else if (!key) {
      const tmp = Identity.generate()
      this.secretKey = tmp.secretKey
      this.key = tmp.key
    } else {
      this.key = key
    }
  }

  get hasSecret () {
    return !!this.secretKey
  }

  // public & secret aliases
  get public () { return this.key }
  set public (v) { this.key = v }
  get secret () { return this.secretKey }
  set secret (v) { this.secretKey = v }

  sign (message) {
    if (!this.hasSecret) throw new Error('SecretNotAvailable')
    const signature = Buffer.allocUnsafe(crypto_sign_BYTES)
    crypto_sign_detached(signature, message, this.secretKey)
    return signature
  }

  verify (message, signature) {
    // Attempt buffer conversion
    if (typeof signature === 'string') {
      if (signature.match(/^[A-F0-9]+$/i)) signature = Buffer.from(signature, 'hex')
      else signature = Buffer.from(signature, 'base64')
    }
    // Attempt buffer conversion for message
    if (typeof message === 'string') message = Buffer.from(message, 'utf8')
    return crypto_sign_verify_detached(signature, message, this.key)
  }

  static generate () {
    const key = Buffer.allocUnsafe(SIZE_PUBLIC)
    const secret = Buffer.allocUnsafe(SIZE_SECRET)
    crypto_sign_keypair(key, secret)
    return new Identity(secret)
  }

  static encode (id, buffer, offset = 0) {
    const sz = Identity.encodingLength(id)
    if (!buffer) {
      buffer = Buffer.alloc(sz)
      offset = 0
    }

    if (id.hasSecret) id.secretKey.copy(buffer, offset)
    else id.key.copy(buffer, offset + (SIZE_SECRET - SIZE_PUBLIC))

    Identity.encode.bytes = sz
    return buffer
  }

  static decode (buffer, offset = 0) {
    if (buffer.length - offset === SIZE_PUBLIC) {
      Identity.decode.bytes = SIZE_PUBLIC
      return new Identity(buffer.slice(offset, offset + SIZE_PUBLIC))
    } else if (buffer.length - offset < SIZE_SECRET) {
      throw new RangeError(`Not enough bytes for secret key (${buffer.length - offset} < ${SIZE_SECRET})`)
    } else {
      Identity.decode.bytes = SIZE_SECRET
      return new Identity(buffer.slice(offset, offset + SIZE_SECRET))
    }
  }

  static encodingLength (id) { return SIZE_SECRET }
}

module.exports = Identity
