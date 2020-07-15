[`pure | 📦`](https://github.com/telamon/create-pure)
[`code style | standard`](https://standardjs.com/)
[![abstract-encoding](https://img.shields.io/badge/abstract--encoding-compliant-brightgreen.svg?style=flat)](https://github.com/mafintosh/abstract-encoding)

# id2

> **I**nter**d**imensional * **Id**entity = Id²

I am exploring the hypothesis that using only a signing pair as a basis for trust between two
parties it is possible to authenticate, securely communicate and eventually build full 'user account profiles'
in an technology agnostic manner.

This is a microscopic module that provides a slightly elevated API around libsodium's elliptic curve signing
cryptography but from a _user-identity_ perspective.

If you want you're welcome to use this module as simple abstraction for cryptographic signing, more information
will be added due time.



## Use

```bash
$ npm install id2
```

```js
import Identity from 'id2'
// or
// const Identity = require('id2')

const bob = Identity.generate()

sendToAlice(bob.key) // => bobPublicKey

const message = 'I allergic to carrots'
const signature = bob.sign(message)

sendToAlice(message)
sendToAlice(signature)

// Alice can now verify that the message was signed by bob using
const user = new Identity(bobPublicKey)
user.verify(message, signature) // => true
```

## API

### `const id = new Identity(key)`

- `key` Buffer|hexstring - Public 32byte or secret 64byte key.

Instantiates an identity from a public or secret key.
Omitting `key` parameter produces the same result as `Identity.generate()`

**Instance Properties**

- **hasSecret** `boolean`, `true` if the secret for this identity is known.
- **key** `Buffer` Public key
- **secretKey** `Buffer` Secret key
- **public** `Buffer` alias for `key` prop
- **secret** `Buffer` alias for `secretKey` prop

### `id.sign(message)`


Parameters:

- **message** `string|Buffer` Message to be signed

Returns `Buffer` the signature

Signs the `message` using `secretKey`,
Throws `SecretNotAvailable` error when attempting to sign a message using an identity that only
contains the public-key

### `id.verify(message, signature)`

Parameters:

- **message** `string|Buffer` Message to verify
- **signature** `Buffer` Signature

Returns `boolean`

Uses the instance public-key to verify if the signature for a given message was produced
by the secret key.

### Static Methods
### `Identity.generate()`

Returns `Identity`

Generates a new instance of an identity with a sign pair.

### `Identity.encode(id, [buffer], [offset])`
Returns `Buffer`

Encodes an Identity instance to binary form.

See [abstract-encoding](https://github.com/mafintosh/abstract-encoding) for more details

### `Identity.decode(buffer, [start], [end])`

Returns `Identity`

Decodes an Identity instance from bytes.

See [abstract-encoding](https://github.com/mafintosh/abstract-encoding) for more details

## Donations

```ad
 _____                      _   _           _
|  __ \   Help Wanted!     | | | |         | |
| |  | | ___  ___ ___ _ __ | |_| |     __ _| |__  ___   ___  ___
| |  | |/ _ \/ __/ _ \ '_ \| __| |    / _` | '_ \/ __| / __|/ _ \
| |__| |  __/ (_|  __/ | | | |_| |___| (_| | |_) \__ \_\__ \  __/
|_____/ \___|\___\___|_| |_|\__|______\__,_|_.__/|___(_)___/\___|

If you're reading this it means that the docs are missing or in a bad state.

Writing and maintaining friendly and useful documentation takes
effort and time. In order to do faster releases
I will from now on provide documentation relational to project activity.

  __How_to_Help____________________________________.
 |                                                 |
 |  - Open an issue if you have ANY questions! :)  |
 |  - Star this repo if you found it interesting   |
 |  - Fork off & help document <3                  |
 |.________________________________________________|

I publish all of my work as Libre software and will continue to do so,
drop me a penny at Patreon to help fund experiments like these.

Patreon: https://www.patreon.com/decentlabs
Discord: https://discord.gg/K5XjmZx
Telegram: https://t.me/decentlabs_se
```


## Changelog

### 1.0.0 first release

## Contributing

By making a pull request, you agree to release your modifications under the license stated in the next section.

Only change-sets by human contributors will be accepted.

## License

[AGPL-3.0-or-later](./LICENSE)

Tony Ivanov <telamohn@gmail.com> &#x1f12f; 2020
