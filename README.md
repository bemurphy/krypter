krypter
=======

Encrypts messages with authentication.

Usage
-----

Pass a secret token. This must be at least 32 bytes
long and should be really random. You can generate
a random secret with `SecureRandom.hex(32)`.

```ruby
require "securerandom"
require "krypter"

secret = SecureRandom.hex(32)
encryptor = Krypter.new(secret)
encrypted = encryptor.encrypt("message")
encryptor.decrypt(encrypted) == "message"
# => true

# If the message is modified, returns nil:
encryptor.decrypt("modified")
# => nil
```

By default, the messages are encrypted with 256-bit AES in CBC mode
(with random IV). The encrypted message is then signed with HMAC-SHA256,
to prevent tampering and chosen ciphertext attacks.

The defaults can be changed when instantiating the encryptor object.

```ruby
encryptor = Encryptor.new(secret,
  cipher: "aes-256-cbc",
  digest: "SHA256",
  separator: "--"
)
```

Installation
------------

```
$ gem install krypter
```
