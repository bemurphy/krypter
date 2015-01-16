require "base64"
require "openssl"

class Krypter
  InvalidSignature = Class.new(StandardError)
  InvalidMessage = Class.new(StandardError)

  def initialize(secret, cipher: "aes-256-cbc", digest: "SHA256", separator: "--")
    @cipher = cipher
    @digest = digest
    @separator = separator
    @encrypt_secret = hmac(secret, "encryption key")
    @sign_secret = hmac(secret, "signin key")
  end

  def encrypt(message)
    return sign(_encrypt(message))
  end

  def decrypt(message)
    ciphertext = verify(message)

    if ciphertext
      return _decrypt(ciphertext)
    end
  end

  private

  def hmac(secret, message)
    return OpenSSL::HMAC.hexdigest(@digest, secret, message)
  end

  def _encrypt(message)
    cipher = OpenSSL::Cipher.new(@cipher)
    cipher.encrypt
    cipher.key = @encrypt_secret

    iv = cipher.random_iv
    ciphertext = cipher.update(message)
    ciphertext << cipher.final

    return [ciphertext, iv].join(@separator)
  end

  def _decrypt(encrypted)
    ciphertext, iv = encrypted.split(@separator)

    decipher = OpenSSL::Cipher.new(@cipher)
    decipher.decrypt
    decipher.key = @encrypt_secret
    decipher.iv = iv

    decrypted = decipher.update(ciphertext)
    decrypted << decipher.final

    return decrypted
  rescue OpenSSL::Cipher::CipherError
    raise InvalidMessage
  end

  def sign(value)
    encoded = Base64.strict_encode64(value)
    signature = authenticate(encoded)

    return [encoded, signature].join(@separator)
  end

  def authenticate(message)
    return hmac(@sign_secret, message)
  end

  def verify(message)
    value, signature = message.split(@separator)
    ==

    if value && signature && secure_compare(signature, authenticate(value))
      return Base64.strict_decode64(value)
    else
      raise InvalidSignature
    end
  end

  # Prevents timing attacks: http://codahale.com/a-lesson-in-timing-attacks/.
  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    cmp = b.bytes
    result = 0

    a.bytes.each_with_index do |char, index|
      result |= char ^ cmp[index]
    end

    return result == 0
  end
end
