require "base64"
require "openssl"

class Krypter
  def initialize(secret, cipher: "aes-256-cbc", digest: "SHA256", separator: "--")
    @cipher = cipher
    @digest = digest
    @separator = separator
    @encrypt_secret = derive_key(secret, "encryption key")
    @sign_secret = derive_key(secret, "signin key")
  end

  def encrypt(message)
    return sign(_encrypt(message))
  end

  def decrypt(message)
    ciphertext = verify(message)

    if ciphertext
      return _decrypt(ciphertext)
    else
      return nil
    end
  end

  private

  def derive_key(secret, salt)
    digest = OpenSSL::Digest.new(@digest)
    length = digest.digest_length

    return OpenSSL::PKCS5.pbkdf2_hmac(secret, salt, 1000, length, digest)
  end

  def _encrypt(message)
    cipher = OpenSSL::Cipher.new(@cipher)
    cipher.encrypt
    cipher.key = @encrypt_secret

    iv = cipher.random_iv
    encrypted = cipher.update(message)
    encrypted << cipher.final

    return sprintf("%s%s%s", encrypted, @separator, iv)
  end

  def _decrypt(ciphertext)
    encrypted, iv = ciphertext.split(@separator)

    decipher = OpenSSL::Cipher.new(@cipher)
    decipher.decrypt
    decipher.key = @encrypt_secret
    decipher.iv = iv

    decrypted = decipher.update(encrypted)
    decrypted << decipher.final

    return decrypted
  rescue OpenSSL::Cipher::CipherError
    return nil
  end

  def sign(value)
    encoded = Base64.strict_encode64(value)
    signature = hmac(encoded)

    return sprintf("%s%s%s", encoded, @separator, signature)
  end

  def hmac(message)
    return OpenSSL::HMAC.hexdigest(@digest, @sign_secret, message)
  end

  def verify(message)
    value, signature = message.split(@separator)

    if value && signature && secure_compare(signature, hmac(value))
      return Base64.strict_decode64(value)
    else
      return nil
    end
  end

  # Prevent timing attacks: http://codahale.com/a-lesson-in-timing-attacks/.
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
