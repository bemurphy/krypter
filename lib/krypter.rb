require "base64"
require "openssl"

class Krypter
  def initialize(secret, cipher: "aes-256-cbc", hmac: "SHA1", separator: "--")
    @secret = secret
    @cipher = cipher
    @hmac = hmac
    @separator = separator
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

  def _encrypt(message)
    cipher = OpenSSL::Cipher.new(@cipher)
    cipher.encrypt
    cipher.key = @secret

    iv = cipher.random_iv
    encrypted = cipher.update(message)
    encrypted << cipher.final

    return sprintf("%s%s%s", encrypted, @separator, iv)
  end

  def _decrypt(ciphertext)
    encrypted, iv = ciphertext.split(@separator)

    decipher = OpenSSL::Cipher.new(@cipher)
    decipher.decrypt
    decipher.key = @secret
    decipher.iv = iv

    decrypted = decipher.update(encrypted)
    decrypted << decipher.final

    return decrypted
  end

  def sign(value)
    encoded = Base64.strict_encode64(value)
    signature = hmac(encoded)

    return sprintf("%s%s%s", encoded, @separator, signature)
  end

  def verify(message)
    value, signature = message.split(@separator)

    if value && signature && secure_compare(signature, hmac(value))
      return Base64.strict_decode64(value)
    else
      return nil
    end
  end

  def hmac(message)
    return OpenSSL::HMAC.hexdigest(@hmac, @secret, message)
  end

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
