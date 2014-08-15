require "openssl"
require "base64"

class Krypter
  def initialize(secret, cipher: "aes-256-cbc", digest: "SHA1")
    @secret = secret
    @cipher = cipher
    @digest = digest
  end

  def encrypt(message)
    ciphertext = _encrypt(message)
    signature = sign(ciphertext)

    return [signature + ciphertext].pack("m0")
  end

  def decrypt(message)
    decoded = message.unpack("m0").first
    signature = decoded[0, signature_length]
    ciphertext = decoded[signature_length .. -1]

    if verify(signature, ciphertext)
      return _decrypt(ciphertext)
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

    return iv + encrypted
  end

  def _decrypt(ciphertext)
    decipher = OpenSSL::Cipher.new(@cipher)
    decipher.decrypt
    decipher.key = @secret
    decipher.iv = ciphertext[0, decipher.iv_len]

    encrypted = ciphertext[decipher.iv_len .. -1]
    decrypted = decipher.update(encrypted)
    decrypted << decipher.final

    return decrypted
  end

  def sign(message)
    return OpenSSL::HMAC.digest(@digest, @secret, message)
  end

  def signature_length
    return OpenSSL::Digest.new(@digest).size
  end

  def verify(signature, message)
    return secure_compare(signature, sign(message))
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
