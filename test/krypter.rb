require "cutest"
require "securerandom"
require_relative "../lib/krypter"

setup do
  Krypter.new(SecureRandom.hex(32))
end

test "encrypts and decrypts" do |encryptor|
  encrypted = encryptor.encrypt("message")
  decrypted = encryptor.decrypt(encrypted)

  assert_equal("message", decrypted)
end

test "encrypt returns different ciphertexts" do |encryptor|
  encrypted1 = encryptor.encrypt("message")
  encrypted2 = encryptor.encrypt("message")

  assert encrypted1 != encrypted2
end

test "wrong signature" do |encryptor|
  encrypted = encryptor.encrypt("message")
  separator = encryptor.instance_variable_get(:@separator)
  ciphertext, signature = encrypted.split(separator)

  message = [signature, ciphertext] * separator
  assert_raise(Krypter::InvalidSignature) do
    encryptor.decrypt(message)
  end

  message = [ciphertext, signature.reverse] * separator
  assert_raise(Krypter::InvalidSignature) do
    encryptor.decrypt(message)
  end

  message = [ciphertext.reverse, signature] * separator
  assert_raise(Krypter::InvalidSignature) do
    encryptor.decrypt(message)
  end

  message = [ciphertext.reverse, signature.reverse] * separator
  assert_raise(Krypter::InvalidSignature) do
    encryptor.decrypt(message)
  end
end

test "tampered data" do |encryptor|
  encrypted = encryptor.encrypt("message")
  separator = encryptor.instance_variable_get(:@separator)
  ciphertext, iv = encryptor.send(:verify, encrypted).split(separator)

  message = encryptor.send(:sign, [iv, ciphertext] * separator)
  assert_raise(Krypter::InvalidMessage) do
    encryptor.decrypt(message)
  end

  message = encryptor.send(:sign, [ciphertext, iv.reverse] * separator)
  assert_raise(Krypter::InvalidMessage) do
    encryptor.decrypt(message)
  end

  message = encryptor.send(:sign, [ciphertext.reverse, iv] * separator)
  assert_raise(Krypter::InvalidMessage) do
    encryptor.decrypt(message)
  end

  message = encryptor.send(:sign, [ciphertext.reverse, iv.reverse] * separator)
  assert_raise(Krypter::InvalidMessage) do
    encryptor.decrypt(message)
  end
end
