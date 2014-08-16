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

test "decrypt returns nil when authentication fails" do |encryptor|
  encrypted = encryptor.encrypt("message")
  separator = encryptor.instance_variable_get(:@separator)
  ciphertext, signature = encrypted.split(separator)

  message = [signature, ciphertext] * separator
  assert(encryptor.decrypt(message).nil?)

  message = [ciphertext, signature.reverse] * separator
  assert(encryptor.decrypt(message).nil?)

  message = [ciphertext.reverse, signature] * separator
  assert(encryptor.decrypt(message).nil?)

  message = [ciphertext.reverse, signature.reverse] * separator
  assert(encryptor.decrypt(message).nil?)
end
