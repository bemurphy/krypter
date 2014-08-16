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

test "decrypt returns nil when using bad signatures" do |encryptor|
  encrypted = encryptor.encrypt("message")
  signature_length = encryptor.send(:signature_length)

  decoded = encrypted.unpack("m0").first
  signature = decoded[0, signature_length]
  ciphertext = decoded[signature_length .. -1]

  message = [ciphertext + signature].pack("m0")
  assert(encryptor.decrypt(message).nil?)

  message = [signature.reverse + ciphertext].pack("m0")
  assert(encryptor.decrypt(message).nil?)

  message = [ciphertext.reverse + signature.reverse].pack("m0")
  assert(encryptor.decrypt(message).nil?)
end
