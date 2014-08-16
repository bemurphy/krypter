require "cutest"
require "securerandom"
require_relative "../lib/krypter"

setup do
  SecureRandom.hex(32)
end

test "encrypts and decrypts" do |secret|
  encryptor = Krypter.new(secret)

  encrypted = encryptor.encrypt("message")
  decrypted = encryptor.decrypt(encrypted)

  assert_equal("message", decrypted)
end

test "encrypt returns different ciphertexts" do |secret|
  encryptor = Krypter.new(secret)

  encrypted1 = encryptor.encrypt("message")
  encrypted2 = encryptor.encrypt("message")

  assert encrypted1 != encrypted2
end
