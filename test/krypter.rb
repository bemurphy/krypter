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
