Gem::Specification.new do |s|
  s.name = "krypter"
  s.version = ""
  s.summary = ""
  s.description = s.summary
  s.authors = ["Francesco Rodríguez"]
  s.email = ["frodsan@me.com"]
  s.homepage = "https://github.com/frodsan/krypter"
  s.license = "MIT"

  s.files = `git ls-files`.split("\n")

  s.add_development_dependency "cutest"
end
