Gem::Specification.new do |s|
  s.name = "krypter"
  s.version = "1.0.0"
  s.summary = "Encrypts and signs messages."
  s.description = s.summary
  s.authors = ["Francesco Rodríguez", "Mayn Kjær"]
  s.email = ["frodsan@me.com", "mayn.kjaer@gmail.com"]
  s.homepage = "https://github.com/harmoni/krypter"
  s.license = "MIT"

  s.files = `git ls-files`.split("\n")

  s.add_development_dependency "cutest"
end
