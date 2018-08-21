
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "zweifische/version"

Gem::Specification.new do |spec|
  spec.name          = "zweifische"
  spec.version       = Zweifische::VERSION
  spec.authors       = ["Nurahmadie"]
  spec.email         = ["nurahmadie@gmail.com"]

  spec.summary       = %q{Ruby binding for @drewcsillag twofish implementation}
  spec.homepage      = "https://github.com/fudanchii/twofish"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rake-compiler", "> 0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
