$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "zweifische"

require "minitest/autorun"

def hexify(input)
  [input].pack("H*").encode(Encoding::ASCII_8BIT)
end
