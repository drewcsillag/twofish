module Zweifische
  class ISO10126Padding
    def self.pad(num)
      Random.new.bytes(num - 1) + num.chr
    end
  end
end
