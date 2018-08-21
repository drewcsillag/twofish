module Zweifische
  class AnsiX923Padding
    def self.pad(num)
      0x00.chr * (num - 1) + num.chr
    end
  end
end
