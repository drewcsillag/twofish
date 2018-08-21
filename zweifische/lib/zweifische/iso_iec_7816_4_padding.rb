module Zweifische
  class ISOIEC78164Padding
    def self.pad(num)
      0x80.chr + (0x00.chr * (num - 1))
    end
  end
end
