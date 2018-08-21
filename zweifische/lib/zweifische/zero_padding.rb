module Zweifische
  class ZeroPadding
    def self.pad(num)
      0x00.chr * num
    end
  end
end
