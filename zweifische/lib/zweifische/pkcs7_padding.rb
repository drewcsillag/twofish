module Zweifische
  class PKCS7Padding
    def self.pad(num)
      num.chr * num
    end
  end
end
