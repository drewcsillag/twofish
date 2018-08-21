module Zweifische
  class Cipher256ecb
    def encrypt_final(plain_text, pad_with: nil)
      if padding && padding.respond_to?(:pad)
        c_encrypt_final_with_pad(plain_text, pad_with)
      else
        c_encrypt_final(plain_text)
      end
    end

    alias_method :encrypt, :encrypt_final
    alias_method :decrypt_final, :c_decrypt_final
    alias_method :decrypt, :c_decrypt_final
  end
end
