require "test_helper"
require "known_answers"

class Zweifische128ECBTest < Minitest::Test
  def ECB_encrypt_test(idx)
    i = ENC_TABLE_128[idx]
    tf = Zweifische::Cipher128ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt(hexify(i[:PT])), hexify(i[:CT])
  end

  def ECB_decrypt_test(idx)
    i = ENC_TABLE_128[idx]
    tf = Zweifische::Cipher128ecb.new(hexify i[:KEY])
    assert_equal tf.decrypt(hexify(i[:CT])), hexify(i[:PT])
  end

  (1..10).each do |i|
    class_eval <<-EODEF
    def test_ECB_I#{i}_encrypt
      ECB_encrypt_test(#{i - 1})
    end

    def test_ECB_I#{i}_decrypt
      ECB_decrypt_test(#{i - 1})
    end
    EODEF
  end
end
