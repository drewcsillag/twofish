require "test_helper"
require "known_answers"

class ZweifischeTest < Minitest::Test
  def ECB_encrypt_test(idx)
    i = ENC_TABLE_256[idx]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I1_encrypt
    ECB_encrypt_test(0)
  end

  def test_ECB_I2_encrypt
    ECB_encrypt_test(1)
  end

  def test_ECB_I3_encrypt
    ECB_encrypt_test(2)
  end

  def test_ECB_I4_encrypt
    ECB_encrypt_test(3)
  end

  def test_ECB_I5_encrypt
    ECB_encrypt_test(4)
  end

  def test_ECB_I6_encrypt
    ECB_encrypt_test(5)
  end

  def test_ECB_I7_encrypt
    ECB_encrypt_test(6)
  end

  def test_ECB_I8_encrypt
    ECB_encrypt_test(7)
  end

  def test_ECB_I9_encrypt
    ECB_encrypt_test(8)
  end

  def test_ECB_I10_encrypt
    ECB_encrypt_test(9)
  end
end
