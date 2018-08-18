require "test_helper"
require "known_answers"

class ZweifischeTest < Minitest::Test
  def test_ECB_I1_encrypt
    i = ENC_TABLE_256[0]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I2_encrypt
    i = ENC_TABLE_256[1]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I3_encrypt
    i = ENC_TABLE_256[2]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I4_encrypt
    i = ENC_TABLE_256[3]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I5_encrypt
    i = ENC_TABLE_256[4]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I6_encrypt
    i = ENC_TABLE_256[5]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I7_encrypt
    i = ENC_TABLE_256[6]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I8_encrypt
    i = ENC_TABLE_256[7]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I9_encrypt
    i = ENC_TABLE_256[8]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end

  def test_ECB_I10_encrypt
    i = ENC_TABLE_256[9]
    tf = Zweifische::Cipher256ecb.new(hexify i[:KEY])
    assert_equal tf.encrypt_final(hexify(i[:PT])), hexify(i[:CT])
  end
end
