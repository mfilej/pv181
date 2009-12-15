require 'test/unit'
require 'cryptogram'

class CryptogramsTest < Test::Unit::TestCase

  def setup
    @cryptogram = Cryptogram.new do |c|
      c.host = "0102030405060708"
      c.card = "a1a2a3a4a5a6a7a8"
      c.enc_key = "cacacacacacacaca2d2d2d2d2d2d2d2d"
      c.mac_key = "2d2d2d2d2d2d2d2dcacacacacacacaca"
    end
  end

  def test_should_assign_attributes
    assert_equal "0102030405060708", @cryptogram.host
    assert_equal "a1a2a3a4a5a6a7a8", @cryptogram.card
    assert_equal "cacacacacacacaca2d2d2d2d2d2d2d2d", @cryptogram.enc_key
    assert_equal "2d2d2d2d2d2d2d2dcacacacacacacaca", @cryptogram.mac_key
  end

  def test_should_combine_challenges
    actual   = @cryptogram.derivation_data
    expected = "a5a6a7a801020304a1a2a3a405060708"
    assert_equal expected, actual
  end
  
  def test_should_calculate_enc_session_key
    actual = @cryptogram.session_enc_key
    expected = "73644da1e5bcbf93fb792988cab34253"
    assert_equal expected, actual
  end
  
  def test_should_calculate_mac_session_key
    actual = @cryptogram.session_mac_key
    expected = "7bd9b6311e3115692d94f3fb63cc81d6"
    assert_equal expected, actual
  end
  
  def test_should_calculate_base_for_host_cryptogram
    actual   = @cryptogram.host_cryptogram_base
    expected = "a1a2a3a4a5a6a7a801020304050607088000000000000000"
    assert_equal expected, actual
  end
  
  def test_should_calculate_base_for_card_cryptogram
    actual   = @cryptogram.card_cryptogram_base
    expected = "0102030405060708a1a2a3a4a5a6a7a88000000000000000"
    assert_equal expected, actual
  end
  
  def test_should_calculate_host_cryptogram
    stub_session_enc_key
    actual   = @cryptogram.host_cryptogram
    expected = "c4d55a919e522ecb"
    assert_equal expected, actual
  end
  
  def test_should_calculate_card_cryptogram
    stub_session_enc_key    
    actual   = @cryptogram.card_cryptogram
    expected = "e6276af834a45b26"
    assert_equal expected, actual
  end
  
  def test_should_not_calculate_derivation_data_without_challenges
    assert_nil Cryptogram.new.derivation_data
  end
  
  def test_should_not_calculate_bases_without_challenges
    assert_nil Cryptogram.new.host_cryptogram_base
    assert_nil Cryptogram.new.card_cryptogram_base
  end
  
  def stub_session_enc_key
    @cryptogram.instance_eval do
      def session_enc_key
        "73644da1e5bcbf93fb792988cab34253"
      end
    end
  end
end