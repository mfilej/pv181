require 'tripple_des'

class Cryptogram
  
  attr_accessor :host, :card, :enc_key, :mac_key

  def initialize
    yield(self) if block_given?
  end

  def derivation_data
    return unless valid?
    card[8,8] + host[0,8] + card[0,8] + host[8,8]
  end
  
  def valid?
    host && card
  end
  
  def session_enc_key
    TrippleDES.encrypt :ecb do |c|
      c.key = enc_key
      c.data = derivation_data
    end
  end
  
  def session_mac_key
    TrippleDES.encrypt :ecb do |c|
      c.key = mac_key
      c.data = derivation_data
    end
  end
  
  def host_cryptogram_base
    valid? and pad(card + host)
  end
  
  def card_cryptogram_base
    valid? and pad(host + card)
  end
  
  def host_cryptogram
    TrippleDES.encrypt :cbc do |c|
      c.key = session_enc_key
      c.data = host_cryptogram_base
    end
  end
  
  def card_cryptogram
    TrippleDES.encrypt :cbc do |c|
      c.key = session_enc_key
      c.data = card_cryptogram_base
    end
  end
  
  private
  
  def pad(hexstr, bytes = 24)
    length = bytes * 2
    padding_len = length - hexstr.length - 1
    "#{hexstr}8#{ "0" * padding_len}"
  end
  
end


# deriv = "a5a6a7a801020304a1a2a3a405060708"
# deriv_bin = hex_to_bin(deriv)
# 
# key = "CA CA CA CA CA CA CA CA 2D 2D 2D 2D 2D 2D 2D 2D".gsub(' ', '').downcase
# key_bin = hex_to_bin(key)
# 
# # File.open("../DERIV", "wb") { |f| f << deriv_bin }
# # File.open("../KEY", "wb")   { |f| f << key_bin }
# 
# base = "A1A2A3A4A5A6A7A801020304050607088000000000000000"
# base_bin = hex_to_bin(base)
# File.open("../BASE", "wb")   { |f| f << base_bin }
# 
