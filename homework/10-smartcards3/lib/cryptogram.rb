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
