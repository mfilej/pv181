# The TrippleDES class is a wrapper around the OpenSSL library
# that supports ecb and cbc 3DES encoding.
#
# Sample usage:
#   TrippleDES.encrypt :ecb do |c|
#     c.key = "KEY GOES HERE"
#     c.data = "DATA TO ENCRYPT GOES HERE"
#   end


require 'openssl'
require 'convert'

class TrippleDES

  MODES = {
    :cbc => 'des3',
    :ecb => 'des-ede3'
  }
  
  attr_accessor :key, :data
  attr_reader :mode
  
  def self.encrypt(mode, &block)
    raise ArgumentError unless [:ecb, :cbc].include?(mode)
    new(mode, &block).encrypt!
  end
  
  def initialize(mode)
    @mode = mode
    yield(self)
  end
  
  def encrypt!
    return unless key and data
    bin_data = Convert.hex_to_bin(data)
    bin_result = cipher(key, bin_data)
    Convert.bin_to_hex(bin_result)
  end
  
  protected
  
  def cipher(key, data)
    return unless key && data
    cipher = OpenSSL::Cipher::Cipher.new(MODES[mode])
    cipher.encrypt
    cipher.key = key
    cipher.iv = "\0\0\0\0\0\0\0\0" if mode == :cbc
    cipher.update(data)
    cipher.final
  end
  
end