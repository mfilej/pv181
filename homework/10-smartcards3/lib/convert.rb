module Convert
  extend self
  
  def bin_to_hex(binstr)
    binstr.unpack("H*").first
  end
  
  def hex_to_bin(hexstr)
    hexstr.gsub(/\s/,'').to_a.pack("H*")
  end
end