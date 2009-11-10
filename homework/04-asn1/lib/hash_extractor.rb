require 'openssl'
require 'hash_extractor'
require 'file_to_hash'

# HashExtractor extracts file hashes from an ASN.1 file of predefined
# format. See HashExtractor#hashes for return values.

class HashExtractor

  def initialize(data)
    @data = data
  end
  
  # returns the root element, parsed from given ASN.1 data
  def root
    @root ||= OpenSSL::ASN1.decode(@data)
  end
  
  # returns an array of [index, hash] pairs where
  # index is the index of the file and
  # hash is it's hash
  #
  #   sample output:
  #   [
  #     [1, "913879bda1b07f95ba628f7b2e9b816fdaf592f2"],
  #     [2, "bb74ede2b6eb9e13527fb078dd979bb542e2fa18"]
  #   ]
  def hashes
    root.value[2].value.map do |element|
      index = element.value[0].value
      hash = element.value[1].value.unpack("H*").first
      [index, hash]
    end
  end

end
