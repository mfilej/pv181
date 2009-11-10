module Padding
  class PKCS < Base
    def pad
      STDOUT.tap do |out|
        [ base16(data),
          prefix, block_type, padding_string, suffix,
          hash_alg_id, hash ].each { |part| out << part }
      end 
    end
    
    def prefix
      "00"
    end
    
    def block_type
      "01"
    end
    
    def padding_string
      "".tap { |out| octets_to_pad.times { out << "ff" } }
    end
    
    def suffix
      prefix
    end
    
    def hash_alg_id
      "8004"
    end
    
    def octets_to_pad
      (data.length - 3) % 16
    end
    
  end
end
