module Padding
  class ANSI < Base
    def pad
      STDOUT.tap do |out|
        [ base16(data),
          prefix, padding_string, suffix,
          hash, hash_alg_id ].each { |part| out << part }
      end 
    end
    
    def prefix
      "6b"
    end
    
    def padding_string
      "".tap { |out| octets_to_pad.times { out << "bb" } }
    end
    
    def suffix
      "ba"
    end
    
    def hash_alg_id
      "33cc"
    end
    
    def octets_to_pad
      (data.length - 3) % 16
    end
    
  end
end
