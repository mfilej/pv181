require "digest/sha1"

module Padding
  class Base
    attr_reader :data
    
    def initialize(input)
      @data = input
    end
    
    def self.pad(string)
      new(string).pad
    end
        
    def hash
      Digest::SHA1.hexdigest(data)
    end
    
    def base16(data)
      data.each_byte.map { |b| "%02x" % b }
    end
  end
end