require 'digest/sha1'

# FileToHash is a simple class that wraps the functionality needed to compute
# a SHA1 of the file it's been initialized with. 
# Sample usage:
# 
# file = FileToHash.new('/tmp/file.example')
# file.hashes_to? "913879bda1b07f95ba628f7b2e9b816fdaf592f2"
# => true

class FileToHash
  
  attr_reader :file
  
  def initialize(file)
    @file = file
  end

  def hash
    @hash ||= File.open(file, "rb") do |source|
      Digest::SHA1.hexdigest(source.read)
    end
  end

  # compares the hash of the file to given_hash, returning true or false
  def hashes_to?(given_hash)
    hash == given_hash
  end
    
end