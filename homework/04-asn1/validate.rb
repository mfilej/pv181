#!/usr/bin/env ruby

# This file is mostly glue code: argument parsing and calling FileToHash
# and HashExtractor with the right parameters. The two classes contain
# the relevant code comments themselves.

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), 'lib')
require 'hash_extractor'

def usage!(msg = nil)
  puts msg if msg
  puts DATA.read % File.basename($0)
  exit 1
end

def source
  usage! if ARGV.empty?
  open(ARGV.first, "rb").read
end

def target_dir
  dir = ARGV[1]
  if dir && !File.directory?(dir)
    usage! "#{ARGV[1]} doesn't exist or is not a directory"
  end
  dir || "."
end

extractor = HashExtractor.new(source)

extractor.hashes.each do |(index, hash)|
  target = File.join(target_dir, "dg#{index}.bin")
  file = FileToHash.new(target)
  
  print "Checking #{target.gsub(/^\.\//, "")}... "

  unless File.exists?(target)
    puts "[error] File not found"
    next
  end
  
  if file.hashes_to?(hash)
    puts "[ok]"
  else
    puts "[error] Hash does NOT match"
  end
end


__END__

Usage: %s <source> [directory]
  source:    the file to read the hashes from and
  directory: the directory containing the files to be hashes
             (defaults to the current directory if omitted)