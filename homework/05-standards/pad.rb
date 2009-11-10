#!/usr/bin/env ruby

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), 'lib')
require "padding"

puts "ANSI:"
Padding::ANSI.pad(open(ARGV[0]).read)

puts "\n\n"

puts "PKCS:"
Padding::PKCS.pad(open(ARGV[0]).read)