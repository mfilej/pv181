# 2

## Goal

Write a program (using Eracom ProtectToolkit C API) to encrypt and decrypt files on disk. The token LABAK should be used and a program will be able to: 

  * generate an asymmetric key associated by a name
  * encrypt a file using the symmetric key
  * decrypt a file using the symmetric key
  * delete the symmetric key
  * the name of the key should be configurable


## Solution & Shortcomings

See the file hsm_encode_decode.c. The solution is incomplete:

  * the source code is very very ugly
  * the input and output file names are hardcoded (input.txt and output.txt)
  * it is only possible to encode and decode files, not to create or destroy  keys
  * the resulting file after decoding will be padded by null characters to the next multiple of 8