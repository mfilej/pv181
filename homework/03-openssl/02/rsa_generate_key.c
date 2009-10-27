#include <openssl/crypto.h>
#include <openssl/x509.h>

#define KEY_SIZE 1024
#define PUBXP 656537

int main()
{

  RSA *rsa;
  BIO *out;
  int err;

  rsa = RSA_generate_key(KEY_SIZE, PUBXP, NULL, NULL);
  if(rsa == NULL) {
    printf("Key generation failed\n");
    return 1;
  }

  if ((out = BIO_new(BIO_s_file())) == NULL) {
    printf("Unable to create BIO for output\n");
    return 1;
  }

  BIO_set_fp(out, stdout, BIO_NOCLOSE);

  PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);
  printf("\n");
  PEM_write_bio_RSAPublicKey(out, rsa);
  
  RSA_free(rsa);
  BIO_free_all(out);
  
  return 0;
}
