#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
// #include <openssl/x509.h>
// #include <openssl/pkcs12.h>
// #include <openssl/pkcs7.h>

#include <string.h>

int main()
{

  int err;
  char errmsg[120];
  SSL_METHOD *req_method;
  SSL_CTX *ctx;
  SSL *connection;
  int socket;
  
  
  SSL_load_error_strings();
  SSL_library_init();
  // TODO: seed PRNG
  
  req_method = SSLv2_client_method(); // v2 or v23 or v3
  ctx = SSL_CTX_new(req_method);
  if(!ctx) {
    printf("SSL: couldn't create a context!");
    return 1;
  }
  
  connection = SSL_new(ctx);
  SSL_set_connect_state(connection); // type = client

  SSL_set_fd(connection, socket);

  err = SSL_connect(connection);

  if (-1 == err) {
    err = ERR_get_error();
    ERR_error_string(err, errmsg);
    printf("SSL error: %s", errmsg);
    return 10;
  }

  return 0;
}
