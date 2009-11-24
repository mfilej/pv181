#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>

#define CONTAINER_NAME "LABAK_KEYSTORE"

void MyHandleError(char *s);
void GetConsoleInput(char* strInput, int intMaxChars);
 
int error( char fn[]) {
	int lastErr = GetLastError();
	printf("Error %s (0x%x) \n", fn, lastErr);
	return lastErr;
}

int main(int argc, char * argv[]) 
{
	HCRYPTPROV hCryptProv; 
	HCRYPTKEY hKey;

	if (CryptAcquireContext(&hCryptProv, CONTAINER_NAME, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		printf("Created a new key container and acquired context \n");
	} else if (CryptAcquireContext(&hCryptProv, CONTAINER_NAME, MS_DEF_PROV, PROV_RSA_FULL, 0)) {
		printf("Acquired context \n");
	} else {
		return error("acquiring context");
	}

	if (CryptGenKey(hCryptProv, AT_KEYEXCHANGE, 0, &hKey)) {
		printf("Generated key for exchange \n");
	} else {
		return error("generating exchange key");
	}

	if (CryptGenKey(hCryptProv, AT_SIGNATURE, 0, &hKey)) {
		printf("Generated key for signing \n");
	} else {
		return error("generating signing key");
	}

	if (CryptReleaseContext(hCryptProv, 0)) {
		printf("Done.");
	} else {
		return error("releasing context");
	}
}
