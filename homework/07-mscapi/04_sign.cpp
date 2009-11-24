#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define CONTAINER_NAME "LABAK_KEYSTORE"

void MyHandleError(char *s);
void GetConsoleInput(char* strInput, int intMaxChars);
 
int error( char fn[]) {
	int lastErr = GetLastError();
	printf("Error %s (0x%x) \n", fn, lastErr);
	return lastErr;
}

BOOL GetExportedKey(HCRYPTKEY hKey, HCRYPTKEY hUserKey, DWORD dwBlobType, LPBYTE *ppbKeyBlob, LPDWORD pdwBlobLen) {

  DWORD dwBlobLength;
  *ppbKeyBlob = NULL;
  *pdwBlobLen = 0;

  if (CryptExportKey(hKey, hUserKey, dwBlobType, 0, NULL, &dwBlobLength)) {
	  printf("Size of the blob for the key determined (%d bytes) \n", dwBlobLength);
  } else {
    return error("determining size for the key");
  }

  // Allocate memory for the pbKeyBlob.
  if (*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength)) {
    printf("Memory has been allocated. \n");
  } else {
    printf("Out of memory. \n");
    return FALSE;
  }

  // Do the actual exporting into the key BLOB.
  if (CryptExportKey(hKey, NULL, dwBlobType, 0, *ppbKeyBlob, &dwBlobLength)) {
	  printf("Contents have been written to the blob (%d bytes) \n", dwBlobLength);
    // *pdwBlobLen = dwBlobLength;
  } else {
    free(*ppbKeyBlob);
    *ppbKeyBlob = NULL;
    return error("exporting key");
  }

  return TRUE;
}

int main(int argc, char * argv[]) 
{
	HCRYPTPROV hCryptProv; 
	HCRYPTKEY hKey;
	HCRYPTKEY userKey;

	PBYTE pbBlob; 
	DWORD dwBlockLen; 
	DWORD dwBlobLength; 

	FILE *hDestination; 
	PCHAR szDest = argv[1];
	hDestination = fopen(szDest, "wb");


	if (CryptAcquireContext(&hCryptProv, CONTAINER_NAME, MS_DEF_PROV, PROV_RSA_FULL, 0)) {
		printf("Acquired context \n");
	} else {
		return error("acquiring context");
	}

	if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &userKey)) {
		printf("Retrieved user key \n");
	} else {
		return error("retrieving user key");
	}

//CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey);
	if (CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, CRYPT_EXPORTABLE, &hKey)) {
		printf("Generated session key \n");
	} else {
		return error("generating session key");
	}

	if (!GetExportedKey(hKey, userKey, SIMPLEBLOB, &pbBlob, &dwBlobLength)) {
		return FALSE;
	}

	printf("Writing key to file %s (%d bytes) \n", szDest, dwBlobLength);
	for (int i=0; i < dwBlobLength; i++) {
		fprintf(hDestination, "%02x", pbBlob[i]); 
	}
	fclose(hDestination);

	if (CryptReleaseContext(hCryptProv, 0)) {
		printf("Done.");
	} else {
		return error("releasing context");
	}
}
