#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <Wincrypt.h>

void MyHandleError(char *s);
void GetConsoleInput(char* strInput, int intMaxChars);

#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

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
	  *pdwBlobLen = dwBlobLength;
  } else {
    free(*ppbKeyBlob);
    *ppbKeyBlob = NULL;
    return error("exporting key");
  }

  return TRUE;
}

int main(int argc, char * argv[]) 
{
	FILE *hDestination; 

	HCRYPTPROV hCryptProv; 
	HCRYPTKEY hKey;

	LPBYTE pbBlob = NULL; 
	DWORD dwBlobLength = 0;

	if (argc < 2) return 1;

	PCHAR szDest = argv[1];

	hDestination = fopen(szDest,"wb");

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
		printf("Acquired context \n");
	} else {
		return error("acquiring context");
	}

	if (CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, CRYPT_EXPORTABLE, &hKey)) {
		printf("Generated key \n");
	} else {
		return error("generating key");
	}
	
	if (!GetExportedKey(hKey, NULL, PLAINTEXTKEYBLOB, &pbBlob, &dwBlobLength)) {
		return FALSE;
	}

	for (int i=0; i < dwBlobLength; i++) {
		fprintf(hDestination, "%02x", pbBlob[i]); 
	}
	printf("Exported key to file %s (%d bytes) \n", szDest, dwBlobLength);
	fclose(hDestination);

	if (!CryptDestroyKey(hKey)) {
		return error("destroying key");
	}

	if (CryptReleaseContext(hCryptProv, 0)) {
		printf("Done. \n");
	} else {
		return error("releasing context");
	}
}
