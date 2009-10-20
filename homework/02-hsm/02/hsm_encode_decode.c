#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <cryptoki.h>
#include <ctextra.h>
#include <ctutil.h>
#include <ctvdef.h>
#include <genmacro.h>

#define CHECK_CK_RV_GOTO(rv, string, label)                 \
    if (rv != CKR_OK)                                       \
    {                                                       \
        fprintf(stderr, "Error occured : %s\n", string);    \
        goto label;                                         \
    }
char USERPIN[5] = { '1','1','1','1',0};

static CK_RV CreateSecretKeyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_CHAR *objLabel){
    CK_RV rv = CKR_OK;
    static CK_BBOOL ckTrue = TRUE;
    static CK_BBOOL ckFalse = FALSE;


    /* 
     * This is the mechanism used to generate a 3DES secret key. The fields
     * of the structure are :
     *
     *  CKM_DES3_KEY_GEN - Type of the mechanism. This informs the cryptoki 
     *                     library that we want to create a 3DES key.
     *  NULL             - This field is the parameter field. Some mechanisms 
     *                     require certain parameters to perform their 
     *                     functions. CKM_DES3_KEY_GEN does not require a 
     *                     parameter, hence the NULL value.
     *  0                - This field is the parameter length field. Since 
     *                     this mechanism type does not require a parameter,
     *                     0 is passed in as the length.
     */
	static CK_MECHANISM mechanism = {CKM_DES3_KEY_GEN, NULL, 0};
    
    /* 
     * This is the attribute template, which lays out some of the attributes the 
     * object will have when it is created. The object will also contain other
     * attributes, which are populated with default values. 
     * The attributes in the template are :
     * 
     *  CKA_LABEL - Points to a char array containing what will be the label
     *              of the key object.
     *
     *  CKA_TOKEN - Points to a CK_BBOOL variable containing the value TRUE.
     *              This object, therefore will be a token object, which 
     *              means it will persist on the token between sessions.
     *
     *  CKA_ENCRYPT - Points to a CK_BBOOL variable containing the value TRUE.
     *                This key, therefore will be able to encrypt data. 
     *
     *  CKA_DECRYPT - Points to a CK_BBOOL variable containing the value TRUE.
     *                This key, therefore will be able to decrypt data. 
     *
     *  CKA_SIGN    - Points to a CK_BBOOL variable containing the value TRUE.
     *                This key, therefore will be able to sign data. 
     *
     *  CKA_VERIFY  - Points to a CK_BBOOL variable containing the value TRUE.
     *                This key, therefore will be able to verify signatures. 
     *
     *  Other attributes are explicitly set to FALSE to ensure that they are 
     *  not set to TRUE by default.
     *
     *  The CKA_KEY_TYPE attribute is not set, since it is implied by the 
     *  mechanism. The same goes for the CKA_CLASS attribute.
     */
    CK_ATTRIBUTE objectTemplate[] = 
    {
        {CKA_LABEL,         NULL,       0},
        {CKA_TOKEN,         &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,       &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_DECRYPT,       &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_SIGN,          &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_VERIFY,        &ckTrue,    sizeof(CK_BBOOL)},
        {CKA_EXPORT,        &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_IMPORT,        &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_WRAP,          &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_UNWRAP,        &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_EXPORTABLE,    &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE,    &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &ckFalse,   sizeof(CK_BBOOL)},
        {CKA_DERIVE,        &ckFalse,   sizeof(CK_BBOOL)},
    };
    CK_SIZE objectSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE* pAttr = NULL;

    /* Fill in the public key label */
    pAttr = FindAttribute(CKA_LABEL, objectTemplate, objectSize);
    pAttr->pValue = objLabel;
    pAttr->ulValueLen = (CK_ULONG)strlen((char*)objLabel);

    rv = C_GenerateKey(hSession, &mechanism, objectTemplate, objectSize, phObject);
    CHECK_CK_RV_GOTO(rv, "C_GenerateKey", end);

end:
    return rv;
}

static CK_RV findObject(CK_SESSION_HANDLE hSession, CK_OBJECT_CLASS objClass, CK_CHAR* pObjLabel, CK_OBJECT_HANDLE* phObj){
    CK_RV rv = CKR_OK;

    /* This is the template used to search for the object. The C_FindObjects 
     * call matches all objects that have attributes matching all attributes 
     * within the search template.
     * 
     * The attributes in the search template are : 
     *  CKA_CLASS - Points to the objClass variable which contains the value
     *              CKO_SECRET_KEY, meaning this object is a secret key object.
     *  CKA_LABEL - Points to a char array containing what will be the label
     *              of the data object.
     *
     * The search will hit on all objects with the given class and label. Note
     * that it is possible to have multiple objects on a token with matching 
     * attributes, no matter what the attributes are. There is nothing 
     * precluding the existence of duplicate objects. In the case of duplicate
     * objects, the first one found is returned 
     */
    CK_ATTRIBUTE objectTemplate[] = 
    {
        {CKA_CLASS,         NULL,       0},
        {CKA_LABEL,         NULL,       0},
    };
    CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numObjectsToFind = 1;
    CK_ULONG numObjectsFound = 0;

    CK_ATTRIBUTE* pAttr = NULL;

    /* 
     * Fill out the template with the values to search for
     */

    /* First set the object class ... */
    pAttr = FindAttribute(CKA_CLASS, objectTemplate, templateSize);
    pAttr->pValue = &objClass;
    pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

    /* Now set the label ... */
    pAttr = FindAttribute(CKA_LABEL, objectTemplate, templateSize);
    pAttr->pValue = pObjLabel;
    pAttr->ulValueLen = strlen((char*)pObjLabel);

    /* 
     * Now perform the search 
     */

    /* First initialise the search operation */
    rv = C_FindObjectsInit(hSession, objectTemplate, templateSize);
    CHECK_CK_RV_GOTO(rv, "C_FindObjectsInit", end);

    /* Search */
    rv = C_FindObjects(hSession,
                       phObj,
                       numObjectsToFind,
                       &numObjectsFound);
    CHECK_CK_RV_GOTO(rv, "C_FindObjects", end);

    /* Terminate the search */
    rv = C_FindObjectsFinal(hSession);
    CHECK_CK_RV_GOTO(rv, "C_FindObjects", end);

    /* Check to see if we found a matching object */
    if (numObjectsFound == 0)
    {
        fprintf(stderr, "Object not found.\n");
        rv = CKR_GENERAL_ERROR;
    }

end:
    return rv;
}

CK_RV encryptData(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_CHAR* pData, CK_SIZE dataLen, CK_CHAR** ppEncData, CK_SIZE* pEncDataLen){
    CK_RV rv = CKR_OK;

    CK_MECHANISM mech;
    CK_MECHANISM_TYPE mechType = CKM_DES3_ECB;

    /*
     * Determine and set up the encryption mechanism based on the key 
     * type of hKey
     */
    mech.mechanism = mechType;
    mech.pParameter = NULL;
    mech.parameterLen = 0;

    /* Initialise the encrypt operation */
    rv = C_EncryptInit(hSession, &mech, hKey);
    CHECK_CK_RV_GOTO(rv, "C_EncryptInit", end);

    /* Do a length prediction so we allocate enough memory for the ciphertext */
    rv = C_Encrypt(hSession, pData, dataLen, NULL, pEncDataLen);
    CHECK_CK_RV_GOTO(rv, "C_Encrypt 1", end);
    
    *ppEncData = (CK_CHAR*)malloc(*pEncDataLen);
    if (*ppEncData == NULL) return CKR_HOST_MEMORY;

    /* Do the proper encrypt */
    rv = C_Encrypt(hSession, pData, dataLen, *ppEncData, pEncDataLen);
    CHECK_CK_RV_GOTO(rv, "C_Encrypt 2", end);

end:

    return rv;
}



static CK_RV decryptData(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hKey,
                         CK_CHAR* pEncData,
                         CK_SIZE encDataLen,
                         CK_CHAR** ppData,
                         CK_SIZE* pDataLen)
{

    CK_RV rv = CKR_OK;

    CK_MECHANISM mech;
    CK_MECHANISM_TYPE mechType = CKM_DES3_ECB;

    mech.mechanism = mechType;
    mech.pParameter = NULL;
    mech.parameterLen = 0;

    /* Initialise the decrypt operation */
    rv = C_DecryptInit(hSession, &mech, hKey);
    CHECK_CK_RV_GOTO(rv, "C_DecryptInit", end);

    /* Length predication */
    rv = C_Decrypt(hSession, pEncData, encDataLen, NULL, pDataLen);
    CHECK_CK_RV_GOTO(rv, "C_Decrypt", end);

    *ppData = (CK_CHAR*)malloc(*pDataLen);
    if (*ppData == NULL) return CKR_HOST_MEMORY;

    /* Do the actual decrypt operation */
    rv = C_Decrypt(hSession, pEncData, encDataLen, *ppData, pDataLen);
    CHECK_CK_RV_GOTO(rv, "C_Decrypt", end);

end:

    return rv;
}

static int encryptDataLoop(FILE *file_in, FILE *file_out, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
	
	
	CK_SIZE dataLen = 0;
	CK_CHAR** ppEncData = NULL;
	CK_SIZE* pEncDataLen = 0;

   int i = 0;
   int N = 8;
   char buffer[8];
   CK_RV rv = CKR_OK;
 
   CK_CHAR* pData = buffer;

   do{
	   N = fread(buffer, 1, 8, file_in);
	   for (i = N; i < 8; i++) {
		buffer[i] = 0;
	   }
	   if (N==0) return 0;
	   rv = encryptData(hSession, hKey, pData, 8, &ppEncData, &pEncDataLen);
	   CHECK_CK_RV_GOTO(rv, "findObject", end);
	   fwrite(ppEncData, 1, 8, file_out);
   } while(N==8);
 
end:

   return 0;
}

static int decryptDataLoop(FILE *file_in, FILE *file_out, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
	
	
	CK_SIZE dataLen = 0;
	CK_CHAR** ppEncData = NULL;
	CK_SIZE* pEncDataLen = 0;

   int i = 0;
   int N = 8;
   char buffer[8];
   CK_RV rv = CKR_OK;
 
   CK_CHAR* pData = buffer;

   printf("Reading file...");
   do{
	   N = fread(buffer, 1, 8, file_in);
	   if (N==0) return 0;
	   rv = decryptData(hSession, hKey, pData, 8, &ppEncData, &pEncDataLen);
	   CHECK_CK_RV_GOTO(rv, "findObject", end);
	   fwrite(ppEncData, 1, N, file_out);
	   i++;
   } while(N==8);
 
end:

   return 0;
}

int main(int argc, char const *argv[]){
	CK_RV rv = CKR_OK;
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_SLOT_ID slotId = 0;
	FILE *file;
	FILE *file_out;
	
	char * key_name;
	char command;

	if (argc !=3) {
		printf("Wrong arguments\n");
		printf("Usage:\n");
		printf("\t%s <command> <key name>\n", argv[0]);
		printf("\t\te - encode\n\t\td - decode\n\n");
		return 1;
	}

	/* read the command and key name arguments from the command line */
	command = argv[1][0];
	key_name = argv[2];

	/* Initialise the cryptoki API */
	printf( "Initializing Cryptoki API ... " );
    rv = C_Initialize(NULL);
    CHECK_CK_RV_GOTO(rv, "C_Initialize", end);
	printf( "OK\n" );

	/* Obtain a session so we can perform cryptoki operations */
	printf( "Obtaining a session ... " );
    rv = C_OpenSession(slotId, CKF_RW_SESSION, NULL, NULL, &hSession);
    CHECK_CK_RV_GOTO(rv, "C_OpenSession", end);
	printf( "OK\n" );

	printf("Using key: %s\n", key_name);

    /* Login as a user with a PIN */
	printf( "Logining as a user with a PIN ... " );
	rv = C_Login(hSession, CKU_USER, (CK_CHAR_PTR)USERPIN, (CK_SIZE) strlen((char*)USERPIN));
	CHECK_CK_RV_GOTO(rv, "C_Login as User", end);
	printf( "OK\n" );

	printf("Creating 3DES secret key ... ");
	rv = CreateSecretKeyObject(hSession, &hKey, key_name);
	CHECK_CK_RV_GOTO(rv, "CreateSecretKeyObject", end);
	printf("OK\n");

	printf("Finding 3DES key ... ");
	rv = findObject(hSession, CKO_SECRET_KEY, key_name, &hKey);
	CHECK_CK_RV_GOTO(rv, "findObject", end);
	printf("OK\n");
		
	switch(command) {
		
		case 'e':
			printf("Opening file... ");
			file = fopen("input.txt", "rb");
			if (!file) {
				printf("file not found\n");
				return 1;
			} else {
				file_out = fopen("output.txt", "wb");
				printf("ok\n");
			}
			
			printf("Encrypting file with 3DES ... ");
			rv = encryptDataLoop(file, file_out, hSession, hKey);
			CHECK_CK_RV_GOTO(rv, "encryptDataLoop", end);
			printf("OK\n");

			fclose(file);
			fclose(file_out);
			break;
		
		case 'd':
			printf("Opening file... ");
			file = fopen("output.txt", "rb");
			if (!file) {
				printf("file not found\n");
				return 1;
			} else {
				file_out = fopen("output2.txt", "wb");
				printf("ok\n");
			}

			printf("Decrypting file with 3DES ... ");
			rv = decryptDataLoop(file, file_out, hSession, hKey);
			CHECK_CK_RV_GOTO(rv, "decryptDataLoop", end);
			printf("OK\n");

			fclose(file);
			fclose(file_out);
			break;

		default:
			printf("Unknown command: %s\n", argv[1]);
	}

	/** Destroying the 3DES key */
	printf("Destrying the 3DES key ... ");
	rv = C_DestroyObject(hSession, hKey);
	CHECK_CK_RV_GOTO(rv, "DestroyObject", end);
	printf("OK\n");

	/* We've finished our work, close the session */
	printf( "Closing the session ... " );
    rv = C_CloseSession(hSession);
    CHECK_CK_RV_GOTO(rv, "C_CloseSession", end);
	printf("OK\n");

    /* We no longer need the cryptoki API ... */
	printf( "Finilizing the cryptoki ... " );
    rv = C_Finalize(NULL);
    CHECK_CK_RV_GOTO(rv, "C_Finalize", end);
	printf("OK\n");

	end:
    if (rv != CKR_OK)
    {
        fprintf(stderr,
                "Error performing create key operation : 0x%lx\n",
                rv);
        /* Clean up... we don't care if there are any errors.
         */
        if (hSession != CK_INVALID_HANDLE) C_CloseSession(hSession);
        C_Finalize(NULL);
    }
    return rv;
}
