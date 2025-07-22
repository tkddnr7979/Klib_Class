#include "CKlib.h"


bool CKlib::KLIB_Encrypt(KL_OBJECT* data, KL_OBJECT& oEncryptedData) {

	bool rtn = false;

	mKeyBuf.clear();
	mKeyBuf = mOrignKeyBuf;
	KLIB_SetKey(mKeyBuf, GetEncDecType(), GetEncDecLength());
	//KLIB_PrintKey("KLIB_Encrypt");


	try {

		KL_RV ret;
		CStringA msg;

		//////////////////////////////////////////
		//암호화 수행 : K_EncryptInit - K_Encrypt
		//////////////////////////////////////////

		// 컨텍스트 초기화 : K_EncryptInit
		if ((ret = K_EncryptInit((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)&mKey)) != KLR_OK) {
			msg.Format("K_EncryptInit failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}


		// 출력 크기를 구한다. : K_Encrypt
		////(Optional) 출력 크기를 반환, 해당 Step은 사용자가 출력 Buffer의 크기를 알고자 할때 수행한다.
		oEncryptedData[1].pValue = NULL;
		if ((ret = K_Encrypt((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)data, (KL_OBJECT_PTR)&oEncryptedData)) != KLR_OK) {
			msg.Format("K_Encrypt(Obtaining Output Length) failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}
		oEncryptedData[1].pValue = (KL_BYTE_PTR)malloc(oEncryptedData[1].ulValueLen);


		// 암호화 : K_Encrypt
		if ((ret = K_Encrypt((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)data, (KL_OBJECT_PTR)oEncryptedData)) != KLR_OK) {
			msg.Format("K_Encrypt failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}
		//K_HexDump((KL_BYTE_PTR)oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, (KL_BYTE_PTR)"encrypted data");


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_Encrypt - Fail : ") + ex);
		rtn = false;
	}

	K_ClearSensitive((KL_OBJECT_PTR)&mKey, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&mCtx, 2);

	return rtn;
}


bool CKlib::KLIB_FileEncrypt(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;
	CStringA msg;

	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readBuffer;
	if (KLIB_FileRead(filePath, readBuffer) == false) {
		OutputDebugStringA("[klib] KLIB_FileEncrypt - Fail : File not found");
		return false;
	}
	KL_ULONG readBufferSize = readBuffer.size();


	//--[Init]-------------------------------------------------------------------------//

	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readBuffer.data(), readBufferSize, TRUE, FALSE},
	};

	//For Encryption Output
	KL_BYTE_PTR EncDataBuf = NULL;
	KL_OBJECT oEncryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, EncDataBuf, 0, FALSE, FALSE}
	};

	//For Decryption Output
	KL_BYTE_PTR DecDataBuf = NULL;
	KL_OBJECT oDecryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, DecDataBuf, 0, FALSE, FALSE}
	};


	//--[Encrypt]-------------------------------------------------------------------------//

	try {

		KL_RV ret;

		if (!KLIB_Encrypt(&oData, oEncryptedData)) {
			msg.Format("Encrpyt failed \n");
			throw msg;
		}
		//K_HexDump((KL_BYTE_PTR)mCtx[1].pValue, mCtx[1].ulValueLen, (unsigned char*)"enc - mCtx");
		//K_HexDump((KL_BYTE_PTR)mKey[1].pValue, mKey[1].ulValueLen, (KL_BYTE_PTR)"enc - Key");

		//--[Encrypt 무결성 체크]-------------------------------------------------------------------------//

		if (!KLIB_Decrypt(&oEncryptedData, oDecryptedData)) {
			msg.Format("Encrpyt Check - Decrpyt failed \n");
			throw msg;
		}
		//K_HexDump((KL_BYTE_PTR)mCtx[1].pValue, mCtx[1].ulValueLen, (unsigned char*)"enc check - mCtx");
		//K_HexDump((KL_BYTE_PTR)mKey[1].pValue, mKey[1].ulValueLen, (KL_BYTE_PTR)"enc check - Key");

		// 해쉬값 비교
		CStringA hashOrigin, hashCopy;
		KLIB_MakeHash(oData, GetHashType(), hashOrigin);
		KLIB_MakeHash(oDecryptedData, GetHashType(), hashCopy);
		bool bHashCompare = (hashOrigin.CompareNoCase(hashCopy) == 0)
			&& hashOrigin.GetLength() > 0
			&& hashCopy.GetLength() > 0;
		//OutputDebugStringA(CStringA("\n[klib] KLIB_FileEncrypt - Hash compare : ") + (bHashCompare ? "True" : "False"));


		// 암호화 파일 저장
		if (bHashCompare) {
			rtn = KLIB_FileWrite(filePath, oEncryptedData);
		}

	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileEncrypt - Fail : ") + ex);
		rtn = false;
	}

	//--[Release]-------------------------------------------------------------------------//

	//사용 컨텍스트, 오브젝트 초기화
	K_ClearSensitive((KL_OBJECT_PTR)&oData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oEncryptedData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oDecryptedData, 2);

	if (oEncryptedData[1].pValue != NULL) {
		free(oEncryptedData[1].pValue);
	}
	if (oDecryptedData[1].pValue != NULL) {
		free(oDecryptedData[1].pValue);
	}


	return rtn;
}


bool CKlib::KLIB_EncryptKeyAndSaveFile(std::vector<KL_BYTE>& key, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;


	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oKeyData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, key.data(), key.size(), TRUE, FALSE},
	};

	//For Encryption Output
	KL_BYTE_PTR EncDataBuf = NULL;
	KL_OBJECT oEncryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, EncDataBuf, 0, FALSE, FALSE}
	};

	//For Decryption Output
	KL_BYTE_PTR DecDataBuf = NULL;
	KL_OBJECT oDecryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, DecDataBuf, 0, FALSE, FALSE}
	};


	try {

		// origin key 암호화.
		if (!KLIB_Encrypt(&oKeyData, oEncryptedData)) {
			throw CStringA("Encrpyt failed");
		}

		KL_CHAR_PTR pStart, pEnd;

		// 복호화하여 무결성 체크
		if (!KLIB_Decrypt(&oEncryptedData, oDecryptedData)) {
			throw CStringA("Encrpyt Check - Decrpyt failed");
		}
		CStringA decryptedData, strKey;
		pStart = (KL_CHAR_PTR)oDecryptedData[1].pValue;
		pEnd = pStart + oDecryptedData[1].ulValueLen;
		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			decryptedData.AppendFormat("%02x", *pPointer);
		}
		for (std::vector<KL_BYTE>::iterator itr = key.begin(); itr != key.end(); itr++) {
			strKey.AppendFormat("%02x", *itr);
		}
		if (decryptedData.CompareNoCase(strKey)) {
			throw CStringA("Encrpyt Check - compare failed");
		}


		// 암호화된 key를 로드 : SaveKey() 재활용 하려고
		CStringA generateKey;
		pStart = (KL_CHAR_PTR)oEncryptedData[1].pValue;
		pEnd = pStart + oEncryptedData[1].ulValueLen;
		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			generateKey.AppendFormat("%02x", *pPointer);
		}
		if (!KLIB_LoadKeyFromData(generateKey, GetEncDecType(), GetEncDecLength())) {
			throw CStringA("LoadKeyFromData failed");
		}
		//KLIB_PrintKey("Encrypt origin key");


		// key파일 저장
		if (!KLIB_SaveKey(mKeyFilePath)) {
			throw CStringA("SaveKey failed");
		}
		//KLIB_PrintKey("Save origin key");


		rtn = true;
	}
	catch (CStringA msg) {
		OutputDebugStringA("[klib] KLIB_EncryptKeyFile - Fail : " + msg);
		rtn = false;
	}


	//사용 컨텍스트, 오브젝트 초기화
	K_ClearSensitive((KL_OBJECT_PTR)&oKeyData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oEncryptedData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oDecryptedData, 2);

	if (oEncryptedData[1].pValue != NULL) {
		free(oEncryptedData[1].pValue);
	}
	if (oDecryptedData[1].pValue != NULL) {
		free(oDecryptedData[1].pValue);
	}


	return rtn;
}