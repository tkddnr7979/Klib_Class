#include"pch.h"
#include "CKlib.h"


bool CKlib::KLIB_Decrypt(KL_OBJECT* data, KL_OBJECT& oDecryptedData) {

	std::lock_guard<std::mutex> lock(mtx);

	bool rtn = false;

	mKeyBuf.clear();
	mKeyBuf = mOrignKeyBuf;
	KLIB_SetKey(mKeyBuf, GetEncDecType(), GetEncDecLength());
	//KLIB_PrintKey("KLIB_Decrypt");

	try {

		KL_RV ret;
		CStringA msg;

		//////////////////////////////////////////
		//복호화 수행 : K_DecryptInit - K_Decrypt
		//////////////////////////////////////////

		// 컨텍스트 초기화 : K_DecryptInit
		if ((ret = K_DecryptInit((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)&mKey)) != KLR_OK) {
			msg.Format("K_DecryptInit failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}


		// 출력 크기를 구한다. : K_Decrypt
		////(Optional) 출력 크기를 반환, 해당 Step은 사용자가 출력 Buffer의 크기를 알고자 할때 수행한다.
		oDecryptedData[1].pValue = NULL;
		if ((ret = K_Decrypt((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)data, (KL_OBJECT_PTR)&oDecryptedData)) != KLR_OK) {
			msg.Format("K_Decrypt(Obtaining Output Length) failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}
		oDecryptedData[1].pValue = (KL_BYTE_PTR)malloc(oDecryptedData[1].ulValueLen);

		// 복호화 : K_Decrypt
		if ((ret = K_Decrypt((KL_CONTEXT_PTR)&mCtx, (KL_OBJECT_PTR)data, (KL_OBJECT_PTR)&oDecryptedData)) != KLR_OK) {
			msg.Format("K_Decrypt failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}
		//K_HexDump((KL_BYTE_PTR)oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen, (KL_BYTE_PTR)"decrypted data");


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_Decrypt - Fail : ") + ex);

		rtn = false;
	}

	K_ClearSensitive((KL_OBJECT_PTR)&mKey, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&mCtx, 2);

	return rtn;
}

bool CKlib::KLIB_FileDecrypt(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen) {

	bool rtn = false;
	CStringA msg;


	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readFileBuffer;
	if (KLIB_FileRead(filePath, readFileBuffer) == false) {
		OutputDebugStringA("[klib] KLIB_FileDecrypt - Fail : File not found");
		return false;
	}
	KL_ULONG readFileBufferSize = readFileBuffer.size();


	//--[Init]-------------------------------------------------------------------------//

	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readFileBuffer.data(), readFileBufferSize, TRUE, FALSE},
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


	//--[Decrypt]-------------------------------------------------------------------------//

	try {

		if (!KLIB_Decrypt(&oData, oDecryptedData)) {
			msg.Format("Decrpyt failed \n");
			throw msg;
		}

		//--[Decrypt 무결성 체크]-------------------------------------------------------------------------//

		if (!KLIB_Encrypt(&oDecryptedData, oEncryptedData)) {
			msg.Format("Decrpyt Check - Encrpyt failed \n");
			throw msg;
		}


		// 해쉬값 비교
		CStringA hashOrigin, hashCopy;
		KLIB_MakeHash(oData, GetHashType(), hashOrigin);
		KLIB_MakeHash(oEncryptedData, GetHashType(), hashCopy);
		bool bHashCompare = (hashOrigin.CompareNoCase(hashCopy) == 0)
							&& hashOrigin.GetLength() > 0
							&& hashCopy.GetLength() > 0;
		//OutputDebugStringA(CStringA("[klib] KLIB_FileDecrypt - Hash compare : ") + (bHashCompare ? "True" : "False"));
		if (!bHashCompare) {
			throw CStringA("Decrpyt Check - Compare failed");
		}


		// 복호화 파일 저장
		if (bHashCompare) {
			rtn = KLIB_FileWrite(filePath, oDecryptedData);
		}

	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileDecrypt - Fail : ") + ex + "\n\t - file : " + filePath);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileDecrypt - Exception : ") + ex.what() + "\n\t - file : " + filePath);
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

bool CKlib::KLIB_FileDecryptAndRead(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen, CStringA& decryptedData)
{
	bool rtn = false;


	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readFileBuffer;
	if (KLIB_FileRead(filePath, readFileBuffer) == false) {
		OutputDebugStringA("[klib] KLIB_FileDecrypt - Fail : File not found \n\t - file : " + filePath);
		return false;
	}
	KL_ULONG readFileBufferSize = readFileBuffer.size();


	//--[Init]-------------------------------------------------------------------------//

	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readFileBuffer.data(), readFileBufferSize, TRUE, FALSE},
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

		//--[Decrypt]-------------------------------------------------------------------------//

		if (!KLIB_Decrypt(&oData, oDecryptedData)) {
			throw CStringA("Decrpyt failed");
		}


		//--[Decrypt 무결성 체크]-------------------------------------------------------------------------//

		if (!KLIB_Encrypt(&oDecryptedData, oEncryptedData)) {
			throw CStringA("Decrpyt Check - Encrpyt failed");
		}

		// 해쉬값 비교
		CStringA hashOrigin, hashCopy;
		KLIB_MakeHash(oData, GetHashType(), hashOrigin);
		KLIB_MakeHash(oEncryptedData, GetHashType(), hashCopy);
		bool bHashCompare = (hashOrigin.CompareNoCase(hashCopy) == 0)
							&& hashOrigin.GetLength() > 0
							&& hashCopy.GetLength() > 0;
		//OutputDebugStringA(CStringA("[klib] KLIB_FileDecrypt - Hash compare : ") + (bHashCompare ? "True" : "False"));
		if (!bHashCompare) {
			throw CStringA("Decrpyt Check - Compare failed");
		}

		//--[return value]-------------------------------------------------------------------------//

		KL_CHAR_PTR pStart = (KL_CHAR_PTR)oDecryptedData[1].pValue
					, pEnd = pStart + oDecryptedData[1].ulValueLen;

		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			//decryptedData.AppendFormat("%02x", *pPointer);
			decryptedData.AppendFormat("%c", *pPointer);
		}
		//OutputDebugStringA("[klib] Decrypted Data : " + decryptedData);


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileDecryptAndRead - Fail : ") + ex + "\n\t - file : " + filePath);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileDecryptAndRead - Exception : ") + ex.what() + "\n\t - file : " + filePath);
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
