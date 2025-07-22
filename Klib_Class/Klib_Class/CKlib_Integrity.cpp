#include "CKlib.h"
#include <PathCch.h>
#include <string>


bool CKlib::KLIB_MakeIntegrityListFile(CStringA filePath)
{
	bool rtn = false;

	KL_OBJECT oData = {
	{KLO_DATA, NULL, 0, FALSE, FALSE},
	{KLA_VALUE, nullptr, 0, TRUE, FALSE},
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

		// 파일 존재 여부 확인
		if (PathFileExistsA(filePath)) {
			
			//OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - already exist");
			
			// 복호화하여 체크
			CStringA integrityList; // 미사용.
			if (!KLIB_FileDecryptAndRead(filePath, GetEncDecType(), GetEncDecLength(), integrityList)) {
				// 복호화 실패시 key가 다르거나 깨진 것으로 판단
				throw CStringA("Integrity List File - DecryptAndRead Fail");
			}
		}
		else {

			// 파일 경로만 추출
			CStringA fileDir(filePath);
			PathRemoveFileSpecA(fileDir.GetBuffer());

			// 디렉토리 생성
			CStringA currentPath;
			const CStringA delimiter(L"\\");
			for (CHAR* nextToken = nullptr, *token = strtok_s(fileDir.GetBuffer(), delimiter, &nextToken)
				; token != nullptr
				; token = strtok_s(NULL, delimiter, &nextToken))
			{
				currentPath += token;
				currentPath += delimiter;

				if (!PathFileExistsA(currentPath)) {
					CreateDirectoryA(currentPath, NULL);
				}
			}


			// 파일 생성
			CloseHandle(CreateFileA(filePath.GetString(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));

			// 파일 존재 여부 확인
			if (!PathFileExistsA(filePath)) {
				throw CString("File not Create");
			}


			// 기본적인 데이터 저장.
			// -> 비어있으면 암복호화 안됨.
			std::vector<KL_BYTE> readBuffer;
			if (KLIB_FileRead(filePath, readBuffer) == false) {
				OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - Fail : File not found");
				return false;
			}

			// push back DecDataBuf
			CStringA readData((char*)oData[1].pValue, oData[1].ulValueLen);
			readData.Append("this file is for the test : this file is for the test\n");

			// relase old Data
			K_ClearSensitive((KL_OBJECT_PTR)&oData, 2);
			if (oData[1].pValue != NULL) {
				free(oData[1].pValue);
			}


			// set new Data
			oData[1].pValue = (KL_BYTE_PTR)malloc(readData.GetLength());
			oData[1].ulValueLen = readData.GetLength();
			if (oData[1].pValue == NULL) {
				throw CString("Memory Allocation Failed");
			}
			memcpy(oData[1].pValue, readData.GetBuffer(), readData.GetLength());



			// 암호화
			if (KLIB_Encrypt(&oData, oEncryptedData)) {
				throw CStringA("Encrypt fail");
			}

			// 무결성 체크 : 복호화
			if (KLIB_Decrypt(&oEncryptedData, oDecryptedData)) {
				throw CStringA("Encrypt check - decrypt fail");
			}

			// 무결성 체크 : 해쉬 체크
			CStringA hashOrigin, hashCopy;
			KLIB_MakeHash(oData, GetHashType(), hashOrigin);
			KLIB_MakeHash(oDecryptedData, GetHashType(), hashCopy);
			if (hashOrigin.CompareNoCase(hashCopy) == 0
				&& hashOrigin.GetLength() > 0
				&& hashCopy.GetLength() > 0) {
				throw CStringA("Encrypt check - hash check fail");
			}


			// 암호화 파일 저장
			if (!KLIB_FileWrite(filePath, oEncryptedData)) {
				throw CStringA("Fail to save");
			}
		}

		mIntegrityListFilePath = filePath;

		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - Fail : " + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_MakeIntegrityListFile - Exception : ") + ex.what());
		rtn = false;
	}


	// 실패 시 경로 초기화
	if (!rtn) {
		mIntegrityListFilePath = "";
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

bool CKlib::KLIB_UpdateIntegrityList(CStringA filePath)
{
	bool rtn = false;
	CStringA msg;


	// 추후 json형태로 변경 필요
	// json을 읽고 거기에 있는지 확인 후 있으면 수정, 없으면 추가

	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readBuffer;
	if (KLIB_FileRead(mIntegrityListFilePath, readBuffer) == false) {
		OutputDebugStringA("[klib] KLIB_FileDecrypt - Fail : File not found");
		return false;
	}


	//--[Init]-------------------------------------------------------------------------//

	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readBuffer.data(), readBuffer.size(), TRUE, FALSE},
	};

	//For Encryption Output
	KL_OBJECT oEncryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, NULL, 0, FALSE, FALSE}
	};

	//For Decryption Output
	KL_OBJECT oDecryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, NULL, 0, FALSE, FALSE}
	};


	try {

		//--[Decrypt]-------------------------------------------------------------------------//

		//printf("--[Decrypt]---------------------------------------------------------------------------------\n");
		KLIB_PrintKey("Integrity");
		if (!KLIB_Decrypt(&oData, oDecryptedData)) {
			msg.Format("Decrpyt failed \n");
			throw msg;
		}

		//--[Decrypt 무결성 체크]-------------------------------------------------------------------------//

		//printf("--[Decrypt Check]----------------------------------------------------------------------------\n");
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
		if (bHashCompare == false) {
			throw CString("Hash Compare Failed");
		}
		//printf("hash origin : %s \nhash Copy : %s", hashOrigin, hashCopy);

		////////////////////////////////////////////////////////

		//--[Update Integrity List]-------------------------------------------------------------------------//

		//printf("--[Update Integrity List]----------------------------------------------------------------------\n");
		CStringA hash;
		if (KLIB_MakeHashFromFile(filePath, KLE_CONTEXT_TYPE::KLO_CTX_SHA256, hash) == false) {
			throw CString("Make Hash Failed");
		}

		// push back DecDataBuf
		CStringA readData((char*)oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen);
		readData.Append(filePath + " : " + hash + "\n");

		// relase old Data
		K_ClearSensitive((KL_OBJECT_PTR)&oEncryptedData, 2);
		if (oEncryptedData[1].pValue != NULL) {
			free(oEncryptedData[1].pValue);
		}
		K_ClearSensitive((KL_OBJECT_PTR)&oDecryptedData, 2);
		if (oDecryptedData[1].pValue != NULL) {
			free(oDecryptedData[1].pValue);
		}

		// set new Data
		oDecryptedData[1].pValue = (KL_BYTE_PTR)malloc(readData.GetLength());
		oDecryptedData[1].ulValueLen = readData.GetLength();
		if (oDecryptedData[1].pValue == NULL) {
			throw CString("Memory Allocation Failed");
		}
		memcpy(oDecryptedData[1].pValue, readData.GetBuffer(), readData.GetLength());

		//K_HexDump((KL_BYTE_PTR)oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen, (KL_BYTE_PTR)"Update Integrity - decrypted data");

		//--[Encrypt]-------------------------------------------------------------------------//

		{
			// 복호화된 내용 저장(확인용)
			CStringA hashDecFilePath("D:\\klibTest\\test1\\tes2\\tes3\\klib_hash_dec.txt");
			KLIB_FileWrite(hashDecFilePath, oDecryptedData);
		}
		//printf("--[Encrypt]---------------------------------------------------------------------------------\n");
		KLIB_Encrypt(&oDecryptedData, oEncryptedData);
		KLIB_FileWrite(mIntegrityListFilePath, oEncryptedData);


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA("[klib] KLIB_UpdateIntegrityList - Fail : " + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_UpdateIntegrityList - Exception : ") + ex.what());
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

bool CKlib::KLIB_IntegrityCheck(CStringA filePath)
{
	bool rtn = false;


	try {

		// 추후 json형태로 변경 필요
		// json을 읽고 거기에 있는지 확인 후 있으면 수정, 없으면 추가
		CStringA hash;
		if (KLIB_MakeHashFromFile(filePath, GetHashType(), hash) == false) {
			throw CStringA("Make Hash Failed");
		}
		hash = filePath + " : " + hash;


		std::ifstream readStream(mIntegrityListFilePath, std::ios::binary);
		if (!readStream.is_open()) {
			throw CStringA("File not found");
		}


		std::string line;
		//CStringA msg;
		int count = 0;
		while (std::getline(readStream, line)) {
			//msg.Format("[klib] Integrity List[%d] : %s", count++, line.c_str());
			//OutputDebugStringA(msg);

			if (hash.Compare(line.c_str()) == 0) {
				//msg.Format("[klib] Integrity List : Find");
				//OutputDebugStringA(msg);
				rtn = true;
				break;
			}
		}


		readStream.close();
	}
	catch (CStringA ex) {
		OutputDebugStringA("[klib] KLIB_IntegrityCheck - Fail : " + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_IntegrityCheck - Exception : ") + ex.what());
		rtn = false;
	}


	return rtn;
}
