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

		// ���� ���� ���� Ȯ��
		if (PathFileExistsA(filePath)) {
			
			//OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - already exist");
			
			// ��ȣȭ�Ͽ� üũ
			CStringA integrityList; // �̻��.
			if (!KLIB_FileDecryptAndRead(filePath, GetEncDecType(), GetEncDecLength(), integrityList)) {
				// ��ȣȭ ���н� key�� �ٸ��ų� ���� ������ �Ǵ�
				throw CStringA("Integrity List File - DecryptAndRead Fail");
			}
		}
		else {

			// ���� ��θ� ����
			CStringA fileDir(filePath);
			PathRemoveFileSpecA(fileDir.GetBuffer());

			// ���丮 ����
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


			// ���� ����
			CloseHandle(CreateFileA(filePath.GetString(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));

			// ���� ���� ���� Ȯ��
			if (!PathFileExistsA(filePath)) {
				throw CString("File not Create");
			}


			// �⺻���� ������ ����.
			// -> ��������� �Ϻ�ȣȭ �ȵ�.
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



			// ��ȣȭ
			if (KLIB_Encrypt(&oData, oEncryptedData)) {
				throw CStringA("Encrypt fail");
			}

			// ���Ἲ üũ : ��ȣȭ
			if (KLIB_Decrypt(&oEncryptedData, oDecryptedData)) {
				throw CStringA("Encrypt check - decrypt fail");
			}

			// ���Ἲ üũ : �ؽ� üũ
			CStringA hashOrigin, hashCopy;
			KLIB_MakeHash(oData, GetHashType(), hashOrigin);
			KLIB_MakeHash(oDecryptedData, GetHashType(), hashCopy);
			if (hashOrigin.CompareNoCase(hashCopy) == 0
				&& hashOrigin.GetLength() > 0
				&& hashCopy.GetLength() > 0) {
				throw CStringA("Encrypt check - hash check fail");
			}


			// ��ȣȭ ���� ����
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


	// ���� �� ��� �ʱ�ȭ
	if (!rtn) {
		mIntegrityListFilePath = "";
	}

	//--[Release]-------------------------------------------------------------------------//

	//��� ���ؽ�Ʈ, ������Ʈ �ʱ�ȭ
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


	// ���� json���·� ���� �ʿ�
	// json�� �а� �ű⿡ �ִ��� Ȯ�� �� ������ ����, ������ �߰�

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

		//--[Decrypt ���Ἲ üũ]-------------------------------------------------------------------------//

		//printf("--[Decrypt Check]----------------------------------------------------------------------------\n");
		if (!KLIB_Encrypt(&oDecryptedData, oEncryptedData)) {
			msg.Format("Decrpyt Check - Encrpyt failed \n");
			throw msg;
		}


		// �ؽ��� ��
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
			// ��ȣȭ�� ���� ����(Ȯ�ο�)
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

	//��� ���ؽ�Ʈ, ������Ʈ �ʱ�ȭ
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

		// ���� json���·� ���� �ʿ�
		// json�� �а� �ű⿡ �ִ��� Ȯ�� �� ������ ����, ������ �߰�
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
