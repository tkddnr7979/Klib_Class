#include"pch.h"
#include "CKlib.h"

#define KLIB_READ_FILE_BUFFER_SIZE 1 << 20
#define KLIB_DATASIZE 22 
#define KLIB_ELEMENTCOUNT 2 
#define KLIB_ELEMENTSIZE (KLIB_DATASIZE/KLIB_ELEMENTCOUNT)


bool CKlib::KLIB_MakeHashFromFile(CStringA filePath, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash)
{
	bool rtn = false;


	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readBuffer;
	if (KLIB_FileRead(filePath, readBuffer) == false) {
		//OutputDebugStringA("[klib] KLIB_Encrypt - Fail : File not found");
		return rtn;
	}
	KL_ULONG readBufferSize = readBuffer.size();


	//Input
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readBuffer.data(), readBufferSize, TRUE, FALSE},
	};

	//--[Make Hash]-------------------------------------------------------------------------//

	rtn = KLIB_MakeHash(oData, dgst_alg, hash);

	//--[Release]-------------------------------------------------------------------------//

	K_ClearSensitive((KL_OBJECT_PTR)&oData, 2);

	return rtn;
}

bool CKlib::KLIB_MakeHashFromData(CStringA data, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash)
{
	bool rtn = false;


	//Input
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, data.GetBuffer(), data.GetLength(), TRUE, FALSE},
	};

	//--[Make Hash]-------------------------------------------------------------------------//

	rtn = KLIB_MakeHash(oData, dgst_alg, hash);

	//--[Release]-------------------------------------------------------------------------//

	K_ClearSensitive((KL_OBJECT_PTR)&oData, 2);

	return rtn;
}

bool CKlib::KLIB_MakeHash(KL_OBJECT& data, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash) {

	bool rtn = false;

	//--[Init]-------------------------------------------------------------------------//

	//Context
	KL_CONTEXT digestctx = {
		{dgst_alg, NULL, 0, FALSE, FALSE}
	};


	//Output Buf
	KL_BYTE DigestBuf[KL_SHA512_HASH_BYTE_LEN] = "";
	KL_OBJECT oDigestData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, DigestBuf, 0, TRUE, FALSE}
	};


	//--[Hash]-------------------------------------------------------------------------//

	try {

		//--[Hash setting]-------------------------------------------------------------------------//

		switch (dgst_alg)
		{
		case KLE_CONTEXT_TYPE::KLO_CTX_SHA224:	oDigestData[1].ulValueLen = KL_SHA224_HASH_BYTE_LEN;		break;
		case KLE_CONTEXT_TYPE::KLO_CTX_SHA256:	oDigestData[1].ulValueLen = KL_SHA256_HASH_BYTE_LEN;		break;
		case KLE_CONTEXT_TYPE::KLO_CTX_SHA384:	oDigestData[1].ulValueLen = KL_SHA384_HASH_BYTE_LEN;		break;
		case KLE_CONTEXT_TYPE::KLO_CTX_SHA512:	oDigestData[1].ulValueLen = KL_SHA512_HASH_BYTE_LEN;		break;
		default:
			throw CStringA("Algorithm Not Supported.\n");
		}

		//--[Hash init]-------------------------------------------------------------------------//

		KL_RV ret;

		////초기화
		if ((ret = K_DigestInit(&digestctx)) != KLR_OK) {
			CStringA exMsg;
			exMsg.Format("K_DigestInit fails: %s\n", K_GetErrorMsg(ret));
			throw exMsg;
		}


		////(Optional) 해시 크기를 반환(oDigestData[1].ulValueLen) : 해당 Sub-Step은 사용자가 출력 Buffer의 크기를 알고자 할때 수행한다.
		oDigestData[1].pValue = NULL;
		if ((ret = K_DigestFinal(&digestctx, (KL_OBJECT_PTR)&oDigestData)) != KLR_OK) {
			CStringA exMsg;
			exMsg.Format("K_DigestFinal fails(Obtainig output length): %s\n", K_GetErrorMsg(ret));
			throw exMsg;
		}
		oDigestData[1].pValue = (KL_BYTE_PTR)malloc(oDigestData[1].ulValueLen);


		//--[make Hash]-------------------------------------------------------------------------//

		if ((ret = K_Digest(&digestctx, (KL_OBJECT_PTR)data, (KL_OBJECT_PTR)&oDigestData)) != KLR_OK) {
			CStringA exMsg;
			exMsg.Format("K_Digest fails: %s\n", K_GetErrorMsg(ret));
			throw exMsg;
		}
		//K_HexDump((KL_BYTE_PTR)oDigestData[1].pValue, oDigestData[1].ulValueLen, (unsigned char*)"hash");


		//--[return value]-------------------------------------------------------------------------//

		KL_CHAR_PTR pStart = (KL_CHAR_PTR)oDigestData[1].pValue
			, pEnd = pStart + oDigestData[1].ulValueLen;

		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			hash.AppendFormat("%02x", *pPointer);
		}
		//OutputDebugStringA("\n [klib] KLIB_MakeHash - hash : " + hash);


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA("[klib] KLIB_MakeHash - Fail : " + ex);
		rtn = false;
	}


	//--[Release]-------------------------------------------------------------------------//

	K_ClearSensitive((KL_OBJECT_PTR)&digestctx, 1);
	K_ClearSensitive((KL_OBJECT_PTR)&oDigestData, 2);

	if (oDigestData[1].pValue != NULL) {
		free(oDigestData[1].pValue);
	}


	return rtn;
}