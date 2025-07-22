#include"pch.h"
#include "CKlib.h"
#include <PathCch.h>
#include <string>
#include "CKlib_Json.h"


#define SHELL_COMMAND_OPEN "\"C:\\comtrue\\shdlp\\ctrenc.exe\" \"%1\""
#define PATH_ENC_ICON_PB "C:\\comtrue\\shdlp\\encicon\\pb_enc.hd"	// PB : public
#define PATH_ENC_ICON_PV "C:\\comtrue\\shdlp\\encicon\\pv_enc.hd"	// PV : private


const std::vector<CStringA> CKlib::mIntegrityFileList = {
	  "char_set.data.model"
	, "shpc_data.model"
	, "HwpSharp.Common.tlb"
	, "HwpSharp.tlb"
	////////////////////////////////////////////////
	//, "approve.ini" // UI�� ���� ������ ������ �ϴ� ���Ἲ üũ�� �� �ʿ䰡 �����
	, "ISYS11df.ini"
	////////////////////////////////////////////////
	, "ctrPAMon.inf"
	, "ctrPAMonEv.inf"
	, "shdlpMedia.inf"
	, "shdlpMediaEv.inf"
	, "shdlpSf.inf"
	, "shdlpSfEv.inf"
	////////////////////////////////////////////////
	, "ctrPAMon32.sys"
	, "ctrPAMon32Ev.sys"
	, "ctrPAMon64.sys"
	, "ctrPAMon64Ev.sys"
	, "ctrPAMonXP.sys"
	, "shdlpMedia32.sys"
	, "shdlpMedia32Ev.sys"
	, "shdlpMedia64.sys"
	, "shdlpMedia64Ev.sys"
	, "shdlpMediaXP.sys"
	, "shdlpSf32.sys"
	, "shdlpSf32Ev.sys"
	, "shdlpSf64.sys"
	, "shdlpSf64Ev.sys"
	////////////////////////////////////////////////
	, "ctrenc.exe"
	, "ctrFp.exe"
	, "ctrRecord.exe"
	, "ctrScan.exe"
	, "ctrwrts.exe"
	, "decompress.exe"
	, "devcon32.exe"
	, "devcon64.exe"
	, "IqpWatermarkConsole.exe"
	, "IqpWatermarkConsole64.exe"
	, "IqpWatermarkInstaller.exe"
	, "IqpWmkInjector.exe"
	, "IqpWmkService.exe"
	, "OleConverter.exe"
	, "remoteUtil.exe"
	, "rundll32.exe"
	, "rundll64.exe"
	, "screensaver.exe"
	, "shdlpAN.exe"
	, "shdlpBackup.exe"
	, "shdlpbu.exe"
	, "shdlpchkr.exe"
	, "shdlpelevator.exe"
	, "shdlpEncDec.exe"
	, "shdlpImageHelper.exe"
	, "shdlpInst.exe"
	, "shdlpMedia.exe"
	, "shdlpPDFMarsking.exe"
	, "shdlpRemoteSession.exe"
	, "shdlpservice.exe"
	, "shdlpSf.exe"
	, "shdlpUI.exe"
	, "shdlpupdate.exe"
	, "shdlpwmk.exe"
	, "shdlpwmkChild.exe"
	, "shpc-proxyc.exe"
	////////////////////////////////////////////////
	, "AxInterop.MSTSCLib.dll"
	, "boost_atomic-vc141-mt-x64-1_83.dll"
	, "boost_chrono-vc141-mt-x64-1_83.dll"
	, "boost_date_time-vc141-mt-x64-1_83.dll"
	, "boost_filesystem-vc141-mt-x64-1_83.dll"
	, "boost_log-vc141-mt-x64-1_83.dll"
	, "boost_system-vc141-mt-x64-1_83.dll"
	, "boost_thread-vc141-mt-x64-1_83.dll"
	, "BouncyCastle.Crypto.dll"
	, "clog.dll"
	, "Common.Logging.Core.dll"
	, "Common.Logging.dll"
	, "CPPNamedPipe.dll"
	, "crypto.dll"
	, "CSBackup.dll"
	, "CSCommon.dll"
	, "CSControl.dll"
	, "CSEPDLP.dll"
	, "CSNamedPipe.dll"
	, "CSSFolder.dll"
	, "ctrCommon.dll"
	, "ctrContextMenu.dll"
	, "ctrContextMenux64.dll"
	, "ctrdec.dll"
	, "ctrflt.dll"
	, "ctrjson.dll"
	, "ctrrecord.dll"
	, "ctrrpc.dll"
	, "ctrstr.dll"
	, "Filters.dll"
	, "HwpSharp.Common.dll"
	, "HwpSharp.dll"
	, "Interop.MSTSCLib.dll"
	, "IqpWmk.dll"
	, "IqpWmk64.dll"
	, "ISYS11df.dll"
	, "ISYSpdf6.dll"
	, "ISYSreaders.dll"
	, "ISYSreadershd.dll"
	, "ISYSreadersocr.dll"
	, "jsoncpp.dll"
	, "klib.dll"
	, "libcrypto-1_1-x64.dll"
	, "libcrypto-3-x64.dll"
	, "libcurl.dll"
	, "libglog.dll"
	, "libssl-3-x64.dll"
	, "libzip.dll"
	, "Microsoft.Win32.Primitives.dll"
	, "Microsoft.WindowsAPICodePack.dll"
	, "Microsoft.WindowsAPICodePack.ExtendedLinguisticServices.dll"
	, "Microsoft.WindowsAPICodePack.Sensors.dll"
	, "Microsoft.WindowsAPICodePack.Shell.dll"
	, "Microsoft.WindowsAPICodePack.ShellExtensions.dll"
	, "Microsoft.Xaml.Behaviors.dll"
	, "netstandard.dll"
	, "Newtonsoft.Json.dll"
	, "onnxruntime.dll"
	, "onnxruntime_providers_shared.dll"
	, "onnxwrapperdll.dll"
	, "opencv_world455.dll"
	, "openldap.dll"
	, "OpenMcdf.dll"//
	, "Perceptive.DocumentFilters.dll"
	, "preVerDec.dll"
	, "Prism.dll"
	, "Prism.Unity.Wpf.dll"
	, "Prism.Wpf.dll"
	, "Quartz.dll"
	, "RestSharp.dll"
	, "SecureDelete.dll"
	, "shdenc.dll"
	, "shdhttp.dll"
	, "shdlpcurl.dll"
	, "shdlpDriverSpt.dll"
	, "shdlpEnc.dll"
	, "shdlpImageHelper.dll"
	, "shdlpInspector.dll"
	, "shdlpMediaComm.dll"
	, "SHDLPPVENC.dll"
	, "shdlpreg.dll"
	, "shdpopup.dll"
	, "ShdProcMgr.dll"
	, "shdshrm.dll"
	, "System.AppContext.dll"
	, "System.Collections.Concurrent.dll"
	, "System.Collections.dll"
	, "System.Collections.NonGeneric.dll"
	, "System.Collections.Specialized.dll"
	, "System.ComponentModel.dll"
	, "System.ComponentModel.EventBasedAsync.dll"
	, "System.ComponentModel.Primitives.dll"
	, "System.ComponentModel.TypeConverter.dll"
	, "System.Console.dll"
	, "System.Data.Common.dll"
	, "System.Data.SQLite.dll"
	, "System.Diagnostics.Contracts.dll"
	, "System.Diagnostics.Debug.dll"
	, "System.Diagnostics.FileVersionInfo.dll"
	, "System.Diagnostics.Process.dll"
	, "System.Diagnostics.StackTrace.dll"
	, "System.Diagnostics.TextWriterTraceListener.dll"
	, "System.Diagnostics.Tools.dll"
	, "System.Diagnostics.TraceSource.dll"
	, "System.Diagnostics.Tracing.dll"
	, "System.Drawing.Primitives.dll"
	, "System.Dynamic.Runtime.dll"
	, "System.Globalization.Calendars.dll"
	, "System.Globalization.dll"
	, "System.Globalization.Extensions.dll"
	, "System.IO.Compression.dll"
	, "System.IO.Compression.ZipFile.dll"
	, "System.IO.dll"
	, "System.IO.FileSystem.dll"
	, "System.IO.FileSystem.DriveInfo.dll"
	, "System.IO.FileSystem.Primitives.dll"
	, "System.IO.FileSystem.Watcher.dll"
	, "System.IO.IsolatedStorage.dll"
	, "System.IO.MemoryMappedFiles.dll"
	, "System.IO.Pipes.dll"
	, "System.IO.UnmanagedMemoryStream.dll"
	, "System.Linq.dll"
	, "System.Linq.Expressions.dll"
	, "System.Linq.Parallel.dll"
	, "System.Linq.Queryable.dll"
	, "System.Net.Http.dll"
	, "System.Net.NameResolution.dll"
	, "System.Net.NetworkInformation.dll"
	, "System.Net.Ping.dll"
	, "System.Net.Primitives.dll"
	, "System.Net.Requests.dll"
	, "System.Net.Security.dll"
	, "System.Net.Sockets.dll"
	, "System.Net.WebHeaderCollection.dll"
	, "System.Net.WebSockets.Client.dll"
	, "System.Net.WebSockets.dll"
	, "System.ObjectModel.dll"
	, "System.Reflection.dll"
	, "System.Reflection.Extensions.dll"
	, "System.Reflection.Primitives.dll"
	, "System.Resources.Reader.dll"
	, "System.Resources.ResourceManager.dll"
	, "System.Resources.Writer.dll"
	, "System.Runtime.CompilerServices.Unsafe.dll"
	, "System.Runtime.CompilerServices.VisualC.dll"
	, "System.Runtime.dll"
	, "System.Runtime.Extensions.dll"
	, "System.Runtime.Handles.dll"
	, "System.Runtime.InteropServices.dll"
	, "System.Runtime.InteropServices.RuntimeInformation.dll"
	, "System.Runtime.Numerics.dll"
	, "System.Runtime.Serialization.Formatters.dll"
	, "System.Runtime.Serialization.Json.dll"
	, "System.Runtime.Serialization.Primitives.dll"
	, "System.Runtime.Serialization.Xml.dll"
	, "System.Security.Claims.dll"
	, "System.Security.Cryptography.Algorithms.dll"
	, "System.Security.Cryptography.Csp.dll"
	, "System.Security.Cryptography.Encoding.dll"
	, "System.Security.Cryptography.Primitives.dll"
	, "System.Security.Cryptography.X509Certificates.dll"
	, "System.Security.Principal.dll"
	, "System.Security.SecureString.dll"
	, "System.Text.Encoding.dll"
	, "System.Text.Encoding.Extensions.dll"
	, "System.Text.RegularExpressions.dll"
	, "System.Threading.dll"
	, "System.Threading.Overlapped.dll"
	, "System.Threading.Tasks.dll"
	, "System.Threading.Tasks.Extensions.dll"
	, "System.Threading.Tasks.Parallel.dll"
	, "System.Threading.Thread.dll"
	, "System.Threading.ThreadPool.dll"
	, "System.Threading.Timer.dll"
	, "System.ValueTuple.dll"
	, "System.Xml.ReaderWriter.dll"
	, "System.Xml.XDocument.dll"
	, "System.Xml.XmlDocument.dll"
	, "System.Xml.XmlSerializer.dll"
	, "System.Xml.XPath.dll"
	, "System.Xml.XPath.XDocument.dll"
	, "Unity.Abstractions.dll"
	, "Unity.Container.dll"
	, "websocket-sharp.dll"
	, "zlib1.dll"
	, "zlib-ng2.dll"
};

/// <summary>
/// <para> HKEY : reg root </para>
/// <para> CStringA : reg path </para>
/// <para> CStringA : key (�⺻���� ���������� ""�� ���) </para>
/// <para> CStringA : value ("(null)" == ���� �Ҵ���� ����)</para>
/// </summary>
const std::vector<std::tuple<HKEY, CStringA, CStringA, CStringA>> CKlib::mIntegrityList_Reg = {

	// -- [shdlpreg] --------------------------------------------------------------------------------------------//

	// ���ؽ�Ʈ �޴� [reg_contextmenu_folderEx/unreg_contextmenu_folderEx]
	  {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Dec",													"", "PC�������� ��ȣȭ�ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Dec\\command",											"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /dec %1"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Enc",													"", "PC�������� ��ȣȭ�ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Enc\\command",											"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /enc %1"}

	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Scan",													"", "PC�������� �����˻��ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.Scan\\command",											"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /scan %1"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\SHDLP.Scan",				"", "PC�������� �����˻��ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\SHDLP.Scan\\command",		"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /recyclebinscan %1"}

	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.ImageScan",												"", "PC�������� �̹��� �˻��ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\Directory\\Shell\\SHDLP.ImageScan\\command",										"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /imagescan %1"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\SHDLP.ImageScan",			"", "PC�������� �̹��� �˻��ϱ�"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\SHDLP.ImageScan\\command",	"", "c:\\comtrue\\shdlp\\shdlpchkr.exe /recyclebinimagescan %1"}

	//// (windows xp��) ���� �� �ڵ����� [reg_shdlp_program_start/unreg_shdlp_program_start]
	//, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "", "shdlpui startup"}

	// ���α׷� ���� [reg_shdlpuninstall/unreg_shdlpuninstall]
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SHDLP", "DisplayName", "SHDLP"}

	// -- [shdlpchkr] --------------------------------------------------------------------------------------------//

	// ��ü���� �������
	, {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\shdlpMedia.sys",		"", "Driver"}
	, {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\shdlpService",		"", "Service"}
	, {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\shdlpMedia.sys",		"", "Driver"}
	, {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\shdlpService",		"", "Service"}


	// .$ENC$ Ȯ���� ���
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.$ENC$",								"", "run_dec_pb"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.$ENC$\\run_dec_pb\\ShellNew",		"", "(null)"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pb\\DefaultIcon",			"", PATH_ENC_ICON_PB}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pb\\Shell",					"", "open"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pb\\Shell\\open",			"", "&open"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pb\\Shell\\open\\command",	"", SHELL_COMMAND_OPEN}

	// .$ENC$PV Ȯ���� ���
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.$ENC$PV",							"", "run_dec_pv"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\.$ENC$PV\\run_dec_pv\\ShellNew",		"", "(null)"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pv\\DefaultIcon",			"", PATH_ENC_ICON_PV}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pv\\Shell",					"", "open"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pv\\Shell\\open",			"", "&open"}
	, {HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\run_dec_pv\\Shell\\open\\command",	"", SHELL_COMMAND_OPEN}


	// .{([*])}$ENC$ Ȯ���� ���
	, {HKEY_CLASSES_ROOT, ".{([*])}$ENC$",										"", "{([*])}_dec_pb"}
	, {HKEY_CLASSES_ROOT, ".{([*])}$ENC$\\{([*])}_dec_pb\\ShellNew",				"", "(null)"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pb\\DefaultIcon",						"", "C:\\comtrue\\shdlp\\encicon\\pb_{([*])}.hd"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pb\\Shell",								"", "open"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pb\\Shell\\open",						"", "&open"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pb\\Shell\\open\\command",				"", SHELL_COMMAND_OPEN}

	// .{([*])}$ENC$PV Ȯ���� ���
	, {HKEY_CLASSES_ROOT, ".{([*])}$ENC$PV",									"", "{([*])}_dec_pv"}
	, {HKEY_CLASSES_ROOT, ".{([*])}$ENC$PV\\{([*])}_dec_pv\\ShellNew",				"", "(null)"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pv\\DefaultIcon",						"", "C:\\comtrue\\shdlp\\encicon\\pv_{([*])}.hd"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pv\\Shell",								"", "open"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pv\\Shell\\open",						"", "&open"}
	, {HKEY_CLASSES_ROOT, "{([*])}_dec_pv\\Shell\\open\\command",				"", SHELL_COMMAND_OPEN}


	// .{([*])}admin$ENC$ Ȯ���� ���
	, {HKEY_CLASSES_ROOT, ".{([*])}admin$ENC$",									"", "{([*])}admin_dec_pb"}
	, {HKEY_CLASSES_ROOT, ".{([*])}admin$ENC$\\{([*])}admin_dec_pb\\ShellNew",		"", "(null)"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pb\\DefaultIcon",					"", "C:\\comtrue\\shdlp\\encicon\\pb_admin.hd"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pb\\Shell",							"", "open"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pb\\Shell\\open",					"", "&open"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pb\\Shell\\open\\command",			"", SHELL_COMMAND_OPEN}

	// .{([*])}admin$ENC$PV Ȯ���� ���
	, {HKEY_CLASSES_ROOT, ".{([*])}admin$ENC$PV",								"", "{([*])}admin_dec_pv"}
	, {HKEY_CLASSES_ROOT, ".{([*])}admin$ENC$PV\\{([*])}admin_dec_pv\\ShellNew",	"", "(null)"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pv\\DefaultIcon",					"", "C:\\comtrue\\shdlp\\encicon\\pv_admin.hd"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pv\\Shell",							"", "open"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pv\\Shell\\open",					"", "&open"}
	, {HKEY_CLASSES_ROOT, "{([*])}admin_dec_pv\\Shell\\open\\command",			"", SHELL_COMMAND_OPEN}


	// .enc Ȯ���� ���(������ ��ȣȭ Ȯ���ڷ� ����)
	, {HKEY_CLASSES_ROOT, ".pvenc",											"", "run_dec_pvps"}
	, {HKEY_CLASSES_ROOT, ".pvenc\\run_dec_pvps\\ShellNew",					"", "(null)"}
	, {HKEY_CLASSES_ROOT, "run_dec_pvps\\DefaultIcon",						"", PATH_ENC_ICON_PB}
	, {HKEY_CLASSES_ROOT, "run_dec_pvps\\Shell",							"", "open"}
	, {HKEY_CLASSES_ROOT, "run_dec_pvps\\Shell\\open",						"", "&open"}
	, {HKEY_CLASSES_ROOT, "run_dec_pvps\\Shell\\open\\command",				"", SHELL_COMMAND_OPEN}

};

const CStringA CKlib::mToken("{([*])}"); // token : {([*])}

const std::vector<CStringA> CKlib::mExtlist = {
	"arch",	"cell",	"doc",	"docx",	"hwp",	"hwx",	"pdf",	"ppt",	"pptx",	"show",	"txt",	"xls",	"xlsx",
	"zip",	"rar",	"alz",	"egg",	"tar",	"tgz",	"tbz",	"7z",	"gz",	"bz",	"bz2"
};


CStringA CKlib::KLIB_GetRegistryValueHash(HKEY hKey, CStringA subKey, CStringA regValueName)
{
	CStringA rtnHash("");

	HKEY key;
	char regValue[256];
	DWORD bufferSize = sizeof(regValue);

	// ������Ʈ�� Ű ����
	if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &key) == ERROR_SUCCESS) {

		if (RegQueryValueExA(key, regValueName, NULL, NULL, (LPBYTE)regValue, &bufferSize) == ERROR_SUCCESS) {
			//OutputDebugStringA("[klib] KLIB_GetRegistryValueHash - registry value : " + CStringA(regValue));

			// ������Ʈ�� ���� �����ͼ� �ؽ� ����
			KLIB_MakeHashFromData(regValue, GetHashType(), rtnHash);
		}
		else {
			//OutputDebugStringA("[klib] KLIB_GetRegistryValueHash - registry value is not exist : " + subKey);

			// ������ �� ������ ���� : �� ���� �������� Ȯ�� �ʿ�
			KLIB_MakeHashFromData("", GetHashType(), rtnHash);
		}

		// Ű �ݱ�
		if (RegCloseKey(key) != ERROR_SUCCESS) {
			OutputDebugStringA("[klib] KLIB_GetRegistryValueHash - close registry fail : " + subKey);
		}
	}
	//else {
	//	OutputDebugStringA("[klib] KLIB_GetRegistryValueHash - find registry fail");
	//}


	return rtnHash;
}

bool CKlib::KLIB_MakeIntegrityListFile()
{
	bool rtn = false;


	try {

		// ���� ���� ���� Ȯ��
		if (!PathFileExistsA(GetIntegrityListFilePath())) {
			OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - �ű� ���Ἲ üũ���� ����");

			// ���� ��θ� ����
			CStringA fileDir(GetIntegrityListFilePath());
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
			CloseHandle(CreateFileA(GetIntegrityListFilePath().GetString(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));

			// ���� ���� ���� Ȯ��
			if (!PathFileExistsA(GetIntegrityListFilePath())) {
				throw CString("File not Create");
			}


			// �ʱ� ������ ���� : ������ ������ ���߿� ���� �б��� �� ��ȣȭ �������� ���� ����
			CKlib_Json jsnInitData;
			CStringA jsnConstPath = "C:\\comtrue\\shdlp\\jsn\\const.jsn";
			if (PathFileExistsA(jsnConstPath)) {
				CKlib_Json jsnConst;
				jsnConst.from_file(jsnConstPath.GetString());
				jsnInitData.set_str(jsnConst.get_str("clientVersion", 0).c_str(), "clientVersion", 0);
			}

			// �ʱ� ������ ����
			if (!KLIB_FileEncryptAndSave(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), jsnInitData.to_text().c_str())) {
				throw CStringA("Make Initialize data in Integrity file fail");
			}


			// �ؽ� ����Ʈ ����
			if (!KLIB_IntegrityList_Update_FileHash()) {
				throw CStringA("Make file hash list fail");
			}
			if (!KLIB_IntegrityList_Update_RegistryHash()) {
				throw CStringA("Make registry hash list fail");
			}

			OutputDebugStringA(CStringA("[klib] KLIB_MakeIntegrityListFile - create integrity file : done"));
		}
		else {
			OutputDebugStringA(CStringA("[klib] KLIB_MakeIntegrityListFile - already is integrity file"));
		}


		// ���Ἲ üũ
		OutputDebugStringA("[klib] KLIB_MakeIntegrityListFile - ���Ἲ üũ");
		if (!KLIB_IntegrityCheck()) {
			throw CStringA("Integrity check fail");
		}


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


	return rtn;
}

bool CKlib::KLIB_IntegrityList_Update_FileHash()
{
	bool rtn = false;


	try {

		// ���� �б�
		CStringA readFileData;
		if (!KLIB_FileDecryptAndRead(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), readFileData)) {
			throw CStringA("Fail to load Integrity file");
		}

		CKlib_Json jsnIntegrityList;
		jsnIntegrityList.from_text(readFileData.GetString());


		// ���Ἲ ����Ʈ�� ������Ʈ ���� �ؽ� ������Ʈ
		for (int idx = 0; idx < mIntegrityFileList.size(); ++idx) {
			//OutputDebugStringA("[klib] KLIB_IntegrityList_Update_FileHash - file path : C:\\comtrue\\shdlp\\" + mIntegrityFileList[idx]);

			CStringA hash;
			KLIB_MakeHashFromFile("C:\\comtrue\\shdlp\\" + mIntegrityFileList[idx], GetHashType(), hash); // ��� �ϵ��ڵ� �ٲܱ�?
			jsnIntegrityList.set_str(hash.GetString(), "hash_file", mIntegrityFileList[idx].GetString(), 0);
		}


		// ��ȣȭ�Ͽ� ���Ϸ� ����
		if (!KLIB_FileEncryptAndSave(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), jsnIntegrityList.to_text().c_str())) {
			throw CStringA("Fail to save Integrity file");
		}


		rtn = true;

	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_IntegrityList_Update_FileHash - Fail : ") + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_IntegrityList_Update_FileHash - Exception : ") + ex.what());
		rtn = false;
	}


	return rtn;
}

bool CKlib::KLIB_IntegrityList_Update_RegistryHash()
{
	bool rtn = false;


	try {

		// ���� �б�
		CStringA readFileData;
		if (!KLIB_FileDecryptAndRead(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), readFileData)) {
			throw CStringA("Fail to load Integrity file");
		}

		CKlib_Json jsnIntegrityList;
		jsnIntegrityList.from_text(readFileData.GetString());


		// ���Ἲ ����Ʈ�� ������Ʈ�� �� ������Ʈ
		for (int idx = 0; idx < mIntegrityList_Reg.size(); ++idx) {

			HKEY hKey = std::get<0>(mIntegrityList_Reg[idx]);
			CStringA subKey = std::get<1>(mIntegrityList_Reg[idx])
				, regValueName = std::get<2>(mIntegrityList_Reg[idx])
				, regValue = std::get<3>(mIntegrityList_Reg[idx]);


			if (subKey.Find(mToken) != -1) {
				// ��ū�� ����ȴٸ� Ȯ���� ���� ��ȸ
				for (int idx_ext = 0; idx_ext < mExtlist.size(); ++idx_ext) {
					CStringA regExtPath = subKey;
					regExtPath.Replace(mToken, mExtlist[idx_ext]);

					CStringA regValueHash = KLIB_GetRegistryValueHash(hKey, regExtPath, regValueName);

					// jsn�� ������Ʈ
					jsnIntegrityList.set_str(regValueName, "hash_reg", regExtPath, "key", 0);
					jsnIntegrityList.set_str(regValueHash, "hash_reg", regExtPath, "value", 0);
				}
			}
			else {
				// ��ū�� ���ٸ� �״�� �� ����
				CStringA regValueHash = KLIB_GetRegistryValueHash(hKey, subKey, regValueName);

				// jsn�� ������Ʈ
				jsnIntegrityList.set_str(regValueName, "hash_reg", subKey, "key", 0);
				jsnIntegrityList.set_str(regValueHash, "hash_reg", subKey, "value", 0);
			}
		}


		// ��ȣȭ�Ͽ� ���Ϸ� ����
		if (!KLIB_FileEncryptAndSave(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), jsnIntegrityList.to_text().c_str())) {
			throw CStringA("Fail to load Integrity file");
		}

		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_IntegrityList_Update_RegistryHash - Fail : ") + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_IntegrityList_Update_RegistryHash - Exception : ") + ex.what());
		rtn = false;
	}


	return rtn;
}


bool CKlib::KLIB_IntegrityCheck()
{
	bool rtn = false;


	try {

		CStringA integrityList;
		if (!KLIB_FileDecryptAndRead(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), integrityList)) {

			// ���Ἲ���� ���� ������ ���, ���� ���Ͽ� ���� ���Ἲ�� �����ϱ� �����Ƿ� ������Ʈ �缳ġ
			KLIB_ReInstall("Integrity Check", "Read integrity file fail");

			throw CStringA("Read integrity file fail");
		}


		CKlib_Json jsnIntegrityList;
		jsnIntegrityList.from_text(integrityList.GetString());

		CKlib_Json jsnHashFileList = jsnIntegrityList.get_part("hash_file", 0)
				, jsnHashRegList = jsnIntegrityList.get_part("hash_reg", 0)
				, jsnIntegrityCheckFailList;
		

		// ���� ���Ἲ üũ
		for (int idx = 0, count = jsnHashFileList.get_count(0); idx < count; ++idx) {

			CStringA fileName(jsnHashFileList.get_nth_key(idx, 0).c_str())
					, integrityCheckData(jsnHashFileList.get_str(fileName, "value", 0).c_str());	// ���Ἲ ���� ��������

			// hash ����
			CStringA fileHash("");
			if (PathFileExistsA("C:\\comtrue\\shdlp\\" + fileName)) {
				KLIB_MakeHashFromFile("C:\\comtrue\\shdlp\\" + fileName, GetHashType(), fileHash);
			}
			
			// fileHash üũ : ������ ������ �� ���ڿ��� ������ ok
			if (fileHash.Compare(integrityCheckData) != 0) {
				//OutputDebugStringA(CStringA("[klib] Integrity check fail : ") + fileName);

				// fileHash ���� �ٸ���
				jsnIntegrityCheckFailList.set_str(fileHash, "hash_file", fileName, "regValueHash", 0);
				jsnIntegrityCheckFailList.set_str(integrityCheckData, "hash_file", fileName, "integrityCheckData", 0);
			}
			//else {
			//	OutputDebugStringA(CStringA("[klib] Integrity check success : ") + fileName);
			//}
		}


		// ������Ʈ�� ���Ἲ üũ
		for (int idx = 0; idx < mIntegrityList_Reg.size(); ++idx) {

			HKEY hKey = std::get<0>(mIntegrityList_Reg[idx]);
			CStringA subKey = std::get<1>(mIntegrityList_Reg[idx])
					, regValueName = std::get<2>(mIntegrityList_Reg[idx])
					, regValue = std::get<3>(mIntegrityList_Reg[idx]);


			if (subKey.Find(mToken) != -1) {

				// ��ū�� ����ȴٸ� Ȯ���� ���� ��ȸ
				for (int idx_ext = 0; idx_ext < mExtlist.size(); ++idx_ext) {

					// Ȯ���ں� ������Ʈ�� ���
					CStringA subKey_Ext(subKey);
					subKey_Ext.Replace(mToken, mExtlist[idx_ext]);

					// ���Ἲ ���� ��������
					CStringA integrityCheckData = jsnHashRegList.get_str(subKey_Ext, "value", 0).c_str();

					// �ؽ��� ����
					CStringA regValueHash = KLIB_GetRegistryValueHash(hKey, subKey_Ext, regValueName);

					if (regValueHash.Compare(integrityCheckData) != 0) {
						// ���� �ٸ��� ���� ����Ʈ�� �߰�
						jsnIntegrityCheckFailList.set_str(regValueHash, "hash_reg", subKey_Ext, "regValueHash", 0);
						jsnIntegrityCheckFailList.set_str(integrityCheckData, "hash_reg", subKey_Ext, "integrityCheckData", 0);
					}
					//else {
					//	// ������
					//	jsnIntegrityCheckFailList.set_int(1, "success_reg", subKey_Ext, 0);
					//}
				}
			}
			else {
				// �ƴϸ� �״�� �� ���� üũ
				CStringA regValueHash = KLIB_GetRegistryValueHash(hKey, subKey, regValueName)
						, integrityCheck = jsnHashRegList.get_str(subKey, "value", 0).c_str();

				if (regValueHash.Compare(integrityCheck) != 0) {
					//OutputDebugStringA(CStringA("[klib] Integrity check fail : ") + subKey);

					// ���� �ٸ��� ���� ����Ʈ�� �߰�
					jsnIntegrityCheckFailList.set_str(regValueHash, "hash_reg", subKey, "regValueHash", 0);
					jsnIntegrityCheckFailList.set_str(integrityCheck, "hash_reg", subKey, "integrityCheck", 0);
				}
				//else {
				//	OutputDebugStringA(CStringA("[klib] Integrity check success : ") + subKey);
				//}
			}
		}

		//OutputDebugStringA(CStringA("[klib] KLIB_IntegrityCheck - ���� ����Ʈ : ") + jsnIntegrityCheckFailList.to_text(false));

		// ���Ἲ üũ ���п� ���� ����.(���н� �缳ġ)
		if (jsnIntegrityCheckFailList.get_count("hash_file", 0) > 0) {
			// ���� ����
			if (!KLIB_RecoveryFile(jsnIntegrityCheckFailList.to_text().c_str())) {
				// ������ ������ ��� ������Ʈ �缳ġ
				KLIB_ReInstall("Integrity Check", "Recover file fail");

				throw CStringA("File recovery fail");
			}
		}

		if (jsnIntegrityCheckFailList.get_count("hash_reg", 0) > 0) {
			// ������Ʈ�� �� ����
			if (!KLIB_RecoveryRegistry(jsnIntegrityCheckFailList.to_text().c_str())) {
				// ������ ������ ��� ������Ʈ �缳ġ
				KLIB_ReInstall("Integrity Check", "Recover registry fail");

				throw CStringA("Registry recovery fail");
			}
		}


		OutputDebugStringA("[klib] KLIB_IntegrityCheck - Done");
		rtn = true;
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

bool CKlib::KLIB_RecoveryFile(CStringA p_jsnIntegrityCheckFailList)
{
	bool rtn = false;

	// ������ ������ ��� ���� �������δ� ��� �� ���� ����.
	// ��� ������ �����ΰų� �������� ���� �޾ƾ���.

	return rtn;
}

bool CKlib::KLIB_RecoveryRegistry(CStringA p_jsnIntegrityCheckFailList)
{
	bool rtn = false;

	CKlib_Json jsnIntegrityCheckFailList;
	jsnIntegrityCheckFailList.from_text(p_jsnIntegrityCheckFailList.GetString());

	try {

		for (int idx = 0; idx < mIntegrityList_Reg.size(); ++idx) {

			CStringA subKey = std::get<1>(mIntegrityList_Reg[idx]);

			if (!jsnIntegrityCheckFailList.is_empty("hash_reg", subKey.GetString(), 0)) {

				HKEY hKey = std::get<0>(mIntegrityList_Reg[idx]);
				CStringA regValueName = std::get<2>(mIntegrityList_Reg[idx])
						 , recoveryValue = std::get<3>(mIntegrityList_Reg[idx]);


				// ���� ����Ʈ�� ���� ��� ������Ʈ�� �� ����
				HKEY key;
				DWORD dwDisp = 0;
				LSTATUS rst = RegOpenKeyExA(hKey, subKey, 0, KEY_WRITE, &key);
				if (rst == ERROR_SUCCESS) {

					rst = RegSetValueExA(key, regValueName, 0, REG_SZ, (LPBYTE)recoveryValue.GetString(), (DWORD)recoveryValue.GetLength());
					RegCloseKey(key);
					if (rst != ERROR_SUCCESS) {
						throw CStringA("Fail to recover registry Integirity : ") + subKey;
					}
					OutputDebugStringA(CStringA("[klib] ������Ʈ�� ���Ἲ ���� - ���� : ") + subKey);


					// ���Ἲ ����Ʈ �ҷ�����
					CStringA readFileData;
					if (!KLIB_FileDecryptAndRead(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), readFileData)) {
						throw CStringA("Fail to load Integrity file");
					}

					CKlib_Json jsnIntegrityList;
					jsnIntegrityList.from_text(readFileData.GetString());


					// ���Ἲ üũ
					CStringA regValueHash = KLIB_GetRegistryValueHash(hKey, subKey, regValueName);
					CStringA recoveryHash;
					KLIB_MakeHashFromData(recoveryValue, GetHashType(), recoveryHash);

					// �ٸ� ��� ���� ����ó��
					if (!(recoveryHash.Compare(regValueHash) == 0
						  && recoveryHash.GetLength() > 0
						  && regValueHash.GetLength() > 0)) {
						throw CStringA("Recover integrity hash check fail");
					}


					// ���Ἲ ����Ʈ�� ������Ʈ�� �� ������Ʈ
					jsnIntegrityList.set_str(regValueName, "hash_reg", subKey, "key", 0);
					jsnIntegrityList.set_str(regValueHash, "hash_reg", subKey, "value", 0);


					// ��ȣȭ�Ͽ� ���Ϸ� ����
					if (!KLIB_FileEncryptAndSave(GetIntegrityListFilePath(), GetEncDecType(), GetEncDecLength(), jsnIntegrityList.to_text().c_str())) {
						throw CStringA("Fail to save Integrity file");
					}
				}
				else {
					throw CStringA("Registry open fail : ") + std::to_string(rst).c_str();
				}
			}
		}


		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA("[klib] KLIB_RecoveryRegistry - Fail : " + ex);
		rtn = false;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_RecoveryRegistry - Exception : ") + ex.what());
		rtn = false;
	}


	return rtn;
}
