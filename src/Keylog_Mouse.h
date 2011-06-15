typedef struct {
	DWORD msg;
	DWORD lprm;
	DWORD wprm;
} key_params_struct;

PROTOTYPE_COMMON_HOOK(BOOL, H_GetMessage, LPMSG lpMsg, HWND hwnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
PROTOTYPE_COMMON_HOOK(BOOL, H_PeekMessage, LPMSG lpMsg, HWND hwnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
//PROTOTYPE_COMMON_HOOK(LONG, H_ImmGetCompositionString, HIMC hIMC, DWORD dwIndex, LPVOID lpBuf, DWORD dwBufLen);

