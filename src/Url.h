typedef struct {
	COMMONDATA;
	IsWindow_t pIsWindow;
#define BROWSER_UNKNOWN      0x00000000
#define BROWSER_IE           0x00000001
#define BROWSER_MOZILLA      0x00000002
#define BROWSER_OPERA		 0x00000003
#define BROWSER_CHROME		 0x00000005
#define BROWSER_TYPE_MASK    0x3FFFFFFF
#define BROWSER_SETTITLE     0x80000000
	DWORD browser_type;
} H_SendMessageStruct;
PROTOTYPE_HOOK(LRESULT, H_SendMessage, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

