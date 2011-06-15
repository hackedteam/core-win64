#include "IPC.h"

#define CALL_ORIGINAL_API(...) ret_code = CallOriginalAPI(__VA_ARGS__)
#define INIT_WRAPPER(FUNCNAME, RETTYPE)	FUNCNAME ## Struct *pData = (FUNCNAME ## Struct *)data_param; RETTYPE ret_code; FUNCNAME ## _t CallOriginalAPI = (FUNCNAME ## _t)data_param; common_ipc_conf_struct *common_ipc_conf; 
#define MARK_HOOK

#define MAKE_HOOK(APINAME, DLLNAME, FUNCNAME, PARAMCOUNT, SETUPDATA) (FUNCNAME ## _setup((FUNCNAME ## Struct *)SETUPDATA) ?  HookDLLFunction(APINAME, DLLNAME, (BYTE *)FUNCNAME ## Hook, 1500, (BYTE *)SETUPDATA, sizeof(FUNCNAME ## Struct), PARAMCOUNT) : NULL)

#define CODE_PATCH_LIMIT 100
#define STUB_SIZE 256
#define COMMONDATA	BYTE OriginalCode[STUB_SIZE]; \
	                BYTE CallStub[STUB_SIZE]; \
                    BYTE *bAPIAdd; \
					IPCClientRead_data_struct *ipc_read_data; \
					IPCClientWrite_data_struct *ipc_write_data; \
					IPCClientRead_t ipc_client_read; \
					IPCClientWrite_t ipc_client_write;

#define PROTOTYPE_HOOK(RETTYPE, FNAME, ...) typedef RETTYPE (WINAPI *FNAME ## _t)(__VA_ARGS__); \
                                            extern RETTYPE _stdcall FNAME ## Hook(void *data_param, __VA_ARGS__); \
											extern BOOL FNAME ## _setup(FNAME ## Struct *data);

#define PROTOTYPE_COMMON_HOOK(RETTYPE, FNAME, ...) typedef struct {COMMONDATA;} FNAME ## Struct; PROTOTYPE_HOOK(RETTYPE, FNAME, __VA_ARGS__);

#define DEFAULT_SETUP_FUNC(FNAME) BOOL FNAME ## _setup(FNAME ## Struct *dummy) { return TRUE; }

typedef struct {COMMONDATA} CommonDataStruct;

extern "C" void __stdcall CALLSTUB1(void);
extern "C" void __stdcall CALLSTUB2(void);
extern "C" void __stdcall ORIGINALCODE(void);
extern "C" int __stdcall GetInstructionLength_x64(void *InPtr, int InType);

typedef struct
{
	LoadLibrary_t		pLoadLibrary;
	GetProcAddress_t	pGetProcAddress;
	FreeLibrary_t		pFreeLibrary;
	WCHAR dll_full_path[MAX_PATH];		
	char hook_func_name[64];
} HookingThreadDataStruct;

typedef BOOL (__stdcall *MakeHooking_t) (void);

// Funzioni esportate 
extern BOOL StartHookingThread(DWORD pid);

// Variabili esportate
extern void *IPC_SHM_Kernel_Object;

