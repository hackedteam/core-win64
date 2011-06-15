typedef struct {
	WCHAR szFileName[MAX_PATH+1];
	DWORD dwOperation;
	DWORD dwPid;
} IPCFileStruct;

typedef struct {
	COMMONDATA;
	GetCurrentProcessId_t pGetCurrentProcessId;
} H_CreateFileWStruct;
PROTOTYPE_HOOK(HANDLE, H_CreateFileW, WCHAR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlags, HANDLE hTemplateFile);

typedef struct {
	COMMONDATA;
	GetCurrentProcessId_t pGetCurrentProcessId;
} H_DeleteFileWStruct;
PROTOTYPE_HOOK(BOOL, H_DeleteFileW, WCHAR *FileName);

typedef struct {
	COMMONDATA;
	GetCurrentProcessId_t pGetCurrentProcessId;
} H_MoveFileWStruct;
PROTOTYPE_HOOK(BOOL, H_MoveFileW, WCHAR *SourceFile, WCHAR *DestFile);
