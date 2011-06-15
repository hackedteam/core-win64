typedef enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    Unknown1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3, /* was SystemTimeInformation */
    Unknown4,
    SystemProcessInformation = 5,
    Unknown6,
    Unknown7,
    SystemProcessorPerformanceInformation = 8,
    Unknown9,
    Unknown10,
    SystemDriverInformation,
    Unknown12,
    Unknown13,
    Unknown14,
    Unknown15,
    SystemHandleList,
    Unknown17,
    Unknown18,
    Unknown19,
    Unknown20,
    SystemCacheInformation,
    Unknown22,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    BYTE Reserved1[52];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION;

#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileNamesInformation 12
#define FileIdBothDirInformation 37
#define FileIdFullDirectoryInformation 38

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
		ULONG NextEntryOffset;
		ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize; 
        ULONG FileAttributes;
        ULONG FileNameLength;
		ULONG EaSize;
		CCHAR ShortNameLength;
		WCHAR ShortName[12];
		LARGE_INTEGER FileId;
		WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION { 
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize; 
        ULONG FileAttributes;
        ULONG FileNameLength;
        WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIRECTORY_INFORMATION {
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaInformationLength;
        WCHAR FileName[1];
} FILE_FULL_DIRECTORY_INFORMATION, *PFILE_FULL_DIRECTORY_INFORMATION;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION { 
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaInformationLength;
        UCHAR AlternateNameLength;
        WCHAR AlternateName[12];
        WCHAR FileName[1];
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION; 

typedef struct _FILE_NAMES_INFORMATION {
        ULONG NextEntryOffset;
        ULONG Unknown;
        ULONG FileNameLength;
        WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
	    ULONG NextEntryOffset;
	    ULONG FileIndex;
	    LARGE_INTEGER CreationTime;
	    LARGE_INTEGER LastAccessTime;
	    LARGE_INTEGER LastWriteTime;
	    LARGE_INTEGER ChangeTime;
	    LARGE_INTEGER EndOfFile;
	    LARGE_INTEGER AllocationSize;
	    ULONG FileAttributes;
	    ULONG FileNameLength;
	    ULONG EaSize;
	    LARGE_INTEGER FileId;
	    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
  LARGE_INTEGER  LastWriteTime;
  ULONG  TitleIndex;
  ULONG  ClassOffset;
  ULONG  ClassLength;
  ULONG  SubKeys;
  ULONG  MaxNameLen;
  ULONG  MaxClassLen;
  ULONG  Values;
  ULONG  MaxValueNameLen;
  ULONG  MaxValueDataLen;
  WCHAR  Class[1];
} KEY_FULL_INFORMATION;

typedef struct _KEY_STR_INFORMATION {
  DWORD dw1;
  DWORD dw2;
  DWORD dw3;
  DWORD dw4;
  DWORD dw5;
  ULONG Values;
} KEY_STR_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation,
  KeyNodeInformation,
  KeyFullInformation 
} KEY_INFORMATION_CLASS;
