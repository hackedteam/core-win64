#include <windows.h>
#include "Common.h"
#include "IPC.h"

// Ritorna l'indirizzo di memoria della configurazione di un dato wrapper
// Torna NULL se fallisce
BYTE * __stdcall IPCClientRead(DWORD wrapper_tag, IPCClientRead_data_struct *pData)
{
	if (!pData->mem_addr) 
		return NULL;
	
	return (pData->mem_addr + wrapper_tag);
}

void IPCClientRead_setup(IPCClientRead_data_struct *data)
{
	HANDLE h_file = OpenFileMapping(FILE_MAP_READ, FALSE, SHARE_MEMORY_READ_NAME);
	data->mem_addr = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		data->mem_addr = (BYTE *)MapViewOfFile(h_file, FILE_MAP_READ, 0, 0, SHARE_MEMORY_READ_SIZE);
}

// Torna TRUE se ha scritto, FALSE se fallisce
BOOL __stdcall IPCClientWrite(DWORD wrapper_tag, IPCClientWrite_data_struct *pData, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority)
{
	unsigned int i, j;
	message_struct *pMessage;
	FILETIME time_stamp;

	// Fallisce se la memoria non e' presente o se il messaggio e' troppo grosso
	// per essere scritto
	if (!pData->mem_addr || msg_len > MAX_MSG_LEN || !message) 
		return FALSE;
	
	// La prima volta cerca una posizione libera.
	// Se non la trova, cerca una posizione occupata da una
	// priorita' minore
	for (j=0; j<2; j++) {
		for (i=0, pMessage=pData->mem_addr; i<MAX_MSG_NUM; i++, pMessage++) {
			if (pMessage->status == STATUS_FREE || (j && pMessage->status == STATUS_WRIT && pMessage->priority < priority)) {
				// XXX Possibilita' di remota race condition sulla lettura dello status
				pMessage->status = STATUS_BUSY;
				pMessage->message_len = msg_len;
				pMessage->priority = priority;
				pMessage->wrapper_tag = wrapper_tag;
				pMessage->flags = flags;

				// Setta il time stamp
				if (pData->pGetSystemTimeAsFileTime) {
					pData->pGetSystemTimeAsFileTime(&time_stamp);

					// Gestisce il caso di due log dello stesso tipo con timestamp uguali
					if (time_stamp.dwLowDateTime != pData->old_low_part ||
						time_stamp.dwHighDateTime != pData->old_hi_part) {
						pData->old_low_part = time_stamp.dwLowDateTime;
						pData->old_hi_part = time_stamp.dwHighDateTime;
						pData->increment = 0;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime;
					} else {
						pData->increment++;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime + pData->increment;
						// se c'e' riporto
						if (pMessage->time_stamp.dwLowDateTime < time_stamp.dwLowDateTime)
							pMessage->time_stamp.dwHighDateTime++;
					}


				} else {
					pMessage->time_stamp.dwHighDateTime = 0;
					pMessage->time_stamp.dwLowDateTime = 0;
				}

				__try {
					MMCPY(pMessage->message, message, msg_len);
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					pMessage->status = STATUS_FREE;
				}

				if (pMessage->status == STATUS_BUSY)
					pMessage->status = STATUS_WRIT;
				return TRUE;
			}
		}
	}

	// Se arriva qui, la coda e' DAVVERO piena e il messaggio viene droppato
	return FALSE;
}

void IPCClientWrite_setup(IPCClientWrite_data_struct *data)
{
	HMODULE h_krn;
	HANDLE h_file;

	h_krn = GetModuleHandle("kernel32.dll");
	data->pGetSystemTimeAsFileTime = (GetSystemTimeAsFileTime_t)GetProcAddress(h_krn, "GetSystemTimeAsFileTime");

	h_file = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, SHARE_MEMORY_WRITE_NAME);
	data->mem_addr = NULL;
	data->old_low_part = 0;
	data->old_hi_part = 0;
	data->increment = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		data->mem_addr = (message_struct *)MapViewOfFile(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_WRITE_SIZE);
}

