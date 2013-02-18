#define WRAPPER_MAX_SHARED_MEM 0x40

#define MAX_MSG_LEN 0x400 // Lunghezza di un messaggio
#define MAX_MSG_NUM 3000 // Massimo numero di messaggi in coda

typedef struct {
	BYTE status; 
#define STATUS_FREE 0 // Libero
#define STATUS_BUSY 1 // In scrittura
#define STATUS_WRIT 2 // Scritto
	FILETIME time_stamp;
	DWORD wrapper_tag;
	DWORD message_len;
	DWORD flags;
	DWORD priority;
#define IPC_LOW_PRIORITY 0x0
#define IPC_DEF_PRIORITY 0x10
#define IPC_HI_PRIORITY  0x100
	BYTE message[MAX_MSG_LEN];
} message_struct;

typedef struct {
	BYTE *mem_addr;
} IPCClientRead_data_struct;

typedef void (WINAPI *GetSystemTimeAsFileTime_t) (LPFILETIME);
typedef struct {
	message_struct *mem_addr;
	GetSystemTimeAsFileTime_t pGetSystemTimeAsFileTime;
	DWORD increment;
	DWORD old_low_part;
	DWORD old_hi_part;
} IPCClientWrite_data_struct;

typedef BOOL (__stdcall *IPCClientWrite_t)(DWORD wrapper_tag, IPCClientWrite_data_struct *pData, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority);
typedef BYTE *(__stdcall *IPCClientRead_t)(DWORD wrapper_tag, IPCClientRead_data_struct *pData);

extern void IPCClientWrite_setup(IPCClientWrite_data_struct *data);
extern void IPCClientRead_setup(IPCClientRead_data_struct *data);
extern BOOL __stdcall IPCClientWrite(DWORD wrapper_tag, IPCClientWrite_data_struct *pData, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority);
extern BYTE * __stdcall IPCClientRead(DWORD wrapper_tag, IPCClientRead_data_struct *pData);

#define SHARE_MEMORY_WRITE_SIZE ((MAX_MSG_NUM * sizeof(message_struct))+2)
#define SHARE_MEMORY_READ_SIZE (WRAPPER_COUNT*WRAPPER_MAX_SHARED_MEM) // Dimensione spazio per la lettura delle configurazioni da parte dei wrapper                                
//#define SHARE_MEMORY_READ_BASENAME "DPA"
//#define SHARE_MEMORY_WRITE_BASENAME "DPB"

extern char SHARE_MEMORY_READ_NAME[];
extern char SHARE_MEMORY_WRITE_NAME[];

#define COMMON_IPC_DATA BOOL active;

typedef struct {
	COMMON_IPC_DATA;
} common_ipc_conf_struct;

#define IPC_CLIENT_READ(TAG) if (pData->ipc_client_read) {pData->ipc_client_read(TAG, pData->ipc_read_data);}
#define IPC_CLIENT_WRITE(TAG, MSG, MSGLEN, FLAGS, PRIORITY) if (pData->ipc_client_write) {pData->ipc_client_write(TAG, pData->ipc_write_data, MSG, MSGLEN, FLAGS, PRIORITY);} 

#define IF_ACTIVE_AGENT(TAG) if(pData->ipc_client_read && (common_ipc_conf=(common_ipc_conf_struct *)pData->ipc_client_read(TAG, pData->ipc_read_data)) && common_ipc_conf->active ) 