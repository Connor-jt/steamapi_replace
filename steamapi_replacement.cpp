// steamapi_replacement.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "C:\Users\Joe bingle\Downloads\steamworks_sdk_160\SteamLiteshop\sdk\public\steam\steam_api.h"

#include <string>
#include <iostream>
#include <cstdio>

#include <Libloaderapi.h>

using namespace std;

typedef unsigned long ulonglong;
typedef unsigned long __uint64;
typedef long longlong;
typedef unsigned int uint;
typedef int DWORD;
typedef char CHAR;

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined;




ulonglong SteamInternal_SteamAPI_Init(char* pszInternalCheckInterfaceVersions, char* pOutErrMsg)
{
    uint uVar1;
    ulonglong SteamInit_result;
    undefined4 extraout_var;
    ulonglong last_char_index;
    char error_output_buffer[1024];
    longlong i;

    memset(error_output_buffer, 0, 0x400);
    uVar1 = init_steam(0, pszInternalCheckInterfaceVersions, error_output_buffer);
    //SteamInit_result = CONCAT44(extraout_var, uVar1);
    SteamInit_result = uVar1;
    if (pOutErrMsg != (char*)0x0) {
        SteamInit_result = 0xffffffffffffffff;
        do {
            last_char_index = SteamInit_result + 1;
            i = SteamInit_result + 1;
            SteamInit_result = last_char_index;
        } while (error_output_buffer[i] != '\0');
        if (last_char_index > 0x3ff) {
            last_char_index = 0x3ff;
        }
        memcpy(pOutErrMsg, error_output_buffer, last_char_index);
        SteamInit_result = (ulonglong)uVar1;
        pOutErrMsg[last_char_index] = '\0';
    }
    return SteamInit_result;
}

static ISteamClient* DAT_ISteamClient_ptr;
static long* DAT_unused_steam_init_param;
static HMODULE* DAT_steamclient_hmodule;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamUser DAT_steam_user;

undefined4 init_steam(char unused, char* pszInternalCheckInterfaceVersions, char* error_output_buffer)

{
    char cVar1;
    undefined auVar2[16];
    uint uVar3;
    DWORD result;
    FARPROC pFVar4;
    INT_PTR IVar5;
    longlong lVar6;
    longlong* steam_utils;
    longlong* steam_user;
    longlong lVar7;
    __uint64 _Var8;
    LPCWSTR lpWideCharStr;
    undefined8* puVar9;
    undefined4 shutdown_Code;
    ulonglong local_res20;
    CHAR string_buf32[32];
    CHAR local_438;
    char acStack_437[1039];
    int IPC_pipe;
    ISteamClient* steam_client_ptr;
    HMODULE steamclient_module;

    if (DAT_ISteamClient_ptr != (ISteamClient*)0x0) {
        return 0;
    }
    //DAT_unused_steam_init_param = unused;
    DAT_ISteamClient_ptr = (ISteamClient*)init_steam_client(&DAT_steamclient_hmodule, &DAT_unused_steam_init_param, 0, "SteamClient021", error_output_buffer);
    if (DAT_ISteamClient_ptr == (ISteamClient*)0x0) {
        return 1;
    }
    //DAT_13b445870 = 0;
    shutdown_Code = 1;
    if (unused == 0) {
        DAT_steam_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
        DAT_steam_user = DAT_ISteamClient_ptr->ConnectToGlobalUser(DAT_steam_IPC_pipe);
        steam_client_ptr = DAT_ISteamClient_ptr;
        if (DAT_steam_IPC_pipe == 0) {
            shutdown_Code = 2;
            // "Cannot create IPC pipe to Steam client process.  Steam is probably not running."
            goto return_failure;
        }
        if (DAT_steam_user == 0) {
            // "ConnectToGlobalUser failed."
            steam_client_ptr->BReleaseSteamPipe(DAT_steam_IPC_pipe);
            goto return_failure;
        }
    }
    //else { // we dont run this section
    //    DAT_steam_user = (*(code*)DAT_ISteamClient_ptr->func_table[3])(DAT_ISteamClient_ptr, &DAT_steam_IPC_pipe, 10);
    //    if ((DAT_steam_user == 0) || (DAT_steam_IPC_pipe == 0)) {
    //        // "CreateLocalUser failed."
    //        *(undefined4*)error_output_buffer = 0x61657243;
    //        *(undefined4*)(error_output_buffer + 4) = 0x6f4c6574;
    //        *(undefined4*)(error_output_buffer + 8) = 0x556c6163;
    //        *(undefined4*)(error_output_buffer + 0xc) = 0x20726573;
    //        *(undefined4*)(error_output_buffer + 0x10) = 0x6c696166;
    //        *(undefined2*)(error_output_buffer + 0x14) = 0x6465;
    //        error_output_buffer[0x16] = '\0';
    //        return 1;
    //    }
    //}
    IPC_pipe = DAT_steam_IPC_pipe;
    if (pszInternalCheckInterfaceVersions != (char*)0x0) {
        steamclient_module = DAT_steamclient_hmodule;
        if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
            steamclient_module = DAT_steamclient_ALT_module;
        }
        pFVar4 = GetProcAddress(steamclient_module, "Steam_IsKnownInterface");
        if (pFVar4 != (FARPROC)0x0) {
            cVar1 = *pszInternalCheckInterfaceVersions;
            while (cVar1 != '\0') {
                IVar5 = (*pFVar4)(pszInternalCheckInterfaceVersions);
                if ((char)IVar5 == '\0') {
                    steam_format_error(error_output_buffer, "No %s", pszInternalCheckInterfaceVersions);
                    FUN_13b4072f0(IPC_pipe, pszInternalCheckInterfaceVersions);
                    shutdown_Code = 3;
                    goto return_failure;
                }
                lVar6 = -1;
                do {
                    lVar7 = lVar6;
                    lVar6 = lVar7 + 1;
                } while (pszInternalCheckInterfaceVersions[lVar6] != '\0');
                pszInternalCheckInterfaceVersions = pszInternalCheckInterfaceVersions + lVar7 + 2;
                cVar1 = *pszInternalCheckInterfaceVersions;
            }
        }
    }
    if (DAT_steamclient_ReleaseThreadLocalMemory == 0) {
        DAT_steam_alt_IPC_pipe = (*(code*)*DAT_ISteamClient_ptr->func_table)();
    }
    steam_utils = (longlong*)(*(code*)DAT_ISteamClient_ptr->func_table[0xc])(DAT_ISteamClient_ptr, 0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (steam_utils == (longlong*)0x0) {
        steam_format_error(error_output_buffer, "No %s", "SteamUtils010");
        IPC_pipe = DAT_steam_IPC_pipe;
        steamclient_module = DAT_steamclient_hmodule;
        if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
            steamclient_module = DAT_steamclient_ALT_module;
        }
        pFVar4 = GetProcAddress(steamclient_module, "Steam_NotifyMissingInterface");
        if (pFVar4 != (FARPROC)0x0) {
            (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUtils010");
        }
    }
    else {
        steam_user = (longlong*)(*(code*)DAT_ISteamClient_ptr->func_table[5])(DAT_ISteamClient_ptr, DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
        if (steam_user != (longlong*)0x0) {
            uVar3 = (**(code**)(*steam_utils + 0x48))(steam_utils);
            if (uVar3 != 0) {
                result = GetEnvironmentVariableA("SteamAppId", (LPSTR)0x0, 0);
                if (result == 0) {
                    string_buf32[0] = '\0';
                    steam_get_appid(string_buf32, &steam_appid);
                    SetEnvironmentVariableA("SteamAppId", string_buf32);
                }
                result = GetEnvironmentVariableA("SteamGameId", (LPSTR)0x0, 0);
                if (result == 0) {
                    local_res20 = (ulonglong)uVar3 & 0xffffffff00ffffff;
                    string_buf32[0] = '\0';
                    steam_get_gameid(string_buf32, &steam_gameid);
                    SetEnvironmentVariableA("SteamGameId", string_buf32);
                    SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
                }
                result = GetEnvironmentVariableA("SteamOverlayGameId", (LPSTR)0x0, 0);
                if (result == 0) {
                    local_res20 = (ulonglong)uVar3 & 0xffffffff00ffffff;
                    string_buf32[0] = '\0';
                    steam_get_gameid(string_buf32, &steam_gameid, local_res20);
                    SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
                }
                SteamAPI_SetBreakpadAppID(uVar3);
                steam_config_callbacks(DAT_steamclient_hmodule);
                config_breakpad_thing();
                if ((uVar3 != 0x301) && (steamclient_module = GetModuleHandleA(PTR_s_gameoverlayrenderer64.dll_13b4443a0), steamclient_module == (HMODULE)0x0)) {
                    steam_write_install_path(0, 0);
                    steam_print_s_c_s(&local_438, "%s\\%s", &DAT_steam_install_path, PTR_s_gameoverlayrenderer64.dll_13b4443a0);
                    lVar6 = -1;
                    do {
                        lVar7 = lVar6;
                        lVar6 = lVar7 + 1;
                    } while ((&local_438)[lVar7 + 1] != '\0');
                    auVar2 = ZEXT816(2) * ZEXT816((longlong)(int)(lVar7 + 1) + 1);
                    _Var8 = SUB168(auVar2, 0);
                    if (SUB168(auVar2 >> 0x40, 0) != 0) {
                        _Var8 = 0xffffffffffffffff;
                    }
                    lpWideCharStr = (LPCWSTR)operator_new(_Var8);
                    IPC_pipe = MultiByteToWideChar(0xfde9, 0, &local_438, -1, lpWideCharStr, (int)lVar7 + 2);
                    if (IPC_pipe == 0) {
                        *lpWideCharStr = L'\0';
                    }
                    steamclient_module = LoadLibraryExW(lpWideCharStr, (HANDLE)0x0, 8);
                    free_mem(lpWideCharStr);
                    if ((steamclient_module == (HMODULE)0x0) && (steamclient_module = LoadLibraryExA(&local_438, (HANDLE)0x0, 8), steamclient_module == (HMODULE)0x0)) {
                        FUN_13b4075c0(PTR_s_gameoverlayrenderer64.dll_13b4443a0, 1, 0);
                    }
                }
                if (_DAT_register_callback_mode_manual < 1) {
                    (*(code*)DAT_ISteamClient_ptr->func_table[0x20])(DAT_ISteamClient_ptr, SteamAPI_CheckCallbackRegistered_t_func);
                }
                puVar9 = (undefined8*)(**(code**)(*steam_user + 0x10))(steam_user, &local_res20);
                FUN_13b4074c0(*puVar9);
                return 0;
            }
            // No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder.
            goto return_failure;
        }
        steam_format_error(error_output_buffer, "No %s", "SteamUser023");
        IPC_pipe = DAT_steam_IPC_pipe;
        steamclient_module = DAT_steamclient_hmodule;
        if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
            steamclient_module = DAT_steamclient_ALT_module;
        }
        pFVar4 = GetProcAddress(steamclient_module, "Steam_NotifyMissingInterface");
        if (pFVar4 != (FARPROC)0x0) {
            (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUser023");
            shutdown_Code = 3;
            goto return_failure;
        }
    }
    shutdown_Code = 3;
return_failure:
    SteamAPI_Shutdown();
    return shutdown_Code;
}




int main()
{

}



