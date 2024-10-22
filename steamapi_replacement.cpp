// steamapi_replacement.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "C:\Users\Joe bingle\Downloads\steamworks_sdk_160\SteamLiteshop\sdk\public\steam\steam_api.h"

#include <string>
#include <iostream>
#include <cstdio>

#include <Libloaderapi.h>

#include <Processenv.h>

using namespace std;
namespace SteamReplace {


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




ulonglong SteamInternal_SteamAPI_Init(const char* pszInternalCheckInterfaceVersions, char* pOutErrMsg){
    ulonglong SteamInit_result;
    ulonglong last_char_index;
    char error_output_buffer[1024];
    longlong i;

    memset(error_output_buffer, 0, 0x400);
    SteamInit_result = init_steam(0, pszInternalCheckInterfaceVersions, error_output_buffer);
    if (pOutErrMsg != (char*)0x0) {
        SteamInit_result = 0xffffffffffffffff;
        do {
            last_char_index = SteamInit_result + 1;
            i = SteamInit_result + 1;
            SteamInit_result = last_char_index;
        } while (error_output_buffer[i] != '\0');

        if (last_char_index > 0x3ff)
            last_char_index = 0x3ff;
        
        memcpy(pOutErrMsg, error_output_buffer, last_char_index);
        pOutErrMsg[last_char_index] = '\0';
    }
    return SteamInit_result;
}

static ISteamClient* DAT_ISteamClient_ptr;
static char DAT_is_anon_user;
static HMODULE DAT_steamclient_hmodule;
//static HMODULE DAT_steamclient_ALT_module;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamPipe DAT_steam_alt_IPC_pipe;
static HSteamUser DAT_steam_user;
static long* DAT_steamclient_ReleaseThreadLocalMemory;
static uint _DAT_register_callback_mode_manual;

undefined4 init_steam(char is_anon, const char* pszInternalCheckInterfaceVersions, char* error_output_buffer)
{
    char cVar1;
    undefined auVar2[16];
    uint app_id;
    ulonglong game_id;
    DWORD result;
    FARPROC pFVar4;
    INT_PTR IVar5;
    longlong lVar6;
    ISteamUtils* steam_utils;
    ISteamUser* steam_user;
    longlong lVar7;
    __uint64 _Var8;
    LPCWSTR lpWideCharStr;
    CSteamID user_id;
    undefined4 shutdown_Code;
    ulonglong local_res20;
    CHAR string_buf32[32];
    CHAR local_438;
    char acStack_437[1039];
    HMODULE temp_module;

    if (!DAT_ISteamClient_ptr) return 0;

    DAT_is_anon_user = is_anon;
    DAT_ISteamClient_ptr = init_steam_client(&DAT_steamclient_hmodule, &DAT_is_anon_user, 0, "SteamClient021", error_output_buffer);
    if (!DAT_ISteamClient_ptr) return 1;
    
    //DAT_13b445870 = 0;
    shutdown_Code = 1;

    DAT_steam_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    DAT_steam_user = DAT_ISteamClient_ptr->ConnectToGlobalUser(DAT_steam_IPC_pipe);

    if (DAT_steam_IPC_pipe == 0) {
        shutdown_Code = 2;
        // "Cannot create IPC pipe to Steam client process.  Steam is probably not running."
        goto return_failure;
    }
    if (DAT_steam_user == 0) {
        // "ConnectToGlobalUser failed."
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_IPC_pipe);
        goto return_failure;
    }

    // verify interface versions
    if (pszInternalCheckInterfaceVersions != 0) {
        temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        pFVar4 = GetProcAddress(temp_module, "Steam_IsKnownInterface");
        if (pFVar4 != (FARPROC)0x0) {
            cVar1 = *pszInternalCheckInterfaceVersions;
            while (cVar1) {
                IVar5 = (*pFVar4)(pszInternalCheckInterfaceVersions);
                if ((char)IVar5 == '\0') {
                    //steam_format_error(error_output_buffer, "No %s", pszInternalCheckInterfaceVersions);
                    //steam_missing_feature(IPC_pipe, pszInternalCheckInterfaceVersions);
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
    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    steam_utils = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
        //steam_format_error(error_output_buffer, "No %s", "SteamUtils010");
        // IPC_pipe = DAT_steam_IPC_pipe;
        //temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        //pFVar4 = GetProcAddress(temp_module, "Steam_NotifyMissingInterface");
        //if (pFVar4 != (FARPROC)0x0) {
        //    (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUtils010");
        //}
    }

    steam_user = DAT_ISteamClient_ptr->GetISteamUser(DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
    if (!steam_user) {
        shutdown_Code = 3;
        goto return_failure;
    }
    app_id = steam_utils->GetAppID();
    game_id = (ulonglong)app_id & 0xffffffff00ffffff; // not sure why this is a thing??
    if (!app_id) {
        // No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder.
        goto return_failure;
        //steam_format_error(error_output_buffer, "No %s", "SteamUser023");
        //temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        //pFVar4 = GetProcAddress(temp_module, "Steam_NotifyMissingInterface");
        //if (pFVar4 != (FARPROC)0x0) {
        //    (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUser023");
        //    shutdown_Code = 3;
        //    goto return_failure;
        //}
    }
    if (!GetEnvironmentVariableA("SteamAppId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 }; // steam had a nice optimization for this actually, only set the first char and last char to \0
        sprintf(str_buf, "%u", app_id, "SteamUser023");
        SetEnvironmentVariableA("SteamAppId", string_buf32);
    }
    if (!GetEnvironmentVariableA("SteamGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamGameId", string_buf32);
        SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
    }
    //SteamAPI_SetBreakpadAppID(app_id);
    steam_config_callbacks(DAT_steamclient_hmodule);
    //config_breakpad_thing();
    
    // probably this stuff isn't needed?? doesn't seem to store anything but check whether the module can be loaded via various means??
    //if ((app_id != 0x301) && (temp_module = GetModuleHandleA("gameoverlayrenderer64.dll"), temp_module == (HMODULE)0x0)) {
    //    steam_write_install_path(0, 0);
    //    //steam_print_s_c_s(&local_438, "%s\\%s", &DAT_steam_install_path, "gameoverlayrenderer64.dll");
    //    lVar6 = -1;
    //    do {
    //        lVar7 = lVar6;
    //        lVar6 = lVar7 + 1;
    //    } while ((&local_438)[lVar7 + 1] != 0);
    //    auVar2 = ZEXT816(2) * ZEXT816((longlong)(int)(lVar7 + 1) + 1);
    //    _Var8 = SUB168(auVar2, 0);
    //    if (SUB168(auVar2 >> 0x40, 0) != 0) {
    //        _Var8 = 0xffffffffffffffff;
    //    }
    //    lpWideCharStr = (LPCWSTR)operator_new(_Var8);
    //    if (MultiByteToWideChar(0xfde9, 0, &local_438, -1, lpWideCharStr, (int)lVar7 + 2) == 0) {
    //        *lpWideCharStr = L'\0';
    //    }
    //    temp_module = LoadLibraryExW(lpWideCharStr, (HANDLE)0x0, 8);
    //    free(lpWideCharStr);
    //    if ((temp_module == (HMODULE)0x0) && (temp_module = LoadLibraryExA(&local_438, (HANDLE)0x0, 8), temp_module == (HMODULE)0x0)) {
    //        load_library_wstr("gameoverlayrenderer64.dll", 1, 0);
    //    }
    //}


    if (_DAT_register_callback_mode_manual < 1)
        DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(SteamAPI_CheckCallbackRegistered_t_func);
    
    // minidump write steam id
    //user_id = steam_user->GetSteamID();
    //FUN_13b4074c0(*user_id);
    return 0;
        
    
return_failure:
    ; DOODY;  SteamAPI_Shutdown();
    return shutdown_Code;
}


}


int main()
{
    const char* pszInternalCheckInterfaceVersions =
        STEAMUTILS_INTERFACE_VERSION "\0"
        STEAMNETWORKINGUTILS_INTERFACE_VERSION "\0"
        STEAMAPPS_INTERFACE_VERSION "\0"
        STEAMCONTROLLER_INTERFACE_VERSION "\0"
        STEAMFRIENDS_INTERFACE_VERSION "\0"
        STEAMGAMESEARCH_INTERFACE_VERSION "\0"
        STEAMHTMLSURFACE_INTERFACE_VERSION "\0"
        STEAMHTTP_INTERFACE_VERSION "\0"
        STEAMINPUT_INTERFACE_VERSION "\0"
        STEAMINVENTORY_INTERFACE_VERSION "\0"
        STEAMMATCHMAKINGSERVERS_INTERFACE_VERSION "\0"
        STEAMMATCHMAKING_INTERFACE_VERSION "\0"
        STEAMMUSICREMOTE_INTERFACE_VERSION "\0"
        STEAMMUSIC_INTERFACE_VERSION "\0"
        STEAMNETWORKINGMESSAGES_INTERFACE_VERSION "\0"
        STEAMNETWORKINGSOCKETS_INTERFACE_VERSION "\0"
        STEAMNETWORKING_INTERFACE_VERSION "\0"
        STEAMPARENTALSETTINGS_INTERFACE_VERSION "\0"
        STEAMPARTIES_INTERFACE_VERSION "\0"
        STEAMREMOTEPLAY_INTERFACE_VERSION "\0"
        STEAMREMOTESTORAGE_INTERFACE_VERSION "\0"
        STEAMSCREENSHOTS_INTERFACE_VERSION "\0"
        STEAMUGC_INTERFACE_VERSION "\0"
        STEAMUSERSTATS_INTERFACE_VERSION "\0"
        STEAMUSER_INTERFACE_VERSION "\0"
        STEAMVIDEO_INTERFACE_VERSION "\0"
        "\0";
    SteamReplace::SteamInternal_SteamAPI_Init(pszInternalCheckInterfaceVersions);
}



