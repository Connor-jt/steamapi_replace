// steamapi_replacement.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "steam_deps.h"

#include "C:\Users\Joe bingle\Downloads\steamworks_sdk_160\SteamLiteshop\sdk\public\steam\steam_api.h"

#include <string>
#include <iostream>
#include <cstdio>

#include <windows.h>
//#include <Libloaderapi.h>
#include <Processenv.h>
#include <winreg.h>
#include <stringapiset.h>
#include <processthreadsapi.h>
#include <handleapi.h>
#include <thread>
#include <future>
#include <map>

using namespace std;


namespace SteamReplace {

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined;

// func typedefs
typedef void* (*CreateInterface)(const char* pName, int* pReturnCode);
typedef void* (*ReleaseThreadLocalMemory)(bool thread_exit);
typedef bool  (*Steam_IsKnownInterface)(const char* str);

typedef bool (*Steam_BGetCallback    )(HSteamPipe hSteamPipe, CallbackMsg_t* pCallbackMsg);
typedef bool (*Steam_FreeLastCallback)(HSteamPipe hSteamPipe);
typedef bool (*Steam_GetAPICallResult)(HSteamPipe hSteamPipe, SteamAPICall_t hSteamAPICall, void* pCallback, int cubCallback, int iCallbackExpected, bool* pbFailed);

static ReleaseThreadLocalMemory DAT_steamclient_ReleaseThreadLocalMemory;
static Steam_BGetCallback     DAT_steam_BGetCallback_func;
static Steam_FreeLastCallback DAT_steam_FreeLastCallback_func;
static Steam_GetAPICallResult DAT_steam_GetAPICallResult_func;

// statics
static ISteamClient* DAT_ISteamClient_ptr;
static ISteamUser* DAT_ISteamUser_ptr;
static long* DAT_steam_client_interface17; // MARKED FOR REMOVAL!!
static HMODULE DAT_steamclient_hmodule;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamPipe DAT_steam_alt_IPC_pipe;
static HSteamUser DAT_steam_user;

static std::map<int, s_deps::CCallbackBase*> registered_callbacks;

//namespace Threaded {
//class ISteamObjMap { // size: 0x30
//public:
//    ISteamObjMap* prev_obj;
//    ISteamObjMap* self_ptr2;
//    ISteamObjMap* next_obj;
//    char flag1;
//    char flag2;
//    USHORT unk1;
//    uint unk2;
//    int cb_index;
//    uint unk3;
//    CCallbackBase* callback;
//};
//class ISteamObj { // size: 0x80
//public:
//    ISteamObjMap* map_struct;
//    undefined8 field1_0x8;
//        
//    ISteamObjMap* active_map_struct;
//    HSteamUser userid;
//    HSteamPipe ipc_pipe;
//    void* unk_ptr2;
//
//    CCallbackBase* callback1;
//    uint has_callback1;
//    uint unk_int3;
//    void* unk_ptr4;
//    void* unk_ptr5;
//
//    CCallbackBase* callback2;
//    uint has_callback2;
//    uint unk_int6;
//    void* unk_ptr7;
//    void* unk_ptr8;
//
//    ISteamObjMap* map_struct2;
//    void* unk_ptr9;
//
//    longlong tls_header;
//};
//// 
////int SteamAPI_CheckCallbackRegistered_t_func(int iCallbackNum){
////    char cVar1;
////    int iVar6 = 0;
////    ISteamObjMap* callbacks_root;
////    ISteamObjMap* pIVar3;
////    ISteamObjMap* pIVar5;
////    ISteamObjMap* pIVar7;
////
////    callbacks_root = FUN_ISteam_thread()->map_struct;
////
////    pIVar3 = callbacks_root;
////    pIVar5 = callbacks_root->self_ptr2;
////
////    while (!pIVar5->flag2) {
////        if (pIVar5->cb_index < iCallbackNum) {
////            pIVar7 = pIVar5->next_obj;
////            pIVar5 = pIVar3;
////        }else
////            pIVar7 = pIVar5->prev_obj;
////       
////        pIVar3 = pIVar5;
////        pIVar5 = pIVar7;
////    }
////
////    if ((pIVar3->flag2 == 0) 
////    && ( pIVar3->cb_index <= iCallbackNum)) {
////        while ((pIVar3 != callbacks_root && (pIVar3->cb_index == iCallbackNum))) {
////            pIVar5 = pIVar3->next_obj;
////            iVar6 += 1;
////            if (!pIVar5->flag2) {
////                cVar1 = pIVar5->prev_obj->flag2;
////                pIVar3 = pIVar5;
////                pIVar5 = pIVar5->prev_obj;
////                while (!cVar1) {
////                    cVar1 = pIVar5->prev_obj->flag2;
////                    pIVar3 = pIVar5;
////                    pIVar5 = pIVar5->prev_obj;
////                }
////            }
////            else {
////                cVar1 = pIVar3->self_ptr2->flag2;
////                pIVar7 = pIVar3->self_ptr2;
////                pIVar5 = pIVar3;
////                while ((pIVar3 = pIVar7, !cVar1 && (pIVar5 == pIVar3->next_obj))) {
////                    cVar1 = pIVar3->self_ptr2->flag2;
////                    pIVar7 = pIVar3->self_ptr2;
////                    pIVar5 = pIVar3;
////                }
////            }
////        }
////    }
////    return iVar6;
////}
//}



const HKEY HKCR = (HKEY)0xffffffff80000000lu; // HKEY_CLASSES_ROOT
const HKEY HKCU = (HKEY)0xffffffff80000001lu; // HKEY_CURRENT_USER
const HKEY HKLM = (HKEY)0xffffffff80000002lu; // HKEY_LOCAL_MACHINE

// FINISHED
bool SteamAPI_IsSteamRunning(){

    char str_buf[70] = {0}; 
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;

    HKEY proc_key = 0;
    if (RegOpenKeyExW(HKCU, (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;

    memset(str_buf, 0, 70); // clean the buffer
    if (!MultiByteToWideChar(0xfde9, 0, "pid", -1, (LPWSTR)str_buf, 4)){
        RegCloseKey(proc_key);
        return false;}

    DWORD dwProcessId = 0;
    DWORD cbdata = 4;
    DWORD type = 0;
    if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, (LPBYTE)&dwProcessId, &cbdata)) {
        RegCloseKey(proc_key);
        return false;}
    RegCloseKey(proc_key);
    
    HANDLE hProcess = OpenProcess(0x400, 0, dwProcessId);
    if (!hProcess)
        return false;

    DWORD exit_code = 0;
    if ((GetExitCodeProcess(hProcess, &exit_code))
    && (exit_code == STILL_ACTIVE)) {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

// FINISHED 
bool steam_write_install_path(char* out_buf, int out_buf_size){
    if (!out_buf || (out_buf_size != 0x410)) 
        return false;

    char str_buf[70] = {0};
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;

    HKEY proc_key = 0;
    if (RegOpenKeyExW(HKCU, (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;

    memset(str_buf, 0, 70); // clean the buffer
    if (!MultiByteToWideChar(0xfde9, 0, "SteamClientDll64", -1, (LPWSTR)str_buf, 17)) {
        RegCloseKey(proc_key);
        return false;
    }

    DWORD cbdata = 0x820;
    DWORD type = 0;
    BYTE processPath_wstr[0x822];
    if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, processPath_wstr, &cbdata)) {
        RegCloseKey(proc_key);
        return false;
    }
    RegCloseKey(proc_key);

    // manually terminate wstring
    processPath_wstr[cbdata] = 0;
    processPath_wstr[cbdata+1] = 0;
    if (!WideCharToMultiByte(0xfde9, 0, (LPCWSTR)processPath_wstr, -1, out_buf, 0x410, 0, 0))
        return false;

    // alternative method to get filename if that failed (pretty sure this cant work with our setup)
    if (!out_buf[0]) {
        WCHAR alt_proc_path[0x103];
        alt_proc_path[0] = L'\0';
        if (!GetModuleFileNameW(GetModuleHandleA("steamclient64.dll"), alt_proc_path, 0x104) < 0x104)
            return false;
        if (!WideCharToMultiByte(0xfde9, 0, alt_proc_path, -1, out_buf, 0x410, 0, 0))
            return false;
    }
    return true;
}

// FINISHED
int init_steam_client(HMODULE* resulting_hmodule, ISteamClient** resulting_interface){
    if (!SteamReplace::SteamAPI_IsSteamRunning())
        return 8;

    CHAR steam_install_path[0x410] = {0};
    if (!steam_write_install_path(steam_install_path, sizeof(steam_install_path)))
        return 9;
    
    // count chars in string (including the null terminator)
    int path_chars = 0;
    while (steam_install_path[path_chars++]);

    LPWSTR steamclient_path_wstr = (LPWSTR)new char[path_chars*2];
    if (!MultiByteToWideChar(0xfde9, 0, steam_install_path, -1, steamclient_path_wstr, path_chars)) {
        delete[] steamclient_path_wstr;
        return 10;}

    HMODULE steamclient_library = LoadLibraryExW(steamclient_path_wstr, 0, 8);
    delete[] steamclient_path_wstr;

    if (!steamclient_library) 
        steamclient_library = LoadLibraryExA(steam_install_path, 0, 8);
    if (!steamclient_library)
        return 11;
    
    CreateInterface create_interface_func = (CreateInterface)GetProcAddress(steamclient_library, "CreateInterface");
    if (!create_interface_func) {
        FreeLibrary(steamclient_library);
        return 12;}

    DAT_steamclient_ReleaseThreadLocalMemory = (ReleaseThreadLocalMemory)GetProcAddress(DAT_steamclient_hmodule, "Steam_ReleaseThreadLocalMemory");

    DAT_steam_client_interface17 = (long*)(*create_interface_func)("SteamClient017", 0);
    *resulting_interface = (ISteamClient*)(*create_interface_func)("SteamClient021", 0);
    *resulting_hmodule = steamclient_library; // not sure why this is set without resulting_interface being true

    if (!*resulting_interface) {
        FreeLibrary(steamclient_library);
        return 13;}

    return 0;
}

// FINISHED
void SteamAPI_Shutdown() {
    if (DAT_steam_IPC_pipe && DAT_steam_user)
        DAT_ISteamClient_ptr->ReleaseUser(DAT_steam_IPC_pipe, DAT_steam_user);
    DAT_steam_user = 0;

    if (DAT_steam_IPC_pipe)
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_IPC_pipe);
    DAT_steam_IPC_pipe = 0;

    if (DAT_steam_alt_IPC_pipe) {
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_alt_IPC_pipe);
        DAT_steam_alt_IPC_pipe = 0;
    }
    DAT_steamclient_ReleaseThreadLocalMemory = 0;

    if (DAT_ISteamClient_ptr)
        DAT_ISteamClient_ptr->BShutdownIfAllPipesClosed();
    DAT_ISteamClient_ptr = 0;

    if (DAT_steamclient_hmodule)
        FreeLibrary(DAT_steamclient_hmodule);
    DAT_steamclient_hmodule = 0;


    DAT_steam_client_interface17 = 0;
}

// FINISHED
int init_steam(const char* pszInternalCheckInterfaceVersions){

    if (DAT_ISteamClient_ptr) return 1;

    int result = init_steam_client(&DAT_steamclient_hmodule, &DAT_ISteamClient_ptr);
    if (result) return result;

    DAT_steam_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    if (!DAT_steam_IPC_pipe) {
        SteamReplace::SteamAPI_Shutdown();
        return 2;}

    DAT_steam_user = DAT_ISteamClient_ptr->ConnectToGlobalUser(DAT_steam_IPC_pipe);
    if (!DAT_steam_user) {
        SteamReplace::SteamAPI_Shutdown();
        return 3;}

    // verify interface versions
    if (pszInternalCheckInterfaceVersions) {
        Steam_IsKnownInterface interface_check_func = (Steam_IsKnownInterface)GetProcAddress(DAT_steamclient_hmodule, "Steam_IsKnownInterface");
        if (interface_check_func) {
            while (*pszInternalCheckInterfaceVersions) {
                if (!(*interface_check_func)(pszInternalCheckInterfaceVersions)) {
                    SteamReplace::SteamAPI_Shutdown();
                    return 4;}
                // iterate string till we reach the next null terminator
                while (*pszInternalCheckInterfaceVersions++);
            }
        }
    }

    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    ISteamUtils* steam_utils = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
        SteamReplace::SteamAPI_Shutdown();
        return 5;}

    DAT_ISteamUser_ptr = DAT_ISteamClient_ptr->GetISteamUser(DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
    if (!DAT_ISteamUser_ptr) {
        SteamReplace::SteamAPI_Shutdown();
        return 6;}

    UINT app_id = steam_utils->GetAppID();
    ULONG game_id = (ULONG)app_id & 0xffffffff00ffffff; // not sure why this is a thing??
    if (!app_id) {
        SteamReplace::SteamAPI_Shutdown();
        return 7;}
    //UINT app_id = 0x00085E4E;

    char str_buf[32];
    if (!GetEnvironmentVariableA("SteamAppId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%u", app_id);
        SetEnvironmentVariableA("SteamAppId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%llu", app_id);
        SetEnvironmentVariableA("SteamGameId", str_buf);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf_s(str_buf, (size_t)32, "%llu", app_id);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    DAT_steam_BGetCallback_func = (Steam_BGetCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_BGetCallback");
    DAT_steam_FreeLastCallback_func = (Steam_FreeLastCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_FreeLastCallback");
    DAT_steam_GetAPICallResult_func = (Steam_GetAPICallResult)GetProcAddress(DAT_steamclient_hmodule, "Steam_GetAPICallResult");

    // not sure what our custom function would look like for this, if it even gets used??
    //DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(Threaded::SteamAPI_CheckCallbackRegistered_t_func);
    
    return 0;
}






// FINISHED
ISteamInput* DAT_SteamInput006;
ISteamUtils* DAT_SteamUtils010;
ISteamController* DAT_SteamController008;
void Steam_RunFrames(){
    if (!DAT_ISteamClient_ptr) return;
    
    // init/run steam untils
    if (!DAT_SteamUtils010) {
        DAT_SteamUtils010 = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
        if (DAT_SteamUtils010) DAT_SteamUtils010->GetAppID();} // not sure why this is called
    if (DAT_SteamUtils010) 
        DAT_SteamUtils010->RunFrame();
    
    // init/run steam input
    if (!DAT_SteamInput006)
        DAT_SteamInput006 = (ISteamInput*)DAT_ISteamClient_ptr->GetISteamGenericInterface(DAT_steam_user, DAT_steam_IPC_pipe, "SteamInput006");
    if (DAT_SteamInput006)
        DAT_SteamInput006->RunFrame(0);

    // init/run steam controller
    if (!DAT_SteamController008)
        DAT_SteamController008 = (ISteamController*)DAT_ISteamClient_ptr->GetISteamGenericInterface(DAT_steam_user, DAT_steam_IPC_pipe, "SteamController008");
    if (DAT_SteamController008)
        DAT_SteamController008->RunFrame();
}

// 
void route_callback(int iCallback, void* data) {
    auto var = registered_callbacks[iCallback];
    if (var) var->Run(data);
}
void process_callbacks(HSteamPipe ipc_pipe, char is_server) {
    if (!DAT_steam_BGetCallback_func || !DAT_steam_FreeLastCallback_func)
        return;

    CallbackMsg_t cb_output;
    while ((*DAT_steam_BGetCallback_func)(ipc_pipe, &cb_output)) {

        cout << "Callback recieved: " << cb_output.m_iCallback << "\n";

        // if the callback type is 'SteamAPICallCompleted_t' then we have to manually await the thing
        if (cb_output.m_iCallback == 703) {
            SteamAPICallCompleted_t* pCallCompleted = (SteamAPICallCompleted_t*)cb_output.m_pubParam;
            void* pTmpCallResult = new char[pCallCompleted->m_cubParam];
            bool bFailed;
            if ((*DAT_steam_GetAPICallResult_func)(ipc_pipe, pCallCompleted->m_hAsyncCall, pTmpCallResult, pCallCompleted->m_cubParam, pCallCompleted->m_iCallback, &bFailed))
                route_callback(pCallCompleted->m_iCallback, pTmpCallResult);
            delete[] pTmpCallResult;
        }
        else route_callback(cb_output.m_iCallback, cb_output.m_pubParam);
                
        memset(cb_output.m_pubParam, 0, cb_output.m_cubParam);
        (*DAT_steam_FreeLastCallback_func)(ipc_pipe);
    }
}


void process_alt_callbacks(HSteamPipe ipc_pipe){
    CallbackMsg_t cb_output;
    while (true) {
        if (!DAT_steam_BGetCallback_func) return;
        if (!(*DAT_steam_BGetCallback_func)(ipc_pipe, &cb_output)) break;

        if (DAT_steam_FreeLastCallback_func)
            (*DAT_steam_FreeLastCallback_func)(ipc_pipe);
    }
}

void SteamAPI_RunCallbacks(){
    if (DAT_steam_IPC_pipe) {
        Steam_RunFrames();
        process_callbacks(DAT_steam_IPC_pipe, 0);
        if (DAT_steam_alt_IPC_pipe)
            process_alt_callbacks(DAT_steam_alt_IPC_pipe);
        return;
    }
    // i dont think this code will ever run ??
    if (DAT_steamclient_ReleaseThreadLocalMemory)
        (*DAT_steamclient_ReleaseThreadLocalMemory)(0);
    if (DAT_steam_alt_IPC_pipe)
        process_alt_callbacks(DAT_steam_alt_IPC_pipe);
    return;
}

ISteamUser* SteamUser() {
    return DAT_ISteamUser_ptr;
}

}

namespace EPacket{
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";
std::string base64_encode(unsigned char* bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}


static std::promise<void> SteamAuthComplete;
static std::string EncodedSteamAuth;

//class SteamAuthHelper{
//public:
    static void OnEncryptedAppTicketResponse(EncryptedAppTicketResponse_t* pEncryptedAppTicketResponse, bool bIOFailure){
        switch (pEncryptedAppTicketResponse->m_eResult)
        {
        case k_EResultOK:{
            unsigned char rgubTicket[1024];
            uint32 cubTicket;
            if (SteamReplace::SteamUser()->GetEncryptedAppTicket(rgubTicket, sizeof(rgubTicket), &cubTicket)){
                EncodedSteamAuth = base64_encode(rgubTicket, cubTicket);
                std::cout << "Steam App Ticket received" << std::endl;
                std::cout << EncodedSteamAuth << std::endl;
            }
            else printf("GetEncryptedAppTicket failed.\n");
        }
        break;
        case k_EResultNoConnection:
            printf("Calling RequestEncryptedAppTicket while not connected to steam results in this error.\n"); 
            break;
        case k_EResultDuplicateRequest:
            printf("Calling RequestEncryptedAppTicket while there is already a pending request results in this " "error.\n"); 
            break;
        case k_EResultLimitExceeded:
            printf("Calling RequestEncryptedAppTicket more than once per minute returns this error.\n"); 
            break;
        }

        SteamAuthComplete.set_value();
    }

    static s_deps::CCallResult</*SteamAuthHelper,*/ EncryptedAppTicketResponse_t> m_SteamCallResultEncryptedAppTicket;
//};
}

int main(){
    const char* pszInternalCheckInterfaceVersions =
        "SteamUtils010" "\0"
        //"SteamNetworkingUtils004" "\0"
        //"STEAMAPPS_INTERFACE_VERSION008" "\0"
        "SteamController008" "\0"
        //"SteamFriends017" "\0"
        //"SteamMatchGameSearch001" "\0"
        //"STEAMHTMLSURFACE_INTERFACE_VERSION_005" "\0"
        //"STEAMHTTP_INTERFACE_VERSION003" "\0"
        "SteamInput006" "\0"
        //"STEAMINVENTORY_INTERFACE_V003" "\0"
        //"SteamMatchMakingServers002" "\0"
        //"SteamMatchMaking009" "\0"
        //"STEAMMUSICREMOTE_INTERFACE_VERSION001" "\0"
        //"STEAMMUSIC_INTERFACE_VERSION001" "\0"
        //"SteamNetworkingMessages002" "\0"
        //"SteamNetworkingSockets012" "\0"
        //"SteamNetworking006" "\0"
        //"STEAMPARENTALSETTINGS_INTERFACE_VERSION001" "\0"
        //"SteamParties002" "\0"
        //"STEAMREMOTEPLAY_INTERFACE_VERSION002" "\0"
        //"STEAMREMOTESTORAGE_INTERFACE_VERSION016" "\0"
        //"STEAMSCREENSHOTS_INTERFACE_VERSION003" "\0"
        //"STEAMUGC_INTERFACE_VERSION020" "\0"
        //"STEAMUSERSTATS_INTERFACE_VERSION012" "\0"
        "SteamUser023" "\0"
        //"STEAMVIDEO_INTERFACE_V007" "\0"
        "\0";

    switch (SteamReplace::init_steam(pszInternalCheckInterfaceVersions)) {
    case  1: std::cout << "steam is already running" << std::endl; break;
    case  2: std::cout << "Cannot create IPC pipe to Steam client process.  Steam is probably not running." << std::endl; break;
    case  3: std::cout << "ConnectToGlobalUser failed." << std::endl; break;
    case  4: std::cout << "interface check failed" << std::endl; break;
    case  5: std::cout << "failed to load 'SteamUtils010' interface" << std::endl; break;
    case  6: std::cout << "failed to load 'SteamUser023' interface" << std::endl; break;
    case  7: std::cout << "No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder." << std::endl; break;
    case  8: std::cout << "[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam." << std::endl; break;
    case  9: std::cout << "Could not determine Steam client install directory." << std::endl; break;
    case 10: std::cout << "couldn't convert path to wide string" << std::endl; break;
    case 11: std::cout << "Failed to load steam client module" << std::endl; break;
    case 12: std::cout << "Unable to locate interface factory in steamclient64.dll" << std::endl; break;
    case 13: std::cout << "failed to load 'SteamClient021' interface" << std::endl; break;
    case  0:{
        std::atomic<bool> bHaltBackgroundThread{ false };
        // Set up a background thread to run
        std::thread HandlerThread = std::thread([&]() {
            while (!bHaltBackgroundThread) {
                //Modio::RunPendingHandlers();
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                SteamReplace::SteamAPI_RunCallbacks();
            }
            bHaltBackgroundThread = false;
        });

        //EPacket::SteamAuthHelper* SteamCallbacks = new EPacket::SteamAuthHelper();
        // Get the Steam Encrypted App Ticket
        char k_unSecretData[] = { 0x39, 0x66, 0x37, 0x61, 0x62, 0x64, 0x36, 0x33, 0x37, 0x35, 0x63, 0x34, 0x61, 0x33, 0x66, 0x64, 0x35, 0x30, 0x61, 0x37, 0x32, 0x62, 0x30, 0x39, 0x31, 0x31, 0x31, 0x35, 0x63, 0x62, 0x32, 0x33, 0x37, 0x32, 0x64, 0x35, 0x65, 0x35, 0x61, 0x63, 0x37, 0x61, 0x37, 0x37, 0x31, 0x39, 0x65, 0x35, 0x34, 0x30, 0x35, 0x33, 0x30, 0x62, 0x32, 0x39, 0x37, 0x65, 0x63, 0x34, 0x62, 0x65, 0x37, 0x39, 0x00 };
        SteamAPICall_t hSteamAPICall = SteamReplace::SteamUser()->RequestEncryptedAppTicket(&k_unSecretData, sizeof(k_unSecretData));
        cout << "API call num: " << hSteamAPICall << "\n";
        cout << "Callback expected: " << EncryptedAppTicketResponse_t::k_iCallback << "\n";
        /*SteamCallbacks->*/EPacket::m_SteamCallResultEncryptedAppTicket.Set(/*hSteamAPICall,*/ /*SteamCallbacks,*/ &EPacket::/*SteamAuthHelper::*/OnEncryptedAppTicketResponse);

        SteamReplace::registered_callbacks[EncryptedAppTicketResponse_t::k_iCallback] = (s_deps::CCallbackBase*)&EPacket::m_SteamCallResultEncryptedAppTicket;

        EPacket::SteamAuthComplete.get_future().wait();

        bHaltBackgroundThread = false;
        HandlerThread.join();
    }}
}

