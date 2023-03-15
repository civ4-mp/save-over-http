#include "stdafx.h"

#define _MBCS
#undef _UNICODE

#include <cstdlib> // needed for update_path_env()
#include <iostream>
#include <sstream>
#include <assert.h>

// To share saves in DirectIP mode
//#include <winsock2.h>
//#include <Ws2tcpip.h>
//#pragma comment(lib, "Ws2_32.lib")
#define WITH_WEBSERVER

// Create BTS_Wrapper.log or Name for  '-l [Name]' arguments
#define WITH_LOGFILE

// Open sockets on IPv6 addresses and redirect traffic.
#define WITH_IPv6

#include <windows.h>

#include "RemoteOps.h"

#ifndef _UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

//std::string sWebserver_Port("8080");
std::string sWebserver_Port("-1");  // Disabled
int Webserver_Port = atoi(sWebserver_Port.c_str());

std::string sLogfile("BTS_Wrapper.log");

// Detect filename of newest exe
const std::string getExeFilename() {

    std::string names[] = {
        "Civ4BeyondSword2020.exe",
        "Civ4BeyondSword2019.exe",
        "Civ4BeyondSword2018.exe",
        "Civ4BeyondSword2017.exe",
        "Civ4BeyondSword2016.exe",
        "Civ4BeyondSword2015.exe",
        "Civ4BeyondSword2014.exe",
        "Civ4BeyondSword.exe"
    };

    int n = sizeof(names) / sizeof(names[0]);
    for (int i = 0; i<n; ++i) {
        if (GetFileAttributesA(names[i].c_str()) != INVALID_FILE_ATTRIBUTES) {
            return names[i];
        }
    }
    return std::string("Exe not found");
}

// Add 'BTS_Wrapper_Libs' subfolder to PATH
bool update_path_env() {
#if 1
	// Get absolute path of subfolder
	DWORD len = GetCurrentDirectory(0, NULL); // Here, len does include final \0
	LPTSTR _directory = (LPTSTR) malloc(len * sizeof(TCHAR));
	len = GetCurrentDirectory(len, _directory); // Here, len does not include final \0
	if (len == 0 ){
		std::cout << "Can't fetch current directory" << std::endl;
		free(_directory);
		return false;
	}
	std::string directory(_directory);
	directory.append("\\BTS_Wrapper_Libs");
	free(_directory);

	// Get current value of PATH variable
	const std::size_t ENV_BUF_SIZE = 1024; // Enough for your PATH?
	char buf[ENV_BUF_SIZE];
	std::size_t bufsize = ENV_BUF_SIZE;
	int e = getenv_s(&bufsize,buf,bufsize,"PATH");  
	if (e) {
		std::cout << "`getenv_s` failed, returned " << e << '\n';
		return false;
	}

	// Update PATH variable
	std::string env_path = buf;
	//std::cout << "In main process, `PATH`=" << env_path << std::endl;
	env_path += ";";
	env_path += directory;
	e = _putenv_s("PATH",env_path.c_str());
	if (e) {
		std::cout << "`_putenv_s` failed, returned " << e << std::endl;
		return false;
	}
#endif
	return true;
}

void trim(std::string &out, const char *buf){
	if (buf != NULL){
			out = std::string(buf, 0, strlen(buf));
	}

	while(out[0] == ' ' ){
		out.erase(0, 1);
	}
	while(out[out.length()-1] == ' '){
		out.pop_back();
	}
}

int main(const int argc, const char * const argv[])
{

    // Find executable and append arguments
    std::stringstream argsStream;
    std::stringstream otherArgsStream;
    int iArg = 1;

    // Exe argument (first position)
    if (argc > 1) {
        std::string userExe(argv[1]);
        if (userExe.compare(userExe.length() - 4, 4, ".exe") == 0
                && GetFileAttributesA(userExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
            argsStream << userExe;
            ++iArg;
        }
        else {
            argsStream << getExeFilename();
        }
    }
    else {
        argsStream << getExeFilename();
    }

		std::string arg;
		while (iArg < argc) {
			trim(arg, argv[iArg]);
			//Double spaces between args need to be filtered out..

			// Filter out port arguments (-P {port})
			if( 0 == std::string("-P").compare(arg)){
				otherArgsStream << "§" << arg;
				++iArg;
				if( iArg < argc ){
					trim(arg, argv[iArg]);
#ifdef WITH_WEBSERVER
					sWebserver_Port = arg;
					Webserver_Port = atoi(sWebserver_Port.c_str());
#endif
					otherArgsStream << "§" << arg;
					++iArg;
				}
				continue;
			}
			// Filter out log arguments (-l {logfile})
			if( 0 == std::string("-l").compare(arg)){
				otherArgsStream << "§" << arg;
				++iArg;
				if( iArg < argc ){
					trim(arg, argv[iArg]);
#ifdef WITH_LOGFILE
					sLogfile = arg;
#endif
					otherArgsStream << "§" << arg;
					++iArg;
				}
				continue;
			}

			// Filter out IPv6 arguments (-6 / --ip6)
			if( 0 == std::string("-6").compare(arg)
					|| 0 == std::string("--ip6").compare(arg)
				){
				otherArgsStream << "§" << "-6";
#ifdef WITH_IPv6
#endif
				++iArg;
				continue;
			}

			// Other arguments (mod, ALTROOT)
			argsStream << " " << argv[iArg]; // Here, I pass arguments unmodified
			++iArg;
		}

    std::string args = argsStream.str();
    std::string otherArgs = otherArgsStream.str();

		if (otherArgs.length() == 0)
			otherArgs.append(" "); // Avoids empty string in allocation of pReservedSpace_Log?!

		std::cout << "Civ4 Args: '" << args  << "'" << std::endl;
		std::cout << "Other Args: '" << otherArgs << "'" << std::endl;

    const std::string dllName("CivSaveOverHttp.dll");
		//char * dllName = "CivSaveOverHttp.dll";
		if( !update_path_env()) {
			std::cout << "Update of PATH variable failed!" << args << std::endl;
			return 0;
		}

    void* pLoadLibrary = (void*)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    std::cout << "LoadLibrary : " << std::hex << pLoadLibrary << std::endl;
    std::cout << "Creating process for " << args << std::endl;

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory(&startupInfo, sizeof(startupInfo));

    if (!CreateProcessA(0, (LPSTR)args.c_str(), 0, 0, 1, CREATE_NO_WINDOW, 0, 0, &startupInfo, &processInformation)
       )
    {
        std::cout << "Could not run BTS exe. GetLastError() = " << GetLastError() << std::endl;
        return 0;
    }

    std::cout << "Allocating virtual memory" << std::endl;
    void* pReservedSpace = VirtualAllocEx(processInformation.hProcess, NULL, dllName.length(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //void* pReservedSpace = VirtualAllocEx(processInformation.hProcess, NULL, strlen(dllName), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pReservedSpace)
    {
        std::cout << "Could not allocate virtual memory. GetLastError() = " << GetLastError() << std::endl;
        return 0;
    }

    std::cout << "Writing process memory" << std::endl;
    if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace, dllName.c_str(), dllName.length(), NULL))
    //if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace, dllName, strlen(dllName), NULL))
    {
        std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError() << std::endl;
        return 0;
    }

    std::cout << "Creating remote thread" << std::endl;
    HANDLE hThread = CreateRemoteThread(processInformation.hProcess, NULL, 1,
            (LPTHREAD_START_ROUTINE)pLoadLibrary, pReservedSpace, 0, NULL);
    if (!hThread)
    {
        std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError() << std::endl;
        return 0;
    }

    std::cout << "Thread created" << std::endl;

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(processInformation.hProcess, pReservedSpace, dllName.length(), MEM_COMMIT);
    //VirtualFreeEx(processInformation.hProcess, pReservedSpace, strlen(dllName), MEM_COMMIT);


    // Get return value of remote call of LoadLibrary by reading GetExitCodeThread
    // We need this value for calls of GetRemoteProcAddress later...
    // NOTE: Unfortunately this doesn’t work for 64bit processes! GetExitCodeThread returns a 32bit value; in a 64bit process, LoadLibrary will return a 64bit value.
    DWORD exitCode;
    if( !GetExitCodeThread(hThread, &exitCode) ){
        std::cout << "Unable to get exit code of remote thread. GetLastError() = " << GetLastError() << std::endl;
        return 0;
    }
    HMODULE dllHandleRemote = (HMODULE) exitCode;

		std::cout << "dllHandleRemote: " << std::hex << dllHandleRemote << std::endl;


    // ===== Setup of CivSaveOverHttp ===
    //0. Propagate otherArgs string into remote process
    //0.0 get position of function StartServer in CivSaveOverHttp.dll 
    void * pSetOtherArgsRemote = (void *) /*FARPROC*/ GetRemoteProcAddress (processInformation.hProcess, dllHandleRemote, "SetOtherArgs");

    std::cout << "pSetOtherArgsRemote: " << std::hex << pSetOtherArgsRemote << std::endl;
    if( pSetOtherArgsRemote ){
        //0.1 Transfer the non-civ arguments into other address space
        //std::cout << "Allocating virtual memory (3)" << std::endl;
        void* pReservedSpace_Log = VirtualAllocEx(processInformation.hProcess, NULL,
                strlen(otherArgs.c_str()), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pReservedSpace_Log)
        {
            std::cout << "Could not allocate virtual memory. (3) GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }

        //std::cout << "Writing process memory (3)" << std::endl;
        if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace_Log,
                    otherArgs.c_str(), strlen(otherArgs.c_str()), NULL))
        {
            std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }

        //0.2 Call SetOtherArgs(pArgs)
        //std::cout << "Creating remote thread (3)" << std::endl;
        HANDLE hThread3 = CreateRemoteThread(processInformation.hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE)pSetOtherArgsRemote, pReservedSpace_Log, 0, NULL);
        if (!hThread3)
        {
            std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }

        //std::cout << "Thread created (3)" << std::endl;

        WaitForSingleObject(hThread3, INFINITE);
        VirtualFreeEx(processInformation.hProcess, pReservedSpace_Log, strlen(otherArgs.c_str()), MEM_COMMIT);
    }


#ifdef WITH_WEBSERVER
    if( Webserver_Port > -1 ){
        //2. Start Webserver as remote thread in the other process
        //2.0 get position of function StartServer in CivSaveOverHttp.dll 
        void * pStartServerRemote = (void *) /*FARPROC*/ GetRemoteProcAddress (processInformation.hProcess, dllHandleRemote, "StartServer");

				if( pStartServerRemote ){
					std::cout << "StartServer: " << std::hex << pStartServerRemote << std::endl;

					//2.0 Transfer the log filename argument into other address space
					//std::cout << "Allocating virtual memory (2)" << std::endl;
					void* pReservedSpace_Log = VirtualAllocEx(processInformation.hProcess, NULL,
							strlen(sLogfile.c_str()), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (!pReservedSpace_Log)
					{
						std::cout << "Could not allocate virtual memory. (5) GetLastError() = " << GetLastError() << std::endl;
						return 0;
					}

					//std::cout << "Writing process memory (2)" << std::endl;
					if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace_Log,
								sLogfile.c_str(), strlen(sLogfile.c_str()), NULL))
					{
						std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError() << std::endl;
						return 0;
					}

					//2.1 Transfer the port argument into other address space
					//std::cout << "Allocating virtual memory (2)" << std::endl;
					void* pReservedSpace_Port = VirtualAllocEx(processInformation.hProcess, NULL,
							strlen(sWebserver_Port.c_str()), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (!pReservedSpace_Port)
					{
						std::cout << "Could not allocate virtual memory. (6) GetLastError() = " << GetLastError() << std::endl;
						return 0;
					}

					//std::cout << "Writing process memory (2)" << std::endl;
					if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace_Port,
								sWebserver_Port.c_str(), strlen(sWebserver_Port.c_str()), NULL))
					{
						std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError() << std::endl;
						return 0;
					}

					//2.2 Call startServer(port)
					std::cout << "Creating remote thread (2)" << std::endl;
					HANDLE hThread2 = CreateRemoteThread(processInformation.hProcess, NULL, 0,
							(LPTHREAD_START_ROUTINE)pStartServerRemote, pReservedSpace_Port, 0, NULL);
					if (!hThread2)
					{
						std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError() << std::endl;
						return 0;
					}

					std::cout << "Thread created (2)" << std::endl;

					WaitForSingleObject(hThread2, INFINITE);
					VirtualFreeEx(processInformation.hProcess, pReservedSpace_Port, strlen(sWebserver_Port.c_str()), MEM_COMMIT);
					VirtualFreeEx(processInformation.hProcess, pReservedSpace_Log, strlen(sLogfile.c_str()), MEM_COMMIT);
				}else{
					std::cout << "StartServer function not exists. CivSaveOverHttp.dll not found?!" << std::endl;
				}
    }
#endif


    //============================================
    // Propagate civ4 calling arguments for logging purposes. (This re-uses pReservedSpace variable from above.)
    void * pSetStartArgsRemote = (void *) /*FARPROC*/ GetRemoteProcAddress (processInformation.hProcess, dllHandleRemote, "SetStartArgs");

    if( pSetStartArgsRemote ){
        // Transfer the args string into other address space
        void* pReservedSpaceArgs = VirtualAllocEx(processInformation.hProcess, NULL, args.length(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pReservedSpace)
        {
            std::cout << "Could not allocate virtual memory. (7) GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }
        if (!WriteProcessMemory(processInformation.hProcess, pReservedSpaceArgs, args.c_str(), args.length(), NULL))
        {
            std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }

        // Call SetStartArgs(pArgs)
        HANDLE hThreadArgs = CreateRemoteThread(processInformation.hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE)pSetStartArgsRemote, pReservedSpaceArgs, 0, NULL);
        if (!hThreadArgs)
        {
            std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError() << std::endl;
            return 0;
        }
        WaitForSingleObject(hThreadArgs, INFINITE);
        VirtualFreeEx(processInformation.hProcess, pReservedSpaceArgs, args.length(), MEM_COMMIT);
    }
    //============================================

    std::cout << "Done" << std::endl;
    return 0;
}

