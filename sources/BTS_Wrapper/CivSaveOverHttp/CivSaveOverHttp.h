#pragma once

// Folgender ifdef-Block ist die Standardmethode zum Erstellen von Makros, die das Exportieren 
// aus einer DLL vereinfachen. Alle Dateien in dieser DLL werden mit dem GETSAVEOVERHTTP_EXPORTS-Symbol
// (in der Befehlszeile definiert) kompiliert. Dieses Symbol darf für kein Projekt definiert werden,
// das diese DLL verwendet. Alle anderen Projekte, deren Quelldateien diese Datei beinhalten, erkennen 
// GETSAVEOVERHTTP_API-Funktionen als aus einer DLL importiert, während die DLL
// mit diesem Makro definierte Symbole als exportiert ansieht.
#ifdef GETSAVEOVERHTTP_EXPORTS
#define GETSAVEOVERHTTP_API __declspec(dllexport)
#else
#define GETSAVEOVERHTTP_API __declspec(dllimport)
#endif

//#include <windows.h>

#include <string>
#include <fstream>
#include "config.h"

#ifdef WITH_LOGFILE
extern bool logactive;
extern std::string logname;
extern std::ofstream logfile;
#define LOGPRINT(X) \
                if( logactive ){ \
                    logfile << X << std::endl; \
                    logfile.flush(); \
                }
#define LOGPRINT0(X) \
                if( logactive ){ \
                    logfile << X; \
                }
#else
#define LOGPRINT(X) 
#define LOGPRINT0(X) 
#endif

char* __cdecl get_ip6_for_ip4(const char *ip4, bool reverse_lookup = false);

#ifdef __cplusplus
extern "C" {
#endif
GETSAVEOVERHTTP_API void StartServer(const char *pPortName);
GETSAVEOVERHTTP_API void SetStartArgs(const char *pArgs);
GETSAVEOVERHTTP_API void SetOtherArgs(const char *pArgs);

#ifdef __cplusplus
}
#endif
