/*
 * Notes:
 *  - Compile it without optimizations...
 *
 */

#include "stdafx.h"

#define GETSAVEOVERHTTP_EXPORTS //?
#include "CivSaveOverHttp.h"
#include "Webserver.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctime>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>

#include <fstream>

#include  <iomanip>
#define HEX_RIGHT(W)  "0x" << std::setfill('0') << std::setw(W) << std::right << std::hex

// To share saves in DirectIP mode
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
// Fuer PostMessage
#pragma comment(lib, "User32.lib")


//#include "../Include/minhook/MinHook.h"
#include "minhook/MinHook.h"
#if defined _M_X64
#pragma comment(lib, "MinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "MinHook.x86.lib")
#endif

// Includes for curl download
#include "curl/curl.h"
#pragma comment(lib, "libcurl.lib")
#define SKIP_PEER_VERIFICATION
int curl_download(const std::string &url, const std::string &path);

typedef int(WINAPI *SENDTO)(
		SOCKET                s,
		const char                  *buf,
		int                   len,
		int                   flags,
		const struct sockaddr *to,
		int                   tolen
		);
typedef int(WINAPI *RECVFROM)(
		SOCKET          s,
		char            *buf,
		int             len,
		int             flags,
		struct sockaddr *from,
		int             *fromlen
		);

SENDTO fpSendto = NULL;
RECVFROM fpRecvFrom = NULL;

#ifdef WITH_WEBSERVER
static int Webserver_Port = 8080;
static int Webserver_Run = 0;
#endif

static const std::string Tmp_Name = std::string("Pitboss.CivBeyondSwordSave");
static std::string Str_Extension = std::string(".CivBeyondSwordSave");
static std::string Str_Pitboss = std::string("\\pitboss\\");
static std::string Str_url_prefix1 = std::string("_http_");
static std::string Str_url_prefix2 = std::string("_https_");
static std::string Str_url_prefix3 = std::string("_url_"); //deprecated syntax. Will be handled like https case.

#define MAX_TMP_NAME_LEN 512
//static char tmp_path[MAX_TMP_NAME_LEN];
static std::string tmp_path = std::string(MAX_TMP_NAME_LEN, ' ');
static std::string save_path = std::string();
static std::string last_cached_orig_path = std::string();
static MH_STATUS status;

#ifdef WITH_LOGFILE
bool logactive = false;
std::string logname = std::string("BTS_Wrapper.log");
std::ofstream logfile;
#endif

#ifdef WITH_IPv6
bool ipv6active(false);

// Map stores "[IPv4:Port]"-string -> "[IPv6:Port]" on host.
std::map<std::string, std::string> ipv6_addresses; 

const std::string IPV6_MARKER_STRING("BTS_WRAPPER_IPv6");
const int IPV6_MARKER_LEN = std::char_traits<char>::length(IPV6_MARKER_STRING.c_str());
const int IPV6_MINIMAL_LEN = std::char_traits<char>::length("0[X:X:X:X:X:X:X:X]:PPPP0"); // 0 - Null byte

// Minimal number of bytes a marked message was increased. (Assuming, no shortcut of ipv6 address is used)
const int IPV6_COMBINED_EXTRA_LEN = IPV6_MARKER_LEN + IPV6_MINIMAL_LEN;


#endif

time_t download_last_start = 0;
time_t download_start = 0;
std::string startArgs;

// for curl file handling
struct DownloadFile {
	const char *filename;
	FILE *stream;
};

static size_t my_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
	struct DownloadFile *out = (struct DownloadFile *)stream;
	if (out && !out->stream) {
		/* open file for writing */
		if (0 != fopen_s(&out->stream, out->filename, "wb")) {
			out->stream = NULL;
			return -1; /* failure, can't open file to write */
		}
	}
	return fwrite(buffer, size, nmemb, out->stream);
}

int gen_temp_file_path(std::string &path) {

	//char tmp_path[MAX_TMP_NAME_LEN]; //ugly
	// Guarantee length of internal buffer
	if( tmp_path.length() < MAX_TMP_NAME_LEN){
		tmp_path.resize(MAX_TMP_NAME_LEN, ' ');
	}

	unsigned int tmp_len = GetTempPathA(MAX_TMP_NAME_LEN, (char *)tmp_path.c_str());
	if (tmp_len + Tmp_Name.length() > MAX_TMP_NAME_LEN) {
		path.clear();
		return -1;
	}
	tmp_path.resize(tmp_len); // otherwise many ' ' follow the \0 inserted by GetTempPathA // hm, bringt nix...
	path.clear();
	path.append(tmp_path);
	path.append(Tmp_Name);
	return 0;
}

#ifdef WITH_LOGFILE

int gen_logfile_path(std::string &path) {

	// Guarantee length of internal buffer
	if( tmp_path.length() < MAX_TMP_NAME_LEN){
		tmp_path.resize(MAX_TMP_NAME_LEN, ' ');
	}

	std::string fname = std::string("BTS_Wrapper.log");
	unsigned int tmp_len = GetTempPathA(MAX_TMP_NAME_LEN, (char *)tmp_path.c_str());
	if (tmp_len + fname.length() > MAX_TMP_NAME_LEN) {
		return -1;
	}
	tmp_path.resize(tmp_len); // otherwise many ' ' follow the \0 inserted by GetTempPathA
	path.clear();
	path.append(tmp_path);
	path.append(fname);
	return 0;
}
#endif

int curl_download(std::string &url, std::string &path) {

	CURL *curl;
	CURLcode res = CURLE_FAILED_INIT;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl != NULL) {

		// Use curl function to encode special chars and space,
		// but restrict on the filename (everything after lastest slash).
		size_t slash_pos = url.rfind('/');
		if (std::string::npos != slash_pos && url.length() > slash_pos + 1) {
			char *curl_filename_encoded = curl_easy_escape(curl, url.c_str() + slash_pos + 1, 0);
			url.replace(slash_pos + 1, url.size() - slash_pos - 1, curl_filename_encoded);
		}
		// Set target file
		struct DownloadFile downloadFile = { path.c_str(), NULL };
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_fwrite);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &downloadFile);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

#ifdef SKIP_PEER_VERIFICATION
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
#ifdef SKIP_HOSTNAME_VERIFICATION
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);

		/* always cleanup */
		curl_easy_cleanup(curl);
		if (downloadFile.stream) {
			fclose(downloadFile.stream);
			downloadFile.stream = NULL;
		}

		if (res == CURLE_OK) {
			curl_global_cleanup();
			return 0;
		}
	}

	curl_global_cleanup();
	return -1;
}
// for curl file handling, end

std::string get_server_ip(struct sockaddr *from) {
	std::string server_ip("");
	char *s = NULL;

	//#define inet_ntop  InetNtopA
	switch (from->sa_family) {
#ifndef WIN_XP
		case AF_INET6: {
										 struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)from;
										 s = (char *)malloc(INET6_ADDRSTRLEN);
										 inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
										 server_ip.append(s);
										 break;
									 }
#endif
		case AF_INET:
									 {
										 struct sockaddr_in *addr_in = (struct sockaddr_in *)from;
#ifdef WIN_XP
										 s = inet_ntoa(addr_in->sin_addr);
										 server_ip.append(s);
#else
										 s = (char *)malloc(INET_ADDRSTRLEN);
										 inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
										 server_ip.append(s);
#endif
										 break;
									 }
		default:
									 break;
	}
	free(s);
	return server_ip;
}

int WINAPI MySendto(
		_In_       SOCKET                s,
		_In_ const char                  *buf,
		_In_       int                   len,
		_In_       int                   flags,
		_In_       const struct sockaddr *to,
		_In_       int                   tolen)
{
	const int assumed_return_value = len;

	// Skips short packages and just analyse longer
	if (assumed_return_value < 30 /* at least 10 required to read msg_type2 */){
		// Skipping short messages like
		// FE FE 64 00 XX        Len=5 (Alive msg)
		// FE FE 04 00 XX 00 YY  Len=7 (?)
		goto sendto_end;
	}

	// buf =  FE FE  A  B  C  D   E  F  G  H  [...]
	//              ^^ ^^
	//              [ msg_type1 ][ msg_type2 ]

	unsigned int msg_type1 = *((unsigned int*)(buf+2)); // Flips byte order to DCBA...
	unsigned int msg_type2 = *((unsigned int*)(buf+6)); // Flips byte order to DCBA...
	LOGPRINT("Send msg_type1: " << HEX_RIGHT(8) << msg_type1
			<< " msg_type2: " << HEX_RIGHT(8) << msg_type2);


#ifdef WITH_WEBSERVER

	// buf =  FE FE  00 00 3E 00  ?? 08 00 00 [...]
	// buf =  FE FE  00 00 5C 00  ?? 08 00 00 [...]  // Auf Pitboss-Host gesehen
	// buf =  FE FE  00 00 4F 00  ?? 08 00 00 [...]  // Auf Pitboss-Host gesehen
	//                    ^random?!
	//              [ msg_type1][ msg_type2 ]

	if (
#if 0
			(  id == 0x0805 /* DirectIP game */
				 || id == 0x0806 /* DirectIP game (2, gesehen bei Test mit multiple-Argument) */
				 || id == 0x0807 /* Pitboss game */
				 || id == 0x0808 /* Pitboss game, wenn schon jemand eingeloggt ist */
				 /* Hm, bei zwei eingeloggten Spielern ändert sich der Wert erneut...*/
			)
#else
			//id >= 0x0805 && id < 0x0815 // old
			msg_type2 >= 0x0805 && msg_type2 < 0x0815
			&& (msg_type1 & 0xFF00FFFF) == 0x0 
#endif
			/*
			 * Package contains 33 bytes and a string of variable length.
			 * Assume save path with at least 31 chars...
			 * This is a conervative estimation, because the path contains substrings like 
			 * 'C:\', 'Saves\pitboss\auto\Recovery_' and '.CivBeyondSwordSave'
			 */
			&& len > 0x40 /* Maybe deprecated check */
		 )
	{

		const unsigned int offset = 0x21; // Start of string.
		const unsigned int path_len = *((unsigned int *)(buf + offset - 4)); // Length info of string
		//const unsigned int crc32 = *((unsigned int *)(buf + offset - 8)); // crc32 value of file

		const char *begin = buf + offset;
		std::string path(begin, path_len);
		//std::string extension(".CivBeyondSwordSave");

		// Locate '\\Saves' substring
		std::string saves_substring("\\Saves");
		size_t pos_saves = path.find(saves_substring);
		if( pos_saves != std::string::npos
				&& (len < 1000 /* just to prevent overflows*/) ){

			std::string save_folder(path, 0, pos_saves+saves_substring.length());
			save_folder.append("\\");

			// Sets static variable, which will be read by other thread
			setRootFolder(save_folder);

			// Path in relation to web root
			std::stringstream url_stream;
			url_stream << "_http_:";
			url_stream <<  Webserver_Port;
			url_stream << path.substr(pos_saves+saves_substring.length());
			std::string url = url_stream.str();

			/* Append '\0' + url.length() + url after file name in the buffer. */
			uint32_t l_old = path.length();
			uint32_t l_url = url.length();

			LOGPRINT("(BTS_Wrapper) Change path in package from '" << path << "' to '" << url);

			// Reserved buffer is long enought to hold a few more bytes.
			*((char *)buf + len) = '\0';
			memcpy((char *)buf + len + 1, &l_url, 4);
			memcpy((char *)buf + len + 5, url.c_str(), l_url);
			len += l_url + 5;
		}

		goto sendto_end;
	}
#endif

#ifdef WITH_IPv6
	if (!ipv6active){
		goto sendto_end;
	}

	// buf =  FE FE  03 00 01 00 | 01 4a ** ** … [String_IPv4:Port]'\0'
	//                                           ^
	//                                        buf+39
	if (msg_type1 == 0x00010003
			&& (msg_type2 & 0x0000FFFF) == 0x00004a01
			&& assumed_return_value > 54)
	{
		// buf =  FE FE  03 00 | 01 00 [...] [String_IPv4:Port]'\0'
		//                                   ^
		//                                   buf+39
		const unsigned int idx_ip = 39;
		if ( *(buf+assumed_return_value) != '\0' ){
			LOGPRINT("(BTS_Wrapper) Hey, string in selected package is not null terminated.");
		}else{
			std::string own_client_ip_port(buf + idx_ip, assumed_return_value-idx_ip-1);
			size_t pos_colon = own_client_ip_port.find(":", 0);
			if( pos_colon != std::string::npos) {
				std::string ip4 = own_client_ip_port.substr(0, pos_colon);
				std::string port = own_client_ip_port.substr(pos_colon+1);
				//std::string own_ip6 = "[bla::bla]";
				LOGPRINT("(BTS_Wrapper) My IPv4:port is '" << own_client_ip_port << "'");

				// Fetch own ipv6 address
				char * _own_ip6 = get_ip6_for_ip4(ip4.c_str());
				std::string own_ip6;
				if (_own_ip6 == NULL){
					own_ip6.append("[0:1:2:3:4:5:6:7:8]");
				}else{
					own_ip6.append(_own_ip6);
					free(_own_ip6);
				}

				// Listen on IPv6 socket by 'socat'  [own_ipv6]:port  -> 127.0.0.1:port
				// TODO

				// Attach BTS_WRAPPER_IPv6 add IPv6 address (null string terminated)
				std::stringstream _tmp;
				_tmp << IPV6_MARKER_STRING << '\0'
					<< own_ip6 << ":" << port;

				std::string new_buffer_end = _tmp.str(); // Note: Contains \0 char.

				// Reserved buffer is long enought to hold a few more bytes.
				//size_t l_old = len - idx_ip;
				size_t l_new = new_buffer_end.length();
				memcpy((char *)buf + len, new_buffer_end.c_str(), l_new);
				*((char *)buf + len + l_new) = '\0';
				len += l_new + 1 /* Final \0 */;
				LOGPRINT("(BTS_Wrapper) Attached '" << new_buffer_end << "' to buffer");

				// New message form:
				// buf =  FE FE  03 00 01 00 | 01 4a ** ** … [String_IPv4:Port]'\0'BTS_WRAPPER_IPv6'\0'[String_IPv6:Port]'\0'
			}

		}
		goto sendto_end;
	}

	// buf =  FE FE  00 00 03 00 | 02 DC DC 06 … [Len1][Ip4:Port][Len2][Nickname]
	//                                           ^
	//                                        buf+18
	if (msg_type1 == 0x00030000
			&& (msg_type2 & 0xFFFFFFFF) == 0x06dcdc02
			&& assumed_return_value > 35)
	{

		// Attach [Len3][Ipv6:Port], if available
		const int pos1 = 18;
		const unsigned int len1 = *((unsigned int*)(buf+pos1));
		std::string ip4(buf+pos1+4, len1);

		auto search = ipv6_addresses.find(ip4);
		if ( search != ipv6_addresses.end()){
			LOGPRINT("Found client in map");

			uint32_t len3 = search->second.length();

			memcpy((char *)buf + len, &len3, 4); // Writing [Len3]
			memcpy((char *)buf + len + 4, search->second.c_str(), len3);
			len += 4 + len3;
			// New message form:
			// buf =  FE FE  00 00 03 00 | 02 DC DC 06 … [Len1][Ip4:Port][Len2][Nickname][Len3][Ip6:Port]
		}


		goto sendto_end;
	}

	// buf =  FE FE  00 00 3F 00 | 08 DC DC 10 … [Len1][Ip4:Port]
	// buf =  FE FE  00 00 3C 00 | 07 DC DC 10 … [Len1][Ip4:Port]
	// buf =  FE FE  00 00 ** 00 | ** DC DC 10 … [Len1][Ip4:Port] (Vermutung zum Pattern)
	//                                           ^
	//                                        buf+18
	// (Like previous but without Nickname information
	if ( 
			(msg_type1 & 0xFF00FFFF) == 0x0 && (msg_type2 & 0xFFFFFF00) == 0x10dcdc00
			&& assumed_return_value> 31)
	{
		// Attach [Len3][Ipv6:Port], if available
		const int pos1 = 18;
		const unsigned int len1 = *((unsigned int*)(buf+pos1));
		std::string ip4(buf+pos1+4, len1);

		LOGPRINT("Search client in map (2)" << ip4);
		auto search = ipv6_addresses.find(ip4);
		if ( search != ipv6_addresses.end()){
			LOGPRINT("Found client in map (2)");

			uint32_t len3 = search->second.length();

			memcpy((char *)buf + len, &len3, 4); // Writing [Len3]
			memcpy((char *)buf + len + 4, search->second.c_str(), len3);
			len += 4 + len3;
			// New message form:
			// buf =  FE FE  00 00 ** 00 | ** DC DC 10 … [Len1][Ip4:Port][Len3][Ip6:Port]
		}

		goto sendto_end;
	}
#endif

sendto_end:		
	int ret = fpSendto(s, buf, len, flags, to, tolen);
	if( ret == len ){
		return assumed_return_value;
	}else{
		return ret;
	}
}

int WINAPI MyRecvfrom(
		_In_        SOCKET          s,
		_Out_       char            *buf,
		_In_        int             len,
		_In_        int             flags,
		_Out_       struct sockaddr *from,
		_Inout_opt_ int             *fromlen)
{
	// recv_from_length = Number of fetched bytes...
	int recv_from_length = fpRecvFrom(s, buf, len, flags, from, fromlen);
	//return recv_from_length;

	if (recv_from_length < 30 /* at least 10 required to read msg_type2 */){
		// Skipping short messages like
		// FE FE 64 00 XX        Len=5 (Alive msg)
		// FE FE 04 00 XX 00 YY  Len=7 (?)
		return recv_from_length;
	}

	// buf =  FE FE  A  B | C  D  E  F | G  H [...]
	//              ^^ ^^
	//              [ msg_type1 ][ msg_type2 ]

	const unsigned int msg_type1 = *((unsigned int*)(buf+2)); // Flips byte order to DCBA...
	const unsigned int msg_type2 = *((unsigned int*)(buf+6)); // Flips byte order to DCBA...
	LOGPRINT("Recv msg_type1: " << HEX_RIGHT(8) << msg_type1
			<< " msg_type2: " << HEX_RIGHT(8) << msg_type2);

#ifdef WITH_WEBSERVER
	// buf =  FE FE  00 00 3E 00  ?? 08 00 00 [...]
	// buf =  FE FE  00 00 5C 00  ?? 08 00 00 [...]  // Auf Pitboss-Host gesehen
	// buf =  FE FE  00 00 4F 00  ?? 08 00 00 [...]  // Auf Pitboss-Host gesehen
	//                    ^random?!
	//              [ msg_type1][ msg_type2 ]

	if ( 
#if 0
			(  id == 0x0805 /* DirectIP game */
				 || id == 0x0806 /* DirectIP game (2, gesehen bei Test mit multiple-Argument) */
				 || id == 0x0807 /* Pitboss game */
				 || id == 0x0808 /* Pitboss game, wenn schon jemand eingeloggt ist */
				 /* Hm, bei zwei eingeloggten Spielern ändert sich der Wert erneut...*/
			)
#else
			//id >= 0x0805 && id < 0x0815 // old
			msg_type2 >= 0x0805 && msg_type2 < 0x0815
			&& (msg_type1 & 0xFF00FFFF) == 0x0 
#endif
			/*
			 * Package contains 33 bytes and a string of variable length.
			 * Assume save path with at least 31 chars...
			 * This is a conervative estimation, because the path contains substrings like 
			 * 'C:\', 'Saves\pitboss\auto\Recovery_' and '.CivBeyondSwordSave'
			 */
			&& len > 0x40 /* Maybe deprecated check */
		 )
		 {

		// Extract file path from packet. Note that the path is not null terminated.
		const unsigned int offset = 0x21; // Start of string.
		const unsigned int path_len = *((unsigned int *)(buf + offset - 4)); // Length info of string
		const   unsigned int crc32 = *((unsigned int *)(buf + offset - 8)); // crc32 value of file
		unsigned int url_offset;
		unsigned int url_len;

		// Check if packet contain data after path.
		if ((int)(offset + path_len) > recv_from_length) {
			// Malformed package
			goto recv_end;
		}else if((int)(offset + path_len) == recv_from_length){
			// Unchanged server or old approach. Search in file path for _http(s)_ keywords.
			url_offset = offset;
			url_len = path_len;
		}else if((int)(offset + path_len) < recv_from_length + 5){
			// New approach with second argument.
			url_offset = offset + path_len + 5; // Start of url string.
			url_len = *((unsigned int *)(buf + url_offset - 4)); // Length info for url
		}else{
			// Malformed package
			goto recv_end;
		}

		if ((int)(url_offset + url_len) != recv_from_length) {
			goto recv_end;
		}

		// Extract url
		std::string path(buf + offset, path_len);
		std::string url(buf + url_offset, url_len);
		std::string extension(".CivBeyondSwordSave");

		// Check if filename maps to pitboss savegame. (Civ4:BTS only)
		if (url.length() < extension.length()) {
			goto recv_end;
		}

		std::string url_ext = url.substr(url.length() - extension.length(), extension.length());
		if (0 != extension.compare(url_ext)) {
			goto recv_end;
		}

		// Check if this file was already cached to omit multiple downloads.
		if (!last_cached_orig_path.empty() &&
				0 == last_cached_orig_path.compare(url))
		{
			// TODO: compare crc32 value of file to uncover old files.
		}
		else {
			last_cached_orig_path = path;
			// Ask system to gen tmp. file name.
			if (gen_temp_file_path(save_path)) {
				goto recv_end;
			}
		}


		/* Create second network packet.
		 * Copy header bytes from original packet and append path to temp file.
		 * This will overwrite the original packet if the download succeeds...
		 * */
		uint32_t l_new = save_path.length();
		char *buf2 = (char *)malloc(offset + l_new + 5);

		// Head
		memcpy(buf2, buf, offset - 4);

		// Changed body
		memcpy(buf2 + offset - 4, &l_new, 4);
		memcpy(buf2 + offset, save_path.c_str(), l_new);

		/* Try to download into save_path.
		 *
		 */
		/* First, construct url
		 * Variant 1 (Pitboss server) url is [...]_http[s]_{server}[:{port}]\[...]
		 *         Example:
		 *        http://{server}/PB1/Saves/pitboss/auto/Recovery_{nick}.CivBeyondSwordSave
		 *
		 * Variant 2 (Direct IP) url is [...]_http[s]_:{port}\[...]
		 *         Example:
		 *        http://{ip}:{port}/Saves/multi/VOTE_[...].CivBeyondSwordSave
		 *
		 * In case 2 (empty server string) the ip of recv should be used as server ip.
		 */
		int protocol(-1);
		size_t hostnameBegin(std::string::npos);
		size_t hostnameEnd(std::string::npos);

		std::string url2 = std::string();
		if (std::string::npos != (hostnameBegin = url.find(Str_url_prefix1))) {
			// HTTP transfer
			hostnameBegin += Str_url_prefix1.size();
			protocol = 0;
			url2.append("http://");
		}
		else if (std::string::npos != (hostnameBegin = url.find(Str_url_prefix2))) {
			// HTTPS transfer
			hostnameBegin += Str_url_prefix2.size();
			protocol = 1;
			url2.append("https://");
		}
		else if (std::string::npos != (hostnameBegin = url.find(Str_url_prefix3))) {
			// HTTPS transfer
			hostnameBegin += Str_url_prefix3.size();
			protocol = 1;
			url2.append("https://");
		}

		if (std::string::npos != hostnameBegin && url[hostnameBegin + 0] == ':') {
			// Construct ip of server
			std::string server_ip = get_server_ip(from);
			url2.append(server_ip);
		}

		hostnameEnd = url.find('\\', hostnameBegin); // The backslash after {server}.
		if( std::string::npos == hostnameEnd ){
			protocol = -1;
		}else{
			url2.append(url, hostnameBegin, hostnameEnd - hostnameBegin);

			// Add '/' and uri part after port.
			size_t backslash_pos(url2.size());
			url2.append("/");
			url2.append(url, hostnameEnd + 1, url.size() - hostnameEnd - 1);

			//Replace backslashes by slashes
			while (std::string::npos != (backslash_pos = url2.find('\\', backslash_pos))) {
				url2[backslash_pos] = '/';
			}
		}

		// Check if download was already invoked ( aka double sending of this packet)
		bool skip(false);
		double seconds(-1.0);
		if( download_last_start != 0 ){
			time(&download_start);
			seconds = difftime(download_start, download_last_start);
			if( seconds < 30 ){
				skip = true;
			}
		}
		if(skip){
			LOGPRINT("(BTS_Wrapper) Skip Download. Time between the download invoking network packets are '" << seconds << "' seconds only. '");
			// Replace buffer with copy
			recv_from_length = offset + l_new + 4;
			memcpy(buf, buf2, recv_from_length);

		}else{
			LOGPRINT("(BTS_Wrapper) Download '" << url2 << "' into '" << save_path << "'.");

			time(&download_last_start);
			if (protocol > -1 &&
					0 == curl_download(url2, save_path))
			{
				last_cached_orig_path = path;

				// Replace buffer with copy
				recv_from_length = offset + l_new + 4;
				memcpy(buf, buf2, recv_from_length);
			}else{
				// Shrink packet to original length?! (offset+path_len)
				recv_from_length = offset + path_len;
			}
			free(buf2);
		}
		goto recv_end;
	}
#endif

#ifdef WITH_IPv6
	if (!ipv6active) {
		goto recv_end;
	}

	// buf =  FE FE  03 00 01 00 | 01 4a ** ** … [String_IPv4:Port]'\0'BTS_WRAPPER_IPv6'\0'[String_IPv6:Port]'\0'
	//                                           ^
	//                                        buf+39
	if (msg_type1 == 0x00010003
			&& (msg_type2 & 0x0000FFFF) == 0x00004a01
			&& recv_from_length > 54 + IPV6_COMBINED_EXTRA_LEN )
	{

		const unsigned int idx_ip = 39;
		const size_t ip4_len = strlen(buf + idx_ip);
		if ( 0 == IPV6_MARKER_STRING.compare(0, IPV6_MARKER_LEN,
					buf + idx_ip + ip4_len + 1, IPV6_MARKER_LEN)){
			const size_t idx_ip6 = idx_ip+ip4_len+IPV6_MARKER_LEN+2;  // +2 for two \0's
			LOGPRINT("Hey, " << buf+idx_ip << " => '" << buf+idx_ip6  << "'");

			// Save client relation in map 
			ipv6_addresses[std::string(buf+idx_ip)] = std::string(buf+idx_ip6);
		}

		goto recv_end;
	}

	// buf =  FE FE  00 00 03 00 | 02 DC DC 06 … [Len1][Ip4:Port][Len2][Nickname][Len3][Ip6:Port]
	//                                           ^
	//                                        buf+18
	if (msg_type1 == 0x00030000
			&& (msg_type2 & 0xFFFFFFFF) == 0x06dcdc02
			&& recv_from_length > 35 + IPV6_MINIMAL_LEN)
	{

		// Fetch [Len3][Ipv6:Port], if available
		const int pos1 = 18;
		const unsigned int len1 = *((unsigned int*)(buf+pos1));
		const int pos2 = pos1 + 4 + len1;
		const unsigned int len2 = *((unsigned int*)(buf+pos2));
		const int pos3 = pos2 + 4 + len2;
		if ( pos3+4 <= recv_from_length) {
			std::string ip4(buf+pos1+4, len1);
			const unsigned int len3 = *((unsigned int*)(buf+pos3));
			std::string ip6(buf+pos3+4, min(len3, recv_from_length-pos3-4));

			std::string local_ip4("127.6.6.1:23456");
			LOGPRINT("Save Client in map f(" << ip4 << ") = " << ip6 );
			ipv6_addresses[ip4] = ip6; // Maybe wrong and we need to store local_ip4?!
			ipv6_addresses[local_ip4] = ip6;


			// TODO: Setup socat from client 2 -> client 1
			local_ip4 = ip4; // Restore orig for debugging TODO
			const unsigned int len1_new = local_ip4.length();

			/* Replace ip4 with local variant (local_ip4) 
			 * This changes the buffer size
			 */
			// Backup [Len2][Nickname] part of buffer
			local_ip4.append(buf+pos2, 4 + len2);

			// Change buffer
			memcpy(buf+pos1, &len1_new, 4);
			memcpy(buf+pos1+4, local_ip4.c_str(), len1_new + 4 + len2);

			// Adapt size information of buffer
			// buf =  FE FE  00 00 | 03 00 [...] [Len1_new][Local_Ip4:Port][Len2][Nickname]
			recv_from_length = pos1 + len1_new + len2 + 2*4;
		} else {
			LOGPRINT("Revived package too short?!" << (pos3+4) << " > " << recv_from_length);
		}

		goto recv_end;
	}

	// buf =  FE FE  00 00 3F 00 | 08 DC DC 10 … [Len1][Ip4:Port][Len3][Ip6:Port]
	// buf =  FE FE  00 00 3C 00 | 07 DC DC 10 … [Len1][Ip4:Port][Len3][Ip6:Port]
	// buf =  FE FE  00 00 ** 00 | ** DC DC 10 … [Len1][Ip4:Port][Len3][Ip6:Port] (Vermutung zum Pattern)
	//                                           ^
	//                                        buf+18
	// (Like previous but without Nickname information
	if ( 
			(msg_type1 & 0xFF00FFFF) == 0x0 && (msg_type2 & 0xFFFFFF00) == 0x10dcdc00
			&& recv_from_length > 31 + IPV6_MINIMAL_LEN)
	{

		// Fetch [Len3][Ipv6:Port], if available
		const int pos1 = 18;
		const unsigned int len1 = *((unsigned int*)(buf+pos1));
		const int pos3 = pos1 + 4 + len1;
		if ( pos3+4 <= recv_from_length) {
			std::string ip4(buf+pos1+4, len1);
			const unsigned int len3 = *((unsigned int*)(buf+pos3));
			std::string ip6(buf+pos3+4, min(len3, recv_from_length-pos3-4));

			std::string local_ip4("127.6.6.1:23456");
			LOGPRINT("Save Client in map f(" << ip4 << ") = " << ip6 );
			ipv6_addresses[ip4] = ip6; // Maybe wrong and we need to store local_ip4?!
			ipv6_addresses[local_ip4] = ip6;

			//TODO
			//...
		}else{
			LOGPRINT("Revived package too short?!" << (pos3+4) << " > " << recv_from_length);
		}
		goto recv_end;
	}
#endif

recv_end:
	return recv_from_length;
}


extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			{
				status = MH_Initialize();
				LOGPRINT("MH_Initialize() returns: " << MH_StatusToString(status));
				LPVOID pfn3 = GetProcAddress(GetModuleHandleA("WS2_32.dll"), "sendto");
				LPVOID pfn4 = GetProcAddress(GetModuleHandleA("WS2_32.dll"), "recvfrom");
				status = MH_CreateHook(pfn3, &MySendto, reinterpret_cast<void**>((LPVOID)&fpSendto));
				LOGPRINT("MH_CreateHook() for sendto returns: " << MH_StatusToString(status));
				status = MH_CreateHook(pfn4, &MyRecvfrom, reinterpret_cast<void**>((LPVOID)&fpRecvFrom));
				LOGPRINT("MH_CreateHook() for recvfrom returns: " << MH_StatusToString(status));
				LOGPRINT(logfile << "(BTS_Wrapper) Enable Hooks of 'sendto' and 'recvfrom'.");
				status = MH_EnableHook(MH_ALL_HOOKS);
				LOGPRINT("MH_EnableHook() returns: " << MH_StatusToString(status));
			}
			break;
		case DLL_PROCESS_DETACH:
			{
				Webserver_Run = 0;
#if 0 //               Crashs?!
				status = MH_DisableHook(MH_ALL_HOOKS);
				LOGPRINT("MH_DisableHook() returns: " << MH_StatusToString(status));
				status = MH_Uninitialize();
				LOGPRINT("MH_Uninitialize() returns: " << MH_StatusToString(status));
				status = MH_Uninitialize();
				LOGPRINT("Process_Detach");
#ifdef WITH_LOGFILE
				if( logfile.is_open() ){
					logfile.close();
				}
#endif
#else
				MH_DisableHook(MH_ALL_HOOKS);
				MH_Uninitialize();
#endif

#ifdef WITH_LOGFILE
				// Bad idea to use logfile at this stage!! Could crash the app.
				//LOGPRINT("Process_Detach");
				//if( logactive and logfile.is_open() ){
				//    logfile.close();
				//}
#endif
			}
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
	}
	return true;

}


// for string delimiter
std::vector<std::string> split(std::string s, std::string delimiter) {
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	std::string token;
	std::vector<std::string> res;

	while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
		token = s.substr (pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back (token);
	}

	res.push_back (s.substr (pos_start));
	return res;
}


/*
 * Examples of traffic packages:
 *
 * (Pitboss game)
 * crc32: ecaf54ee
 *                       _____
 0000  fe fe 00 00|85 00 07 08|00 00 00 01 ff ff ff ff  ................
 0010  fe 54 15 01 37 00 00 00 00|ee 54 af ec|62 00 00  .T..7.....T..b..
 0020  00 5a 3a 5c 68 6f 6d 65 5c 70 62 5c 5f 75 72 6c  .Z:\home\pb\_url
 [...]
 0070  2e 43 69 76 42 65 79 6f 6e 64 53 77 6f 72 64 53  .CivBeyondSwordS
 0080  61 76 65                                         ave

 * (Pitboss game, someone already logged in)
 *                        _____
 0000   fe fe 00 00|55 00 08 08|00 00 00 01 ff ff ff ff   þþ..U.......ÿÿÿÿ
 0010   5d 13 00 00 36 00 00 00 00 ff 0e 96 91 64 00 00   ]...6....ÿ...d..
 0020   00 5a 3a 5c 68 6f 6d 65 5c 63 69 76 70 62 5c 5f   .Z:\home\civpb\_
 [...]
 0070   6c 65 2e 43 69 76 42 65 79 6f 6e 64 53 77 6f 72   le.CivBeyondSwor
 0080   64 53 61 76 65                                    dSave

 * (Direct IP game)
 *                       _____
 0000  fe fe 00 00|3f 00 05 08|00 00 00 01 00 00 00 00  ....?...........
 0010  01 00 00 00 7c 00 00 00 00 5a 2c 23 07 5d 00 00  ....|....Z,#.]..
 0020  00 43 3a 5c 55 73 65 72 73 5c 85 65 85 65 5c 44  .C:\Users\XxXx\D
 [...]
 0060  49 50 5f 50 42 4d 6f 64 5f 76 58 2e 43 69 76 42  IP_PBMod_vX.CivB
 0070  65 79 6f 6e 64 53 77 6f 72 64 53 61 76 65        eyondSwordSave
 */


#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_WEBSERVER
	void StartServer(const char *pPortName)
	{
		// Set static variable (will read by other thread)
		Webserver_Port = atoi(pPortName);
		startServer(Webserver_Port);
		Webserver_Run = 1;

		// Not threadsave, but StartServer only called once at startup
		LOGPRINT("(BTS_Wrapper) Webserver for Saves started at port " << Webserver_Port);

		//stopServer(); // Never reached...
		return;

		// Because Webserver_Run will only set to 0 in DllMain,
		// this loop never ends, but the program exits before.
		// Fortunately the MHD threads are shutdown correctly without any further commands.
		while( Webserver_Run ) {
			Sleep(1000);
		}
		stopServer(); // Never reached...
	}
#endif


	// Other, non-Civ4, related args. Used to setup this lib.
	// Call this before SetStartArgs.
	void SetOtherArgs(const char *pArgs)
	{

		std::string str(pArgs);
		std::string delimiter = "§";
		std::vector<std::string> args = split(str, delimiter);

		std::vector<std::string>::iterator it = args.begin();
		std::vector<std::string>::iterator itEnd = args.end();
		while ( it < itEnd ) { // Loop through args and setup

#ifdef WITH_LOGFILE
			if( 0 == std::string("-l").compare(*it)){
				it++;
				if( it < itEnd ){
					logname = std::string(*it);
					logactive = false;

					// Try creation of logfile in current dir
					logfile.open(logname);
					if( logfile.is_open() ){
						logactive = true;
					}else{
						// Create file in %TMP% folder
						if( 0 == gen_logfile_path(logname)){
							logfile.open(logname);
							if( logfile.is_open() ){
								logactive = true;
								LOGPRINT("Log path: " << logname);
							}
						}
					}
					it++;
				}
				continue;
			}
#endif
#ifdef WITH_IPv6
			// Filter out log arguments (-ip6)
			if( 0 == std::string("-6").compare(*it)
					|| 0 == std::string("--ip6").compare(*it)
				){
				ipv6active = true;
				LOGPRINT("Enable IPv6");
				it++;
				continue;
			}
#endif
#ifdef WITH_WEBSERVER
			// Already handled by Injector process.
			if( 0 == std::string("-P").compare(*it)){
				it++;
				if( it < itEnd ){
					int unused_webserver_port = atoi((*it).c_str());
					LOGPRINT("Enable Webserver");
					it++;
				}
				continue;
			}
#endif

			it++;
		}

		LOGPRINT0("(BTS_Wrapper) Wrapper args: ");
		for (it = args.begin(); it < itEnd; it++) {
			LOGPRINT0(*it << " ");
		}
		LOGPRINT("");

	}

	// Arguments used to start Civ4
	void SetStartArgs(const char *pArgs)
	{
		startArgs = pArgs;
		// Not threadsave, but SetStartArgs only called once at startup
		LOGPRINT("(BTS_Wrapper) Startup args: " << startArgs);
	}


#ifdef __cplusplus
}
#endif
