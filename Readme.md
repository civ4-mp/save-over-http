=== Target ===
This repository can build the 'BTS_Wrapper.exe' which improving the Civ4 multiplayer capabilities.
The main reason for using this tool is the speedup during entering a Civ4 Pitboss multiplayer game.

The tool was extended over the years and supports now multiple features.

Features:
* Speed up loading of Saves from Civ4 Pitboss servern.
  Normally, the network code of Civ4:BTS limits the bandwidth to ancient 10kB/sec, 
	but advanced saves consume a few MB. This leads to long timeouts during the login… 

* Fast loading of saves in normal Civ4 MP games. Simply forward an extra port, e.g. 2055, for sharing the
  save-game folder. All clients will load the save game over this port instead the normal slow ingame way.

* IPv6 support. (WIP)	
  If Host or client own an IPv6 address the Wrapper will using the 'socat' tool for tunnel the ingame traffic
	over IPv6. By avoiding the NAT64-gates from ISP's this should resolving the issues of DualStack light 
	and IPv6-only connections.
	It should work for all IPv4/IPv6 combinations unless an IPv4-only and a IPv6-only client want join.
	(If one player is IPv4 only he could still host the game. Here, the IPv6 clients can just the
	ISP's NAT64 service.)



=== How to use it ===
It requires changes on both (client & pb server) sides.

1) As Player (non hosting):  
	• Copy BTS_Wrapper.exe and BTS_Wrapper_Libs folder into your
	Civ4:BTS installation folder. Do not delete/move the normal executable. It's still required.
	• Start your game with the wrapper, i.e.
	'BTS_Wrapper.exe mod= "PBMod_v10"\"'.

	• If MSVCP100.dll is missing, see http://answers.microsoft.com/en-us/windows/forum/windows_other-performance/msvcp100dll-missing/9a687c31-0619-4ee9-b511-020985e29b5f

2) As host of normal multiplayer game (Direct IP host)
• Add '-P [port number, i.e. 2055]' argument to the start arguments of BTS_Wrapper.exe.
	This port will be used to transfer the save game.
• Extend the port forwarding of Civ4 on the new port. This step depends on your network settings. 

3) As Civ4 Pitboss host (with Linux in mind):
	The tricky part is the **encoding of the server ip** into the data, provided to the clients, if they loading the save.
	Assuming that your current Altroot folder for the server is `$HOME/PBs/PB1`
	and your server has the ip `1.2.3.4`, then the following steps fitting paths/urls into matching pairs.

	1) Setup a webserver and prepare a folder for your PB saves and allow symlinks.
	  Example path: `/var/www/PBs`

	2) Create a folder which encodes the IP/url of your server. The naming scheme is "_http[s]_{ip|url}".
		Move the Pitboss Altroot folder into this directory.
		Example path: `$HOME/_http_1.2.3.4/PBs/PB1`.

		=> At runtime Civ4 will store the save games into 
		`Z:\home\$USERNAME\_http_1.2.3.4\PBs\PB1\Saves\pitboss\auto` (Windows path syntax).

	3) Create the directory `/var/www/PBs/PB1/Save/pitboss` and place a symbolic link into the above 'auto' directory.

	Now, the save games are public available. If a modified client connects, it converts
	`_http_1.2.3.4/` into `http://1.2.3.4/` and downloading the file
	`http://1.2.3.4/PBs/PB1/Saves/pitboss/auto/Recovery_{nickname}.CivBeyondSwordSave`.
	If the download fails the save will transfered normally.

	If it doesn't work re-check the setup of your paths.



=== Sources ===
The sources and project files for Visual Studio 2017 can be found in ./sources.
Used following libraries:
• MinHook, https://github.com/TsudaKageyu/minhook/
• Curl, https://github.com/bagder/curl
• LibMicroHTTPD, http://www.gnu.org/software/libmicrohttpd/
• Socat (http://www.dest-unreach.org/socat) and Cygwin-port (https://github.com/agokal/socat-install-cygwin)


Olaf Schulz, 2015-23

