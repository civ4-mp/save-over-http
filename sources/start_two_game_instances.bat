@echo off
cd I:\Olaf\Civ4\Beyond the Sword\

rem Erste Instanz mit altroot
BTS_Wrapper.exe "multiple mod= PB Mod_vX\"\" /ALTROOT=I:\Olaf\PBs\PB1" -l BTS_Wrapper.host.log -6
pause


rem Zweite Instanz starten
BTS_Wrapper.exe mod= PB Mod_vX  -l BTS_Wrapper.client1.log -6
