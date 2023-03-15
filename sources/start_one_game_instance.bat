@echo off

cd I:\Olaf\Civ4\Beyond the Sword\

rem zweite Instanz mit altroot
rem BTS_Wrapper.exe "multiple mod= PB Mod_vX\"\" /ALTROOT=I:\Olaf\PBs\PB7" -l BTS_Wrapper.host.log
rem pause


rem Erste Instanz starten
rem BTS_Wrapper.exe mod= PB Mod_vX  -l BTS_Wrapper.client1.log -P 2055
rem BTS_Wrapper.exe mod= PBMod_v10"\"  -l BTS_Wrapper.client1.log
rem BTS_Wrapper.exe mod= PBMod_v10"\"  -l BTS_Wrapper.client1.log -6
BTS_Wrapper.exe Civ4BeyondSword2015.exe mod= PBMod_v10 -l BTS_Wrapper.client1.log
rem BTS_Wrapper.exe PakBuild.exe -l BTS_Wrapper.client1.log
pause

