@echo off
copy BTS_Wrapper\Debug\BTS_Wrapper.exe ..\debug\.
copy BTS_Wrapper\Debug\CivSaveOverHttp.dll ..\debug\BTS_Wrapper_Libs\.

rem Static linking of *-lib variants. But we need still the dll files
copy Lib\lib*.dll ..\debug\BTS_Wrapper_Libs\.
copy Lib\vcruntime140.dll ..\debug\BTS_Wrapper_Libs\.

rem Socat dependencies
copy Lib\socat.exe ..\debug\BTS_Wrapper_Libs\.
copy Lib\cyg*.dll ..\debug\BTS_Wrapper_Libs\.

echo .
echo "'debug' folder updated"
echo "Copy content of 'debug' to Civ4:BTS installation folder"
pause
