@echo off
copy BTS_Wrapper\Release\BTS_Wrapper.exe ..\release\.
copy BTS_Wrapper\Release\CivSaveOverHttp.dll ..\release\BTS_Wrapper_Libs\.

rem Static linking of *-lib variants. But we need still the dll files
copy Lib\lib*.dll ..\release\BTS_Wrapper_Libs\.
copy Lib\vcruntime140.dll ..\release\BTS_Wrapper_Libs\.

rem Socat dependencies
copy Lib\socat.exe ..\release\BTS_Wrapper_Libs\.
copy Lib\cyg*.dll ..\release\BTS_Wrapper_Libs\.

echo .
echo "'release' folder updated"
echo "Copy content of 'release' to Civ4:BTS installation folder"
pause

