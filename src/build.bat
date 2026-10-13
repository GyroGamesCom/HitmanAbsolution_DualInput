@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars32.bat" >nul
cd /d "%~dp0"
cl /nologo /MT /O2 /GS- /W3 /D_CRT_SECURE_NO_WARNINGS /LD xinput9_1_0.c /Fe:xinput9_1_0.dll /link /DEF:xinput9_1_0.def user32.lib kernel32.lib dinput8.lib dxguid.lib || exit /b 1
if not exist ..\mod mkdir ..\mod
copy /y xinput9_1_0.dll ..\mod\xinput9_1_0.dll >nul || exit /b 1
dumpbin /exports ..\mod\xinput9_1_0.dll
del xinput9_1_0.obj xinput9_1_0.exp xinput9_1_0.lib xinput9_1_0.dll 2>nul
