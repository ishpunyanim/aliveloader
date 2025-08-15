@echo off

:: Setup environment for VS 2022 (adjust path to your install if needed)
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

set CommonCompilerFlags=-MT -nologo -Gm- -GR- -EHa- -Od -Oi -WX -W4 -wd4201 -wd4100 -wd4189 -FC -Z7
set CommonLinkerFlags=-opt:ref user32.lib gdi32.lib

REM TODO - can we just build both with one exe?

IF NOT EXIST ..\build mkdir ..\build
pushd ..\build

echo Compiling...
REM 32-bit build
REM cl %CommonCompilerFlags% ..\code\refloader.cpp /link -subsystem:CONSOLE %CommonLinkerFlags%

echo Output...
REM 64-bit build
cl %CommonCompilerFlags% ..\code\refloader.cpp /link %CommonLinkerFlags%
cl /LD ..\code\msgbox.c user32.lib /Fe:..\code\msgbox.dll /link -subsystem:CONSOLE 

echo Done. Checking for output...
if exist refloader.exe (
    echo SUCCESS: refloader.exe created.
) else (
    echo ERROR: No .exe file generated.
)

popd
