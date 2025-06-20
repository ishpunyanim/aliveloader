@echo off

pushd ..\..\..\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build
call "vcvarsall.bat" x64
popd

set path=c:\Project\misc;%path%

pushd c:\Project

