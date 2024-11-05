@echo off
rem Ensure we're in the right directory
cd /d %~dp0

rem Build the resource file
windres -i ../../dll_resources/MinHook.rc -o MinHook_rc.o

rem Compile source files into object files
gcc -c -I../../include -I../../src -std=c11 ../../src/*.c ../../src/HDE/*.c

rem Create the static library from object files
ar rcs libMinHook.a *.o

rem Clean up object files
del *.o

echo Build completed. Static library libMinHook.a created.
