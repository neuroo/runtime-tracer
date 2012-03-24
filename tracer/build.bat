
call "C:\Program Files\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86

@mkdir obj-ia32

set PINPATH=C:\src\pin-2.10
:: Includes
set INCLUDES=%PINPATH%\source\include
set INSTLIB=%PINPATH%\source\tools\InstLib
set XED2IA32=%PINPATH%\extras\xed2-ia32\include
set COMPONENTS=%PINPATH%\extras\components\include
set BOOST_INCLUDES="C:\Program Files\boost_1_47"
set SQLITE_INCLUDES="C:\src\sqlite"

:: Libs
set MAINLIBS=%PINPATH%\ia32\lib
set MAINLIBS_NT=%PINPATH%\ia32\lib-ext
set XED2IAD32_LIBS=%PINPATH%\extras\xed2-ia32\lib
set BOOST_LIBS="C:\Program Files\boost_1_47\lib"

@echo "Build..."
cl /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 /I%INCLUDES% /I%INCLUDES%\gen /I%INSTLIB% /I%XED2IA32% /I%COMPONENTS% /Fo.\obj-ia32\sqlite.o .\src\sqlite3.c

::cl /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 /I%INCLUDES% /I%INCLUDES%\gen /I%INSTLIB% /I%XED2IA32% /I%COMPONENTS% /I%BOOST_INCLUDES% /Fo.\obj-ia32\callgraph.o .\src\callgraph.cpp

cl /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 /I%INCLUDES% /I%INCLUDES%\gen /I%INSTLIB% /I%XED2IA32% /I%COMPONENTS% /Fo.\obj-ia32\trace.o .\src\trace.cpp

cl /c /MT /EHs- /EHa- /wd4530 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /DUSING_XED /D_CRT_SECURE_NO_DEPRECATE /D_SECURE_SCL=0 /nologo /Gy /O2 /DTARGET_IA32 /DHOST_IA32 /I%INCLUDES% /I%INCLUDES%\gen /I%INSTLIB% /I%XED2IA32% /I%COMPONENTS% /Fo.\obj-ia32\tracer.o .\src\tracer.cpp

@echo "Link..."
link /DLL /EXPORT:main /NODEFAULTLIB /OPT:REF /NOLOGO /INCREMENTAL:NO /MACHINE:x86 /ENTRY:Ptrace_DllMainCRTStartup@12 /BASE:0x55000000 /LIBPATH:%MAINLIBS% /LIBPATH:%MAINLIBS_NT%  /LIBPATH:%XED2IAD32_LIBS% /LIBPATH:%BOOST_LIBS% /OUT:obj-ia32\tracer.dll obj-ia32\tracer.o obj-ia32\trace.o obj-ia32\sqlite.o pin.lib libxed.lib libcpmt.lib libcmt.lib pinvm.lib kernel32.lib ntdll-32.lib 
::libboost_graph-vc90-mt-1_47.lib /  obj-ia32\callgraph.o

@echo "Move it around..."
copy .\obj-ia32\tracer.dll .\