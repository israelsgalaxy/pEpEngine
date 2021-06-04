@ECHO OFF

:: The script is located in ...\pEpForWindowsAdapterSolution\pEpEngine\build-windows\
SET current_directory=%~dp0

:: Engine directory is ...\pEpForWindowsAdapterSolution\pEpEngine\
SET engine_directory=%current_directory:~0,-14%

:: YML2 directory is ...\pEpForWindowsAdapterSolution\yml2\
SET yml2_directory=%engine_directory:~0,-11%\yml2

:: Create the system.db
PUSHD %engine_directory%\db
CALL make_systemdb
IF NOT EXIST "%ProgramData%\pEp" "MKDIR %ProgramData%\pEp"
DEL "%ProgramData%\pEp\system.db"
MOVE system.db "%ProgramData%\pEp\system.db"

:: Generate code in ...\pEpEngine\sync
CD ..\sync

:: Make sure YML2 is installed
PY -m pip install --upgrade pip
PY -m pip install wheel
PY -m pip install yml2

:: Generate the Sync code
IF NOT EXIST generated MKDIR generated

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_actions.ysl2 sync.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_actions.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_codec.ysl2 distribution.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_codec.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_codec.ysl2 sync.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_codec.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_messages.ysl2 sync.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_messages.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_messages.ysl2 distribution.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_messages.ysl2 distribution.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_message_func.ysl2 sync.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_message_func.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

ECHO PY -m yml2.yml2proc -E utf-8 -y gen_statemachine.ysl2 sync.fsm
PY -m yml2.yml2proc -E utf-8 -y gen_statemachine.ysl2 sync.fsm
IF %ERRORLEVEL% NEQ 0 GOTO end

XCOPY /y generated\*.asn1 ..\asn.1\
XCOPY /y generated\*.c ..\src\
XCOPY /y generated\*.h ..\src\

CD %engine_directory%\asn.1

DEL *.h
DEL *.c

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keysync.asn1 sync.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

..\..\Tools\asn1c\bin\asn1c -S ../../Tools/asn1c/share/asn1c -gen-PER -fincludes-quoted -fcompound-names -pdu=auto pEp.asn1 keyreset.asn1 distribution.asn1
IF %ERRORLEVEL% NEQ 0 GOTO end

DEL *-sample.c

CD %engine_directory%\..
MKDIR pEp
XCOPY pEpEngine\src\*.h pEp\ /Y/F/I
XCOPY libpEpAdapter\*.hh pEp\ /Y/F/I
XCOPY libpEpAdapter\*.hxx pEp\ /Y/F/I

:end

POPD
EXIT /B %ERRORLEVEL%