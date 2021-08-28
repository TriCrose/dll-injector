clang -g -gcodeview .\Hook.cpp -shared -luser32 -lgdi32 -o Hook.dll && clang -g -gcodeview .\Injector.cpp -lshlwapi -o Injector.exe
