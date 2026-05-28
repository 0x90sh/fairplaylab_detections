# Communication Surface

Real WDM driver PoC for a safe IOCTL surface, command audit, and dispatch pointer ownership checks.

Build client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build driver:

```bat
msbuild driver\fpl_comm_surface.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run:

```bat
sc create fpl_comm_surface type= kernel binPath= "%CD%\driver\x64\Release\fpl_comm_surface.sys"
sc start fpl_comm_surface
bin\windows-x64\communication_surface_client.exe
bin\windows-x64\communication_surface_client.exe audit
bin\windows-x64\communication_surface_client.exe self
sc stop fpl_comm_surface
sc delete fpl_comm_surface
```
