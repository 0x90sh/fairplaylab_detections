# Process Image Thread Monitor

Real WDM driver PoC using process, image, and thread notify callbacks.

Build client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build driver:

```bat
msbuild driver\fpl_process_monitor.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run:

```bat
sc create fpl_process_monitor type= kernel binPath= "%CD%\driver\x64\Release\fpl_process_monitor.sys"
sc start fpl_process_monitor
bin\windows-x64\process_image_thread_monitor_client.exe
bin\windows-x64\process_image_thread_monitor_client.exe clear
sc stop fpl_process_monitor
sc delete fpl_process_monitor
```
