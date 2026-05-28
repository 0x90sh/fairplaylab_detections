# Process Handle Callbacks

Real WDM driver PoC using `ObRegisterCallbacks` to strip dangerous process and thread handle rights for a protected PID.

Build client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build driver:

```bat
msbuild driver\fpl_handle_guard.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run:

```bat
sc create fpl_handle_guard type= kernel binPath= "%CD%\driver\x64\Release\fpl_handle_guard.sys"
sc start fpl_handle_guard
bin\windows-x64\process_handle_callbacks_client.exe set <pid>
bin\windows-x64\process_handle_callbacks_client.exe probe <pid>
bin\windows-x64\process_handle_callbacks_client.exe events
sc stop fpl_handle_guard
sc delete fpl_handle_guard
```
