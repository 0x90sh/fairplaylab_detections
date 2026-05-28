# Driver Inventory

Real WDM driver PoC using `AuxKlibQueryModuleInformation` to return loaded kernel module inventory.

Build client:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Build driver:

```bat
msbuild driver\fpl_driver_inventory.vcxproj /p:Configuration=Release /p:Platform=x64
```

Run:

```bat
sc create fpl_driver_inventory type= kernel binPath= "%CD%\driver\x64\Release\fpl_driver_inventory.sys"
sc start fpl_driver_inventory
bin\windows-x64\driver_inventory_client.exe
sc stop fpl_driver_inventory
sc delete fpl_driver_inventory
```
