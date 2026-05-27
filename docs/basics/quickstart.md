---
icon: redhat
---

# Cheating 101

### The concept of cheating

Cheating aims to gain an unfair advantage by accessing or injecting data that the game normally hides or controls. Conceptually, this involves "reading" hidden game state, extracting information the player shouldn’t see and "writing" or emulating inputs to alter game behavior beyond intended mechanics. Through this combination of data extraction and manipulation, cheaters can see more and do more than legitimate players.

#### The 3 technical categories

Cheating techniques fall into three technical categories software, network, and hardware. Because each approach uses different mechanisms to extract hidden game data or inject/emulate inputs. Each form and method of "cheating" has its own sets of challenges and potential detection vectors.

{% hint style="info" %}
By detailing all cheating methods and building a shared knowledge base, we establish a foundation that makes our detection vector sections much easier to understand. We won't deepdive, it's a just a quick freshup.
{% endhint %}

#### Software

Software cheating encompasses both **internal** and **external** techniques that either "read" hidden game state or "write" to manipulate gameplay.&#x20;

1. Internal

Injecting a DLL into the game process lets you directly dereference in-memory pointers to "read" or "write" game values and work directly with the games sdk opening many possibilites.

```cpp
// Read
int health = *(int*)(baseAddress + 0x00F8);
// Write
*(int*)(baseAddress + 0x00F8) = 999;
```

{% hint style="warning" %}
Dereference in memory pointers, operating from within the process.
{% endhint %}

2. External (Usermode memory access)

With obtaining a handle to the games process we can externally interact with the processes memory often trying to avoid writing too memory. Considered easier too stay undetected but also having limited possibilites.

```cpp
DWORD pid = 4321;  // Game’s process ID
HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
if (!hProc) { std::cerr << "Error: cannot open process\n"; return 1; }

// Direct address (resolved via reverse engineering)
uintptr_t healthAddr = 0x00AABBCC;
int healthValue = 0;
SIZE_T bytesRead;
if (ReadProcessMemory(hProc, (LPCVOID)healthAddr, &healthValue, sizeof(healthValue), &bytesRead)) {
    std::cout << "Original Health: " << healthValue << "\n";
    int newHealth = 999;
    SIZE_T bytesWritten;
    WriteProcessMemory(hProc, (LPVOID)healthAddr, &newHealth, sizeof(newHealth), &bytesWritten);
    std::cout << "Health set to " << newHealth << "\n";
} else {
    std::cerr << "ReadProcessMemory failed\n";
}
CloseHandle(hProc);
```

{% hint style="warning" %}
External usermode memory access
{% endhint %}

3. External (Kernelmode memory access)

Using a kmd (kernel mode driver) essentially allows low level access of virtual process memory, without the process knowing. No process handle is required nor any read/write memory api's are used, the driver can directly reference the EPROCESS structure.

```cpp
PEPROCESS targetProcess;
NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
if (!NT_SUCCESS(status)) return;

SIZE_T bytesTransferred;
int healthValue = 0;

// Read from user-space address 0x00AABBCC in target process
MmCopyVirtualMemory(
    targetProcess,               // Source process
    (PVOID)0x00AABBCC,           // Address in target
    PsGetCurrentProcess(),       // Destination process (kernel)
    &healthValue,                // Kernel buffer
    sizeof(healthValue),         // Number of bytes
    KernelMode,                  // Access mode
    &bytesTransferred            // Bytes actually transferred
);
DbgPrint("Original Health: %d\n", healthValue);

// Write new health (999) back into target process
int newHealth = 999;
MmCopyVirtualMemory(
    PsGetCurrentProcess(),       // Source process (kernel)
    &newHealth,                  // Kernel buffer
    targetProcess,               // Destination process
    (PVOID)0x00AABBCC,           // Address in target
    sizeof(newHealth),           // Number of bytes
    KernelMode,                  // Access mode
    &bytesTransferred            // Bytes actually transferred
);
DbgPrint("Health set to %d\n", newHealth);

ObDereferenceObject(targetProcess);
```

{% hint style="warning" %}
External kernelmode memory access
{% endhint %}

4. External (Pixel/Color botting or image processing)

There is alternative ways of obtaining information or inputting / altering the gamestate. With Pixel/Colorbotting the screen can be processed for information and with emulating peripheral events malicious inputs can be fired. (Like a mouse click or drag)

```python
import pyautogui
import numpy as np

# Capture screen and convert to NumPy array (RGB)
screenshot = pyautogui.screenshot()
frame = np.array(screenshot)

# Define target color (pure red) and tolerance
target_color = np.array([255, 0, 0])
tolerance = 10

# Create mask of pixels within tolerance
diff = np.abs(frame.astype(int) - target_color)
mask = np.all(diff <= tolerance, axis=-1)

# Find first matching pixel
coords = np.column_stack(np.where(mask))
if coords.size:
    y, x = coords[0]
    pyautogui.moveTo(x, y)
    pyautogui.click()
```

{% hint style="warning" %}
Image processing & peripheral emulation (pixel/color botting)
{% endhint %}

5. External (Neural Network Prediction / Obj detection)

Simmilar to Pixel/Color botting we can scan images for certain objects and locating theire positions using neural networks / obj detection models like YOLO and then again emulating peripheral user input.

```python
norm_xy = model.predict(preprocess(grab_screen()))
screen_x = norm_xy[0] * screen_width
screen_y = norm_xy[1] * screen_height
move_mouse(screen_x, screen_y); click()
```

{% hint style="warning" %}
AI detection and prediction
{% endhint %}

#### Network

Network-based cheats intercept or inject packets between a game client and server to gain hidden information or manipulate game state without touching local memory.

* Reading / Writing (Packet Sniffing, manipulation & Analysis)

By capturing packets, a cheat can extract player positions, game events, or other server-sent data. For example, using Python’s Scapy to sniff UDP packets and parse coordinates:

```python
from scapy.all import sniff, UDP, Raw
import struct

def parse_game_packet(pkt):
    if UDP in pkt and pkt[UDP].dport == 27015:  # game’s port
        data = bytes(pkt[Raw])
        # Suppose bytes 5–12 encode two floats: x, y positions
        x, y = struct.unpack_from('<ff', data, offset=5)
        print(f"Enemy at x={x:.1f}, y={y:.1f}")

sniff(filter="udp port 27015", prn=parse_game_packet)
```

Here, sniff captures all UDP traffic on port 27015,  struct.unpack\_from decodes two 32-bit floats (little-endian) at offset 5. This reveals hidden player locations (a "network ESP").

* Reading / Writing example of LoL Electron Client abusing reversed API

The LoL client is an Electron app exposing a local REST API (over HTTPS) that bots can call to automate actions like accepting matches or picking champions. By reading the "lockfile" (in the game’s install folder), you obtain the port, PID, and a base64 encoded token for Basic Auth. For instance, to accept a match and then select a champion in champion select:

```python
import os, base64, requests, json

# 1) Read Riot lockfile to get port and auth token
lockfile_path = os.path.expanduser(r"~\Riot Games\League of Legends\lockfile")
with open(lockfile_path, "r") as f:
    # Format: name:PID:port:password:protocol
    name, pid, port, password, protocol = f.read().split(":")

# 2) Prepare session with Basic Auth header
token = base64.b64encode(f"riot:{password}".encode()).decode()
session = requests.Session()
session.verify = False  # LoL client uses self-signed cert
session.headers.update({"Authorization": f"Basic {token}"})

# 3) Accept a ready-check (match found)
ready_check_url = f"https://127.0.0.1:{port}/lol-matchmaking/v1/ready-check/accept"
resp = session.post(ready_check_url)
if resp.status_code == 204:
    print("Match accepted")

# 4) Pick a champion (e.g., championId = 103 for Ahri)
pick_payload = { "championId": 103, "actionId": 1, "completed": True }
champ_select_url = f"https://127.0.0.1:{port}/lol-champ-select/v1/session"
resp = session.patch(champ_select_url, data=json.dumps(pick_payload))
if resp.ok:
    print("Champion pick sent")
```

This method "writes" to the serverside gamestate by emulating legitimate in-client API calls rather than tampering with raw network packets or memory.

#### Hardware

Hardware cheats leverage external devices to bypass software-based protections, either by accessing memory without going through the CPU or by emulating human inputs at the electrical level.

1. DMA Direct Memory Access

A specialized PCIe card or Thunderbolt adapter is inserted into the system to perform memory reads/writes directly, circumventing the OS and anticheat hooks. Because DMA can access physical RAM with minimal CPU involvement, it can extract hidden game state (e.g., opponent locations) or patch values (e.g., health, ammo) in real time using PCIe read commands or DMA write operations. Using this with a secondary system it's virtually impossible for usermode anticheats to detect, because memory is modified outside CPU‐driven APIs. (Write canb obviously be detected)

Challenges are the high compelxity/costs and anticheats are forced to block devices based on suspicious heuristics or known firmware signatures.

<figure><img src="../.gitbook/assets/GNsLSzda4AAeEl3.jfif" alt=""><figcaption><p>DMA Flow Illustration</p></figcaption></figure>

2. Microcontroller-Based Keyboard/Mouse Emulation

Software based input injection using Windows APIs like `SendInput` or `mouse_event` always marks events with a "synthetic" flag (`MOUSEEVENTF_HWHEEL` or other flags) that anticheats can detect and block. In contrast, microcontrollers (e.g., Arduino, Raspberry Pi Zero, or commercial adapters like KMBox) enumerate as genuine USB HID devices. The game and OS see every report as coming from a real keyboard or mouse, no "virtual" flag, making these hardware cheats far harder to detect.

* Arduino (ATmega32U4)

```cpp
// Arduino Pro Micro (ATmega32U4) – HID mouse auto-click every 50 ms
#include <Mouse.h>

void setup() {
  Mouse.begin();  // Enumerate as a standard USB mouse
}

void loop() {
  // Perform a left-click without any synthetic flag
  Mouse.click(MOUSE_LEFT);
  delay(50);  // 20 clicks/sec—beyond human capability
}

```

Because the Arduino’s firmware implements the USB HID descriptor directly, each `Mouse.click()` is indistinguishable from a physical button press, no software API call is involved.

* Raspberry Pi Zero

```python
import time

# Format: [buttons, x-low, x-high, y-low, y-high, wheel]
# Move to (500, 500) then left-click
def send_report(hid, buttons, x, y, wheel=0):
    # Convert 16-bit coords to two bytes (little-endian)
    xl, xh = x & 0xFF, (x >> 8) & 0xFF
    yl, yh = y & 0xFF, (y >> 8) & 0xFF
    report = bytes([buttons, xl, xh, yl, yh, wheel])
    hid.write(report)

if __name__ == "__main__":
    # Wait until /dev/hidg0 is ready
    time.sleep(2)
    with open('/dev/hidg0', 'wb') as hid:
        # 1) Move cursor to (500, 500)
        send_report(hid, 0x00, 500, 500)
        time.sleep(0.01)
        # 2) Press left button (bit 0 = 1)
        send_report(hid, 0x01, 500, 500)
        time.sleep(0.01)
        # 3) Release button
        send_report(hid, 0x00, 500, 500)
```

The Pi Zero’s USB gadget framework makes the OS believe it’s talking to a standard mouse. By writing properly formatted 6-byte HID reports, it moves the cursor and clicks with electrical signals, no high-level API means no "virtual" flag.



### Wrap up

There are many more concepts and methods regarding cheating, but the mentioned basics help you to get started.

The battle between cheat developers and anticheat engineers is a continuous loop: as defenders implement new detection techniques, attackers create novel evasion methods or exploit different vectors (memory, network, hardware). Once a defense becomes effective, cheaters adapt shifting to more covert approaches or alternative entry points, forcing defenders to update their strategies again. This cat and mouse cycle drives increasingly sophisticated tools on both sides.
