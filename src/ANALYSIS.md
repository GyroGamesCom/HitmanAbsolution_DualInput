# Hitman Absolution (Steam) – input system RE findings (dual input: pad + gyro-as-mouse)

Target: `HMA.exe` (x86, MSVC10, ImageBase 0x400000, no DYNAMIC_BASE -> all VAs fixed), SHA-256 F143C24385D77F52B7DBC48E42E9F632A6C20E40728EC1805454740E893C4915. Glacier 2.
Static analysis (REA/Ghidra + capstone). [O] observed, [I] inference, [?] unknown.
File offset of a .text VA = VA - 0x400C00.

## TL;DR
1. Mouse = DirectInput8 device `ZMouseWindows`, immediate `GetDeviceState(cbData=0x14 = DIMOUSESTATE2)`, c_dfDIMouse2 (DIDF_RELAXIS), coop level 5 (EXCL|FG) or 0xA (NONEXCL|FG). No raw input, no WM_MOUSEMOVE. GetCursorPos/ScreenToClient only feed absolute cursor axes 3/4 (menu cursor). [O]
2. Pad = `ZGameControlWindowsX360` (type 2), XInputGetState (ord 3) each frame, radial dead zone. [O]
3. Active-device switch = `ZInputDeviceManagerWindows::UpdateActiveDevice` 0x7F7EE0, manager static 0x122EE10. Any device with a pressed button or |axis| > 0.05 becomes active (0x122F7AC). Mouse counts are raw -> any motion switches. Everything reads `active->GetType()==2`: glyphs, Scaleform `_global.isGamePadActive`/`isMouseActive`, control scheme, camera math, aim behaviour. [O]
4. Switch fix: 0x7F7F11 `83 F8 04` -> `A8 FB 90` (skip types 0 mouse and 4 virtual). Pad glyphs stay. [O]
5. No "ignore mouse in pad mode" gate. Mouse look action is ADDED to right-stick values every frame (0x674BF7). Each camera picks integrator by `type != 2`: mouse = linear, no smoothing/accel/dt; pad = curve + turbo ramp + exp smoothing. With patch 4 only, gyro would be integrated as stick. [O]
6. Native mouse path while pad active: hook vtable slot +0x28 (GetActiveDevice) at 0xEE7BC4 (orig 0x00641DB0). Return the mouse device only for camera call sites (return-address whitelist) and only on mouse frames. [O]/[I]
7. Proxy loading: DINPUT8!DirectInput8Create and XINPUT9_1_0 ord 3/4 are static imports (thunks 0xC0ADB0/0xC0ADB6/0xC0ADBC). No LoadLibrary of dinput8/xinput, no SetDllDirectory, not KnownDLLs. [O]

## Device manager (ZInputDeviceManagerWindows) – static 0x122EE10
vtable 0xEE7B9C, ctor 0x87DA40, DI init 0x5D38D0 (DirectInput8Create @0x5D3903).

| Field | Abs | Meaning |
|---|---|---|
| +0x04.. | 0x122EE14 | IInputDevice* devices[] |
| +0x84 | 0x122EE94 | device count |
| +0x998 | 0x122F7A8 | ZVirtualControlWindows (type 4) |
| +0x99C | 0x122F7AC | active device ptr (getter 0x641DB0 = `8B 81 9C 09 00 00 C3`) |
| +0x9A0 | 0x122F7B0 | u8 device class changed |
| +0x9B8 | 0x122F7C8 | HWND |
| +0x9BC | 0x122F7CC | u8 PCNewFeatures |
| +0xA68 | 0x122F878 | IDirectInput8A* |

Vtable: +0x24 UpdateActiveDevice 0x7F7EE0, +0x28 GetActiveDevice, +0x2C ClassChanged, +0x34 GetDeviceByIndex, +0x3C FindDeviceByName.
Device type at dev+0x78 (getter vt+4 = 0x539AA0).

| type | class | vtable | update |
|---|---|---|---|
| 0 | ZMouseWindows | 0xEE7CD4 | 0x7F1D90 |
| 1 | ZKeyboardWindows | 0xEE79EC | 0x5EF2C0 (GetDeviceData + GetAsyncKeyState) |
| 2 | ZGameControlWindowsX360 | 0xEE7C44 | 0x748530 |
| 4 | ZVirtualControlWindows | 0xEE7B0C | skipped by switch |

Generic device vtable: +8 NumButtons, +0xC IsButtonDown, +0x1C NumAxes, +0x30 GetAxis.

### ZMouseWindows::Update 0x7F1D90
GetDeviceState(dev,0x14,this+0x2B4); buttons 0..7; axes 0/1/2 = (float)lX/lY/lZ raw; each frame GetCursorPos, SetCursorPos(same), mouse_event(MOVE,0,0), ScreenToClient -> axes 3/4. Wheel = buttons 8/9.
Setup 0x885C20: SetDataFormat(c_dfDIMouse2 @0xF51664), SetCooperativeLevel(hwnd, nonExcl ? 0xA : 5) (`NON_EXCLUSIVE_MOUSE` option 0x7687C0 [I]).
Proxy: hook IDirectInputDevice8A::GetDeviceState (vtable index 9), filter cbData==0x14. Keyboard uses GetDeviceData (index 10).

### XInput
Created at 0x996048 (DontUseDirectInputGamepads=1 in embedded config 0xE7C4B8, PCNewFeatures=1, PauseOnFocusLoss=1).
Update 0x748530: XInputGetState(+0x2C4); 0x48F -> probe 0..3; sticks /32767, triggers /255; radial dead zone 0x9AD630 radius +0x80 (exactly 0 inside); axes 0 LX,1 LY,2 RX,3 RY,4 LT,5 RT; 14 buttons; XInputSetState rumble.
Reconnect poll 0x8738F0. GetState call sites 0x7485FD, 0x748618, 0x748652, 0x873925. SetState 0x5D6C3D, 0x5D6C5C, 0x748867.

## The switch 0x7F7EE0
```c
old = active;
for (dev in devices) {
  if (dev->GetType()==4) continue;                 // 0x7F7F11 cmp eax,4 ; je 0x7F7FD1
  for (b) if (dev->IsButtonDown(b)) { active=dev; goto next; }
  for (a) { if (dev->GetType()==0 && (a==3||a==4)) continue;
            v=dev->GetAxis(a); if (v<-0.05f || v>0.05f) { active=dev; break; } }
next:; }
classChanged = ((active->type>>1)^(old->type>>1))&1;
```

| Purpose | VA | FileOff | Original | New |
|---|---|---|---|---|
| B (recommended) mouse never active | 0x7F7F11 | 0x3F7311 | `83 F8 04` | `A8 FB 90` |
| A only mouse motion ignored | 0x7F7F6D | 0x3F736D | `83 FF` | `EB 3A` |
| C pad-lock (mouse+kb ignored) | 0x7F7F11 | 0x3F7311 | `83 F8 04` | `A8 FA 90` |

Context: 0x7F7F08 `8B 0E 8B 01 8B 50 04 FF D2 83 F8 04 0F 84 B7 00 00 00 8B 0E 8B 01 8B 50 08 33 FF FF D2`
0x7F7F60 `8B 0E 8B 11 8B 42 04 FF D0 85 C0 75 0A 83 FF 03 74 37 83 FF 04 74 32`

## Readers of the active device
All `(*(0x122EE10)->vt[0x28])()->vt[4]()==2`, gated by PCNewFeatures byte 0x114DE90.
- 0x513A50 per-frame HUD: Scaleform `_global.isMouseActive`/`isGamePadActive`, mirror byte 0x1156418; cursor show 0x843840.
- 0x83E790, 0x5FAFC0: same globals other movies.
- Prompts/glyphs: 0x6A4B60, 0x78BA90, 0x79FAE0, 0x42A7E0, 0x8DC640, 0x47EC80, 0x4FA0C0, 0xA087B0, 0x89ED20, 0x51C2E0, 0x717910, 0x788E50.
- 0x4F15C0 control scheme select (pad Alpha/Beta/Gamma, index 3 Keyboard when type != 2).
- Menus/cursor: 0x4CE2F0, 0x5F7E50, 0x957FC0, 0x9FD850, 0x4E1BB0, 0x551D30.
- 0x487E60 movement direction. Aim/cover behaviour: 0x997AF0, 0x99E740, 0x8A8000, 0x7C7DD0, 0x9A6FA0, 0x9BC150, 0x994A90, 0x5E4AB0, 0x592F70, 0x4758B0, 0x7DF410, 0x941980, 0x95C500. Haptics 0x926320. Pad mappings 0x508410, 0xA166A0.
- 0x674B50 aim-assist flag `[obj+0x3ED] = pad ? options+0x3B : 0`.
- Camera integrators: 0x54B6F0, 0x4C23E0, 0x74AE10, 0x85CF50.

## Pipeline: actions -> InputMgr -> scheme -> camera
Actions (ZInputActionManager static 0x122F7D0): combined scheme 0xE57678 + KBM block 0x6C73A0 (`eIAKBMLookHorizontal=rel(ms,x); eIAKBMLookVertical=rel(ms,y)`). All evaluated every frame. Refs: RightH 0x114E45C, RightV 0x114E46C, KBMLookH 0x114E4FC, KBMLookV 0x114E50C.

InputMgr IM = `*(*(u32*)0x1221358 + 0xA30)`; update 0x674B50 (called from 0x86C2E2, 0x7C5B6A). If !IM[+0xA8] -> 0x9C39F0, return (+0xA8 = player input enabled).
0x93E950 fills +0xC clamp(RightH), +0x8 clamp(RightV), +0x14/+0x10 left, +0x20/+0x24 left raw, +0x1C/+0x18 right raw, +0x2C/+0x28 triggers.
Then if PCNewFeatures: `+0xC += KBMLookH; +0x8 += -KBMLookV` (0x674BF7..0x674C27) unclamped. Then aim-assist flag, 0x4F15C0.

Scheme state (0x250 B, ctor 0x9C3B30): 4 instances at selector IM+0x38 +4..+0x10; +0x1C current index; state ptr at hitman+0xA34 (0x5E7810). 0x9392C0: state[0]=IM+8 (V), state[1]=IM+0xC (H). S+0x17C pad pitch speed, S+0x180 pad yaw speed, S+0x184 mouse sensitivity.

### Camera integrators
ZHM53rdPersonCamera (vtable 0xEBC334; 0x985960 -> 0x4804D0 -> 0x54B6F0), normal/cover/over-shoulder.
Mouse branch (gate `83 F8 02 0F 84 91 03 00 00` @0x54B769): `angle += v * invert(options+0x3D/+0x3E) * cam[+0x520] * fov[param+0x80] * 0.016 (0xE6BE44) * k * S[+0x184]`, k = 0.1 or `1/(base[0x104F25C]-cam[+0x1A0])` while hitman+0x6EC & 0x400 (aim zoom), extra `[+0x3E0]` precision aim. Linear, no accel/smoothing/dt.
Pad branch: curve 0x9E4170, invert props 0x12C/0x136, speeds S+0x180/0x17C, turbo ramp |stick|>0.95, 1/120 s sub-steps with `pow(1-GameCamSmoothing[0x11531DC], dt*30)`.
Other cameras: Ventilator 0x4C23E0, Closet 0x74AE10, 0x85CF50 (ShootingBallet / zoom 0x9E5BE0 [I]).

## Recommended mod design
1. Proxy (xinput9_1_0.dll and/or dinput8.dll). Verify bytes, then patch B at 0x7F7F11, and redirect `*(u32*)0xEE7BC4` (.rdata, orig 0x00641DB0):
```c
void* __fastcall HookGetActiveDevice(void* mgr){
  void* real=*(void**)((char*)mgr+0x99C);
  if (g_mouseFrame && IsCameraRA((uintptr_t)_ReturnAddress())) {
    int n=*(int*)((char*)mgr+0x84);
    for(int i=0;i<n;i++){ void* d=((void**)((char*)mgr+4))[i]; if(*(int*)((char*)d+0x78)==0) return d; }
  }
  return real; }
```
Camera return addresses (each followed by `8B 10 8B C8 8B 42 04 FF D0 83 F8 02`):

| Return addr | Function | je after |
|---|---|---|
| 0x54B760 | 3rd person 0x54B6F0 | 0x54B76C `0F 84 91 03 00 00` |
| 0x4C24C1 / 0x4C2539 / 0x4C2634 / 0x4C27F3 | Ventilator | `74 16` / `0F 84 8D 00 00 00` / `74 5E` / `74 34` |
| 0x74B07A / 0x74B2DB | Closet | `0F 84 CC 00 00 00` / `74 26` |
| 0x85D1AE / 0x85D2C9 | point shooting/zoom | `74 2D` / `74 67` |
| optional 0x674C34 | aim-assist flag | `74 03` |

g_mouseFrame = mouse lX|lY != 0 this frame AND right stick inside dead zone. Stick deflected -> zero lX/lY (stick priority).
2. dinput8 side: hook GetDeviceState (index 9), filter cbData==0x14.
3. Menus: zero mouse deltas while menu open / player input disabled.

## Readable globals
| What | Read |
|---|---|
| PCNewFeatures | `*(u8*)0x114DE90`==1 |
| Active device | `*(u32*)0x122F7AC`, type `*(i32*)(p+0x78)` |
| Device count/list | 0x122EE94 / 0x122EE14 |
| isGamePadActive mirror | `*(u8*)0x1156418` |
| Hitman | `H=*(u32*)0x1221358` |
| InputMgr | `IM=*(u32*)(H+0xA30)`: +8 V, +0xC H, u8 +0xA8 input enabled |
| Scheme index | `*(i32*)(*(u32*)(IM+0x38)+0x1C)` |
| Scheme state | `S=*(u32*)(H+0xA34)` +0x184 mouse sens |
| HUD/menu mgr (0x1161C00) | 0x1161C79 HUD, 0x1161C7C front-end open, 0x1161C7D pause open [I] |
| Scaleform cursor visible | `*(u8*)(*(u32*)0x1221698+0xC)` |
| Options | `O=*(u32*)0x1221AA8`: +0x3D/+0x3E invert, +0x3B aim assist [I] |
| IDirectInput8 | `*(u32*)0x122F878` |

Gameplay predicate: `IM && IM[+0xA8] && !b(0x1161C7C) && !b(0x1161C7D)` [I].

## Confirm live
1. 0x122F7AC type flips 2<->0 on mouse move unpatched; stays 2 with B.
2. `*(0xEE7BC4)==0x00641DB0`; bytes at 0x7F7F11, 0x54B769.
3. IM+0xC scale per mouse count.
4. S+0x184 vs mouse sensitivity slider.
5. Menu bytes 0x1161C7C/7D in menu/pause/gameplay; IM+0xA8 in cutscenes/loading.
6. Pad dead zone pad+0x80. 7. Active device at boot. 8. 0x9E5BE0 zoom camera?

## Anti-tamper (live-confirmed)
- HMA.exe has Arxan-style code-checksum guards. Function 0xDC4900 checksums code regions at start-up and the result is used as an array index (0x12627C4 -> write at 0x6564A0). Any modified byte in .text (possibly .rdata too) makes the game crash silently right after start. So patches at 0x537437 (launcher), 0x7F7F11 (switch) and the .rdata vtable dword 0xEE7BC4 all crash the game. [O]
- Therefore NO writes to the exe's .text/.rdata. Only the IAT slot (per-machine DLL addresses, cannot be checksummed) is patched.
- Replacement: vptr swapping on objects in .data/heap (never checksummed), using vtable copies ([-1] RTTI + 64 slots) kept in the proxy DLL, built completely before the vptr is published.
  - Manager (static 0x122EE10, vptr 0xEE7B9C, set by the ctor at runtime): copy vtable, slot 10 (+0x28) = HookGetActiveDevice (replaces the 0xEE7BC4 patch). Install thread polls until the vptr is 0xEE7B9C; re-installs if it reverts.
  - Switch (replaces 0x7F7F11): device-type getter is virtual slot 1 (vt+4, `8B 41 78 C3`). Mouse (type 0, vtable 0xEE7CD4), and keyboard (type 1, vtable 0xEE79EC) with PadLock=1, get a vtable copy whose slot 1 returns 4 when the return address is 0x7F7F11 (the switch then skips the device), else *(int*)(dev+0x78). Device list re-scanned about once per second (devices may be created later).
  - Launcher skip (0x537437) dropped: it needs a code patch.
