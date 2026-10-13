# Dual Input for Hitman: Absolution

Gyro aiming and gamepad at the same time. Gyro moves the camera like a real mouse
(linear, no stick curve or acceleration), and the game keeps showing gamepad buttons.

## What it does

- Gyro goes straight into the camera as native mouse look.
- The gamepad stays the active device (gamepad prompts, no switching to keyboard icons).
- The right stick/trackpad has priority: while you push it, gyro is ignored.
- Menus are not affected.
- **F10** turns the mod on/off in game.

## Install

1. Close the game. Run `install.bat`.
2. Steam Input (controller layout for the game):
   - Gyro: **As Mouse**
   - Right trackpad / right stick: **Joystick**
3. Start the game and press a gamepad button once.

**Manual install:** copy `xinput9_1_0.dll` and `xinput_mouse.ini` from `mod` next to `HMA.exe`.

## Uninstall

Run `uninstall.bat`, or delete `xinput9_1_0.dll`, `xinput_mouse.ini` and `xinput_mouse.log`
from the game folder.

## Settings

`xinput_mouse.ini` next to `HMA.exe`. Most values apply while the game runs.

| Key | Default | |
|---|---|---|
| `NativeSensitivity` | 1.0 | Gyro speed (on top of the in-game mouse sensitivity) |
| `InvertY` | 0 | 1 = flip vertical gyro |
| `StickOverride` | 0.25 | How far the right stick must move to override gyro |
| `NativeSmoothingMs` | 0 | Gyro smoothing in ms (0 = off) |
| `ToggleKey` | 121 | Mod on/off key (121 = F10, 0 = none) |
| `Enabled` | 1 | 0 = mod off |

## Problems

- **No effect:** after starting the game, `xinput_mouse.log` must appear next to `HMA.exe`.
- **Keyboard icons at start:** press any gamepad button once.
- **Game updated, mod stopped working:** the mod checks the game code and turns itself off
  if it changed.
- Tested on the Steam version (`HMA.exe` SHA-256 `F143C243...4915`).

Source code is in `src` (build with `src\build.bat`, MSVC x86).

Unofficial fan mod, not affiliated with IO Interactive, Square Enix or Valve.
Use at your own risk. License: `LICENSE.txt`.
