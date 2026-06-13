# dr2c-mod-loader

A [Frida](https://frida.re/)-based mod loader for [Death Road to Canada](http://store.steampowered.com/app/252610).

It injects your mod into the game at runtime — no need to modify the original files — and works on both **desktop** and **Android**. It can also repackage the game into a mod-bundled APK, or compile the loader into a single standalone executable.

---

## Install & Run

Download the latest release from the [Releases page](https://github.com/sevenshape/dr2c-mod-loader/releases).

### Android

1. Get a mod framework like [LSPatch](https://github.com/7723mod/NPatch) or [LSPosed](https://github.com/vectordotdev/vector)
2. Use it to install **modloader.apk** into your DR2C game.

### Desktop

```bash
# Windows (x64)
./dr2c-mod-loader-win32-x64.exe

# macOS (Intel only) — M1 / M2 / M3 / M4 Macs are not yet supported
# You may need to disable SIP before running.
chmod +x ./dr2c-mod-loader-darwin-x64 && ./dr2c-mod-loader-darwin-x64

# Linux (x64)
chmod +x ./dr2c-mod-loader-linux-x64 && ./dr2c-mod-loader-linux-x64
```

---

## Development

### Requirements

- [Node.js](https://nodejs.org/) + npm
- [Python](https://www.python.org/) + [pipx](https://pipx.pypa.io/) — `postinstall` installs `frida-tools` via pipx
- [Frida](https://frida.re/), [Deno](https://deno.com/)
- Android SDK platform-tools (`adb`) and JDK + Gradle, for Android/APK targets

Android targets generally need a **rooted device or emulator** so Frida can attach.

### Setup

```bash
git clone https://github.com/sevenshape/dr2c-mod-loader.git
cd dr2c-mod-loader
npm install          # postinstall installs frida-tools via pipx
npm run which        # verify the frida / frida-compile toolchain
```

### Build & run

```bash
npm run build                 # compile index.js -> dist/main.js and assemble dist/
npm run build:package         # build + bundle the mod into a distributable .zip

npm run dev                   # load the mod into the running desktop game
npm run dev:android           # attach to com.noodlecake.drtc on a connected device

npm run pck                   # compile a standalone binary via Deno
```

`*:package` variants of `dev` / `dev:android` run against the packaged build.

### Build an APK

```bash
npm run init:android          # one-time: scaffold the Capacitor Android project
npm run build:apk             # -> ./build/modloader.apk
npm run install:apk           # install on a connected device

npm run dev:apk               # full loop: build, install, relaunch, tail Xposed logs
npm run dev:apk:reload        # relaunch and tail logs only (no rebuild)
```

---

## Disclaimer

Unofficial, fan-made tool — not affiliated with or endorsed by Rocketcat Games, Madgarden, or Noodlecake Studios. Use only with a copy of the game you own, and at your own risk.

## License

[ISC License](./LICENSE)
