# dr2c-mod-loader

A [Frida](https://frida.re/)-based mod loader for [Death Road to Canada](http://store.steampowered.com/app/252610).

It injects your mod into the game at runtime — no need to modify the original files — and works on both **desktop** and **Android**. It can also repackage the game into a mod-bundled APK, or compile the loader into a single standalone executable.

---

## PC / iOS / Android 汉化扩展（2026-10）

本分支包含三端运行实现及必要构建工具。中文更新内容见
[CHANGELOG.md](./CHANGELOG.md#未发布---2026-10-16)。测试、诊断入口和生成产物不纳入源码提交。

Windows 的资源模组应声明 `"dr2cRuntime": "resources-only"`，由原版补丁加载器处理；
该声明不让 Android 跳过模组自身脚本。iOS 使用宿主加载器，不执行模组包内的 PC/Android JS。
Windows 的 padded 字体来自原版补丁，不能随所选资源模组切换路径。

正式 iOS 构建使用 `npm run build:ios-unified-release`；它需要自备合法的干净砸壳游戏包、
匹配的 Gadget、gum-graft 和 Xcode iOS SDK。Android 共存构建使用
`utils/build-android-coexist-set.js`，需另行准备该脚本列出的 APK、Java 工具及本地签名材料。
这些外部输入不包含在仓库内；具体版本偏移和 ABI 必须与实现相匹配。

通用 `npm run build` 会重新生成 `dist/main.js`，不要用它覆盖 PC 补丁中已有的旧版
约 1.8 MB 启动器；该 PC 部署仍由旧启动器读取更新后的根加载器 `index.js`。
构建命令不是跨版本通用的游戏安装器。

Windows 的 `font_ucs2_12x12_padded.png` 由同目录原字体加边缘扩展生成，
沿用 [原字体许可证](./assets/font_ucs2_12x12.png.LICENSE)。

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

The mod-loader source code is licensed under the [ISC License](./LICENSE).

`assets/font_ucs2_12x12.png` is a bitmap derived from
[Fusion Pixel Font](https://github.com/TakWolf/fusion-pixel-font) by TakWolf,
licensed under the SIL Open Font License 1.1. The full license text is
included at
[assets/font_ucs2_12x12.png.LICENSE](./assets/font_ucs2_12x12.png.LICENSE).
