## [未发布] - 2026-10-16

本次汇总 PC、iOS 和 Android 的汉化与模组加载实现，不包含光影、3D 车辆等独立实验项目。
由 PrintedAttic94 与 Codex 协作整理。

### 三端共用

- 完善 UTF-8 字形映射、测宽、换行、字体缩放及原生颜色/特殊格式兼容。
- 主图集扩充至 4096×4096，Unicode 字体使用独立 4096×4096 图集；
  在适配路径中用原生 C 处理字形映射与缩放，降低高频 JavaScript 回调开销。
- 自定义角色支持中文与字母、数字混合命名，动态长度限制最多容纳 6 个汉字，
  避免 UTF-8 字符截断及末字乱码。
- 修复小队资源列表角色名的 UTF-8 显示与宽度截断，补齐多处硬编码菜单翻译。
- 完善 i18n DeathForth 生成：区分可翻译文本与可执行字符串，保留模式、天赋、特质
  和选项处理词的稳定身份，修复部分切换语言后的存档加载问题。
- 安装模组后提示重新打开游戏，避免新旧资源缓存混用。

### PC（Windows）

- `dr2cRuntime: "resources-only"` 仅在 Windows 生效；资源模组不再执行旧加载器，
  由原版补丁的加载器负责 hook，并读取所选模组的翻译、脚本与游戏贴图。
- padded 字体加入边缘扩展，修复部分显卡上文字边缘细线；字体固定从
  游戏目录的 `mods/dr2c-mod-loader/assets/font_ucs2_12x12_padded.png` 读取，
  无需给既有资源模组逐个补文件。
- 优化中文输入、首次输入焦点及系统/游戏鼠标光标切换。
- 完善模式、天赋、特质容量扩展与相关显示兼容。
- 调整本地 ZIP 安装窗口、文件过滤及删除逻辑；保留独立 Gadget 注入相关构建工具，
  避免修改 SDL2 导致音频异常。

### iOS

- 增加匹配游戏版本的函数偏移、严格代码签名启动、原生字体动态库及正式构建脚本。
- 完善控制台触摸、键盘工具栏、预显示、光标与历史输入同步。
- 补齐小队资源、初始队友、角色存取、装备空栏、任务总结及属性报幕等硬编码翻译。
- 增加模式/天赋/特质容量、模式详情、名称测宽与截断等原生兼容补丁。
- 正式打包保留原始 Info.plist，清理多余签名与 Finder 元数据；运行原生 hook
  需要匹配的 Frida Gadget/gum-graft 与适配的游戏二进制，不能仅替换 JS 代替全部原生补丁。

### Android

- 完善 i18n 模组加载、中文命名和小队名称显示，补齐触控设置等移动端硬编码翻译。
- 控制台支持触摸呼出键盘、滑动浏览、输入预显示及粘贴/历史/光标/收起工具栏，
  并同步原生输入状态与控制台开关。
- 完善模式容量扩展的原生布局、图标、阴影与详情页兼容。
- 改包名共存不再依赖固定 application id 的外部路径；更新 APK 自带加载器时保留已安装模组。
- 增加 provider authority 修正、DEX 重建、APK 原生库/资源对齐及无签名共存包构建工具。
- ARM64 为既有实机验证路径；不同游戏版本、ABI、系统与输入法仍需分别验证，
  不将某台设备通过视为所有安卓设备已通过。

### 提交范围

- 包含运行源码、必要字体资源及正式构建/补丁工具。
- 不提交本地测试脚本、诊断入口、反汇编映射报告、自动生成中间文件、签名私钥、游戏本体或安装包。
- 构建输出仍由 `dist/`、`build/` 等忽略规则排除；外部游戏文件与工具需自行准备。

## [0.0.2] - 2026-06-12

### 🚀 Features

- Add macOS support and refactor language/i18n system

### 💼 Other

- Switch bundler to deno

### 🚜 Refactor

- Migrate Python utils to Node.js, optimize symbol handling and fix string comparison
- Unify module paths and improve interactions

### ⚙️ Miscellaneous Tasks

- Add README, LICENSE, update author, and improve build scripts
- Release v0.0.2
## [0.0.1-dev.2605270823] - 2026-05-31
