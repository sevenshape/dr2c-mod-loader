console.log('[dr2c-loader] compiled entry started');

const JSZip = require('jszip');
const fridaFS = require('frida-fs');
// The Java bridge is Android-only. Avoid initializing its Frida-17 build in
// the iOS Gadget 16.6.6 runtime before the loader entrypoint can run.
const Java = Process.platform === 'linux'
    ? require('frida-java-bridge').default
    : null;

// A jailed iOS process launched from its icon uses Frida Gadget with
// code_signing=required. In that mode only explicitly gum-grafted app
// functions may be intercepted; attempting the normal debug hook set would
// either fail during setup or require grafting unrelated functions. Keep the
// autonomous bootstrap deliberately small, then opt features back in as their
// exact targets are added to the graft manifest.
const IOS_STRICT_CODE_SIGNING = Process.platform === 'darwin'
    && (globalThis.__DR2C_IOS_AUTONOMOUS__ === true
        || (typeof Process.codeSigningPolicy === 'string'
            && Process.codeSigningPolicy === 'required'));

const fs = {
    // 使用 frida-fs 的原生方法
    ...fridaFS,  // 保留模块原有方法

    // 或者扩展你自己的方法
    mkdirSync: mkdirSync  // 你的自定义实现
};

/** @param {string} libName  @returns {Object} */
function requireAgent(libName) {
    if (libName === 'jszip') return JSZip;
    if (libName === 'frida-fs') return fs;
    if (libName === 'frida-java-bridge') return { default: Java };
    return NULL;
}

/**
 * Frida 17 exposes getGlobalExportByName(), while the Gadget 16 runtime used
 * by the self-signed iOS package exposes findGlobalExportByName(). Keep one
 * checked compatibility entrypoint for both runtimes.
 * @param {string} name
 * @returns {NativePointer}
 */
function getGlobalExport(name) {
    let address = null;
    if (typeof Module.getGlobalExportByName === 'function')
        address = Module.getGlobalExportByName(name);
    else if (typeof Module.findGlobalExportByName === 'function')
        address = Module.findGlobalExportByName(name);
    else if (typeof Module.findExportByName === 'function')
        address = Module.findExportByName(null, name);
    if (!address) throw new Error('Global export not found: ' + name);
    return address;
}

// This script is loaded by the SDL2 Gadget before prog.exe enters its normal
// wrapper initialization. SDL reads this hint from the process environment
// while enabling Windows text input, so set it before the game makes its one
// startup SDL_StartTextInput() call as well as at console-open time below.
if (Process.platform === 'windows') {
    try {
        const setEnvironmentVariableA = new NativeFunction(
            getGlobalExport('SetEnvironmentVariableA'), 'int', ['pointer', 'pointer']
        );
        setEnvironmentVariableA(
            Memory.allocUtf8String('SDL_IME_SHOW_UI'),
            Memory.allocUtf8String('1')
        );
        console.log('[dr2c-loader] Windows SDL IME UI environment hint set');
    } catch (e) {
        console.log('[dr2c-loader] Windows SDL IME UI environment hint unavailable:', e);
    }
}

/**
 * @brief 从 buffer 读取一个 UTF-8 序列，返回 BMP 码点
 *
 * 解析 buffer 中从 offset 位置开始的 UTF-8 字节序列，将其解码为
 * Unicode 码点。只处理 BMP 范围内的字符（U+0000 ~ U+FFFF），
 * 对于非法序列、超出 BMP 范围（4 字节序列，即 U+10000 以上）
 * 或 buffer 长度不足的情况，均返回 0。
 *
 * @param buf       指向 UTF-8 字节流的指针
 * @param offset    当前读取偏移量（字节索引）
 * @param totalLen  buffer 的总字节长度
 *
 * @return 解码后的 Unicode BMP 码点（0x0000 ~ 0xFFFF），
 *         解析失败时返回 0
 */
function getBmpCodePointNav(buf, offset, totalLen) {
    if (offset >= totalLen) return 0;

    const b0 = buf.add(offset).readU8();
    if (b0 < 0x80) return b0;
    if (b0 < 0xC2) return 0;

    if (b0 < 0xE0) {
        if (offset + 2 > totalLen) return 0;
        const b1 = buf.add(offset + 1).readU8();
        if ((b1 & 0xC0) !== 0x80) return 0;
        return ((b0 & 0x1F) << 6) | (b1 & 0x3F);
    }

    if (b0 < 0xF0) {
        if (offset + 3 > totalLen) return 0;
        const b1 = buf.add(offset + 1).readU8();
        if ((b1 & 0xC0) !== 0x80) return 0;
        if (b0 === 0xE0 && b1 < 0xA0) return 0;
        if (b0 === 0xED && b1 >= 0xA0) return 0;
        const b2 = buf.add(offset + 2).readU8();
        if ((b2 & 0xC0) !== 0x80) return 0;
        return ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
    }

    // Four-byte UTF-8 sequences are outside this BMP-only font atlas.
    return 0;
}

function formatArg(a) {
    if (typeof a === 'string') return a;
    if (a instanceof ArrayBuffer) return hexdump(a);  // Frida 场景常有 ArrayBuffer
    try {
        return JSON.stringify(a);
    } catch (e) {
        return String(a);  // 兜底，处理循环引用等 JSON 失败的情况
    }
}

/**
 * @param {...any} args
 * @returns {void}
 */
function info(...args) {
    console.info('[*]', ...args);
    if (globalThis.logFile) {
        const message = args.map(formatArg).join(' ');
        globalThis.logFile.write('[*] ' + message + '\n');
        globalThis.logFile.flush();
    }
}

/**
 * @param {...any} args
 * @returns {void}
 */
function log(...args) {
    console.log('[+]', ...args);
    if (globalThis.logFile) {
        const message = args.map(formatArg).join(' ');
        globalThis.logFile.write('[+] ' + message + '\n');
        globalThis.logFile.flush();
    }
}

/**
 * 把参数格式化成「信息 + 堆栈帧」的字符串。
 * @param {any[]} args
 * @param {string} [fallbackStack] 无 Error 参数时使用的堆栈（由调用方抓取）
 * @returns {string}
 */
function formatLog(args, fallbackStack) {
    const fmt = (a) => {
        if (a instanceof Error) return a.name + ': ' + a.message;
        if (typeof a === 'string') return a;
        if (a === null) return 'null';
        if (a === undefined) return 'undefined';
        const seen = new WeakSet();
        try {
            return JSON.stringify(a, (key, value) => {
                if (typeof value === 'bigint') return value.toString();
                if (value instanceof NativePointer) return value.toString();
                if (value !== null && typeof value === 'object') {
                    if (seen.has(value)) return '[Circular]';
                    seen.add(value);
                }
                return value;
            }, 2);
        } catch (e) {
            return String(a);
        }
    };

    const errObj = args.find(a => a instanceof Error);
    const rawStack = (errObj && errObj.stack) ? errObj.stack : (fallbackStack || new Error().stack);
    const frames = rawStack.split('\n').filter(l => /^\s*at\s/.test(l)).join('\n');

    return args.map(fmt).join(' ') + '\n' + frames;
}

/**
 * @param {...any} args
 * @returns {void}
 */
function warn(...args) {
    const message = formatLog(args, new Error().stack);
    console.warn('[!]', message);
    if (globalThis.logFile) {
        globalThis.logFile.write('[!] ' + message + '\n');
        globalThis.logFile.flush();
    }
}

/**
 * @param {...any} args
 * @returns {void}
 */
function error(...args) {
    const message = formatLog(args, new Error().stack);
    console.error('[-]', message);
    if (globalThis.logFile) {
        globalThis.logFile.write('[-] ' + message + '\n');
        globalThis.logFile.flush();
    }
}

/** @type {string} */
// @ts-ignore
globalThis.modsDir;

/** @type {Module} */
// @ts-ignore
globalThis.mainModule;

/** @type {*} */
// @ts-ignore
globalThis.application;
/** @type {*} */
// @ts-ignore
globalThis.applicationContext;
/** @type {*} */
// @ts-ignore
globalThis.activity;
globalThis.language = 'en';
globalThis.i18n = {};
globalThis.checkMode = false;

try {
    if (Process.getModuleByName('liblog.so')) {
        globalThis.isAndroid = true;
    } else {
        globalThis.isAndroid = false;
    }
} catch (e) {
    globalThis.isAndroid = false;
}

function moduleDirectory(module) {
    const path = module.path;
    return path.substring(0, path.lastIndexOf('/'));
}

/**
 * Windows' padded font belongs to the base translation patch, not the active
 * resource mod. mod.dir changes when a resource-only mod is selected, and old
 * mod packages do not contain the padded atlas. Resolve this one asset from
 * the fixed patch directory next to the EXE; keep mobile font paths unchanged.
 * @returns {string}
 */
function getUnicodeFontAssetPath() {
    if (Process.platform === 'windows') {
        const executablePath = Process.mainModule.path.replace(/\\/g, '/');
        const gameDirectory = executablePath.substring(0, executablePath.lastIndexOf('/'));
        return gameDirectory + '/mods/dr2c-mod-loader/assets/font_ucs2_12x12_padded.png';
    }
    return mod.dir + '/assets/font_ucs2_12x12.png';
}

function getDarwinGameBundleDirectory() {
    const gameModule = Process.findModuleByName('DR2C');
    return moduleDirectory(gameModule || Process.mainModule);
}

// @ts-ignore
if (typeof mod === 'undefined') {
    switch (Process.platform) {
        case 'windows':
            var mod = {
                dir: Process.mainModule.path.substring(0, Process.mainModule.path.lastIndexOf('\\')),
                script: ''
            }
            break;
        case 'linux':
            if (globalThis.isAndroid) {
                var mod = {
                    dir: '',/* 在main建立 */
                    script: ''
                }
            } else {
                var mod = {
                    dir: Process.mainModule.path.substring(0, Process.mainModule.path.lastIndexOf('/')),
                    script: ''
                }
            }
            break;
        case 'darwin':
            var darwinBundleDir = getDarwinGameBundleDirectory();
            var mod = {
                dir: darwinBundleDir,
                script: '',
                bundleDir: darwinBundleDir
            }
            break;
        default:
            throw new Error("Failed to get mod dir");
            break;
    }
}

/**
 * @param {string} modsDir 
 * @returns {{ dir: string; script: string; resourceOnly?: boolean; }[]}
 */
function loadMods(modsDir) {
    /** @type {{ dir: string; script: string; resourceOnly?: boolean; }[]} */
    let modsScript = [];
    fs.mkdirSync(modsDir);

    fs.readdirSync(globalThis.modsDir).forEach(ele => {
        if (ele === '.' || ele === '..') return;
        const modDir = `${globalThis.modsDir}/${ele}`;
        const stats = fs.lstatSync(modDir);

        if (stats.isDirectory()) {
            try {
                let manifest = null;
                try {
                    manifest = JSON.parse(File.readAllText(modDir + '/package.json'));
                } catch (e) {
                    // Preserve compatibility with manually copied legacy
                    // script mods which predate package.json.
                    warn('Mod package manifest unavailable; using legacy script:', modDir);
                }
                // On Windows, a resource-only package supplies DeathForth,
                // language and font assets while the separately installed
                // root loader owns the hooks. Android packages are standalone
                // and must retain their own index.js/main.js execution path;
                // iOS defers every package script separately below.
                if (Process.platform === 'windows'
                    && manifest && manifest.dr2cRuntime === 'resources-only') {
                    modsScript.push({ dir: modDir, script: '', resourceOnly: true });
                    log('Resource-only mod package discovered:', modDir);
                } else {
                    modsScript.push({ dir: modDir, script: File.readAllText(modDir + '/index.js') });
                }
            } catch (e) {
                error(e);
            }
        }
    });

    for (const mod of modsScript) {
        if (mod.resourceOnly) {
            log('Resource-only mod script skipped:', mod.dir);
            continue;
        }
        // iOS mods built by the existing project contain a PC/Android loader
        // with platform-specific symbol lookup.  The injected iOS loader owns
        // the hooks and offsets; installed packages provide assets only.
        if (Process.platform === 'darwin') {
            log('iOS mod package discovered (script deferred):', mod.dir);
            continue;
        }
        try {
            log('Loading nested mod script:', mod.dir);
            const fun = new Function('require', 'mod', mod.script);
            fun(requireAgent, mod);
            log('Nested mod script registered:', mod.dir);
        } catch (e) {
            // A package's index.js runs in the same Gadget realm as this
            // loader.  Do not let a syntax/top-level error silently abort the
            // remaining scan; persist the complete failure in mod.log.
            error('Nested mod script failed: ' + mod.dir, e);
        }
    }

    return modsScript;
}

/**
 * Find a resource-only package without evaluating any neighbouring mod
 * scripts. This is needed when this loader was itself started as a nested
 * mod and inherited the outer mods directory (the PC Scheme A layout).
 * @param {string} modsDir
 * @returns {string | null}
 */
function findResourceOnlyModDirectory(modsDir) {
    if (Process.platform !== 'windows') return null;
    try {
        for (const entry of fs.readdirSync(modsDir)) {
            if (entry === '.' || entry === '..') continue;
            const candidate = `${modsDir}/${entry}`;
            if (!fs.lstatSync(candidate).isDirectory()) continue;
            try {
                const manifest = JSON.parse(File.readAllText(candidate + '/package.json'));
                if (manifest.dr2cRuntime === 'resources-only') {
                    return candidate;
                }
            } catch (e) {
                // It is not a package, or belongs to an old package format.
            }
        }
    } catch (e) {
        warn('Unable to scan inherited mods directory for resource package:', modsDir, e);
    }
    return null;
}

/**
 * Windows' native resource loader uses narrow file paths for several PNG and
 * audio requests. Keep the visible package name intact, but install packages
 * with a non-ASCII name into a deterministic ASCII-only directory.
 * @param {string} name
 * @returns {string}
 */
function getInstalledModDirectoryName(name) {
    const text = String(name || 'mod');
    if (Process.platform !== 'windows' || /^[A-Za-z0-9._-]+$/.test(text))
        return text;

    let encoded = '';
    for (const character of text) {
        const codePoint = character.codePointAt(0);
        encoded += codePoint.toString(16).padStart(4, '0');
    }
    return 'mod-u' + encoded;
}

/** @type {{ [key: string]: NativePointer }} */
var LANG_STR = Object.fromEntries(
    Object.entries({}).map(([k, v]) => [k, allocMixedString(v)])
)
/** @type {{ [key: string]: string }} */
var LANG = {}

// The iOS 1.32 executable predates the PC/Android builds used to produce the
// mod's lang.json. These strings live in the old Mach-O instead of the latest
// DeathForth files, so they need an iOS-specific compatibility layer. Keep it
// in memory only: the installed mod and its lang.json are never rewritten.
const IOS_HARDCODED_ZH = Object.freeze({
    'ATK': '攻击',
    'SWAP': '切换武器',
    'USE': '互动',
    'External Music': '外部音乐',
    'CARRYING:': '携带:',
    'No Buddy': '不携带初始队友',
    'LOAD': '读取',
    "DELETE existing '%s' character?": '删除现有角色“%s”?',
    'junk.': '垃圾。',
    'car siphon empty': '没油了',
    'LOOT in the car: %s\n\n': '车内资源：%s\n\n',
    'nothing': '无资源',
    'equipment slot none': '无装备',
    'OUTTA GAS': '燃料耗尽',
    'OUTTA AMMO': '弹药耗尽',
    'ammo': '弹药',
    'Press START to JOIN!': '按开始键加入!',
    'TOUCH CONTROLS': '触屏控制',
    'Dead zone': '死区',
    'Drag zone': '拖动区域',
    'Transparency': '透明度',
    'Show pad': '显示触控板',
    'Movement': '移动',
    'Buttons': '按钮',
    'Entire box is ATTACK': '整个区域均为攻击键',
    'TAP to swap sides': '点击切换侧边',
    'DRAG LOCKED': '拖动已锁定',
    '\uE0F1Entire box is ATTACK': '\uE0F1整个区域均为攻击键',
    '\uE0F2TAP to swap sides': '\uE0F2点击切换侧边',
    '\uE0F2\uE0F7DRAG LOCKED': '\uE0F2\uE0F7拖拽已锁定',
    'ROLE:': '分工:',
    'WHAT THE...': '怎么回事……',
    'INVALID': '无效',
    'OPTIONS': '选项',
    'Settings have been reset': '设置已重置',
    'PRESS!': '按下!',
    'IN USE': '使用中',
    'Show again': '再次显示',
    'SELECT CHARACTER': '选择角色'
});

// Android's MAY-04-2023 executable still builds these captions in native C,
// after the DeathForth/i18n layer has finished. Keep the compatibility aliases
// Android-only: several words (especially "empty" and "NONE") need call-site-
// specific handling below and must never be translated globally.
const ANDROID_HARDCODED_ZH = Object.freeze({
    'With buddy': '携带初始队友',
    'No buddy': '不携带初始队友',
    'LOAD': '读取',
    'junk.': '垃圾。',
    'car siphon empty': '没油了',
    'nothing': '无资源',
    'revealed': '属性已揭示',
    'equipment slot none': '无装备',
    'TOUCH CONTROLS': '触屏控制',
    'Dead zone': '死区',
    'Drag zone': '拖动区域',
    'Transparency': '透明度',
    'Transpanency': '透明度',
    'Show pad': '显示触控板',
    'Movement': '移动',
    'Buttons': '按钮',
    'Entire box is ATTACK': '整个区域均为攻击键',
    'TAP to swap sides': '点击切换侧边',
    'DRAG LOCKED': '拖动已锁定',
    '\uE0F1Entire box is ATTACK': '\uE0F1整个区域均为攻击键',
    '\uE0F2TAP to swap sides': '\uE0F2点击切换侧边',
    '\uE0F2\uE0F7DRAG LOCKED': '\uE0F2\uE0F7拖拽已锁定',
    'Found:': '找到：',
    ' zombies destroyed.': '只僵尸被消灭。',
    ' zombies destroyed': '只僵尸被消灭'
});

// These late PC strings are assembled by native menus instead of DeathForth.
// Keep them as runtime language aliases so the normal format/button hooks can
// translate them, without editing a selected mod's lang.json.  The values are
// applied only for Chinese; every other language continues to use the game's
// original literals or its own lang.json entries.
function addPCDynamicChineseTranslations(language) {
    if (Process.platform !== 'windows' || language !== 'zh') return;
    const used = LANG['USED'] || 'USED';
    const page = LANG['PAGE'] || 'PAGE';
    Object.assign(LANG, {
        'LOOT in the car: %s\n\n': '车内资源：%s\n\n',
        'nothing': '无资源',
        'LOAD': LANG['Load'] || '读取',
        'No Buddy': LANG['No buddy'] || '不携带初始队友',
        'equipment slot none': '无装备',
        '%s - USED %d/%d - PAGE %d/%d': `%s - ${used} %d/%d - ${page} %d/%d`
    });
}

// cyoa_loot_summary formats these strings with native snprintf before the
// completed page reaches any of the normal text hooks.  A static bridge in the
// strict self-signed executable reads this table directly from its writable
// Frida data segment, so refresh it every time the active language is rebuilt.
const IOS_LOOT_SUMMARY_NAMES = Object.freeze([
    'none', 'food', 'gas', 'medical',
    'pistol ammo', 'rifle ammo', 'shotgun ammo', 'junk'
]);
const IOS_LOOT_SUMMARY_FORMAT =
    '%c + %d, \uE0F1total %s\uE0F0 %d \uE099 %d\n';
const IOS_CHARACTER_STORAGE_TITLE_FORMAT =
    '%s - USED %d/%d - PAGE %d/%d';
const IOS_CHARACTER_DELETE_FORMAT =
    "DELETE existing '%s' character?";
const IOS_MAP_JUNK_TEXT = 'junk.';
const IOS_MAP_CAR_EMPTY_KEY = 'car siphon empty';
const IOS_TEAM_LOOT_FORMAT = 'LOOT in the car: %s\n\n';
const IOS_TEAM_LOOT_EMPTY = 'nothing';
const IOS_EQUIPMENT_NONE_KEY = 'equipment slot none';
const IOS_ROLE_DESCRIPTIONS = Object.freeze([
    'ROLE:\n\nLead the mission through the scavenging site.\n\nControlled by PLAYER.',
    'ROLE:\n\nFollow and assist the lead member.',
    'ROLE:\n\nRest and recover from afar while guarding team supplies.'
]);

function refreshIOSLootSummaryTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosLootSummaryTable)
        return;

    const table = globalThis.iosLootSummaryTable;
    IOS_LOOT_SUMMARY_NAMES.forEach((name, index) => {
        table.add(index * Process.pointerSize).writePointer(L(name));
    });
    table.add(8 * Process.pointerSize).writePointer(L(IOS_LOOT_SUMMARY_FORMAT));
}

function refreshIOSCharacterStorageTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosCharacterStorageTable)
        return;

    const table = globalThis.iosCharacterStorageTable;
    const used = LANG['USED'] || 'USED';
    const page = LANG['PAGE'] || 'PAGE';
    const titleFormat = IOS_CHARACTER_STORAGE_TITLE_FORMAT
        .replace('USED', used)
        .replace('PAGE', page);
    const values = [
        titleFormat,
        L('SAVE'),
        L('LOAD'),
        L('empty'),
        L(IOS_CHARACTER_DELETE_FORMAT)
    ];
    values.forEach((value, index) => {
        table.add(index * Process.pointerSize)
            .writePointer(index === 0 ? L(value) : value);
    });
}

function refreshIOSMapEventTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosMapEventTable)
        return;

    const table = globalThis.iosMapEventTable;
    table.writePointer(L(IOS_MAP_JUNK_TEXT));
    // The global "empty" translation belongs to the custom-character slot.
    // Keep the original word outside Chinese, but use a context-specific key
    // for both empty-car siphoning paths in the Chinese iOS build.
    table.add(Process.pointerSize).writePointer(
        globalThis.language === 'zh' ? L(IOS_MAP_CAR_EMPTY_KEY) : L('empty')
    );
}

function refreshIOSEquipmentSwapTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosEquipmentSwapTable)
        return;

    globalThis.iosEquipmentSwapTable.writePointer(
        globalThis.language === 'zh' ? L(IOS_EQUIPMENT_NONE_KEY) : L('NONE')
    );
}

function refreshIOSTeamLootTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosTeamLootTable)
        return;

    const table = globalThis.iosTeamLootTable;
    table.writePointer(L(IOS_TEAM_LOOT_EMPTY));
    table.add(Process.pointerSize).writePointer(L(IOS_TEAM_LOOT_FORMAT));
}

function refreshIOSStartingBuddyTranslations() {
    if (Process.platform !== 'darwin' || !globalThis.iosStartingBuddyTable)
        return;

    const table = globalThis.iosStartingBuddyTable;
    table.writePointer(L('No buddy'));
    table.add(Process.pointerSize).writePointer(L('With buddy'));
}

function refreshIOSRoleDescriptions() {
    if (Process.platform !== 'darwin' || !globalThis.iosRoleDescriptionTable)
        return;

    const table = globalThis.iosRoleDescriptionTable;
    IOS_ROLE_DESCRIPTIONS.forEach((description, index) => {
        table.add(index * Process.pointerSize).writePointer(L(description));
    });
}

/** @param {string} iso639_1  */
function loadLangEx(iso639_1 = globalThis.language, override = false) {
    const path = mod.dir + '/assets/lang.json';
    try {
        const s = File.readAllText(path);
        const o = JSON.parse(s);
        if (!o['selected_lang'] || override) o['selected_lang'] = iso639_1;
        LANG = { ...o['string_literal'][o['selected_lang']] };
        if (Process.platform === 'darwin' && o['selected_lang'] === 'zh') {
            Object.assign(LANG, IOS_HARDCODED_ZH);
        }
        if (Process.platform === 'linux' && globalThis.isAndroid &&
            o['selected_lang'] === 'zh') {
            Object.assign(LANG, ANDROID_HARDCODED_ZH);
        }
        addPCDynamicChineseTranslations(o['selected_lang']);
        LANG_STR = Object.fromEntries(
            Object.entries(LANG).map(([k, v]) => [k, allocMixedString(globalThis.checkMode ? `code-str.${Object.keys(LANG).indexOf(k)}` : v)])
        );

        const file = new File(path, 'w');
        file.write(JSON.stringify(o, null, 4));
        file.close();

        globalThis.language = o['selected_lang'];
        refreshIOSLootSummaryTranslations();
        refreshIOSCharacterStorageTranslations();
        refreshIOSMapEventTranslations();
        refreshIOSEquipmentSwapTranslations();
        refreshIOSTeamLootTranslations();
        refreshIOSStartingBuddyTranslations();
        refreshIOSRoleDescriptions();

        const i18nPath = `${mod.dir}/assets/dr2c/i18n/${language}.json`;
        globalThis.i18n = (() => { try { return JSON.parse(File.readAllText(i18nPath)); } catch (e) { warn('i18nHook', e); return null; } })();
        if (i18n) {
            i18n.id = [];

            i18n.args = {};
            const colorNames = ["WHITE", "BLUE", "GREEN", "RED", "PURPLE", "SKULL", "FLICKER", "TOGGLE", "RAINBOW", "FLASHY", "BLINKY", "BOUNCY", "BOUNCY_OFF", "ROLLCLR", "BRIGHTER", "GLOW"];
            colorNames.forEach((name, index) => {
                i18n.args[name] = String.fromCharCode(0xE0F0 + index);
            });
        }

        log('load lang', path, Object.keys(LANG_STR).length, o['selected_lang']);
    } catch (e) {
        globalThis.i18n = null;
        warn('loadLangEx', e);
    }
}
function loadLang() {
    if (Process.platform === 'linux' || Process.platform === 'darwin') {
        if (isAndroid) {
            Java.perform(function () {
                var Locale = Java.use('java.util.Locale');
                var iso639_1 = Locale.getDefault().getLanguage();

                loadLangEx(iso639_1);
            });
        } else {
            var getenv = new NativeFunction(
                findExportByName(null, "getenv"),
                'pointer', ['pointer']
            );
            let lang = getenv(L("LANGUAGE")).readCString() || "en_US";
            let iso639_1 = lang.substring(0, 2);
            loadLangEx(iso639_1);
        }
    }
    if (Process.platform === 'windows') {
        const LOCALE_NAME_MAX_LENGTH = 85;

        const GetUserDefaultLocaleName = findExportByName('kernel32.dll', 'GetUserDefaultLocaleName');
        if (!GetUserDefaultLocaleName) {
            throw new Error('找不到 GetUserDefaultLocaleName');
        }

        const getUserDefaultLocaleName = new NativeFunction(GetUserDefaultLocaleName, 'int', ['pointer', 'int']);

        // 分配内存并调用
        const buffer = Memory.alloc(LOCALE_NAME_MAX_LENGTH * 2); // 宽字符（UTF-16）需要按2字节长度来分配
        const result = getUserDefaultLocaleName(buffer, LOCALE_NAME_MAX_LENGTH);

        if (result > 0) {
            const localeName = buffer.readUtf16String(result);
            if (localeName) {
                const iso639_1 = localeName.substring(0, 2).toLowerCase();
                loadLangEx(iso639_1);
            }
        }
    }
}

function getActivity() {
    if (globalThis.activity) return globalThis.activity;

    // Do not derive the Activity class from the APK package name. NPatch can
    // give a coexisting build a different application id while the original
    // Java class names remain unchanged, and some repackers rewrite both.
    // ActivityThread is the stable source of truth in either case.
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const thread = ActivityThread.currentActivityThread();
        if (thread) {
            const activities = thread.mActivities.value;
            const iterator = activities.values().iterator();
            while (iterator.hasNext()) {
                const record = iterator.next();
                const activity = record.activity.value;
                if (activity && !activity.isFinishing()) {
                    globalThis.activity = activity;
                    log('从 ActivityThread 获取当前 Activity:', activity.getClass().getName());
                    return globalThis.activity;
                }
            }
        }
    } catch (e) {
        // Android releases differ in their private ActivityThread layout.
        // Keep the original class lookup as a compatibility fallback.
    }

    Java.choose('com.noodlecake.drtc.DrtcGameActivity', {
        onMatch: function (activity) {
            log('找到 Activity 实例:', activity);
            globalThis.activity = activity;
        },
        onComplete: function () {
            log('Activity 实例搜索结束');
        }
    });
    return globalThis.activity;
}

function main() {
    if (Process.platform === 'darwin')
        globalThis.__DR2C_BOOT_STAGE__ = 'main entered';
    /**
    * @param {Module} module 
    */
    function main_body(module) {
        if (Process.platform === 'darwin')
            globalThis.__DR2C_BOOT_STAGE__ = 'main_body entered';
        if (!globalThis.modsDir)
            globalThis.logFile = new File(mod.dir + '/mod.log', "w");

        info('module loaded @ ' + module.base + ' size=' + module.size);
        globalThis.mainModule = module;
        info('mod path:', Process.mainModule.path, globalThis.modsDir, mod.dir);

        const main_build_stamp = new NativeFunction(findSymbol('main_build_stamp'), 'pointer', []);
        globalThis.build_stamp = main_build_stamp().readCString();
        log('main_build_stamp', globalThis.build_stamp);
        switch (globalThis.build_stamp) {
            case 'OCT-15-2025.15.11':
                globalThis.load_gfx = globalThis.mainModule.base.add(0xEE0FC);
                globalThis.btn_music_slider = globalThis.mainModule.base.add(0x100F64);
                globalThis.update_weapon_info_text = globalThis.mainModule.base.add(0x107428);
                break;
            case 'MAY-04-2023.09.39':
                // Exact MR2C.apk armeabi-v7a: private functions are Thumb.
                if (Process.platform !== 'linux' || Process.arch !== 'arm')
                    throw Error('Unsupported ABI for Android .09.39 build');
                globalThis.load_gfx = globalThis.mainModule.base.add(0x87AA5);
                globalThis.btn_music_slider = globalThis.mainModule.base.add(0x96B8D);
                globalThis.update_weapon_info_text = globalThis.mainModule.base.add(0x9B589);
                break;
            case 'MAY-04-2023.09.30':
                globalThis.load_gfx = globalThis.mainModule.base.add(0xB07D4);
                globalThis.btn_music_slider = globalThis.mainModule.base.add(0xC4D98);
                globalThis.update_weapon_info_text = globalThis.mainModule.base.add(0xCACB4);
                break;
            default:
                globalThis.load_gfx = findSymbol('load_gfx');
                globalThis.btn_music_slider = findSymbol('btn_music_slider');
                globalThis.update_weapon_info_text = findSymbol('update_weapon_info_text');
                break;
        }
        if (!globalThis.modsDir) {
            globalThis.modsDir = mod.dir + '/mods';
            const modsScript = loadMods(modsDir);
            const resourceOnlyMod = modsScript.find(item => item.resourceOnly);
            if (IOS_STRICT_CODE_SIGNING) {
                // The standalone Mach-O uses the compact 64-entry definition
                // layout from process startup.  Its description fields are
                // owned by this compatibility layer, so install it even in a
                // fresh container where no translation mod exists yet.
                hookIOSDefinitionCapacity();
                if (modsScript.length === 0) {
                    // Install every native hook while the executable is still
                    // in its permitted startup patching window.  iOS rejects
                    // new Interceptor sites after the game has started under
                    // strict code signing.  With no selected mod, LANG_STR is
                    // empty and the dynamic asset redirect falls back to the
                    // app bundle, so this remains the original English game.
                    // The bundled loader font is initialized by the normal
                    // load_gfx pass and is ready if a translation is installed
                    // later in the same process.
                    globalThis.__DR2C_BOOT_STAGE__ = 'strict baseline hooks requested';
                    hookI18n();
                    hook();
                    hookUtf8();
                    globalThis.__DR2C_BOOT_STAGE__ = 'strict baseline ready';
                    info('iOS autonomous strict baseline: hot activation ready');
                } else {
                    // The autonomous package cannot execute a mod's legacy
                    // PC/Android index.js. Use its current DeathForth, data,
                    // language and font assets through the validated iOS path.
                    mod.dir = resourceOnlyMod ? resourceOnlyMod.dir : modsScript[0].dir;
                    info('iOS autonomous mod resources selected:', mod.dir);
                    loadLang();
                    hookI18n();
                    hook();
                    globalThis.__DR2C_BOOT_STAGE__ = 'strict UTF-8 hook requested';
                    hookUtf8();
                    globalThis.__DR2C_BOOT_STAGE__ = 'strict translation ready';
                    info('iOS autonomous translation ready');
                }
            } else if (modsScript.length === 0) {
                // globalThis.checkMode = true;
                if (Process.platform === 'darwin') {
                    // iOS starts in the original English UI.  Translation and
                    // the custom font are provided by an installed mod; doing
                    // GL/font work here races the game's startup renderer.
                    hook();
                    info('iOS minimal hook baseline: Mods only');
                } else {
                    loadLang();
                    hookI18n();
                    hook();
                    tryHookWindowsDefinitionCapacity();
                    hookUtf8();
                    hookPerkExtend(globalThis.build_stamp);
                }
            } else if (Process.platform === 'darwin') {
                // Use the installed package's resources with this loader's
                // validated iOS hooks.  Do not execute the package's legacy
                // PC/Android index.js (loadMods deliberately deferred it).
                mod.dir = resourceOnlyMod ? resourceOnlyMod.dir : modsScript[0].dir;
                info('iOS mod resources selected:', mod.dir);
                loadLang();
                hookI18n();
                hook();
                info('iOS translation stage C: installing i18n and UTF-8 font hooks');
                hookIOSDefinitionCapacity();
                hookUtf8();
                info('iOS translation stage C ready');
            } else if (resourceOnlyMod) {
                // Keep the root loader's current i18n, UTF-8 font and
                // definition hooks, while sourcing game resources from the
                // installed generic resource-only package.
                mod.dir = resourceOnlyMod.dir;
                info('Resource-only mod resources selected:', mod.dir);
                loadLang();
                hookI18n();
                hook();
                tryHookWindowsDefinitionCapacity();
                hookUtf8();
                hookPerkExtend(globalThis.build_stamp);
                info('Resource-only translation and definition hooks ready');
            }

        } else {
            if (Process.platform === 'darwin') {
                hook();
                info('iOS minimal hook baseline: Mods only');
            } else {
                // Scheme A: the original Chinese loader is itself inside the
                // outer mods directory. Select a sibling resource package
                // before loading language and installing the root hooks.
                const inheritedResourceOnlyMod = findResourceOnlyModDirectory(globalThis.modsDir);
                if (inheritedResourceOnlyMod) {
                    mod.dir = inheritedResourceOnlyMod;
                    info('Inherited resource-only mod resources selected:', mod.dir);
                }
                loadLang();
                hookI18n();
                hook();
                tryHookWindowsDefinitionCapacity();
                hookUtf8();
                hookPerkExtend(globalThis.build_stamp);
                if (inheritedResourceOnlyMod) {
                    info('Inherited resource-only translation and definition hooks ready');
                }
            }
        }
        // Optional, language-independent 3D Car entry; after host initialization.
        try {
            const carPath = mod.dir + '/assets/dr2c/deathforth/spritecar/entry.js';
            let hasCar = false;
            try { hasCar = fs.statSync(carPath).isFile(); } catch (_) {}
            if (hasCar) {
                const carEntry = File.readAllText(carPath);
                new Function('mod', carEntry)(mod);
            }
        } catch (e) {
            error('Spritecar entry failed; host loader continues:', e);
        }
    }

    if (Process.platform === 'windows')
        waitForModule('prog.exe',
            /**
             * @param {Module} module 
             */
            function (module) {
                SYMBOLS = JSON.parse(SYMBOLS_JSON_STR);
                for (const key in SYMBOLS) {
                    const value = SYMBOLS[key];
                    const num = parseInt(value, 16);

                    if (num >= 0x472BB0 && num < 0x474840) {
                        const newNum = num + 0x40;
                        SYMBOLS[key] = '0x' + newNum.toString(16);
                    }

                    if (num >= 0x474840) {
                        const newNum = num + 0x240;
                        SYMBOLS[key] = '0x' + newNum.toString(16);
                    }
                }
                SYMBOLS["_turtle"] = "0x4d10c0";


                main_body(module);
            });

    if (Process.platform === 'linux' && isAndroid)
        waitForModule('libmain.so',
            /**
             * @param {Module} module 
             */
            function (module) {
                globalThis.application = Java.use('android.app.ActivityThread').currentApplication();
                globalThis.applicationContext = globalThis.application.getApplicationContext();
                var externalDir = globalThis.applicationContext.getExternalFilesDir('');


                if (externalDir != null) {
                    if (!mod.dir) {
                        mod.dir = externalDir.getAbsolutePath();
                    }
                } else {
                    throw new Error("Failed get to mods dir");
                }

                main_body(module);
            });


    if (Process.platform === 'linux' && !isAndroid)
        waitForModule('prog-linux',
            /**
             * @param {Module} module 
             */
            function (module) {
                main_body(module);
            });


    if (Process.platform === 'darwin')
        waitForModule('DR2C',
            /**
             * @param {Module} module 
             */
            function (module) {
                prepareDarwinRuntimeDirectory(module);
                main_body(module);
            });
}

function hookI18n() {
    if (Process.platform === 'darwin' && globalThis.iosI18nHooksInstalled) {
        log('iOS i18n hooks already installed');
        return;
    }
    if (Process.platform === 'darwin')
        globalThis.iosI18nHooksInstalled = true;

    const fs_register_func = new NativeFunction(findSymbol('fs_register_func'), 'int', ['pointer', 'pointer', 'pointer', 'int']);
    const fs_get_string = new NativeFunction(findSymbol('fs_get_string'), 'pointer', ['pointer', 'int']);
    const fs_get_float = new NativeFunction(findSymbol('fs_get_float'), 'double', ['pointer', 'int']);
    const fs_remove = new NativeFunction(findSymbol('fs_remove'), 'int', ['pointer', 'int']);
    const fs_push_string = new NativeFunction(findSymbol('fs_push_string'), 'int', ['pointer', 'pointer']);

    // Native stat constants are built from chara_stat_name. Keep that name
    // source untranslated until the internal dictionary is complete.
    // The strict renderer experiment belongs to hookUtf8, not hookI18n.
    // Keep this disabled while the stable native-remap path below is used.
    if (false && Process.platform === 'darwin' && IOS_STRICT_CODE_SIGNING) {
        // Gum-grafted Interceptor.attach listeners on both of these render
        // functions are not stable when the game enters a second UI session:
        // crash reports repeatedly landed in glyphs_batch_plot_ex+0x8c and
        // sprite_batch_plot+0xdc with a stale glyph descriptor.  Keep the
        // whole UTF-8 draw in one replacement instead of nesting two hot-path
        // listeners.  Pure native strings still go through the original
        // implementation.
        const IOS_DEFAULT_GLYPHS = globalThis.mainModule.base.add(0x5AF630);
        const IOS_GLYPH_CALLBACK = globalThis.mainModule.base.add(0x15F808);
        const IOS_GLYPH_CALLBACK_CONTEXT = globalThis.mainModule.base.add(0x15F810);
        let invalidGlyphWarnings = 12;
        let cachedGlyphCallbackPointer = NULL;
        let cachedGlyphCallback = null;

        function validIOSGlyphDescriptor(glyphs) {
            if (!glyphs || glyphs.isNull()) return false;
            try {
                const fontId = glyphs.readU32() & 0x3fff;
                const first = glyphs.add(4).readS32();
                const count = glyphs.add(8).readU32();
                return fontId < 0x4000 && first >= -128 && first <= 255 &&
                    count > 0 && count <= 256;
            } catch (_) {
                return false;
            }
        }

        function currentIOSGlyphCallback() {
            const pointer = IOS_GLYPH_CALLBACK.readPointer();
            if (pointer.isNull()) return null;
            if (cachedGlyphCallback === null || !pointer.equals(cachedGlyphCallbackPointer)) {
                cachedGlyphCallbackPointer = pointer;
                cachedGlyphCallback = new NativeFunction(pointer, 'int', ['int', 'int', 'pointer']);
            }
            return cachedGlyphCallback;
        }

        globalThis.iosStrictGlyphBatchReplacement = new NativeCallback(
            (requestedGlyphs, text, byteCount, alignment, batch) => {
                let glyphs = requestedGlyphs;
                try {
                    if (!validIOSGlyphDescriptor(glyphs)) {
                        if (invalidGlyphWarnings > 0) {
                            invalidGlyphWarnings--;
                            warn('iOS glyph descriptor', `Rejected ${glyphs}; using default font`);
                        }
                        glyphs = IOS_DEFAULT_GLYPHS;
                    }
                    if (!validIOSGlyphDescriptor(glyphs) || text.isNull() ||
                        byteCount <= 0 || byteCount > 4096) return 0;

                    const firstByte = glyphs.add(4).readS32();
                    const glyphCount = glyphs.add(8).readU32();
                    const font = SPRITE_GET(glyphs.readU32());
                    const glyphsToDraw = [];
                    let hasUtf8 = false;

                    for (let offset = 0; offset < byteCount;) {
                        const codePoint = getBmpCodePointNav(text, offset, byteCount);
                        let length = 1;
                        if (codePoint >= 0x80) {
                            length = codePoint < 0x800 ? 2 : 3;
                            hasUtf8 = true;
                        }
                        const rawByte = text.add(offset).readU8();
                        let index = (rawByte - firstByte) >>> 0;
                        if (index >= glyphCount) index = glyphCount - 1;
                        const sprite = font.add(index * 40);
                        glyphsToDraw.push({
                            codePoint,
                            rawByte,
                            index,
                            sprite,
                            length,
                            advance: length > 1 ? IOS_UNICODE_ADVANCE : sprite.add(12).readS16()
                        });
                        offset += length;
                    }

                    if (!hasUtf8)
                        return GLYPHS_BATCH_PLOT_EX(glyphs, text, byteCount, alignment, batch);
                    if (!unifont) return 0;

                    const localTurtle = Memory.alloc(96);
                    Memory.copy(localTurtle, TURTLE_BASE, 96);
                    const totalAdvance = glyphsToDraw.reduce((sum, item) => sum + item.advance, 0);
                    let initial = glyphsToDraw[0].advance * 0.5;
                    if (alignment === 2) initial -= totalAdvance;
                    else if (alignment === 1) initial -= totalAdvance * 0.5;
                    TURTLE_TRANS(initial, 0.0);

                    const nativeCallback = currentIOSGlyphCallback();
                    const callbackContext = IOS_GLYPH_CALLBACK_CONTEXT.readPointer();
                    try {
                        for (let i = 0; i < glyphsToDraw.length; i++) {
                            const item = glyphsToDraw[i];
                            if (i) TURTLE_TRANS(item.advance * 0.5, 0.0);

                            if (item.length === 1) {
                                const callbackIndex = (item.index << 24) >> 24;
                                const handled = nativeCallback
                                    ? nativeCallback(callbackIndex, 0, callbackContext) !== 0
                                    : false;
                                if (!handled) SPRITE_BATCH_PLOT(item.sprite, 0, batch);
                                if (nativeCallback)
                                    nativeCallback(callbackIndex, 1, callbackContext);
                            } else {
                                unifont.writeU16(unifont_x + IOS_UNICODE_CELL_SIZE * (item.codePoint & 0xff));
                                unifont.add(2).writeU16(
                                    unifont_y + IOS_UNICODE_CELL_SIZE * ((item.codePoint >> 8) & 0xff) + 1
                                );
                                const scaleXAddress = TURTLE_BASE.add(0x18);
                                const scaleYAddress = TURTLE_BASE.add(0x20);
                                const scaleX = scaleXAddress.readDouble();
                                const scaleY = scaleYAddress.readDouble();
                                scaleXAddress.writeDouble(scaleX * IOS_UNICODE_SCALE);
                                scaleYAddress.writeDouble(scaleY * IOS_UNICODE_SCALE);
                                SPRITE_BATCH_PLOT(unifont, 0, batch);
                                scaleXAddress.writeDouble(scaleX);
                                scaleYAddress.writeDouble(scaleY);
                            }
                            TURTLE_TRANS(item.advance * 0.5, 0.0);
                        }
                    } finally {
                        const preservedFloats = TURTLE_BASE.add(0x50).readByteArray(16);
                        Memory.copy(TURTLE_BASE, localTurtle, 96);
                        if (preservedFloats !== null)
                            TURTLE_BASE.add(0x50).writeByteArray(preservedFloats);
                    }

                    // The game normally submits only atlas 0.  Submit the
                    // separate Unicode atlas immediately after the current
                    // main-atlas text so Chinese stays in the same UI layer.
                    if (iosFontAtlas !== null) {
                        SPRITE_BATCH_DRAW(IOS_MAIN_ATLAS);
                        SPRITE_BATCH_DRAW(iosFontAtlas);
                    }
                    return byteCount;
                } catch (e) {
                    if (invalidGlyphWarnings > 0) {
                        invalidGlyphWarnings--;
                        error('iOS strict glyph draw failed:', e);
                    }
                    return 0;
                }
            },
            'int', ['pointer', 'pointer', 'int', 'int', 'int']
        );
        Interceptor.replace(GLYPHS_BATCH_PLOT_EX, globalThis.iosStrictGlyphBatchReplacement);
        log('Replace glyphs_batch_plot_ex iOS strict single-callback renderer 已安装');
    } else if (Process.platform === 'darwin') {
        globalThis.iosForthInternalNamesRegistered = false;
        globalThis.iosForthRegistrationHook = Interceptor.attach(findSymbol('fs_register_const'), {
            onEnter(args) {
                this.finishedInternalNames = false;
                if (args[1].isNull()) return;
                const name = args[1].readCString();
                this.finishedInternalNames = name === 'CHAR_STAT_MAX';
            },
            onLeave() {
                if (!this.finishedInternalNames) return;
                globalThis.iosForthInternalNamesRegistered = true;
            }
        });
    }


    /**
     * @param {string} template - 包含 {key} 占位符的模板字符串
     * @param {Object<string, string|number>} [values={}] - 用于替换占位符的键值对
     * @returns {string} 替换后的字符串。若占位符在 values 中不存在,则保留原样
     */
    function formatMessage(template, values = {}) {
        // log(template, JSON.stringify(values));
        return template.replace(/\{(\w+)\}/g, (match, key) => {
            return key in values ? String(values[key]) : match;
        });
    }

    if (globalThis.i18n) {
        Interceptor.attach(findSymbol('forth_init'), {
            onEnter(args) {
                this.a1 = args[0];
                if (Process.platform === 'darwin')
                    globalThis.iosForthInternalNamesRegistered = false;
            },
            onLeave(retval) {
                log('forth_init')
                File.writeAllText
            fs_register_func(this.a1, L('i18n.fmt'), navFun('i18n.fmt', () => {
                if (!i18n) {
                    return 0;
                }

                // info('fmt', i18n.id.at(-1), i18n.id.length);
                const id = i18n.id.pop();
                // const str = readByteString(fs_get_string(this.a1, -1));

                if (i18n[id] && i18n[id]['template']) {
                    const msg = formatMessage(i18n[id]['template'], i18n.args);
                    fs_remove(this.a1, 1);
                    fs_push_string(this.a1, L(msg));

                    // log(JSON.stringify(i18n.args));
                    // if (str !== msg) {
                    //     log('i18n.args', JSON.stringify(i18n.args));
                    //     log('i18n.fmt', id, str, msg);
                    // }
                }
                return 0;
            }), 0);

            fs_register_func(this.a1, L('i18n.arg!'), navFun('i18n.arg!', () => {
                if (!i18n) {
                    fs_remove(this.a1, 1);
                    return 0;
                }

                const idx = fs_get_float(this.a1, -1);
                const str = readByteString(fs_get_string(this.a1, -2));
                fs_remove(this.a1, 1);
                i18n.args[`${idx}`] = str;
                return 0;
            }), 0);

            fs_register_func(this.a1, L('i18n.id!'), navFun('i18n.id!', () => {
                if (!i18n) {
                    fs_remove(this.a1, 1);
                    return 0;
                }


                const str = readByteString(fs_get_string(this.a1, -1));
                fs_remove(this.a1, 1);
                i18n.id.push(str);

                // info('id!', i18n.id.at(-1), i18n.id.length);

                return 0;
            }), 0);

            fs_register_func(this.a1, L('i18n.id@'), navFun('i18n.id@', () => {
                if (!i18n) {
                    return 0;
                }

                // info('id@', i18n.id.at(-1), i18n.id.length);

                i18n.id.pop();
                return 0;
            }), 0);

            fs_register_func(this.a1, L('i18n.strlit!'), navFun('i18n.strlit!', () => {
                if (!i18n) {
                    fs_remove(this.a1, 1);
                    return 0;
                }

                const idx = fs_get_float(this.a1, -1);
                fs_remove(this.a1, 1);
                const id = i18n.id.at(-1);

                if (i18n[id] && i18n[id]['translated.strlits']) {

                    // const str = readByteString(fs_get_string(this.a1, -2));
                    fs_remove(this.a1, 1);

                    if (globalThis.checkMode)
                        fs_push_string(this.a1, L(`${id.slice(0, id.indexOf('.') + 7)}`));
                    else
                        fs_push_string(this.a1, L(`${i18n[id]['translated.strlits'][idx]}`));
                }
                return 0;
            }), 0);

            fs_register_func(this.a1, L('i18n.code-strlit!'), navFun('i18n.code-strlit!', () => {
                if (!i18n) {
                    return 0;
                }

                const str = readByteString(fs_get_string(this.a1, -1));
                fs_remove(this.a1, 1);
                fs_push_string(this.a1, L(str));
                return 0;
            }), 0);

            }
        });
    }


    const button_ex = findSymbol('button_ex');
    const plot_text = findSymbol('plot_text');
    /** @type {NativePointer} */
    const btn_music_slider = globalThis.btn_music_slider;
    const main_stextf = findSymbol('main_stextf');
    const chara_stat_name = findSymbol('chara_stat_name');

    // A few road-screen messages are assembled in native C. The translated
    // format string reaches main_stextf, but its nested string arguments do
    // not pass through Frida's args[] view on Apple arm64 because variadic
    // arguments live in 8-byte caller-stack slots. Translate those %s slots
    // in place before the native formatter consumes them.
    function translateIOSVariadicStrings(format, stackPointer) {
        const conversion = /%(?:\d+\$)?[-+ #0']*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|j|z|t|L)?([diuoxXfFeEgGaAcspn%])/g;
        let slot = 0;
        let match;
        while ((match = conversion.exec(format)) !== null) {
            if (match[1] === '%') continue;

            // A '*' width or precision is itself a variadic integer slot.
            slot += (match[0].match(/\*/g) || []).length;
            if (match[1] === 's') {
                const slotPointer = stackPointer.add(slot * Process.pointerSize);
                const value = slotPointer.readPointer();
                if (!value.isNull()) {
                    const text = readByteString(value);
                    if (text && LANG_STR[text])
                        slotPointer.writePointer(L(text));
                }
            }
            slot++;
        }
    }

    // snprintf is deliberately not grafted in the strict self-signed build.
    // Its completed loot-total line eventually reaches plot_text, so keep a
    // display-only fallback for the same hard-coded road-message vocabulary.
    function translateIOSRoadMessage(text) {
        if (globalThis.language !== 'zh') return text;

        const resources = [
            'shotgun ammo', 'rifle ammo', 'pistol ammo',
            'medical', 'ammo', 'food', 'gas'
        ];
        const escaped = resources.map(resource =>
            resource.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        );
        const resourcePattern = `(${escaped.join('|')})`;
        let translated = text;

        translated = translated.replace(
            new RegExp(`total ${resourcePattern}`, 'g'),
            (_, resource) => `${LANG[resource] || resource}总数`
        );
        translated = translated.replace(
            new RegExp(`\\b(GET|LOSE)\\s*${resourcePattern}\\b`, 'g'),
            (_, verb, resource) =>
                `${LANG[verb] || verb}${LANG[resource] || resource}`
        );
        translated = translated.replace(
            /\b(increases|decreases)\b/g,
            word => LANG[word] || word
        );
        return translated;
    }

    Interceptor.attach(chara_stat_name, {
        onEnter(args) {
            // if (args[0].isNull()) return;
            this.a1 = args[0].toInt32();
        },

        onLeave(retval) {
            // chara_stat_name is also used to construct internal Forth words
            // such as STAT_VITALITY. Translating it during native constant
            // registration creates STAT_最大生命 and breaks every script that
            // references the stable English symbol. Translate display calls
            // only after CHAR_STAT_MAX marks the end of that registration run.
            if (Process.platform === 'darwin' && !globalThis.iosForthInternalNamesRegistered)
                return;
            if (this.returnAddress <= findSymbol('team_btn_char_stats')) return;
            // log(`chara_stat_name ret: ${this.returnAddress}`);
            const names = [
                "morale",      // 0
                "attitude",    // 1
                "composure",   // 2
                "charm",       // 3
                "wits",        // 4
                "loyalty",     // 5
                "medical",     // 6
                "mechanical",  // 7
                "shooting",    // 8
                "strength",    // 9
                "dexterity",   // 10
                "fitness",     // 11
                "vitality"     // 12
            ];
            const str = (this.a1 >>> 0) > 0xC ? "invalid" : names[this.a1];
            if (LANG_STR[str]) {
                retval.replace(L(str));
            }
        }
    });

    if (Process.platform === 'linux') {
        Interceptor.attach(button_ex, {
            onEnter(args) {
                // button_ex is (x, y, id, text, callback) on 32-bit ARM, but
                // AAPCS64 places the same logical text argument in X1 for this
                // optimized build. Using args[1] unconditionally left every
                // armeabi-v7a button literal untranslated.
                const textArg = globalThis.isAndroid && Process.arch === 'arm'
                    ? 3 : 1;
                if (args[textArg].isNull()) return;
                const str = readByteString(args[textArg]);
                if (!str || !LANG_STR[str]) return;

                args[textArg] = L(str);
            }
        });
    } else if (Process.platform === 'darwin') {
        // iOS 的 Mods hook 已经 replace 了 button_ex。如果这里再 attach，
        // replacement 回调原函数时会同步重入另一个 JS listener，
        // 导致 Frida 脚本线程与游戏主线程一起阻塞。翻译在 hook() 的
        // 同一个 replacement 中完成。
        // plot_text is display-only and has a fixed string argument, so it is
        // safe to translate directly. Older iOS-only labels such as OPTIONS
        // bypass button_ex and otherwise never reach the language table.
        Interceptor.attach(plot_text, {
            onEnter(args) {
                if (args[0].isNull()) return;
                const str = readByteString(args[0]);
                if (!str) return;
                if (LANG_STR[str]) {
                    args[0] = L(str);
                    return;
                }
                const translated = translateIOSRoadMessage(str);
                if (translated !== str) args[0] = L(translated);
            }
        });

        // Static preview captions on the touch-control screen are game_label
        // objects, not plot_text/button_ex calls. Translate them once when the
        // label object is constructed.
        globalThis.iosGameLabelI18nHook = Interceptor.attach(findSymbol('game_label'), {
            onEnter(args) {
                if (args[0].isNull()) return;
                const str = readByteString(args[0]);
                if (!str || !LANG_STR[str]) return;
                args[0] = L(str);
            }
        });

        // touch_controls_layout's Drag-zone callback temporarily swaps the
        // button text to "\xF2\xF7DRAG LOCKED" immediately before drawing it,
        // bypassing both construction-time hooks. At 0x73668 X19 is the button
        // whose +0xC8 text field has just been replaced; redirect only that
        // transient draw and let the native callback restore its own pointer.
        globalThis.iosDragLockedI18nHook = Interceptor.attach(
            globalThis.mainModule.base.add(0x73668), {
                onEnter() {
                    const btn = this.context.x19;
                    if (btn.isNull()) return;
                    btn.add(200).writePointer(L('\uE0F2\uE0F7DRAG LOCKED'));
                }
            });
    } else if (Process.platform === 'windows') {
        Interceptor.attach(button_ex, {
            onEnter(args) {
                if (args[3].isNull()) return;
                const str = readByteString(args[3]);
                if (!str || !LANG_STR[str]) return;

                args[3] = L(str);
            }
        });
        Interceptor.attach(plot_text, {
            onEnter(args) {
                if (args[0].isNull()) return;
                const str = readByteString(args[0]);
                if (!str || !LANG_STR[str]) return;

                args[0] = L(str);
            }
        });
        Interceptor.attach(findSymbol('main_btn_wrap'), {
            onEnter(args) {
                const a1 = args[0];
                if (a1.isNull()) return;

                const strPtr = a1.add(200).readPointer();
                if (strPtr.isNull()) return;

                const str = strPtr.readCString();
                if (!str || !LANG_STR[str]) return;

                a1.add(200).writePointer(L(str));
            }
        });
    } else {
        throw new Error(`Unsupported platform: ${Process.platform}`);
    }


    Interceptor.attach(btn_music_slider, {
        onEnter(args) {
            this.a1 = args[0]
        },

        onLeave(retval) {
            if (this.a1.isNull()) return;

            const str = readByteString(this.a1.add(200).readPointer());
            if (!str || !LANG_STR[str]) return;

            this.a1.add(200).writePointer(L(str));
        }
    });

    Interceptor.attach(main_stextf, {
        onEnter(args) {
            const str = readByteString(args[0]);
            if (!str || !LANG_STR[str]) return;
            // log(`main_stextf ${str}`);
            args[0] = LANG_STR[str];
            if (Process.platform === 'darwin') {
                translateIOSVariadicStrings(str, this.context.sp);
                return;
            }
            const matches = str.match(/%./g);
            if (!matches) return;
            matches.forEach((item, index) => {
                if (item === '%s') {
                    const vastr = args[index + 1].readCString();
                    if (vastr && LANG_STR[vastr]) {
                        args[index + 1] = L(vastr);
                    }
                }
            });
        }
    });

    /* 
_vsnprintf	
_vsprintf	
_vfprintf	
_sprintf	
_printf	
_fprintf	
__snprintf	*/
    if (Process.platform === 'darwin' && IOS_STRICT_CODE_SIGNING) {
        info('iOS autonomous snprintf hook skipped');
    } else {
        const snprintf = findSymbol('snprintf');
        Interceptor.attach(snprintf, {
            onEnter(args) {
                const str = readByteString(args[2]);
                if (!str || !LANG_STR[str]) return;
                // log(`snprintf ${str}`);
                args[2] = LANG_STR[str];
                // Same Apple arm64 variadic ABI rule as main_stextf above: keep
                // the original stack-resident values and only replace the fixed
                // format parameter.
                if (Process.platform === 'darwin') return;
                const matches = str.match(/%./g);
                if (!matches) return;
                matches.forEach((item, index) => {
                    if (item === '%s') {
                        const vastr = args[index + 3].readCString();
                        if (vastr && LANG_STR[vastr]) {
                            args[index + 3] = L(vastr);
                        }
                    }
                });
            }
        });
    }

    // sprintf(str, format, ...)：可变参数，replace 需重建调用帧，按最多 6 个指针宽可变参数透传。
    // format 在 args[1]，可变参数从 args[2] 起。浮点(%f/%g)会因按 pointer marshalling 损坏，
    // UI 翻译只涉及 %s/%d，安全；超过 6 个可变参数会被截断（与 snprintf hook 同等风险范围）。
    // const sprintf = findSymbol('snprintf');
    const sprintf = Process.platform === 'windows'
        ? Process.getModuleByName('msvcrt').getExportByName('sprintf')
        : getGlobalExport('sprintf');
    const SPRINTF = new NativeFunction(sprintf, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    if (Process.platform === 'darwin') {
        // Apple arm64 的 variadic ABI 不能把 sprintf(...) 的参数统一当成
        // 6 个 pointer 重建。旧 replacement 会影响进程中所有 sprintf 调用，
        // 包括游戏启动期的非 UI 调用。iOS 先保留原始调用帧。
        info('iOS sprintf variadic replacement skipped');
    } else {
        Interceptor.replace(SPRINTF, new NativeCallback(function (str, format, v0, v1, v2, v3, v4, v5) {
            const va = [v0, v1, v2, v3, v4, v5];
            const fmt = readByteString(format);
            if (fmt && LANG_STR[fmt]) {
                // log(`sprintf ${fmt}`);
                format = LANG_STR[fmt];
                const matches = fmt.match(/%./g);
                if (matches) {
                    matches.forEach((item, index) => {
                        if (item === '%s' && index < va.length) {
                            const vastr = va[index].readCString();

                            // if (vastr && vastr.indexOf('Mechanic') !== -1)
                            //     log(vastr);

                            if (vastr && LANG_STR[vastr]) {

                                // if (vastr.indexOf('Mechanic') !== -1)
                                //     log(vastr, 'pass');

                                va[index] = L(vastr);
                            }
                        }
                    });
                }
            }
            return SPRINTF(str, format, va[0], va[1], va[2], va[3], va[4], va[5]);
        }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
    }

    const update_weapon_info_text = globalThis.update_weapon_info_text;
    Interceptor.attach(findSymbol('uppercase'), {
        onEnter(args) {
            if (this.returnAddress >= update_weapon_info_text && this.returnAddress < update_weapon_info_text.add(0xff)) {
                const str = readByteString(args[0]);
                if (!str || !LANG_STR[str]) return;
                args[0] = LANG_STR[str];
            }
        }
    });

    Interceptor.attach(findSymbol('thing_report_ex'), {
        onEnter(args) {
            const str = readByteString(args[1]);
            if (!str || !LANG_STR[str]) return;
            args[1] = LANG_STR[str];
        }
    });
}

// Windows keeps its own console UI and keyboard path. Its SDL_TEXTINPUT event,
// however, is eventually reduced to a single-byte `console_insert_char` call.
// That function validates bytes through the current C locale, which rejects a
// UTF-8 IME commit before it reaches the console buffer. The new test EXE was
// checked directly: the active console handler is RVA 0x301c0, its 128-byte
// input buffer is RVA 0x31e580, and the byte cursor is RVA 0x320634.
//
// Keep this deliberately separate from the mobile UIKit bridge. We only
// consume a non-ASCII SDL_TEXTINPUT while the native console handler has run
// in the current frame, then use the console's existing erase/redraw calls.
// Normal desktop keys, console opening, and all non-console text entry still
// use the game unchanged.
function hookWindowsConsoleUtf8Input() {
    if (Process.platform !== 'windows' || globalThis.windowsConsoleUtf8HookInstalled)
        return;
    globalThis.windowsConsoleUtf8HookInstalled = true;

    const module = globalThis.mainModule;
    const inputBuffer = module.base.add(0x31e580);
    const inputCursor = module.base.add(0x320634);
    const consoleUpdate = module.base.add(0x301c0);
    const eraseEcho = new NativeFunction(findSymbol('console_delete_char'), 'void', []);
    const appendEcho = new NativeFunction(findSymbol('console_add_text'), 'pointer', ['pointer']);
    const memmove = new NativeFunction(getGlobalExport('memmove'),
        'pointer', ['pointer', 'pointer', 'uint']);
    let setTextInputRect = null;
    let textInputRect = null;
    let setSdlHint = null;
    let startTextInput = null;
    let stopTextInput = null;
    let imeShowUiHint = null;
    let imeShowUiValue = null;
    let getForegroundWindow = null;
    let setWindowLongW = null;
    let callWindowProcW = null;
    let defWindowProcW = null;
    let setFocus = null;
    let immGetContext = null;
    let immReleaseContext = null;
    let immSetCandidateWindow = null;
    let immGetCandidateListW = null;
    let createWindowExW = null;
    let setWindowTextW = null;
    let setWindowPos = null;
    let showWindow = null;
    let getWindowRect = null;
    let candidateForm = null;
    let candidatePreviewWindow = NULL;
    let imeWindowProc = null;
    let imeWindowHandle = NULL;
    let originalImeWindowProc = NULL;
    let imeConsoleSessionInitialized = false;
    let consoleSeenAt = 0;
    let imeUiPreparationQueued = false;
    let initialTextFocusRestored = false;
    // SDL 2 in this game sends each pinyin key as SDL_TEXTINPUT as well as
    // the final selected Chinese text.  WM_IME_* is the reliable source for
    // distinguishing composition from a committed result.
    const imeCompositionState = { active: false, resultPending: false };
    globalThis.windowsImeCompositionState = imeCompositionState;

    try {
        // DR2C starts SDL text input but never supplies an IME rectangle. On
        // Windows that leaves some IMEs with an off-window candidate popup.
        // This is only a placement hint; pre-edit text is not committed to the
        // command buffer until SDL_TEXTINPUT arrives.
        setTextInputRect = new NativeFunction(getGlobalExport('SDL_SetTextInputRect'),
            'void', ['pointer']);
        textInputRect = Memory.alloc(16); // SDL_Rect { x, y, w, h }
        textInputRect.writeS32(20);
        textInputRect.add(4).writeS32(20);
        textInputRect.add(8).writeS32(420);
        textInputRect.add(12).writeS32(28);
    } catch (e) {
        warn('Windows SDL IME rectangle is unavailable:', e);
    }

    try {
        setSdlHint = new NativeFunction(getGlobalExport('SDL_SetHint'), 'int',
            ['pointer', 'pointer']);
        startTextInput = new NativeFunction(getGlobalExport('SDL_StartTextInput'),
            'void', []);
        stopTextInput = new NativeFunction(getGlobalExport('SDL_StopTextInput'),
            'void', []);
        imeShowUiHint = Memory.allocUtf8String('SDL_IME_SHOW_UI');
        imeShowUiValue = Memory.allocUtf8String('1');
    } catch (e) {
        warn('Windows SDL IME UI controls are unavailable:', e);
    }

    try {
        getForegroundWindow = new NativeFunction(getGlobalExport('GetForegroundWindow'),
            'pointer', []);
        // prog.exe is 32-bit, so the W variant of SetWindowLong is the
        // correct pointer-width API here (GWLP_WNDPROC == -4).
        setWindowLongW = new NativeFunction(getGlobalExport('SetWindowLongW'),
            'pointer', ['pointer', 'int', 'pointer']);
        callWindowProcW = new NativeFunction(getGlobalExport('CallWindowProcW'),
            'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer']);
        defWindowProcW = new NativeFunction(getGlobalExport('DefWindowProcW'),
            'int', ['pointer', 'uint', 'pointer', 'pointer']);
        setFocus = new NativeFunction(getGlobalExport('SetFocus'), 'pointer', ['pointer']);
        immGetContext = new NativeFunction(getGlobalExport('ImmGetContext'),
            'pointer', ['pointer']);
        immReleaseContext = new NativeFunction(getGlobalExport('ImmReleaseContext'),
            'int', ['pointer', 'pointer']);
        immSetCandidateWindow = new NativeFunction(getGlobalExport('ImmSetCandidateWindow'),
            'int', ['pointer', 'pointer']);
        immGetCandidateListW = new NativeFunction(getGlobalExport('ImmGetCandidateListW'),
            'uint', ['pointer', 'uint', 'pointer', 'uint']);
        createWindowExW = new NativeFunction(getGlobalExport('CreateWindowExW'),
            'pointer', ['uint', 'pointer', 'pointer', 'uint', 'int', 'int',
                'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer']);
        setWindowTextW = new NativeFunction(getGlobalExport('SetWindowTextW'),
            'int', ['pointer', 'pointer']);
        setWindowPos = new NativeFunction(getGlobalExport('SetWindowPos'),
            'int', ['pointer', 'pointer', 'int', 'int', 'int', 'int', 'uint']);
        showWindow = new NativeFunction(getGlobalExport('ShowWindow'),
            'int', ['pointer', 'int']);
        getWindowRect = new NativeFunction(getGlobalExport('GetWindowRect'),
            'int', ['pointer', 'pointer']);
        // CANDIDATEFORM on x86: DWORD index/style, POINT, RECT.
        candidateForm = Memory.alloc(32);
        candidateForm.writeU32(0);       // first candidate list
        candidateForm.add(4).writeU32(4); // CFS_CANDIDATEPOS
        candidateForm.add(8).writeS32(20);
        candidateForm.add(12).writeS32(42);
        candidateForm.add(16).writeS32(0);
        candidateForm.add(20).writeS32(0);
        candidateForm.add(24).writeS32(0);
        candidateForm.add(28).writeS32(0);
    } catch (e) {
        warn('Windows IMM candidate-window controls are unavailable:', e);
    }

    function placeImeCandidateWindow() {
        if (!setTextInputRect || !textInputRect) return;
        try {
            setTextInputRect(textInputRect);
        } catch (e) {
            warn('Windows SDL IME rectangle update failed:', e);
        }
    }

    function activateSystemImeUi() {
        try {
            // SDL's default differs between versions: older Windows builds
            // often expose only SDL_TEXTEDITING, leaving the OS candidate UI
            // hidden. Request the native candidate window explicitly.  Do
            // not stop/start the SDL text-input session here: this function
            // is reached while SDL_PollEvent is returning the first key for
            // a freshly focused editor, and restarting the session at that
            // point discards that key and leaves the widget unfocused until
            // the player clicks it again.
            if (setSdlHint && imeShowUiHint)
                setSdlHint(imeShowUiHint, imeShowUiValue);
            placeImeCandidateWindow();
            log('Windows system IME candidate UI requested without restarting text input');
        } catch (e) {
            warn('Windows system IME candidate UI request failed:', e);
        }
    }

    function configureImmCandidateWindow(hwnd) {
        if (!immGetContext || !immSetCandidateWindow || !immReleaseContext ||
            !candidateForm || !hwnd || hwnd.isNull())
            return;
        const context = immGetContext(hwnd);
        if (!context || context.isNull()) {
            warn('Windows IMM has no input context for the game window');
            return;
        }
        try {
            const ok = immSetCandidateWindow(context, candidateForm);
            log('Windows IMM candidate position set:', ok);
        } finally {
            immReleaseContext(hwnd, context);
        }
    }

    function hideImmCandidatePreview() {
        if (candidatePreviewWindow && !candidatePreviewWindow.isNull() && showWindow)
            showWindow(candidatePreviewWindow, 0); // SW_HIDE
    }

    function refreshImmCandidatePreview(hwnd) {
        if (!immGetContext || !immGetCandidateListW || !immReleaseContext ||
            !createWindowExW || !setWindowTextW || !setWindowPos || !getWindowRect ||
            !hwnd || hwnd.isNull())
            return;
        const context = immGetContext(hwnd);
        if (!context || context.isNull()) return;
        try {
            const byteCount = immGetCandidateListW(context, 0, NULL, 0);
            if (byteCount < 28) {
                hideImmCandidatePreview();
                return;
            }
            const list = Memory.alloc(byteCount);
            if (immGetCandidateListW(context, 0, list, byteCount) < 28) {
                hideImmCandidatePreview();
                return;
            }
            const count = Math.min(9, list.add(8).readU32());
            const selected = list.add(12).readU32();
            const candidates = [];
            for (let i = 0; i < count; i++) {
                const offset = list.add(24 + i * 4).readU32();
                if (offset >= byteCount) continue;
                const value = list.add(offset).readUtf16String();
                if (!value) continue;
                candidates.push(`${i + 1}. ${i === selected ? '【' : ''}${value}${i === selected ? '】' : ''}`);
            }
            if (candidates.length === 0) {
                hideImmCandidatePreview();
                return;
            }

            if (!candidatePreviewWindow || candidatePreviewWindow.isNull()) {
                const WS_POPUP = 0x80000000;
                const WS_BORDER = 0x00800000;
                const WS_EX_TOPMOST = 0x00000008;
                const WS_EX_TOOLWINDOW = 0x00000080;
                const WS_EX_NOACTIVATE = 0x08000000;
                candidatePreviewWindow = createWindowExW(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                    Memory.allocUtf16String('STATIC'), Memory.allocUtf16String(''),
                    // Visibility is applied below with SWP_NOACTIVATE.  A
                    // WS_VISIBLE popup created during the very first IME
                    // composition can briefly take focus from the game.
                    WS_POPUP | WS_BORDER,
                    0, 0, 1, 1, NULL, NULL, NULL, NULL
                );
                if (!candidatePreviewWindow || candidatePreviewWindow.isNull()) {
                    warn('Windows IMM fallback candidate window creation failed');
                    return;
                }
            }

            const rect = Memory.alloc(16);
            if (getWindowRect(hwnd, rect) === 0) return;
            const left = rect.readS32();
            const top = rect.add(4).readS32();
            setWindowTextW(candidatePreviewWindow,
                Memory.allocUtf16String(candidates.join('    ')));
            // HWND_TOPMOST=-1, SWP_NOACTIVATE | SWP_SHOWWINDOW.
            setWindowPos(candidatePreviewWindow, ptr(-1), left + 20, top + 52,
                560, 34, 0x0010 | 0x0040);
            log('Windows IMM fallback candidate preview:', candidates.join(' | '));
        } catch (e) {
            warn('Windows IMM fallback candidate preview failed:', e);
        } finally {
            immReleaseContext(hwnd, context);
        }
    }

    function installImeUiWindowProc() {
        if (!getForegroundWindow || !setWindowLongW || !callWindowProcW ||
            !defWindowProcW || imeWindowProc)
            return;
        const hwnd = getForegroundWindow();
        if (!hwnd || hwnd.isNull()) return;

        // SDL 2 versions predating SDL_HINT_IME_SHOW_UI clear these bits
        // before forwarding WM_IME_SETCONTEXT. Forward the original message
        // to SDL first (so it still receives text events), then explicitly
        // give the default Windows IME window the requested UI flags.
        const WM_IME_SETCONTEXT = 0x0281;
        const WM_IME_NOTIFY = 0x0282;
        const WM_IME_STARTCOMPOSITION = 0x010d;
        const WM_IME_ENDCOMPOSITION = 0x010e;
        const WM_IME_COMPOSITION = 0x010f;
        const GCS_RESULTSTR = 0x0800;
        const ISC_SHOW_UI = 0xe000000f; // composition, guide, soft keyboard, candidates 0-3
        imeWindowProc = new NativeCallback(function (window, message, wParam, lParam) {
            const result = callWindowProcW(
                originalImeWindowProc, window, message, wParam, lParam
            );
            if (message === WM_IME_SETCONTEXT && !wParam.isNull()) {
                try {
                    const flags = (lParam.toUInt32() | ISC_SHOW_UI) >>> 0;
                    defWindowProcW(window, message, wParam, ptr(flags));
                } catch (e) {
                    warn('Windows IME default UI forwarding failed:', e);
                }
            }
            if (message === WM_IME_STARTCOMPOSITION) {
                imeCompositionState.active = true;
                imeCompositionState.resultPending = false;
            } else if (message === WM_IME_COMPOSITION) {
                // The result message is delivered before SDL_PollEvent
                // returns its corresponding SDL_TEXTINPUT event.  Preserve
                // this flag through WM_IME_ENDCOMPOSITION so that event can
                // be accepted exactly once.
                if ((lParam.toUInt32() & GCS_RESULTSTR) !== 0)
                    imeCompositionState.resultPending = true;
            } else if (message === WM_IME_ENDCOMPOSITION) {
                imeCompositionState.active = false;
                hideImmCandidatePreview();
            }
            if (message === WM_IME_STARTCOMPOSITION ||
                message === WM_IME_COMPOSITION || message === WM_IME_NOTIFY) {
                // SDL may suppress the stock candidate window, but it still
                // maintains the IMM candidate list for these messages.
                refreshImmCandidatePreview(window);
            }
            return result;
        }, 'int', ['pointer', 'uint', 'pointer', 'pointer']);
        originalImeWindowProc = setWindowLongW(hwnd, -4, imeWindowProc);
        if (!originalImeWindowProc || originalImeWindowProc.isNull()) {
            imeWindowProc = null;
            warn('Windows IME window-procedure installation failed');
            return;
        }
        imeWindowHandle = hwnd;
        configureImmCandidateWindow(hwnd);
        // The console may open after the window has already received its
        // activation message. Re-send it with UI flags once for this session.
        defWindowProcW(hwnd, WM_IME_SETCONTEXT, ptr(1), ptr(ISC_SHOW_UI));
        log('Windows native IME candidate UI window procedure installed');
    }

    // Installing a window procedure from the same SDL_PollEvent call that
    // yielded the first character can leave the game's keyboard widget with
    // stale focus for that one session.  Prepare it after that event returns
    // instead, and once at startup before a player normally opens any text
    // field.  The IME itself is still handled by Windows, not by a custom
    // input overlay.
    function prepareImeUiDeferred() {
        if (imeWindowProc || imeUiPreparationQueued) return;
        imeUiPreparationQueued = true;
        setTimeout(() => {
            imeUiPreparationQueued = false;
            installImeUiWindowProc();
            configureImmCandidateWindow(imeWindowHandle);
        }, 0);
    }

    function restoreInitialTextFocus() {
        // The initial editable control opened after game boot sometimes has
        // SDL text input enabled but no Win32 keyboard focus.  A user click
        // inside the control fixes it; do the equivalent once, on the game
        // window itself, before the first character is processed.
        if (initialTextFocusRestored || !getForegroundWindow || !setFocus) return;
        const hwnd = getForegroundWindow();
        if (!hwnd || hwnd.isNull()) return;
        try {
            setFocus(hwnd);
            initialTextFocusRestored = true;
            log('Windows initial game text focus restored');
        } catch (e) {
            warn('Windows initial game text focus restore failed:', e);
        }
    }

    function byteLength(value) {
        const source = Memory.allocUtf8String(value);
        let length = 0;
        while (source.add(length).readU8() !== 0) length++;
        return length;
    }

    function insertUtf8(value) {
        const source = Memory.allocUtf8String(value);
        let sourceLength = byteLength(value);
        if (sourceLength === 0) return;

        let currentLength = 0;
        while (currentLength < 127 && inputBuffer.add(currentLength).readU8() !== 0)
            currentLength++;
        const cursor = Math.max(0, Math.min(currentLength, inputCursor.readS32()));
        const available = 126 - currentLength;
        if (available <= 0) return;
        if (sourceLength > available) {
            // Never split an UTF-8 code point when a single IME commit is too
            // large for the game's fixed-size command buffer.
            let safeLength = available;
            while (safeLength > 0 &&
                (source.add(safeLength).readU8() & 0xc0) === 0x80)
                safeLength--;
            sourceLength = safeLength;
        }
        if (sourceLength <= 0) return;

        memmove(inputBuffer.add(cursor + sourceLength), inputBuffer.add(cursor),
            currentLength - cursor + 1);
        Memory.copy(inputBuffer.add(cursor), source, sourceLength);
        inputCursor.writeS32(cursor + sourceLength);

        // This is the same display path console_insert_char uses after it has
        // changed the buffer. eraseEcho redraws only the visible echo; it does
        // not mutate inputBuffer.
        for (let i = 0; i < currentLength; i++) eraseEcho();
        appendEcho(inputBuffer);
        log('Windows console accepted UTF-8 input:', value);
    }

    function deletePreviousUtf8CodePoint() {
        let currentLength = 0;
        while (currentLength < 127 && inputBuffer.add(currentLength).readU8() !== 0)
            currentLength++;
        const cursor = Math.max(0, Math.min(currentLength, inputCursor.readS32()));
        if (cursor === 0) return false;

        // An ASCII byte is still best handled by the untouched native path.
        // For UTF-8, walk back from the byte before the cursor to its leading
        // byte. This also repairs a cursor that the original left/right code
        // has placed inside a multi-byte code point.
        let start = cursor - 1;
        if (inputBuffer.add(start).readU8() < 0x80) return false;
        while (start > 0 && (inputBuffer.add(start).readU8() & 0xc0) === 0x80)
            start--;
        const lead = inputBuffer.add(start).readU8();
        const width = (lead & 0xf8) === 0xf0 ? 4 :
            (lead & 0xf0) === 0xe0 ? 3 :
                (lead & 0xe0) === 0xc0 ? 2 : 0;
        if (width === 0 || start + width > currentLength) return false;
        for (let i = 1; i < width; i++) {
            if ((inputBuffer.add(start + i).readU8() & 0xc0) !== 0x80)
                return false;
        }

        memmove(inputBuffer.add(start), inputBuffer.add(start + width),
            currentLength - start - width + 1);
        inputCursor.writeS32(start);
        for (let i = 0; i < currentLength; i++) eraseEcho();
        appendEcho(inputBuffer);
        return true;
    }

    // sub_4301c0 is the per-frame console state handler in the current test
    // executable. Tracking this avoids relying on an old build's relocated
    // global state pointer and keeps non-console SDL text input untouched.
    Interceptor.attach(consoleUpdate, {
        onEnter() {
            consoleSeenAt = Date.now();
            // The current EXE's actual console-opening route does not reach
            // the old main_do_console_open symbol mapping. consoleUpdate is
            // verified from its executable and runs every console frame, so
            // initialize the Windows IME integration here instead.
            if (!imeConsoleSessionInitialized) {
                imeConsoleSessionInitialized = true;
                restoreInitialTextFocus();
                activateSystemImeUi();
                prepareImeUiDeferred();
            }
        }
    });
    Interceptor.attach(findSymbol('main_do_console_open'), {
        onLeave() {
            // Cover the first frame immediately after the console is opened.
            consoleSeenAt = Date.now();
            activateSystemImeUi();
            prepareImeUiDeferred();
        }
    });
    Interceptor.attach(findSymbol('console_insert_char'), {
        onEnter(args) {
            // This MinGW function uses a non-standard usercall ABI: its
            // single character parameter is passed in EAX, not on the stack.
            // The native console deletes one byte for Backspace. Intercept
            // only a UTF-8 code point immediately before its cursor; ASCII
            // deletion remains completely native.
            if ((this.context.eax.toInt32() & 0xff) !== 8) return;
            if (!deletePreviousUtf8CodePoint()) return;
            this.context.eax = ptr(0);
        }
    });
    Interceptor.attach(findSymbol('SDL_PollEvent'), {
        onEnter(args) {
            this.event = args[0];
        },
        onLeave(result) {
            try {
                if (result.toInt32() === 0 || !this.event ||
                    Date.now() - consoleSeenAt > 250)
                    return;
                // SDL_TEXTINPUT: Uint32 type, Uint32 timestamp, Uint32
                // windowID, then char text[32].
                if (this.event.readU32() !== 0x303) return;
                let length = 0;
                while (length < 31 && this.event.add(12 + length).readU8() !== 0)
                    length++;
                if (length === 0) return;
                const value = this.event.add(12).readUtf8String(length);
                if (!value || !/[^\x00-\x7f]/.test(value)) return;

                insertUtf8(value);
                // Prevent the game's byte-oriented input queue from receiving
                // the same UTF-8 bytes a second time.
                this.event.writeU32(0);
            } catch (e) {
                error('Windows console UTF-8 input hook failed:', e);
            }
        }
    });
    // The custom-character name editor uses the same SDL text-input session
    // as the console. Expose this existing IME integration so its native
    // candidate window can be activated without installing a competing
    // WndProc hook.
    globalThis.windowsActivateTextImeUi = () => {
        restoreInitialTextFocus();
        activateSystemImeUi();
        prepareImeUiDeferred();
    };
    // By the time a player reaches the console or Custom Character editor,
    // the game's foreground window already exists.  Do this outside an SDL
    // event so the first keystroke is never part of the setup sequence.
    setTimeout(prepareImeUiDeferred, 750);
    log('Windows console UTF-8 input hook installed');
}

// The current Windows executable exposes the active generic text widget at
// RVA 0x46c828. Custom Character > Name is its only normal in-game caller:
// the field stores a UTF-8 byte buffer at +200 and a byte cursor at +256.
// Keep the storage rule identical to iOS: 18 UTF-8 bytes, i.e. six CJK names
// or eighteen ASCII letters/digits, with mixed names sharing one real budget.
function hookWindowsCustomNameUtf8Input() {
    if (Process.platform !== 'windows' || globalThis.windowsCustomNameUtf8HookInstalled)
        return;
    globalThis.windowsCustomNameUtf8HookInstalled = true;

    const module = globalThis.mainModule;
    const activeEditorSlot = module.base.add(0x46c828);
    const EDITOR_TEXT_OFFSET = 200;
    const EDITOR_CURSOR_OFFSET = 256;
    const EDITOR_WIDTH_OFFSET = 32;
    const EDITOR_BUFFER_CAPACITY = 39;
    const CUSTOM_NAME_MAX_UTF8_BYTES = 18;
    // Match the iOS widened Custom Character name field.  The original
    // renderer measures UTF-8 byte-by-byte, so its legacy width is too small
    // even for a legal six-character CJK name (18 bytes).
    const CUSTOM_NAME_FIELD_WIDTH = 144;
    // sub_47B9B0's final text renderer keeps incrementing a char pointer
    // until its *byte*-measured width fits.  That corrupts the start position
    // of UTF-8 names and is why a six-CJK-character name appeared capped.
    // In this verified PC build, RVA 0x7bac5 is precisely the conditional
    // branch to that truncation loop.  Change JBE to JMP only after checking
    // the original opcode, so a future EXE revision is left untouched.
    const CUSTOM_NAME_BYTE_CLIP_BRANCH_RVA = 0x7bac5;
    const memmove = new NativeFunction(getGlobalExport('memmove'),
        'pointer', ['pointer', 'pointer', 'uint']);
    let lastEditor = NULL;
    let nativePixelTruncationDisabled = false;

    function disableNativeByteClip() {
        const branch = module.base.add(CUSTOM_NAME_BYTE_CLIP_BRANCH_RVA);
        try {
            const opcode = branch.readU8();
            if (opcode !== 0x76) { // JBE rel8 in the verified new EXE
                warn('Windows custom-name byte-clip patch skipped; expected JBE, got 0x' +
                    opcode.toString(16));
                return;
            }
            Memory.patchCode(branch, 2, code => code.writeU8(0xeb)); // JMP rel8
            log('Windows custom-name native UTF-8 byte clipping disabled');
        } catch (e) {
            error('Windows custom-name byte-clip patch failed:', e);
        }
    }

    disableNativeByteClip();

    function activeNameEditor() {
        try {
            const editor = activeEditorSlot.readPointer();
            if (!editor || editor.isNull()) return null;
            const buffer = editor.add(EDITOR_TEXT_OFFSET).readPointer();
            if (!buffer || buffer.isNull()) return null;
            return { editor, buffer, cursor: editor.add(EDITOR_CURSOR_OFFSET) };
        } catch (e) {
            warn('Windows custom-name editor lookup failed:', e);
            return null;
        }
    }

    function byteLength(value) {
        const source = Memory.allocUtf8String(value);
        let length = 0;
        while (source.add(length).readU8() !== 0) length++;
        return length;
    }

    function currentLength(buffer) {
        let length = 0;
        while (length < EDITOR_BUFFER_CAPACITY && buffer.add(length).readU8() !== 0)
            length++;
        return length;
    }

    function safePrefix(value, maximumBytes) {
        let result = '';
        let used = 0;
        for (const character of Array.from(value)) {
            const bytes = byteLength(character);
            if (used + bytes > maximumBytes) break;
            result += character;
            used += bytes;
        }
        return result;
    }

    function normalizeCursor(buffer, cursor, direction = -1) {
        let result = Math.max(0, Math.min(currentLength(buffer), cursor));
        if (direction < 0) {
            while (result > 0 && (buffer.add(result).readU8() & 0xc0) === 0x80)
                result--;
        } else {
            while (result < currentLength(buffer) &&
                (buffer.add(result).readU8() & 0xc0) === 0x80)
                result++;
        }
        return result;
    }

    function clampName(editor) {
        const length = currentLength(editor.buffer);
        if (length <= CUSTOM_NAME_MAX_UTF8_BYTES) return false;
        let value = '';
        try {
            value = editor.buffer.readUtf8String(length);
        } catch (_) {
            return false;
        }
        const limited = safePrefix(value, CUSTOM_NAME_MAX_UTF8_BYTES);
        const source = Memory.allocUtf8String(limited);
        const limitedLength = byteLength(limited);
        Memory.copy(editor.buffer, source, limitedLength + 1);
        editor.cursor.writeS32(Math.min(editor.cursor.readS32(), limitedLength));
        return true;
    }

    function widenNameField(editor) {
        try {
            const width = editor.editor.add(EDITOR_WIDTH_OFFSET).readFloat();
            if (Number.isFinite(width) && width > 0 && width < CUSTOM_NAME_FIELD_WIDTH) {
                editor.editor.add(EDITOR_WIDTH_OFFSET).writeFloat(CUSTOM_NAME_FIELD_WIDTH);
                log('Windows custom-name field width expanded from', width, 'to', CUSTOM_NAME_FIELD_WIDTH);
            }
        } catch (e) {
            warn('Windows custom-name field width expansion failed:', e);
        }
    }

    function insertUtf8(editor, value) {
        clampName(editor);
        const length = currentLength(editor.buffer);
        const cursor = normalizeCursor(editor.buffer, editor.cursor.readS32());
        const remaining = CUSTOM_NAME_MAX_UTF8_BYTES - length;
        if (remaining <= 0) return false;
        const accepted = safePrefix(value, remaining);
        if (!accepted) return false;
        const source = Memory.allocUtf8String(accepted);
        const inserted = byteLength(accepted);
        if (length + inserted >= EDITOR_BUFFER_CAPACITY) return false;
        memmove(editor.buffer.add(cursor + inserted), editor.buffer.add(cursor),
            length - cursor + 1);
        Memory.copy(editor.buffer.add(cursor), source, inserted);
        editor.cursor.writeS32(cursor + inserted);
        log('Windows custom name accepted UTF-8 input:', accepted);
        return true;
    }

    function deletePrevious(editor) {
        const length = currentLength(editor.buffer);
        const cursor = normalizeCursor(editor.buffer, editor.cursor.readS32());
        if (cursor === 0) return false;
        let start = cursor - 1;
        while (start > 0 && (editor.buffer.add(start).readU8() & 0xc0) === 0x80)
            start--;
        memmove(editor.buffer.add(start), editor.buffer.add(cursor),
            length - cursor + 1);
        editor.cursor.writeS32(start);
        return true;
    }

    function deleteNext(editor) {
        const length = currentLength(editor.buffer);
        const cursor = normalizeCursor(editor.buffer, editor.cursor.readS32());
        if (cursor >= length) return false;
        let end = cursor + 1;
        while (end < length && (editor.buffer.add(end).readU8() & 0xc0) === 0x80)
            end++;
        memmove(editor.buffer.add(cursor), editor.buffer.add(end), length - end + 1);
        editor.cursor.writeS32(cursor);
        return true;
    }

    function moveCursor(editor, delta) {
        const length = currentLength(editor.buffer);
        let cursor = normalizeCursor(editor.buffer, editor.cursor.readS32());
        if (delta < 0 && cursor > 0) {
            cursor--;
            while (cursor > 0 && (editor.buffer.add(cursor).readU8() & 0xc0) === 0x80)
                cursor--;
        } else if (delta > 0 && cursor < length) {
            cursor++;
            while (cursor < length && (editor.buffer.add(cursor).readU8() & 0xc0) === 0x80)
                cursor++;
        }
        editor.cursor.writeS32(cursor);
    }

    Interceptor.attach(findSymbol('SDL_PollEvent'), {
        onEnter(args) {
            this.event = args[0];
        },
        onLeave(result) {
            try {
                if (result.toInt32() === 0 || !this.event) return;
                const editor = activeNameEditor();
                if (!editor) {
                    lastEditor = NULL;
                    return;
                }
                if (lastEditor.isNull() || !lastEditor.equals(editor.editor)) {
                    lastEditor = editor.editor;
                    if (globalThis.windowsActivateTextImeUi)
                        globalThis.windowsActivateTextImeUi();
                    log('Windows custom-name UTF-8 editor activated');
                }

                const type = this.event.readU32();
                if (type === 0x303) { // SDL_TEXTINPUT
                    let length = 0;
                    while (length < 31 && this.event.add(12 + length).readU8() !== 0)
                        length++;
                    if (length === 0) return;
                    const value = this.event.add(12).readUtf8String(length);
                    if (!value) return;
                    const ime = globalThis.windowsImeCompositionState;
                    if (ime && ime.active && !ime.resultPending) {
                        // This old SDL build emits the live pinyin letters as
                        // TEXTINPUT.  They are pre-edit text, not part of the
                        // custom name; accepting them consumes the byte
                        // budget before the Chinese result arrives.
                        this.event.writeU32(0);
                        log('Windows custom name ignored IME pre-edit text:', value);
                        return;
                    }
                    if (ime && ime.resultPending) {
                        ime.resultPending = false;
                        log('Windows custom name accepted IME result:', value);
                    }
                    // This is the sole printable-text path for this field.
                    // SDL emits committed text here for ASCII, digits, and
                    // IME-selected CJK alike; accepting only CJK allowed the
                    // old KeyDown path to insert pinyin bytes before a CJK
                    // commit arrived.
                    insertUtf8(editor, value);
                    // Also consume a rejected over-limit commit: forwarding
                    // it would let the old byte-oriented callback bypass the
                    // shared 18-byte limit.
                    this.event.writeU32(0);
                    return;
                }

                if (type !== 0x300) return; // SDL_KEYDOWN
                const key = this.event.add(20).readS32(); // SDL_Keysym.sym
                let handled = false;
                if (key === 8) handled = deletePrevious(editor); // Backspace
                else if (key === 127) handled = deleteNext(editor); // Delete
                else if (key === 1073741904) { moveCursor(editor, -1); handled = true; } // Left
                else if (key === 1073741903) { moveCursor(editor, 1); handled = true; } // Right
                else {
                    // Consume ordinary printable KeyDown events.  The game
                    // has a byte-oriented keyboard callback which would
                    // otherwise receive IME pinyin letters before SDL emits
                    // their committed Chinese text.  Preserve shortcuts and
                    // non-printable controls by checking the SDL modifier.
                    const modifiers = this.event.add(24).readU16();
                    const shortcut = (modifiers & 0x0fc0) !== 0; // Ctrl/Alt/GUI
                    if (!shortcut && key >= 32 && key <= 126)
                        handled = true;
                }
                if (handled) this.event.writeU32(0);
            } catch (e) {
                error('Windows custom-name UTF-8 input hook failed:', e);
            }
        }
    });
    // ASCII input remains on the game's original keyboard path.  During
    // rendering, apply the iOS-equivalent 144px field width before the
    // native byte-oriented clipping loop runs, then clamp to the shared
    // 18-byte budget even when no SDL_TEXTINPUT event is emitted for a
    // physical ASCII key.
    Interceptor.attach(module.base.add(0x7b9b0), {
        onEnter(args) {
            try {
                const editor = activeNameEditor();
                if (editor && args[0].equals(editor.editor)) {
                    widenNameField(editor);
                    clampName(editor);
                }
            } catch (e) {
                error('Windows custom-name length clamp failed:', e);
            }
        }
    });
    // sub_47CFF0 invokes sub_47C910(name, 96) after every keyboard event.
    // The helper decrements *bytes* until a native-font pixel width fits, so
    // widening it to 144 can still cut the final UTF-8 sequence in half (for
    // example the first two bytes of U+9F99, 龙).  This is the same secondary
    // truncator disabled by the verified iOS fix.  Our own 18-byte,
    // code-point-safe limit is the sole limit for this one name field.
    Interceptor.attach(module.base.add(0x7c910), {
        onEnter(args) {
            try {
                const editor = activeNameEditor();
                this.customNameBuffer = !!editor && args[0].equals(editor.buffer);
            } catch (e) {
                error('Windows custom-name post-input pixel-limit hook failed:', e);
            }
        },
        onLeave(retval) {
            if (!this.customNameBuffer) return;
            // Caller truncates its backing string only when this returns a
            // non-zero byte index. Returning 0 preserves the complete UTF-8
            // name, including the final character at the 18-byte boundary.
            retval.replace(ptr(0));
            if (!nativePixelTruncationDisabled) {
                nativePixelTruncationDisabled = true;
                log('Windows custom-name post-input byte truncation disabled');
            }
        }
    });
    log('Windows custom-name UTF-8 input hook installed');
}

// Keep the original desktop cursor contract around the Windows IME bridge.
// The game renders its own cursor and normally keeps the Windows system cursor
// hidden. In the current EXE, cursor_timeout starts at 60 and is refreshed by
// physical mouse movement; keyboard input clears it. The IME bridge can leave
// that refresh stale, so update the game's timer rather than showing SDL's
// system cursor (which would produce two cursors).
function hookWindowsMouseCursorWake() {
    if (Process.platform !== 'windows' || globalThis.windowsMouseCursorWakeHookInstalled)
        return;
    if (globalThis.build_stamp !== 'JUN-20-2024.10.25') {
        log('Windows mouse-motion cursor wake skipped for unknown build:', globalThis.build_stamp);
        return;
    }
    globalThis.windowsMouseCursorWakeHookInstalled = true;

    try {
        // JUN-20-2024.10.25: mapped old data symbols are shifted by 0x1000
        // in this build. The initialized value is 60 in the executable's
        // .data segment, matching the native cursor countdown.
        const cursorTimeout = globalThis.mainModule.base.add(0xd1340);
        const sdlShowCursor = new NativeFunction(findSymbol('SDL_ShowCursor'), 'int', ['int']);

        Interceptor.attach(findSymbol('SDL_PollEvent'), {
            onEnter(args) {
                this.event = args[0];
            },
            onLeave(result) {
                try {
                    if (result.toInt32() === 0 || !this.event) return;
                    const type = this.event.readU32();
                    if (type === 0x300) { // SDL_KEYDOWN
                        cursorTimeout.writeS32(0);
                        // The native game uses a software cursor, never the
                        // Windows hardware cursor.
                        sdlShowCursor(0);
                        return;
                    }
                    // SDL_MouseMotionEvent: xrel/yrel are signed 32-bit
                    // fields at offsets 28/32. Ignore synthetic zero-motion
                    // events; they are not a player moving the mouse.
                    if (type !== 0x400) return;
                    const xrel = this.event.add(28).readS32();
                    const yrel = this.event.add(32).readS32();
                    if (xrel !== 0 || yrel !== 0) {
                        cursorTimeout.writeS32(60);
                        sdlShowCursor(0);
                    }
                } catch (e) {
                    warn('Windows mouse-motion cursor tracking failed:', e);
                }
            }
        });

        log('Windows mouse-motion cursor wake hook installed');
    } catch (e) {
        warn('Windows mouse-motion cursor wake hook unavailable:', e);
    }
}

// In the pause menu's black “LOOT in the car” panel, team_char_loot_panel
// calls sub_47D150(name, 64) before formatting each member row.  sub_47D150
// truncates UTF-8 byte-by-byte, so it retains two Chinese characters plus part
// of a third, then the caller adds '.'.  Keep the original panel's twelve
// narrow-character capacity while making the cut on code-point boundaries:
// ASCII costs one display unit, every non-ASCII code point costs two.
function hookWindowsTeamLootNameDisplay() {
    if (Process.platform !== 'windows' || globalThis.windowsTeamLootNameDisplayHookInstalled)
        return;
    globalThis.windowsTeamLootNameDisplayHookInstalled = true;

    const module = globalThis.mainModule;
    // New EXE (JUN-20-2024.10.25): call sub_47D150 in team_char_loot_panel.
    const TEAM_LOOT_NAME_TRUNCATE_RETURN_RVA = 0xb2a4f;
    const DISPLAY_UNITS = 12;
    const logged = new Set();

    function clipToDisplayUnits(value) {
        let units = 0;
        let output = '';
        let truncated = false;
        for (const character of Array.from(value)) {
            const width = character.codePointAt(0) <= 0x7f ? 1 : 2;
            if (units + width > DISPLAY_UNITS) {
                truncated = true;
                break;
            }
            output += character;
            units += width;
        }
        return { output, truncated };
    }

    Interceptor.attach(module.base.add(0x7d150), {
        onEnter(args) {
            if (!this.returnAddress.equals(module.base.add(TEAM_LOOT_NAME_TRUNCATE_RETURN_RVA)))
                return;
            try {
                const source = args[0].readUtf8String();
                const clipped = clipToDisplayUnits(source);
                this.teamLootName = { buffer: args[0], source, ...clipped };
            } catch (e) {
                error('Windows Team loot-name read failed:', e);
            }
        },
        onLeave(retval) {
            if (!this.teamLootName) return;
            try {
                const { buffer, source, output, truncated } = this.teamLootName;
                // Restore a complete UTF-8 prefix after the native byte cutter
                // has returned.  The caller tests our value and appends its
                // normal '.' only when a real display-unit cut occurred.
                buffer.writeUtf8String(output);
                retval.replace(ptr(truncated ? 1 : 0));
                const diagnosticKey = source + '\u0000' + output + '\u0000' + truncated;
                if (!logged.has(diagnosticKey)) {
                    logged.add(diagnosticKey);
                    log('Windows Team loot-name display-unit truncation active:', source, '=>', output,
                        truncated ? '(caller appends .)' : '(complete)');
                }
            } catch (e) {
                error('Windows Team loot-name replacement failed:', e);
            }
        }
    });
    log('Windows Team loot-name display hook installed');
}

// Two PC menus assign their display label after the generic button constructor
// has already run.  Catch those assignments at their owning callbacks, rather
// than globally translating every late "empty" string (which would change
// unrelated gameplay messages).
function hookWindowsLateMenuTranslations() {
    if (Process.platform !== 'windows' || globalThis.windowsLateMenuTranslationsInstalled)
        return;
    globalThis.windowsLateMenuTranslationsInstalled = true;

    const module = globalThis.mainModule;
    const buttonTextOffset = 200;

    function replaceButtonText(button, expected) {
        if (!button || button.isNull()) return;
        const field = button.add(buttonTextOffset);
        const label = field.readPointer();
        if (label.isNull()) return;
        const text = readByteString(label);
        if (text === expected && LANG_STR[text]) field.writePointer(L(text));
    }

    // starting-buddy toggle callback: chooses "No buddy" / "With buddy" in
    // response to each layout pass.
    Interceptor.attach(module.base.add(0x59700), {
        onEnter(args) {
            this.startingBuddyButton = args[0];
            this.startingBuddyLayout = args[1].toInt32() === 5;
        },
        onLeave() {
            if (!this.startingBuddyLayout || this.startingBuddyButton.isNull()) return;
            try {
                const field = this.startingBuddyButton.add(buttonTextOffset);
                const text = readByteString(field.readPointer());
                if ((text === 'No buddy' || text === 'With buddy') && LANG_STR[text])
                    field.writePointer(L(text));
            } catch (e) {
                error('Windows starting-buddy translation failed:', e);
            }
        }
    });

    // Character-loot rows are assembled through an unlocalized format string.
    // Replace the completed buffer at the two team_char_loot_panel display
    // calls, which catches both the overall “nothing” header and every
    // individual member's “nothing” line.
    const teamLootTextReturnRvas = [0xb2951, 0xb29d7];
    Interceptor.attach(module.base.add(0x76840), {
        onEnter(args) {
            try {
                if (!teamLootTextReturnRvas.some(rva =>
                    this.returnAddress.equals(module.base.add(rva)))) return;
                const text = readByteString(args[0]);
                if (!text || !text.includes('nothing') || !LANG_STR['nothing']) return;
                args[0] = L(text.replace(/\bnothing\b/g, LANG['nothing']));
            } catch (e) {
                error('Windows team-loot row translation failed:', e);
            }
        }
    });

    // The custom-character callback writes “empty” and then immediately calls
    // sub_47AD50.  Hook that final button step, after every native overwrite,
    // rather than an earlier callback that may be superseded before drawing.
    Interceptor.attach(module.base.add(0x7ad50), {
        onEnter(args) {
            try {
                // sub_47AD50 is also reached by non-button dispatch paths.
                // Those legitimately pass a null first argument; they are not
                // empty-slot render attempts and must not produce diagnostics.
                if (args[0].isNull()) return;
                replaceButtonText(args[0], 'empty');
            } catch (e) {
                error('Windows custom-character empty-slot translation failed:', e);
            }
        }
    });

    // The new PC EXE's equipment-swap renderer does not retain the callback
    // result above: sub_4B05B0 writes its literal directly in the final UI
    // path.  Patch only that verified x86 immediate (0x4B06B2), which assigns
    // button.text = "NONE" for an unusable empty weapon slot.  This cannot
    // affect other NONE uses elsewhere in the game.
    if (LANG_STR['equipment slot none']) {
        const noneStore = module.base.add(0xb06b2);
        const expectedOpcode = [0xc7, 0x83, 0xc8, 0x00, 0x00, 0x00];
        const actualOpcode = Array.from(new Uint8Array(noneStore.readByteArray(expectedOpcode.length)));
        if (expectedOpcode.every((byte, index) => actualOpcode[index] === byte)) {
            Memory.patchCode(noneStore.add(6), 4, code =>
                code.writeU32(L('equipment slot none').toUInt32()));
            log('Windows equipment-swap NONE translation installed');
        } else {
            warn('Windows equipment-swap NONE translation skipped: unexpected instruction bytes');
        }
    }

    log('Windows late menu translation hooks installed');
}

// iOS keeps the complete in-game console renderer and command parser, but its
// mobile text-input bridge is compiled as two no-op stubs.  This UIKit overlay
// supplies the missing input surface while leaving rendering and evaluation to
// the game's original console implementation.
let iosConsoleInputField = null;
let iosConsoleInputClass = null;
let iosConsoleSurfaceClass = null;
let iosConsoleHostWindow = null;
let iosConsolePanSurface = null;
let iosConsolePreviewLabel = null;
let iosConsoleInputPreview = '';
let iosConsoleCompositionPreview = '';
let iosConsolePreviewCursor = 0;
let iosConsolePanStartY = null;
let iosConsoleOpen = false;
let iosConsoleInstallAttempts = 0;
let iosConsoleInputPumpInstalled = false;
const iosConsolePendingBytes = [];
const iosConsolePendingActions = [];
const iosConsoleHistory = [];
let iosConsoleHistoryIndex = 0;
let iosConsoleHistoryDraft = '';
let iosConsolePendingScroll = 0;
let iosConsolePendingClose = false;
let iosConsoleSuppressNativeButtonUntil = 0;
let iosConsoleWindowTouchHookInstalled = false;
let iosConsoleLastNativeUpdateAt = 0;
let iosConsoleWatchdog = null;
let iosConsoleApplicationWasInactive = false;
let iosConsoleNativeStateSeen = false;
let iosConsoleMainStateIndex = null;
const iosConsoleTouchStarts = new Map();

function getIOSConsoleNative() {
    if (globalThis.iosConsoleNative) return globalThis.iosConsoleNative;
    globalThis.iosConsoleNative = {
        open: new NativeFunction(findSymbol('main_do_console_open'), 'void', []),
        close: new NativeFunction(findSymbol('main_do_console_close'), 'void', []),
        insertChar: new NativeFunction(findSymbol('console_insert_char'), 'pointer', ['int']),
        clearInput: new NativeFunction(findSymbol('console_clear_input'), 'void', []),
        scriptDoInput: new NativeFunction(findSymbol('script_do_input'), 'int', ['pointer']),
        redrawBackspace: new NativeFunction(
            globalThis.mainModule.base.add(0x61A08), 'void', []
        ),
        appendOutput: new NativeFunction(
            globalThis.mainModule.base.add(0x61AF4), 'void', ['pointer']
        ),
        memmove: new NativeFunction(
            getGlobalExport('memmove'),
            'pointer', ['pointer', 'pointer', 'ulong']
        ),
        inputCursor: globalThis.mainModule.base.add(0x39C644),
        inputBuffer: globalThis.mainModule.base.add(0x39C648),
        scrollback: globalThis.mainModule.base.add(0x39C6F8),
        // state_current() at 0x55ac0 returns the pointer stored at 0xbd440.
        // The four callbacks in console_state begin at 0xbd738. Reading the
        // slot directly avoids requiring another gum-graft interception site.
        currentStateSlot: globalThis.mainModule.base.add(0xBD440),
        consoleState: globalThis.mainModule.base.add(0xBD738),
        // main_do_console_open/close and main_state_push/pop use these two
        // globals respectively. They cover both the explicit close request
        // and a new UI state being pushed over the console.
        popupRequest: globalThis.mainModule.base.add(0x5AF648),
        mainStateIndex: globalThis.mainModule.base.add(0x4AC7D8)
    };
    return globalThis.iosConsoleNative;
}

function sendIOSConsoleByte(value) {
    // UIKit callbacks run on the main thread while SDL may be updating on a
    // different thread. Touch only the JS queue here; the console's own update
    // function drains it on the correct game thread.
    iosConsolePendingBytes.push(value & 0xff);
}

function iosConsoleUtf8ByteLength(value) {
    if (!value) return 0;
    const utf8 = Memory.allocUtf8String(value);
    let length = 0;
    while (utf8.add(length).readU8() !== 0) length++;
    return length;
}

function trimIOSConsoleTextToAvailableBytes(value) {
    const available = 126 - iosConsoleUtf8ByteLength(iosConsoleInputPreview);
    if (!value || available <= 0) return '';
    let result = '';
    let used = 0;
    for (const character of Array.from(value.replace(/\u0000/g, ''))) {
        const bytes = iosConsoleUtf8ByteLength(character);
        if (used + bytes > available) break;
        result += character;
        used += bytes;
    }
    return result;
}

function sendIOSConsoleText(value) {
    value = trimIOSConsoleTextToAvailableBytes(value);
    if (!value) return '';
    // console_insert_char rejects each non-ASCII UTF-8 byte through
    // __maskrune before it reaches the input buffer. Preserve the committed
    // string as one queue item so the game-thread pump can insert it directly.
    if (/[^\x00-\x7f]/.test(value)) {
        iosConsolePendingBytes.push({utf8: value});
        return value;
    }
    const utf8 = Memory.allocUtf8String(value);
    for (let i = 0; ; i++) {
        const byte = utf8.add(i).readU8();
        if (byte === 0) break;
        sendIOSConsoleByte(byte);
    }
    return value;
}

function insertIOSConsoleUtf8(native, value) {
    const source = Memory.allocUtf8String(value);
    let byteLength = 0;
    while (source.add(byteLength).readU8() !== 0) byteLength++;
    if (byteLength === 0) return;

    let currentLength = 0;
    while (currentLength < 127 &&
        native.inputBuffer.add(currentLength).readU8() !== 0) currentLength++;
    const cursor = Math.max(0, Math.min(currentLength, native.inputCursor.readS32()));
    const available = 126 - currentLength;
    if (available <= 0) return;
    if (byteLength > available) {
        // Do not truncate in the middle of a multi-byte UTF-8 code point.
        let safeLength = available;
        while (safeLength > 0 &&
            (source.add(safeLength).readU8() & 0xc0) === 0x80) safeLength--;
        byteLength = safeLength;
    }
    if (byteLength <= 0) return;

    native.memmove(
        native.inputBuffer.add(cursor + byteLength),
        native.inputBuffer.add(cursor),
        currentLength - cursor + 1
    );
    Memory.copy(native.inputBuffer.add(cursor), source, byteLength);
    native.inputCursor.writeS32(cursor + byteLength);

    // Match console_insert_char's redraw path: erase the previously echoed
    // input and append the complete updated byte string once.
    for (let i = 0; i < currentLength; i++) native.redrawBackspace();
    native.appendOutput(native.inputBuffer);
}

function replaceIOSConsoleInput(native, value) {
    const source = Memory.allocUtf8String(value);
    const byteLength = Math.min(126, iosConsoleUtf8ByteLength(value));
    let oldLength = 0;
    while (oldLength < 127 &&
        native.inputBuffer.add(oldLength).readU8() !== 0) oldLength++;

    for (let i = 0; i < oldLength; i++) native.redrawBackspace();
    if (byteLength > 0)
        Memory.copy(native.inputBuffer, source, byteLength);
    native.inputBuffer.add(byteLength).writeU8(0);
    native.inputCursor.writeS32(byteLength);
    native.appendOutput(native.inputBuffer);
}

function iosConsoleCursorByteOffset() {
    const characters = Array.from(iosConsoleInputPreview);
    const before = characters.slice(0, iosConsolePreviewCursor).join('');
    return iosConsoleUtf8ByteLength(before);
}

function insertIOSConsolePreviewText(value) {
    const characters = Array.from(iosConsoleInputPreview);
    const inserted = Array.from(value);
    const cursor = Math.max(0, Math.min(characters.length, iosConsolePreviewCursor));
    characters.splice(cursor, 0, ...inserted);
    iosConsolePreviewCursor = cursor + inserted.length;
    iosConsoleInputPreview = characters.join('');
    iosConsoleHistoryIndex = iosConsoleHistory.length;
}

function moveIOSConsoleCursor(delta) {
    const length = Array.from(iosConsoleInputPreview).length;
    iosConsolePreviewCursor = Math.max(
        0,
        Math.min(length, iosConsolePreviewCursor + delta)
    );
    iosConsolePendingActions.push({
        type: 'cursor',
        byteOffset: iosConsoleCursorByteOffset()
    });
    updateIOSConsoleInputPreview();
}

function navigateIOSConsoleHistory(delta) {
    if (iosConsoleHistory.length === 0) return;
    if (delta < 0) {
        if (iosConsoleHistoryIndex === iosConsoleHistory.length)
            iosConsoleHistoryDraft = iosConsoleInputPreview;
        if (iosConsoleHistoryIndex > 0) iosConsoleHistoryIndex--;
    } else {
        if (iosConsoleHistoryIndex < iosConsoleHistory.length)
            iosConsoleHistoryIndex++;
    }

    iosConsoleInputPreview = iosConsoleHistoryIndex === iosConsoleHistory.length
        ? iosConsoleHistoryDraft
        : iosConsoleHistory[iosConsoleHistoryIndex];
    iosConsolePreviewCursor = Array.from(iosConsoleInputPreview).length;
    iosConsolePendingActions.push({
        type: 'replace',
        value: iosConsoleInputPreview
    });
    updateIOSConsoleInputPreview();
}

function updateIOSConsoleInputPreview() {
    if (!iosConsolePreviewLabel) return;
    const characters = Array.from(iosConsoleInputPreview);
    iosConsolePreviewCursor = Math.max(
        0,
        Math.min(characters.length, iosConsolePreviewCursor)
    );
    const before = characters.slice(0, iosConsolePreviewCursor).join('');
    const after = characters.slice(iosConsolePreviewCursor).join('');
    iosConsolePreviewLabel.setText_(
        `> ${before}${iosConsoleCompositionPreview}|${after}`
    );
}

function hasIOSMarkedText(field) {
    const range = field.markedTextRange();
    return !!(range && range.handle && !range.handle.isNull());
}

function callUITextFieldDeleteBackward(field) {
    if (!globalThis.uiTextFieldDeleteBackward) {
        globalThis.uiTextFieldDeleteBackward = new NativeFunction(
            ObjC.classes.UITextField['- deleteBackward'].implementation,
            'void',
            ['pointer', 'pointer']
        );
    }
    globalThis.uiTextFieldDeleteBackward(
        field.handle || field,
        ObjC.selector('deleteBackward')
    );
}

function syncIOSConsolePreviewFromNative(native = getIOSConsoleNative()) {
    let byteLength = 0;
    while (byteLength < 126 &&
        native.inputBuffer.add(byteLength).readU8() !== 0) byteLength++;
    let value = '';
    try {
        value = byteLength > 0
            ? native.inputBuffer.readUtf8String(byteLength)
            : '';
    } catch (_) {
        value = native.inputBuffer.readCString() || '';
    }
    const cursorBytes = Math.max(
        0,
        Math.min(byteLength, native.inputCursor.readS32())
    );
    let beforeCursor = '';
    try {
        beforeCursor = cursorBytes > 0
            ? native.inputBuffer.readUtf8String(cursorBytes)
            : '';
    } catch (_) {
        beforeCursor = value;
    }
    iosConsoleInputPreview = value || '';
    iosConsolePreviewCursor = Math.min(
        Array.from(iosConsoleInputPreview).length,
        Array.from(beforeCursor || '').length
    );
    iosConsoleCompositionPreview = '';
    log('iOS console preview restored from native input',
        `${byteLength} bytes`, `cursor=${cursorBytes}`);
}

function closeIOSConsoleUIKitAfterNativeExit() {
    if (!iosConsoleOpen) return;
    iosConsoleOpen = false;
    iosConsoleNativeStateSeen = false;
    iosConsoleMainStateIndex = null;
    iosConsolePendingBytes.length = 0;
    iosConsolePendingActions.length = 0;
    iosConsolePendingScroll = 0;
    iosConsolePendingClose = false;
    iosConsoleInputPreview = '';
    iosConsoleCompositionPreview = '';
    iosConsolePreviewCursor = 0;
    iosConsoleHistoryIndex = iosConsoleHistory.length;
    iosConsoleHistoryDraft = '';
    ObjC.schedule(ObjC.mainQueue, () => {
        if (!iosConsoleInputField) return;
        updateIOSConsoleInputPreview();
        iosConsoleInputField.setText_('');
        iosConsoleInputField.resignFirstResponder();
        iosConsoleInputField.setHidden_(true);
        if (iosConsolePanSurface)
            iosConsolePanSurface.setHidden_(true);
    });
    log('iOS console UIKit overlay closed after native console exit');
}

function hasIOSConsoleNativeExited(native = getIOSConsoleNative()) {
    if (!iosConsoleNativeStateSeen) return false;
    if (native.popupRequest.readS32() < 0) return true;
    if (!native.currentStateSlot.readPointer().equals(native.consoleState))
        return true;
    return iosConsoleMainStateIndex !== null &&
        native.mainStateIndex.readS32() !== iosConsoleMainStateIndex;
}

function startIOSConsoleNativeExitWatchdog() {
    if (iosConsoleWatchdog !== null) return;
    iosConsoleWatchdog = setInterval(() => {
        if (!iosConsoleOpen || iosConsoleLastNativeUpdateAt === 0) return;
        try {
            const applicationState = ObjC.classes.UIApplication
                .sharedApplication().applicationState();
            if (applicationState !== 0) {
                iosConsoleApplicationWasInactive = true;
                return;
            }
            if (iosConsoleApplicationWasInactive) {
                // Returning from Control Center, the Home screen or another
                // app can resume UIKit before the game's next native frame.
                // Reset the watchdog clock instead of mistaking that normal
                // suspension gap for a console-state transition.
                iosConsoleApplicationWasInactive = false;
                iosConsoleLastNativeUpdateAt = Date.now();
                return;
            }

            // console_update can run once more while a command is switching
            // to a dialog, map or another game state. Its timestamp alone is
            // therefore not an authoritative indication that the console is
            // still on top. Once console_update has proved that the requested
            // console state was entered, follow the game's actual current
            // state pointer and mirror any transition in UIKit immediately.
            if (iosConsoleNativeStateSeen) {
                const native = getIOSConsoleNative();
                if (hasIOSConsoleNativeExited(native)) {
                    closeIOSConsoleUIKitAfterNativeExit();
                    return;
                }
            }
        } catch (e) {
            warn('iOS console native-state watchdog failed:', e);
            return;
        }
        // While the native console is the active game state, console_update
        // runs every frame. Dialog/map/state commands stop that update loop;
        // after a generous gap, mirror the native close in UIKit without
        // issuing a second game-state mutation.
        if (Date.now() - iosConsoleLastNativeUpdateAt > 700)
            closeIOSConsoleUIKitAfterNativeExit();
    }, 250);
}

function setIOSConsoleOpen(open) {
    const native = getIOSConsoleNative();
    iosConsolePendingClose = false;
    iosConsoleTouchStarts.clear();
    iosConsolePanStartY = null;
    iosConsoleOpen = open;
    if (open) {
        iosConsoleLastNativeUpdateAt = Date.now();
        iosConsoleApplicationWasInactive = false;
        iosConsoleNativeStateSeen = false;
        iosConsoleMainStateIndex = null;
        native.open();
        syncIOSConsolePreviewFromNative(native);
        iosConsoleHistoryIndex = iosConsoleHistory.length;
        iosConsoleHistoryDraft = iosConsoleInputPreview;
        if (iosConsoleInputField) {
            ObjC.schedule(ObjC.mainQueue, () => {
                if (iosConsoleInputField && iosConsoleOpen) {
                    updateIOSConsoleInputPreview();
                    iosConsoleInputField.setHidden_(false);
                }
                if (iosConsolePanSurface && iosConsoleOpen)
                    iosConsolePanSurface.setHidden_(false);
            });
        }
        log('iOS console requested open');
    } else {
        iosConsoleNativeStateSeen = false;
        iosConsoleMainStateIndex = null;
        iosConsolePendingBytes.length = 0;
        iosConsolePendingActions.length = 0;
        iosConsolePendingScroll = 0;
        iosConsoleInputPreview = '';
        iosConsoleCompositionPreview = '';
        iosConsolePreviewCursor = 0;
        iosConsoleHistoryIndex = iosConsoleHistory.length;
        iosConsoleHistoryDraft = '';
        updateIOSConsoleInputPreview();
        if (iosConsoleInputField) {
            ObjC.schedule(ObjC.mainQueue, () => {
                if (!iosConsoleInputField) return;
                iosConsoleInputField.setText_('');
                iosConsoleInputField.resignFirstResponder();
                iosConsoleInputField.setHidden_(true);
                if (iosConsolePanSurface)
                    iosConsolePanSurface.setHidden_(true);
            });
        }
        native.close();
        log('iOS console requested close');
    }
}

function requestIOSConsoleCloseFromUIKit() {
    // UIKit gesture callbacks are not the game's update thread. Resign the
    // keyboard on UIKit now, but defer the native state mutation until the
    // console update hook runs on the game thread.
    iosConsolePendingClose = true;
    iosConsolePendingActions.length = 0;
    iosConsoleInputPreview = '';
    iosConsoleCompositionPreview = '';
    iosConsolePreviewCursor = 0;
    updateIOSConsoleInputPreview();
    if (iosConsoleInputField) {
        iosConsoleInputField.setText_('');
        iosConsoleInputField.resignFirstResponder();
        iosConsoleInputField.setHidden_(true);
    }
    if (iosConsolePanSurface)
        iosConsolePanSurface.setHidden_(true);
}

function scrollIOSConsole(delta) {
    iosConsolePendingScroll += delta;
}

function hookIOSConsoleWindowTouches() {
    if (iosConsoleWindowTouchHookInstalled) return;
    iosConsoleWindowTouchHookInstalled = true;
    const sendEvent = ObjC.classes.UIApplication['- sendEvent:'];
    if (!sendEvent) throw new Error('UIApplication sendEvent: is unavailable');

    // Retain the listener for the lifetime of the script. On this UIKit path,
    // allowing the InvocationListener wrapper to be collected also removes the
    // native callback even though attach() initially succeeded.
    globalThis.iosConsoleWindowTouchListener = Interceptor.attach(sendEvent.implementation, {
        onEnter(args) {
            if (!iosConsoleOpen || !iosConsoleInputField || !iosConsoleHostWindow) return;
            try {
                const event = new ObjC.Object(args[2]);
                const touches = event.allTouches();
                if (!touches || touches.handle.isNull()) return;
                const iterator = touches.objectEnumerator();
                let touch;
                while ((touch = iterator.nextObject()) && !touch.handle.isNull()) {
                    const phase = touch.phase();
                    const key = touch.handle.toString();
                    // Window coordinates are stable across the transparent
                    // text field and keyboard focus transitions. In DR2C's
                    // landscape orientation, a visual upward swipe increases
                    // this Y coordinate (the inverse of portrait UIKit).
                    const point = touch.locationInView_(NULL);
                    if (phase === 0) {
                        iosConsoleTouchStarts.set(key, point[1]);
                        log('iOS console raw touch began', Math.round(point[1]));
                        continue;
                    }
                    if (phase !== 3 && phase !== 4) continue;
                    const start = iosConsoleTouchStarts.get(key);
                    iosConsoleTouchStarts.delete(key);
                    if (phase === 4 || start === undefined) continue;
                    const distance = point[1] - start;
                    if (Math.abs(distance) < 16) continue;
                    const rows = 5 * Math.max(
                        1,
                        Math.min(6, Math.round(Math.abs(distance) / 50))
                    );
                    scrollIOSConsole(distance > 0 ? rows : -rows);
                    log('iOS console raw scroll', distance > 0 ? 'up' : 'down', rows);
                }
            } catch (e) {
                error('iOS console raw touch tracking failed:', e);
            }
        }
    });
    log('iOS console raw application touch tracking installed');
}

function hookIOSConsoleInputPump() {
    if (iosConsoleInputPumpInstalled) return;
    iosConsoleInputPumpInstalled = true;
    Interceptor.attach(findSymbol('console_update'), {
        onEnter() {
            try {
                iosConsoleLastNativeUpdateAt = Date.now();
                const native = getIOSConsoleNative();
                if (!iosConsoleNativeStateSeen) {
                    iosConsoleNativeStateSeen = true;
                    iosConsoleMainStateIndex = native.mainStateIndex.readS32();
                    log('iOS console native state entered',
                        `stack=${iosConsoleMainStateIndex}`);
                } else if (iosConsoleOpen && hasIOSConsoleNativeExited(native)) {
                    closeIOSConsoleUIKitAfterNativeExit();
                    return;
                }
                if (iosConsolePendingClose) {
                    iosConsolePendingClose = false;
                    iosConsoleOpen = false;
                    iosConsolePendingBytes.length = 0;
                    iosConsolePendingScroll = 0;
                    native.close();
                    log('iOS console requested close from native hit target');
                    return;
                }
                if (iosConsolePendingActions.length !== 0) {
                    const actions = iosConsolePendingActions.splice(0, 64);
                    for (const action of actions) {
                        if (action.type === 'replace') {
                            replaceIOSConsoleInput(native, action.value);
                        } else if (action.type === 'cursor') {
                            const currentLength = iosConsoleUtf8ByteLength(
                                iosConsoleInputPreview
                            );
                            native.inputCursor.writeS32(Math.max(
                                0,
                                Math.min(currentLength, action.byteOffset)
                            ));
                        }
                    }
                }
                if (iosConsolePendingScroll !== 0) {
                    const old = native.scrollback.readS32();
                    const next = Math.max(
                        0,
                        old + iosConsolePendingScroll
                    );
                    native.scrollback.writeS32(next);
                    log('iOS console scrollback applied', `${old} -> ${next}`);
                    iosConsolePendingScroll = 0;
                }

                if (iosConsolePendingBytes.length === 0) return;
                const pending = iosConsolePendingBytes.splice(0, 256);
                for (const item of pending) {
                    if (typeof item === 'object') {
                        insertIOSConsoleUtf8(native, item.utf8);
                        continue;
                    }
                    const command = native.insertChar(item);
                    if (!command.isNull()) {
                        native.scriptDoInput(command);
                        native.clearInput();
                        if (iosConsoleOpen && hasIOSConsoleNativeExited(native)) {
                            closeIOSConsoleUIKitAfterNativeExit();
                            return;
                        }
                    }
                }
            } catch (e) {
                error('iOS console game-thread input pump failed:', e);
            }
        },
        onLeave() {
            try {
                if (iosConsoleOpen &&
                    hasIOSConsoleNativeExited(getIOSConsoleNative()))
                    closeIOSConsoleUIKitAfterNativeExit();
            } catch (e) {
                error('iOS console native-exit sync failed:', e);
            }
        }
    });
    log('iOS console game-thread input pump installed');
}

function getIOSConsoleInputClass() {
    if (iosConsoleInputClass) return iosConsoleInputClass;
    const className = `DR2CIOSConsoleInput_${Process.id}_${Date.now()}`;
    iosConsoleInputClass = ObjC.registerClass({
        name: className,
        super: ObjC.classes.UITextField,
        protocols: [ObjC.protocols.UITextFieldDelegate],
        methods: {
            '- dr2cConsoleEditingChanged:': {
                retType: 'void',
                argTypes: ['object'],
                implementation(field) {
                    try {
                        const value = field.text().toString();
                        if (hasIOSMarkedText(field)) {
                            // Pinyin and other multi-stage IMEs keep their
                            // uncommitted composition in markedTextRange.
                            // Clearing it here removes the candidate bar.
                            iosConsoleCompositionPreview = value;
                            updateIOSConsoleInputPreview();
                            return;
                        }
                        iosConsoleCompositionPreview = '';
                        if (value) {
                            const accepted = sendIOSConsoleText(value);
                            if (accepted) {
                                insertIOSConsolePreviewText(accepted);
                                updateIOSConsoleInputPreview();
                            }
                        }
                        field.setText_('');
                    } catch (e) {
                        error('iOS console text input failed:', e);
                    }
                }
            },
            '- deleteBackward': {
                retType: 'void',
                argTypes: [],
                implementation() {
                    try {
                        const field = iosConsoleInputField;
                        if (!field) return;
                        const composing = hasIOSMarkedText(field);
                        const hadStagedText = field.text().length() > 0;
                        callUITextFieldDeleteBackward(field);
                        if (!composing && !hadStagedText) {
                            const characters = Array.from(iosConsoleInputPreview);
                            const cursor = Math.max(
                                0,
                                Math.min(characters.length, iosConsolePreviewCursor)
                            );
                            const removed = cursor > 0
                                ? characters.splice(cursor - 1, 1)[0]
                                : '';
                            if (!removed) return;
                            const utf8 = Memory.allocUtf8String(removed);
                            let byteCount = 0;
                            while (utf8.add(byteCount).readU8() !== 0) byteCount++;
                            for (let i = 0; i < Math.max(1, byteCount); i++)
                                sendIOSConsoleByte(8);
                            iosConsoleInputPreview = characters.join('');
                            iosConsolePreviewCursor = cursor - 1;
                            iosConsoleHistoryIndex = iosConsoleHistory.length;
                            updateIOSConsoleInputPreview();
                        }
                    } catch (e) {
                        error('iOS console backspace failed:', e);
                    }
                }
            },
            '- textFieldShouldReturn:': {
                retType: 'bool',
                argTypes: ['object'],
                implementation(field) {
                    try {
                        const command = iosConsoleInputPreview;
                        if (command &&
                            iosConsoleHistory[iosConsoleHistory.length - 1] !== command) {
                            iosConsoleHistory.push(command);
                            if (iosConsoleHistory.length > 100)
                                iosConsoleHistory.shift();
                        }
                        sendIOSConsoleByte(13);
                        iosConsoleInputPreview = '';
                        iosConsoleCompositionPreview = '';
                        iosConsolePreviewCursor = 0;
                        iosConsoleHistoryIndex = iosConsoleHistory.length;
                        iosConsoleHistoryDraft = '';
                        updateIOSConsoleInputPreview();
                        field.setText_('');
                        field.resignFirstResponder();
                    } catch (e) {
                        error('iOS console command submit failed:', e);
                    }
                    return true;
                }
            },
            '- dr2cConsoleDismissKeyboard:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    if (iosConsoleInputField)
                        iosConsoleInputField.resignFirstResponder();
                }
            },
            '- dr2cConsolePaste:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    try {
                        if (!iosConsoleOpen) return;
                        const field = iosConsoleInputField;
                        const Pasteboard = ObjC.classes.UIPasteboard;
                        if (!field || !Pasteboard) return;
                        field.becomeFirstResponder();
                        const clipboard = Pasteboard.generalPasteboard().string();
                        if (!clipboard || clipboard.handle.isNull()) return;
                        const accepted = sendIOSConsoleText(clipboard.toString());
                        if (!accepted) return;
                        insertIOSConsolePreviewText(accepted);
                        updateIOSConsoleInputPreview();
                        log('iOS console clipboard text queued',
                            `${iosConsoleUtf8ByteLength(accepted)} bytes`);
                    } catch (e) {
                        error('iOS console paste failed:', e);
                    }
                }
            },
            '- dr2cConsoleHistoryUp:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    if (iosConsoleOpen) navigateIOSConsoleHistory(-1);
                }
            },
            '- dr2cConsoleHistoryDown:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    if (iosConsoleOpen) navigateIOSConsoleHistory(1);
                }
            },
            '- dr2cConsoleCursorLeft:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    if (iosConsoleOpen) moveIOSConsoleCursor(-1);
                }
            },
            '- dr2cConsoleCursorRight:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    if (iosConsoleOpen) moveIOSConsoleCursor(1);
                }
            },
            '- dr2cConsoleTap:': {
                retType: 'void',
                argTypes: ['object'],
                implementation(recognizer) {
                    if (!iosConsoleOpen) return;
                    // This selector is dispatched by UIKit on its main thread,
                    // which is the safe place to explicitly request keyboard
                    // focus. A full-screen custom UITextField does not always
                    // adopt first-responder status from its default touch path.
                    if (iosConsoleInputField)
                        iosConsoleInputField.becomeFirstResponder();
                }
            },
            '- dr2cConsolePan:': {
                retType: 'void',
                argTypes: ['object'],
                implementation(recognizer) {
                    try {
                        if (!iosConsoleOpen) return;
                        const state = recognizer.state();
                        const point = recognizer.locationInView_(iosConsoleInputField);
                        if (state === 1) { // UIGestureRecognizerStateBegan
                            iosConsolePanStartY = point[1];
                            log('iOS console pan began', Math.round(point[1]));
                            return;
                        }
                        if (state !== 3 && state !== 4) return;
                        const start = iosConsolePanStartY;
                        iosConsolePanStartY = null;
                        if (state === 4 || start === null) return;
                        const distance = point[1] - start;
                        if (Math.abs(distance) < 16) return;
                        const rows = 5 * Math.max(
                            1,
                            Math.min(6, Math.round(Math.abs(distance) / 50))
                        );
                        // DR2C runs landscape with the UIKit Y axis inverted
                        // relative to the physical swipe direction observed on
                        // this view: visual upward motion increases Y.
                        scrollIOSConsole(distance > 0 ? rows : -rows);
                        log('iOS console pan scroll',
                            distance > 0 ? 'up' : 'down', rows);
                    } catch (e) {
                        error('iOS console pan failed:', e);
                    }
                }
            }
        }
    });
    return iosConsoleInputClass;
}

function getIOSConsoleSurfaceClass() {
    if (iosConsoleSurfaceClass) return iosConsoleSurfaceClass;
    const className = `DR2CIOSConsoleSurface_${Process.id}_${Date.now()}`;
    iosConsoleSurfaceClass = ObjC.registerClass({
        name: className,
        super: ObjC.classes.UIView,
        methods: {
            '- touchesBegan:withEvent:': {
                retType: 'void',
                argTypes: ['object', 'object'],
                implementation(touches) {
                    try {
                        if (!iosConsoleOpen || !iosConsoleInputField) return;
                        const touch = touches.anyObject();
                        const point = touch.locationInView_(iosConsoleInputField);
                        iosConsolePanStartY = point[1];
                        log('iOS console direct touch began', Math.round(point[1]));
                    } catch (e) {
                        error('iOS console direct touch begin failed:', e);
                    }
                }
            },
            '- touchesEnded:withEvent:': {
                retType: 'void',
                argTypes: ['object', 'object'],
                implementation(touches) {
                    try {
                        if (!iosConsoleOpen || !iosConsoleInputField) return;
                        const touch = touches.anyObject();
                        const point = touch.locationInView_(iosConsoleInputField);
                        const start = iosConsolePanStartY;
                        iosConsolePanStartY = null;
                        if (start === null) return;
                        const distance = point[1] - start;
                        if (Math.abs(distance) < 16) {
                            const size = iosConsoleInputField.bounds()[1];
                            const box = globalThis.iosConsoleButtonNormalizedHitBox;
                            const x = point[0] / size[0];
                            const y = point[1] / size[1];
                            if (box && x >= box.left && x <= box.right &&
                                y >= box.top && y <= box.bottom) {
                                // Prevent the same physical touch from closing
                                // through UIKit and then reopening through the
                                // SDL/native button callback later in the frame.
                                iosConsoleSuppressNativeButtonUntil = Date.now() + 600;
                                requestIOSConsoleCloseFromUIKit();
                                return;
                            }
                            iosConsoleInputField.becomeFirstResponder();
                            return;
                        }
                        const rows = 5 * Math.max(
                            1,
                            Math.min(6, Math.round(Math.abs(distance) / 50))
                        );
                        scrollIOSConsole(distance > 0 ? rows : -rows);
                        log('iOS console direct touch scroll',
                            distance > 0 ? 'up' : 'down', rows);
                    } catch (e) {
                        error('iOS console direct touch end failed:', e);
                    }
                }
            },
            '- touchesCancelled:withEvent:': {
                retType: 'void',
                argTypes: ['object', 'object'],
                implementation() {
                    iosConsolePanStartY = null;
                }
            }
        }
    });
    return iosConsoleSurfaceClass;
}

function installIOSConsoleOverlay() {
    if (Process.platform !== 'darwin' || !ObjC.available || iosConsoleInputField) return;
    ObjC.schedule(ObjC.mainQueue, () => {
        try {
            const application = ObjC.classes.UIApplication.sharedApplication();
            let window = application.keyWindow();
            if (!window && application.windows().count() > 0)
                window = application.windows().objectAtIndex_(0);
            if (!window) throw new Error('No application window');

            // Touching a full-screen overlay reveals iOS's landscape Home
            // Indicator as a thin grey line at the extreme right edge. DR2C's
            // own root controller implements this policy, so override only
            // that method and request an immediate system UI refresh.
            if (!globalThis.iosConsoleHomeIndicatorHookInstalled) {
                const autoHide = ObjC.classes.ViewController &&
                    ObjC.classes.ViewController['- prefersHomeIndicatorAutoHidden'];
                if (autoHide) {
                    globalThis.iosConsoleHomeIndicatorAutoHide = new NativeCallback(
                        () => 1,
                        'bool',
                        ['pointer', 'pointer']
                    );
                    // In autonomous mode this app method is not itself a
                    // gum-graft target. Replacing its code bytes would fail
                    // under code_signing=required; updating the Objective-C
                    // method table instead leaves the signed Mach-O intact.
                    const classReplaceMethod = new NativeFunction(
                        getGlobalExport('class_replaceMethod'),
                        'pointer',
                        ['pointer', 'pointer', 'pointer', 'pointer']
                    );
                    classReplaceMethod(
                        ObjC.classes.ViewController.handle,
                        ObjC.selector('prefersHomeIndicatorAutoHidden'),
                        globalThis.iosConsoleHomeIndicatorAutoHide,
                        Memory.allocUtf8String('B@:')
                    );
                    globalThis.iosConsoleHomeIndicatorHookInstalled = true;
                }
            }

            const controller = window.rootViewController();
            if (!controller) throw new Error('No root view controller');
            if (controller.respondsToSelector_(
                ObjC.selector('setNeedsUpdateOfHomeIndicatorAutoHidden')
            )) controller.setNeedsUpdateOfHomeIndicatorAutoHidden();
            const view = controller.view();
            if (!view) throw new Error('No root view');

            const InputClass = getIOSConsoleInputClass();
            const field = InputClass.alloc().initWithFrame_(view.bounds());
            field.setDelegate_(field);
            field.setAutoresizingMask_(18); // flexible width + height
            field.setBackgroundColor_(ObjC.classes.UIColor.clearColor());
            field.setTextColor_(ObjC.classes.UIColor.clearColor());
            field.setTintColor_(ObjC.classes.UIColor.clearColor());
            field.setBorderStyle_(0);
            // UIKeyboardTypeDefault is required for Chinese Pinyin and other
            // marked-text input methods. The previous ASCIICapable value
            // explicitly removed those keyboards and their candidate bar.
            field.setAutocorrectionType_(0);
            field.setSpellCheckingType_(0);
            field.setKeyboardType_(0); // UIKeyboardTypeDefault
            field.setReturnKeyType_(9); // UIReturnKeyDone
            field.setEnablesReturnKeyAutomatically_(false);
            field.addTarget_action_forControlEvents_(
                field,
                ObjC.selector('dr2cConsoleEditingChanged:'),
                131072 // UIControlEventEditingChanged
            );

            const tap = ObjC.classes.UITapGestureRecognizer.alloc()
                .initWithTarget_action_(field, ObjC.selector('dr2cConsoleTap:'));
            tap.setCancelsTouchesInView_(false);
            field.addGestureRecognizer_(tap);

            // An explicit keyboard-only dismiss control. Unlike Done, this
            // button does not submit or alter the current console command.
            const keyboardBar = ObjC.classes.UIToolbar.alloc()
                .initWithFrame_([[0, 0], [view.bounds()[1][0], 38]]);
            const previewLabel = ObjC.classes.UILabel.alloc()
                .initWithFrame_([[0, 0], [Math.max(160, view.bounds()[1][0] - 300), 38]]);
            previewLabel.setTextColor_(ObjC.classes.UIColor.labelColor());
            previewLabel.setFont_(ObjC.classes.UIFont.fontWithName_size_('Menlo', 14));
            previewLabel.setNumberOfLines_(1);
            previewLabel.setLineBreakMode_(4); // NSLineBreakByTruncatingHead
            previewLabel.setAccessibilityLabel_('控制台当前输入');
            const previewItem = ObjC.classes.UIBarButtonItem.alloc()
                .initWithCustomView_(previewLabel);
            const flexible = ObjC.classes.UIBarButtonItem.alloc()
                .initWithBarButtonSystemItem_target_action_(5, NULL, NULL);
            const makeKeyboardItem = (title, selector, accessibilityLabel) => {
                const item = ObjC.classes.UIBarButtonItem.alloc()
                    .initWithTitle_style_target_action_(
                        title,
                        0,
                        field,
                        ObjC.selector(selector)
                    );
                item.setAccessibilityLabel_(accessibilityLabel);
                return item;
            };
            const pasteItem = makeKeyboardItem(
                'Paste', 'dr2cConsolePaste:', '粘贴控制台命令'
            );
            const historyUp = makeKeyboardItem(
                '↑', 'dr2cConsoleHistoryUp:', '上一条历史命令'
            );
            const historyDown = makeKeyboardItem(
                '↓', 'dr2cConsoleHistoryDown:', '下一条历史命令'
            );
            const cursorLeft = makeKeyboardItem(
                '←', 'dr2cConsoleCursorLeft:', '光标左移'
            );
            const cursorRight = makeKeyboardItem(
                '→', 'dr2cConsoleCursorRight:', '光标右移'
            );
            const dismissKeyboard = ObjC.classes.UIBarButtonItem.alloc()
                .initWithTitle_style_target_action_(
                    '⌄',
                    0,
                    field,
                    ObjC.selector('dr2cConsoleDismissKeyboard:')
                );
            dismissKeyboard.setAccessibilityLabel_('收起键盘');
            const keyboardItems = ObjC.classes.NSMutableArray.array();
            keyboardItems.addObject_(previewItem);
            keyboardItems.addObject_(flexible);
            keyboardItems.addObject_(pasteItem);
            keyboardItems.addObject_(historyUp);
            keyboardItems.addObject_(historyDown);
            keyboardItems.addObject_(cursorLeft);
            keyboardItems.addObject_(cursorRight);
            keyboardItems.addObject_(dismissKeyboard);
            keyboardBar.setItems_(keyboardItems);
            field.setInputAccessoryView_(keyboardBar);
            field.setHidden_(true);

            view.addSubview_(field);
            // UITextField installs many private text-selection and drag
            // recognizers that win against a custom one-finger pan. Use a
            // plain full-screen transparent view above it so dragging has no
            // recognizer competition. Taps on this view still focus the field.
            const SurfaceClass = getIOSConsoleSurfaceClass();
            const panSurface = SurfaceClass.alloc().initWithFrame_(view.bounds());
            panSurface.setAutoresizingMask_(18); // flexible width + height
            panSurface.setBackgroundColor_(ObjC.classes.UIColor.clearColor());
            panSurface.setUserInteractionEnabled_(true);
            panSurface.setHidden_(true);
            view.addSubview_(panSurface);
            iosConsoleInputField = field;
            iosConsoleHostWindow = window;
            iosConsolePanSurface = panSurface;
            iosConsolePreviewLabel = previewLabel;
            globalThis.iosConsoleTouchSurface = panSurface;
            startIOSConsoleNativeExitWatchdog();
            updateIOSConsoleInputPreview();
            log('iOS console keyboard and gesture bridge installed');
        } catch (e) {
            iosConsoleInstallAttempts++;
            if (iosConsoleInstallAttempts < 20) {
                setTimeout(installIOSConsoleOverlay, 500);
            } else {
                error('iOS console overlay install failed:', e);
            }
        }
    });
}

// DR2C's EAGLView implements only UIKeyInput. That is enough for direct Latin
// key presses, but not for Chinese Pinyin: iOS needs a full UITextInput object
// to own marked text and present candidates. In addition, EAGLView's original
// insertText: forwards only the first UTF-8 byte. Use a transparent UITextField
// as the system IME client and relay each committed UTF-8 byte to the game's
// existing keyboard callback.
let iosGameTextInputField = null;
let iosGameTextInputClass = null;
let iosGameTextInputTarget = null;
let iosGameTextInputInstallAttempts = 0;
let iosGameTextInputOpen = false;
const iosGamePendingEdits = [];
const IOS_GAME_TEXT_BUFFER_BYTES = 40;
// Several team/map render paths copy at most 19 bytes, including the trailing
// NUL. Keep custom names within 18 UTF-8 bytes: up to six CJK characters or
// up to eighteen ASCII characters, with mixed names naturally sharing the
// same structural budget.
const IOS_CUSTOM_NAME_MAX_UTF8_BYTES = 18;

function getIOSGameKeyboardCallbackOffset() {
    if (globalThis.iosGameKeyboardCallbackOffset !== undefined)
        return globalThis.iosGameKeyboardCallbackOffset;

    let offset = 2400; // verified EAGLView layout fallback for this iOS build
    try {
        const classGetInstanceVariable = new NativeFunction(
            getGlobalExport('class_getInstanceVariable'),
            'pointer', ['pointer', 'pointer']
        );
        const ivarGetOffset = new NativeFunction(
            getGlobalExport('ivar_getOffset'),
            'int64', ['pointer']
        );
        let ivar = classGetInstanceVariable(
            ObjC.classes.EAGLView.handle,
            Memory.allocUtf8String('keyboard_callback')
        );
        if (ivar.isNull()) {
            ivar = classGetInstanceVariable(
                ObjC.classes.EAGLView.handle,
                Memory.allocUtf8String('_keyboard_callback')
            );
        }
        if (!ivar.isNull()) {
            const runtimeOffset = ivarGetOffset(ivar);
            offset = runtimeOffset.toNumber
                ? runtimeOffset.toNumber()
                : Number(runtimeOffset);
        }
    } catch (e) {
        warn('Unable to resolve EAGLView keyboard callback ivar; using verified offset', e);
    }
    globalThis.iosGameKeyboardCallbackOffset = offset;
    return offset;
}

function getIOSGameKeyboardCallback() {
    if (!iosGameTextInputTarget) return null;
    const callbackPointer = iosGameTextInputTarget.handle
        .add(getIOSGameKeyboardCallbackOffset())
        .readPointer();
    if (callbackPointer.isNull()) return null;
    const key = callbackPointer.toString();
    if (!globalThis.iosGameKeyboardCallbacks)
        globalThis.iosGameKeyboardCallbacks = {};
    if (!globalThis.iosGameKeyboardCallbacks[key]) {
        globalThis.iosGameKeyboardCallbacks[key] = new NativeFunction(
            callbackPointer,
            'void',
            ['int', 'int']
        );
    }
    return globalThis.iosGameKeyboardCallbacks[key];
}

function sendIOSGameKeyboardByte(value, action = 0) {
    const callback = getIOSGameKeyboardCallback();
    if (!callback) {
        warn('iOS game keyboard callback is unavailable');
        return;
    }
    // The original insertText: uses ldrsb, so preserve its signed-char ABI.
    const signed = value > 127 ? value - 256 : value;
    callback(signed, action);
}

function sendIOSGameKeyboardText(value) {
    if (!value) return;
    // The game's generic string editor applies __maskrune separately to each
    // byte and turns a committed Chinese character into "???". Queue the
    // complete string for insertion by the game-thread buffer hook instead.
    iosGamePendingEdits.push({utf8: value});
}

function readIOSGameTextBuffer(buffer) {
    let byteLength = 0;
    while (byteLength < IOS_GAME_TEXT_BUFFER_BYTES &&
        buffer.add(byteLength).readU8() !== 0) byteLength++;
    return {
        byteLength,
        value: byteLength === 0 ? '' : buffer.readUtf8String(byteLength)
    };
}

function truncateIOSCustomNameToByteLimit(value, maximumBytes) {
    let result = '';
    let byteLength = 0;
    for (const character of Array.from(value)) {
        const codePoint = character.codePointAt(0);
        const characterBytes = codePoint <= 0x7f ? 1
            : codePoint <= 0x7ff ? 2
                : codePoint <= 0xffff ? 3 : 4;
        if (byteLength + characterBytes > maximumBytes) break;
        result += character;
        byteLength += characterBytes;
    }
    return result;
}

function clampIOSCustomName(buffer, cursorPointer) {
    const current = readIOSGameTextBuffer(buffer);
    if (current.byteLength <= IOS_CUSTOM_NAME_MAX_UTF8_BYTES) return false;

    const limited = truncateIOSCustomNameToByteLimit(
        current.value,
        IOS_CUSTOM_NAME_MAX_UTF8_BYTES
    );
    const source = Memory.allocUtf8String(limited);
    let byteLength = 0;
    while (source.add(byteLength).readU8() !== 0) byteLength++;
    Memory.copy(buffer, source, byteLength + 1);
    cursorPointer.writeS32(Math.min(cursorPointer.readS32(), byteLength));
    return true;
}

function applyIOSGameTextInsertion(buffer, cursorPointer, value) {
    const current = readIOSGameTextBuffer(buffer);
    const currentLength = current.byteLength;
    const cursor = Math.max(
        0,
        Math.min(currentLength, cursorPointer.readS32())
    );
    const remainingBytes = IOS_CUSTOM_NAME_MAX_UTF8_BYTES - currentLength;
    if (remainingBytes <= 0) return;

    const limitedValue = truncateIOSCustomNameToByteLimit(
        value,
        remainingBytes
    );
    if (!limitedValue) return;

    const available = IOS_GAME_TEXT_BUFFER_BYTES - currentLength;
    if (available <= 0) return;

    const source = Memory.allocUtf8String(limitedValue);
    let byteLength = 0;
    while (source.add(byteLength).readU8() !== 0) byteLength++;
    if (byteLength > available) {
        let safeLength = available;
        while (safeLength > 0 &&
            (source.add(safeLength).readU8() & 0xc0) === 0x80) safeLength--;
        byteLength = safeLength;
    }
    if (byteLength <= 0) return;

    const memmove = globalThis.iosGameTextMemmove;
    memmove(
        buffer.add(cursor + byteLength),
        buffer.add(cursor),
        currentLength - cursor + 1
    );
    Memory.copy(buffer.add(cursor), source, byteLength);
    cursorPointer.writeS32(cursor + byteLength);
}

function applyIOSGameTextDeletion(buffer, cursorPointer) {
    let currentLength = 0;
    while (currentLength < IOS_GAME_TEXT_BUFFER_BYTES &&
        buffer.add(currentLength).readU8() !== 0) currentLength++;
    const cursor = Math.max(
        0,
        Math.min(currentLength, cursorPointer.readS32())
    );
    if (cursor === 0) return;

    // Find the leading byte of the previous UTF-8 code point so one Backspace
    // removes one Chinese character instead of only its final continuation
    // byte. This also behaves identically to the original editor for ASCII.
    let start = cursor - 1;
    while (start > 0 && (buffer.add(start).readU8() & 0xc0) === 0x80)
        start--;
    globalThis.iosGameTextMemmove(
        buffer.add(start),
        buffer.add(cursor),
        currentLength - cursor + 1
    );
    cursorPointer.writeS32(start);
}

function drainIOSGameTextEdits(buffer, cursorPointer) {
    if (!iosGameTextInputOpen) return;
    const clamped = clampIOSCustomName(buffer, cursorPointer);
    if (iosGamePendingEdits.length === 0) {
        if (clamped)
            log('iOS overlong custom name repaired:', buffer.readCString());
        return;
    }
    const edits = iosGamePendingEdits.splice(0, 64);
    for (const edit of edits) {
        if (edit.delete) applyIOSGameTextDeletion(buffer, cursorPointer);
        else applyIOSGameTextInsertion(buffer, cursorPointer, edit.utf8);
    }
    log('iOS game text buffer updated:', buffer.readCString());
}

function getIOSGameTextInputClass() {
    if (iosGameTextInputClass) return iosGameTextInputClass;
    const className = `DR2CIOSGameTextInput_${Process.id}_${Date.now()}`;
    iosGameTextInputClass = ObjC.registerClass({
        name: className,
        super: ObjC.classes.UITextField,
        protocols: [ObjC.protocols.UITextFieldDelegate],
        methods: {
            '- dr2cGameTextEditingChanged:': {
                retType: 'void',
                argTypes: ['object'],
                implementation(field) {
                    try {
                        // Keep Pinyin inside UITextField until the user chooses
                        // a candidate. Only the resulting committed NSString is
                        // forwarded to the byte-oriented game callback.
                        if (hasIOSMarkedText(field)) return;
                        const value = field.text().toString();
                        if (value) sendIOSGameKeyboardText(value);
                        field.setText_('');
                    } catch (e) {
                        error('iOS game text input failed:', e);
                    }
                }
            },
            '- deleteBackward': {
                retType: 'void',
                argTypes: [],
                implementation() {
                    try {
                        const field = iosGameTextInputField;
                        if (!field) return;
                        const composing = hasIOSMarkedText(field);
                        const hadStagedText = field.text().length() > 0;
                        callUITextFieldDeleteBackward(field);
                        if (!composing && !hadStagedText)
                            iosGamePendingEdits.push({delete: true});
                    } catch (e) {
                        error('iOS game text backspace failed:', e);
                    }
                }
            },
            '- textFieldShouldReturn:': {
                retType: 'bool',
                argTypes: ['object'],
                implementation(field) {
                    try {
                        // EAGLView's original insertText: receives LF when the
                        // system Return/Done key is pressed.
                        sendIOSGameKeyboardByte(10, 0);
                        field.setText_('');
                    } catch (e) {
                        error('iOS game text Return failed:', e);
                    }
                    return true;
                }
            }
        }
    });
    return iosGameTextInputClass;
}

function installIOSGameTextInputBridge() {
    if (Process.platform !== 'darwin' || !ObjC.available || iosGameTextInputField) return;
    ObjC.schedule(ObjC.mainQueue, () => {
        try {
            const application = ObjC.classes.UIApplication.sharedApplication();
            let window = application.keyWindow();
            if (!window && application.windows().count() > 0)
                window = application.windows().objectAtIndex_(0);
            if (!window) throw new Error('No application window');
            const controller = window.rootViewController();
            if (!controller) throw new Error('No root view controller');
            const view = controller.view();
            if (!view) throw new Error('No root view');

            const InputClass = getIOSGameTextInputClass();
            const field = InputClass.alloc().initWithFrame_([[0, 0], [1, 1]]);
            field.setDelegate_(field);
            field.setBackgroundColor_(ObjC.classes.UIColor.clearColor());
            field.setTextColor_(ObjC.classes.UIColor.clearColor());
            field.setTintColor_(ObjC.classes.UIColor.clearColor());
            field.setBorderStyle_(0);
            field.setKeyboardType_(0); // UIKeyboardTypeDefault, including Pinyin
            field.setAutocorrectionType_(0);
            field.setSpellCheckingType_(0);
            field.setReturnKeyType_(9); // UIReturnKeyDone
            field.setEnablesReturnKeyAutomatically_(false);
            field.addTarget_action_forControlEvents_(
                field,
                ObjC.selector('dr2cGameTextEditingChanged:'),
                131072 // UIControlEventEditingChanged
            );
            view.addSubview_(field);
            view.sendSubviewToBack_(field);
            iosGameTextInputField = field;

            globalThis.iosGameTextMemmove = new NativeFunction(
                getGlobalExport('memmove'),
                'pointer', ['pointer', 'pointer', 'ulong']
            );
            // iOS 1.32's generic editable-string handler receives the active
            // name buffer and cursor pointer every frame while the keyboard is
            // open. Drain UIKit edits here so all game-state mutation stays on
            // the game's own thread.
            globalThis.iosGameTextBufferHook = Interceptor.attach(
                globalThis.mainModule.base.add(0x81F34),
                {
                    onEnter(args) {
                        try {
                            if (!args[1].isNull() && !args[2].isNull())
                                drainIOSGameTextEdits(args[1], args[2]);
                        } catch (e) {
                            error('iOS game text buffer update failed:', e);
                        }
                    }
                }
            );

            const classReplaceMethod = new NativeFunction(
                getGlobalExport('class_replaceMethod'),
                'pointer',
                ['pointer', 'pointer', 'pointer', 'pointer']
            );
            globalThis.iosGameBecomeFirstResponder = new NativeCallback(
                (self) => {
                    try {
                        iosGameTextInputTarget = new ObjC.Object(self);
                        iosGameTextInputOpen = true;
                        iosGamePendingEdits.length = 0;
                        ObjC.schedule(ObjC.mainQueue, () => {
                            if (!iosGameTextInputField) return;
                            iosGameTextInputField.setText_('');
                            iosGameTextInputField.becomeFirstResponder();
                        });
                        log('iOS game text input requested open');
                    } catch (e) {
                        error('iOS game text input open failed:', e);
                    }
                    return 1;
                },
                'bool',
                ['pointer', 'pointer']
            );
            globalThis.iosGameResignFirstResponder = new NativeCallback(
                () => {
                    try {
                        iosGameTextInputOpen = false;
                        iosGamePendingEdits.length = 0;
                        ObjC.schedule(ObjC.mainQueue, () => {
                            if (!iosGameTextInputField) return;
                            iosGameTextInputField.setText_('');
                            iosGameTextInputField.resignFirstResponder();
                        });
                        log('iOS game text input requested close');
                    } catch (e) {
                        error('iOS game text input close failed:', e);
                    }
                    return 1;
                },
                'bool',
                ['pointer', 'pointer']
            );
            const methodTypes = Memory.allocUtf8String('B@:');
            classReplaceMethod(
                ObjC.classes.EAGLView.handle,
                ObjC.selector('becomeFirstResponder'),
                globalThis.iosGameBecomeFirstResponder,
                methodTypes
            );
            classReplaceMethod(
                ObjC.classes.EAGLView.handle,
                ObjC.selector('resignFirstResponder'),
                globalThis.iosGameResignFirstResponder,
                methodTypes
            );
            log('iOS Chinese game text input bridge installed');
        } catch (e) {
            iosGameTextInputInstallAttempts++;
            if (iosGameTextInputInstallAttempts < 20) {
                setTimeout(installIOSGameTextInputBridge, 500);
            } else {
                error('iOS game text input bridge install failed:', e);
            }
        }
    });
}

// Android ships the same native console and byte-oriented name editor as the
// desktop/iOS builds, but its Java activity never supplies a Unicode-aware
// input client for either one.  Keep every native mutation on the game's
// update thread and use ordinary Android EditText controls only as IME clients.
// This is intentionally Android-only: neither the iOS UIKit bridge nor the
// Windows SDL/IMM bridge passes through any of the code below.
let androidTextBridgeInstalled = false;
let androidConsoleRoot = null;
let androidConsoleField = null;
let androidConsoleToolbar = null;
let androidConsoleSurface = null;
let androidConsoleWindowManager = null;
let androidConsoleWindowParams = null;
let androidConsoleToolbarAttached = false;
let androidConsolePopup = null;
let androidConsolePopupY = -1;
let androidConsoleKeyboardWasVisible = false;
let androidNameField = null;
let androidConsoleVisible = false;
let androidConsoleKeyboardDismissed = false;
let androidConsoleTouchStartY = null;
let androidConsoleTouchStartX = null;
let androidConsoleUiSyncing = false;
let androidNameUiSyncing = false;
let androidActiveNameEditor = NULL;
let androidLastNameEditor = NULL;
let androidConsoleHistoryIndex = 0;
let androidConsoleHistoryDraft = '';
let androidConsolePreviewRendered = null;
let androidConsolePreviewRenderedSelection = -1;
const androidConsoleHistory = [];
const androidConsoleActions = [];
const androidNameActions = [];
const ANDROID_CONSOLE_MAX_UTF8_BYTES = 126;
const ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES = 18;
const ANDROID_CUSTOM_NAME_FIELD_WIDTH = 144;

function androidJavaText(value) {
    if (value === null || value === undefined) return '';
    try {
        // Frida already converts the result of Java CharSequence.toString()
        // to a Unicode JavaScript string. Calling getBytes() on that result
        // fails because it is no longer a Java object; String(editable)
        // instead produces the literal "[object Object]". Use the actual
        // virtual toString() result and leave UTF-8 encoding to the native
        // queue below.
        if (typeof value === 'string') return value;
        let text = value.toString();
        if (typeof text === 'string') return text;
        // Some Android 9 Editable implementations return a Java String
        // wrapper here, whose JavaScript coercion is literally
        // "[object Object]". Read CharSequence one UTF-16 code unit at a time
        // instead of relying on Frida's wrapper coercion.
        const CharSequence = Java.use('java.lang.CharSequence');
        const sequence = Java.cast(text, CharSequence);
        let output = '';
        const length = Number(sequence.length());
        for (let index = 0; index < length; index++) {
            const character = sequence.charAt(index);
            output += typeof character === 'string'
                ? character
                : String.fromCharCode(Number(character));
        }
        return output;
    } catch (e) {
        warn('Android Java text conversion failed:', e);
        return '';
    }
}

function androidUtf8ByteLength(value) {
    if (!value) return 0;
    const source = Memory.allocUtf8String(value);
    let length = 0;
    while (source.add(length).readU8() !== 0) length++;
    return length;
}

function androidUtf8Prefix(value, maximumBytes) {
    let result = '';
    let used = 0;
    for (const character of Array.from(String(value || '').replace(/\u0000/g, ''))) {
        const bytes = androidUtf8ByteLength(character);
        if (used + bytes > maximumBytes) break;
        result += character;
        used += bytes;
    }
    return result;
}

function readAndroidUtf8Buffer(buffer, maximumBytes) {
    let length = 0;
    while (length < maximumBytes && buffer.add(length).readU8() !== 0) length++;
    if (length === 0) return { value: '', length: 0 };
    try {
        return { value: buffer.readUtf8String(length) || '', length };
    } catch (_) {
        // Never expose a partially written UTF-8 sequence to Java.  Walk back
        // to the last valid prefix; the next game-thread clamp repairs it.
        while (length > 0) {
            try {
                return { value: buffer.readUtf8String(length) || '', length };
            } catch (_) {
                length--;
            }
        }
        return { value: '', length: 0 };
    }
}

function getAndroidNativeTextLayout() {
    if (globalThis.androidNativeTextLayout)
        return globalThis.androidNativeTextLayout;
    if (Process.arch !== 'arm64' && Process.arch !== 'arm')
        throw new Error('Unsupported Android ABI: ' + Process.arch);

    const arm64 = Process.arch === 'arm64';
    const base = globalThis.mainModule.base;
    const codeAddress = rva => arm64 ? base.add(rva) : base.add(rva).or(1);
    let startTextInput = null;
    let stopTextInput = null;
    try {
        // SDL owns Android's text-input connection.  Going through it instead
        // of focusing an overlay EditText keeps this working with OEM and
        // third-party keyboards alike.
        startTextInput = new NativeFunction(getGlobalExport('SDL_StartTextInput'),
            'void', []);
        stopTextInput = new NativeFunction(getGlobalExport('SDL_StopTextInput'),
            'void', []);
    } catch (e) {
        warn('Android SDL text-input exports unavailable:', e);
    }
    globalThis.androidNativeTextLayout = {
        arm64,
        buttonSize: arm64 ? 0x188 : 0x150,
        buttonListenerOffset: arm64 ? 256 : 232,
        editorTextOffset: 200,
        editorCursorOffset: arm64 ? 292 : 256,
        consoleUpdate: base.add(arm64 ? 0x42E28 : 0x2F4C0),
        consoleCursor: base.add(arm64 ? 0x21A784 : 0x1951FC),
        consoleDisplayCursor: base.add(arm64 ? 0x21A77C : 0x1951F4),
        consoleBuffer: base.add(arm64 ? 0x21A788 : 0x195200),
        consoleScroll: base.add(arm64 ? 0x21A83C : 0x1952A4),
        consoleState: findSymbol('console_state'),
        consolePopup: findSymbol('console_popup_'),
        activeEditor: findSymbol('main_edit_focus_button'),
        stateCurrent: new NativeFunction(findSymbol('state_current'), 'pointer', []),
        consoleOpen: new NativeFunction(findSymbol('main_do_console_open'), 'void', []),
        consoleClose: new NativeFunction(findSymbol('main_do_console_close'), 'void', []),
        consoleClear: new NativeFunction(findSymbol('console_clear_input'), 'void', []),
        consoleAddText: new NativeFunction(findSymbol('console_add_text'), 'pointer', ['pointer']),
        consoleLineAt: new NativeFunction(codeAddress(arm64 ? 0x42844 : 0x2F0B8),
            'pointer', ['int']),
        scriptDoInput: new NativeFunction(findSymbol('script_do_input'), 'int', ['pointer']),
        // wrapper_call("keyboard", "open") is the game's own (statically
        // linked) route to SDL_StartTextInput. SDL is not exported globally
        // on Android, so this is more reliable than looking for a dynamic
        // SDL_StartTextInput export.
        wrapperCall: new NativeFunction(codeAddress(arm64 ? 0x135EA8 : 0xECF5C),
            'int', ['pointer', 'pointer']),
        startTextInput,
        stopTextInput,
        memmove: new NativeFunction(getGlobalExport('memmove'), 'pointer',
            ['pointer', 'pointer', 'ulong'])
    };
    return globalThis.androidNativeTextLayout;
}

function androidUtf8SplitAtByte(value, requestedByte) {
    let left = '';
    let used = 0;
    for (const character of Array.from(String(value || ''))) {
        const bytes = androidUtf8ByteLength(character);
        if (used + bytes > requestedByte) break;
        left += character;
        used += bytes;
    }
    return {left, right: String(value || '').slice(left.length), byte: used};
}

function requestAndroidNativeConsoleKeyboard(native = getAndroidNativeTextLayout()) {
    try {
        androidConsoleKeyboardWasVisible = false;
        if (native.startTextInput) {
            native.startTextInput();
            androidConsoleKeyboardDismissed = false;
            setAndroidConsoleToolbarVisible(true);
            log('Android native console IME requested');
            return true;
        }
        native.wrapperCall(Memory.allocUtf8String('keyboard'),
            Memory.allocUtf8String('open'));
        androidConsoleKeyboardDismissed = false;
        setAndroidConsoleToolbarVisible(true);
        log('Android native console IME requested through wrapper_call');
        return true;
    } catch (e) {
        warn('Android native console IME request failed:', e);
    }
    return false;
}

function setAndroidConsoleToolbarVisible(visible) {
    if (!androidConsoleToolbar || !androidConsolePopup || !globalThis.activity) return;
    Java.scheduleOnMainThread(() => {
        try {
            if (visible) {
                if (!androidConsoleToolbarAttached) {
                    const Gravity = Java.use('android.view.Gravity');
                    androidConsolePopup.showAtLocation(
                        globalThis.activity.getWindow().getDecorView(),
                        Gravity.TOP.value,
                        0,
                        0
                    );
                    androidConsoleToolbarAttached = true;
                    androidConsolePopupY = 0;
                }
            } else if (androidConsoleToolbarAttached) {
                androidConsolePopup.dismiss();
                androidConsoleToolbarAttached = false;
                androidConsolePopupY = -1;
            }
        } catch (e) {
            androidConsoleToolbarAttached = false;
            androidConsolePopupY = -1;
            warn('Android console toolbar window update failed:', e);
        }
    });
}

function isAndroidConsoleNativeOpen(native = getAndroidNativeTextLayout()) {
    try {
        return native.stateCurrent().equals(native.consoleState);
    } catch (_) {
        return false;
    }
}

function androidConsolePreviewFromNative(native = getAndroidNativeTextLayout()) {
    const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
    const cursorBytes = Math.max(0, Math.min(current.length, native.consoleCursor.readS32()));
    let before = '';
    try {
        before = cursorBytes === 0
            ? ''
            : native.consoleBuffer.readUtf8String(cursorBytes) || '';
    } catch (_) {
        before = current.value;
    }
    return {
        value: current.value,
        selection: Math.min(current.value.length, before.length)
    };
}

function queueAndroidConsoleReplace(value, selection) {
    const limited = androidUtf8Prefix(value, ANDROID_CONSOLE_MAX_UTF8_BYTES);
    const prefix = limited.slice(0, Math.max(0, Math.min(limited.length, selection)));
    androidConsoleActions.push({
        type: 'replace',
        value: limited,
        cursor: androidUtf8ByteLength(prefix)
    });
}

function setAndroidConsoleField(value, selection) {
    if (!androidConsoleField) return;
    androidConsoleUiSyncing = true;
    try {
        const JString = Java.use('java.lang.String');
        const raw = String(value || '');
        const cursor = Math.max(0, Math.min(raw.length, Number(selection) || 0));
        // The Java control is intentionally display-only. Draw a cursor in
        // its text instead of using EditText.setSelection(), which is absent
        // from the Android 9 wrapper returned to Frida on this device.
        const shown = raw.slice(0, cursor) + '|' + raw.slice(cursor);
        const text = JString.$new(shown);
        // Button.setText() is consistently callable across the Android 9+
        // targets. The preview is deliberately a display-only Button rather
        // than an EditText: it never owns the IME and cannot steal SDL input.
        androidConsoleField.setText(text);
        androidConsolePreviewRendered = raw;
        androidConsolePreviewRenderedSelection = cursor;
    } finally {
        androidConsoleUiSyncing = false;
    }
}

function showAndroidKeyboard(field) {
    if (!field || !globalThis.activity) return;
    try {
        const Context = Java.use('android.content.Context');
        const View = Java.use('android.view.View');
        const InputMethodManager = Java.use(
            'android.view.inputmethod.InputMethodManager'
        );
        const view = Java.cast(field, View);
        const imm = Java.cast(
            globalThis.activity.getSystemService(Context.INPUT_METHOD_SERVICE.value),
            InputMethodManager
        );
        view.setFocusable(true);
        view.setFocusableInTouchMode(true);
        view.requestFocus();
        imm.restartInput(view);
        imm.showSoftInput(view, 1);
    } catch (e) {
        warn('Android soft keyboard open failed:', e);
    }
}

function hideAndroidKeyboard(field) {
    if (!field || !globalThis.activity) return;
    try {
        const Context = Java.use('android.content.Context');
        const View = Java.use('android.view.View');
        const InputMethodManager = Java.use(
            'android.view.inputmethod.InputMethodManager'
        );
        const view = Java.cast(field, View);
        const imm = Java.cast(
            globalThis.activity.getSystemService(Context.INPUT_METHOD_SERVICE.value),
            InputMethodManager
        );
        imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        view.clearFocus();
    } catch (e) {
        warn('Android soft keyboard close failed:', e);
    }
}

function requestAndroidConsoleKeyboard() {
    if (!androidConsoleVisible || !androidConsoleField ||
        globalThis.androidConsoleKeyboardRequestPending) return;
    globalThis.androidConsoleKeyboardRequestPending = true;
    Java.scheduleOnMainThread(() => {
        try {
            androidConsoleKeyboardDismissed = false;
            showAndroidKeyboard(androidConsoleField);
        } finally {
            globalThis.androidConsoleKeyboardRequestPending = false;
        }
    });
}

function activateAndroidConsoleUi() {
    if (androidConsoleVisible) return;
    const View = Java.use('android.view.View');
    const preview = androidConsolePreviewFromNative();
    androidConsoleVisible = true;
    // Opening the console alone should not pop up either the keyboard or its
    // companion toolbar. Both appear only after the user taps the console.
    androidConsoleKeyboardDismissed = true;
    androidConsoleHistoryIndex = androidConsoleHistory.length;
    androidConsoleHistoryDraft = preview.value;
    Java.scheduleOnMainThread(() => {
        // Keep the compact toolbar, but never restore its fullscreen
        // transparent touch surface: it swallowed console swipes on some
        // fullscreen Android builds.
        if (androidConsoleField) setAndroidConsoleField(preview.value, preview.selection);
        if (androidConsoleSurface) androidConsoleSurface.setVisibility(View.GONE.value);
        if (androidConsoleRoot) androidConsoleRoot.setVisibility(View.GONE.value);
    });
    log('Android console UI entered; native input restored');
}

function deactivateAndroidConsoleUi() {
    if (!androidConsoleVisible) return;
    const View = Java.use('android.view.View');
    androidConsoleVisible = false;
    androidConsoleKeyboardDismissed = false;
    androidConsoleKeyboardWasVisible = false;
    androidConsoleTouchStartY = null;
    Java.scheduleOnMainThread(() => {
        // SDL owns the active Android input connection for console text.
        // Leave the platform keyboard lifecycle to SDL when the console exits.
        if (androidConsoleRoot) androidConsoleRoot.setVisibility(View.GONE.value);
    });
    setAndroidConsoleToolbarVisible(false);
    try {
        const native = getAndroidNativeTextLayout();
        if (native.stopTextInput) native.stopTextInput();
        else native.wrapperCall(Memory.allocUtf8String('keyboard'),
            Memory.allocUtf8String('close'));
    } catch (e) {
        warn('Android native console IME close failed:', e);
    }
    log('Android console UI left');
}

function navigateAndroidConsoleHistory(delta) {
    if (androidConsoleHistory.length === 0) return;
    let value = '';
    const current = androidConsolePreviewFromNative();
    if (delta < 0) {
        if (androidConsoleHistoryIndex === androidConsoleHistory.length)
            androidConsoleHistoryDraft = current.value;
        if (androidConsoleHistoryIndex > 0) androidConsoleHistoryIndex--;
    } else if (androidConsoleHistoryIndex < androidConsoleHistory.length) {
        androidConsoleHistoryIndex++;
    }
    value = androidConsoleHistoryIndex === androidConsoleHistory.length
        ? androidConsoleHistoryDraft
        : androidConsoleHistory[androidConsoleHistoryIndex];
    setAndroidConsoleField(value, value.length);
    queueAndroidConsoleReplace(value, value.length);
}

function rememberAndroidConsoleHistory(value) {
    const entry = String(value || '');
    if (!entry) return;
    // script_do_input can be reached both from a hardware/soft Enter and the
    // toolbar.  Keep a single entry for the one command in either case.
    if (androidConsoleHistory[androidConsoleHistory.length - 1] !== entry)
        androidConsoleHistory.push(entry);
    if (androidConsoleHistory.length > 100) androidConsoleHistory.shift();
    androidConsoleHistoryIndex = androidConsoleHistory.length;
    androidConsoleHistoryDraft = '';
}

function installAndroidConsoleNativePump() {
    if (globalThis.androidConsoleNativePumpInstalled) return;
    globalThis.androidConsoleNativePumpInstalled = true;
    const native = getAndroidNativeTextLayout();
    const newline = Memory.allocUtf8String('\n');

    // Normal Android Enter is handled entirely inside the native console, so
    // SDL key events are not a dependable place to capture history. Record
    // it at the point the game actually interprets a console line instead.
    Interceptor.attach(findSymbol('script_do_input'), {
        onEnter(args) {
            try {
                if (!isAndroidConsoleNativeOpen(native)) return;
                rememberAndroidConsoleHistory(
                    readAndroidUtf8Buffer(args[0], ANDROID_CONSOLE_MAX_UTF8_BYTES).value
                );
            } catch (_) {}
        }
    });

    const replaceInput = action => {
        const value = androidUtf8Prefix(action.value, ANDROID_CONSOLE_MAX_UTF8_BYTES);
        const source = Memory.allocUtf8String(value);
        const length = androidUtf8ByteLength(value);
        if (length > 0) Memory.copy(native.consoleBuffer, source, length);
        native.consoleBuffer.add(length).writeU8(0);
        const cursor = Math.max(0, Math.min(length, action.cursor));
        native.consoleCursor.writeS32(cursor);
        // console_add_text() maintains a separate current display line. The
        // earlier bridge only changed consoleBuffer, leaving that line at the
        // final history entry; this caused the visual jump and contaminated
        // the command submitted on Enter. Keep both native representations
        // in lockstep, just as the original per-character input routine does.
        const line = native.consoleLineAt(0);
        if (line && !line.isNull()) {
            if (length > 0) Memory.copy(line, source, length);
            line.add(length).writeU8(0);
        }
        native.consoleDisplayCursor.writeS32(cursor);
        if (androidConsoleField && androidConsoleVisible) {
            const displayCursor = androidUtf8SplitAtByte(value, cursor).left.length;
            Java.scheduleOnMainThread(() =>
                setAndroidConsoleField(value, displayCursor)
            );
        }
    };

    const insertInput = value => {
        const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
        const cursor = Math.max(0, Math.min(current.length, native.consoleCursor.readS32()));
        const split = androidUtf8SplitAtByte(current.value, cursor);
        const room = ANDROID_CONSOLE_MAX_UTF8_BYTES - current.length;
        const accepted = androidUtf8Prefix(value, room);
        if (!accepted) return;
        const next = split.left + accepted + split.right;
        replaceInput({
            value: next,
            cursor: split.byte + androidUtf8ByteLength(accepted)
        });
    };

    const deleteInputCharacter = backwards => {
        const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
        const cursor = Math.max(0, Math.min(current.length, native.consoleCursor.readS32()));
        const split = androidUtf8SplitAtByte(current.value, cursor);
        if (backwards) {
            const characters = Array.from(split.left);
            if (characters.length === 0) return;
            const removed = characters.pop();
            replaceInput({
                value: characters.join('') + split.right,
                cursor: split.byte - androidUtf8ByteLength(removed)
            });
        } else {
            const characters = Array.from(split.right);
            if (characters.length === 0) return;
            characters.shift();
            replaceInput({value: split.left + characters.join(''), cursor: split.byte});
        }
    };

    const moveInputCursor = forwards => {
        const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
        const cursor = Math.max(0, Math.min(current.length, native.consoleCursor.readS32()));
        const split = androidUtf8SplitAtByte(current.value, cursor);
        const character = forwards
            ? Array.from(split.right)[0]
            : Array.from(split.left).pop();
        if (!character) return;
        const next = split.byte +
            (forwards ? androidUtf8ByteLength(character) : -androidUtf8ByteLength(character));
        native.consoleCursor.writeS32(next);
        native.consoleDisplayCursor.writeS32(next);
        if (androidConsoleField && androidConsoleVisible) {
            const selection = androidUtf8SplitAtByte(current.value, next).left.length;
            Java.scheduleOnMainThread(() =>
                setAndroidConsoleField(current.value, selection)
            );
        }
    };

    Interceptor.attach(native.consoleUpdate, {
        onEnter() {
            try {
                const actions = androidConsoleActions.splice(0, 64);
                for (const action of actions) {
                    if (action.type === 'replace') {
                        replaceInput(action);
                    } else if (action.type === 'insert') {
                        insertInput(action.value);
                    } else if (action.type === 'delete') {
                        deleteInputCharacter(action.backwards);
                    } else if (action.type === 'cursor') {
                        moveInputCursor(action.forwards);
                    } else if (action.type === 'scroll') {
                        native.consoleScroll.writeS32(Math.max(
                            0,
                            native.consoleScroll.readS32() + action.delta
                        ));
                    } else if (action.type === 'close') {
                        native.consoleClose();
                    } else if (action.type === 'submit') {
                        const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
                        if (current.value) {
                            rememberAndroidConsoleHistory(current.value);
                            native.consoleAddText(native.consoleBuffer);
                            native.consoleAddText(newline);
                            native.scriptDoInput(native.consoleBuffer);
                        }
                        native.consoleClear();
                    }
                }
            } catch (e) {
                error('Android console game-thread pump failed:', e);
            }
        }
    });
    log('Android console UTF-8 game-thread pump installed');
}

function installAndroidCustomNameNativeBridge() {
    if (globalThis.androidCustomNameNativeBridgeInstalled) return;
    globalThis.androidCustomNameNativeBridgeInstalled = true;
    const native = getAndroidNativeTextLayout();

    const activeEditor = () => {
        const editor = native.activeEditor.readPointer();
        if (!editor || editor.isNull()) return null;
        const buffer = editor.add(native.editorTextOffset).readPointer();
        if (!buffer || buffer.isNull()) return null;
        return {
            editor,
            buffer,
            cursor: editor.add(native.editorCursorOffset)
        };
    };

    const writeName = (editor, value, cursor) => {
        const limited = androidUtf8Prefix(value, ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES);
        const source = Memory.allocUtf8String(limited);
        const length = androidUtf8ByteLength(limited);
        Memory.copy(editor.buffer, source, length + 1);
        editor.cursor.writeS32(Math.max(0, Math.min(length, cursor)));
        editor.editor.add(32).writeFloat(ANDROID_CUSTOM_NAME_FIELD_WIDTH);
        return {value: limited, cursor: Math.max(0, Math.min(length, cursor))};
    };

    const splitAtByte = (value, requestedByte) => {
        let left = '';
        let used = 0;
        for (const character of Array.from(value)) {
            const bytes = androidUtf8ByteLength(character);
            if (used + bytes > requestedByte) break;
            left += character;
            used += bytes;
        }
        return {left, right: value.slice(left.length), byte: used};
    };

    const insertCommittedText = (editor, inserted) => {
        const current = readAndroidUtf8Buffer(editor.buffer, 39);
        const split = splitAtByte(current.value, editor.cursor.readS32());
        const room = ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES - current.length;
        const accepted = androidUtf8Prefix(inserted, room);
        if (!accepted) return false;
        writeName(editor, split.left + accepted + split.right,
            split.byte + androidUtf8ByteLength(accepted));
        return true;
    };

    const deleteNameCharacter = (editor, backwards) => {
        const current = readAndroidUtf8Buffer(editor.buffer, 39);
        const split = splitAtByte(current.value, editor.cursor.readS32());
        if (backwards) {
            const characters = Array.from(split.left);
            if (characters.length === 0) return false;
            const removed = characters.pop();
            writeName(editor, characters.join('') + split.right,
                split.byte - androidUtf8ByteLength(removed));
        } else {
            const characters = Array.from(split.right);
            if (characters.length === 0) return false;
            characters.shift();
            writeName(editor, split.left + characters.join(''), split.byte);
        }
        return true;
    };

    const moveNameCursor = (editor, forwards) => {
        const current = readAndroidUtf8Buffer(editor.buffer, 39);
        const split = splitAtByte(current.value, editor.cursor.readS32());
        if (forwards) {
            const next = Array.from(split.right)[0];
            if (!next) return false;
            editor.cursor.writeS32(split.byte + androidUtf8ByteLength(next));
        } else {
            const previous = Array.from(split.left).pop();
            if (!previous) return false;
            editor.cursor.writeS32(split.byte - androidUtf8ByteLength(previous));
        }
        return true;
    };

    // Android's wrapper handles SDL_TEXTINPUT as `(char)event.text[0]`.
    // Consume the complete committed UTF-8 string before that wrapper sees it,
    // and make cursor/deletion operations advance by code point rather than by
    // byte.  The stock Android keyboard remains the IME client.
    Interceptor.attach(findSymbol('SDL_PollEvent'), {
        onEnter(args) {
            this.androidEvent = args[0];
        },
        onLeave(retval) {
            if (retval.toInt32() === 0 || !this.androidEvent) return;
            try {
                const type = this.androidEvent.readU32();
                if (isAndroidConsoleNativeOpen()) {
                    if (type === 0x700) {
                        const x = this.androidEvent.add(24).readFloat();
                        const y = this.androidEvent.add(28).readFloat();
                        // Classify the whole gesture before the stock console
                        // sees it. The Java overlay is intentionally hidden:
                        // on fullscreen Android it can capture the touch
                        // surface without ever receiving an OnTouch callback.
                        const onToggle = x >= 0.90 && y >= 0.16 && y <= 0.32;
                        if (!onToggle) {
                            androidConsoleTouchStartX = x;
                            androidConsoleTouchStartY = y;
                            this.androidEvent.writeU32(0);
                            return;
                        }
                    } else if (type === 0x701) {
                        const x = this.androidEvent.add(24).readFloat();
                        const y = this.androidEvent.add(28).readFloat();
                        const startY = androidConsoleTouchStartY;
                        const startX = androidConsoleTouchStartX;
                        androidConsoleTouchStartY = null;
                        androidConsoleTouchStartX = null;
                        if (startY !== null && startX !== null) {
                            const dy = y - startY;
                            const dx = x - startX;
                            this.androidEvent.writeU32(0);
                            if (Math.abs(dy) < 0.025 && Math.abs(dx) < 0.025) {
                                requestAndroidNativeConsoleKeyboard(native);
                            } else if (Math.abs(dy) > Math.abs(dx)) {
                                const rows = 5 * Math.max(1, Math.min(6,
                                    Math.round(Math.abs(dy) / 0.06)));
                                androidConsoleActions.push({
                                    type: 'scroll',
                                    delta: dy < 0 ? -rows : rows
                                });
                                log('Android console swipe queued', dy < 0 ? 'up' : 'down', rows);
                            }
                            return;
                        }
                    } else if (type === 0x702) {
                        // Consume movement too, otherwise the stock control
                        // can turn a finished swipe into a tap/click.
                        if (androidConsoleTouchStartY !== null) {
                            this.androidEvent.writeU32(0);
                            return;
                        }
                    } else if (type === 0x303) {
                        let length = 0;
                        while (length < 31 &&
                            this.androidEvent.add(12 + length).readU8() !== 0) length++;
                        if (length > 0) {
                            const value = this.androidEvent.add(12).readUtf8String(length);
                            if (value) {
                                androidConsoleActions.push({type: 'insert', value});
                                // The Android game wrapper otherwise truncates
                                // SDL_TEXTINPUT to its first UTF-8 byte.
                                this.androidEvent.writeU32(0);
                            }
                        }
                        return;
                    } else if (type === 0x300) {
                        const key = this.androidEvent.add(20).readS32();
                        let action = null;
                        if (key === 8) action = {type: 'delete', backwards: true};
                        else if (key === 127) action = {type: 'delete', backwards: false};
                        else if (key === 1073741904) action = {type: 'cursor', forwards: false};
                        else if (key === 1073741903) action = {type: 'cursor', forwards: true};
                        if (action) {
                            androidConsoleActions.push(action);
                            this.androidEvent.writeU32(0);
                            return;
                        }
                        if (key === 13 || key === 10 || key === 66) {
                            const current = readAndroidUtf8Buffer(native.consoleBuffer, 127);
                            if (current.value) {
                                androidConsoleHistory.push(current.value);
                                if (androidConsoleHistory.length > 100)
                                    androidConsoleHistory.shift();
                            }
                            androidConsoleHistoryIndex = androidConsoleHistory.length;
                            androidConsoleHistoryDraft = '';
                        }
                        // Soft keyboards commonly emit both KEYDOWN and
                        // TEXTINPUT for one committed character. TEXTINPUT is
                        // the authoritative UTF-8 payload above; allowing the
                        // printable key through duplicates/garbles commands.
                        // Keep Return for the native console submit handler.
                        if (key !== 13 && key !== 10 && key >= 32 && key <= 126) {
                            this.androidEvent.writeU32(0);
                            return;
                        }
                    }
                }

                const editor = activeEditor();
                if (!editor) return;
                if (type === 0x303) {
                    let length = 0;
                    while (length < 31 &&
                        this.androidEvent.add(12 + length).readU8() !== 0) length++;
                    if (length === 0) return;
                    const value = this.androidEvent.add(12).readUtf8String(length);
                    if (value && insertCommittedText(editor, value))
                        this.androidEvent.writeU32(0);
                    return;
                }
                if (type !== 0x300) return;
                const key = this.androidEvent.add(20).readS32();
                let handled = false;
                if (key === 8) handled = deleteNameCharacter(editor, true);
                else if (key === 127) handled = deleteNameCharacter(editor, false);
                else if (key === 1073741904) handled = moveNameCursor(editor, false);
                else if (key === 1073741903) handled = moveNameCursor(editor, true);
                if (handled) this.androidEvent.writeU32(0);
            } catch (e) {
                error('Android SDL UTF-8 text event bridge failed:', e);
            }
        }
    });

    // main_btn_edit_focus measures UTF-8 one byte at a time and then advances
    // the draw pointer into the middle of a character until it fits.  Replace
    // only its final plot_text argument with the complete authoritative name.
    const editRenderThreads = new Map();
    const editFocus = findSymbol('main_btn_edit_focus');
    Interceptor.attach(editFocus, {
        onEnter(args) {
            if (args[1].toUInt32() !== 7) return;
            const tid = Process.getCurrentThreadId();
            const stack = editRenderThreads.get(tid) || [];
            stack.push(args[0]);
            editRenderThreads.set(tid, stack);
            args[0].add(32).writeFloat(ANDROID_CUSTOM_NAME_FIELD_WIDTH);
            this.androidEditRenderTid = tid;
        },
        onLeave() {
            if (this.androidEditRenderTid === undefined) return;
            const stack = editRenderThreads.get(this.androidEditRenderTid) || [];
            stack.pop();
            if (stack.length) editRenderThreads.set(this.androidEditRenderTid, stack);
            else editRenderThreads.delete(this.androidEditRenderTid);
        }
    });
    const editPreviewBuffers = new Map();
    const madTicks = findSymbol('mad_ticks');
    Interceptor.attach(findSymbol('plot_text'), {
        onEnter(args) {
            const tid = Process.getCurrentThreadId();
            const stack = editRenderThreads.get(tid);
            if (!stack || stack.length === 0) return;
            const button = stack[stack.length - 1];
            const value = button.add(native.editorTextOffset).readPointer();
            if (!value || value.isNull()) return;
            if (button.add(188).readU8() === 0) {
                args[0] = value;
                return;
            }
            const current = readAndroidUtf8Buffer(value, 39);
            const split = splitAtByte(current.value,
                button.add(native.editorCursorOffset).readS32());
            let preview = editPreviewBuffers.get(tid);
            if (!preview) {
                preview = Memory.alloc(64);
                editPreviewBuffers.set(tid, preview);
            }
            if (split.byte > 0) Memory.copy(preview, value, split.byte);
            preview.add(split.byte).writeU8((madTicks.readU32() & 0x10) ? 1 : 2);
            const tailLength = current.length - split.byte;
            if (tailLength > 0) Memory.copy(
                preview.add(split.byte + 1),
                value.add(split.byte),
                tailLength
            );
            preview.add(current.length + 1).writeU8(0);
            args[0] = preview;
        }
    });

    Interceptor.attach(findSymbol('main_edit_field_update_editing'), {
        onEnter() {
            this.androidNameRestore = null;
            try {
                const editor = activeEditor();
                if (!editor) return;
                const current = readAndroidUtf8Buffer(editor.buffer, 39);
                let desiredValue = androidUtf8Prefix(
                    current.value,
                    ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES
                );
                let desiredCursor = Math.max(0, Math.min(
                    androidUtf8ByteLength(desiredValue),
                    editor.cursor.readS32()
                ));
                const actions = androidNameActions.splice(0, 32);
                for (const action of actions) {
                    desiredValue = androidUtf8Prefix(
                        action.value,
                        ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES
                    );
                    desiredCursor = Math.max(0, Math.min(
                        androidUtf8ByteLength(desiredValue),
                        action.cursor
                    ));
                }
                const written = writeName(editor, desiredValue, desiredCursor);
                // The stock editor consumes SDL text one byte at a time and can
                // split a UTF-8 character after our Java EditText has already
                // supplied the complete value. Let it keep navigation/confirm
                // behaviour, then restore the authoritative UTF-8 buffer.
                this.androidNameRestore = {
                    editor,
                    value: written.value,
                    cursor: written.cursor
                };
            } catch (e) {
                error('Android custom-name game-thread update failed:', e);
            }
        },
        onLeave() {
            if (!this.androidNameRestore) return;
            try {
                writeName(
                    this.androidNameRestore.editor,
                    this.androidNameRestore.value,
                    this.androidNameRestore.cursor
                );
            } catch (e) {
                error('Android custom-name post-update restore failed:', e);
            }
        }
    });

    // The original post-edit width limiter writes a NUL at an arbitrary byte
    // offset. Preserve the complete UTF-8 value for this one active editor.
    Interceptor.attach(findSymbol('main_do_str_pixelw_limit'), {
        onEnter(args) {
            this.restore = null;
            try {
                const editor = activeEditor();
                if (!editor || !args[0].equals(editor.buffer)) return;
                const current = readAndroidUtf8Buffer(editor.buffer, 39);
                this.restore = {
                    buffer: editor.buffer,
                    value: androidUtf8Prefix(
                        current.value,
                        ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES
                    )
                };
            } catch (e) {
                error('Android custom-name width-limit guard failed:', e);
            }
        },
        onLeave(retval) {
            if (!this.restore) return;
            const source = Memory.allocUtf8String(this.restore.value);
            const length = androidUtf8ByteLength(this.restore.value);
            Memory.copy(this.restore.buffer, source, length + 1);
            retval.replace(ptr(0));
        }
    });

    globalThis.androidActiveNameEditor = activeEditor;
    log('Android custom-name UTF-8 native bridge installed');
}

function installAndroidTeamNameDisplayHook() {
    if (globalThis.androidTeamNameDisplayHookInstalled) return;
    globalThis.androidTeamNameDisplayHookInstalled = true;
    const base = globalThis.mainModule.base;
    const arm64 = Process.arch === 'arm64';
    const ranges = arm64
        ? [[0xFD6C0, 1216], [0xFDB80, 1100], [0xFDFCC, 1448]]
        : [[0xC3488, 818], [0xC3810, 726], [0xC3B38, 998]];
    const pauseLootRva = arm64 ? 0x100A94 : 0xC5C0C;
    const rendererThreads = new Map();
    const pauseLootThreads = new Map();
    const rendererAddress = rva => arm64 ? base.add(rva) : base.add(rva).or(1);
    for (const [rva] of ranges) {
        Interceptor.attach(rendererAddress(rva), {
            onEnter() {
                const tid = Process.getCurrentThreadId();
                rendererThreads.set(tid, (rendererThreads.get(tid) || 0) + 1);
                this.androidTeamRendererTid = tid;
            },
            onLeave() {
                const tid = this.androidTeamRendererTid;
                const depth = (rendererThreads.get(tid) || 1) - 1;
                if (depth > 0) rendererThreads.set(tid, depth);
                else rendererThreads.delete(tid);
            }
        });
    }
    Interceptor.attach(rendererAddress(pauseLootRva), {
        onEnter() {
            const tid = Process.getCurrentThreadId();
            pauseLootThreads.set(tid, (pauseLootThreads.get(tid) || 0) + 1);
            this.androidPauseLootTid = tid;
        },
        onLeave() {
            const tid = this.androidPauseLootTid;
            const depth = (pauseLootThreads.get(tid) || 1) - 1;
            if (depth > 0) pauseLootThreads.set(tid, depth);
            else pauseLootThreads.delete(tid);
        }
    });

    const retainedNames = [];
    const keepName = value => {
        const pointer = Memory.allocUtf8String(value);
        retainedNames.push(pointer);
        if (retainedNames.length > 64) retainedNames.shift();
        return pointer;
    };
    const displayName = value => {
        const characters = Array.from(value);
        const totalUnits = characters.reduce((sum, character) =>
            sum + (character.codePointAt(0) <= 0x7f ? 1 : 2), 0);
        if (totalUnits <= 12) return value;

        let output = '';
        let units = 0;
        // Return only a UTF-8-safe 12-unit prefix. The native renderer
        // compares this with the original name and appends its own dot.
        for (const character of characters) {
            const width = character.codePointAt(0) <= 0x7f ? 1 : 2;
            if (units + width > 12) break;
            output += character;
            units += width;
        }
        return output;
    };

    // team_btn_char_* calls wrap_text before its fixed-size strncpy. Hooking
    // strncpy was too late: wrap_text had already split a CJK name after six
    // UTF-8 bytes (two glyphs). Replace the wrapper result with the full,
    // display-width-truncated name instead.
    Interceptor.attach(findSymbol('wrap_text'), {
        onEnter(args) {
            this.teamName = null;
            if (!rendererThreads.get(Process.getCurrentThreadId()) ||
                args[0].isNull()) return;
            try {
                const source = args[0].readPointer();
                if (!source || source.isNull()) return;
                this.teamName = keepName(displayName(readMixedUtf8String(source)));
            } catch (e) {
                error('Android team-name UTF-8 truncation failed:', e);
            }
        },
        onLeave(retval) {
            if (this.teamName) retval.replace(this.teamName);
        }
    });

    // The black pause-menu resource panel uses a separate renderer. It copies
    // the full name and then calls a byte-oriented width limiter, which cuts a
    // three-byte CJK character after the second glyph. Restore a 12-display-
    // unit UTF-8 prefix after that call and let the stock function append its
    // own truncation dot.
    Interceptor.attach(findSymbol('main_do_str_pixelw_limit'), {
        onEnter(args) {
            this.androidPauseName = null;
            if (!pauseLootThreads.get(Process.getCurrentThreadId()) ||
                args[0].isNull()) return;
            try {
                const source = readMixedUtf8String(args[0]);
                const clipped = displayName(source);
                this.androidPauseName = {
                    buffer: args[0],
                    source,
                    clipped,
                    truncated: clipped !== source
                };
            } catch (e) {
                error('Android pause-menu name capture failed:', e);
            }
        },
        onLeave(retval) {
            if (!this.androidPauseName) return;
            try {
                const pointer = Memory.allocUtf8String(this.androidPauseName.clipped);
                const length = androidUtf8ByteLength(this.androidPauseName.clipped);
                Memory.copy(this.androidPauseName.buffer, pointer, length + 1);
                retval.replace(this.androidPauseName.truncated ? 1 : 0);
            } catch (e) {
                error('Android pause-menu name restore failed:', e);
            }
        }
    });

    // Keep the stock 19-byte copy and truncation marker logic unchanged.
    // Six three-byte CJK glyphs plus NUL fit it exactly.
    log('Android Team name UTF-8 wrap bridge installed');
}

function installAndroidPersistentConsoleButton() {
    if (globalThis.androidNativeConsoleButtonInstalled) return;
    globalThis.androidNativeConsoleButtonInstalled = true;
    const native = getAndroidNativeTextLayout();
    const buttonEx = new NativeFunction(findSymbol('button_ex'), 'pointer',
        ['float', 'float', 'int', 'pointer', 'pointer']);
    const buttonsCount = new NativeFunction(findSymbol('buttons_count'), 'int', []);
    const buttonSetW = new NativeFunction(findSymbol('button_set_w'), 'void', ['pointer', 'float']);
    const buttonSetH = new NativeFunction(findSymbol('button_set_h'), 'void', ['pointer', 'float']);
    const madW = new NativeFunction(findSymbol('mad_w'), 'float', []);
    const madH = new NativeFunction(findSymbol('mad_h'), 'float', []);
    const mainBtnDefault = new NativeFunction(findSymbol('main_btn_default'), 'uint',
        ['pointer', 'int']);
    const buttonText = L('~');
    let buttonId = -1;
    let buttonValid = false;

    const toggleConsole = () => {
        try {
            if (isAndroidConsoleNativeOpen(native)) native.consoleClose();
            else native.consoleOpen();
        } catch (e) {
            error('Android native console button failed:', e);
        }
        return 1;
    };
    globalThis.androidConsoleButtonFunc = new NativeCallback((button, event) => {
        const result = mainBtnDefault(button, event);
        if (event === 3) return toggleConsole();
        return result;
    }, 'uint', ['pointer', 'int']);

    const appendButton = () => {
        const width = madW();
        const height = madH();
        if (!(width > 0) || !(height > 0)) return;
        buttonId = buttonsCount();
        const button = buttonEx(0, 0, 0, buttonText,
            globalThis.androidConsoleButtonFunc);
        if (!button || button.isNull()) return;
        buttonSetW(button, width * 0.045);
        buttonSetH(button, height * 0.065);
        button.add(16).writeFloat(width * 0.95);
        button.add(20).writeFloat(height * 0.24);
        const touchAlpha100 = 1.0 / 11.0;
        for (const alphaOffset of [60, 76, 92, 108, 124, 140])
            button.add(alphaOffset).writeFloat(touchAlpha100);
        buttonValid = true;
        log('Android persistent native console button installed',
            `${width}x${height}`, `id=${buttonId}`);
    };

    Interceptor.attach(findSymbol('buttons_start'), {
        onLeave() {
            buttonId = -1;
            buttonValid = false;
        }
    });
    Interceptor.attach(findSymbol('buttons_reset_to'), {
        onEnter(args) {
            if (buttonValid && args[0].toInt32() <= buttonId) buttonValid = false;
        }
    });
    Interceptor.attach(findSymbol('buttons_update'), {
        onEnter() {
            if (!buttonValid) appendButton();
        }
    });
}

function installAndroidTextInputUi() {
    if (Process.platform !== 'linux' || !globalThis.isAndroid || androidTextBridgeInstalled)
        return;
    Java.perform(() => {
        let activity = null;
        try {
            activity = getActivity();
        } catch (e) {
            warn('Android Activity lookup failed:', e);
        }
        if (!activity) {
            setTimeout(installAndroidTextInputUi, 500);
            return;
        }
        androidTextBridgeInstalled = true;
        Java.scheduleOnMainThread(() => {
            try {
                const View = Java.use('android.view.View');
                const Gravity = Java.use('android.view.Gravity');
                const FrameLayout = Java.use('android.widget.FrameLayout');
                const FrameLayoutParams = Java.use(
                    'android.widget.FrameLayout$LayoutParams'
                );
                const LinearLayout = Java.use('android.widget.LinearLayout');
                const LinearLayoutParams = Java.use(
                    'android.widget.LinearLayout$LayoutParams'
                );
                const PopupWindow = Java.use('android.widget.PopupWindow');
                const EditText = Java.use('android.widget.EditText');
                const Button = Java.use('android.widget.Button');
                const Color = Java.use('android.graphics.Color');
                const ColorDrawable = Java.use('android.graphics.drawable.ColorDrawable');
                const Rect = Java.use('android.graphics.Rect');
                const Context = Java.use('android.content.Context');
                const InputType = Java.use('android.text.InputType');
                const EditorInfo = Java.use('android.view.inputmethod.EditorInfo');
                const InputMethodManager = Java.use(
                    'android.view.inputmethod.InputMethodManager'
                );
                const WindowManager = Java.use('android.view.WindowManager');
                const WindowManagerLayoutParams = Java.use(
                    'android.view.WindowManager$LayoutParams'
                );
                const PixelFormat = Java.use('android.graphics.PixelFormat');
                const BuildVersion = Java.use('android.os.Build$VERSION');
                const MotionEvent = Java.use('android.view.MotionEvent');
                const OnGlobalLayoutListener = Java.use(
                    'android.view.ViewTreeObserver$OnGlobalLayoutListener'
                );
                const BaseInputConnection = Java.use('android.view.inputmethod.BaseInputConnection');
                const JString = Java.use('java.lang.String');
                const displayMetrics = activity.getResources().getDisplayMetrics();
                const dp = value => Math.max(1, Math.round(value * displayMetrics.density.value));
                const consoleToolbarHeight = dp(32);
                const decor = Java.cast(activity.getWindow().getDecorView(), FrameLayout);
                const inputMethodManager = Java.cast(
                    activity.getSystemService(Context.INPUT_METHOD_SERVICE.value),
                    InputMethodManager
                );
                // Keep the concrete implementation returned by Activity.
                // Java.cast(..., WindowManager interface) drops addView() in
                // this Frida runtime, so the application panel was never
                // actually attached.
                const windowManager = activity.getWindowManager();
                const androidSdk = BuildVersion.SDK_INT.value;

                const ConsoleWatcher = Java.registerClass({
                    name: `top.sevenshape.dr2c.ConsoleWatcher${Process.id}`,
                    implements: [Java.use('android.text.TextWatcher')],
                    methods: {
                        beforeTextChanged() {},
                        onTextChanged() {},
                        afterTextChanged(editable) {
                            if (androidConsoleUiSyncing || !androidConsoleVisible) return;
                            try {
                                if (BaseInputConnection.getComposingSpanStart(editable) >= 0)
                                    return;
                                const value = androidJavaText(editable);
                                const selection = Math.max(0, androidConsoleField.getSelectionStart());
                                const limited = androidUtf8Prefix(
                                    value,
                                    ANDROID_CONSOLE_MAX_UTF8_BYTES
                                );
                                if (limited !== value) {
                                    setAndroidConsoleField(limited, limited.length);
                                }
                                queueAndroidConsoleReplace(limited, Math.min(selection, limited.length));
                            } catch (e) {
                                error('Android console EditText sync failed:', e);
                            }
                        }
                    }
                });

                const NameWatcher = Java.registerClass({
                    name: `top.sevenshape.dr2c.NameWatcher${Process.id}`,
                    implements: [Java.use('android.text.TextWatcher')],
                    methods: {
                        beforeTextChanged() {},
                        onTextChanged() {},
                        afterTextChanged(editable) {
                            if (androidNameUiSyncing || !androidActiveNameEditor ||
                                androidActiveNameEditor.isNull()) return;
                            try {
                                if (BaseInputConnection.getComposingSpanStart(editable) >= 0)
                                    return;
                                const value = androidJavaText(editable);
                                const limited = androidUtf8Prefix(
                                    value,
                                    ANDROID_CUSTOM_NAME_MAX_UTF8_BYTES
                                );
                                if (limited !== value) {
                                    androidNameUiSyncing = true;
                                    androidNameField.setText(JString.$new(limited));
                                    androidNameField.setSelection(limited.length);
                                    androidNameUiSyncing = false;
                                }
                                const selection = Math.max(0, Math.min(
                                    limited.length,
                                    androidNameField.getSelectionStart()
                                ));
                                androidNameActions.push({
                                    value: limited,
                                    cursor: androidUtf8ByteLength(limited.slice(0, selection))
                                });
                            } catch (e) {
                                androidNameUiSyncing = false;
                                error('Android custom-name EditText sync failed:', e);
                            }
                        }
                    }
                });

                const Controls = Java.registerClass({
                    name: `top.sevenshape.dr2c.ConsoleControls${Process.id}`,
                    implements: [
                        Java.use('android.view.View$OnClickListener'),
                        Java.use('android.view.View$OnTouchListener'),
                        Java.use('android.widget.TextView$OnEditorActionListener')
                    ],
                    methods: {
                        onClick(view) {
                            const action = view.getTag()
                                ? androidJavaText(view.getTag())
                                : '';
                            try {
                                // The native console buffer is the only data
                                // source. Android 9 may expose Editable as a
                                // wrapper object when a toolbar button reads
                                // it, which previously injected [object Object].
                                const preview = androidConsolePreviewFromNative();
                                const text = preview.value;
                                const selection = preview.selection;
                                if (action === 'paste') {
                                    const ClipboardManager = Java.use(
                                        'android.content.ClipboardManager'
                                    );
                                    const clipboard = Java.cast(
                                        activity.getSystemService(
                                            Context.CLIPBOARD_SERVICE.value
                                        ),
                                        ClipboardManager
                                    );
                                    if (clipboard.hasPrimaryClip()) {
                                        const clip = clipboard.getPrimaryClip();
                                        if (clip && clip.getItemCount() > 0) {
                                            const pasted = androidJavaText(
                                                clip.getItemAt(0).coerceToText(activity)
                                            );
                                            const merged = text.slice(0, selection) + pasted +
                                                text.slice(selection);
                                            const limited = androidUtf8Prefix(
                                                merged,
                                                ANDROID_CONSOLE_MAX_UTF8_BYTES
                                            );
                                            const next = Math.min(
                                                limited.length,
                                                selection + pasted.length
                                            );
                                            setAndroidConsoleField(limited, next);
                                            queueAndroidConsoleReplace(limited, next);
                                        }
                                    }
                                } else if (action === 'up') {
                                    navigateAndroidConsoleHistory(-1);
                                } else if (action === 'down') {
                                    navigateAndroidConsoleHistory(1);
                                } else if (action === 'left' || action === 'right') {
                                    const next = Math.max(0, Math.min(
                                        text.length,
                                        selection + (action === 'left' ? -1 : 1)
                                    ));
                                    queueAndroidConsoleReplace(text, next);
                                } else if (action === 'dismiss') {
                                    androidConsoleKeyboardDismissed = true;
                                    androidConsoleKeyboardWasVisible = false;
                                    // The real IME client is SDL, not this
                                    // display-only EditText. Closing only
                                    // the Java field hides the toolbar but
                                    // leaves the keyboard alive.
                                    try {
                                        const native = getAndroidNativeTextLayout();
                                        if (native.stopTextInput) native.stopTextInput();
                                        else native.wrapperCall(
                                            Memory.allocUtf8String('keyboard'),
                                            Memory.allocUtf8String('close')
                                        );
                                    } catch (e) {
                                        warn('Android native console IME dismiss failed:', e);
                                    }
                                    hideAndroidKeyboard(androidConsoleField);
                                    setAndroidConsoleToolbarVisible(false);
                                }
                            } catch (e) {
                                error('Android console control failed:', action, e);
                            }
                        },
                        onTouch(view, event) {
                            try {
                                const action = event.getActionMasked();
                                if (action === MotionEvent.ACTION_DOWN.value) {
                                    androidConsoleTouchStartY = event.getY();
                                    return true;
                                }
                                if (action !== MotionEvent.ACTION_UP.value &&
                                    action !== MotionEvent.ACTION_CANCEL.value) return true;
                                const start = androidConsoleTouchStartY;
                                androidConsoleTouchStartY = null;
                                if (start === null || action === MotionEvent.ACTION_CANCEL.value)
                                    return true;
                                const distance = event.getY() - start;
                                if (Math.abs(distance) < dp(16)) {
                                    androidConsoleKeyboardDismissed = false;
                                    showAndroidKeyboard(androidConsoleField);
                                } else {
                                    const rows = 5 * Math.max(1, Math.min(
                                        6,
                                        Math.round(Math.abs(distance) / dp(50))
                                    ));
                                    androidConsoleActions.push({
                                        type: 'scroll',
                                        delta: distance < 0 ? rows : -rows
                                    });
                                }
                            } catch (e) {
                                error('Android console touch bridge failed:', e);
                            }
                            return true;
                        },
                        onEditorAction(view, actionId, event) {
                            if (actionId === EditorInfo.IME_ACTION_DONE.value ||
                                actionId === EditorInfo.IME_ACTION_GO.value ||
                                (event && event.getKeyCode && event.getKeyCode() === 66)) {
                                androidConsoleActions.push({type: 'submit'});
                                setAndroidConsoleField('', 0);
                                androidConsoleHistoryIndex = androidConsoleHistory.length;
                                androidConsoleHistoryDraft = '';
                                return true;
                            }
                            return false;
                        }
                    }
                });
                const controls = Controls.$new();

                const root = FrameLayout.$new(activity);
                root.setBackgroundColor(Color.TRANSPARENT.value);
                root.setVisibility(View.GONE.value);
                root.setFocusable(false);
                root.setClickable(false);
                const rootParams = FrameLayoutParams.$new(-1, -1);
                // addContentView attaches after the fullscreen SDL surface.
                // Adding to DecorView directly can leave this layer behind a
                // SurfaceView on Android 8/9 even though it is VISIBLE.
                activity.addContentView(root, rootParams);
                if (root.setElevation) root.setElevation(dp(100));
                if (root.setTranslationZ) root.setTranslationZ(dp(100));

                const surface = View.$new(activity);
                surface.setBackgroundColor(Color.TRANSPARENT.value);
                surface.setClickable(true);
                surface.setOnTouchListener(controls);
                const surfaceParams = FrameLayoutParams.$new(-1, -1);
                surfaceParams.topMargin.value = dp(44);
                surfaceParams.bottomMargin.value = consoleToolbarHeight;
                surfaceParams.rightMargin.value = Math.round(
                    displayMetrics.widthPixels.value * 0.09
                );
                root.addView(surface, surfaceParams);
                androidConsoleSurface = surface;

                const toolbar = LinearLayout.$new(activity);
                toolbar.setOrientation(LinearLayout.HORIZONTAL.value);
                toolbar.setGravity(Gravity.CENTER_VERTICAL.value);
                toolbar.setPadding(dp(4), 0, 0, 0);
                toolbar.setBackgroundColor(Color.argb(230, 32, 32, 32));
                const toolbarParams = FrameLayoutParams.$new(-1, consoleToolbarHeight);
                toolbarParams.gravity.value = Gravity.TOP.value;
                // SurfaceView/GLSurfaceView can sit above every ordinary
                // child of DecorView. Attach this compact control bar as an
                // application panel instead, so it is a real window above
                // the SDL surface without requiring any overlay permission.
                const consoleWindowParams = WindowManagerLayoutParams.$new(
                    -1,
                    consoleToolbarHeight,
                    WindowManagerLayoutParams.TYPE_APPLICATION_PANEL.value,
                    WindowManagerLayoutParams.FLAG_NOT_FOCUSABLE.value |
                        WindowManagerLayoutParams.FLAG_NOT_TOUCH_MODAL.value |
                        WindowManagerLayoutParams.FLAG_LAYOUT_IN_SCREEN.value,
                    PixelFormat.TRANSLUCENT.value
                );
                consoleWindowParams.gravity.value = Gravity.TOP.value;
                consoleWindowParams.token.value = decor.getWindowToken();
                if (toolbar.setElevation) toolbar.setElevation(dp(16));
                const consolePopup = PopupWindow.$new(
                    toolbar, -1, consoleToolbarHeight, false
                );
                consolePopup.setBackgroundDrawable(
                    ColorDrawable.$new(Color.TRANSPARENT.value)
                );
                consolePopup.setOutsideTouchable(false);
                consolePopup.setInputMethodMode(
                    PopupWindow.INPUT_METHOD_NOT_NEEDED.value
                );
                consolePopup.setSoftInputMode(0);

                // Use the same stable TextView implementation as the action
                // buttons. On Android 9 the embedded EditText could accept
                // text yet fail to paint it above the game SurfaceView.
                const field = Button.$new(activity);
                field.setSingleLine(true);
                // Preview only. SDL remains the IME client.
                field.setFocusable(false);
                field.setFocusableInTouchMode(false);
                field.setClickable(false);
                field.setEnabled(true);
                field.setAlpha(1.0);
                field.setTextColor(Color.WHITE.value);
                field.setHintTextColor(Color.rgb(145, 145, 145));
                field.setBackgroundColor(Color.TRANSPARENT.value);
                field.setHint(JString.$new('Console input'));
                field.setTextSize(16);
                field.setGravity(Gravity.LEFT.value | Gravity.CENTER_VERTICAL.value);
                field.setPadding(dp(8), 0, dp(4), 0);
                const fieldParams = LinearLayoutParams.$new(0, -1, 1.0);
                toolbar.addView(field, fieldParams);
                androidConsoleField = field;

                // Paste benefits from a text label, while arrows and the
                // keyboard control only need compact icon targets. Keeping
                // the latter narrower gives the live preview most of the row.
                const pasteWidth = Math.max(
                    dp(40),
                    Math.round(displayMetrics.widthPixels.value * 0.040)
                );
                const iconWidth = Math.max(
                    dp(28),
                    Math.round(displayMetrics.widthPixels.value * 0.028)
                );
                const makeButton = (label, action, width) => {
                    const button = Button.$new(activity);
                    button.setText(JString.$new(label));
                    button.setTextSize(12);
                    button.setMinWidth(0);
                    button.setMinimumWidth(0);
                    button.setPadding(0, 0, 0, 0);
                    // Android's themed Button background includes large
                    // transparent insets. A direct drawable makes adjacent
                    // controls truly compact; the 1dp layout margin remains
                    // the only intentional separator.
                    button.setBackground(
                        ColorDrawable.$new(Color.WHITE.value)
                    );
                    button.setTag(JString.$new(action));
                    button.setOnClickListener(controls);
                    const params = LinearLayoutParams.$new(width, -1);
                    params.setMargins(1, 0, action === 'dismiss' ? 0 : 1, 0);
                    toolbar.addView(button, params);
                };
                makeButton('Paste', 'paste', pasteWidth);
                makeButton('↑', 'up', iconWidth);
                makeButton('↓', 'down', iconWidth);
                makeButton('←', 'left', iconWidth);
                makeButton('→', 'right', iconWidth);
                makeButton('⌄', 'dismiss', iconWidth);

                // The IME is a separate Android window and may cover decor
                // children in fullscreen mode. Keep the complete input bar
                // at the top of the screen. OEM landscape keyboards do not
                // report one reliable top edge: candidate rows, split-key
                // bodies and floating panels may be separate windows, so an
                // IME-height-derived Y can leave half of the bar covered.
                // Insets are still observed below only to notice when the
                // keyboard has been dismissed through its own UI.
                const visibleFrame = Rect.$new();
                const ConsoleLayout = Java.registerClass({
                    name: `top.sevenshape.dr2c.ConsoleLayout${Process.id}`,
                    implements: [OnGlobalLayoutListener],
                    methods: {
                        onGlobalLayout() {
                            try {
                                decor.getWindowVisibleDisplayFrame(visibleFrame);
                                let keyboardHeight = 0;
                                try {
                                    // This hidden-but-stable framework method
                                    // is present on the Android 6-9 targets.
                                    // Unlike getWindowVisibleDisplayFrame it
                                    // still reports the IME in fullscreen.
                                    keyboardHeight = Number(
                                        inputMethodManager
                                            .getInputMethodWindowVisibleHeight()
                                    ) || 0;
                                } catch (_) {}
                                const visibleBottom = visibleFrame.bottom.value;
                                const fallback = decor.getHeight();
                                if (keyboardHeight <= 0 && androidSdk >= 30) {
                                    try {
                                        const WindowInsetsType = Java.use(
                                            'android.view.WindowInsets$Type'
                                        );
                                        const insets = decor.getRootWindowInsets();
                                        if (insets) {
                                            keyboardHeight = insets.getInsets(
                                                WindowInsetsType.ime()
                                            ).bottom.value;
                                        }
                                    } catch (_) {}
                                }
                                if (keyboardHeight <= 0 && visibleBottom > 0 &&
                                    fallback - visibleBottom > dp(80)) {
                                    keyboardHeight = fallback - visibleBottom;
                                }
                                if (keyboardHeight > 0) {
                                    androidConsoleKeyboardWasVisible = true;
                                } else if (androidConsoleToolbarAttached &&
                                    androidConsoleKeyboardWasVisible &&
                                    !androidConsoleKeyboardDismissed) {
                                    // The keyboard's own dismiss control
                                    // closes the IME without touching our
                                    // toolbar. Once it has genuinely been
                                    // observed, a zero-height frame means it
                                    // was dismissed and the companion bar
                                    // should leave with it.
                                    androidConsoleKeyboardDismissed = true;
                                    androidConsoleKeyboardWasVisible = false;
                                    setAndroidConsoleToolbarVisible(false);
                                }
                                // toolbar is the content of a PopupWindow.
                                // Both stay fixed at screen Y=0; never move
                                // them from an OEM-specific IME height.
                                if (androidConsoleToolbarAttached && androidConsolePopup) {
                                    toolbar.setY(0);
                                    if (androidConsolePopupY !== 0) {
                                        androidConsolePopup.update(
                                            0, 0, -1, consoleToolbarHeight, true
                                        );
                                        androidConsolePopupY = 0;
                                    }
                                }
                            } catch (e) {
                                warn('Android console toolbar layout failed:', e);
                            }
                        }
                    }
                });
                const consoleLayout = ConsoleLayout.$new();
                decor.getViewTreeObserver().addOnGlobalLayoutListener(consoleLayout);

                const nameField = EditText.$new(activity);
                nameField.setSingleLine(true);
                nameField.setAlpha(0.01);
                nameField.setInputType(InputType.TYPE_CLASS_TEXT.value |
                    InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS.value);
                nameField.setImeOptions(EditorInfo.IME_ACTION_DONE.value |
                    EditorInfo.IME_FLAG_NO_EXTRACT_UI.value);
                nameField.addTextChangedListener(NameWatcher.$new());
                const nameParams = FrameLayoutParams.$new(dp(2), dp(2));
                nameParams.gravity.value = Gravity.BOTTOM.value | Gravity.LEFT.value;
                decor.addView(nameField, nameParams);
                androidNameField = nameField;

                androidConsoleRoot = root;
                androidConsoleToolbar = toolbar;
                androidConsoleWindowManager = windowManager;
                androidConsoleWindowParams = consoleWindowParams;
                androidConsolePopup = consolePopup;
                globalThis.androidConsoleControls = controls;
                globalThis.androidConsoleWatcher = field;
                globalThis.androidNameWatcher = nameField;
                globalThis.androidConsoleLayout = consoleLayout;
                log('Android console/custom-name Java IME bridge installed');
            } catch (e) {
                androidTextBridgeInstalled = false;
                error('Android text input UI installation failed:', e);
                setTimeout(installAndroidTextInputUi, 1000);
            }
        });
    });

    // Watch native state without mutating it. All writes are queued into the
    // two game-thread hooks above.
    if (globalThis.androidTextInputWatchdog) return;
    globalThis.androidTextInputWatchdog = setInterval(() => {
        try {
            const native = getAndroidNativeTextLayout();
            const consoleOpen = isAndroidConsoleNativeOpen(native);
            if (consoleOpen && !androidConsoleVisible) activateAndroidConsoleUi();
            else if (!consoleOpen && androidConsoleVisible) deactivateAndroidConsoleUi();

            // SDL owns the actual Android text connection, so the preview is
            // display-only and must be refreshed from native memory. This
            // also covers text committed by IMEs that do not dispatch a
            // useful Java Editable update (common on Android 8/9).
            if (consoleOpen && androidConsoleVisible && androidConsoleField &&
                !globalThis.androidConsolePreviewSyncPending) {
                const preview = androidConsolePreviewFromNative(native);
                if (preview.value !== androidConsolePreviewRendered ||
                    preview.selection !== androidConsolePreviewRenderedSelection) {
                    globalThis.androidConsolePreviewSyncPending = true;
                    Java.scheduleOnMainThread(() => {
                        try {
                            if (androidConsoleVisible) {
                                setAndroidConsoleField(
                                    preview.value,
                                    preview.selection
                                );
                            }
                        } finally {
                            globalThis.androidConsolePreviewSyncPending = false;
                        }
                    });
                }
            }

            const editor = native.activeEditor.readPointer();
            androidActiveNameEditor = editor;
            if (!androidNameField) return;
            if (!editor || editor.isNull() || consoleOpen) {
                if (androidLastNameEditor && !androidLastNameEditor.isNull()) {
                    androidLastNameEditor = NULL;
                    Java.scheduleOnMainThread(() => hideAndroidKeyboard(androidNameField));
                }
                return;
            }
            if (!androidLastNameEditor || androidLastNameEditor.isNull() ||
                !androidLastNameEditor.equals(editor)) {
                androidLastNameEditor = editor;
                const buffer = editor.add(native.editorTextOffset).readPointer();
                const current = readAndroidUtf8Buffer(buffer, 39);
                Java.scheduleOnMainThread(() => {
                    androidNameUiSyncing = true;
                    const JString = Java.use('java.lang.String');
                    androidNameField.setText(JString.$new(current.value));
                    androidNameField.setSelection(current.value.length);
                    androidNameUiSyncing = false;
                    // main_btn_edit_focus has already opened SDL's Android
                    // keyboard client. Do not steal focus with the helper
                    // EditText: committed UTF-8 now comes through the native
                    // SDL_TEXTINPUT bridge above.
                });
                log('Android custom-name IME activated');
            }
        } catch (e) {
            warn('Android text input watchdog failed:', e);
        }
    }, 100);
}

// Translate strings which the Android executable assembles after the normal
// DeathForth/i18n pass. The two APK ABIs contain the same logic at different
// RVAs, so every context-sensitive hook is described for arm64 and armv7.
function installAndroidHardcodedTranslations() {
    if (Process.platform !== 'linux' || !globalThis.isAndroid ||
        globalThis.androidHardcodedTranslationsInstalled) return;
    globalThis.androidHardcodedTranslationsInstalled = true;

    if (globalThis.build_stamp !== 'MAY-04-2023.09.30') {
        warn('Android hardcoded translations skipped for unknown build:',
            globalThis.build_stamp);
        return;
    }
    if (Process.arch !== 'arm64' && Process.arch !== 'arm') {
        warn('Android hardcoded translations skipped for unsupported ABI:',
            Process.arch);
        return;
    }

    const base = globalThis.mainModule.base;
    const arm64 = Process.arch === 'arm64';
    const buttonTextOffset = 200;
    const layout = arm64 ? {
        customEmpty: [0x3FB34, 1068],
        buddyRenderer: 0x84288,
        carSiphon: [0x8C960, 1180],
        junkPickup: [0x8D9A8, 748],
        equipment: [0xFBB90, 2164],
        teamLoot: [0xFC844, 716],
        pauseLoot: [0x100A94, 892],
        role: [0x102468, 276],
        dragLocked: [0x10CEA8, 156]
    } : {
        customEmpty: [0x2CF88, 768],
        buddyRenderer: 0x63BEE,
        carSiphon: [0x6A8F0, 868],
        junkPickup: [0x6B5D0, 566],
        equipment: [0xC1EB8, 1612],
        teamLoot: [0xC2974, 512],
        pauseLoot: [0xC5C0C, 646],
        role: [0xC6DDC, 186],
        dragLocked: [0xCD7D0, 104]
    };

    const functionAddress = rva => {
        const address = base.add(rva);
        return arm64 ? address : address.or(1);
    };
    const normalizedAddress = address => arm64
        ? address
        : address.and(ptr('0xfffffffe'));
    const within = (address, range) => {
        const value = normalizedAddress(address);
        const start = base.add(range[0]);
        return value.compare(start) >= 0 &&
            value.compare(start.add(range[1])) < 0;
    };
    const chineseEnabled = () => globalThis.language === 'zh';
    const translated = key => LANG[key] || key;

    function replaceButtonText(button, keys) {
        if (!chineseEnabled() || !button || button.isNull()) return;
        const field = button.add(buttonTextOffset);
        const source = field.readPointer();
        if (!source || source.isNull()) return;
        const text = readMixedUtf8String(source);
        const key = keys.find(candidate => text === candidate);
        if (!key) return;
        field.writePointer(L(translated(key)));
    }

    // Static page titles, including the runtime counters on custom-character
    // SAVE/LOAD pages.
    Interceptor.attach(findSymbol('main_common_page_setup'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull()) return;
            try {
                const text = readMixedUtf8String(args[0]);
                if (LANG_STR[text]) {
                    args[0] = L(text);
                    return;
                }
                const match = text.match(
                    /^(SAVE|LOAD) - USED (\d+)\/(\d+) - PAGE (\d+)\/(\d+)$/
                );
                if (!match) return;
                const operation = match[1] === 'LOAD'
                    ? (LANG['LOAD'] || LANG['Load'] || 'LOAD')
                    : (LANG['SAVE'] || 'SAVE');
                const output = `${operation} - ${LANG['USED'] || 'USED'} ` +
                    `${match[2]}/${match[3]} - ${LANG['PAGE'] || 'PAGE'} ` +
                    `${match[4]}/${match[5]}`;
                // main_common_page_setup stores this pointer in UI state, so
                // retain dynamic strings in L() beyond the hook invocation.
                this.androidTranslatedTitle = L(output);
                args[0] = this.androidTranslatedTitle;
            } catch (e) {
                error('Android page-title translation failed:', e);
            }
        }
    });

    // The touch-controls preview uses game_label rather than button_ex.
    Interceptor.attach(findSymbol('game_label'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull()) return;
            try {
                const text = readByteString(args[0]);
                if (text && LANG_STR[text]) args[0] = L(text);
            } catch (e) {
                error('Android touch-control label translation failed:', e);
            }
        }
    });

    // The custom-character name is already UTF-8 here, so translate the
    // completed prompt instead of changing its native format globally.
    Interceptor.attach(findSymbol('cyoa_yesno'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull()) return;
            try {
                const text = readMixedUtf8String(args[0]);
                const match = text.match(/^DELETE existing '(.+)' character\?$/);
                if (!match) return;
                this.androidDeletePrompt = L(
                    `删除现有角色“${match[1]}”?`
                );
                args[0] = this.androidDeletePrompt;
            } catch (e) {
                error('Android custom-character delete translation failed:', e);
            }
        }
    });

    // mission.df appends the heading, count and suffix separately.
    Interceptor.attach(findSymbol('cyoa_append_text'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull()) return;
            try {
                const text = readByteString(args[0]);
                if (text && LANG_STR[text]) args[0] = L(text);
            } catch (e) {
                error('Android mission-summary translation failed:', e);
            }
        }
    });

    // "empty" is intentionally context-sensitive: a custom-character slot is
    // 空人物栏, while an exhausted wreck means 没油了.
    Interceptor.attach(findSymbol('thing_report_ex'), {
        onEnter(args) {
            if (!chineseEnabled() || args[1].isNull()) return;
            try {
                const text = readMixedUtf8String(args[1]);
                if (within(this.returnAddress, layout.carSiphon) &&
                    (text === 'empty' || text === translated('empty'))) {
                    args[1] = L('car siphon empty');
                } else if (within(this.returnAddress, layout.junkPickup) &&
                    text === 'junk.') {
                    args[1] = L('junk.');
                }
            } catch (e) {
                error('Android map-report translation failed:', e);
            }
        }
    });

    // team_char_loot_panel builds the whole black-panel buffer before calling
    // plot_text_wrapped_ex. Scope by the owning function instead of the direct
    // return address because this build reaches the plotter through helpers.
    const teamLootThreads = new Map();
    for (const range of [layout.teamLoot, layout.pauseLoot]) {
        Interceptor.attach(functionAddress(range[0]), {
            onEnter() {
                const tid = Process.getCurrentThreadId();
                teamLootThreads.set(tid, (teamLootThreads.get(tid) || 0) + 1);
                this.androidTeamLootTid = tid;
            },
            onLeave() {
                const tid = this.androidTeamLootTid;
                const depth = (teamLootThreads.get(tid) || 1) - 1;
                if (depth > 0) teamLootThreads.set(tid, depth);
                else teamLootThreads.delete(tid);
            }
        });
    }

    // Replacing every whole-word "nothing" covers both the car header and all
    // members. The Android formatter emits the heading both with and without
    // a colon depending on the loaded DeathForth data.
    Interceptor.attach(findSymbol('plot_text_wrapped_ex'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull() ||
                !teamLootThreads.get(Process.getCurrentThreadId())) return;
            try {
                const text = readMixedUtf8String(args[0]);
                const output = text
                    .replace(/LOOT in the car:?/g, '车内资源：')
                    .replace(/\bnothing\b/g, translated('nothing'));
                if (output === text) return;
                this.androidTeamLootText = L(output);
                args[0] = this.androidTeamLootText;
            } catch (e) {
                error('Android team-loot translation failed:', e);
            }
        }
    });

    // Stat-change blurbs are completed native buffers at this point.
    Interceptor.attach(findSymbol('team_set_last_blurb_text'), {
        onEnter(args) {
            if (!chineseEnabled() || args[0].isNull()) return;
            try {
                const text = readMixedUtf8String(args[0]);
                const output = text.replace(/\b(increases|decreases|revealed)\b/g,
                    word => translated(word));
                if (output === text) return;
                this.androidStatBlurb = L(output);
                args[0] = this.androidStatBlurb;
            } catch (e) {
                error('Android stat-blurb translation failed:', e);
            }
        }
    });

    // Late button labels are written after button_ex, so intercept their final
    // renderer and alter only the verified owning context.
    Interceptor.attach(functionAddress(layout.buddyRenderer), {
        onEnter(args) {
            try {
                replaceButtonText(args[0], ['No buddy', 'With buddy']);
            } catch (e) {
                error('Android starting-buddy translation failed:', e);
            }
        }
    });
    Interceptor.attach(findSymbol('main_btn_image_wrap'), {
        onEnter(args) {
            if (!within(this.returnAddress, layout.customEmpty)) return;
            try { replaceButtonText(args[0], ['empty']); }
            catch (e) { error('Android custom empty-slot translation failed:', e); }
        }
    });
    Interceptor.attach(findSymbol('main_btn_framed'), {
        onEnter(args) {
            try {
                if (within(this.returnAddress, layout.equipment)) {
                    if (!chineseEnabled() || args[0].isNull()) return;
                    const field = args[0].add(buttonTextOffset);
                    if (readMixedUtf8String(field.readPointer()) === 'NONE')
                        field.writePointer(L('equipment slot none'));
                } else if (within(this.returnAddress, layout.dragLocked)) {
                    replaceButtonText(args[0], [
                        '\uE0F2\uE0F7DRAG LOCKED', 'DRAG LOCKED'
                    ]);
                }
            } catch (e) {
                error('Android late framed-button translation failed:', e);
            }
        }
    });
    Interceptor.attach(findSymbol('main_btn_wrap'), {
        onEnter(args) {
            if (!within(this.returnAddress, layout.role)) return;
            try { replaceButtonText(args[0], Array.from(IOS_ROLE_DESCRIPTIONS)); }
            catch (e) { error('Android role-description translation failed:', e); }
        }
    });

    log(`Android ${Process.arch} hardcoded translation hooks installed`);
}

function hookAndroidTextFeatures() {
    if (Process.platform !== 'linux' || !globalThis.isAndroid ||
        globalThis.androidTextFeaturesInstalled) return;
    globalThis.androidTextFeaturesInstalled = true;
    if (globalThis.build_stamp !== 'MAY-04-2023.09.30') {
        warn('Android text features skipped for unknown build:', globalThis.build_stamp);
        return;
    }
    try { installAndroidConsoleNativePump(); }
    catch (e) { error('Android console native bridge failed:', e); }
    try { installAndroidCustomNameNativeBridge(); }
    catch (e) { error('Android custom-name native bridge failed:', e); }
    try { installAndroidTeamNameDisplayHook(); }
    catch (e) { error('Android Team name display hook failed:', e); }
    try { installAndroidPersistentConsoleButton(); }
    catch (e) { error('Android persistent console button failed:', e); }
    try { installAndroidHardcodedTranslations(); }
    catch (e) { error('Android hardcoded translations failed:', e); }
    setTimeout(installAndroidTextInputUi, 750);
}

function hook() {
    if (Process.platform === 'darwin')
        globalThis.__DR2C_BOOT_STAGE__ = 'hook entered';
    var START = '\uE0F5\uE0FB\uE0E7\uE0F0\uE0FC  START  \uE0F5\uE0FB\uE0E7\uE0FC';
    const containsAsciiStart = (text) => {
        if (text.isNull()) return false;
        const needle = [0x53, 0x54, 0x41, 0x52, 0x54];
        for (let i = 0; i < 64; i++) {
            const b = text.add(i).readU8();
            if (b === 0) return false;
            if (b !== needle[0]) continue;
            let match = true;
            for (let j = 1; j < needle.length; j++) {
                if (text.add(i + j).readU8() !== needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    };
    const button_ex = new NativeFunction(findSymbol('button_ex'), 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']);
    const langCallback = new NativeCallback(() => {
        const main_trigger_event = new NativeFunction(findSymbol('main_trigger_event'), 'int', ['int']);
        const main_tabscreen_start = new NativeFunction(findSymbol('main_tabscreen_start'), 'int', []);
        const main_push_popup_state = new NativeFunction(findSymbol('main_push_popup_state'), 'int', ['pointer']);
        main_trigger_event(11);
        main_tabscreen_start();
        main_push_popup_state(LangLayout);
        return 1;
    }, 'uint', []);
    if (Process.platform === 'darwin')
        globalThis.__DR2C_LANG_CALLBACK_PTR__ = langCallback;
    if (globalThis.__DR2C_EARLY_BUTTON_REPLACEMENT__) {
        // The standalone bootstrap must own button_ex early enough to create
        // Mods, so publish translation back into that retained replacement.
        globalThis.__DR2C_TRANSLATE_BUTTON_TEXT__ = text => {
            if (!text || text.isNull()) return text;
            const str = readByteString(text);
            return str && LANG_STR[str] ? L(str) : text;
        };
        info('iOS autonomous early Mods hook retained');
        globalThis.__DR2C_BOOT_STAGE__ = 'early hook retained';
    } else {
        Interceptor.replace(button_ex, new NativeCallback(function (a1, a2, a3, a4, a5) {
            let str = null;
            let buttonText = a4;
            if (!a4.isNull()) {
                str = readByteString(a4);
                if (Process.platform === 'darwin' && str && LANG_STR[str])
                    buttonText = L(str);
            }

            const ret = button_ex(a1, a2, a3, buttonText, a5);
            if (a4.isNull()) return ret;

            if (str === START || a4.equals(L(START))
                || (Process.platform === 'darwin' && containsAsciiStart(a4))) {
                const btn = button_ex(a1, a2 - 1, 0, L("Mods"), findSymbol('main_btn_data_func'));
                setOnClickListenerEx(btn, modCallback);
            }

            if (str === 'Fast Text' || a4.equals(L('Fast Text'))) {
                const btn = button_ex(a1, a2 + 2, 0, L("Language"), findSymbol('main_btn_data_func'));
                setOnClickListenerEx(btn, langCallback);
            }
            return ret;
        }, 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']));
    }

    if (Process.platform === 'darwin'
        && !globalThis.iosNativeConsoleButtonHooksInstalled) {
        globalThis.iosNativeConsoleButtonHooksInstalled = true;

        const buttonsCount = new NativeFunction(findSymbol('buttons_count'), 'int', []);
        const buttonSetW = new NativeFunction(findSymbol('button_set_w'), 'void', ['pointer', 'float']);
        const buttonSetH = new NativeFunction(findSymbol('button_set_h'), 'void', ['pointer', 'float']);
        const madW = new NativeFunction(findSymbol('mad_w'), 'float', []);
        const madH = new NativeFunction(findSymbol('mad_h'), 'float', []);
        // Keep the persistent button readable before a translation mod has
        // installed the UTF-8 renderer. The full-width tilde is three UTF-8
        // bytes and the stock 1.32 glyph path renders each byte as an icon.
        const consoleText = L('~');
        let consoleButtonId = -1;
        let consoleButtonValid = false;
        // main_btn_data_func adds the opaque menu frame and also dispatches
        // +256, so bypassing it removes both behaviours. Delegate drawing to
        // the common unframed path and handle the native click event directly
        // here instead.
        const mainBtnUnframedBase = new NativeFunction(
            globalThis.mainModule.base.add(0x7D240),
            'uint',
            ['pointer', 'int']
        );
        // button_ex stores its normal drawing/action function at +248 on
        // arm64. The game's click listener is a separate pointer at +256,
        // which is the same mechanism already used by the native Mods button.
        const openIOSConsoleFromNativeButton = () => {
            if (Date.now() < iosConsoleSuppressNativeButtonUntil) {
                return 1;
            }
            try {
                setIOSConsoleOpen(!iosConsoleOpen);
            } catch (e) {
                error('iOS native console button failed:', e);
            }
            return 1;
        };
        globalThis.iosNativeConsoleButtonClick = new NativeCallback(
            openIOSConsoleFromNativeButton,
            'uint',
            []
        );
        globalThis.iosNativeConsoleButtonFunc = new NativeCallback(
            (btn, event) => {
                const result = mainBtnUnframedBase(btn, event);
                if (event === 3) return openIOSConsoleFromNativeButton();
                return result;
            },
            'uint',
            ['pointer', 'int']
        );
        function appendIOSNativeConsoleButton() {
            const width = madW();
            const height = madH();
            if (!(width > 0) || !(height > 0)) return;

            consoleButtonId = buttonsCount();
            const btn = button_ex(
                0.0,
                0.0,
                0,
                consoleText,
                globalThis.iosNativeConsoleButtonFunc
            );
            if (btn.isNull()) return;

            // Keep it below the game's upper-right status icon and make it
            // slightly smaller than the former 44x36 UIKit control. Fractions
            // keep the SDL and UIKit hit boxes aligned regardless of Retina
            // scale or orientation.
            const buttonWidth = width * 0.045;
            const buttonHeight = height * 0.065;
            const centerX = width * 0.95;
            const centerY = height * 0.24;
            buttonSetW(btn, buttonWidth);
            buttonSetH(btn, buttonHeight);
            btn.add(16).writeFloat(centerX);
            btn.add(20).writeFloat(centerY);
            // Match the original iOS touch-control transparency slider at a
            // fixed value of 100: alpha = 1 - 100 / 110 = 1/11. Apply it to
            // every native button colour state so press/highlight/disabled
            // transitions cannot briefly become opaque.
            const touchAlpha100 = 1.0 / 11.0;
            for (const alphaOffset of [60, 76, 92, 108, 124, 140])
                btn.add(alphaOffset).writeFloat(touchAlpha100);
            // Retain +256 for structure compatibility. The unframed +248 path
            // deliberately bypasses main_btn_data_func, so event 3 above is
            // the single active click dispatcher and cannot double-toggle.
            btn.add(256).writePointer(globalThis.iosNativeConsoleButtonClick);
            consoleButtonValid = true;

            globalThis.iosConsoleButtonNormalizedHitBox = {
                left: 0.95 - 0.045 * 0.5,
                right: 0.95 + 0.045 * 0.5,
                top: 0.24 - 0.065 * 0.5,
                bottom: 0.24 + 0.065 * 0.5
            };
            log('iOS native console button installed',
                `${width}x${height}`, `id=${consoleButtonId}`);
        }

        // Page setup clears the native button pool. Appending on the first
        // update after that clear means all state-specific buttons keep their
        // original indices, while this button persists in menus, gameplay and
        // the console state itself.
        Interceptor.attach(findSymbol('buttons_start'), {
            onLeave() {
                consoleButtonId = -1;
                consoleButtonValid = false;
            }
        });
        Interceptor.attach(findSymbol('buttons_reset_to'), {
            onEnter(args) {
                if (consoleButtonValid && args[0].toInt32() <= consoleButtonId)
                    consoleButtonValid = false;
            }
        });
        Interceptor.attach(findSymbol('buttons_update'), {
            onEnter() {
                if (!consoleButtonValid) appendIOSNativeConsoleButton();
            }
        });
    }

    /**
     * @typedef {Object} Mod
     * @property {string} name
     * @property {string} version
     * @property {string} description
     * @property {string} modDir
     */

    let mods_init = false;


    /** @type {Mod[]} */
    let mods = [];


    const modCallback = new NativeCallback(
        () => {
            const main_trigger_event = new NativeFunction(findSymbol('main_trigger_event'), 'int', ['int']);
            const main_tabscreen_start = new NativeFunction(findSymbol('main_tabscreen_start'), 'int', []);
            const main_push_popup_state = new NativeFunction(findSymbol('main_push_popup_state'), 'int', ['pointer']);

            log('modCallback');

            main_trigger_event(11);
            main_tabscreen_start();
            main_push_popup_state(modLayout);

            return 1;
        },
        'uint',  // 返回值: LRESULT
        []
    );

    // The autonomous iOS package installs its tiny button hook before this
    // full bundle is parsed. Publish the real callback once it is ready so
    // that the early native Mods button can hand control to this UI.
    if (Process.platform === 'darwin')
        globalThis.__DR2C_MOD_CALLBACK_PTR__ = modCallback;
    if (Process.platform === 'darwin')
        globalThis.__DR2C_BOOT_STAGE__ = 'mods callback ready';

    const modLayout = new NativeCallback(
        () => {
            const main_tabscreen_reset = new NativeFunction(findSymbol('main_tabscreen_reset'), 'int', []);
            const main_tabscreen_add_tab = new NativeFunction(findSymbol('main_tabscreen_add_tab'), 'int', ['pointer', 'pointer']);
            const main_tabscreen_layout_ex = new NativeFunction(findSymbol('main_tabscreen_layout_ex'), 'int', ['int']);
            const main_tabscreen_set_exitfunc = new NativeFunction(findSymbol('main_tabscreen_set_exitfunc'), 'int', ['pointer']);

            log('modLayout')

            main_tabscreen_reset();
            main_tabscreen_set_exitfunc(ptr(0));
            main_tabscreen_add_tab(L("Mods"), modTabLayout);
            main_tabscreen_layout_ex(1);

            return 1;
        },
        'uint',  // 返回值: LRESULT
        []
    );

    let modPage = 0;
    let modInstallInProgress = false;

    function getIOSInstalledModResourceCategories(modDirectory) {
        const categoryHasEntries = name => {
            try {
                return fs.readdirSync(
                    modDirectory + '/assets/dr2c/' + name
                ).some(entry => entry !== '.' && entry !== '..');
            } catch (_) {
                return false;
            }
        };
        return {
            hasGfx: categoryHasEntries('gfx'),
            hasData: categoryHasEntries('data')
        };
    }

    function activateIOSInstalledMod(modDirectory, resourceCategories) {
        if (Process.platform !== 'darwin') return;

        const {hasGfx, hasData} = resourceCategories
            || getIOSInstalledModResourceCategories(modDirectory);
        info(
            'iOS hot activation resource categories:',
            `gfx=${hasGfx}`,
            `data=${hasData}`
        );

        if (hasGfx || hasData) {
            // GFX atlases and several data tables are process-lifetime caches.
            // Mixing a new Deathforth/LANG with their old contents produces an
            // inconsistent game, while rebuilding the fixed 0x4000-entry
            // sprite table in place is not atomic. Leave the current process
            // completely untouched. The install-success page tells the user
            // to remove the game from the app switcher and reopen it, so the
            // next launch selects this mod before any cache is built.
            info('iOS installed mod contains cached GFX/data; manual process restart required');
            return;
        }

        // All iOS asset/deathforth redirects read mod.dir at call time, so
        // switching this root also updates hooks installed by an earlier mod.
        mod.dir = modDirectory;
        info('iOS hot activation selected mod resources:', mod.dir);

        loadLang();
        hookI18n();
        hookUtf8(true);

        // This is the same one-byte request set by the native sys_reset word.
        // The main update loop consumes it after this callback returns, safely
        // rebuilding Deathforth through the now-active mod file redirects.
        const requestSystemReset = new NativeFunction(
            findSymbol('main_do_sys_reset'),
            'void',
            []
        );
        requestSystemReset();
        info('iOS hot activation requested native sys_reset');
    }

    function refreshModsList() {
        const discovered = [];
        const dirPath = globalThis.modsDir;
        fs.readdirSync(dirPath).forEach(ele => {
            if (ele === '.' || ele === '..') return;
            const fullPath = `${dirPath}/${ele}`;
            const stats = fs.lstatSync(fullPath);
            if (!stats.isDirectory()) return;
            if (Process.platform === 'windows'
                && fullPath === dirPath + '/dr2c-mod-loader') return;
            try {
                const mjson = JSON.parse(File.readAllText(fullPath + '/package.json'));
                if (!mjson.name) throw new Error('Missing name in package.json');
                mjson.modDir = fullPath;
                // UTF-8 glyph rendering is now stable on iOS, so preserve the
                // package metadata instead of replacing non-ASCII text with
                // the temporary diagnostic placeholders used during bring-up.
                mjson.uiName = mjson.name;
                mjson.uiDescription = mjson.description || 'Installed mod package.';
                discovered.push(mjson);
            } catch (e) {
                warn('Skip invalid mod directory: ' + fullPath, e);
            }
        });
        mods = discovered;
        mods_init = true;
        const lastPage = Math.max(0, Math.ceil(mods.length / 6) - 1);
        if (modPage > lastPage) modPage = lastPage;
        log('Mods rescan', mods.length, mods.map(item => item.name).join(', '));
    }

    const modTabLayout = new NativeCallback(
        () => {
            const button_set_layout = new NativeFunction(findSymbol('button_set_layout'), 'int', ['float', 'float']);
            const main_tabscreen_blank_tab_layout = new NativeFunction(findSymbol('main_tabscreen_blank_tab_layout'), 'int', []);
            const main_tabscreen_tabbox_shrink = new NativeFunction(findSymbol('main_tabscreen_tabbox_shrink'), 'int', []);
            const main_btn_data_func = new NativeFunction(findSymbol('main_btn_data_func'), 'int', []);
            const game_lower_box = new NativeFunction(findSymbol('game_lower_box'), 'int', ['pointer']);
            const cyoa_just_ok = new NativeFunction(findSymbol('cyoa_just_ok'), 'int', ['pointer']);
            const cyoa_set_choice_text = new NativeFunction(findSymbol('cyoa_set_choice_text'), 'int', ['pointer']);
            const cyoa_add_choice = new NativeFunction(findSymbol('cyoa_add_choice'), 'int', []);
            const cyoa_set_title = new NativeFunction(findSymbol('cyoa_set_title'), 'int', ['pointer']);
            const cyoa_set_choice_func = new NativeFunction(findSymbol('cyoa_set_choice_func'), 'int', ['pointer']);
            const cyoa_start = new NativeFunction(findSymbol('cyoa_start'), 'int', ['int']);
            const cyoa_hint = new NativeFunction(findSymbol('cyoa_hint'), 'int', []);

            // The Files app may add or extract a mod while the game is
            // running.  Re-scan on every layout instead of caching the first
            // (often empty) result for the lifetime of the process.
            refreshModsList();

            button_set_layout(1.0, 1.0);
            main_tabscreen_blank_tab_layout();
            button_set_layout(2.0, 3.0);
            main_tabscreen_tabbox_shrink();
            mods.slice(0 + modPage * 6, 6 + modPage * 6).forEach((mod, i, array) => {
                const btn = button_ex((i % 6 % 2), Math.floor(i / 2), modPage + i, L((mod.uiName || mod.name) + '-' + mod.version), main_btn_data_func);
                setOnClickListener(btn, () => {
                    log('desc_' + mod.name);
                    const displayName = mod.uiName || mod.name;
                    cyoa_just_ok(L(mod.uiDescription || mod.description));
                    cyoa_set_choice_func(navFun('desc_ok_' + mod.name,
                        () => {
                            log('desc_ok_' + mod.name);
                            return 1;
                        }
                    ));
                    cyoa_add_choice();
                    cyoa_set_choice_func(navFun('desc_update_' + mod.name,
                        () => {
                            log('desc_update_' + mod.name);
                            return 1;
                        }
                    ));
                    cyoa_set_choice_func(navFun('desc_delete_' + mod.name,
                        () => {
                            log('desc_delete_' + mod.name);

                            cyoa_just_ok(L(`Delete the mod '${displayName}'?`));
                            cyoa_set_choice_func(navFun('desc_delete_confirm_no_' + mod.name,
                                () => {
                                    return 1;
                                }
                            ));
                            cyoa_set_choice_text(L("NO"));
                            cyoa_add_choice();
                            cyoa_set_choice_func(navFun('desc_delete_confirm_delete_' + mod.name,
                                () => {
                                    const target = mod.modDir;
                                    try {
                                        if (!target) throw new Error('Installed mod has no directory record');
                                        rmrfSync(target);
                                        try {
                                            fs.lstatSync(target);
                                            throw new Error('Directory still exists after deletion');
                                        } catch (e) {
                                            if (e && e.message === 'Directory still exists after deletion') throw e;
                                        }
                                        log('Deleted installed mod:', mod.name, target);
                                        refreshModsList();
                                        new NativeFunction(modLayout, 'int', [])();
                                    } catch (e) {
                                        error('Delete mod failed:', mod.name, target, e);
                                        cyoa_just_ok(L('Unable to delete this mod. Check mod.log.'));
                                        cyoa_set_title(L('DELETE FAILED'));
                                    }
                                    return 1;
                                }
                            ));
                            cyoa_set_choice_text(L("DELETE"));
                            cyoa_set_title(L("DELETE"));

                            return 1;
                        }
                    ));
                    cyoa_set_choice_text(L("DELETE"));
                    cyoa_set_title(L(displayName + '-' + mod.version));
                    return 1;
                });
            });
            const box = Memory.alloc(28 * 2);
            game_lower_box(box);
            button_set_layout(7.0, 1.0);

            const btn_l = button_ex(0.0, 0.0, -1, L("L"), main_btn_data_func);
            setOnClickListener(btn_l, () => {
                modPage--;
                if (modPage < 0) {
                    modPage = Math.floor(mods.length / 6);
                }
                log('btn_L', modPage);
                new NativeFunction(modLayout, 'int', [])();
                return 1;
            });
            const btn_R = button_ex(6.0, 0.0, 1, L("R"), main_btn_data_func);
            setOnClickListener(btn_R,
                () => {

                    modPage++;
                    if (modPage > mods.length / 6) modPage = 0;
                    log('btn_R', modPage)
                    new NativeFunction(modLayout, 'int', [])();
                    return 1;
                }
            );

            button_set_layout(3.0, 1.0);
            const btn_install = button_ex(1.0, 0.0, 0, L("Install Mod From File"), main_btn_data_func);
            setOnClickListener(btn_install,
                async () => {
                    if (modInstallInProgress) {
                        warn('btn_install', 'Installation already in progress.');
                        return 0;
                    }
                    modInstallInProgress = true;
                    try {

                    info('btn_install');
                    let path1;
                    try {
                        path1 = await filedialog();
                    } catch (e) {
                        if (!(e instanceof Error) || e.message !== 'No file selected')
                            error('iOS file selection failed:', e);
                        return 0;
                    }
                    log('selected', JSON.stringify(path1));
                    if (!path1) return;

                    cyoa_just_ok(L('Install Mod Working.'));
                    cyoa_set_title(L('WAITING'));

                    try {
                        const data1 = File.readAllBytes(path1);

                        const zip = await JSZip.loadAsync(data1);


                        const fmod = zip.file('package.json');
                        if (fmod) {
                            if (!fmod) throw new Error("Failed to find package.json");
                            const s1 = await fmod.async('text');

                            /** @type {Mod} */
                            const mod = JSON.parse(s1);
                            if (!mod["name"]) throw new Error('Failed to find name property from package.json');


                            const delMods = mods.filter(item => item.name === mod.name);
                            for (const delMod of delMods) {
                                rmrfSync(delMod.modDir);
                            }

                            const installDirName = getInstalledModDirectoryName(mod.name);
                            const mdir = globalThis.modsDir + '/' + installDirName;
                            if (Process.platform === 'windows' && installDirName !== mod.name)
                                log('Windows mod installed in ASCII resource directory:', installDirName);
                            fs.mkdirSync(mdir);

                            File.writeAllText(`${mdir}/package.json`, s1);

                            const jsfile = zip.file('index.js');
                            if (jsfile)
                                File.writeAllText(`${mdir}/index.js`, await jsfile.async('text'));

                            const mainfile = zip.file('main.js');
                            if (mainfile)
                                File.writeAllText(`${mdir}/main.js`, await mainfile.async('text'));

                            for (const path of Object.keys(zip.files)) {
                                const entry = zip.files[path];
                                if (path.startsWith('assets/')) {
                                    if (entry.dir) {
                                        fs.mkdirSync(mdir + '/' + path.slice(0, -1));
                                    } else {
                                        const data = await entry.async('array');
                                        File.writeAllBytes(mdir + '/' + path, data);
                                    }
                                }
                            }

                            mods = mods.filter(item => item.name !== mod.name);
                            mods.push(mod);
                            mod.modDir = mdir;

                            const iosResourceCategories = Process.platform === 'darwin'
                                ? getIOSInstalledModResourceCategories(mdir)
                                : null;
                            // Scripts, language files and game assets are
                            // all read during boot.  A copied package becomes
                            // active only after the game is reopened.
                            cyoa_just_ok(L(
                                '模组安装完成。请完全关闭并重新打开游戏。\n'
                                + 'Install complete. Fully close and reopen the game.'
                            ));
                            cyoa_set_title(L('需要重启 RESTART REQUIRED'));
                            info(
                                'Mod install complete; restart required',
                                iosResourceCategories
                                    ? `gfx=${iosResourceCategories.hasGfx}, data=${iosResourceCategories.hasData}`
                                    : 'non-iOS platform'
                            );
                        } else {
                            const tdir = mod.dir + '/assets/dr2c';

                            rmrfSync(tdir);

                            fs.mkdirSync(tdir);

                            for (const path of Object.keys(zip.files)) {
                                const entry = zip.files[path];
                                if (path.startsWith('data/') || path.startsWith('deathforth/') || path.startsWith('gfx/')) {
                                    if (entry.dir) {
                                        fs.mkdirSync(tdir + '/' + path.slice(0, -1));
                                    } else {
                                        const data = await entry.async('array');
                                        File.writeAllBytes(tdir + '/' + path, data);
                                    }
                                }
                            }

                            cyoa_just_ok(L(
                                '模组安装完成。请完全关闭并重新打开游戏。\n'
                                + 'Install complete. Fully close and reopen the game.'
                            ));
                            cyoa_set_title(L('需要重启 RESTART REQUIRED'));
                        }
                    } catch (e) {
                        if (e instanceof Error) {
                            error(e.stack);
                            if (e.message !== 'No file selected') {
                                cyoa_just_ok(L('Invalid mod detected. error: ' + e.stack));
                                cyoa_set_title(L('INSTALL MOD FAIL'));
                            }
                        } else {
                            cyoa_just_ok(L('Invalid mod detected. unknown error'));
                            cyoa_set_title(L('INSTALL MOD FAIL'));
                        }

                    }
                    return 0;
                    } finally {
                        modInstallInProgress = false;
                    }
                }
            );
            return 0;
        },
        'uint',  // 返回值: LRESULT
        []
    );

    const LangLayout = new NativeCallback(
        () => {
            const button_set_layout = new NativeFunction(findSymbol('button_set_layout'), 'int', ['float', 'float']);
            const main_tabscreen_blank_tab_layout = new NativeFunction(findSymbol('main_tabscreen_blank_tab_layout'), 'int', []);
            const main_tabscreen_tabbox_shrink = new NativeFunction(findSymbol('main_tabscreen_tabbox_shrink'), 'int', []);
            const main_btn_data_func = new NativeFunction(findSymbol('main_btn_data_func'), 'int', []);
            const game_lower_box = new NativeFunction(findSymbol('game_lower_box'), 'int', ['pointer']);
            const cyoa_just_ok = new NativeFunction(findSymbol('cyoa_just_ok'), 'int', ['pointer']);
            const cyoa_set_choice_text = new NativeFunction(findSymbol('cyoa_set_choice_text'), 'int', ['pointer']);
            const cyoa_add_choice = new NativeFunction(findSymbol('cyoa_add_choice'), 'int', []);
            const cyoa_set_title = new NativeFunction(findSymbol('cyoa_set_title'), 'int', ['pointer']);
            const cyoa_set_choice_func = new NativeFunction(findSymbol('cyoa_set_choice_func'), 'int', ['pointer']);
            const cyoa_start = new NativeFunction(findSymbol('cyoa_start'), 'int', ['int']);
            const cyoa_hint = new NativeFunction(findSymbol('cyoa_hint'), 'int', []);
            const cyoa_yesno = new NativeFunction(findSymbol('cyoa_yesno'), 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            const main_common_page_setup = new NativeFunction(findSymbol('main_common_page_setup'), 'int', ['pointer', 'int']);

            main_common_page_setup(L('Change Language'), 0);
            button_set_layout(1.0, 1.0);
            main_tabscreen_blank_tab_layout();
            button_set_layout(4.0, 6.0);

            const path = mod.dir + '/assets/lang.json';
            const jsonStr = File.readAllText(path);
            const json = JSON.parse(jsonStr);
            const langs = Object.keys(json['string_literal']);

            langs.forEach((lang, i, array) => {
                const btn = button_ex((i % 4), Math.floor(i / 4), i, L(lang + '.Language.Name'), main_btn_data_func);
                setOnClickListener(btn, () => {

                    cyoa_yesno(L(LANG['Change Language to '] + LANG[lang + '.Language.Name'] + '?'), L('YES'), L('NO'),
                        navFun('', (ptr) => {
                            if (ptr instanceof NativePointer) {
                                const yes = ptr.add(80).readInt();
                                if (yes) {
                                    loadLangEx(lang, true);
                                }
                            }
                        }, 'void', ['pointer'])
                    );
                    cyoa_add_choice();
                    cyoa_set_choice_func(navFun('desc_delete_confirm_delete_' + mod.name,
                        () => {
                            cyoa_just_ok(L(lang + '.Language.Contributors.List'))
                            return 1;
                        }
                    ));
                    cyoa_set_choice_text(L("Contributors List"));
                });
            });
            return 0;
        },
        'uint',  // 返回值: LRESULT
        []
    );

    if (Process.platform === 'darwin') {
        // console_update is included in the autonomous gum-graft manifest, so
        // the keyboard queue can be drained on the game thread in both debug
        // and strict standalone builds.
        hookIOSConsoleInputPump();
        setTimeout(installIOSConsoleOverlay, 750);
        // The editable-string handler at 0x81f34 is grafted in the standalone
        // package as well, so character naming can use the same full UITextInput
        // bridge (including marked-text Pinyin input) outside debug mode.
        setTimeout(installIOSGameTextInputBridge, 750);
    } else if (Process.platform === 'windows') {
        hookWindowsConsoleUtf8Input();
        hookWindowsCustomNameUtf8Input();
        hookWindowsMouseCursorWake();
        hookWindowsTeamLootNameDisplay();
        hookWindowsLateMenuTranslations();
    } else if (Process.platform === 'linux' && globalThis.isAndroid) {
        hookAndroidTextFeatures();
    }
    info('hook inited');
}

// ── 初始化 ────────────────────────────────────────────────────────────────────
function hookUtf8(lateActivation = false) {
    if (Process.platform === 'darwin' && globalThis.iosUtf8HooksInstalled) {
        if (lateActivation && globalThis.iosRequestLateFontAtlasInit)
            globalThis.iosRequestLateFontAtlasInit();
        log('iOS UTF-8 hooks already installed');
        return;
    }
    if (Process.platform === 'darwin')
        globalThis.iosUtf8HooksInstalled = true;

    /** @type {NativePointer} */
    const load_gfx = globalThis.load_gfx;
    const IOS_MAIN_ATLAS = Process.platform === 'darwin'
        ? globalThis.mainModule.base.add(0x415238)
        : NULL;


    // ── （NativeFunction） ─────────────────────────────────────────

    const SPRITE_GET_PTR = findSymbol('sprite_get');
    const SPRITE_GET = new NativeFunction(SPRITE_GET_PTR, 'pointer', ['int16']);
    const TURTLE_TRANS = new NativeFunction(findSymbol('turtle_trans'), 'void', ['double', 'double']);
    const ATLAS_GET = new NativeFunction(findSymbol('atlas_get'), 'pointer', ['int']);
    const ATLAS_UPLOAD_PTR = findSymbol('atlas_upload');
    const ATLAS_UPLOAD = new NativeFunction(ATLAS_UPLOAD_PTR, 'int', ['pointer', 'int', 'int']);
    const WRAPPER_SET_TITLE = Process.platform === 'darwin'
        ? () => { }
        : new NativeFunction(findSymbol('wrapper_set_window_title'), 'void', ['pointer']);
    const WRAPPER_FILE_DATA_PATH = new NativeFunction(findSymbol('wrapper_file_data_path'), 'pointer', []);
    const FILE_DATA_PATH = new NativeFunction(findSymbol('file_data_path'), 'pointer', ['pointer']);
    const FILE_OPEN_DATA_READ_PTR = findSymbol('file_open_data_read');
    const FILE_OPEN_DATA_READ = new NativeFunction(FILE_OPEN_DATA_READ_PTR, 'pointer', ['pointer']);
    const FILE_OPEN_D = Process.platform === 'darwin'
        ? new NativeFunction(findSymbol('file_open_d'), 'pointer', ['pointer', 'int'])
        : null;
    const ATLAS_LOAD_SPRITESHEET = new NativeFunction(findSymbol('atlas_load_spritesheet'), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int', 'pointer']);
    const SPRITE_COUNT = new NativeFunction(findSymbol('sprite_count'), 'int', []);
    const SPRITE_BATCH_PLOT_PTR = findSymbol('sprite_batch_plot');
    const SPRITE_BATCH_PLOT = new NativeFunction(SPRITE_BATCH_PLOT_PTR, 'void', ['pointer', 'int', 'int']);
    const SPRITE_BATCH_DRAW_PTR = findSymbol('sprite_batch_draw');
    const SPRITE_BATCH_DRAW = new NativeFunction(SPRITE_BATCH_DRAW_PTR, 'void', ['pointer']);
    const TURTLE_SET_SCALE = new NativeFunction(findSymbol('turtle_set_scale'), 'void', ['double']);
    const TURTLE_SET_SCALEX = new NativeFunction(findSymbol('turtle_set_scalex'), 'void', ['double']);
    const TURTLE_SET_SCALEY = new NativeFunction(findSymbol('turtle_set_scaley'), 'void', ['double']);
    const GLYPHS_SET_CALLBACK = new NativeFunction(findSymbol('glyphs_set_callback'), 'void', ['pointer', 'pointer']);
    const GLYPHS_BATCH_PLOT_EX_PTR = findSymbol('glyphs_batch_plot_ex');
    const GLYPHS_BATCH_PLOT_EX = new NativeFunction(GLYPHS_BATCH_PLOT_EX_PTR, 'int', ['pointer', 'pointer', 'int', 'int', 'int']);
    const ATLAS_CREATE_TEXTURE = new NativeFunction(findSymbol('atlas_create_texture'), 'pointer', ['pointer', 'int', 'int']);
    const ATLAS_FREE_IMAGE_DATA = new NativeFunction(findSymbol('atlas_free_image_data'), 'void', ['int']);
    const text_w = new NativeFunction(findSymbol('text_w'), 'int', ['pointer']);
    // a2(字体句柄) 反编译为 __int64，用 'pointer' 原样透传避免高位丢失；a4 为跳行首空白开关
    const WRAP_TEXT_EX = new NativeFunction(findSymbol('wrap_text_ex'), 'pointer', ['pointer', 'pointer', 'int', 'int']);
    const GLYPH_W = new NativeFunction(findSymbol('glyph_w'), 'float', ['pointer', 'int']);
    const TURTLE_BASE = findSymbol('turtle');

    // ── 主逻辑 ────────────────────────────────────────────────
    /** @type {NativeFunction<number, [number, number, NativePointer]> | null} */
    let originalGlyphCb = null;
    /** @type {NativePointer} */
    let originalGlyphCtx;
    /** @type {number} */
    let font_base_id;  // 由 load_gfx 中的 hook 初始化
    let load_gfx_hooking = 0;
    // Windows and mobile keep the Unicode font in an independent atlas.
    // Desktop Linux is not part of the supported independent-atlas builds.
    const isAndroidUnicodeRuntime =
        Process.platform === 'linux' && globalThis.isAndroid === true;
    const isWindowsUnicodeRuntime = Process.platform === 'windows';
    const separateFontAtlasEnabled =
        Process.platform === 'darwin' || isAndroidUnicodeRuntime || isWindowsUnicodeRuntime;
    const customFontAtlasEnabled = true;
    const customGlyphRemapEnabled = true;
    // Use JavaScript null for the not-yet-created state. Frida's NULL is a
    // NativePointer object and is therefore truthy even though its address is 0.
    let unifont = null;
    let iosFontAtlas = null;
    let unifont_x = 0;
    let unifont_y = 0;
    const IOS_UNICODE_CELL_SIZE = 12;
    const IOS_UNICODE_ADVANCE = 8;
    const IOS_UNICODE_SCALE = IOS_UNICODE_ADVANCE / IOS_UNICODE_CELL_SIZE;
    const IOS_UNICODE_ATLAS_SIZE = IOS_UNICODE_CELL_SIZE * 256;
    // Windows uses a PC-only padded grid. Some desktop GPU/driver combinations
    // sample half a texel beyond an integer sprite rectangle while shrinking a
    // 12px glyph to an 8px advance. A one-pixel edge-extruded gutter on all
    // four sides prevents a neighbouring glyph row from appearing as a fine
    // line without fading glyph edges toward transparency.
    // Mobile retains its already verified tightly packed 12×12 atlas.
    const GENERIC_UNICODE_CELL_SIZE = IOS_UNICODE_CELL_SIZE;
    const GENERIC_UNICODE_ADVANCE = IOS_UNICODE_ADVANCE;
    const GENERIC_UNICODE_SCALE = GENERIC_UNICODE_ADVANCE / GENERIC_UNICODE_CELL_SIZE;
    const GENERIC_UNICODE_CELL_PADDING = isWindowsUnicodeRuntime ? 1 : 0;
    const GENERIC_UNICODE_CELL_STRIDE = GENERIC_UNICODE_CELL_SIZE +
        GENERIC_UNICODE_CELL_PADDING * 2;
    const GENERIC_UNICODE_ATLAS_SIZE = GENERIC_UNICODE_CELL_STRIDE * 256;
    // Android's native sprite sampler needs the Unicode source rectangle one
    // pixel below the atlas cell origin.  Without this offset, some Android
    // GPUs expose the neighbouring texel row as a white line above glyphs.
    // Windows and iOS use their own verified zero-offset sampling paths.
    const GENERIC_UNICODE_Y_OFFSET = isAndroidUnicodeRuntime ? 1 : 0;
    // Sprite pointers temporarily occupied by Unicode glyphs during the
    // current native glyphs_batch_plot_ex call.  Only these sprites receive
    // Android's 8/12 render-time scale; ASCII and UI/effect glyphs keep the
    // game's native Turtle transform.
    const iosScaledGlyphSprites = new Set();
    let glyphDebugRemaining = Process.platform === 'darwin' ? 16 : 0;
    let iosGlyphRemapDebugRemaining = Process.platform === 'darwin' ? 8 : 0;
    function initIOSFontAtlas() {
        if (unifont) return true;
        const fontAtlasIndex = 15;
        const fontAtlas = ATLAS_GET(fontAtlasIndex);
        if (!fontAtlas || fontAtlas.isNull()) {
            warn('Unicode font atlas', `Atlas ${fontAtlasIndex} is unavailable.`);
            return false;
        }
        iosFontAtlas = fontAtlas;
        const fontPath = Memory.allocUtf8String(getUnicodeFontAssetPath());
        log(`Unicode deferred font atlas path: ${fontPath.readCString()}`);

        const imageData = ATLAS_CREATE_TEXTURE(fontAtlas, 4096, 4096);
        if (imageData.isNull()) {
            warn('Unicode font atlas', 'Failed to allocate deferred font atlas.');
            return false;
        }

        font_base_id = SPRITE_COUNT();
        const loaded = ATLAS_LOAD_SPRITESHEET(
            fontAtlas, 0, GENERIC_UNICODE_ATLAS_SIZE, GENERIC_UNICODE_ATLAS_SIZE, 0, 1, fontPath
        );
        // The Windows renderer needs the same preferred upload format/fallback
        // sequence as its normal atlas. Mobile builds use their established
        // RGBA upload path.
        let uploaded = ATLAS_UPLOAD(fontAtlas, 0, isWindowsUnicodeRuntime ? 3 : 0);
        if (!uploaded && isWindowsUnicodeRuntime)
            uploaded = ATLAS_UPLOAD(fontAtlas, 0, 2) || ATLAS_UPLOAD(fontAtlas, 0, 0);
        ATLAS_FREE_IMAGE_DATA(fontAtlasIndex);
        log(`Unicode deferred font atlas loaded: texture = ${fontAtlas.add(16).readU32()}, base_id = ${font_base_id}, total_sprites = ${SPRITE_COUNT()}, added = ${loaded}, uploaded = ${uploaded}`);

        if (!uploaded || font_base_id === SPRITE_COUNT()) {
            font_base_id = 0;
            return false;
        }
        unifont = SPRITE_GET(font_base_id);
        unifont_x = unifont.readU16();
        unifont_y = unifont.add(2).readU16();
        log(`Unicode deferred font atlas ready: sprite = ${unifont}, origin = ${unifont_x},${unifont_y}`);
        if (globalThis.nativeUnicodeTextState) {
            const state = globalThis.nativeUnicodeTextState;
            state.unifontSlot.writePointer(unifont);
            state.unifontXSlot.writeS32(unifont_x);
            state.unifontYSlot.writeS32(unifont_y);
            state.mainAtlasSlot.writePointer(
                Process.platform === 'darwin' ? IOS_MAIN_ATLAS : ATLAS_GET(0)
            );
            state.fontAtlasSlot.writePointer(fontAtlas);
            log(`${isAndroidUnicodeRuntime ? 'Android' : 'Windows'} native font state READY; ` +
                'independent font atlas 4096²' +
                (isWindowsUnicodeRuntime
                    ? ', edge-extruded 14×14 cells with 12×12 sampling'
                    : ''));
        }
        if (globalThis.iosNativeUnicodeSetFont) {
            globalThis.iosNativeUnicodeSetFont(
                unifont, unifont_x, unifont_y, fontAtlas
            );
            log('iOS signed native font state READY; independent font atlas 4096²');
        }
        return true;
    }

    // Non-strict/debug builds may install hookUtf8 after load_gfx has already
    // returned. Initialize the Unicode texture on a later main-atlas draw in
    // that case. The standalone strict package must not attach this additional
    // sprite_batch_draw listener: it is not present in the gum-graft manifest
    // and iOS rejects it before the validated UTF-8 and file redirect hooks can
    // be installed. Strict builds instead install hookUtf8 before load_gfx, so
    // the existing atlas_upload listener below initializes the font normally.
    let iosLateFontAtlasPending = false;
    if (Process.platform === 'darwin' && !IOS_STRICT_CODE_SIGNING) {
        globalThis.iosRequestLateFontAtlasInit = () => {
            if (unifont || iosLateFontAtlasPending) return;
            iosLateFontAtlasPending = true;
            log('iOS late font atlas initialization requested');
        };
        globalThis.iosLateFontAtlasDrawHook = Interceptor.attach(
            SPRITE_BATCH_DRAW_PTR, {
                onEnter(args) {
                    if (!iosLateFontAtlasPending || unifont ||
                        !args[0].equals(IOS_MAIN_ATLAS)) return;
                    iosLateFontAtlasPending = false;
                    try {
                        if (!initIOSFontAtlas())
                            warn('iOS late font atlas initialization failed; restart remains available');
                    } catch (e) {
                        error('iOS late font atlas initialization failed:', e);
                    }
                }
            }
        );
    }
    const FULL_WIDTH = 0x11;
    const HALF_WIDTH = 0x28;

    // 预分配 turtle 保存缓冲区（96 字节）
    const savedTurtle = Memory.alloc(96);

    // 预分配 text 保存缓冲区（2048 字节）
    const markCharOut = Memory.alloc(10240);


    // ── glyphs_set_callback ───────────────────────────────────────────────
    // Android/PC used to replace this registration API and later invoke the
    // captured callback from JavaScript for every glyph.  That changes the
    // game's draw-state protocol and can make dynamically supplied UTF-8 text
    // disappear even though static Chinese in a .df still renders.  Keep the
    // engine callback registered natively on every platform.
    if (customGlyphRemapEnabled) {
    log('glyphs_set_callback 保留原生实现');

    // ── Replace glyphs_batch_plot_ex ──────────────────────────────────────
    // Run the game renderer on Windows and Android.  Apart from drawing the
    // glyph, it owns the private-use colour, flash and bounce controls; the
    // old Android JavaScript renderer bypassed those controls completely.
    const genericNativeRemapEnabled =
        Process.platform === 'windows' || isAndroidUnicodeRuntime;
    let windowsNativeTextRemapInstalled = false;
    let iosNativeTextRemapInstalled = false;
    // JUN-20-2024 uses cdecl and 32-byte sprite records (verified against
    // prog_new.sqlite). All mutable CModule storage must be external: its
    // compiled data pages are read-only, including C static arrays.
    const windowsNativeTextRemapEnabled = Process.pointerSize === 4 &&
        globalThis.build_stamp === 'JUN-20-2024.10.25';
    const genericCTextRemapEnabled = isAndroidUnicodeRuntime ||
        (isWindowsUnicodeRuntime && windowsNativeTextRemapEnabled);
    let windowsNativeTextState = null;
    if (genericNativeRemapEnabled && genericCTextRemapEnabled) {
        // Keep the complete Windows/Android text remap in native code. The former
        // NativeCallback crossed into JavaScript for every ordinary ASCII
        // text call. Keep native colour/effect callbacks intact while removing
        // those JS transitions and per-string JS allocations.
        let replacedNativeSprite = false;
        let replacedNativeGlyph = false;
        try {
            const originalGlyphSlot = Memory.alloc(Process.pointerSize);
            const originalSpriteSlot = Memory.alloc(Process.pointerSize);
            const activeBaseSlot = Memory.alloc(Process.pointerSize);
            const activeCountSlot = Memory.alloc(4);
            const activeSlots = Memory.alloc(256);
            const unifontSlot = Memory.alloc(Process.pointerSize);
            const unifontXSlot = Memory.alloc(4);
            const unifontYSlot = Memory.alloc(4);
            const mainAtlasSlot = Memory.alloc(Process.pointerSize);
            const fontAtlasSlot = Memory.alloc(Process.pointerSize);
            const outputBuffer = Memory.alloc(4097);
            const nativeSpriteSize = Process.pointerSize === 8 ? 40 : 32;
            const savedBuffer = Memory.alloc(256 * nativeSpriteSize);
            const savedSlotsBuffer = Memory.alloc(256 * 4);
            const inGlyphCallSlot = Memory.alloc(4);
            const spriteSizeSlot = Memory.alloc(4);
            const unicodeYOffsetSlot = Memory.alloc(4);
            const unicodeStrideSlot = Memory.alloc(4);
            const unicodePaddingSlot = Memory.alloc(4);
            inGlyphCallSlot.writeS32(0);
            mainAtlasSlot.writePointer(ptr(0));
            fontAtlasSlot.writePointer(ptr(0));
            originalGlyphSlot.writePointer(ptr(0));
            originalSpriteSlot.writePointer(ptr(0));
            activeBaseSlot.writePointer(ptr(0));
            activeCountSlot.writeS32(0);
            activeSlots.writeByteArray(new Uint8Array(256));
            unifontSlot.writePointer(ptr(0));
            unifontXSlot.writeS32(0);
            unifontYSlot.writeS32(0);
            spriteSizeSlot.writeS32(nativeSpriteSize);
            unicodeYOffsetSlot.writeS32(isAndroidUnicodeRuntime ? 1 : 0);
            unicodeStrideSlot.writeS32(GENERIC_UNICODE_CELL_STRIDE);
            unicodePaddingSlot.writeS32(GENERIC_UNICODE_CELL_PADDING);

            const nativeModule = new CModule(`
                typedef int (*glyphs_batch_plot_ex_t)(void *, const unsigned char *, int, int, int);
                typedef void (*sprite_batch_plot_t)(void *, int, int);
                extern void *original_glyph_slot;
                extern void *original_sprite_slot;
                extern void *active_base_slot;
                extern int active_count_slot;
                extern unsigned char active_slots[];
                extern void *unifont_slot;
                extern int unifont_x_slot;
                extern int unifont_y_slot;
                extern int sprite_size_slot;
                extern int unicode_y_offset_slot;
                extern int unicode_stride_slot;
                extern int unicode_padding_slot;
                extern void *main_atlas_slot;
                extern void *font_atlas_slot;
                extern void sprite_batch_draw_fn(void *);
                extern void *sprite_get_fn(short);
                extern char turtle_base[];

                extern unsigned char output[4097];
                extern unsigned char saved[];
                extern int saved_slots[256];
                extern int in_glyph_call;

                static int decode_utf8(const unsigned char *text, int length, int at, unsigned int *codepoint) {
                    unsigned char b0 = text[at];
                    *codepoint = b0;
                    if (b0 >= 0xc2 && b0 < 0xe0 && at + 1 < length) {
                        unsigned char b1 = text[at + 1];
                        if ((b1 & 0xc0) == 0x80) {
                            *codepoint = ((unsigned int)(b0 & 0x1f) << 6) | (b1 & 0x3f);
                            return 2;
                        }
                    } else if (b0 >= 0xe0 && b0 < 0xf0 && at + 2 < length) {
                        unsigned char b1 = text[at + 1];
                        unsigned char b2 = text[at + 2];
                        if ((b1 & 0xc0) == 0x80 && (b2 & 0xc0) == 0x80 &&
                            !(b0 == 0xe0 && b1 < 0xa0) && !(b0 == 0xed && b1 >= 0xa0)) {
                            *codepoint = ((unsigned int)(b0 & 0x0f) << 12) |
                                ((unsigned int)(b1 & 0x3f) << 6) | (b2 & 0x3f);
                            return 3;
                        }
                    }
                    return 1;
                }

                static int is_private_use(unsigned int codepoint) {
                    return codepoint >= 0xe000 && codepoint <= 0xf8ff;
                }

                static int take_candidate(unsigned char used[], int first, int count) {
                    int ranges[8] = { 65, 90, 97, 122, 48, 57, 32, 126 };
                    int r, byte, index;
                    for (r = 0; r < 8; r += 2) {
                        for (byte = ranges[r]; byte <= ranges[r + 1]; byte++) {
                            index = byte - first;
                            if (index >= 0 && index < count && !used[byte]) {
                                used[byte] = 1;
                                return byte;
                            }
                        }
                    }
                    return -1;
                }

                void sprite_batch_plot_wrapper(void *sprite, int flip, int batch) {
                    sprite_batch_plot_t original = (sprite_batch_plot_t)original_sprite_slot;
                    void *base = active_base_slot;
                    if (original == 0) return;
                    if (base != 0) {
                        long offset = (char *)sprite - (char *)base;
                        if (offset >= 0 && sprite_size_slot > 0 &&
                            offset % sprite_size_slot == 0) {
                            int slot = (int)(offset / sprite_size_slot);
                            if (slot < active_count_slot && active_slots[slot]) {
                                double *scale_x = (double *)(turtle_base + 0x18);
                                double *scale_y = (double *)(turtle_base + 0x20);
                                double saved_x = *scale_x;
                                double saved_y = *scale_y;
                                *scale_x = saved_x * (2.0 / 3.0);
                                *scale_y = saved_y * (2.0 / 3.0);
                                original(sprite, flip, batch);
                                *scale_x = saved_x;
                                *scale_y = saved_y;
                                return;
                            }
                        }
                    }
                    original(sprite, flip, batch);
                }

                int glyphs_batch_plot_ex_wrapper(void *glyphs, const unsigned char *text,
                    int byte_count, int alignment, int batch) {
                    glyphs_batch_plot_ex_t original = (glyphs_batch_plot_ex_t)original_glyph_slot;
                    unsigned char used[256] = {0};
                    unsigned char mapped[256];
                    unsigned int codepoints[256];
                    unsigned char patched[256] = {0};
                    int unique = 0, saved_count = 0, first, count, at, out = 0, i;
                    int remappable = 0;
                    void *font;
                    void *uni;
                    if (original == 0 || glyphs == 0 || text == 0 || byte_count < 0 || byte_count > 4096 || in_glyph_call)
                        return original ? original(glyphs, text, byte_count, alignment, batch) : 0;
                    first = *(int *)((char *)glyphs + 4);
                    count = *(unsigned int *)((char *)glyphs + 8);
                    if (first < -128 || first > 255 || count <= 0 || count > 256)
                        return original(glyphs, text, byte_count, alignment, batch);
                    uni = unifont_slot;
                    if (uni == 0)
                        return original(glyphs, text, byte_count, alignment, batch);
                    for (at = 0; at < byte_count;) {
                        unsigned int cp;
                        int n = decode_utf8(text, byte_count, at, &cp);
                        if (n == 1) used[text[at]] = 1;
                        else if (!is_private_use(cp)) {
                            int known = 0;
                            remappable = 1;
                            for (i = 0; i < unique; i++) if (codepoints[i] == cp) { known = 1; break; }
                            if (!known) {
                                if (unique >= 256) return original(glyphs, text, byte_count, alignment, batch);
                                codepoints[unique++] = cp;
                            }
                        }
                        at += n;
                    }
                    if (!remappable) {
                        return original(glyphs, text, byte_count, alignment, batch);
                    }
                    for (i = 0; i < unique; i++) {
                        int candidate = take_candidate(used, first, count);
                        if (candidate < 0) {
                            return original(glyphs, text, byte_count, alignment, batch);
                        }
                        mapped[i] = (unsigned char)candidate;
                    }
                    font = sprite_get_fn((short)(*(unsigned int *)glyphs & 0x3fff));
                    if (font == 0) return original(glyphs, text, byte_count, alignment, batch);
                    active_base_slot = font;
                    active_count_slot = count;
                    for (i = 0; i < 256; i++) active_slots[i] = 0;
                    for (at = 0; at < byte_count;) {
                        unsigned int cp;
                        int n = decode_utf8(text, byte_count, at, &cp);
                        if (n == 1 || is_private_use(cp)) {
                            int k;
                            for (k = 0; k < n; k++) output[out++] = text[at + k];
                        } else {
                            int map_index = -1, slot;
                            unsigned char *target;
                            for (i = 0; i < unique; i++) if (codepoints[i] == cp) { map_index = i; break; }
                            if (map_index < 0) { active_base_slot = 0; active_count_slot = 0; return original(glyphs, text, byte_count, alignment, batch); }
                            output[out++] = mapped[map_index];
                            slot = (int)mapped[map_index] - first;
                            if (!patched[slot]) {
                                int k;
                                target = (unsigned char *)font + slot * sprite_size_slot;
                                for (k = 0; k < sprite_size_slot; k++)
                                    saved[saved_count * sprite_size_slot + k] = target[k];
                                saved_slots[saved_count++] = slot;
                                patched[slot] = 1;
                                active_slots[slot] = 1;
                                for (k = 0; k < sprite_size_slot; k++)
                                    target[k] = ((unsigned char *)uni)[k];
                                *(unsigned short *)(target + 0) = (unsigned short)(unifont_x_slot + unicode_padding_slot + unicode_stride_slot * (cp & 255));
                                *(unsigned short *)(target + 2) = (unsigned short)(unifont_y_slot + unicode_padding_slot + unicode_stride_slot * ((cp >> 8) & 255) + unicode_y_offset_slot);
                                *(unsigned short *)(target + 4) = 12;
                                *(unsigned short *)(target + 6) = 12;
                                *(short *)(target + 12) = 8;
                            }
                        }
                        at += n;
                    }
                    output[out] = 0;
                    in_glyph_call = 1;
                    original(glyphs, output, out, alignment, batch);
                    /* Flush both textures in UI order before later panels can
                       cover this string. Keep the entire operation native. */
                    if (main_atlas_slot != 0 && font_atlas_slot != 0) {
                        sprite_batch_draw_fn(main_atlas_slot);
                        sprite_batch_draw_fn(font_atlas_slot);
                    }
                    in_glyph_call = 0;
                    for (i = 0; i < saved_count; i++) {
                        unsigned char *target = (unsigned char *)font + saved_slots[i] * sprite_size_slot;
                        int k;
                        for (k = 0; k < sprite_size_slot; k++)
                            target[k] = saved[i * sprite_size_slot + k];
                    }
                    for (i = 0; i < 256; i++) active_slots[i] = 0;
                    active_base_slot = 0;
                    active_count_slot = 0;
                    return byte_count;
                }
            `, {
                original_glyph_slot: originalGlyphSlot,
                original_sprite_slot: originalSpriteSlot,
                active_base_slot: activeBaseSlot,
                active_count_slot: activeCountSlot,
                active_slots: activeSlots,
                unifont_slot: unifontSlot,
                unifont_x_slot: unifontXSlot,
                unifont_y_slot: unifontYSlot,
                sprite_size_slot: spriteSizeSlot,
                unicode_y_offset_slot: unicodeYOffsetSlot,
                unicode_stride_slot: unicodeStrideSlot,
                unicode_padding_slot: unicodePaddingSlot,
                main_atlas_slot: mainAtlasSlot,
                font_atlas_slot: fontAtlasSlot,
                sprite_batch_draw_fn: SPRITE_BATCH_DRAW_PTR,
                sprite_get_fn: SPRITE_GET_PTR,
                turtle_base: TURTLE_BASE,
                output: outputBuffer,
                saved: savedBuffer,
                saved_slots: savedSlotsBuffer,
                in_glyph_call: inGlyphCallSlot
            });
            const originalSprite = Interceptor.replaceFast(
                SPRITE_BATCH_PLOT_PTR, nativeModule.sprite_batch_plot_wrapper
            );
            replacedNativeSprite = true;
            originalSpriteSlot.writePointer(originalSprite);
            const originalGlyph = Interceptor.replaceFast(
                GLYPHS_BATCH_PLOT_EX_PTR, nativeModule.glyphs_batch_plot_ex_wrapper
            );
            replacedNativeGlyph = true;
            originalGlyphSlot.writePointer(originalGlyph);
            // Retain every external allocation for the lifetime of the hooks.
            windowsNativeTextState = { unifontSlot, unifontXSlot, unifontYSlot, mainAtlasSlot, fontAtlasSlot,
                originalGlyphSlot, originalSpriteSlot, activeBaseSlot, activeCountSlot,
                activeSlots, outputBuffer, savedBuffer, savedSlotsBuffer, inGlyphCallSlot,
                spriteSizeSlot, unicodeYOffsetSlot, unicodeStrideSlot,
                unicodePaddingSlot };
            globalThis.windowsNativeUnicodeTextModule = nativeModule;
            globalThis.windowsNativeUnicodeTextState = windowsNativeTextState;
            globalThis.nativeUnicodeTextState = windowsNativeTextState;
            Interceptor.flush();
            windowsNativeTextRemapInstalled = true;
            log(`${isAndroidUnicodeRuntime ? 'Android' : 'Windows'} native Unicode remap ACTIVE; ` +
                `C UTF-8 mapping + native 8/12 scaling, sprite=${nativeSpriteSize}, ` +
                `yOffset=${unicodeYOffsetSlot.readS32()}`);
        } catch (e) {
            // Installation must be transactional before the JS fallback runs.
            if (replacedNativeGlyph) Interceptor.revert(GLYPHS_BATCH_PLOT_EX_PTR);
            if (replacedNativeSprite) Interceptor.revert(SPRITE_BATCH_PLOT_PTR);
            Interceptor.flush();
            windowsNativeTextState = null;
            globalThis.windowsNativeUnicodeTextState = null;
            globalThis.nativeUnicodeTextState = null;
            warn(`${isAndroidUnicodeRuntime ? 'Android' : 'Windows'} native Unicode remap ` +
                'FALLBACK TO JAVASCRIPT:', e);
        }
    }

    // Jailed iOS runs with code_signing=required, so runtime-generated CModule
    // code is not a reliable release path. MR2CUnicode.dylib is compiled ahead
    // of time, bundled into Frameworks, and signed together with the app. The
    // two already gum-grafted game entrypoints only jump into that signed code.
    if (Process.platform === 'darwin') {
        let replacedNativeSprite = false;
        let replacedNativeGlyph = false;
        try {
            let nativeImage = null;
            try {
                nativeImage = Process.getModuleByName('MR2CUnicode.dylib');
            } catch (_) {
                nativeImage = Process.enumerateModules().find(module =>
                    module.name === 'MR2CUnicode.dylib' ||
                    module.path.endsWith('/MR2CUnicode.dylib')) || null;
            }
            if (!nativeImage) {
                const executablePath = Process.mainModule.path;
                const appRoot = executablePath.slice(0, executablePath.lastIndexOf('/'));
                const nativePath = `${appRoot}/Frameworks/MR2CUnicode.dylib`;
                nativeImage = Module.load(nativePath);
                log(`iOS signed native Unicode module loaded: ${nativePath}`);
            }
            if (!nativeImage)
                throw new Error('signed Frameworks/MR2CUnicode.dylib is not loaded');
            const nativeExport = name => {
                let address = null;
                if (typeof nativeImage.findExportByName === 'function')
                    address = nativeImage.findExportByName(name);
                if (!address && typeof nativeImage.getExportByName === 'function') {
                    try { address = nativeImage.getExportByName(name); } catch (_) { }
                }
                if (!address)
                    throw new Error(`MR2CUnicode export is missing: ${name}`);
                return address;
            };
            const configure = new NativeFunction(
                nativeExport('mr2c_unicode_configure'), 'void',
                ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'int']
            );
            const setOriginals = new NativeFunction(
                nativeExport('mr2c_unicode_set_originals'), 'void',
                ['pointer', 'pointer']
            );
            const setFont = new NativeFunction(
                nativeExport('mr2c_unicode_set_font'), 'void',
                ['pointer', 'int', 'int', 'pointer']
            );
            configure(
                SPRITE_GET_PTR,
                SPRITE_BATCH_DRAW_PTR,
                TURTLE_BASE,
                IOS_MAIN_ATLAS,
                40,
                0
            );
            const originalSprite = Interceptor.replaceFast(
                SPRITE_BATCH_PLOT_PTR,
                nativeExport('mr2c_sprite_batch_plot_wrapper')
            );
            replacedNativeSprite = true;
            const originalGlyph = Interceptor.replaceFast(
                GLYPHS_BATCH_PLOT_EX_PTR,
                nativeExport('mr2c_glyphs_batch_plot_ex_wrapper')
            );
            replacedNativeGlyph = true;
            setOriginals(originalSprite, originalGlyph);
            globalThis.iosNativeUnicodeSetFont = setFont;
            globalThis.iosNativeUnicodeModule = nativeImage;
            Interceptor.flush();
            iosNativeTextRemapInstalled = true;
            log('iOS signed native Unicode remap ACTIVE; C UTF-8 mapping + ' +
                'native 8/12 scaling, sprite=40, yOffset=0');
        } catch (e) {
            if (replacedNativeGlyph) Interceptor.revert(GLYPHS_BATCH_PLOT_EX_PTR);
            if (replacedNativeSprite) Interceptor.revert(SPRITE_BATCH_PLOT_PTR);
            Interceptor.flush();
            globalThis.iosNativeUnicodeSetFont = null;
            globalThis.iosNativeUnicodeModule = null;
            warn('iOS signed native Unicode remap FALLBACK TO JAVASCRIPT:', e);
        }
    }

    if (genericNativeRemapEnabled && !windowsNativeTextRemapInstalled) {
        const genericSpriteSize = Process.pointerSize === 8 ? 40 : 32;
        // This hook runs for every sprite in a PC frame, not just text. Avoid
        // allocating a pointer string and consulting a Set on that hot path.
        // The active byte-font is at most 256 contiguous sprite records, so a
        // fixed slot bitmap is enough to identify temporary Unicode records.
        const genericScaledGlyphSlots = new Uint8Array(256);
        let genericScaledGlyphBase = null;
        let genericScaledGlyphCount = 0;
        let windowsNativeGlyphScale = null;

        // The former JS interceptor ran for every map, character, particle,
        // and UI sprite.  On Windows replace it with a tiny native wrapper.
        // The wrapper calls the original function directly and only touches
        // Turtle scale when a byte-font slot is temporarily backed by Unicode.
        if (isWindowsUnicodeRuntime) {
            try {
                const originalSlot = Memory.alloc(Process.pointerSize);
                const activeBaseSlot = Memory.alloc(Process.pointerSize);
                const activeCountSlot = Memory.alloc(4);
                const activeSlots = Memory.alloc(256);
                const clearedSlots = Memory.alloc(256);
                originalSlot.writePointer(ptr(0));
                activeBaseSlot.writePointer(ptr(0));
                activeCountSlot.writeS32(0);
                Memory.copy(activeSlots, clearedSlots, 256);

                const nativeModule = new CModule(`
                    typedef int (*sprite_batch_plot_t)(void *, int, int);
                    extern void *original_slot;
                    extern void *active_base_slot;
                    extern int active_count_slot;
                    extern unsigned char active_slots[];
                    extern char turtle_base[];
                    int sprite_batch_plot_wrapper(void *sprite, int flip, int batch) {
                        sprite_batch_plot_t original = (sprite_batch_plot_t)original_slot;
                        void *base = active_base_slot;
                        if (original == 0) return 0;
                        if (base != 0) {
                            long offset = (char *)sprite - (char *)base;
                            if (offset >= 0 && (offset & 31) == 0) {
                                int slot = (int)(offset >> 5);
                                if (slot < active_count_slot && active_slots[slot]) {
                                    double *scale_x = (double *)(turtle_base + 0x18);
                                    double *scale_y = (double *)(turtle_base + 0x20);
                                    double saved_x = *scale_x;
                                    double saved_y = *scale_y;
                                    *scale_x = saved_x * (2.0 / 3.0);
                                    *scale_y = saved_y * (2.0 / 3.0);
                                    int result = original(sprite, flip, batch);
                                    *scale_x = saved_x;
                                    *scale_y = saved_y;
                                    return result;
                                }
                            }
                        }
                        return original(sprite, flip, batch);
                    }
                `, {
                    original_slot: originalSlot,
                    active_base_slot: activeBaseSlot,
                    active_count_slot: activeCountSlot,
                    active_slots: activeSlots,
                    turtle_base: TURTLE_BASE
                });
                const original = Interceptor.replaceFast(
                    SPRITE_BATCH_PLOT_PTR, nativeModule.sprite_batch_plot_wrapper
                );
                originalSlot.writePointer(original);
                Interceptor.flush();
                windowsNativeGlyphScale = { activeBaseSlot, activeCountSlot, activeSlots, clearedSlots };
                globalThis.windowsNativeUnicodeSpriteScaleModule = nativeModule;
                log('Windows native Unicode sprite scale wrapper installed');
            } catch (e) {
                warn('Windows native Unicode sprite scale unavailable; using JS fallback:', e);
            }
        }

        function validGenericNativeGlyphCall(glyphs, text, byteCount) {
            if (glyphs.isNull() || text.isNull() || byteCount < 0 || byteCount > 4096)
                return false;
            try {
                const first = glyphs.add(4).readS32();
                const count = glyphs.add(8).readU32();
                return first >= -128 && first <= 255 && count > 0 && count <= 256;
            } catch (_) {
                return false;
            }
        }

        // The imported package has one common main.js for Android and PC.
        // Scale only the temporary replacement slots; native ASCII glyphs and
        // the game's private-use controller/effect glyphs keep their normal
        // Turtle transform.
        if (windowsNativeGlyphScale === null) Interceptor.attach(SPRITE_BATCH_PLOT, {
            onEnter(args) {
                if (genericScaledGlyphBase === null) return;
                const offset = args[0].sub(genericScaledGlyphBase).toInt32();
                if (offset < 0 || offset % genericSpriteSize !== 0) return;
                const slot = offset / genericSpriteSize;
                if (slot >= genericScaledGlyphCount || !genericScaledGlyphSlots[slot]) return;
                const scaleXAddress = TURTLE_BASE.add(0x18);
                const scaleYAddress = TURTLE_BASE.add(0x20);
                this.originalScaleX = scaleXAddress.readDouble();
                this.originalScaleY = scaleYAddress.readDouble();
                scaleXAddress.writeDouble(this.originalScaleX * GENERIC_UNICODE_SCALE);
                scaleYAddress.writeDouble(this.originalScaleY * GENERIC_UNICODE_SCALE);
                this.scaledUnicodeGlyph = true;
            },
            onLeave() {
                if (!this.scaledUnicodeGlyph) return;
                TURTLE_BASE.add(0x18).writeDouble(this.originalScaleX);
                TURTLE_BASE.add(0x20).writeDouble(this.originalScaleY);
            }
        });


        Interceptor.replace(GLYPHS_BATCH_PLOT_EX, new NativeCallback(
            (glyphs, text, byteCount, alignment, batch) => {
                if (!validGenericNativeGlyphCall(glyphs, text, byteCount) || !unifont)
                    return GLYPHS_BATCH_PLOT_EX(glyphs, text, byteCount, alignment, batch);

                const firstByte = glyphs.add(4).readS32();
                const glyphCount = glyphs.add(8).readU32();
                const font = SPRITE_GET(glyphs.readS16());
                const codePoints = [];
                const usedBytes = new Set();
                let hasRemappableUtf8 = false;

                for (let sourceIndex = 0; sourceIndex < byteCount;) {
                    const b0 = text.add(sourceIndex).readU8();
                    let codePoint = b0;
                    let byteLength = 1;
                    if (b0 >= 0xC2 && b0 < 0xE0 && sourceIndex + 1 < byteCount) {
                        const b1 = text.add(sourceIndex + 1).readU8();
                        if ((b1 & 0xC0) === 0x80) {
                            codePoint = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
                            byteLength = 2;
                        }
                    } else if (b0 >= 0xE0 && b0 < 0xF0 && sourceIndex + 2 < byteCount) {
                        const b1 = text.add(sourceIndex + 1).readU8();
                        const b2 = text.add(sourceIndex + 2).readU8();
                        const validContinuation = (b1 & 0xC0) === 0x80 && (b2 & 0xC0) === 0x80;
                        const validRange = !(b0 === 0xE0 && b1 < 0xA0) && !(b0 === 0xED && b1 >= 0xA0);
                        if (validContinuation && validRange) {
                            codePoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
                            byteLength = 3;
                        }
                    }
                    const privateUse = codePoint >= 0xE000 && codePoint <= 0xF8FF;
                    if (byteLength === 1) usedBytes.add(b0);
                    else if (!privateUse) hasRemappableUtf8 = true;
                    codePoints.push({ codePoint, sourceIndex, byteLength, privateUse });
                    sourceIndex += byteLength;
                }

                if (!hasRemappableUtf8)
                    return GLYPHS_BATCH_PLOT_EX(glyphs, text, byteCount, alignment, batch);

                if (windowsNativeGlyphScale !== null) {
                    Memory.copy(windowsNativeGlyphScale.activeSlots,
                        windowsNativeGlyphScale.clearedSlots, 256);
                    windowsNativeGlyphScale.activeBaseSlot.writePointer(font);
                    windowsNativeGlyphScale.activeCountSlot.writeS32(glyphCount);
                } else {
                    genericScaledGlyphBase = font;
                    genericScaledGlyphCount = glyphCount;
                    genericScaledGlyphSlots.fill(0);
                }

                const candidates = [];
                // Alphanumerics are safe in all game menus.  Use remaining
                // printable bytes only if a longer localized string needs
                // more slots; source bytes are always excluded.
                const candidateOrder =
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
                    ' !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
                for (let i = 0; i < candidateOrder.length; i++) {
                    const byte = candidateOrder.charCodeAt(i);
                    const index = byte - firstByte;
                    if (index >= 0 && index < glyphCount && !usedBytes.has(byte) && !candidates.includes(byte))
                        candidates.push(byte);
                }

                const slotByCodePoint = new Map();
                for (const item of codePoints) {
                    if (item.byteLength === 1 || item.privateUse || slotByCodePoint.has(item.codePoint)) continue;
                    const byte = candidates.shift();
                    if (byte === undefined) {
                        warn('generic glyph remap', 'No free native glyph slots for this string.');
                        return GLYPHS_BATCH_PLOT_EX(glyphs, text, byteCount, alignment, batch);
                    }
                    slotByCodePoint.set(item.codePoint, byte);
                }

                const transformedBytes = [];
                const savedSprites = [];
                const patchedBytes = new Set();
                for (const item of codePoints) {
                    if (item.byteLength === 1 || item.privateUse) {
                        for (let i = 0; i < item.byteLength; i++)
                            transformedBytes.push(text.add(item.sourceIndex + i).readU8());
                        continue;
                    }

                    const byte = slotByCodePoint.get(item.codePoint);
                    transformedBytes.push(byte);
                    if (patchedBytes.has(byte)) continue;
                    patchedBytes.add(byte);

                    const slot = byte - firstByte;
                    const target = font.add(slot * genericSpriteSize);
                    savedSprites.push({ target, data: target.readByteArray(genericSpriteSize) });
                    if (windowsNativeGlyphScale !== null)
                        windowsNativeGlyphScale.activeSlots.add(slot).writeU8(1);
                    else
                        genericScaledGlyphSlots[slot] = 1;
                    Memory.copy(target, unifont, genericSpriteSize);
                    target.writeU16(
                        unifont_x + GENERIC_UNICODE_CELL_PADDING +
                        GENERIC_UNICODE_CELL_STRIDE * (item.codePoint & 0xff)
                    );
                    target.add(2).writeU16(
                        unifont_y + GENERIC_UNICODE_CELL_PADDING +
                        GENERIC_UNICODE_CELL_STRIDE *
                        ((item.codePoint >> 8) & 0xff) + GENERIC_UNICODE_Y_OFFSET
                    );
                    target.add(4).writeU16(GENERIC_UNICODE_CELL_SIZE);
                    target.add(6).writeU16(GENERIC_UNICODE_CELL_SIZE);
                    target.add(12).writeS16(GENERIC_UNICODE_ADVANCE);
                }

                const transformed = Memory.alloc(transformedBytes.length + 1);
                transformed.writeByteArray(transformedBytes);
                transformed.add(transformedBytes.length).writeU8(0);
                try {
                    GLYPHS_BATCH_PLOT_EX(glyphs, transformed, transformedBytes.length, alignment, batch);

                    // The independent font texture must be submitted while
                    // this native text call's draw/blend state is current.
                    // Its matching atlas-0 batch has to precede it: the PC
                    // renderer changes blend/mask state between text passes.
                    if ((isAndroidUnicodeRuntime || isWindowsUnicodeRuntime) && iosFontAtlas !== null) {
                        SPRITE_BATCH_DRAW(ATLAS_GET(0));
                        SPRITE_BATCH_DRAW(iosFontAtlas);
                    }
                } finally {
                    for (const saved of savedSprites) {
                        saved.target.writeByteArray(saved.data);
                    }
                    if (windowsNativeGlyphScale !== null) {
                        Memory.copy(windowsNativeGlyphScale.activeSlots,
                            windowsNativeGlyphScale.clearedSlots, 256);
                        windowsNativeGlyphScale.activeBaseSlot.writePointer(ptr(0));
                        windowsNativeGlyphScale.activeCountSlot.writeS32(0);
                    } else {
                        genericScaledGlyphSlots.fill(0);
                        genericScaledGlyphBase = null;
                        genericScaledGlyphCount = 0;
                    }
                }
                return byteCount;
            },
            'int', ['pointer', 'pointer', 'int', 'int', 'int']
        ));
        log('Replace glyphs_batch_plot_ex Windows/Android JavaScript fallback 已安装');
    }

    if (Process.platform === 'darwin' && !iosNativeTextRemapInstalled) {
        const iosSafeEmptyGlyphText = Memory.alloc(1);
        iosSafeEmptyGlyphText.writeU8(0);
        const iosDefaultGlyphs = globalThis.mainModule.base.add(0x5AF630);
        let iosRejectedGlyphCalls = 12;

        function validIOSNativeGlyphCall(glyphs, text, byteCount) {
            if (glyphs.isNull() || text.isNull() || byteCount < 0 || byteCount > 4096)
                return false;
            try {
                const fontId = glyphs.readU32() & 0x3fff;
                const first = glyphs.add(4).readS32();
                const count = glyphs.add(8).readU32();
                // All iOS DR2C bitmap fonts are byte-indexed. A count beyond
                // 256 or a nonsensical first byte means this is a stale or
                // corrupted descriptor rather than a font. Do not require a
                // trailing NUL: this routine receives an explicit byte count
                // and many legitimate callers pass a non-terminated slice.
                return fontId < 0x4000 && first >= -128 && first <= 255 &&
                    count > 0 && count <= 256;
            } catch (_) {
                return false;
            }
        }

        function describeIOSGlyphCall(glyphs, text, byteCount) {
            let descriptor = 'unreadable';
            let bytes = 'unreadable';
            try {
                descriptor = `fontId=${glyphs.readU32()} masked=${glyphs.readU32() & 0x3fff} ` +
                    `first=${glyphs.add(4).readS32()} count=${glyphs.add(8).readU32()}`;
            } catch (_) { }
            try {
                const previewLength = Math.max(0, Math.min(byteCount, 24));
                const values = [];
                for (let i = 0; i < previewLength; i++)
                    values.push(text.add(i).readU8().toString(16).padStart(2, '0'));
                bytes = values.join(' ');
            } catch (_) { }
            return `${descriptor} textBytes=[${bytes}]`;
        }

        Interceptor.attach(SPRITE_BATCH_PLOT, {
            onEnter(args) {
                if (!iosScaledGlyphSprites.has(args[0].toString())) return;

                // Match the Android custom-glyph path: retain the original
                // 12x12 bitmap and reduce only its draw geometry to 8/12.
                // Multiplying both axes independently also preserves any
                // scale already applied by native effects/callbacks.
                const scaleXAddress = TURTLE_BASE.add(0x18);
                const scaleYAddress = TURTLE_BASE.add(0x20);
                this.originalScaleX = scaleXAddress.readDouble();
                this.originalScaleY = scaleYAddress.readDouble();
                scaleXAddress.writeDouble(this.originalScaleX * IOS_UNICODE_SCALE);
                scaleYAddress.writeDouble(this.originalScaleY * IOS_UNICODE_SCALE);
                this.scaledUnicodeGlyph = true;
            },
            onLeave() {
                if (!this.scaledUnicodeGlyph) return;
                TURTLE_BASE.add(0x18).writeDouble(this.originalScaleX);
                TURTLE_BASE.add(0x20).writeDouble(this.originalScaleY);
            }
        });
        log('Attach sprite_batch_plot iOS Unicode 8/12 scale 已安装');

        Interceptor.attach(GLYPHS_BATCH_PLOT_EX, {
            onEnter(args) {
                // The separate atlas is initialized only after load_gfx.  Do
                // not allocate/upload GL resources from a glyph callback: on
                // iOS this may run on a render worker and previously crashed
                // in memmove while the graphics state was incomplete.
                const byteCount = args[2].toInt32();
                if (!validIOSNativeGlyphCall(args[0], args[1], byteCount)) {
                    if (iosRejectedGlyphCalls > 0) {
                        iosRejectedGlyphCalls--;
                        const caller = this.returnAddress.sub(globalThis.mainModule.base);
                        warn('iOS glyph call', `Rejected glyphs=${args[0]} text=${args[1]} ` +
                            `bytes=${byteCount} caller=${caller} ` +
                            describeIOSGlyphCall(args[0], args[1], byteCount));
                    }
                    // The native routine reads the first byte before checking
                    // byteCount, so provide a real empty string and the known
                    // default font instead of merely setting count to zero.
                    args[0] = iosDefaultGlyphs;
                    args[1] = iosSafeEmptyGlyphText;
                    args[2] = ptr(0);
                    return;
                }
                if (!unifont) return;

                const a1 = args[0];
                const a2 = args[1];
                if (a2.isNull() || byteCount <= 0 || byteCount > 4096) {
                    if (byteCount > 4096)
                        warn('iOS glyph remap', `Rejected unreasonable byte count: ${byteCount}`);
                    return;
                }
                const v5 = a1.add(4).readS32();
                const glyphCount = a1.add(8).readU32();
                const spriteSize = 40;
                // sprite_get(id) is a masked index into this fixed iOS array.
                // Computing it directly avoids a nested NativeFunction call
                // while Frida is already inside glyphs_batch_plot_ex.
                const spriteArray = globalThis.mainModule.base.add(0x23C780);
                const font = spriteArray.add((a1.readU32() & 0x3fff) * spriteSize);
                const codePoints = [];
                const usedBytes = new Set();
                let hasUtf8 = false;
                let hasRemappableUtf8 = false;

                for (let sourceIndex = 0; sourceIndex < byteCount;) {
                    const b0 = a2.add(sourceIndex).readU8();
                    let codePoint = b0;
                    let byteLength = 1;
                    if (b0 >= 0xC2 && b0 < 0xE0 && sourceIndex + 1 < byteCount) {
                        const b1 = a2.add(sourceIndex + 1).readU8();
                        if ((b1 & 0xC0) === 0x80) {
                            codePoint = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
                            byteLength = 2;
                        }
                    } else if (b0 >= 0xE0 && b0 < 0xF0 && sourceIndex + 2 < byteCount) {
                        const b1 = a2.add(sourceIndex + 1).readU8();
                        const b2 = a2.add(sourceIndex + 2).readU8();
                        const validContinuation = (b1 & 0xC0) === 0x80 && (b2 & 0xC0) === 0x80;
                        const validRange = !(b0 === 0xE0 && b1 < 0xA0) && !(b0 === 0xED && b1 >= 0xA0);
                        if (validContinuation && validRange) {
                            codePoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
                            byteLength = 3;
                        }
                    }
                    if (byteLength > 1) {
                        hasUtf8 = true;
                        if (codePoint < 0xE000 || codePoint > 0xF8FF)
                            hasRemappableUtf8 = true;
                    } else {
                        usedBytes.add(b0);
                    }
                    codePoints.push({
                        codePoint,
                        sourceIndex,
                        byteLength,
                        privateUse: codePoint >= 0xE000 && codePoint <= 0xF8FF
                    });
                    sourceIndex += byteLength;
                }
                if (!hasUtf8 || !hasRemappableUtf8) return;

                const candidates = [];
                // Prefer alphanumeric glyphs: the game's callback treats much
                // of the punctuation range as controller/UI icons.
                const candidateOrder =
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                for (let i = 0; i < candidateOrder.length; i++) {
                    const byte = candidateOrder.charCodeAt(i);
                    const index = byte - v5;
                    if (index >= 0 && index < glyphCount && !usedBytes.has(byte))
                        candidates.push(byte);
                }

                const slotByCodePoint = new Map();
                for (const item of codePoints) {
                    if (item.byteLength === 1 || item.privateUse || slotByCodePoint.has(item.codePoint)) continue;
                    const byte = candidates.shift();
                    if (byte === undefined) {
                        warn('iOS glyph remap', 'No free native glyph slots for this string.');
                        return;
                    }
                    slotByCodePoint.set(item.codePoint, byte);
                }

                const transformedBytes = [];
                const savedSprites = [];
                const patchedBytes = new Set();
                for (const item of codePoints) {
                    if (item.byteLength === 1) {
                        transformedBytes.push(a2.add(item.sourceIndex).readU8());
                        continue;
                    }
                    if (item.privateUse) {
                        for (let i = 0; i < item.byteLength; i++)
                            transformedBytes.push(a2.add(item.sourceIndex + i).readU8());
                        continue;
                    }

                    const byte = slotByCodePoint.get(item.codePoint);
                    transformedBytes.push(byte);
                    if (patchedBytes.has(byte)) continue;
                    patchedBytes.add(byte);

                    const target = font.add((byte - v5) * spriteSize);
                    savedSprites.push({ target, data: target.readByteArray(spriteSize) });
                    iosScaledGlyphSprites.add(target.toString());
                    Memory.copy(target, unifont, spriteSize);
                    target.writeU16(unifont_x + IOS_UNICODE_CELL_SIZE * (item.codePoint & 0xff));
                    // Keep the 12px source rectangle inside its glyph cell.
                    // A +1 texture-Y offset samples the next row's first pixels.
                    target.add(2).writeU16(
                        unifont_y + IOS_UNICODE_CELL_SIZE * ((item.codePoint >> 8) & 0xff)
                    );
                    target.add(4).writeU16(IOS_UNICODE_CELL_SIZE);
                    target.add(6).writeU16(IOS_UNICODE_CELL_SIZE);
                    target.add(12).writeS16(IOS_UNICODE_ADVANCE);
                }
                const transformed = Memory.alloc(transformedBytes.length + 1);
                transformed.writeByteArray(transformedBytes);
                transformed.add(transformedBytes.length).writeU8(0);

                // Keep the Frida-owned allocation alive until the intercepted
                // native call has finished.  Merely assigning its address to
                // args[1] does not retain the JavaScript NativePointer wrapper;
                // GC could otherwise recycle the buffer between onEnter and
                // the Mach-O function reading it, producing flickering/random
                // glyph bytes on short labels such as Mods and Options.
                this.transformedBuffer = transformed;
                this.savedSprites = savedSprites;
                this.originalByteCount = byteCount;
                // Keep the game's native glyph callback active.  Candidate
                // slots are restricted to alphanumerics, which the callback
                // leaves alone, while embedded control bytes still need it for
                // effects such as RAINBOW and BOUNCY/Bouncy-Off.
                args[1] = transformed;
                args[2] = ptr(transformedBytes.length);
                if (iosGlyphRemapDebugRemaining > 0) {
                    iosGlyphRemapDebugRemaining--;
                    let sourcePreview = '<unreadable>';
                    try { sourcePreview = a2.readUtf8String(byteCount); } catch (_) { }
                    log(`iOS glyph remap: ${byteCount} UTF-8 bytes -> ${transformedBytes.length} ` +
                        `native bytes, patched ${patchedBytes.size} slots, source=${JSON.stringify(sourcePreview)}`);
                }
            },
            onLeave(retval) {
                if (!this.savedSprites) return;
                for (const saved of this.savedSprites) {
                    iosScaledGlyphSprites.delete(saved.target.toString());
                    saved.target.writeByteArray(saved.data);
                }
                // Preserve UI layer order. The game only flushes atlas 0, and
                // a frame-end atlas-15 flush lets later main-atlas UI overwrite
                // earlier Chinese lines. Submit both batches at the end of the
                // exact text draw instead: background/current main content,
                // then the independent font texture on top.
                if (iosFontAtlas !== null) {
                    SPRITE_BATCH_DRAW(IOS_MAIN_ATLAS);
                    SPRITE_BATCH_DRAW(iosFontAtlas);
                }
                retval.replace(this.originalByteCount);
                this.transformedBuffer = null;
            }
        });
        log('iOS Unicode remap JAVASCRIPT FALLBACK ACTIVE');
    } else if (!genericNativeRemapEnabled && !iosNativeTextRemapInstalled) {
    const GLYPHS_BATCH_PLOT_EX_HOOK = Interceptor.replace(GLYPHS_BATCH_PLOT_EX, new NativeCallback(
        (a1, a2, a3, a4, a5) => {
            if (!unifont) return GLYPHS_BATCH_PLOT_EX(a1, a2, a3, a4, a5);
            if (a1.isNull()) return 0;

            if (Process.platform === 'darwin') {
                const v5 = a1.add(4).readS32();
                const glyphCount = a1.add(8).readU32();
                const font = SPRITE_GET(a1.readS16());
                const spriteSize = 40;
                const codePoints = [];
                const usedBytes = new Set();
                let hasUtf8 = false;

                for (let sourceIndex = 0; sourceIndex < a3;) {
                    const codePoint = getBmpCodePointNav(a2, sourceIndex, a3);
                    let byteLength = 1;
                    if (codePoint >= 0x80) {
                        byteLength = codePoint < 0x800 ? 2 : 3;
                        hasUtf8 = true;
                    } else {
                        usedBytes.add(a2.add(sourceIndex).readU8());
                    }
                    codePoints.push({ codePoint, sourceIndex, byteLength });
                    sourceIndex += byteLength;
                }

                // Let the native implementation handle ordinary game text. In
                // particular, this keeps all iOS render-state and batching ABI
                // inside Mach-O code instead of crossing JS once per glyph.
                if (!hasUtf8)
                    return GLYPHS_BATCH_PLOT_EX(a1, a2, a3, a4, a5);

                const candidates = [];
                const firstByte = Math.max(v5, 0x21);
                const lastByte = Math.min(0x7e, v5 + glyphCount - 1, 0xff);
                for (let byte = firstByte; byte <= lastByte; byte++) {
                    if (!usedBytes.has(byte)) candidates.push(byte);
                }

                const slotByCodePoint = new Map();
                for (const item of codePoints) {
                    if (item.byteLength === 1 || slotByCodePoint.has(item.codePoint)) continue;
                    const byte = candidates.shift();
                    if (byte === undefined) {
                        warn('iOS glyph remap', 'No free native glyph slots for this string.');
                        return GLYPHS_BATCH_PLOT_EX(a1, a2, a3, a4, a5);
                    }
                    slotByCodePoint.set(item.codePoint, byte);
                }

                const transformed = Memory.alloc(codePoints.length + 1);
                const savedSprites = [];
                const patchedBytes = new Set();
                for (let outputIndex = 0; outputIndex < codePoints.length; outputIndex++) {
                    const item = codePoints[outputIndex];
                    if (item.byteLength === 1) {
                        transformed.add(outputIndex).writeU8(a2.add(item.sourceIndex).readU8());
                        continue;
                    }

                    const byte = slotByCodePoint.get(item.codePoint);
                    transformed.add(outputIndex).writeU8(byte);
                    if (patchedBytes.has(byte)) continue;
                    patchedBytes.add(byte);

                    const target = font.add((byte - v5) * spriteSize);
                    savedSprites.push({ target, data: target.readByteArray(spriteSize) });
                    Memory.copy(target, unifont, spriteSize);
                    target.writeU16(unifont_x + 12 * (item.codePoint & 0xff));
                    target.add(2).writeU16(unifont_y + 12 * ((item.codePoint >> 8) & 0xff) + 1);
                    target.add(4).writeU16(12);
                    target.add(6).writeU16(12);
                    target.add(12).writeS16(12);
                }
                transformed.add(codePoints.length).writeU8(0);

                try {
                    GLYPHS_BATCH_PLOT_EX(a1, transformed, codePoints.length, a4, a5);
                } finally {
                    for (const saved of savedSprites)
                        saved.target.writeByteArray(saved.data);
                }
                return a3;
            }

            const v5 = a1.add(4).readS32();        // (int)a1[1]  base char code
            const font = SPRITE_GET(a1.readS16());    // SPRITE_GET((INT16)a1[0])
            const sprite_offset = Process.pointerSize === 8 ? 40 : 32;

            // 保存 turtle（96 字节）
            Memory.copy(savedTurtle, TURTLE_BASE, 96);

            const v6 = a1.add(8).readU32();          // a1[2]
            if (v6 === 0) return 0;

            let v8 = (a2.readU8() - v5) >>> 0;      // (DWORD)*a2 - v5
            if (v6 <= v8) v8 = v6 - 1;

            // 第一个字形宽度的一半
            let v9 = font.add(sprite_offset * v8).add(12).readS16() * 0.5;

            // 累计所有字形宽度
            let v11 = 0.0;
            if (a3 > 0) {
                for (let i = 0; i < a3; i++) {
                    const bmpCodePoint = getBmpCodePointNav(a2, i, a3);
                    const _utf8Len = (bmpCodePoint < 0x80 || bmpCodePoint === -1) ? 0 :
                        (bmpCodePoint < 0x800) ? 2 : 3;

                    if (_utf8Len) {
                        const c = (_utf8Len === 3 ? FULL_WIDTH : HALF_WIDTH) - v5;/* 全半角按utf8长度判断 */
                        v11 += font.add(sprite_offset * c).add(12).readS16();
                        i += _utf8Len - 1;
                    } else {
                        const c = a2.add(i).readU8() - v5;
                        v11 += font.add(sprite_offset * c).add(12).readS16();
                    }

                }
            }

            // 根据对齐方式调整起始偏移
            if (a4 === 2) v9 = v9 - v11;
            else if (a4 === 1) v9 = v9 + (-v11 * 0.5);

            TURTLE_TRANS(v9, 0.0);

            // 逐字形渲染
            for (let v13 = 0; v13 < a3; v13++) {
                const bmpCodePoint = getBmpCodePointNav(a2, v13, a3);
                const _utf8Len = (bmpCodePoint < 0x80 || bmpCodePoint === 0) ? 0 :
                    (bmpCodePoint < 0x800) ? 2 : 3;

                let v14 = (a2.add(v13).readU8() - v5) >>> 0;
                if (_utf8Len) {
                    v14 = ((_utf8Len === 3 ? FULL_WIDTH : HALF_WIDTH) - v5) >>> 0;
                }
                const charV14 = ((v14 & 0xFF) << 24) >> 24;   // (char)v14

                // The iOS title-screen callback mutates render state around each
                // glyph. Calling it from the JS replacement makes the default
                // ASCII sprite batch invisible on an early attach. The same
                // bytes render correctly when the callback was not captured,
                // including the private-use icon glyphs, so keep the custom iOS
                // path self-contained.
                const callbackHandled = Process.platform !== 'darwin' && originalGlyphCb
                    ? originalGlyphCb(charV14, 0, originalGlyphCtx) !== 0
                    : false;
                if (!callbackHandled) {

                    const v15 = a1.add(8).readU32();
                    if (v14 >= v15) v14 = v15 - 1;
                    const v16 = font.add(sprite_offset * v14);
                    if (glyphDebugRemaining > 0) {
                        glyphDebugRemaining--;
                        log('glyph debug', {
                            byte: a2.add(v13).readU8(),
                            codePoint: bmpCodePoint,
                            utf8Len: _utf8Len,
                            glyphIndex: v14,
                            sprite: v16,
                            xywh: [v16.readU16(), v16.add(2).readU16(), v16.add(4).readU16(), v16.add(6).readU16()],
                            advance: v16.add(12).readS16(),
                            atlas: v16.add(32).readPointer(),
                            batch: a5
                        });
                    }

                    if (v13) {
                        TURTLE_TRANS(v16.add(12).readS16() * 0.5, 0.0);
                    }

                    if (!_utf8Len)
                        SPRITE_BATCH_PLOT(v16, 0, a5);
                    else {
                        unifont.add(0).writeU16(unifont_x + 12 * (bmpCodePoint & 0xFF));/* 纹理x轴 */
                        unifont.add(2).writeU16(unifont_y + 12 * ((bmpCodePoint >> 8) & 0xFF) + 1);/* 纹理y轴 下调1像素对齐游戏字体和解决纹理半像素对齐*/

                        unifont.add(4).writeU16(12);/* 宽度 */
                        unifont.add(6).writeU16(12);/* 高度 */

                        const scale = TURTLE_BASE.add(0x18).readDouble();
                        TURTLE_SET_SCALEX(scale * 8 / 12);
                        TURTLE_SET_SCALEY(scale * 8 / 12);
                        SPRITE_BATCH_PLOT(unifont, 0, a5);
                        TURTLE_SET_SCALE(scale);

                        v13 += _utf8Len - 1;
                    }
                    TURTLE_TRANS(v16.add(12).readS16() * 0.5, 0.0);
                }

                if (Process.platform !== 'darwin' && originalGlyphCb)
                    originalGlyphCb(charV14, 1, originalGlyphCtx);
            }

            // 保留浮点字段
            const savedFloats = TURTLE_BASE.add(0x50).readByteArray(16);

            // 恢复 turtle
            Memory.copy(TURTLE_BASE, savedTurtle, 96);

            // 写回浮点字段
            if (savedFloats !== null) {
                TURTLE_BASE.add(0x50).writeByteArray(savedFloats);
            } else {
                throw new Error("无法读取保存的浮点数据");
            }

            return a3;
        },
        'int', ['pointer', 'pointer', 'int', 'int', 'int']
    ));
    log('Replace glyphs_batch_plot_ex 已安装');
    }
    } else {
        log('iOS glyph replacements 已暂停（atlas-only 隔离测试）');
    }

    // ── Attach load_gfx ──────────────────────────────────────
    // iOS 诊断阶段：不把 2048² 主 atlas 扩到 4096²，也不在
    // load_gfx 返回前手动重新上传。unifont 保持 null 时字形 hook 会回退原函数。
    if (!customFontAtlasEnabled)
        log('iOS custom font atlas 已暂停（灰屏隔离测试）');

    const load_gfx_hook = Interceptor.attach(load_gfx, {
        onEnter(args) {
            if (!customFontAtlasEnabled) return;
            if (Process.platform === 'darwin')
                log('iOS load_gfx enter');
            load_gfx_hooking = 1;
        },
        onLeave(retval) {
            if (!customFontAtlasEnabled) return;
            load_gfx_hooking = 0;
            if (Process.platform === 'darwin')
                log(`iOS load_gfx leave: ${retval}`);

            if (separateFontAtlasEnabled) {
                // Normally initialized immediately after the main atlas upload
                // below. Keep this as a guarded fallback for unusual builds.
                if (!unifont)
                    initIOSFontAtlas();
                return;
            }

            const v0 = ATLAS_GET(0);
            const v149 = retval.toInt32();

            font_base_id = SPRITE_COUNT();
            let v150 = Memory.allocUtf8String(mod.dir + '/assets/font_ucs2_12x12.png');
            log(`font atlas path: ${v150.readCString()}`);
            const v151 = ATLAS_LOAD_SPRITESHEET(v0, 0, 3072, 3072, 0, 1, v150) + v149;
            log(`font atlas loaded: base_id = ${font_base_id}, total_sprites = ${SPRITE_COUNT()}, returned = ${v149}, new = ${v151}`);

            if (!ATLAS_UPLOAD(v0, 0, 3)) {
                WRAPPER_SET_TITLE(Memory.allocUtf8String('DR2C: (!RGB5_A1)'));
                if (!ATLAS_UPLOAD(v0, 0, 2)) {
                    WRAPPER_SET_TITLE(Memory.allocUtf8String('DR2C: (!RGB4A)'));
                    if (!ATLAS_UPLOAD(v0, 0, 0))
                        WRAPPER_SET_TITLE(Memory.allocUtf8String('DR2C: atlas upload FAILED'));
                }
            }

            retval.replace(ptr(v151));
            if (font_base_id === SPRITE_COUNT()) {
                font_base_id = 0;
                warn('load_gfx_hook', 'Failed to load font.');
                return;
            }
            unifont = SPRITE_GET(font_base_id);
            unifont_x = unifont.readU16();
            unifont_y = unifont.add(2).readU16();
            if (isWindowsUnicodeRuntime && globalThis.windowsNativeUnicodeTextState) {
                const state = globalThis.windowsNativeUnicodeTextState;
                state.unifontSlot.writePointer(unifont);
                state.unifontXSlot.writeS32(unifont_x);
                state.unifontYSlot.writeS32(unifont_y);
                log('Windows native UTF-8 text remap font state ready');
            }
        }
    });
    if (Process.platform === 'darwin')
        globalThis.iosLoadGfxHook = load_gfx_hook;
    log('Attach load_gfx 已安装');

    // ── load_gfx_hooking ──────────────────────────────────────
    if (separateFontAtlasEnabled) {
    // Initialize the independent font texture immediately after the game's
    // main atlas upload succeeds. This runs on the graphics thread with a
    // current GL context, without depending on load_gfx's return hook.
    globalThis.iosAtlasUploadInitHook = Interceptor.attach(ATLAS_UPLOAD_PTR, {
        onEnter(args) {
            this.initFontAtlas = load_gfx_hooking && !unifont;
            if (this.initFontAtlas)
                log(`Unicode main atlas_upload enter: atlas = ${args[0]}, filter = ${args[1]}, format = ${args[2]}`);
        },
        onLeave(retval) {
            if (!this.initFontAtlas) return;
            log(`Unicode main atlas_upload leave: ${retval.toInt32()}`);
            if (retval.toInt32() === 0) return;
            load_gfx_hooking = 0;
            log('Unicode main atlas upload complete; initializing font atlas');
            initIOSFontAtlas();
        }
    });
    if (isWindowsUnicodeRuntime || isAndroidUnicodeRuntime) {
        globalThis.mainAtlasSize4096Hook = Interceptor.attach(ATLAS_CREATE_TEXTURE, {
            onEnter(args) {
                if (!load_gfx_hooking) return;
                const atlas0 = ATLAS_GET(0);
                const isMainAtlas = args[0].equals(atlas0);
                if (!isMainAtlas) return;
                const width = args[1].toInt32();
                const height = args[2].toInt32();
                if (width === 4096 && height === 4096) return;
                args[1] = ptr(4096);
                args[2] = ptr(4096);
                const platform = isAndroidUnicodeRuntime ? 'Android' : 'Windows';
                log(`${platform} main atlas ACTIVE: ${width}x${height} → 4096x4096`);
            }
        });
    }
    if (Process.platform === 'darwin') {
        const widthInstruction = globalThis.mainModule.base.add(0x83140).readU32();
        const heightInstruction = globalThis.mainModule.base.add(0x83144).readU32();
        if (widthInstruction === 0x52820001 && heightInstruction === 0x52820002) {
            log('iOS main atlas VERIFIED: static 4096x4096 patch is present');
        } else {
            warn('iOS main atlas patch NOT VERIFIED:',
                `width=0x${widthInstruction.toString(16)}, ` +
                `height=0x${heightInstruction.toString(16)}`);
        }
    }
    log('Attach atlas_upload Unicode font init 已安装');
    } else {
    Interceptor.replace(ATLAS_UPLOAD, new NativeCallback(function (a, b, c) {
        if (load_gfx_hooking) {
            log("skip atlas_upload ", a, b, c);
            return 1;
        }
        return ATLAS_UPLOAD(a, b, c);
    }, 'int', ['pointer', 'int', 'int']));

    Interceptor.replace(ATLAS_FREE_IMAGE_DATA, new NativeCallback(function (a) {
        if (load_gfx_hooking) {
            log("skip ATLAS_FREE_IMAGE_DATA ", a);
            return 1;
        }
        return ATLAS_FREE_IMAGE_DATA(a);
    }, 'void', ['int']));

    Interceptor.attach(ATLAS_CREATE_TEXTURE, {
        onEnter(args) {
            if (load_gfx_hooking) {
                const width = args[1].toInt32();
                const height = args[2].toInt32();
                // Legacy desktop Linux path; Windows/mobile use a separate font atlas.
                const atlasSize = 4096;
                args[1] = ptr(atlasSize);
                args[2] = ptr(atlasSize);
                log(`atlas_create_texture: ${width}x${height} → ${atlasSize}x${atlasSize}`);
            }
        }
    });
    }

    // ── 使用MOD路径加载data ──────────────────────────────────────
    if (Process.platform === 'darwin') {
        // The old implementation coordinated three hooks through one global
        // skip_path_rep flag. iOS loads assets concurrently, so one request
        // could reset another request's flag and redirect the whole data root
        // to a partial mod directory. Override only this invocation's returned
        // full path; Interceptor invocation state (`this`) is thread-local.
        let redirectedPathLogRemaining = 20;
        let redirectedDataOpenLogRemaining = 30;
        Interceptor.attach(FILE_DATA_PATH, {
            onEnter(args) {
                this.modAssetPath = null;
                if (args[0].isNull()) return;
                const relativePath = args[0].readCString();
                if (!relativePath) return;
                const candidate = mod.dir + '/assets/dr2c/' + relativePath;
                try {
                    fs.statSync(candidate);
                    this.modAssetPath = candidate;
                } catch (e) {
                    // No override: the original app data path remains intact.
                }
            },
            onLeave(retval) {
                if (!this.modAssetPath) return;
                if (redirectedPathLogRemaining > 0) {
                    redirectedPathLogRemaining--;
                    log('iOS mod asset redirect', this.modAssetPath);
                }
                retval.replace(L(this.modAssetPath));
            }
        });

        // DeathForth's $loadfile primitive calls file_open_data_read directly;
        // it never goes through file_data_path above. Open an existing mod
        // asset by absolute path, and preserve the native bundle fallback for
        // files the mod does not provide.
        globalThis.iosFileOpenDataReadReplacement = new NativeCallback(relativePathPointer => {
            if (!relativePathPointer.isNull()) {
                const relativePath = relativePathPointer.readCString();
                if (relativePath) {
                    const candidate = mod.dir + '/assets/dr2c/' + relativePath;
                    try {
                        fs.statSync(candidate);
                        if (redirectedDataOpenLogRemaining > 0) {
                            redirectedDataOpenLogRemaining--;
                            log('iOS mod data open redirect', candidate);
                        }
                        return FILE_OPEN_D(L(candidate), 0);
                    } catch (e) {
                        // Missing from the mod: read the original app asset.
                    }
                }
            }
            return FILE_OPEN_DATA_READ(relativePathPointer);
        }, 'pointer', ['pointer']);
        Interceptor.replace(FILE_OPEN_DATA_READ_PTR, globalThis.iosFileOpenDataReadReplacement);
        log('iOS per-call mod asset redirect 已安装');
    } else {
        let skip_path_rep = 0;
        Interceptor.attach(WRAPPER_FILE_DATA_PATH, {
            onLeave(retval) {
                if (skip_path_rep) return;
                retval.replace(L(mod.dir + '/assets/dr2c/'));
            }
        });

        const checkModAsset = {
            onEnter(args) {
                const str = args[0].readCString();
                try {
                    fs.statSync(mod.dir + '/assets/dr2c/' + str);
                } catch (e) {
                    skip_path_rep = 1;
                }
            },
            onLeave(retval) {
                skip_path_rep = 0;
            }
        };
        Interceptor.attach(FILE_DATA_PATH, checkModAsset);
        Interceptor.attach(FILE_OPEN_DATA_READ, checkModAsset);
    }

    // ── utf8自动换行逻辑 ──────────────────────────────────────
    const FILL_CHAR = 0xFF;
    // ── Replace wrap_text_ex: 直接在 JS 里做 UTF-8 感知换行 ──────────────
    // 返回一行内容（指向本地静态缓冲区），并把 *a1 推进到下一行起点。
    // 不再需要 markChar 占位还原：源串保持原始 UTF-8，宽度按整字形测量。
    const WRAP_BUF_SIZE = 256;            // 与原生 wrap_text_ex_buffer 一致
    const wrapBuf = Memory.alloc(WRAP_BUF_SIZE);

    /** ASCII 空白，对应原函数 isspace(_ISspace=0x2000)，但排除 \n \r */
    const isSpaceNoNL = (b) => b === 0x20 || b === 0x09 || b === 0x0B || b === 0x0C;
    /**
     * 返回 p+off 处一个 UTF-8 序列的字节长度。
     * 游戏文本里可能直接混入非法字节，以下情况一律按单字节(返回 1)处理，
     * 避免吞掉后续字符或越过结尾 \0：
     *   - 落单的 continuation 字节 0x80-0xBF；overlong 首字节 0xC0/0xC1；非法首字节 0xF5-0xFF
     *   - 序列被截断、或后续不是合法 continuation(0x80-0xBF，含提前遇到 \0)
     * 注意：只读到 \0 为止，readU8 读到 \0 即判失败返回 1，不会越界。
     */
    const utf8SeqLen = (p, off) => {
        const b0 = p.add(off).readU8();
        if (b0 < 0xC2) return 1;                                  // ASCII / 落单 continuation / overlong 首字节
        const n = b0 < 0xE0 ? 2 : b0 < 0xF0 ? 3 : b0 < 0xF5 ? 4 : 1;
        if (n === 1) return 1;                                    // 0xF5-0xFF
        for (let k = 1; k < n; k++) {
            const bk = p.add(off + k).readU8();
            if (bk < 0x80 || bk > 0xBF) return 1;                // 截断 / 非 continuation（含 \0）
        }
        return n;
    };

    Interceptor.replace(WRAP_TEXT_EX, new NativeCallback((a1, a2, a3, a4) => {
        // ── 入口校验（对应反编译开头的三处 null/空判断）──
        if (a1.isNull()) return NULL;
        const src0 = a1.readPointer();
        if (src0.isNull() || src0.readU8() === 0) return NULL;

        // ── 跳过行首空白（仅 a4 == 0；不跳 \n \r）──
        let start = 0;
        if (a4 === 0) {
            while (isSpaceNoNL(src0.add(start).readU8())) start++;
        }
        const src = src0.add(start);      // 本行扫描起点（对应原 v4）
        // New Windows EXE glyph_w: sprite_get(font id), unsigned byte minus
        // first glyph, signed int16 width at 32*index+12. Resolve the font once
        // per line instead of a JS -> native call for every scanned character.
        const pcDirectWidths = isWindowsUnicodeRuntime && Process.pointerSize === 4 &&
            globalThis.build_stamp === 'JUN-20-2024.10.25';
        const pcFont = pcDirectWidths ? SPRITE_GET(a2.readS16()) : null;
        const pcFirst = pcDirectWidths ? a2.add(4).readS32() : 0;
        const pcCount = pcDirectWidths ? a2.add(8).readS32() : 0;

        // ── 扫描断行点 ──
        let i = 0;            // 当前字节偏移
        let acc = 0;          // 累计宽度（按原函数逐步截断为 int）
        let breakAt = -1;     // 优选断行字节位置（该位置及之后归下一行）
        let lineLen, consumed;

        for (; ;) {
            const b = src.add(i).readU8();

            if (b === 0) {                    // 字符串结束
                lineLen = i; consumed = i; break;
            }
            if (b === 0x0A || b === 0x0D) {   // 硬换行 \n / \r（消费掉换行符）
                lineLen = i; consumed = i + 1;
                // \r\n 视为单个换行，避免多出一个空行
                // log('硬换行 \n / \r（消费掉换行符）');
                if (b === 0x0D && src.add(i + 1).readU8() === 0x0A) consumed = i + 2;
                break;
            }

            const seq = utf8SeqLen(src, i);   // 非法字节会被判为 seq=1，按单字节渲染/推进

            // 记录断行机会：空白处，或宽字符之前（CJK 可在字间换行；非法单字节不算宽字符）
            if (isSpaceNoNL(b)) breakAt = i;          // 空白留到下一行被 trim
            else if (seq >= 2 && i > 0) breakAt = i;  // 合法多字节字符前可断

            // 测量本字符宽度：单字节用本字节，多字节按全/半角字形测量
            const raw = seq === 1 ? b : (seq === 2 ? HALF_WIDTH : FULL_WIDTH);
            const measure = (raw << 24) >> 24;        // (char) 符号扩展，与原版 glyph_w(a2,(char)v8) 一致
            if (pcDirectWidths) {
                const index = (raw & 0xff) - pcFirst;
                const width = index >= 0 && index < pcCount
                    ? pcFont.add(index * 32 + 12).readS16() : 0;
                acc = Math.trunc(acc + width);
            } else {
                acc = Math.trunc(acc + GLYPH_W(a2, measure));
            }

            // 超出最大宽度，或放不下整个字符就会撑爆缓冲区 → 断行
            if (acc >= a3 || i + seq > WRAP_BUF_SIZE - 1) {
                if (breakAt > 0) { lineLen = breakAt; consumed = breakAt; }       // 词/字间断行
                else if (i > 0) { lineLen = i; consumed = i; }                    // 强制字符级断行
                else { lineLen = seq; consumed = seq; }                           // 首字符超宽：至少输出 1 个，防死循环
                break;
            }

            i += seq;
        }

        // ── 写入静态缓冲区并截断 ──
        if (lineLen > 0) Memory.copy(wrapBuf, src, lineLen);
        wrapBuf.add(lineLen).writeU8(0);

        // ── 推进调用方游标（consumed 已含硬换行符）──
        a1.writePointer(src.add(consumed));

        return wrapBuf;
    }, 'pointer', ['pointer', 'pointer', 'int', 'int']));

    // ── utf8字符测宽逻辑 ──────────────────────────────────────

    /**
     * 把 input(UTF-8) 里的多字节字符替换成等长占位字节写入 output，供原生 text_w 测宽：
     *   2 字节字符   → [FILL_CHAR, HALF_WIDTH]
     *   3/4 字节字符 → [FILL_CHAR ×(n-1), FULL_WIDTH]
     * FILL_CHAR(0xFF) 是零宽字形，末尾的宽度标记字节贡献半/全角宽度，
     * 因此每个字符恰好计一个半/全角字形——与 wrap_text_ex 的宽度口径完全一致。
     * ASCII 和非法字节(seq=1)原样拷贝。text_w 只返回宽度，不需要 markCharUni 还原。
     * 输出字节数与输入相同，复用 markCharOut(10240) 不会膨胀。
     * @param {NativePointer} input
     * @param {NativePointer} output
     */
    function fillWideChars(input, output) {
        let i = 0, o = 0;
        for (; o < 10240 - 4;) {
            const b = input.add(i).readU8();
            if (b === 0) break;
            const seq = utf8SeqLen(input, i);
            if (seq === 1) {
                output.add(o++).writeU8(b);            // ASCII / 非法字节原样
            } else {
                for (let k = 0; k < seq - 1; k++) output.add(o++).writeU8(FILL_CHAR);
                output.add(o++).writeU8(seq === 2 ? HALF_WIDTH : FULL_WIDTH);
            }
            i += seq;
        }
        output.add(o).writeU8(0);
    }

    Interceptor.attach(text_w, {
        onEnter(args) {
            if (args[0].isNull()) return;
            fillWideChars(args[0], markCharOut);
            args[0] = markCharOut;
        }
    });

    if (lateActivation && globalThis.iosRequestLateFontAtlasInit)
        globalThis.iosRequestLateFontAtlasInit();
    log('hookUtf8 inited');
}


/**
 * Expand the OCT-03-2022 iOS definition tables without growing their BSS
 * allocations. The old build stores a 256-byte description inside every
 * 0x140-byte gamemode/perk/trait record. Moving descriptions to Frida-owned
 * memory leaves compact records that fit 64 entries in the original tables:
 *
 *   gamemode: name[40], icon@0x28, locked@0x2c, applyword@0x30, stride 0x40
 *   perk/trait: name[40], level@0x88, locked@0x90, applyword@0x98, stride 0xa0
 *
 * The fixed metadata boundaries (0x2800/0x2808 for perk/trait and 0x2d00 for
 * gamemodes) stay unchanged, preserving all count/page globals and callers.
 */
function hookIOSDefinitionCapacity() {
    if (Process.platform !== 'darwin' || globalThis.build_stamp !== 'OCT-03-2022.14.24')
        return;
    if (globalThis.iosDefinitionCapacityInstalled)
        return;

    const base = globalThis.mainModule.base;

    const movW = (rd, imm) => (0x52800000 | ((imm & 0xffff) << 5) | rd) >>> 0;
    const addX = (rd, rn, imm) => (0x91000000 | ((imm & 0xfff) << 10) | (rn << 5) | rd) >>> 0;
    const cmpW = (rn, imm) => (0x7100001f | ((imm & 0xfff) << 10) | (rn << 5)) >>> 0;
    const ldrW = (rt, rn, off) => (0xb9400000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
    const strW = (rt, rn, off) => (0xb9000000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
    const ldrX = (rt, rn, off) => (0xf9400000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
    const strX = (rt, rn, off) => (0xf9000000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;

    let patchedInstructions = 0;
    const pendingPatches = [];
    const verifyInstruction = (rva, expected, replacement, label) => {
        const address = base.add(rva);
        const actual = address.readU32() >>> 0;
        if (actual === replacement) return;
        if (actual !== expected) {
            throw new Error(
                `iOS capacity patch mismatch ${label} @ 0x${rva.toString(16)}: ` +
                `expected 0x${expected.toString(16)}, got 0x${actual.toString(16)}`
            );
        }
        pendingPatches.push([address, replacement]);
    };

    // Gamemode: 36 x 0x140 -> 64 x 0x40, with descriptions stored externally.
    const modePatches = [
        [0x911F8, movW(9, 0x140), movW(9, 0x40), 'gamemode_is_locked stride'],
        [0x91208, ldrW(0, 8, 0x130), ldrW(0, 8, 0x2c), 'gamemode_is_locked field'],
        [0x91248, movW(10, 0x140), movW(10, 0x40), 'gamemode_applyword stride'],
        [0x91250, ldrX(0, 8, 0x138), ldrX(0, 8, 0x30), 'gamemode_applyword field'],
        [0x912B4, movW(24, 0x140), movW(24, 0x40), 'gamemode_layout list stride'],
        [0x91338, ldrW(8, 8, 0x12c), ldrW(8, 8, 0x28), 'gamemode_layout icon'],
        [0x91360, ldrW(8, 8, 0x130), ldrW(8, 8, 0x2c), 'gamemode_layout locked'],
        [0x914B4, movW(20, 0x140), movW(20, 0x40), 'gamemode_layout detail stride'],
        [0x914C4, ldrW(8, 8, 0x12c), ldrW(8, 8, 0x28), 'gamemode_layout detail icon'],
        [0x914F8, ldrW(9, 9, 0x130), ldrW(9, 9, 0x2c), 'gamemode_layout detail locked'],
        [0x9169C, movW(25, 0x140), movW(25, 0x40), 'btn_gamemode_desc stride'],
        [0x9170C, ldrW(8, 8, 0x130), ldrW(8, 8, 0x2c), 'btn_gamemode_desc locked'],
        [0x91B20, cmpW(8, 0x24), cmpW(8, 0x40), 'word_strmode capacity'],
        [0x91B4C, movW(9, 0x140), movW(9, 0x40), 'word_strmode stride'],
        [0x91BD8, strW(0, 8, 0x12c), strW(0, 8, 0x28), 'word_mode_icon field'],
        [0x91BF8, strW(0, 8, 0x130), strW(0, 8, 0x2c), 'word_mode_locked field'],
        [0x91C1C, strX(0, 8, 0x138), strX(0, 8, 0x30), 'word_mode_applyword field'],
        [0x91CD0, ldrW(8, 20, 0x130), ldrW(8, 20, 0x2c), 'gamemode button locked'],
        [0x91DCC, movW(9, 0x140), movW(9, 0x40), 'gamemode button stride']
    ];

    // Perk/trait: two fixed 0x2800-byte data partitions, 64 x 0xa0 each.
    const perkPatches = [
        [0x3512C, ldrW(8, 0, 0x130), ldrW(8, 0, 0x90), 'random perk locked'],
        [0x35150, ldrW(8, 0, 0x130), ldrW(8, 0, 0x90), 'random trait locked'],
        [0x91F6C, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'perkntrait_find stride'],
        [0x92164, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'word_strperk search stride'],
        [0x92170, cmpW(21, 0x20), cmpW(21, 0x40), 'word_strperk capacity'],
        [0x921A4, movW(8, 0x140), movW(8, 0xa0), 'word_strperk insert stride'],
        [0x92230, addX(20, 20, 0x140), addX(20, 20, 0xa0), 'word_strtrait search stride'],
        [0x9223C, cmpW(21, 0x21), cmpW(21, 0x40), 'word_strtrait capacity'],
        [0x92270, movW(8, 0x140), movW(8, 0xa0), 'word_strtrait insert stride'],
        [0x9231C, strW(9, 8, 0x128), strW(9, 8, 0x88), 'word_lvl field'],
        [0x92340, strW(0, 8, 0x130), strW(0, 8, 0x90), 'word_lock field'],
        [0x92364, strX(0, 8, 0x138), strX(0, 8, 0x98), 'word_applyword field'],
        [0x923AC, movW(10, 0x140), movW(10, 0xa0), 'perk_info stride'],
        [0x923D4, movW(10, 0x140), movW(10, 0xa0), 'trait_info stride'],
        [0x92510, movW(9, 0x140), movW(9, 0xa0), 'perkntrait layout first stride'],
        [0x92598, addX(27, 27, 0x140), addX(27, 27, 0xa0), 'perkntrait layout next stride'],
        [0x92728, movW(10, 0x140), movW(10, 0xa0), 'perk button trait stride'],
        [0x92730, ldrW(8, 8, 0x130), ldrW(8, 8, 0x90), 'perk button trait locked'],
        [0x9279C, movW(10, 0x140), movW(10, 0xa0), 'perk button perk stride'],
        [0x927CC, movW(10, 0x140), movW(10, 0xa0), 'perk button selected stride'],
        [0x927D4, ldrW(10, 10, 0x130), ldrW(10, 10, 0x90), 'perk button selected locked'],
        [0x92870, movW(10, 0x140), movW(10, 0xa0), 'perk button level stride'],
        [0x92878, ldrW(8, 8, 0x128), ldrW(8, 8, 0x88), 'perk button level'],
        [0x9295C, cmpW(8, 0x18), cmpW(8, 0x38), 'perk/trait page maximum compare'],
        [0x92960, movW(10, 0x18), movW(10, 0x38), 'perk/trait page maximum value'],
        [0x929E8, ldrW(8, 19, 0x130), ldrW(8, 19, 0x90), 'perk description locked'],
        [0x92A58, ldrW(8, 19, 0x128), ldrW(8, 19, 0x88), 'perk description level'],
        [0x973D0, ldrX(1, 0, 0x138), ldrX(1, 0, 0x98), 'perkfinder applyword']
    ];

    for (const patch of modePatches) verifyInstruction(...patch);
    for (const patch of perkPatches) verifyInstruction(...patch);
    for (const [address, replacement] of pendingPatches) {
        Memory.patchCode(address, 4, code => code.writeU32(replacement));
        patchedInstructions++;
    }

    const MODE_BASE = base.add(0x4E7F68);
    const MODE_CURRENT = base.add(0x4EAC70);
    const MODE_STRIDE = 0x40;
    // The compact records only occupy the first 0x1000 bytes of the original
    // 0x2d00-byte gamemode allocation.  Keep a native pointer table in the
    // reclaimed tail so the statically patched strict-signing display path can
    // retrieve the Frida-owned descriptions without intercepting libc.
    const MODE_DESCRIPTION_TABLE = MODE_BASE.add(64 * MODE_STRIDE);
    // Keep the mission-summary table in unused writable __FRIDA_DATA0 space.
    // Unlike the reclaimed gamemode allocation, the game never zeroes this
    // segment while rebuilding definitions.
    const LOOT_SUMMARY_TABLE = base.add(0x5EC800);
    // Five pointers used by the strict static custom-character storage bridge:
    // title format, SAVE, LOAD, empty-slot label and delete-confirmation format.
    const CHARACTER_STORAGE_TABLE = base.add(0x5EC900);
    // Strict map-event bridges: the resource-7 "junk." special case and the
    // context-specific empty-car message used by both siphoning exit paths.
    const MAP_EVENT_TABLE = base.add(0x5EC940);
    // One pointer for the hardcoded NONE label in the pause/equipment-swap UI.
    const EQUIPMENT_SWAP_TABLE = base.add(0x5EC950);
    // Empty-member label and header format for the pause-menu team loot page.
    const TEAM_LOOT_TABLE = base.add(0x5EC958);
    // No-buddy and with-buddy states in the pre-game starting-companion UI.
    const STARTING_BUDDY_TABLE = base.add(0x5EC968);
    // Lead, follow and rest description pointers in the pre-mission role tab.
    const ROLE_DESCRIPTION_TABLE = base.add(0x5EC978);
    const PERK_BASE = base.add(0x4EAC88);
    const PERK_CURRENT = base.add(0x4EFC98);
    const PERK_STRIDE = 0xa0;
    const PERK_PARTITION = 0x2808;
    const EMPTY = allocMixedString('');
    const modeDescriptions = new Array(64);
    const perkDescriptions = new Array(128);

    const preserveNativeString = pointer => {
        if (!pointer || pointer.isNull()) return EMPTY;
        const value = readByteString(pointer);
        return value === null ? EMPTY : allocMixedString(value);
    };

    const modeIndex = pointer => {
        if (!pointer || pointer.isNull()) return -1;
        const offset = pointer.sub(MODE_BASE).toInt32();
        if (offset < 0 || offset >= 64 * MODE_STRIDE || offset % MODE_STRIDE !== 0) return -1;
        return Math.floor(offset / MODE_STRIDE);
    };

    const perkIndex = pointer => {
        if (!pointer || pointer.isNull()) return -1;
        const offset = pointer.sub(PERK_BASE).toInt32();
        if (offset >= 0 && offset < 64 * PERK_STRIDE && offset % PERK_STRIDE === 0)
            return Math.floor(offset / PERK_STRIDE);
        const traitOffset = offset - PERK_PARTITION;
        if (traitOffset >= 0 && traitOffset < 64 * PERK_STRIDE && traitOffset % PERK_STRIDE === 0)
            return 64 + Math.floor(traitOffset / PERK_STRIDE);
        return -1;
    };

    const fsPopString = new NativeFunction(findSymbol('fs_pop_string'), 'pointer', ['pointer']);
    const fsPushString = new NativeFunction(findSymbol('fs_push_string'), 'int', ['pointer', 'pointer']);

    globalThis.iosModeDescSetter = new NativeCallback(a1 => {
        const source = fsPopString(a1);
        const current = MODE_CURRENT.readPointer();
        const index = modeIndex(current);
        if (index >= 0) {
            const description = preserveNativeString(source);
            modeDescriptions[index] = description;
            MODE_DESCRIPTION_TABLE.add(index * Process.pointerSize)
                .writePointer(description);
        }
        return current;
    }, 'pointer', ['pointer']);
    Interceptor.replace(base.add(0x91B84), globalThis.iosModeDescSetter);

    globalThis.iosPerkDescSetter = new NativeCallback(a1 => {
        const source = fsPopString(a1);
        const current = PERK_CURRENT.readPointer();
        const index = perkIndex(current);
        if (index >= 0) perkDescriptions[index] = preserveNativeString(source);
        return current;
    }, 'pointer', ['pointer']);
    Interceptor.replace(base.add(0x922C4), globalThis.iosPerkDescSetter);

    globalThis.iosPerkDescGetter = new NativeCallback(a1 => {
        const index = perkIndex(PERK_CURRENT.readPointer());
        return fsPushString(a1, index >= 0 && perkDescriptions[index] ? perkDescriptions[index] : EMPTY);
    }, 'int', ['pointer']);
    Interceptor.replace(base.add(0x92370), globalThis.iosPerkDescGetter);

    const descriptionFromPerkField = pointer => {
        if (!pointer || pointer.isNull()) return null;
        const index = perkIndex(pointer.sub(40));
        return index >= 0 ? (perkDescriptions[index] || EMPTY) : null;
    };
    for (const name of ['cyoa_just_ok', 'cyoa_yesno']) {
        Interceptor.attach(findSymbol(name), {
            onEnter(args) {
                const description = descriptionFromPerkField(args[0]);
                if (description) args[0] = description;
            }
        });
    }

    const descriptionFromModeField = pointer => {
        if (!pointer || pointer.isNull()) return null;
        const index = modeIndex(pointer.sub(40));
        return index >= 0 ? (modeDescriptions[index] || EMPTY) : null;
    };
    if (!IOS_STRICT_CODE_SIGNING) {
        globalThis.iosModeDescriptionStrlenHook = Interceptor.attach(findSymbol('strlen'), {
            onEnter(args) {
                const description = descriptionFromModeField(args[0]);
                if (description) args[0] = description;
            }
        });
        globalThis.iosModeDescriptionStrcatHook = Interceptor.attach(findSymbol('strcat'), {
            onEnter(args) {
                const description = descriptionFromModeField(args[1]);
                if (description) args[1] = description;
            }
        });
    } else {
        info('iOS autonomous gamemode libc display hooks skipped');
    }

    const clearModeDescriptions = () => {
        modeDescriptions.fill(undefined);
        for (let index = 0; index < 64; index++) {
            MODE_DESCRIPTION_TABLE.add(index * Process.pointerSize)
                .writePointer(EMPTY);
        }
    };
    clearModeDescriptions();
    globalThis.iosLootSummaryTable = LOOT_SUMMARY_TABLE;
    globalThis.iosCharacterStorageTable = CHARACTER_STORAGE_TABLE;
    globalThis.iosMapEventTable = MAP_EVENT_TABLE;
    globalThis.iosEquipmentSwapTable = EQUIPMENT_SWAP_TABLE;
    globalThis.iosTeamLootTable = TEAM_LOOT_TABLE;
    globalThis.iosStartingBuddyTable = STARTING_BUDDY_TABLE;
    globalThis.iosRoleDescriptionTable = ROLE_DESCRIPTION_TABLE;
    refreshIOSLootSummaryTranslations();
    refreshIOSCharacterStorageTranslations();
    refreshIOSMapEventTranslations();
    refreshIOSEquipmentSwapTranslations();
    refreshIOSTeamLootTranslations();
    refreshIOSStartingBuddyTranslations();
    refreshIOSRoleDescriptions();
    Interceptor.attach(base.add(0x919E0), {
        onEnter() { clearModeDescriptions(); }
    });
    Interceptor.attach(base.add(0x91F90), {
        onEnter() { perkDescriptions.fill(undefined); }
    });

    globalThis.iosDefinitionCapacityInstalled = true;
    globalThis.iosModeDescriptions = modeDescriptions;
    globalThis.iosModeDescriptionTable = MODE_DESCRIPTION_TABLE;
    globalThis.iosPerkDescriptions = perkDescriptions;
    log(`iOS gamemode/perk/trait capacity expanded to 64 (${patchedInstructions} instructions)`);
}

/**
 * The JUN-20-2024 Windows executable already reserves 64 full perk records
 * and 64 full trait records.  Its game-mode table is the outlier: only 36
 * complete 0x138-byte records live in BSS.  Redirect every verified x86
 * reference to a Frida-owned 64-record table before DeathForth is parsed.
 *
 * Keeping the original 0x138-byte record layout is deliberate.  Unlike the
 * old iOS executable, this PC build has no reclaimable padding in a record:
 * each description is stored inline and is used by the native details page.
 */
function hookWindowsDefinitionCapacity() {
    if (Process.platform !== 'windows'
        || Process.arch !== 'ia32'
        || globalThis.build_stamp !== 'JUN-20-2024.10.25'
        || globalThis.windowsDefinitionCapacityInstalled)
        return;

    const base = globalThis.mainModule.base;
    const RECORD_STRIDE = 0x138;
    const ORIGINAL_CAPACITY = 36;
    const CAPACITY = 64;
    const ORIGINAL_TABLE_SIZE = ORIGINAL_CAPACITY * RECORD_STRIDE;
    const TABLE_SIZE = CAPACITY * RECORD_STRIDE;
    const ORIGINAL_TABLE = base.add(0x3CEDA0);
    const MODE_COUNT = base.add(0x3D1980);
    const MODE_CURRENT = base.add(0x3D1984);
    const codeStart = base.add(0x1000);
    const codeSize = 0xCF000;

    const u32Pattern = value => {
        const n = value >>> 0;
        return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join(' ');
    };
    const findExactly = (address, size, pattern, expectedCount, label) => {
        const matches = Memory.scanSync(address, size, pattern);
        if (matches.length !== expectedCount) {
            throw new Error(
                `Windows gamemode capacity patch mismatch ${label}: ` +
                `expected ${expectedCount} match(es), got ${matches.length}`
            );
        }
        return matches;
    };

    // These are the only in-record absolute bases in the current executable:
    // record start, icon (+0x12c), locked (+0x130), applyword (+0x134).
    // Match counts are intentionally strict, so a future EXE will be skipped
    // rather than receiving an incomplete pointer redirect.
    const pointerBases = [
        [0x000, 6, 'record base'],
        [0x12c, 2, 'icon field'],
        [0x130, 4, 'locked field'],
        [0x134, 1, 'applyword field']
    ];
    const pendingPointerPatches = [];
    for (const [offset, expectedCount, label] of pointerBases) {
        const oldPointer = ORIGINAL_TABLE.add(offset).toUInt32();
        const matches = findExactly(codeStart, codeSize, u32Pattern(oldPointer), expectedCount, label);
        for (const match of matches) pendingPointerPatches.push([match.address, offset]);
    }

    // word_strmode: cmp edx, 35.  Its following JG rejects the 37th entry;
    // changing the immediate to 63 permits exactly 64 entries (0..63).
    const capacityImmediate = findExactly(base.add(0x58C00), 0x80, '83 fa 23', 1, 'word_strmode limit')[0]
        .address
        .add(2);
    if (capacityImmediate.readU8() !== 0x23)
        throw new Error('Windows gamemode capacity patch mismatch word_strmode immediate');

    const expandedTable = Memory.alloc(TABLE_SIZE);
    Memory.copy(expandedTable, ORIGINAL_TABLE, ORIGINAL_TABLE_SIZE);

    // All table-reset entry points used by gamedef configuration still clear
    // the old BSS tail, which used to include count/current.  Reset those two
    // globals explicitly and clear all 64 redirected records before native
    // code runs, preserving the original parser lifecycle.
    const clearExpandedTable = () => {
        expandedTable.writeByteArray(new Array(TABLE_SIZE).fill(0));
        MODE_COUNT.writeS32(0);
        MODE_CURRENT.writePointer(ptr(0));
    };
    for (const rva of [0x584A0, 0x58C80, 0x59190]) {
        Interceptor.attach(base.add(rva), { onEnter: clearExpandedTable });
    }

    for (const [address, offset] of pendingPointerPatches) {
        const replacement = expandedTable.add(offset).toUInt32();
        Memory.patchCode(address, 4, code => code.writeU32(replacement));
    }
    Memory.patchCode(capacityImmediate, 1, code => code.writeU8(0x3f));

    globalThis.windowsDefinitionCapacityInstalled = true;
    globalThis.windowsGamemodeTable = expandedTable;
    log(`Windows gamemode capacity expanded ${ORIGINAL_CAPACITY} → ${CAPACITY}; perks/traits already use 64`);
}

// Definition capacity must never prevent the unrelated UTF-8/font hooks from
// starting.  A new executable may legitimately fail the strict code-layout
// check above; in that case leave its native capacity untouched and continue
// with the normal Chinese rendering path.
function tryHookWindowsDefinitionCapacity() {
    try {
        hookWindowsDefinitionCapacity();
    } catch (error) {
        info('Windows gamemode capacity expansion skipped:', error);
    }
}

/**
 * Android MAY-04-2023 keeps roughly 32 perk/trait records because each
 * 0x140-byte record embeds a 256-byte description.  Move those descriptions to
 * Frida-owned memory and compact the native records in place.  The fixed BSS
 * partitions then hold 64 entries:
 *
 *   arm64 perk/trait 0xa0
 *   armv7 perk/trait 0x98
 *
 * Game-mode records use the same compact representation. Their detail page
 * reads two descriptions directly; those loads are redirected to the unused
 * final pointer slot at +0x38, preserving the native button draw callbacks.
 *
 * Every instruction is checked before any write occurs.  A different game
 * build therefore logs and skips this feature instead of receiving a partial
 * binary patch.
 */
function hookAndroidDefinitionCapacity() {
    if (Process.platform !== 'linux' || !globalThis.isAndroid ||
        globalThis.build_stamp !== 'MAY-04-2023.09.30' ||
        globalThis.androidDefinitionCapacityInstalled) return;
    if (Process.arch !== 'arm64' && Process.arch !== 'arm')
        throw new Error('Unsupported Android definition ABI: ' + Process.arch);

    const base = globalThis.mainModule.base;
    const arm64 = Process.arch === 'arm64';
    const EXPAND_ANDROID_GAMEMODES = true;
    const pending = [];

    const bytesEqual = (address, expected) => {
        const actual = new Uint8Array(address.readByteArray(expected.length));
        return expected.every((byte, index) => actual[index] === byte);
    };
    const queueBytes = (rva, expected, replacement, label) => {
        if (!EXPAND_ANDROID_GAMEMODES && label.startsWith('mode ')) return;
        const address = base.add(rva);
        if (bytesEqual(address, replacement)) return;
        if (!bytesEqual(address, expected)) {
            const actual = Array.from(new Uint8Array(address.readByteArray(expected.length)))
                .map(value => value.toString(16).padStart(2, '0')).join(' ');
            throw new Error(
                `Android capacity patch mismatch ${label} @ 0x${rva.toString(16)}: ${actual}`
            );
        }
        pending.push({address, replacement, label});
    };
    const u32Bytes = value => [
        value & 0xff,
        (value >>> 8) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 24) & 0xff
    ];
    const queueU32 = (rva, expected, replacement, label) =>
        queueBytes(rva, u32Bytes(expected >>> 0), u32Bytes(replacement >>> 0), label);

    if (arm64) {
        const movW = (rd, imm) =>
            (0x52800000 | ((imm & 0xffff) << 5) | rd) >>> 0;
        const movX = (rd, imm) =>
            (0xd2800000 | ((imm & 0xffff) << 5) | rd) >>> 0;
        const addX = (rd, rn, imm) =>
            (0x91000000 | ((imm & 0xfff) << 10) | (rn << 5) | rd) >>> 0;
        const cmpW = (rn, imm) =>
            (0x7100001f | ((imm & 0xfff) << 10) | (rn << 5)) >>> 0;
        const ldrW = (rt, rn, off) =>
            (0xb9400000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
        const strW = (rt, rn, off) =>
            (0xb9000000 | (((off / 4) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
        const ldrX = (rt, rn, off) =>
            (0xf9400000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;
        const strX = (rt, rn, off) =>
            (0xf9000000 | (((off / 8) & 0xfff) << 10) | (rn << 5) | rt) >>> 0;

        const patches = [
            // Gamemode records: 36 x 0x140 -> 64 x 0x40.
            [0x821B0, movX(10, 0x140), movX(10, 0x40), 'mode locked stride'],
            [0x821C4, ldrW(0, 8, 0x130), ldrW(0, 8, 0x2c), 'mode locked field'],
            [0x823E0, movX(10, 0x140), movX(10, 0x40), 'mode apply stride'],
            [0x823EC, ldrX(0, 8, 0x138), ldrX(0, 8, 0x30), 'mode apply field'],
            [0x82478, movX(1, 0x140), movX(1, 0x40), 'mode layout stride'],
            [0x82484, ldrW(11, 8, 0x12c), ldrW(11, 8, 0x28), 'mode layout icon'],
            [0x827DC, movW(12, 0x140), movW(12, 0x40), 'mode detail stride'],
            [0x82814, addX(8, 8, 0x28), ldrX(8, 8, 0x38), 'mode detail description length pointer'],
            [0x828B4, addX(1, 8, 0x28), ldrX(1, 8, 0x38), 'mode detail description concatenate pointer'],
            [0x82980, movX(10, 0x140), movX(10, 0x40), 'mode locked lookup stride'],
            [0x82994, ldrW(0, 8, 0x130), ldrW(0, 8, 0x2c), 'mode locked lookup field'],
            [0x82C1C, movX(1, 0x140), movX(1, 0x40), 'mode alternate layout stride'],
            [0x82C28, ldrW(11, 9, 0x12c), ldrW(11, 9, 0x28), 'mode alternate icon'],
            [0x8304C, cmpW(8, 0x24), cmpW(8, 0x40), 'mode capacity'],
            [0x83084, movX(10, 0x140), movX(10, 0x40), 'mode insert stride'],
            [0x83170, strW(0, 30, 0x12c), strW(0, 30, 0x28), 'mode icon setter'],
            [0x831A4, strW(0, 30, 0x130), strW(0, 30, 0x2c), 'mode locked setter'],
            [0x831F4, strX(9, 8, 0x138), strX(9, 8, 0x30), 'mode apply setter'],
            // sub_83218 receives a compact mode-record pointer as an
            // argument, so it has no direct BSS reference for the static
            // scan to find.  Its locked-icon read needs the same relocation.
            [0x83318, ldrW(12, 8, 0x130), ldrW(12, 8, 0x2c), 'mode detail helper locked field'],
            [0x834D0, movW(11, 0x140), movW(11, 0x40), 'mode button stride'],

            // Perk/trait records: 0x140 -> 0xa0.
            [0x3D570, ldrW(9, 8, 0x130), ldrW(9, 8, 0x90), 'random perk locked'],
            [0x3D5AC, ldrW(9, 8, 0x130), ldrW(9, 8, 0x90), 'random trait locked'],
            [0xC61F8, movX(10, 0x140), movX(10, 0xa0), 'perk find stride'],
            [0xC64C8, cmpW(9, 0x20), cmpW(9, 0x40), 'perk capacity'],
            [0xC650C, movX(11, 0x140), movX(11, 0xa0), 'perk insert stride'],
            [0xC65BC, cmpW(10, 0x20), cmpW(10, 0x40), 'trait capacity'],
            [0xC6610, movX(11, 0x140), movX(11, 0xa0), 'trait insert stride'],
            [0xC6758, strW(8, 9, 0x128), strW(8, 9, 0x88), 'perk level setter'],
            [0xC67A8, strW(9, 8, 0x130), strW(9, 8, 0x90), 'perk locked setter'],
            [0xC67F8, strX(9, 8, 0x138), strX(9, 8, 0x98), 'perk apply setter'],
            [0xC68E4, movX(13, 0x140), movX(13, 0xa0), 'perk info stride'],
            [0xC6978, movX(13, 0x140), movX(13, 0xa0), 'trait info stride'],
            [0xC6C58, movX(13, 0x140), movX(13, 0xa0), 'perk first layout stride'],
            [0xC6CEC, movX(13, 0x140), movX(13, 0xa0), 'perk next layout stride'],
            [0xC6FE0, cmpW(8, 0x18), cmpW(8, 0x38), 'perk page maximum compare'],
            // The compiler encoded `mov w8, #0x18` as the ORR-immediate MOV
            // alias (0x321d07e8), rather than MOVZ.  Replacing it with the
            // equivalent MOVZ form is safe, but verification must match the
            // instruction that is actually present in this exact build.
            [0xC7068, 0x321d07e8, movW(8, 0x38), 'perk page maximum value'],
            [0xC7150, ldrW(10, 9, 0x130), ldrW(10, 9, 0x90), 'perk detail locked'],
            [0xC71E0, ldrW(9, 8, 0x128), ldrW(9, 8, 0x88), 'perk detail level first'],
            [0xC71F4, ldrW(9, 8, 0x128), ldrW(9, 8, 0x88), 'perk detail level second'],
            [0xC72F4, ldrW(9, 0, 0x130), ldrW(9, 0, 0x90), 'perk button locked'],
            [0xC73DC, ldrW(9, 0, 0x128), ldrW(9, 0, 0x88), 'perk button level first'],
            [0xC73F8, ldrW(9, 0, 0x128), ldrW(9, 0, 0x88), 'perk button level second'],
            [0xC74A4, ldrW(9, 0, 0x130), ldrW(9, 0, 0x90), 'trait button locked'],
            [0xD53D0, ldrX(1, 8, 0x138), ldrX(1, 8, 0x98), 'perkfinder applyword']
        ];
        for (const patch of patches) queueU32(...patch);
    } else {
        // Thumb-2 encodings verified against the supplied armeabi-v7a .so.
        const patches = [
            // Gamemode.
            [0x62072, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x40,0x02], 'mode locked stride'],
            [0x6207E, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x2c,0x00], 'mode locked field'],
            [0x621DC, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x40,0x02], 'mode apply stride'],
            [0x621E4, [0xd0,0xf8,0x34,0x01], [0xd0,0xf8,0x30,0x00], 'mode apply field'],
            [0x62276, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x40,0x03], 'mode layout stride'],
            [0x6227E, [0xd1,0xf8,0x2c,0x11], [0xd1,0xf8,0x28,0x10], 'mode layout icon'],
            [0x625A0, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x40,0x03], 'mode detail stride'],
            [0x625BE, [0x11,0xf1,0x28,0x01], [0xd1,0xf8,0x38,0x10], 'mode detail description length pointer'],
            [0x6265A, [0x11,0xf1,0x28,0x01], [0xd1,0xf8,0x38,0x10], 'mode detail description concatenate pointer'],
            [0x6272C, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x40,0x03], 'mode locked lookup stride'],
            [0x62738, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x2c,0x00], 'mode locked lookup field'],
            [0x62900, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x40,0x03], 'mode alternate stride'],
            [0x62908, [0xd1,0xf8,0x2c,0x11], [0xd1,0xf8,0x28,0x10], 'mode alternate icon'],
            [0x62C82, [0x24,0x28], [0x40,0x28], 'mode capacity'],
            [0x62CAC, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x40,0x03], 'mode insert stride'],
            [0x62D92, [0xc1,0xf8,0x2c,0x01], [0xc1,0xf8,0x28,0x00], 'mode icon setter'],
            [0x62DBE, [0xc1,0xf8,0x30,0x01], [0xc1,0xf8,0x2c,0x00], 'mode locked setter'],
            [0x62DFE, [0xc1,0xf8,0x34,0x01], [0xc1,0xf8,0x30,0x00], 'mode apply setter'],
            [0x62EEC, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x2c,0x00], 'mode detail helper locked field'],
            [0x63044, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x40,0x02], 'mode button stride'],

            // Perk/trait.
            [0x2B0AE, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x90,0x00], 'random perk locked'],
            [0x2B0D8, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x90,0x00], 'random trait locked'],
            [0x979BA, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x98,0x02], 'perk find stride'],
            [0x97BC4, [0x20,0x28], [0x40,0x28], 'perk capacity'],
            [0x97BEA, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x98,0x03], 'perk insert stride'],
            [0x97C88, [0x21,0x28], [0x40,0x28], 'trait capacity'],
            [0x97CAE, [0x4f,0xf4,0x9c,0x73], [0x4f,0xf0,0x98,0x03], 'trait insert stride'],
            [0x97DB6, [0xc1,0xf8,0x28,0x01], [0xc1,0xf8,0x88,0x00], 'perk level setter'],
            [0x97DF2, [0xc1,0xf8,0x30,0x01], [0xc1,0xf8,0x90,0x00], 'perk locked setter'],
            [0x97E2E, [0xc1,0xf8,0x34,0x01], [0xc1,0xf8,0x94,0x00], 'perk apply setter'],
            [0x97ED2, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x98,0x02], 'perk info stride'],
            [0x97F32, [0x4f,0xf4,0x9c,0x72], [0x4f,0xf0,0x98,0x02], 'trait info stride'],
            [0x98120, [0x4f,0xf4,0x9c,0x7c], [0x4f,0xf0,0x98,0x0c], 'perk layout stride'],
            [0x98416, [0x17,0x28], [0x37,0x28], 'perk page maximum compare'],
            [0x9846C, [0x18,0x20], [0x38,0x20], 'perk page maximum value'],
            [0x98524, [0xd1,0xf8,0x30,0x11], [0xd1,0xf8,0x90,0x10], 'perk detail locked'],
            [0x98596, [0xd1,0xf8,0x28,0x11], [0xd1,0xf8,0x88,0x10], 'perk detail level first'],
            [0x985AA, [0xd0,0xf8,0x28,0x01], [0xd0,0xf8,0x88,0x00], 'perk detail level second'],
            [0x986A4, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x90,0x00], 'perk button locked'],
            [0x9873C, [0xd0,0xf8,0x28,0x01], [0xd0,0xf8,0x88,0x00], 'perk button level first'],
            [0x98750, [0xd0,0xf8,0x28,0x01], [0xd0,0xf8,0x88,0x00], 'perk button level second'],
            [0x987D0, [0xd0,0xf8,0x30,0x01], [0xd0,0xf8,0x90,0x00], 'trait button locked'],
            [0xA31B2, [0xd1,0xf8,0x34,0x11], [0xd1,0xf8,0x94,0x10], 'perkfinder applyword']
        ];
        for (const patch of patches) queueBytes(...patch);
    }

    // Apply only after every expected instruction above has passed.
    for (const patch of pending) {
        Memory.patchCode(patch.address, patch.replacement.length, code => {
            code.writeByteArray(patch.replacement);
        });
    }

    const MODE_BASE = base.add(arm64 ? 0x24BBF8 : 0x1C6558);
    const MODE_CURRENT = base.add(arm64 ? 0x24E900 : 0x1C913C);
    const MODE_STRIDE = 0x40;
    const PERK_BASE = base.add(arm64 ? 0x2EF118 : 0x268B80);
    const PERK_CURRENT = base.add(arm64 ? 0x2F4128 : 0x26D990);
    const PERK_STRIDE = arm64 ? 0xa0 : 0x98;
    const PERK_PARTITION = arm64 ? 0x2808 : 0x2708;
    const modeDescriptions = new Array(64);
    const perkDescriptions = new Array(128);
    const EMPTY = Memory.allocUtf8String('');
    const strlen = new NativeFunction(getGlobalExport('strlen'), 'ulong', ['pointer']);
    const fsPopString = new NativeFunction(findSymbol('fs_pop_string'), 'pointer', ['pointer']);
    const fsPushString = new NativeFunction(findSymbol('fs_push_string'), 'int',
        ['pointer', 'pointer']);
    const codeAddress = rva => arm64 ? base.add(rva) : base.add(rva).or(1);

    const copyCString = pointer => {
        if (!pointer || pointer.isNull()) return EMPTY;
        const lengthValue = strlen(pointer);
        const length = lengthValue.toNumber ? lengthValue.toNumber() : Number(lengthValue);
        const copy = Memory.alloc(length + 1);
        Memory.copy(copy, pointer, length + 1);
        return copy;
    };
    const modeIndex = pointer => {
        if (!pointer || pointer.isNull()) return -1;
        const offset = pointer.sub(MODE_BASE).toInt32();
        if (offset < 0 || offset >= 64 * MODE_STRIDE || offset % MODE_STRIDE !== 0)
            return -1;
        return Math.floor(offset / MODE_STRIDE);
    };
    const perkIndex = pointer => {
        if (!pointer || pointer.isNull()) return -1;
        const offset = pointer.sub(PERK_BASE).toInt32();
        if (offset >= 0 && offset < 64 * PERK_STRIDE && offset % PERK_STRIDE === 0)
            return Math.floor(offset / PERK_STRIDE);
        const traitOffset = offset - PERK_PARTITION;
        if (traitOffset >= 0 && traitOffset < 64 * PERK_STRIDE &&
            traitOffset % PERK_STRIDE === 0)
            return 64 + Math.floor(traitOffset / PERK_STRIDE);
        return -1;
    };

    if (EXPAND_ANDROID_GAMEMODES) {
    globalThis.androidModeDescSetter = new NativeCallback(a1 => {
        const source = fsPopString(a1);
        const current = MODE_CURRENT.readPointer();
        const index = modeIndex(current);
        if (index >= 0) {
            const description = copyCString(source);
            modeDescriptions[index] = description;
            // +0x38 is the unused final word of our compact 0x40-byte record.
            // The two verified native detail loads above read this pointer,
            // leaving the original formatting and button callbacks intact.
            current.add(0x38).writePointer(description);
        }
        // The original `strmode-desc` returns strncpy's destination:
        // record + 0x28.  Returning the record itself was part of the old
        // experimental bridge and did not preserve the native ABI.
        return current && !current.isNull() ? current.add(0x28) : current;
    }, 'pointer', ['pointer']);
    Interceptor.replace(
        codeAddress(arm64 ? 0x830D8 : 0x62D0C),
        globalThis.androidModeDescSetter
    );

    Interceptor.attach(findSymbol('gamemodes_init'), {
        onEnter() {
            modeDescriptions.fill(undefined);
        }
    });
    }

    globalThis.androidPerkDescSetter = new NativeCallback(a1 => {
        const source = fsPopString(a1);
        const current = PERK_CURRENT.readPointer();
        const index = perkIndex(current);
        if (index >= 0) perkDescriptions[index] = copyCString(source);
        return current;
    }, 'pointer', ['pointer']);
    Interceptor.replace(
        codeAddress(arm64 ? 0xC6684 : 0x97D20),
        globalThis.androidPerkDescSetter
    );

    globalThis.androidPerkDescGetter = new NativeCallback(a1 => {
        const index = perkIndex(PERK_CURRENT.readPointer());
        return fsPushString(
            a1,
            index >= 0 && perkDescriptions[index] ? perkDescriptions[index] : EMPTY
        );
    }, 'int', ['pointer']);
    Interceptor.replace(
        codeAddress(arm64 ? 0xC6808 : 0x97E40),
        globalThis.androidPerkDescGetter
    );

    const perkDescriptionFromField = pointer => {
        if (!pointer || pointer.isNull()) return null;
        const index = perkIndex(pointer.sub(40));
        return index >= 0 ? (perkDescriptions[index] || EMPTY) : null;
    };
    for (const name of ['cyoa_just_ok', 'cyoa_yesno']) {
        Interceptor.attach(findSymbol(name), {
            onEnter(args) {
                const replacement = perkDescriptionFromField(args[0]);
                if (replacement) args[0] = replacement;
            }
        });
    }

    Interceptor.attach(findSymbol('perks_init'), {
        onEnter() { perkDescriptions.fill(undefined); }
    });

    globalThis.androidDefinitionCapacityInstalled = true;
    globalThis.androidModeDescriptions = modeDescriptions;
    globalThis.androidPerkDescriptions = perkDescriptions;
    log(EXPAND_ANDROID_GAMEMODES
        ? `Android ${Process.arch} gamemode/perk/trait capacity expanded to 64 (${pending.length} verified instructions)`
        : `Android ${Process.arch} perk/trait capacity expanded to 64; gamemode kept at native 36 (${pending.length} verified instructions)`);
}

function tryHookAndroidDefinitionCapacity() {
    try {
        hookAndroidDefinitionCapacity();
    } catch (e) {
        error('Android definition capacity expansion skipped:', e);
    }
}

/**
 * @param {string} build_stamp 
 */
function hookPerkExtend(build_stamp) {
    if (Process.platform === 'linux' && globalThis.isAndroid) {
        tryHookAndroidDefinitionCapacity();
        return;
    }
    const fs_pop_string = new NativeFunction(findSymbol('fs_pop_string'), 'pointer', ['pointer']);

    /** @type {NativePointer[]} */
    const perkDesc = [];
    if (build_stamp === 'MAY-04-2023.09.30') {
        /** @param {number} offset @param {number[]} arr  */
        function repAss(offset, arr) {
            Memory.patchCode(globalThis.mainModule.base.add(offset), arr.length, code => {
                code.writeByteArray(arr);
            });
        }


        /*1.desc转移: 替换perk的$desc方法, 把文本转移到其他地方*/
        const newFunc = new NativeCallback(function (a1) {
            const src = fs_pop_string(a1);
            let result = globalThis.mainModule.base.add(0x2F4128).readPointer();
            if (result) {
                const index = Math.floor(result.sub(globalThis.mainModule.base.add(0x2EF118)).toInt32() / 0xA0);
                perkDesc[index] = Memory.alloc(0x300);
                Memory.copy(perkDesc[index], src, 0x300);
                perkDesc[index].add(0x300).writeByteArray([0]);
                // log(`perkDesc`, index, perkDesc[index], perkDesc[index].readCString());
            }
            return result;
        }, 'pointer', ['pointer']);
        Interceptor.replace(globalThis.mainModule.base.add(0xC6684), newFunc);

        Interceptor.attach(findSymbol('cyoa_just_ok'), {
            onEnter(args) {
                if (!args[0]) return;
                if (globalThis.mainModule.base.add(0x2EF118) <= args[0] && args[0] <= globalThis.mainModule.base.add(0x2EF118).add(0x10240 * 2)) {
                    // log('cyoa_just_ok',args[0]);
                    const index = Math.floor(args[0].sub(globalThis.mainModule.base.add(0x2EF118)).toInt32() / 0xA0);
                    args[0] = perkDesc[index];
                }
            },
            onLeave(retval) {
            }
        });

        Interceptor.attach(findSymbol('cyoa_yesno'), {
            onEnter(args) {
                if (!args[0]) return;
                if (globalThis.mainModule.base.add(0x2EF118) <= args[0] && args[0] <= globalThis.mainModule.base.add(0x2EF118).add(0x10240 * 2)) {
                    const index = Math.floor(args[0].sub(globalThis.mainModule.base.add(0x2EF118)).toInt32() / 0xA0);
                    args[0] = perkDesc[index];
                }
            },
            onLeave(retval) {
            }
        });

        /* 扩大perk限制数字:
         * word_strperk
         *   C64C8                 CMP             W9, #0x20: 3f 01 01 71
         * word_strtrait sub_C6484
         *   C65BC                 CMP             W10, #0x20: 5f 01 01 71
         * btn_perk_page
         *   0xC7068
         *   0xC6FE0
         *   */
        repAss(0xC64C8, [0x3f, 0x01, 0x01, 0x71]);
        repAss(0xC65BC, [0x5f, 0x01, 0x01, 0x71]);
        repAss(0xC7068, [0x08, 0x07, 0x80, 0x52]);
        repAss(0xC6FE0, [0x1f, 0xe1, 0x00, 0x71]);

        /* 特殊间隔更改
        * btn_perk  trait的锁定0x130寻址采用基址偏移寻址, 改为0x94就是0x872CDC( 0x872d78 - (0x130 - 0x94) )
        *   489057:	8b 80 78 2d 87 00    	mov    0x872d78(%eax),%eax           */

        /* btn_perk 怀疑被perk_info代替*/

        /*2.间隔修改: 修改word_strperk和word_str的间隔为0x9c
        0x130 -> 0x90;
        word_strperk 0xC6484
          C650C MOV X11, #0xA0 : 0b 14 80 d2
        word_strtrait sub_C6570
          C6610 MOV X11, #0xA0 : 0b 14 80 d2
        perk_info
          C68E4 MOV X13, #0xA0 : 0d 14 80 d2
        trait_info
          C6978 MOV X13, #0xA0 : 0d 14 80 d2
        layout  sub_C6A70
          C6CEC                 MOV             X13, #0x140 : 0d 14 80 d2
          C6C58                 MOV             X13, #0x140 : 0d 14 80 d2
        btn_perk sub_C6E48 里面第二部分逻辑在sub_C7298
 
        do_perk_desc sub_C70F4
 
        perkntrait_find
          C61F8                 MOV             X10, #0x140 : 0a 14 80 d2*/

        repAss(0xC650C, [0x0b, 0x14, 0x80, 0xd2]);
        repAss(0xC6610, [0x0b, 0x14, 0x80, 0xd2]);
        repAss(0xC68E4, [0x0d, 0x14, 0x80, 0xd2]);
        repAss(0xC6978, [0x0d, 0x14, 0x80, 0xd2]);
        repAss(0xC6CEC, [0x0d, 0x14, 0x80, 0xd2]);
        repAss(0xC6C58, [0x0d, 0x14, 0x80, 0xd2]);

        /* btn_perk 怀疑被perk_info代替*/
        /*do_perk_desc 怀疑被perk_info代替*/

        repAss(0xC61F8, [0x0a, 0x14, 0x80, 0xd2]);

        /*3.level转移: 修改word_lvl和do_perk_desc等级的间隔为0x8c
        0x128 -> 0x88;
        word_lvl sub_C66F0
          C6758                 STR             W8, [X9,#0x128] 28 89 00 b9
        do_perk_desc sub_C70F4
          C71E0                 LDR             W9, [X8,#0x128] 09 89 40 b9
          C71F4                 LDR             W9, [X8,#0x128] 09 89 40 b9
        btn_perk
          C73DC                 LDR             W9, [X0,#0x128] 09 88 40 b9
          C73F8                 LDR             W9, [X0,#0x128] 09 88 40 b9
          */

        repAss(0xC6758, [0x28, 0x89, 0x00, 0xb9]);
        repAss(0xC71E0, [0x09, 0x89, 0x40, 0xb9]);
        repAss(0xC71F4, [0x09, 0x89, 0x40, 0xb9]);
        repAss(0xC73DC, [0x09, 0x88, 0x40, 0xb9]);
        repAss(0xC73F8, [0x09, 0x88, 0x40, 0xb9]);


        /*4.锁定转移: 修改word_lock和do_perk_desc锁定的间隔为
        0x130 -> 0x90
        word_lock
          C67A8                 STR             W9, [X8,#0x130] 09 91 00 b9
        do_perk_desc
          C7150                 LDR             W10, [X9,#0x130] 2a 91 40 b9
        charmake_roll_a_char
          3D570                 LDR             W9, [X8,#0x130]  09 91 40 b9
          3D5AC                 LDR             W9, [X8,#0x130]  09 91 40 b9
        btn_perk
          C72F4                 LDR             W9, [X0,#0x130] 09 90 40 b9
          C74A4                 LDR             W9, [X0,#0x130] 09 90 40 b9
        */

        repAss(0xC67A8, [0x09, 0x91, 0x00, 0xb9]);
        repAss(0xC7150, [0x2a, 0x91, 0x40, 0xb9]);
        repAss(0x3D570, [0x09, 0x91, 0x40, 0xb9]);
        repAss(0x3D5AC, [0x09, 0x91, 0x40, 0xb9]);
        repAss(0xC72F4, [0x09, 0x90, 0x40, 0xb9]);
        repAss(0xC74A4, [0x09, 0x90, 0x40, 0xb9]);


        /*
        5.修改word_applyword_0和perkfinder的间隔为0x98
        0x138->0x98
        word_applyword_0
          C67F8                 STR             X9, [X8,#0x138] 09 4d 00 f9
        perkfinder
          D53D0                 LDR             X1, [X8,#0x138] 01 4d 40 f9
          */

        repAss(0xC67F8, [0x09, 0x4d, 0x00, 0xf9]);
        repAss(0xD53D0, [0x01, 0x4d, 0x40, 0xf9]);

        log('perks 扩展完成');

    }
}

/** @type {Object<string, NativePointer>} */
const strList = {};
/** @param {string} str @returns {NativePointer} */
function L(str) {
    if (LANG_STR[str]) {
        return LANG_STR[str];
    }
    if (!strList[str]) {
        const str_p = allocMixedString(str);
        strList[str] = str_p;
    }
    return strList[str];
}

/** @type {Object<string, NativePointer>} */
const navFunList = {};
/** 
 * @param {string} name 
 * @param {NativeCallbackImplementation<NativeCallbackReturnValue, RecursiveValuesOf<NativeCallbackArgumentTypeMap>[]>} fun  
 * @param {NativeCallbackReturnType} ret  
 * @param {[] | NativeCallbackArgumentType[]} arg  
 * @returns {NativePointer} */
function navFun(name, fun, ret = 'void', arg = []) {
    const p = new NativeCallback(
        fun,
        ret,
        arg
    );
    navFunList[name] = p;
    return p;
}
/** @type {Object<number, NativePointer>} */
const OnClickListenerMap = {};
/** @param {NativePointer} btn @param {NativePointer} funPtr  @returns {NativePointer} */
function setOnClickListenerEx(btn, funPtr) {
    OnClickListenerMap[btn.toInt32()] = funPtr;
    if (Process.arch === 'ia32') {
        btn.add(4 * 58).writePointer(OnClickListenerMap[btn.toInt32()]);
    }
    if (Process.arch === 'arm') {
        // Android armeabi-v7a's 0x150-byte button record stores its listener
        // at +232. This is distinct from the arm64/x64 +256 layout.
        btn.add(4 * 58).writePointer(OnClickListenerMap[btn.toInt32()]);
    }
    if (Process.arch === 'arm64' || Process.arch === 'x64') {
        btn.add(8 * 32).writePointer(OnClickListenerMap[btn.toInt32()]);
    }
    return btn;
}
/** @param {NativePointer} btn @param {NativeCallbackImplementation<void, []>} fun  @returns {NativePointer} */
function setOnClickListener(btn, fun) {
    const p = new NativeCallback(
        fun,
        'void',
        []
    );
    return setOnClickListenerEx(btn, p);
}

/** @param {string} s  */
function allocMixedString(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);

        if (c >= 0xE000 && c <= 0xE0FF) {
            bytes.push(c & 0xFF);
            continue;
        }

        // 处理 surrogate pair(emoji 等,一般用不上)
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.length) {
            const low = s.charCodeAt(i + 1);
            c = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
            i++;
        }

        if (c <= 0xFF) {
            bytes.push(c);                              // 直接当字节
        } else if (c <= 0x7FF) {
            bytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
        } else if (c <= 0xFFFF) {
            bytes.push(0xE0 | (c >> 12),
                0x80 | ((c >> 6) & 0x3F),
                0x80 | (c & 0x3F));
        } else {
            bytes.push(0xF0 | (c >> 18),
                0x80 | ((c >> 12) & 0x3F),
                0x80 | ((c >> 6) & 0x3F),
                0x80 | (c & 0x3F));
        }
    }
    bytes.push(0);
    const buf = Memory.alloc(bytes.length);
    buf.writeByteArray(bytes);
    return buf;
}
/** @param {NativePointer} p  @returns {string} */
function readByteString(p) {
    let s = '';
    let i = 0;
    while (true) {
        const b = p.add(i).readU8();
        if (b === 0) break;
        if (b > 0x7F) {
            s += String.fromCharCode((0xE0 << 8) | b);    // 非法utf8转为: 0xF5 → "\uE0F5"
        } else {
            s += String.fromCharCode(b);
        }
        i++;
    }
    return s;
}

// Decode genuine UTF-8 while retaining the game's single-byte formatting
// opcodes as U+E0xx sentinels. This is needed for completed native buffers
// that may contain both a Chinese character name and colour/animation bytes.
function readMixedUtf8String(p, maximumBytes = 16384) {
    let output = '';
    let offset = 0;
    while (offset < maximumBytes) {
        const first = p.add(offset).readU8();
        if (first === 0) return output;
        if (first < 0x80) {
            output += String.fromCharCode(first);
            offset++;
            continue;
        }

        let length = 0;
        let codePoint = 0;
        let minimum = 0;
        if ((first & 0xe0) === 0xc0) {
            length = 2;
            codePoint = first & 0x1f;
            minimum = 0x80;
        } else if ((first & 0xf0) === 0xe0) {
            length = 3;
            codePoint = first & 0x0f;
            minimum = 0x800;
        } else if ((first & 0xf8) === 0xf0) {
            length = 4;
            codePoint = first & 0x07;
            minimum = 0x10000;
        }

        let valid = length !== 0 && offset + length <= maximumBytes;
        for (let index = 1; valid && index < length; index++) {
            const next = p.add(offset + index).readU8();
            if (next === 0 || (next & 0xc0) !== 0x80) {
                valid = false;
                break;
            }
            codePoint = (codePoint << 6) | (next & 0x3f);
        }
        valid = valid && codePoint >= minimum && codePoint <= 0x10ffff &&
            !(codePoint >= 0xd800 && codePoint <= 0xdfff);

        if (!valid) {
            output += String.fromCharCode(0xe000 | first);
            offset++;
            continue;
        }
        output += String.fromCodePoint(codePoint);
        offset += length;
    }
    throw new Error('Unterminated mixed UTF-8 string');
}

// RVAs in the stripped iOS Mach-O (preferred image base 0x100000000).
// Keep this table version-specific and add entries only after static and/or
// runtime validation against the OCT-03-2022 iOS build.
const IOS_SYMBOLS = {
    main_build_stamp: 0x7C5CC,
    load_gfx: 0x83128,
    btn_music_slider: 0xA720,
    update_weapon_info_text: 0x797F0,
    fs_register_func: 0x36970,
    fs_register_const: 0x36B64,
    fs_push_string: 0x37354,
    fs_get_float: 0x37C20,
    fs_get_string: 0x37C84,
    fs_pop_string: 0x37CB0,
    fs_remove: 0x38218,
    forth_init: 0x399DC,
    mad_w: 0xC8B8,
    mad_h: 0xC8D0,
    buttons_update: 0x53844,
    buttons_start: 0x53CDC,
    buttons_reset_to: 0x53D5C,
    buttons_count: 0x543EC,
    button_ex: 0x54100,
    button_set_layout: 0x53E0C,
    button_set_w_ex: 0x53F68,
    button_set_w: 0x53FF0,
    button_set_h_ex: 0x53FFC,
    button_set_h: 0x54084,
    main_btn_data_func: 0x81BBC,
    main_trigger_event: 0x7DC34,
    main_do_sys_reset: 0x7DF84,
    main_push_popup_state: 0xDE5C,
    main_tabscreen_start: 0x82AEC,
    main_tabscreen_reset: 0x82A84,
    main_tabscreen_add_tab: 0x82C00,
    main_tabscreen_layout_ex: 0x8285C,
    main_tabscreen_set_exitfunc: 0x82C10,
    main_tabscreen_blank_tab_layout: 0x82830,
    main_tabscreen_tabbox_shrink: 0x827B8,
    main_common_page_setup: 0x82308,
    game_lower_box: 0x245C0,
    cyoa_start: 0x47BB0,
    cyoa_set_title: 0x47CFC,
    cyoa_add_choice: 0x47DCC,
    cyoa_set_choice_text: 0x47EA8,
    cyoa_set_choice_func: 0x48144,
    cyoa_hint: 0x48290,
    cyoa_just_ok: 0x48318,
    cyoa_yesno: 0x483C8,
    plot_text: 0x7CABC,
    main_stextf: 0x7D7F4,
    // Statically verified against the stripped OCT-03-2022 Mach-O. The iOS
    // build retains the console state and parser even though its text-input
    // platform functions at 0x7ABDC/0x7ABE4 are no-op stubs.
    main_do_console_open: 0x7DE40,
    main_do_console_close: 0x7DE50,
    console_insert_char: 0x62DCC,
    console_clear_input: 0x61DE8,
    console_update: 0x61E88,
    script_do_input: 0x57B84,
    chara_stat_name: 0x74930,
    team_btn_char_stats: 0x409A8,
    uppercase: 0x7C6A0,
    thing_report_ex: 0x239F4,
    game_label: 0x242FC,
    main_btn_wrap: 0x80858,
    sprite_get: 0x54E74,
    sprite_count: 0x54EAC,
    sprite_batch_draw: 0x54C78,
    sprite_batch_plot: 0x547D8,
    turtle_trans: 0x891C8,
    turtle_set_scale: 0x89128,
    turtle_set_scalex: 0x89138,
    turtle_set_scaley: 0x89144,
    turtle: 0xBD870,
    glyphs_set_callback: 0x33DA8,
    glyphs_batch_plot_ex: 0x33DBC,
    glyph_w: 0x34064,
    text_w: 0x82F9C,
    wrap_text_ex: 0x80514,
    plot_text_ex: 0x7C9E0,
    atlas_get: 0x73A68,
    atlas_upload: 0x73A80,
    atlas_create_texture: 0x73D08,
    atlas_load_spritesheet: 0x74664,
    atlas_free_image_data: 0x74814,
    wrapper_file_data_path: 0x7AA2C,
    file_data_path: 0x556B8,
    file_open_data_read: 0x55714,
    file_open_d: 0x5593C,
};

/**
 * @param {string} name 
 * @returns {NativePointer}
 */
function findSymbol(name) {
    if (Process.platform === 'linux' || Process.platform === 'darwin') {
        let exp = null;
        if (Process.platform === 'darwin' && IOS_SYMBOLS[name] !== undefined) {
            exp = globalThis.mainModule.base.add(IOS_SYMBOLS[name]);
        }
        if (!exp) {
            exp = globalThis.mainModule.findExportByName(name);
        }
        // The stripped iOS Mach-O has no useful local names. Re-enumerating its
        // symbol table for every mapped function makes Frida script loading time out.
        if (!exp && Process.platform !== 'darwin') {
            const sym = globalThis.mainModule.enumerateSymbols().find(s => s.name === name);
            if (sym) {
                exp = sym.address;
            }
        }
        if (!exp) {
            const sym = Module.findGlobalExportByName(name);
            if (sym) {
                exp = sym;
            }
        }
        if (!exp) {
            throw new Error(`MOD Symbol not found: ${name}`);
        }

        // info(`Found symbol: ${name} @ ${exp}`);
        return exp;
    }
    for (const cand of [name, '_' + name]) {
        if (!SYMBOLS) throw new Error("COFF_SYMBOLS is not defined");
        if (SYMBOLS[cand]) {

            // info(`Found symbol: ${name} @ ${COFF_SYMBOLS[cand].toString(16)}`);
            return ptr(SYMBOLS[cand]);
        };
    }
    throw new Error(`Symbol not found: ${name}`);
}

/**
 * @param {string} moduleName 
 * @param {function} callback 
 */
function waitForModule(moduleName, callback) {
    let fired = false;
    const fire = () => {
        if (fired) return;
        const m = Process.findModuleByName(moduleName);
        if (!m) return;
        fired = true;
        try {
            callback(m);
        } catch (e) {
            globalThis.__DR2C_BOOT_ERROR__ = e && e.stack ? e.stack : String(e);
            error('callback error: ', e);
        }
    };

    // 1) 已加载就直接走
    if (Process.findModuleByName(moduleName)) {
        fire();
        return;
    }

    // 2) hook android_dlopen_ext —— Android 7+ 加载 so 的真正入口
    // @ts-ignore
    const dlopen_ext = Module.findExportByName ? Module.findExportByName(null, "android_dlopen_ext") : Module.findGlobalExportByName("android_dlopen_ext");
    if (dlopen_ext) {
        Interceptor.attach(dlopen_ext, {
            onEnter(args) {
                this.path = args[0] ? args[0].readCString() : null;
            },
            onLeave() {
                log(moduleName)
                if (this.path && this.path.indexOf(moduleName) !== -1) {
                    fire();
                }
            }
        });
    }
}



/** @type {{ [key: string]: string }} */
let SYMBOLS = {}
const SYMBOLS_JSON_STR = '{"__mingw32_init_mainargs": "0x4012a0", "_mainCRTStartup": "0x4012e0", "_WinMainCRTStartup": "0x401300", "_atexit": "0x401320", "__onexit": "0x401330", ".text": "0x4cfe20", ".bss": "0x94c060", "_obj": "0x50b008", "_deregister_frame_fn": "0x4d0000", "___JCR_LIST__": "0x4d0634", "___gcc_register_frame": "0x401340", "___gcc_deregister_frame": "0x401430", ".data": "0x4d0634", ".eh_frame": "0x50a6d8", ".rdata": "0x4e1980", ".rdata$zzz": "0x4e2de8", ".jcr": "0x4d0634", "_atlas_is_ok": "0x401460", "_atlas_": "0x50b020", "_atlas_get": "0x401480", "_atlas_get_full": "0x4014a0", "_atlas_update_texture": "0x4014c0", "_atlas_upload": "0x401540", "_freetype": "0x50ce60", "_atlas_create_texture": "0x4018a0", "_atlas_add_rgba_image": "0x401a50", "_add_shrinkwrap_sprite": "0x401d90", "_atlas_add_sprite_sheet": "0x4020c0", "_atlas_add_glyphs": "0x402220", "_rgba_load": "0x402500", "_rgba_free": "0x402560", "_atlas_add_spritesheet_from_rgba": "0x4025a0", "_atlas_load_spritesheet": "0x402610", "_atlas_load_font": "0x4026b0", "_atlas_init": "0x402770", "_atlas_free_image_data": "0x402790", "_atlas_exit": "0x4027d0", "_atlas_delete_texture": "0x402850", "_draw_reset_last_texture_bind": "0x4028a0", "_last_texture": "0x4d0004", "_draw_bind_texture": "0x4028b0", "_draw_clear": "0x402930", "_draw_clear_ex": "0x402970", "_draw_reset_view": "0x4029b0", "_draw_reset": "0x402a90", "_draw_flip": "0x402b60", "_draw_apply_scissor_rect": "0x402b70", "_sighandler": "0x402bb0", "_error_signal": "0x520ea4", "_error_set_handler_state": "0x402bd0", "_err_handler_state": "0x50ce80", "_error_handler_state": "0x402be0", "_error_last_signal": "0x402bf0", "_error_return_to_recovery_point": "0x402c00", "_error_setup_signals": "0x402c20", "_error_log_context": "0x402c80", "_err_log": "0x50cea0", "_error_context_at": "0x402d00", "_error_log_backup_if": "0x402d30", "_error_log_backup": "0x402d70", "_error_log_count": "0x402d80", "_error_init_log": "0x402d90", "_error_clear_log": "0x402dc0", "_file_write_d": "0x402dd0", "_file_read_d": "0x402e00", "_file_close_d": "0x402e30", "_file_delete_d": "0x402e60", "_file_length_d": "0x402ea0", "_file_open_d": "0x402f10", "_file_data_path": "0x402f70", "__filepath": "0x520ec0", "_file_save_path": "0x402fc0", "_file_temp_path": "0x403010", "_file_doc_path": "0x403060", "_file_open_read": "0x4030b0", "_file_open_write": "0x4030d0", "_file_open_data_read": "0x4030f0", "_file_open_save_read": "0x403140", "_file_open_save_write": "0x403190", "_file_open_save_append": "0x4031e0", "_file_delete_save": "0x403230", "_file_open_doc_read": "0x403270", "_file_open_doc_write": "0x4032c0", "_file_delete_doc": "0x403310", "_file_open_temp_read": "0x403350", "_file_open_temp_write": "0x4033a0", "_file_delete_temp": "0x4033f0", "_file_getc": "0x403430", "_file_putc": "0x403470", "_file_get32": "0x4034a0", "_file_getl": "0x4034e0", "_file_put32": "0x4034f0", "_file_putl": "0x403520", "_file_getw": "0x403530", "_file_putw": "0x403570", "_file_open_append": "0x4035a0", "_file_delete": "0x4035c0", "_file_read": "0x4035d0", "_file_write": "0x4035e0", "_file_length": "0x4035f0", "_file_close": "0x403600", "_glyphs_set_callback": "0x403610", "_glyph_callback_func_": "0x5212c4", "_glyph_callback_context_": "0x5212c0", "_glyphs_batch_plot_ex": "0x403630", "_glyphs_batch_plot": "0x4038b0", "_glyphs_plot_char": "0x403900", "_glyph_w": "0x403970", "_glyph_h": "0x4039b0", "_glyphs_w": "0x4039f0", "_glyphs_h": "0x403a70", "_glyphs_make_font": "0x403b00", "_set_mouse_state.part.0": "0x403b30", "_input_name": "0x403b60", "_keynames_": "0x4d1240", "_input_init": "0x403b80", "_write_pos": "0x528308", "_read_pos": "0x528304", "_input_add_event": "0x403c10", "_events": "0x528320", "_input_add_key_ascii": "0x403c80", "_input_set_callback": "0x403de0", "_input_callback_": "0x5212e0", "_input_drop_key": "0x403df0", "_inkey": "0x5212e4", "_keybuf": "0x521300", "_input_get_key_ascii": "0x403e30", "_input_clear_key_events": "0x403e90", "_input_clear_joy_events": "0x403ec0", "_input_peek_key_event": "0x403f10", "_input_get_key_event": "0x403f20", "_input_get_key": "0x403fb0", "_input_update_events": "0x404010", "_keyspressed": "0x528300", "_input_keyspressed": "0x404210", "_input_clear_events": "0x404220", "_input_clear_buffer": "0x4042b0", "_input_reset": "0x4042e0", "_enter": "0x4ba990", "_start_seconds": "0x52f358", "__demo_seconds": "0x52f348", "_sound_pulse_fx": "0x4aab10", "_render": "0x4b9c40", "_growl_effect": "0x4aa850", "_update": "0x4ba9a0", "_state.12416": "0x52f324", "_mad_quit": "0x404b00", "_quit_": "0x52f368", "_mad_set_quit_key": "0x404b10", "_mad_is_quit": "0x404b20", "_mad_set_logic_rate": "0x404b30", "_logic_rate": "0x4d0030", "_time_ticks": "0x52f364", "_logic_ticks": "0x52f360", "_mad_init.part.1": "0x404ba0", "_mad_state": "0x4d0020", "_is_init_": "0x52f36c", "_mad_logic_rate": "0x404c50", "_mad_seconds": "0x404c60", "_mad_lerp": "0x404c80", "_mad_beep": "0x404ca0", "_mad_init_audio_stream": "0x404d20", "_mad_enable_wave": "0x404d50", "_mad_enable_synth": "0x404d70", "_mad_enable_synth_effects_logic_sync": "0x404d90", "_mad_set_glitch_callback": "0x404da0", "_mad_set_postprocess_callback": "0x404db0", "_mad_graphics": "0x404dc0", "_mad_w": "0x404e00", "_mad_h": "0x404e20", "_mad_fps": "0x404e40", "_fps_": "0x52f340", "_mad_pause": "0x404e50", "_paused_": "0x52f33c", "_mad_is_paused": "0x404e60", "_mad_disable_render": "0x404e70", "_render_disabled_": "0x52f338", "_mad_enable_resize": "0x404e80", "_mad_enable_vsync": "0x404e90", "_mad_force_render": "0x404ea0", "_mad_run": "0x404eb0", "_old_rate.12490": "0x52f330", "_seconds.12488": "0x52f328", "_frames.12489": "0x52f32c", "_mad_set_app_name": "0x405160", "_appname_": "0x52f334", "_mad_app_name": "0x405170", "_mad_errornum": "0x405190", "_lasterrornum": "0x52f350", "_mad_set_errornum": "0x4051a0", "_mad_has_focus": "0x4051b0", "_mad_init": "0x4051c0", "_mad_exit": "0x4051f0", "_music_volume": "0x405220", "_music_load_ex": "0x405230", "_music_load": "0x405260", "_music_pause": "0x405290", "_plat_msg_init": "0x4052b0", "_list_poster": "0x531540", "_list_replier": "0x52f3a0", "__init": "0x52f380", "_msg_alloc": "0x405300", "__refid": "0x52f38c", "_plat_msg_exit": "0x4053a0", "_plat_msg_set_poster": "0x4053b0", "__poster": "0x52f388", "_plat_msg_set_replier": "0x4053c0", "__replier": "0x52f384", "_plat_msg_alloc_poster": "0x4053d0", "_plat_msg_alloc_replier": "0x4053e0", "_plat_msg_free": "0x4053f0", "_plat_msg_poster_send": "0x405400", "_plat_msg_replier_send": "0x405450", "_poly_plot": "0x4054a0", "_polylist": "0x5336e0", "_vertex_index": "0x533aec", "_vertex_count": "0x533ae8", "_vertex_list": "0x549aa0", "_colour_index": "0x533af0", "_colour_list": "0x53b040", "_element_count": "0x533ae4", "_element_list": "0x566fa0", "_poly_point": "0x4055a0", "_poly_draw_start": "0x405680", "_poly_set_blend": "0x4056c0", "_last_mode": "0x4d0034", "_poly_draw_end": "0x405700", "_poly_bar": "0x4057c0", "_poly_center_bar": "0x4058a0", "_poly_circle_ex": "0x405990", "_poly_circle": "0x405b60", "_mrand_ex": "0x405bb0", "_mrand": "0x405be0", "_rnd": "0x405c10", "_rnd_ex": "0x405c70", "_frnd": "0x405cd0", "_frnd_ex": "0x405d20", "_rnd5050": "0x405d70", "_rnd5050_ex": "0x405da0", "_rndsign_ex": "0x405dd0", "_rndsign": "0x405e10", "_dice_ex": "0x405e50", "_dice": "0x405ed0", "_onein_ex": "0x405f00", "_onein": "0x405f50", "_choose_weighted_item_ex": "0x405fa0", "_count_weighted_items": "0x406080", "_choose_weighted_item": "0x4060b0", "_init_sine_table": "0x4060d0", "_quad_batch": "0x406120", "_sprite_last_batch_entry": "0x406430", "_sprite_batch_plot": "0x406460", "_sprite_batch_plot_centered": "0x406570", "_sprite_batch_register_callback": "0x406660", "_sprite_batches_reset": "0x406670", "_sprite_batch_draw": "0x406690", "_element_init": "0x566f80", "_sprite_last": "0x4068f0", "_spritecount": "0x626fac", "_sprites_": "0x6c92cc", "_sprite_alloc": "0x406900", "_sprite_get": "0x406930", "_sprite_get_id": "0x406950", "_sprite_count": "0x406960", "_sprites_reset": "0x406970", "_leave": "0x48b1d0", "_state_current": "0x4069e0", "_current": "0x4d0038", "_state_last": "0x4069f0", "_last": "0x6a6fc0", "_state_switch": "0x406a00", "_state_set": "0x406a50", "_state_render": "0x406a60", "_state_update": "0x406a80", "_my_state": "0x4d003c", "_syn_update": "0x406aa0", "_syn_adsr_attack": "0x4074c0", "_syn_adsr_decay": "0x407530", "_syn_adsr_sustain": "0x4075a0", "_syn_adsr_release": "0x4075f0", "_syn_adsr": "0x407650", "_syn_adsr_in": "0x407860", "_syn_adsr_hold": "0x4078b0", "_syn_adsr_get_step": "0x4078e0", "_syn_adsr_get_sustain": "0x407930", "_syn_stage": "0x407960", "_syn_reset": "0x407990", "_syn_enable": "0x407b20", "_syn_enable_range": "0x407b70", "_syn_ramp": "0x407be0", "_syn_ramp_freq": "0x407c70", "_syn_mix": "0x407d60", "_syn_mix_pan": "0x407d90", "_syn_osc_duty": "0x407e40", "_syn_osc_sine": "0x407ed0", "_syn_osc_triangle": "0x407fb0", "_syn_osc_pulse": "0x4080b0", "_syn_osc_noise": "0x4081b0", "_syn_osc_phase": "0x408290", "_syn_osc_freq": "0x4082f0", "_syn_osc_in_sync": "0x408360", "_syn_osc_amp": "0x4083b0", "_syn_osc_off": "0x4083e0", "_syn_osc_in_freq": "0x408410", "_syn_osc_in_amp": "0x408460", "_syn_osc_in_off": "0x4084b0", "_syn_osc_in_duty": "0x408500", "_syn_filt_highpass": "0x408550", "_syn_filt_lowpass": "0x4085f0", "_syn_filt_cutoff": "0x4086a0", "_syn_filt_q": "0x408700", "_syn_filt_in": "0x408730", "_syn_filt_in_cutoff": "0x408780", "_syn_filt_in_q": "0x4087d0", "_syn_math_mul": "0x408820", "_syn_math_add": "0x4088c0", "_syn_math_val": "0x408900", "_syn_bitcrush": "0x408980", "_syn_bitcrush_in": "0x408a00", "_syn_bitcrush_in_bits": "0x408a50", "_syn_freqval": "0x408aa0", "_syn_copy": "0x408ac0", "_syn_check_active": "0x408b70", "_syn_disable_inactive": "0x408bd0", "_syn_find_last_used": "0x408c70", "_syn_vol": "0x408ca0", "_syn_init": "0x408ce0", "_syn_set_beat_callback": "0x408d70", "_new_effect_ex": "0x408e10", "_effect_max_": "0x4d0050", "_synth_effects": "0x6a7180", "_cur": "0x8da268", "_effect_slots_": "0x4d004c", "_synth_effects_allocated": "0x408fd0", "_synth_effects_max": "0x409020", "_synth_effects_active": "0x409030", "_synth_effect_get": "0x409080", "_dummy.12258": "0x6a70c0", "_synth_effect_ex": "0x4090b0", "_dummy.12284": "0x6a7000", "_synth_effect_stop": "0x409140", "_synth_effect_stop_all_func": "0x409160", "_synth_effect": "0x4091b0", "_synth_effects_update": "0x4091d0", "_ticks_old.12307": "0x6a6fe8", "_last_seconds.12308": "0x6a6fe0", "_synth_effects_init": "0x4093a0", "_synth_effects_tail_slot": "0x409460", "_texture_atlas_new": "0x409470", "_texture_atlas_delete": "0x409570", "_texture_atlas_set_region": "0x4095e0", "_texture_atlas_fit": "0x409770", "_texture_atlas_merge": "0x409810", "_texture_atlas_get_region": "0x4098b0", "_texture_atlas_clear": "0x409af0", "_turtle_turn": "0x409bb0", "_turtle_set_angle": "0x409c60", "_turtle_set_pos": "0x409c70", "_turtle_set_pos_unscaled": "0x409ca0", "_turtle_set_posx_unscaled": "0x409cc0", "_turtle_set_posy_unscaled": "0x409cd0", "_turtle_set_scale": "0x409ce0", "_turtle_set_scalex": "0x409d00", "_turtle_set_scaley": "0x409d10", "_turtle_set_rgba": "0x409d20", "_turtle_set_rgb": "0x409e40", "_turtle_trans": "0x409f10", "_turtle_move": "0x409f60", "_turtle_set_home": "0x409f80", "_home_turtle": "0x4d0060", "_turtle_home": "0x409fa0", "_turtle_reset": "0x409fc0", "_turtle_point_at": "0x40a020", "_turtle_angle_to": "0x40a070", "_turtle_dx": "0x40a0f0", "_turtle_dy": "0x40a100", "_hexdump_ex": "0x40a110", "_hexdump": "0x40a200", "_compare_and_swap": "0x40a230", "_spinlock_init": "0x40a250", "_spinlock_lock": "0x40a260", "_spinlock_unlock": "0x40a280", "_vector_new": "0x40a290", "_vector_delete": "0x40a320", "_vector_get": "0x40a360", "_vector_front": "0x40a3e0", "_vector_back": "0x40a440", "_vector_contains": "0x40a4a0", "_vector_empty": "0x40a520", "_vector_size": "0x40a560", "_vector_reserve": "0x40a590", "_vector_capacity": "0x40a5f0", "_vector_shrink": "0x40a620", "_vector_clear": "0x40a670", "_vector_set": "0x40a6b0", "_vector_insert": "0x40a740", "_vector_erase_range": "0x40a800", "_vector_erase": "0x40a8d0", "_vector_push_back": "0x40a940", "_vector_pop_back": "0x40a970", "_vector_resize": "0x40a9d0", "_vector_push_back_data": "0x40aa30", "_vector_insert_data": "0x40aaf0", "_vector_sort": "0x40ac00", "_read_uint32_le": "0x40ac70", "_wave_set_voice_pan.part.0": "0x40acd0", "_voices": "0x6a8680", "_wave_set_voice_vol.part.1": "0x40ae10", "_wave_set_voice_pitch.part.2": "0x40af20", "_sample_rate": "0x4d0124", "_wave_init": "0x40afc0", "_initialized": "0x6a8b00", "_sample_bits": "0x4d0120", "_wave_load": "0x40b010", "_wave_free": "0x40b3f0", "_wave_take_voice": "0x40b460", "_wave_drop_voice": "0x40b4a0", "_wave_start_voice": "0x40b4c0", "_wave_stop_voice": "0x40b4f0", "_wave_set_voice_pan": "0x40b510", "_wave_set_voice_vol": "0x40b540", "_wave_set_voice_pitch": "0x40b570", "_wave_set_voice_loop": "0x40b5a0", "_wave_play": "0x40b5d0", "_wave_just_play": "0x40b680", "_wave_output": "0x40b6b0", "_wave_output_stereo": "0x40b7f0", "_wave_drop_all": "0x40b980", "_wave_stop_wav": "0x40b9a0", "_wave_is_wav_playing": "0x40b9e0", "_wave_count_playing": "0x40ba20", "_translate_symbol": "0x40ba60", "_replier_for_plat_msg": "0x40c160", "_remove_controller_or_joy": "0x40c170", "_wrapper_desktop_w": "0x40c1d0", "_desktop_w": "0x6a8b5c", "_wrapper_desktop_h": "0x40c1e0", "_desktop_h": "0x6a8b58", "_wrapper_display_w": "0x40c1f0", "_display_w": "0x4d012c", "_wrapper_display_h": "0x40c200", "_display_h": "0x4d0128", "_wrapper_fullscreen": "0x40c210", "_fullscreen_": "0x6a8b54", "_wrapper_delay": "0x40c220", "_wrapper_check_joy": "0x40c260", "_wrapper_joy_count": "0x40c280", "_numcontrollers": "0x6a8b60", "_wrapper_load_joystick_mappings": "0x40c290", "_wrapper_joy_name": "0x40c2c0", "_controller": "0x6a8b80", "_wrapper_joy_button_name": "0x40c2f0", "_buf.12538": "0x6a8b20", "_wrapper_stop_audio_stream": "0x40c370", "_wrapper_start_audio_stream": "0x40c380", "_wrapper_get_seconds": "0x40c390", "_wrapper_get_ticks": "0x40c3b0", "_wrapper_set_logic_rate": "0x40c400", "_wrapper_yield": "0x40c410", "_wrapper_reset_opengl_matrix": "0x40c430", "_wrapper_handle_events": "0x40c4c0", "_init_": "0x8a8800", "_displayWindow": "0x6a8b50", "_wrapper_destroy_graphics": "0x40cfa0", "_wrapper_set_graphics": "0x40cfd0", "_glContext": "0x6a8b4c", "_wrapper_flip_screen": "0x40d340", "_wrapper_set_fullscreen": "0x40d360", "_wrapper_init": "0x40d3b0", "_wrapper_tweet_start": "0x40d400", "_wrapper_tweet_add_text": "0x40d410", "_wrapper_tweet_add_url": "0x40d420", "_wrapper_tweet_finish": "0x40d430", "_wrapper_open_url": "0x40d440", "_wrapper_run_thread": "0x40d4a0", "_wrapper_show_cursor": "0x40d4e0", "_wrapper_copy_data_to_clipboard": "0x40d500", "_wrapper_set_clipboard_text": "0x40d510", "_wrapper_clipboard_text": "0x40d520", "_wrapper_is_clipboard_text": "0x40d530", "_wrapper_copy_file_to_clipboard": "0x40d540", "_wrapper_set_window_title": "0x40d550", "_wrapper_call_set_func": "0x40d570", "_wrapper_call_ex_func": "0x6a8b48", "_wrapper_call_ex": "0x40d580", "_wrapper_call": "0x40d690", "_wrapper_exit": "0x40d6a0", "_init_paths.part.1": "0x40d740", "_savepath": "0x6a9060", "_temppath": "0x6a8c60", "_docpath": "0x6a8e60", "_init.12645": "0x6a8c40", "_init_paths": "0x40d870", "_wrapper_file_data_path": "0x40d890", "_wrapper_file_save_path": "0x40d8c0", "_wrapper_file_temp_path": "0x40d8f0", "_wrapper_file_doc_path": "0x40d920", "_wrapper_file_dir_walk": "0x40d950", "_wrapper_mkdir": "0x40d960", "_stbi__stdio_eof": "0x40d970", "_stbi__refill_buffer": "0x40d980", "_stbi__start_file": "0x40d9f0", "_stbi__stdio_callbacks": "0x4d27c4", "_stbi__idct_block": "0x40da50", "_resample_row_1": "0x40e100", "_stbi__resample_row_v_2": "0x40e110", "_stbi__resample_row_hv_2": "0x40e160", "_stbi__resample_row_generic": "0x40e210", "_stbi__YCbCr_to_RGB_row": "0x40e260", "_stbi__bitreverse16": "0x40e320", "_stbi__fill_bits": "0x40e370", "_stbi__zreceive": "0x40e3b0", "_stbi__high_bit": "0x40e400", "_stbi__out_gif_code": "0x40e460", "_stbi__stdio_skip": "0x40e590", "_stbi__stdio_read": "0x40e5e0", "_stbi__malloc_mad2": "0x40e610", "_stbi__getn": "0x40e670", "_stbi__vertical_flip": "0x40e710", "_stbi__hdr_convert": "0x40e8c0", "_stbi__mad3sizes_valid": "0x40e9d0", "_stbi__malloc_mad3": "0x40ea50", "_stbi__get8": "0x40eaa0", "_stbi__get16be": "0x40eb00", "_stbi__get32be": "0x40eb30", "_stbi__get16le": "0x40eb50", "_stbi__get32le": "0x40eb80", "_stbi__tga_read_rgb16": "0x40eba0", "_stbi__grow_buffer_unsafe": "0x40ec20", "_stbi__extend_receive": "0x40eca0", "_stbi__jbias": "0x4d2740", "_stbi__bmask": "0x4d2780", "_stbi__jpeg_huff_decode": "0x40ed10", "_stbi__gif_test_raw": "0x40ee80", "_stbi__gif_parse_colortable": "0x40eee0", "_stbi__hdr_gettoken": "0x40ef30", "_stbi__pnm_skip_whitespace": "0x40f000", "_stbi__pnm_getinteger": "0x40f120", "_stbi__skip.part.3": "0x40f180", "_stbi__get_marker.isra.4.part.5": "0x40f1e0", "_stbi__resample_row_h_2": "0x40f220", "_stbi__hdr_test_core": "0x40f2d0", "_stbi__hdr_test": "0x40f330", "_stbi__hdr_info": "0x40f390", "_stbi__shiftsigned": "0x40f560", "_mul_table.15084": "0x4d2340", "_shift_table.15085": "0x4d2300", "_stbi__zhuffman_decode": "0x40f5f0", "_stbi__create_png_image_raw.isra.30": "0x40f6d0", "___emutls_v.stbi__g_failure_reason": "0x4d0130", "_stbi__depth_scale_table": "0x4d2380", "_first_row_filter": "0x4d238c", "_stbi__zexpand.part.27": "0x4105f0", "_stbi__pnm_info": "0x410670", "_stbi__gif_header": "0x4107b0", "_stbi__gif_load_next.isra.31": "0x4108f0", "_stbi__readval": "0x411030", "_stbi__zbuild_huffman": "0x4110d0", "_stbi__compute_huffman_codes": "0x411300", "_length_dezigzag.14575": "0x4d22e4", "_stbi__parse_zlib": "0x411630", "_stbi__zlength_extra": "0x4d25e0", "_stbi__zlength_base": "0x4d2660", "_stbi__zdist_extra": "0x4d24e0", "_stbi__zdist_base": "0x4d2560", "_stbi__zdefault_length": "0x4d23c0", "_stbi__zdefault_distance": "0x4d23a0", "_stbi__jpeg_decode_block_prog_dc": "0x411b20", "_stbi__jpeg_decode_block": "0x411c70", "_stbi__jpeg_dezigzag": "0x4d26e0", "_stbi__build_huffman": "0x411e50", "_stbi__process_marker": "0x411ff0", "_tag.14167": "0x4d2378", "_tag.14173": "0x4d2370", "_stbi__convert_format16": "0x412580", "_stbi__convert_format": "0x412990", "_stbi__gif_load.isra.32": "0x412d90", "_stbi__load_gif_main.constprop.40": "0x412e70", "_stbi__bmp_parse_header.constprop.42": "0x413100", "_stbi__bmp_load.isra.23": "0x413420", "_stbi__free_jpeg_components.constprop.43": "0x414090", "_stbi__decode_jpeg_header": "0x414120", "_rgb.14218": "0x4d236c", "_stbi__mad4sizes_valid.constprop.45": "0x4146a0", "_stbi__hdr_load.isra.33": "0x414710", "_stbi_failure_reason": "0x414cc0", "_stbi_image_free": "0x414ce0", "_stbi_set_flip_vertically_on_load": "0x414cf0", "_stbi__vertically_flip_on_load_global": "0x6a9268", "_stbi_set_flip_vertically_on_load_thread": "0x414d00", "___emutls_v.stbi__vertically_flip_on_load_local": "0x4d0140", "___emutls_v.stbi__vertically_flip_on_load_set": "0x4d0150", "_stbi_load_gif_from_memory": "0x414d30", "_stbi_is_hdr_from_memory": "0x414e60", "_stbi_is_hdr_from_file": "0x414ec0", "_stbi_is_hdr": "0x414f10", "_stbi_is_hdr_from_callbacks": "0x414f50", "_stbi_ldr_to_hdr_gamma": "0x414fd0", "_stbi__l2h_gamma": "0x4d0188", "_stbi_ldr_to_hdr_scale": "0x414fe0", "_stbi__l2h_scale": "0x4d0184", "_stbi_hdr_to_ldr_gamma": "0x414ff0", "_stbi__h2l_gamma_i": "0x4d0180", "_stbi_hdr_to_ldr_scale": "0x415000", "_stbi__h2l_scale_i": "0x4d017c", "_stbi_zlib_decode_malloc_guesssize": "0x415010", "_stbi_zlib_decode_malloc": "0x4150b0", "_stbi_zlib_decode_malloc_guesssize_headerflag": "0x4150e0", "_stbi__parse_png_file": "0x415180", "_png_sig.14684": "0x4d2364", "_stbi__de_iphone_flag": "0x6a9260", "_invalid_chunk.15022": "0x4d0160", "_stbi__unpremultiply_on_load": "0x6a9264", "_stbi__load_main": "0x416240", "_stbi__load_and_postprocess_8bit": "0x4199b0", "_stbi_load_from_file": "0x419b10", "_stbi_load": "0x419b90", "_stbi_load_from_memory": "0x419c10", "_stbi_load_from_callbacks": "0x419c90", "_stbi__loadf_main": "0x419d40", "_stbi_loadf_from_memory": "0x419f90", "_stbi_loadf_from_callbacks": "0x41a010", "_stbi_loadf_from_file": "0x41a0c0", "_stbi_loadf": "0x41a110", "_stbi__load_and_postprocess_16bit": "0x41a1a0", "_stbi_load_from_file_16": "0x41a320", "_stbi_load_16": "0x41a3a0", "_stbi_load_16_from_memory": "0x41a420", "_stbi_load_16_from_callbacks": "0x41a4a0", "_stbi__info_main": "0x41a550", "_stbi__is_16_main": "0x41ace0", "_stbi_zlib_decode_buffer": "0x41adb0", "_stbi_zlib_decode_noheader_malloc": "0x41ae20", "_stbi_zlib_decode_noheader_buffer": "0x41aeb0", "_stbi_set_unpremultiply_on_load": "0x41af20", "_stbi_convert_iphone_png_to_rgb": "0x41af30", "_stbi_info_from_file": "0x41af40", "_stbi_info": "0x41afb0", "_stbi_is_16_bit_from_file": "0x41b020", "_stbi_is_16_bit": "0x41b070", "_stbi_info_from_memory": "0x41b0d0", "_stbi_info_from_callbacks": "0x41b150", "_stbi_is_16_bit_from_memory": "0x41b1f0", "_stbi_is_16_bit_from_callbacks": "0x41b250", "_wrapper_load_rgba": "0x41b2d0", "_stream_exit": "0x41b320", "_music": "0x6c92a0", "_mixaudio": "0x41b360", "_sample_rate_": "0x6a928c", "_last_synth_state.12482": "0x6a9280", "_logic_rate.12483": "0x6a9284", "_synthbuf": "0x6a92a0", "_synfx_update": "0x41b510", "_wrapper_pause_music": "0x41b520", "_wrapper_resume_music": "0x41b530", "_wrapper_music_volume": "0x41b540", "_wrapper_play_music_ex": "0x41b580", "_wrapper_set_music_position": "0x41b5f0", "_wrapper_sound_exit": "0x41b610", "_wrapper_is_other_music_playing": "0x41b620", "_wrapper_play_music": "0x41b630", "_wrapper_set_audio_for_background": "0x41b650", "_wrapper_set_audio_for_ambient": "0x41b660", "_wrapper_sound_init": "0x41b670", "_init.12538": "0x6a9288", "_do_click_ex": "0x41b7d0", "_btn_count": "0x6c92e0", "_btns": "0x6c9300", "_btn_reset_counter": "0x6c92e8", "_buttons_set_fade": "0x41bbe0", "_fade_": "0x4d01f8", "_buttons_fade": "0x41bbf0", "_buttons_draw_ex": "0x41bc00", "_font_": "0x6c92d0", "_buttons_draw": "0x41c350", "_buttons_update": "0x41c370", "_button_do_click_ex": "0x41c4a0", "_button_do_click": "0x41c4d0", "_buttons_start": "0x41c4f0", "_btn_action": "0x6c92e4", "_buttons_set_click_defaults": "0x41c530", "_btn_def_noclick": "0x6c92d6", "_btn_def_noclickthru": "0x6c92d5", "_btn_def_noemptyclick": "0x6c92d4", "_buttons_set_action": "0x41c550", "_buttons_count": "0x41c560", "_button_get": "0x41c570", "_buttons_reset_to": "0x41c580", "_buttons_default_colours": "0x41c5a0", "_btn_fg": "0x4d01d8", "_btn_bg": "0x4d01e8", "_btn_hi_fg": "0x4d01b8", "_btn_hi_bg": "0x4d01c8", "_btn_dis_fg": "0x4d0198", "_btn_dis_bg": "0x4d01a8", "_buttons_bg": "0x41c650", "_buttons_fg": "0x41c680", "_buttons_hi_bg": "0x41c6b0", "_buttons_hi_fg": "0x41c6e0", "_buttons_dis_bg": "0x41c710", "_buttons_dis_fg": "0x41c740", "_button_box": "0x41c770", "_btn_box": "0x4d0204", "_button_box_top": "0x41c780", "_button_box_bottom": "0x41c790", "_button_box_left": "0x41c7a0", "_button_box_right": "0x41c7b0", "_button_set_box": "0x41c7c0", "_button_set_layout": "0x41c7f0", "_btn_across": "0x6c92dc", "_btn_down": "0x6c92d8", "_buttons_layout_w": "0x41c810", "_buttons_layout_h": "0x41c820", "_button_set_squeeze_x": "0x41c830", "_font_scalex": "0x4d0218", "_button_set_squeeze_y": "0x41c8c0", "_font_scaley": "0x4d0214", "_buttons_set_default_squeeze": "0x41c950", "_default_squeeze": "0x4d0194", "_default_clamp": "0x4d0190", "_button_set_squeeze": "0x41c970", "_button_set_text": "0x41c9c0", "_buttons_set_default_shrink": "0x41ca20", "_default_shrink": "0x4d018c", "_button_set_w_ex": "0x41ca30", "_button_set_w": "0x41ca70", "_button_set_h_ex": "0x41cab0", "_button_set_h": "0x41caf0", "_button_init": "0x41cb30", "_button_ex": "0x41cb70", "_fg_additive": "0x6c92c8", "_bg_additive": "0x6c92c4", "_pulse_amount": "0x4d0200", "_pulse_speed": "0x4d01fc", "_default_backing": "0x6c92c0", "_button": "0x41ce70", "_button_label": "0x41ceb0", "_button_grid_ex": "0x41cf10", "_button_grid": "0x41cf70", "_buttons_set_font_scalex": "0x41cfa0", "_buttons_set_font_scaley": "0x41cfc0", "_buttons_set_font_scale": "0x41cfe0", "_buttons_set_sprites": "0x41d010", "_buttons_set_font": "0x41d020", "_buttons_set_pulse": "0x41d040", "_buttons_set_default_backing": "0x41d060", "_buttons_set_fg_additive": "0x41d070", "_buttons_set_bg_additive": "0x41d080", "_button_count": "0x41d090", "_sign": "0x41d0a0", "_sign_int": "0x41d0c0", "_calc_fsqrt": "0x41d0d0", "_calc_rel_dir_x": "0x41d110", "_calc_rel_dir_y": "0x41d160", "_calc_gcd": "0x41d1b0", "_calc_summation": "0x41d1e0", "_calc_geometric_series_sum": "0x41d200", "_calc_is_circle_collide": "0x41d240", "_calc_dist_sqr": "0x41d280", "_calc_dist": "0x41d2a0", "_calc_xy": "0x41d2f0", "_calc_angle_xy": "0x41d370", "_calc_angle_sector": "0x41d400", "_calc_angle_to": "0x41d490", "_calc_angle_to_point": "0x41d4e0", "_calc_sector_angle": "0x41d560", "_calc_time_to_axis_intercept": "0x41d600", "_calc_axis_pos_in_time": "0x41d650", "_calc_axis_vel_for_time_and_pos": "0x41d680", "_calc_flight_time": "0x41d6d0", "_calc_vel_for_flight_time": "0x41d6e0", "_calc_bresenham": "0x41d6f0", "_dot": "0x41d810", "_dot3": "0x41d830", "_normal2d": "0x41d850", "_cross2d": "0x41d870", "_cross3d": "0x41d890", "_vecxy": "0x41d8e0", "_vecxyz": "0x41d8f0", "_add": "0x41d910", "_add3": "0x41d940", "_sub": "0x41d970", "_sub3": "0x41d9a0", "_mult": "0x41d9d0", "_mult3": "0x41da00", "_magnitude_squared": "0x41da30", "_magnitude": "0x41da50", "_mag3_squared": "0x41da90", "_mag3": "0x41dab0", "_normalize": "0x41db00", "_norm3": "0x41db90", "_calc_diff_to_circle": "0x41dc40", "_calc_diff_to_circle_edge": "0x41dce0", "_calc_nearest_point_on_circle_edge": "0x41dd60", "_calc_nearest_point_in_circle": "0x41ddd0", "_calc_nearest_point_in_box": "0x41de40", "_calc_nearest_point_on_box_edge": "0x41df50", "_calc_diff_circle_vs_box": "0x41e260", "_test_circle_vs_point": "0x41e270", "_test_circle_vs_aabb": "0x41e2a0", "_calc_nearest_point_on_line_segment": "0x41e410", "_test_circle_vs_line_segment": "0x41e490", "_calc_diff_circle_vs_circle": "0x41e570", "_calc_diff3_circle_vs_circle": "0x41e620", "_test_circle_vs_capsule": "0x41e700", "_calc_fatan2": "0x41e7d0", "_calc_hsv_to_rgb": "0x41e840", "_calc_hex_to_rgb": "0x41e9c0", "_calc_rgb_to_hex": "0x41ea10", "_rgb_mult": "0x41ea80", "_rgba_mult": "0x41eab0", "_rgb_add": "0x41eaf0", "_rgba_add": "0x41eb20", "_angle_colour": "0x41eb60", "_calc_catmullrom_spline": "0x41eca0", "_particle_default_update": "0x41ed20", "_particle_sort": "0x41ed60", "_particles": "0x86ba08", "_default_draw": "0x41eda0", "_flash_draw": "0x41ede0", "_particle_is_valid": "0x41ee70", "_particle_is_active": "0x41ee90", "_particle_update_accel3": "0x41eec0", "_particles_set_max": "0x41ef20", "_max_particles": "0x4d021c", "_particles_init": "0x41ef40", "_latest": "0x7cbd24", "_sprites": "0x86ba3c", "_init": "0x8da080", "_count_": "0x6e2dc0", "_camera_callback": "0x6e2dcc", "_particle_dummy": "0x41efa0", "_dummy.12608": "0x6e1cc0", "_particle_new": "0x41efc0", "_particle_free": "0x41f0e0", "_particle_id": "0x41f110", "_particles_active": "0x41f130", "_particles_update": "0x41f140", "_particle_order": "0x6e1dc0", "_particles_set_camera_offset_callback": "0x41f270", "_particles_draw_ex": "0x41f280", "_particles_draw": "0x41f520", "_particle_effect_flash": "0x41f550", "_particle_pre_draw_and_fade": "0x41f710", "_particle_default_alpha_draw": "0x41f810", "_particle_default_additive_draw": "0x41f860", "_particle_effect_sprite": "0x41f8c0", "_stick_init": "0x41f920", "_stick_btn": "0x41f990", "_stick_draw_ex": "0x41fa10", "_stick_draw": "0x4200e0", "_stick_update": "0x420100", "_stick_vector": "0x4203b0", "_stick_scaled_vector": "0x420440", "_stick_scale": "0x4204e0", "_stick_angle": "0x420550", "_code_branch": "0x420590", "_code_lit_int": "0x4205a0", "_code_lit_float": "0x4205d0", "_code_lit_string": "0x420600", "_code_lit_wordref": "0x420630", "_code_docon": "0x420660", "_code_dovar": "0x420690", "_code_dodefer": "0x4206c0", "_code_exit_inner": "0x420700", "_code_fatal": "0x420720", "_code_enter": "0x420740", "_code_dodoes": "0x420780", "_code_exit": "0x4207e0", "_code_break": "0x420840", "_code_branch0": "0x420870", "_code_does": "0x4208c0", "_code_interpret": "0x420950", "_code_compile": "0x420b40", "_code_next": "0x420b80", "_code_for": "0x420c00", "_code_init_table": "0x420c40", "_init.3727": "0x71cde0", "_add_chunk.isra.0": "0x420e00", "_inc_cell.part.1": "0x420e50", "_resolve_tag": "0x420e70", "_patch_breaks": "0x420eb0", "_break_tag": "0x4d024c", "_fs_ahead.part.6": "0x420f20", "_orig_tag": "0x4d0258", "_fs_if.part.3": "0x420f20", "_compile_init": "0x420f80", "_compile_exit": "0x420fb0", "_compile_abort": "0x420ff0", "_compile_word": "0x421030", "_compile_postponed": "0x421080", "_compile_int": "0x4210f0", "_compile_float": "0x421170", "_compile_string": "0x421240", "_compile_wordref": "0x421390", "_fs_literal": "0x421410", "_fs_postpone": "0x421560", "_fs_recurse": "0x4215d0", "_fs_compile_begin": "0x421640", "_colon_tag": "0x4d0268", "_fs_compile_pause": "0x4216e0", "_fs_compile_resume": "0x421720", "_fs_compile_end": "0x421770", "_fs_if": "0x421890", "_fs_then": "0x421900", "_fs_begin": "0x4219b0", "_dest_tag": "0x4d0260", "_fs_until": "0x421a00", "_fs_again": "0x421af0", "_fs_while": "0x421be0", "_fs_repeat": "0x421c10", "_fs_ahead": "0x421c40", "_fs_else": "0x421cb0", "_fs_for": "0x421cf0", "_for_tag": "0x4d0254", "_fs_next": "0x421da0", "_fs_break": "0x421eb0", "_fs_does": "0x421fd0", "_dict_create": "0x422040", "_dict_get_word_dict": "0x422090", "_dict_get_linear": "0x4220a0", "_dict_get": "0x422110", "_dict_get1": "0x422170", "_dict_value": "0x422180", "_dict_del": "0x4221a0", "_dict_forget": "0x422250", "_dict_set_exec": "0x4222a0", "_dict_set_code": "0x4222b0", "_dict_get_flags": "0x4222c0", "_dict_set_flags": "0x4222d0", "_dict_get_last": "0x4222e0", "_dict_get_first": "0x422310", "_dict_get_next": "0x422340", "_dict_get_prev": "0x422350", "_dict_get_name": "0x422360", "_dict_set_name": "0x422370", "_dict_add_word": "0x4223d0", "_dict_attach": "0x422480", "_dict_refcount": "0x4224a0", "_dict_attached": "0x4224b0", "_dict_dump_hash_table": "0x4224c0", "_dict_dump_hash_stats": "0x4224d0", "_dict_rehash_table": "0x4224e0", "_dict_release": "0x4224f0", "_hashfunc_key_str": "0x422540", "_mh_find": "0x422590", "_mh_new_ex": "0x422620", "_mh_put": "0x4226e0", "_dump_table_stats": "0x422880", "_comparefunc_key_str": "0x422a60", "_fhash_rehash": "0x422ab0", "_fhash_new_dict_ex": "0x422ac0", "_fhash_new_dict": "0x422af0", "_fhash_put_dict": "0x422b10", "_fhash_get_dict": "0x422b30", "_fhash_del_dict": "0x422b80", "_fhash_dump_stats": "0x422c70", "_fhash_dump_dict": "0x422cd0", "_fhash_free_dict": "0x422ce0", "_fhash_dict_load": "0x422d10", "_fhash_dict_size": "0x422d20", "_vm_inner_step": "0x422d30", "_vm_inner_loop": "0x422d60", "_vm_reset": "0x422d90", "_vm_abort": "0x422db0", "_vm_push_int": "0x422e10", "_vm_push_marker": "0x422e40", "_vm_get_int": "0x422e70", "_vm_get_marker": "0x422eb0", "_vm_cs_roll": "0x422ef0", "_vm_get_type": "0x422f90", "_vm_push_ip": "0x422fd0", "_vm_load_word": "0x423010", "_is_token_end": "0x423020", "_parse_general": "0x423080", "_parse_get_token": "0x423150", "_stack_init": "0x423310", "_stack_new": "0x423350", "_stack_delete": "0x4233c0", "_stack_check_offset": "0x4233f0", "_stack_convert_offset": "0x423450", "_stack_push": "0x4234b0", "_stack_push_value": "0x4234f0", "_stack_copy": "0x423540", "_stack_copy_resize": "0x4235c0", "_stack_get_deref": "0x423650", "_stack_push_ref": "0x423690", "_stack_pick_ref": "0x4236e0", "_stack_pick_deref": "0x423720", "_stack_pick": "0x423790", "_stack_swap": "0x423800", "_stack_pop": "0x423860", "_stack_remove": "0x4238a0", "_stack_get_value": "0x4238e0", "_stack_pop_to": "0x423910", "_stack_rotl": "0x4239a0", "_stack_rotr": "0x423a70", "_string_set_temp_str": "0x423b40", "_search_dictionaries.isra.0": "0x423bc0", "_fs_throw_it.part.5": "0x423c60", "_get_stack": "0x423c80", "_run_system": "0x423cf0", "_fs_sys_init_ex": "0x423ea0", "_fs_sys_init": "0x424000", "_fs_get_type_name": "0x424030", "__type_name": "0x4d2c80", "_fs_get_result_string": "0x4240b0", "__result_name": "0x4d2ab4", "__error_name": "0x4d2be0", "_fs_get_last_token": "0x424150", "_fs_get_current_line_number": "0x4241f0", "_voc_new_word": "0x424260", "_fs_register_func": "0x4242a0", "_fs_register_defer": "0x424330", "_fs_register_const": "0x4243d0", "_fs_register_var": "0x424490", "_voc_get_word": "0x424530", "_voc_current_get_word": "0x424600", "_fs_create_stack": "0x424680", "_fs_stack_rotl": "0x424700", "_fs_stack_rotr": "0x424740", "_fs_stack_pick": "0x424780", "_fs_stack_pick_ref": "0x4247d0", "_fs_stack_swap_out": "0x424820", "_fs_stack_swap": "0x424880", "_fs_stack_depth": "0x4248c0", "_fs_stack_size": "0x4248f0", "_fs_stack_space": "0x424910", "_fs_stack_push": "0x424930", "_fs_stack_copy_resized": "0x424980", "_fs_stack_pop": "0x4249e0", "_fs_store": "0x424a10", "_fs_func_call": "0x424a70", "_fs_push_func": "0x424aa0", "_fs_push_int": "0x424b00", "_fs_push_float": "0x424b40", "_fs_push_string": "0x424b80", "_fs_push_string_span": "0x424be0", "_in_push_wordref": "0x424c50", "_in_get_word": "0x424c90", "_fs_push_word": "0x424d00", "_fs_is_push_word": "0x424d80", "_fs_push_last_word": "0x424df0", "_fs_push_first_word": "0x424e40", "_fs_is_dict_empty": "0x424e90", "_fs_get_shared_count": "0x424eb0", "_fs_push_last_shared_word": "0x424ed0", "_fs_push_first_shared_word": "0x424f70", "_fs_push_next_word": "0x425010", "_fs_push_previous_word": "0x4250f0", "_fs_push_user": "0x4251d0", "_fs_get_type": "0x425210", "_fs_get_ref_type": "0x425240", "_fs_get_func": "0x425290", "_fs_find_word_handle": "0x4252c0", "_fs_find_current_word_handle": "0x425300", "_fs_get_word_handle": "0x425340", "_fs_pop_word_handle": "0x425370", "_fs_push_word_handle": "0x4253b0", "_fs_push_word_xt": "0x4253c0", "_fs_get_void": "0x425400", "_fs_get_token": "0x425430", "_fs_get_user": "0x425480", "_fs_pop_user": "0x4254d0", "_fs_get_int": "0x425530", "_fs_pop_int": "0x425560", "_fs_get_float": "0x4255b0", "_fs_pop_float": "0x4255e0", "_fs_get_string": "0x425630", "_fs_pop_string": "0x425670", "_fs_peek_char": "0x4256c0", "_fs_scan_char": "0x4256f0", "_fs_scan_text": "0x425730", "_fs_forget_ex": "0x4257d0", "_fs_forget": "0x4258b0", "_fs_get_word_flags": "0x4258e0", "_fs_set_word_flags": "0x425910", "_fs_get_word_name": "0x425980", "_fs_set_word_name": "0x425a00", "_fs_is_compiling": "0x425a80", "_fs_index": "0x425a90", "_fs_strlen": "0x425b20", "_sys_input_drop": "0x425b60", "_fs_input_length": "0x425c00", "_fs_input_offset": "0x425c20", "_fs_clear_input": "0x425c40", "_fs_reset_ex": "0x425c70", "_fs_load_input": "0x425cb0", "_fs_input_new": "0x425d80", "_fs_step": "0x425dd0", "_fs_run": "0x425de0", "_fs_is_running": "0x425df0", "_fs_execute": "0x425e00", "_fs_load_word": "0x425e30", "_fs_pop": "0x425e70", "_fs_remove": "0x425e90", "_fs_depth": "0x425ec0", "_fs_rdepth": "0x425ed0", "_fs_space": "0x425ee0", "_fs_pick": "0x425ef0", "_fs_pick_ref": "0x425f20", "_fs_fetch": "0x425f50", "_fs_swap": "0x425f80", "_fs_rotl": "0x425fb0", "_fs_rotr": "0x425fe0", "_fs_push_word_data": "0x426010", "_fs_push_word_voc": "0x426060", "_fs_throw_it": "0x4260e0", "_fs_voc_new": "0x426100", "_fs_voc_size": "0x426160", "_fs_voc_depth": "0x426180", "_fs_voc_pick": "0x4261a0", "_fs_voc_push": "0x426200", "_fs_voc_pop": "0x426280", "_fs_voc_clear": "0x4262c0", "_fs_voc_clear_compile": "0x4262f0", "_fs_reset": "0x426340", "_fs_voc_get_compile": "0x426380", "_fs_voc_set_compile": "0x4263b0", "_fs_dict_attach": "0x426420", "_fs_exit": "0x426480", "_fs_to_r": "0x4264d0", "_fs_r_to": "0x426500", "_fs_r_fetch": "0x426530", "_fs_r_pick": "0x426570", "_fs_rswap": "0x4265b0", "_fs_sys_exit": "0x4265e0", "_value_init_string": "0x4266d0", "_value_new_ref": "0x426720", "_value_new_wordref": "0x426770", "_value_init_ref": "0x4267c0", "_value_init_wordref": "0x426800", "_value_shift": "0x426840", "_value_swap": "0x426870", "_value_copy": "0x4268b0", "_value_get_int": "0x4269f0", "_value_get_float": "0x426a80", "_value_get_string": "0x426ad0", "_value_unref": "0x426c20", "_value_unwordref": "0x426c70", "_value_clean": "0x426cc0", "_value_store": "0x426d40", "_value_new_array": "0x426dd0", "_value_delete": "0x426df0", "_value_delete_array": "0x426e20", "_pos_occupant": "0x426e70", "_ai_is_pos_clear_ex": "0x426ea0", "_ai_is_pos_clear": "0x426ee0", "_ai_scan_los": "0x426f40", "_ai_scan_los_steps_ex": "0x427170", "_ai_scan_los_steps": "0x427380", "_ai_get_good_destpos_ex": "0x4273d0", "_ai_get_good_destpos": "0x427880", "_ai_get_good_destpos_scan_ex": "0x4278d0", "_ai_get_good_destpos_scan": "0x427e70", "_chara_set_stat": "0x427ec0", "___func__.18298": "0x4d2e24", "_chara_stat": "0x427f30", "___func__.18303": "0x4d2e18", "_chara_effective_stat": "0x427f90", "___func__.18310": "0x4d2e00", "_chara_set_bonus": "0x428020", "___func__.18316": "0x4d2df0", "_chara_bonus": "0x4280a0", "___func__.18321": "0x4d2de4", "_chara_stat_known": "0x428100", "___func__.18326": "0x4d2dd0", "_chara_stat_set_known": "0x428160", "___func__.18332": "0x4d2db8", "_chara_inc_stat": "0x4281c0", "___func__.18338": "0x4d2da8", "_chara_clamp_stat": "0x428240", "___func__.18345": "0x4d2d94", "_chara_set_modnum": "0x428330", "_chara_check_modnum": "0x428360", "_chara_clear_modnum": "0x428390", "_chara_refresh_stat_mods": "0x4283c0", "_chara_call_command_mods": "0x428460", "_chara_call_animate_mods": "0x4284e0", "_chara_call_main_event_mod": "0x428590", "_chara_stat_name.part.0": "0x428650", "_chara_get_safe.part.2": "0x4286d0", "_dummy.18618": "0x71ce00", "_chara_new_ex.part.4": "0x428720", "_do_chara_new": "0x4288e0", "_chara_slot_max.part.7": "0x428940", "___func__.18778": "0x4d2fd4", "_chara_stat_name": "0x428980", "_chara_loot_amt": "0x4289a0", "_chara_add_loot": "0x4289c0", "_chara_is_injured": "0x428a00", "___func__.18582": "0x4d3094", "_chara_thing": "0x428a50", "___func__.18586": "0x4d3088", "_chara_thing_safe": "0x428ab0", "_chara_get": "0x428ae0", "_chara_is_dead": "0x428b10", "_chara_move_loot_to_trunk": "0x428b40", "_chara_get_safe": "0x428bb0", "_chara_get_custom": "0x428bd0", "_chara_get_game": "0x428c10", "_chara_id": "0x428c40", "_chara_get_stat": "0x428c70", "___func__.18638": "0x4d3078", "_chara_get_max_health": "0x428cf0", "_chara_get_injury_count": "0x428d60", "___func__.18647": "0x4d3060", "_chara_default_ai_settings": "0x428dd0", "_chara_new_ex": "0x428ef0", "_chars_recycle": "0x428f10", "___func__.18661": "0x4d3050", "_chara_new": "0x429010", "_chara_free": "0x429040", "_chara_dump_stats": "0x429090", "___func__.18685": "0x4d303c", "_chara_debug_stats": "0x4291d0", "___func__.18693": "0x4d3028", "_chara_roll_hat_id": "0x429210", "_chara_roll_glasses_id": "0x4292a0", "_chara_roll_body_id": "0x429330", "_chara_roll_head_id": "0x4293d0", "_chara_roll_hair_id": "0x429460", "_chara_roll_beard_id": "0x4294f0", "_chara_rand_skinclr": "0x429580", "_chara_gen_ex2.part.13": "0x4295c0", "___func__.18744": "0x4d3018", "_chara_gen_ex2": "0x429990", "_chara_gen_ex": "0x4299c0", "_chara_gen": "0x429a10", "_chara_get_head_sprite": "0x429a30", "_chara_set_default_weapon": "0x429ab0", "___func__.18769": "0x4d2ffc", "_chara_default_weapon": "0x429b00", "___func__.18773": "0x4d2fe4", "_chara_slot_max": "0x429b50", "_chara_slot_weapon": "0x429b80", "_chara_used_weapon": "0x429be0", "_chara_can_drop_weapon": "0x429c10", "___func__.18793": "0x4d2fbc", "_chara_is_nodrop_slot": "0x429c90", "_chara_set_weapon": "0x429d20", "___func__.18804": "0x4d2fa8", "_chara_weapon_stack": "0x429e50", "___func__.18814": "0x4d2f94", "_chara_drop_weapons_to_trunk": "0x429f00", "_chara_wrap_slot_used": "0x429fa0", "_chara_weapon_charges": "0x429ff0", "___func__.18829": "0x4d2f7c", "_chara_weapon_charges_avail": "0x42a090", "___func__.18837": "0x4d2f60", "_chara_weapons_carried": "0x42a150", "_chara_weapon_slots_free": "0x42a1c0", "_chara_weapon_stack_avail": "0x42a200", "___func__.18857": "0x4d2f44", "_chara_inc_weapon_stack": "0x42a2c0", "___func__.18866": "0x4d2f2c", "_chara_try_add_slot_weapon": "0x42a3c0", "_chara_try_add_free_weapon": "0x42a480", "_chara_drop_weapon": "0x42a590", "_chara_main_script_event": "0x42a5e0", "___func__.18896": "0x4d2f14", "_char_extra_head_count_max": "0x42a6b0", "_char_head_count_ex": "0x42a6d0", "_char_head_count": "0x42a730", "_char_extra_hair_count_max": "0x42a790", "_char_hair_count_ex": "0x42a7b0", "_char_hair_count": "0x42a810", "_char_extra_hat_count_max": "0x42a870", "_char_hat_count_ex": "0x42a890", "_char_hat_count": "0x42a8f0", "_char_extra_body_count_max": "0x42a950", "_char_body_count_ex": "0x42a980", "_char_body_count": "0x42aa00", "_char_extra_glasses_count_max": "0x42aa80", "_char_glasses_count_ex": "0x42aaa0", "_char_glasses_count": "0x42ab00", "_char_extra_beard_count_max": "0x42ab60", "_char_beard_count_ex": "0x42ab70", "_char_beard_count": "0x42abe0", "_chara_babble": "0x42ac50", "___func__.18973": "0x4d2f04", "_chara_ugh": "0x42ae00", "_chara_hup": "0x42aeb0", "_chara_clear_if_preferred_slot": "0x42af80", "_chara_is_preferred_slot": "0x42afb0", "_chara_set_preferred_slot": "0x42afd0", "_chara_is_usable_as_preferred": "0x42b000", "_chara_ammo_for_weapon": "0x42b0b0", "_reenter_leave": "0x42b0e0", "_hairclr_randfunc": "0x42b0f0", "_dude": "0x7d09c0", "_bodysize_randfunc": "0x42b130", "_validate_body": "0x42b170", "_reset": "0x71d0e8", "_customize_reenter": "0x42b2f0", "_first": "0x71d470", "_back_to_start": "0x4599e0", "_picked_trait": "0x42b380", "_selected_trait": "0x71d0f0", "_picked_perk": "0x42b3c0", "_selected_perk": "0x71d0f4", "_beard_randfunc": "0x42b400", "_shades_randfunc": "0x42b440", "_hat_randfunc": "0x42b480", "_hair_randfunc": "0x42b4c0", "_skinclr_randfunc": "0x42b500", "_face_randfunc": "0x42b530", "_bottoms_randfunc": "0x42b570", "_tops_randfunc": "0x42b5b0", "_gender_randfunc": "0x42b5f0", "_validate_body_reenter": "0x42b620", "_btn_char_edit_mode": "0x42b640", "_char_edit_mode": "0x71d0ec", "_btn_rotate_uint16_val_inc": "0x42b6a0", "_btn_rotate_uint16_val_dec": "0x42b720", "_btn_rotate_uint16_val": "0x42b7b0", "_btn_select_trait": "0x42b910", "___func__.19007": "0x4d3204", "_btn_select_perk": "0x42b9e0", "___func__.19001": "0x4d31f4", "_customize_btn_char_panel": "0x42bab0", "_btn_roll_datafunc": "0x42bbf0", "_selection.constprop.5": "0x42bd20", "_customize_layout": "0x42be70", "_charmake_selected_perk": "0x42c690", "_charmake_selected_trait": "0x42c6a0", "_charmake_roll_a_char": "0x42c6b0", "_btn_roll_char": "0x459890", "_charmake_validate_chars": "0x42c800", "_charmake_clear_chars": "0x42c830", "_charmake_load_chars": "0x42c860", "_init_.19029": "0x71d0e0", "_customize_enter": "0x42c8e0", "_charmake_chara_for_edit": "0x42c910", "_load_and_leave": "0x42c950", "_load_to_char": "0x71d474", "_save_enter": "0x42c9a0", "_changed": "0x71d478", "_charsave_reenter_state": "0x4d02c0", "_load_enter": "0x42c9d0", "_charload_reenter_state": "0x4d02b0", "_save_and_leave": "0x42ca40", "_chardelete": "0x42ca70", "_charmake_set_load_to_char": "0x42cae0", "_charmake_chara_for_slot": "0x42caf0", "_charmake_is_slot_used": "0x42cb20", "_layout": "0x4ba470", "_chars": "0x71d480", "_saving": "0x71d47c", "_titletext.19169": "0x71d420", "_save_reenter": "0x42cd50", "_btn_chara_page": "0x42cd70", "_load_reenter": "0x42cde0", "_charmake_do_load_from_slot": "0x42ce00", "_btn_chara_slot": "0x42ce60", "_charmake_count_custchars": "0x42d280", "_sound_cant": "0x42d2b0", "_humans_available": "0x42d300", "_charselect_buttons": "0x42d330", "_temp_slots": "0x71d4a4", "_try_unjoin": "0x42d5f0", "_btn_temp_char": "0x42d6f0", "_btn_human": "0x42dc10", "_main_post_chara_event": "0x42e180", "___func__.19016": "0x4d3300", "_charselect_process_assignments": "0x42e240", "_charselect_layout": "0x42e450", "_last_.19042": "0x71d4a0", "_add_int": "0x42e4d0", "_add_char": "0x42e500", "_add_str": "0x42e520", "_add_cmd": "0x42e550", "_scan_token": "0x42e580", "_read_data": "0x42e660", "_read_cmd": "0x42e6a0", "_read_is_int": "0x42e720", "_read_int": "0x42e770", "_search_with_tags_ex": "0x42e7c0", "_search_with_tags": "0x42e940", "_quiet_": "0x71d4c8", "_console_btn_wrap": "0x42ea20", "_scrollback": "0x71f630", "_input_buf": "0x71d580", "_row_tail": "0x71f644", "_row_head": "0x71f648", "_textlines": "0x71f660", "_console_window_lines": "0x71f62c", "_input_cursor": "0x71f634", "_char_bip.part.2": "0x42f230", "_last_.18482": "0x71d4c4", "_bip.part.3": "0x42f260", "_last_.18477": "0x71d4c0", "_console_init.part.6": "0x42f2b0", "_input_history": "0x71d620", "_row_cursor": "0x71f640", "_window": "0x71f63c", "_wrap_width": "0x71f638", "_forth_next_word_like.constprop.9": "0x42f510", "_console_init": "0x42f850", "_console_delete_char": "0x42f870", "_console_add_text_ex": "0x42f900", "_change_history": "0x42fae0", "_input_index": "0x71d604", "_history_index": "0x71d608", "_input_backup_buf": "0x71d4e0", "_console_insert_char": "0x42fcb0", "_last_found": "0x71f628", "_last_found_count": "0x71f624", "_auto_cursor_pos": "0x71f620", "_console_add_text": "0x4300f0", "_console_write": "0x430110", "_console_clear_input": "0x430950", "_console_quiet": "0x430980", "_controls_test_key.part.0": "0x430990", "_controls_set_mapping": "0x430a40", "_controls_get_mapping_keyid": "0x430ab0", "_controls_get_mapping_mode": "0x430af0", "_controls_get_joyid": "0x430b30", "_controls_replace_and_set_key_mapping": "0x430b60", "_controls_validate_mappings": "0x430cc0", "_controls_test_key": "0x430da0", "_controls_check_any_joy_button": "0x430dd0", "_controls_joy_dir": "0x430e00", "_controls_dir_to_cmd": "0x430fc0", "_controls_cmd_to_dir": "0x431030", "_controls_joy_cmd": "0x431080", "_controls_poll_all_cmds": "0x431110", "_cursor_to_button": "0x4313f0", "_cursor": "0x79ca80", "_find_current_button_ex.constprop.0": "0x431460", "_find_nearest_button": "0x4314f0", "_cursor_pos": "0x4317a0", "_cursor_current_button": "0x4317c0", "_cursor_disable": "0x4317f0", "_cursors_disabled_": "0x79ca6c", "_cursor_is_disabled": "0x431810", "_cursors_disable": "0x431820", "_cursors_reset": "0x431840", "_cursor_spriteid": "0x79ca7c", "_cursors_invalidate_button": "0x4318d0", "_cursor_save": "0x431900", "_cursorpos": "0x79ca64", "_cursor_set_spriteid": "0x431920", "_cursor_set_which_spriteid": "0x431940", "_cursor_set_hide_timeout": "0x431960", "_cursor_reset_hide_timeout": "0x431970", "_cursors_active": "0x431990", "_cursor_colour": "0x4319c0", "_cursor_draw": "0x431b60", "_cursors_draw": "0x432070", "_cursor_to_nearest": "0x4321b0", "_cursor_navigate": "0x4322a0", "_cursors_navigate_buttons": "0x4325d0", "_cursor_reset_nearest": "0x4326d0", "_cursor_restore": "0x432720", "_cursors_reset_nearest": "0x4327b0", "_resume": "0x4329b0", "_cyoa_btn_choice": "0x4329e0", "_cyoa_push_popup_state_btn": "0x432e90", "_draw_icon": "0x432ed0", "_cyoa_btn_image_wrap": "0x432fd0", "_draw_char_head": "0x4330d0", "_draw_event_card": "0x433140", "_draw_character.part.6": "0x4331d0", "_draw_character": "0x434640", "_layout_more.constprop.8": "0x433390", "_textbox": "0x79cb60", "_cyoa_more_btn": "0x4337a0", "_cyoa_is_active": "0x433aa0", "_cyoa_start": "0x433ae0", "_cyoa_set_fade": "0x433c50", "_cyoa_set_clickspeed": "0x433c60", "_cyoa_set_title": "0x433c70", "_cyoa_set_title_popup_button": "0x433ca0", "_cyoa_set_icon_handler": "0x433cd0", "_cyoa_set_textmode": "0x433cf0", "_cyoa_set_text": "0x433d00", "_cyoa_append_text": "0x433d30", "_cyoa_set_choice_text": "0x433d90", "_cyoa_add_choice": "0x433e00", "_cyoa_set_choice_charid": "0x433ed0", "_cyoa_set_choice_iconid": "0x433f20", "_cyoa_set_choice_func": "0x433f70", "_cyoa_set_choice_handle": "0x433fb0", "_cyoa_set_choice_id": "0x433ff0", "_cyoa_set_choice_esc_default": "0x434030", "_cyoa_picked": "0x434070", "_cyoa_hint": "0x434080", "_cyoa_chosen_id": "0x434090", "_cyoa_chosen_charid": "0x4340b0", "_cyoa_chosen_text": "0x4340d0", "_cyoa_show": "0x4340f0", "_cyoa_just_ok": "0x434100", "_cyoa_yesno": "0x4341a0", "_cyoa_set_image_icon": "0x434320", "_cyoa_set_image_icon_rgb": "0x434340", "_cyoa_set_icon_hint": "0x434360", "_cyoa_set_hint": "0x434370", "_cyoa_set_character_icon": "0x434380", "_cyoa_is_typing": "0x4343a0", "_draw_layer_particles": "0x4343f0", "_draw_road_layer": "0x434430", "_parallax": "0x79cb80", "_road_data": "0x79cb84", "_specialchar": "0x79cb78", "_resume_enter": "0x435150", "_refresh": "0x79cb7c", "_rain_particle": "0x445d30", "_smoke_particle_update": "0x446e00", "_bounce_particle_update": "0x4bb710", "_rain_update": "0x44fbe0", "_done_layout": "0x79cb74", "_resume_leave": "0x4361d0", "_driving_state_init": "0x4361e0", "_game_road_set_special_charid": "0x436540", "_game_road_special_charid": "0x436550", "_check_car_hit_junk": "0x436560", "_driving_state_exit": "0x436570", "_add_undo": "0x43aed0", "_undo": "0x7ad160", "_template": "0x7a9ca0", "_btn_setup_layout": "0x4365f0", "_btn_mouse_pos": "0x4366f0", "_next_layout_mode": "0x436750", "_layout_mode": "0x7aa2f4", "_special_render_": "0x7aa2d8", "_layout_": "0x79ccbc", "_update_": "0x79ccb8", "_tileset": "0x7a9a20", "_layout_all_tiles": "0x436920", "_btn_tileset": "0x436a70", "_btn_all_tiles": "0x4372e0", "_tile_base": "0x7aa2f0", "_btn_clr": "0x43c0e0", "_btn_group_data_toggle": "0x437d50", "_btn_plot_func": "0x437dd0", "_btn_plot_range": "0x437e40", "_plot_template": "0x437f60", "_params": "0x79cbc0", "_layout_preview": "0x4385c0", "_common_update": "0x438910", "_editing_a_field": "0x7aa2e4", "_keypressed": "0x7aa2ec", "_keypressed_id": "0x7aa2e8", "_update_all_tiles": "0x438a10", "_render_preview": "0x438a20", "_zoom": "0x4d0394", "_update_preview": "0x438b40", "_btn_redo": "0x43c2d0", "_btn_undo": "0x43c480", "_btn_paste": "0x43c630", "_btn_copy": "0x43c780", "_layout_template": "0x438fd0", "_template_edit_btn": "0x7aa2e0", "_mode_select": "0x7aa2dc", "_btn_custom": "0x439650", "_btn_plot_tile": "0x439700", "_btn_edit_group_id": "0x439750", "_btn_edit_field": "0x439980", "_btn_edit_template": "0x439cf0", "_update_template": "0x43acd0", "_node_editor": "0x7aa300", "_undo_count": "0x7ad158", "_undo_total": "0x7ad154", "_undo_index": "0x7ad15c", "_grid": "0x7c9d80", "_editor": "0x7ac7c0", "_ffill4": "0x43b000", "_export_edit_to_room": "0x43b0e0", "_draw_edit_map": "0x43b2d0", "_scroll_y": "0x7ac7ac", "_scroll_x": "0x7ac7b0", "_click_x": "0x7ac798", "_click_y": "0x7ac794", "_cursprite": "0x4d03d8", "_outside": "0x7ac790", "_more_render": "0x43ba50", "_preview_render": "0x43bae0", "_preview_update": "0x43bbe0", "_cam_x": "0x7ac7a8", "_cam_y": "0x7ac7a4", "_clear_grid": "0x43bd10", "_preview_enter": "0x43bd80", "_import_room_to_edit": "0x43bf30", "_btn_flood": "0x43c1a0", "_btn_script_sel": "0x43c1f0", "_script_edit_button": "0x7ac79c", "_edit_focus_button": "0x7ac7a0", "_btn_tags": "0x43c2c0", "_copy": "0x7c8f80", "_setup_highlight": "0x43c890", "_edit_more_state": "0x4d03c8", "_layout_more": "0x43cb50", "_more_enter": "0x43ce80", "_refresh_search": "0x43ce90", "_edit_room_tags": "0x43cf10", "_btn_edit_focus_button": "0x43cf60", "_edit_cursor": "0x43d0c0", "_init_.19012": "0x7ac780", "_edit_field.part.2": "0x43d220", "_more_update": "0x43d380", "_last.18893": "0x7ac788", "_delay.18892": "0x7ac784", "_edit_preview_state": "0x4d03b8", "_fillsprite": "0x7ac78c", "_error_save_log": "0x43df20", "_show_error": "0x43e140", "_error_total_count": "0x7caa08", "_error_count": "0x7caa0c", "_CSWTCH.16": "0x4d3920", "_error_append_logfile": "0x43e3c0", "_last_.18450": "0x7caa04", "_error_state_init": "0x43e4b0", "_word_strbuf_clear": "0x43e4d0", "_str_buf": "0x7caa18", "_str_ptr": "0x7caa14", "_word_dot_hex": "0x43e4f0", "_word_abort_": "0x43e540", "___FUNCTION__.19276": "0x4d4264", "_word_max": "0x43e570", "_word_min": "0x43e5d0", "_word_clamp": "0x43e630", "_word_abs": "0x43e6f0", "_word_cos": "0x43e720", "_word_sin": "0x43e790", "_word_tofloat": "0x43e7f0", "_word_not": "0x43e820", "_word_xor": "0x43e850", "_word_or": "0x43e890", "_word_and": "0x43e8d0", "_word_andbit": "0x43e910", "_word_zeq": "0x43e940", "_word_game_ticks": "0x43e970", "_word_mad_ticks": "0x43e990", "_word_seed": "0x43e9b0", "_word_toint": "0x43e9d0", "_word_set_voc": "0x43ea00", "_word_tohandle": "0x43ea60", "_word_depth": "0x43ea90", "_word_type": "0x43eac0", "_forth_emit": "0x43eb20", "_word_notbit": "0x43eb90", "_word_getvoid": "0x43ebd0", "_word_1sub": "0x43ec20", "_word_1add": "0x43ec60", "_word_seed_set": "0x43eca0", "_word_stack_size": "0x43ecd0", "_word_stack_depth": "0x43ed00", "_forth_toname": "0x43ed30", "_word_strtypeof": "0x43ed80", "_word_insrc": "0x43edd0", "_word_inbuf": "0x43edf0", "_word_crstr": "0x43ee10", "_word_strbuf_fetch": "0x43ee30", "_word_find": "0x43ee70", "_word_save_delete": "0x43eee0", "_word_strasc": "0x43eef0", "___FUNCTION__.18913": "0x4d4244", "_word_strupper": "0x43ef80", "_word_strlower": "0x43f000", "_word_rshift": "0x43f080", "_word_lshift": "0x43f0e0", "_word_xorbit": "0x43f140", "_word_orbit": "0x43f190", "_word_2drop": "0x43f1e0", "_word_veq": "0x43f200", "_word_remove": "0x43f260", "_word_strstrlen": "0x43f290", "_word_strlen": "0x43f2d0", "_forth_strcat": "0x43f310", "_word_strcreate": "0x43f3f0", "___FUNCTION__.18967": "0x4d4270", "_word_voc_depth": "0x43f460", "_word_voc_fetch": "0x43f490", "_word_voc_pick": "0x43f4e0", "_forth_word_stack": "0x43f530", "_word_stack_push": "0x43f560", "_word_store": "0x43f590", "_word_nip": "0x43f5d0", "_word_stack_resizes": "0x43f600", "_word_swap": "0x43f650", "_forth_word_stack_shove": "0x43f680", "_word_strsplit": "0x43f790", "___FUNCTION__.18907": "0x4d4234", "_word_totype": "0x43f830", "_word_strconstant": "0x43f880", "___FUNCTION__.18653": "0x4d41f4", "_word_strhash": "0x43f900", "_word_openurl": "0x43f960", "_word_dictstats": "0x43f990", "_word_dictdump": "0x43f9a0", "_word_stack_pull": "0x43f9d0", "_word_stack_enqueue": "0x43fa10", "_word_stack_dequeue": "0x43fa60", "_word_stack_pop": "0x43fab0", "_word_stack_swaps": "0x43fad0", "_word_stack_swapsdrop": "0x43fb00", "_word_rndrange": "0x43fb40", "_word_stack_shuffles": "0x43fba0", "_word_stack_pick": "0x43fc00", "_word_pick": "0x43fc30", "_word_2dup": "0x43fc70", "_word_over": "0x43fca0", "_word_under": "0x43fcc0", "_word_dup": "0x43fd00", "_word_getchar": "0x43fd20", "_word_parse": "0x43fd50", "_word_word": "0x43fd90", "_word_token": "0x43fda0", "_word_tick": "0x43fdd0", "_word_line_comment": "0x43fe30", "_word_paren": "0x43fe60", "_word_constant": "0x43fe90", "_word_iscompile": "0x43fec0", "_word_last_token": "0x43fef0", "_word_line_number": "0x43ff20", "_word_inoff": "0x43ff50", "_word_inlen": "0x43ff80", "_word_stranew": "0x43ffb0", "_word_save_exists": "0x440050", "_word_save_read": "0x440090", "_word_filesize": "0x4401a0", "_word_strcmp": "0x440210", "_word_streq": "0x4402b0", "_word_strstrstr": "0x440350", "_word_strstrrep": "0x4403e0", "_word_strchr": "0x4406c0", "_word_strmid": "0x440710", "___FUNCTION__.18900": "0x4d4228", "_word_strleft": "0x4407b0", "___FUNCTION__.18885": "0x4d4218", "_word_strright": "0x440850", "___FUNCTION__.18892": "0x4d4208", "_forth_execute": "0x4408f0", "_word_evaluate": "0x440930", "_word_xtforget": "0x440970", "_word_forget": "0x4409a0", "_word_throw": "0x440a10", "_word_yield": "0x440a40", "_word_defer": "0x440a60", "_word_tickpostpone": "0x440ab0", "_word_postpone": "0x440ae0", "_word_isimmediate": "0x440b10", "_word_immediate": "0x440b70", "_word_strhandle": "0x440bc0", "_word_mad_seconds": "0x440bf0", "_word_moonphaseyd": "0x440c10", "_word_timescale": "0x440c50", "_word_moonphase": "0x440c70", "_word_current_is_dst": "0x440c90", "_word_current_year_day": "0x440cb0", "_word_current_year": "0x440cd0", "_word_current_month_day": "0x440cf0", "_word_current_month": "0x440d10", "_word_current_week_day": "0x440d30", "_word_current_hour": "0x440d50", "_word_current_min": "0x440d70", "_word_current_sec": "0x440d90", "_word_time": "0x440db0", "_word_dice": "0x440de0", "_word_onein": "0x440e40", "_word_rndsign": "0x440e80", "_word_rnd5050": "0x440ea0", "_word_neq": "0x440ec0", "_word_eq": "0x440f40", "_word_lte": "0x440fb0", "_word_lt": "0x441020", "_word_gte": "0x441090", "_word_gt": "0x441100", "_word_fdiv": "0x441170", "_word_fmul": "0x4411d0", "_word_fsub": "0x441230", "_word_fadd": "0x441290", "_word_frndrange": "0x4412f0", "_word_mrand": "0x441360", "_word_pow": "0x441380", "_word_mod": "0x4413d0", "_word_anglediff": "0x441450", "_word_xyangle": "0x441490", "_word_anglexy": "0x4414d0", "_word_xysub": "0x441530", "_word_xymag": "0x4415c0", "_word_xynorm": "0x441610", "_word_msin": "0x441680", "_word_k": "0x4416b0", "_word_j": "0x4416d0", "_word_i": "0x4416f0", "_word_to_xt": "0x441710", "_word_to_body": "0x441740", "_word_strvariable": "0x441780", "___FUNCTION__.18636": "0x4d41e0", "_word_variable": "0x441830", "_word_set_current": "0x441860", "_word_prevword": "0x441890", "_word_nextword": "0x4418d0", "_word_voc_push": "0x441910", "_word_to_voc": "0x441940", "_word_testword": "0x441980", "_word_rover": "0x4419b0", "_word_rpick": "0x4419d0", "_word_rdepth": "0x441a10", "_word_roll": "0x441a40", "_word_rot": "0x441a70", "_word_negroll": "0x441aa0", "_word_negrot": "0x441ad0", "_word_tuck": "0x441b00", "_word_literal": "0x441b40", "_word_then": "0x441b70", "_words_like": "0x441b90", "_word_words_all": "0x441e90", "_word_words_like": "0x441ea0", "_word_once_colon": "0x441f20", "_word_noname": "0x441f90", "_word_coloncolon": "0x441fb0", "_word_colon": "0x442000", "_word_fetch": "0x442030", "_word_strbuf_cat": "0x442070", "_str_buf_len": "0x7caa10", "_word_parse_line": "0x442120", "_handle_file_error.isra.22": "0x4421b0", "___FUNCTION__.19200": "0x4d4250", "_savesave": "0x442200", "_word_save_write": "0x442250", "_word_save_append": "0x442280", "_word_save_new": "0x4422b0", "_word_file_read": "0x4422f0", "_word_strload": "0x442390", "_word_strbuf_write": "0x4423e0", "_word_char": "0x442460", "_word_0x": "0x4424e0", "_forth_word_strset.part.26": "0x442570", "_forth_word_cset.part.2": "0x442570", "_forth_word_iset.part.3": "0x442570", "_forth_word_wset.part.4": "0x442570", "_forth_word_8set.part.5": "0x442570", "_forth_word_4set.part.6": "0x442570", "_forth_word_2set.part.7": "0x442570", "_forth_word_1set.part.8": "0x442570", "_forth_word_fset.part.9": "0x442570", "_forth_word_fget.part.10": "0x442570", "_forth_word_cget.part.11": "0x442570", "_forth_word_iget.part.12": "0x442570", "_forth_word_wget.part.13": "0x442570", "_forth_word_8get.part.14": "0x442570", "_forth_word_4get.part.15": "0x442570", "_forth_word_2get.part.16": "0x442570", "_forth_word_1get.part.17": "0x442570", "_forth_word_hset.part.18": "0x442570", "_forth_word_hget.part.19": "0x442570", "_forth_word_strget.part.20": "0x442570", "_forth_word_strget": "0x442590", "_forth_word_hget": "0x4425d0", "_forth_word_hset": "0x442630", "_forth_word_1get": "0x4426a0", "_forth_word_2get": "0x4426e0", "_forth_word_4get": "0x442720", "_forth_word_8get": "0x442760", "_forth_word_wget": "0x4427a0", "_forth_word_iget": "0x4427e0", "_forth_word_cget": "0x442820", "_forth_word_fget": "0x442860", "_forth_word_fset": "0x4428a0", "_forth_word_1set": "0x4428e0", "_forth_word_2set": "0x442920", "_forth_word_4set": "0x442960", "_forth_word_8set": "0x4429a0", "_forth_word_wset": "0x4429f0", "_forth_word_iset": "0x442a30", "_forth_word_cset": "0x442a70", "_forth_word_strset": "0x442ab0", "_word_cr": "0x442b10", "_forth_usertype_name": "0x442b50", "_usertype_names": "0x4d42e0", "_forth_print_user": "0x442b70", "_print_stack_item": "0x442cb0", "_forth_show_stack": "0x443070", "_word_rdump": "0x443110", "_word_dot": "0x443410", "_forth_word_typechk": "0x443440", "_forth_init": "0x443500", "_forth_show_return_stack": "0x445520", "_forth_global_exit": "0x445530", "_word_strbuf_delete": "0x445570", "_thing_y_compare": "0x445580", "_flame_update": "0x445620", "_game_update_map": "0x445650", "_game_title_camera_pos": "0x445680", "_touch_stick": "0x8da1a0", "_enter_running": "0x445cf0", "_game_btn_stick": "0x445d20", "_render_game_over": "0x445ef0", "_enter_game_over": "0x445fa0", "_update_game_over": "0x446120", "_fly_fx": "0x446150", "_is_walkoverable_by.isra.0": "0x446420", "_game_update_type_text": "0x4464b0", "_game_pos_bucket_ex.isra.5": "0x446540", "_btn_touch": "0x4465e0", "_touch_cmd": "0x7cb31c", "_flash_colour.constprop.38": "0x446740", "_is_solid_for.constprop.40": "0x4467a0", "_is_spawn_tile_ok": "0x446800", "_thing_action_ex": "0x4468a0", "_thing_info_": "0x7cbd40", "___func__.19563": "0x4d472c", "_thing_action": "0x446920", "_game_things_init": "0x446950", "_leader_playerid": "0x4469f0", "_leader_set_playerid": "0x446a00", "_player_get": "0x446a10", "_leader_get": "0x446a30", "_thing_get": "0x446a40", "_thing_print_to_console": "0x446a70", "_thing_is_here": "0x446c80", "_thing_is_active": "0x446cb0", "_thing_get_valid": "0x446ce0", "_thing_get_active": "0x446d30", "_thing_dummy": "0x446d80", "_dummy.19647": "0x7caec0", "_thing_get_safe": "0x446da0", "_game_update_float_text": "0x446e50", "_thing_id": "0x447180", "_game_vehicle_setup_default_motor": "0x4471a0", "_is_solid": "0x4471f0", "_is_pos_solid_for": "0x447240", "_water_particle_update": "0x447310", "_game_shatter_particle_update": "0x4473b0", "_resolve_pos_dir": "0x447540", "_is_pos_snow": "0x4478f0", "_is_pos_solid": "0x447940", "_is_pos_wet": "0x447970", "_tile_push": "0x4479b0", "_game_thing_check_for_nearest": "0x4479e0", "_is_pos_overlap_item": "0x447b30", "_check_for_clear": "0x447c00", "_game_draw_box_ex": "0x447d10", "_game_draw_box": "0x447e10", "_game_draw_circle_ex": "0x447e40", "_particle_draw_circle": "0x447fa0", "_game_draw_circle": "0x447fe0", "_thing_is_line_clear": "0x448010", "_game_pos_tile_occupant": "0x448020", "_game_nearest_diff_to_thing_ex": "0x4480e0", "_game_nearest_diff_to_thing": "0x4481b0", "_game_nearest_point_on_thing_ex": "0x4481e0", "_game_nearest_point_on_thing": "0x448270", "_dist2_to_thing": "0x4482a0", "_thing_get_nearest_point": "0x4482e0", "_thing_get_nearest_point_ex": "0x448390", "_thing_get_nearest_edge_point_ex": "0x448440", "_thing_get_nearest_edge_point": "0x4484f0", "_thing_dont_hit_party_member": "0x4485a0", "_game_is_current_map_view": "0x448620", "_game_rumble_camera": "0x448650", "_foreach_active_thing": "0x448690", "_game_map_select": "0x448700", "_game_day_scale": "0x448710", "_game_wind_force": "0x4487b0", "_game_daylight_scale": "0x4487e0", "_game_night_scale": "0x448880", "_game_update_lighting": "0x4488a0", "_thing_switch_to_map_pos": "0x448990", "_pos_snap_to_center": "0x448ca0", "_pos_snap_nearest_tile_edge": "0x448d40", "_game_get_team_member": "0x448e50", "_game_get_first_valid_team_member": "0x448e80", "_game_chara_find_valid_group_slot_for": "0x448ea0", "_game_chara_set_team_status": "0x448ee0", "___func__.20190": "0x4d4704", "_game_chara_to_party": "0x448fc0", "___func__.20196": "0x4d46f0", "_game_set_group_chara_location": "0x449020", "___func__.20203": "0x4d46d0", "_game_init": "0x4490a0", "_game_set_vehicle": "0x449120", "_vehicle": "0x7cbd20", "_game_is_human_in_team": "0x449140", "_game_is_human_absent_ex": "0x449180", "_game_is_human_absent": "0x449260", "_game_leader_count_party_absentees": "0x449290", "_game_chara_recruit": "0x4492f0", "___func__.20250": "0x4d46bc", "_game_chara_decruit": "0x449390", "___func__.20256": "0x4d46a8", "_team_remove_dead": "0x449480", "_char_thing_to_road_ex": "0x4494d0", "_char_thing_to_road": "0x449670", "_char_all_thing_to_road": "0x449680", "_game_transfer_chars_to_road": "0x4496a0", "_game_transfer_all_chars_to_road": "0x449700", "_thing_slide": "0x449760", "_thing_is_overlap": "0x4498f0", "_thing_drift": "0x4499b0", "_game_lighting_for_pos": "0x449b00", "_game_rgb_weather_lighting": "0x449b90", "_game_set_turtle_weather_lighting": "0x449c70", "_game_tile_lighting_for_pos_ex": "0x449cc0", "_game_light_source": "0x449df0", "_game_rgb_lighting_for_pos_ex": "0x449e00", "_game_set_turtle_lighting_for_pos_ex": "0x44a0e0", "_game_set_turtle_lighting_for_pos": "0x44a150", "_shatter_particle_draw": "0x44a180", "_bits_particle_draw": "0x44a2a0", "_game_sprite_particle_draw": "0x44a410", "_rain_draw": "0x44a470", "_float_text_draw": "0x44a520", "_thing_shaded_sprite_plot": "0x44a860", "_game_set_turtle_lighting_for_pos2": "0x44ac80", "_game_set_turtle_lighting_for_tile_pos": "0x44acb0", "_thing_sprite": "0x44ad10", "_thing_inside_update": "0x44ad30", "_thing_get_out": "0x44adb0", "_thing_get_in": "0x44ae10", "___func__.20581": "0x4d4654", "_game_sort_things": "0x44af10", "_scount": "0x7cb3ac", "_sprite_list": "0x7cb3c0", "_game_draw_things": "0x44b030", "___func__.20617": "0x4d4640", "_game_daylight_tint": "0x44b940", "_game_draw_touch_stick": "0x44b970", "_draw_touch_stick.part.19": "0x44bbe0", "_base_render": "0x44bc20", "_draw_touch_stick": "0x44c4b0", "_game_fade_clr": "0x44c4e0", "_game_fade": "0x44c500", "_game_segue_to_ex": "0x44c5f0", "_game_segue_to": "0x44c710", "_game_segue_to_mission": "0x44c730", "_game_segue_to_road": "0x44c750", "_game_wipe": "0x44c770", "_game_fade_draw": "0x44c790", "_game_poll_touchscreen_cmds": "0x44c940", "_game_poll_all_cmds": "0x44c9e0", "_game_unpickle_map_around": "0x44ca80", "_game_alert_room_ex": "0x44cbf0", "_game_link_get_roomid": "0x44d1f0", "_game_alert_room": "0x44d220", "_game_clear_all_pickles": "0x44d260", "_game_update_maps": "0x44d300", "_game_clear_buckets": "0x44d330", "_game_loot_stat_name": "0x44d400", "_init_.20925": "0x7caea0", "_names.20926": "0x7cad60", "_game_loot_stat_icon": "0x44d500", "_CSWTCH.654": "0x4d45bc", "_game_loot_name": "0x44d540", "_buf.20942": "0x7cad4c", "_foreach_active_thing_near_pos": "0x44d580", "_foreach_active_thing_near_self": "0x44d690", "_foreach_active_thing_around_pos": "0x44d6c0", "___func__.21019": "0x4d4620", "_foreach_active_thing_around_self": "0x44d840", "_game_zombies_inc": "0x44d880", "_zombie_count": "0x7cb314", "_game_zombie_count": "0x44d890", "_game_active_count": "0x44d8a0", "_active_count": "0x7cb318", "_is_same_pos_tile": "0x44d8b0", "_game_update_state": "0x44d970", "_val.21167": "0x7cad48", "_game_add_mission_timer": "0x44dec0", "_game_reset_mission_timer": "0x44df10", "_game_clear_timers": "0x44df20", "_game_update_mission_timers": "0x44df40", "_game_force_refresh": "0x44dfc0", "_force_refresh": "0x7cb30c", "_game_colour_swap": "0x44dfd0", "_game_pop_the_trunk": "0x44dff0", "_pop_trunk": "0x7cb308", "_game_pop_up_settings": "0x44e000", "_pop_settings": "0x7cb304", "_game_set_resume_pause": "0x44e010", "_resume_pause": "0x7cb310", "_game_set_global_echo": "0x44e020", "_game_textpad_add": "0x44e030", "_textptr": "0x4d0440", "_textpad": "0x86c520", "_game_particle_ex": "0x44e080", "_dummy.21442": "0x7cac60", "_game_particle_dot": "0x44e170", "_flame_base": "0x44e1f0", "_thing_ember_effect": "0x44e4a0", "_thing_flame_effect": "0x44e510", "_thing_lick_effect": "0x44e550", "_game_gas_smoke_xy": "0x44e580", "_game_gas_smoke_me": "0x44e6a0", "_game_particle_circle_ex": "0x44e6e0", "_game_particle_circle": "0x44e730", "_game_particle_line": "0x44e780", "_thing_is_line_clear_ex": "0x44e870", "_thing_diff_thing_edges_ex": "0x44ead0", "_thing_diff_thing_edges": "0x44ec40", "_thing_diff_thing_ex": "0x44ec70", "_thing_diff_thing": "0x44edd0", "_thing_splash_effect_ex": "0x44ee00", "_thing_splash_effect": "0x44f0b0", "_game_dust_me": "0x44f0e0", "_game_hit_spark": "0x44f2a0", "_game_thing_hit_spark": "0x44f470", "_game_alert_here": "0x44f4d0", "_game_particle": "0x44f6c0", "_thing_cancel_report": "0x44f6f0", "_float_text_ex": "0x44f720", "_game_float_text": "0x44f7d0", "_float_text": "0x44f810", "_thing_message": "0x44f820", "_thing_report_ex": "0x44f8c0", "_thing_report": "0x44f9a0", "_thing_dbg_report": "0x44f9d0", "_thing_say": "0x44f9e0", "_flipx": "0x44fab0", "_thing_stun": "0x44fad0", "_thing_vol": "0x44fb00", "_pos_vol": "0x44fb70", "_fly_update": "0x44fdd0", "_sound_dummy": "0x4502c0", "_dummy.21542": "0x7caba0", "_thing_sound_check": "0x4502e0", "_thing_sound_ruffle": "0x450350", "_thing_sound_ruffle_ex": "0x4503c0", "_thing_sound_noise": "0x450430", "_thing_sound_pip": "0x450490", "_thing_sound_pulse": "0x4504f0", "_thing_sound_thump_ex": "0x450550", "_thing_sound_thump": "0x4505c0", "_thing_sound_shred": "0x4505f0", "_burn_sound": "0x450650", "_last_.20508": "0x7caea4", "_thing_burn_effect": "0x450730", "_thing_sound_ringmod": "0x450a00", "_thing_sound_fm_sweep": "0x450a60", "_thing_sound_crunch": "0x450ad0", "_thing_effect": "0x450b20", "_thing_effect_ex": "0x450b80", "_game_label": "0x450be0", "_game_set_box": "0x450c20", "_game_upper_box": "0x450c80", "_game_full_box": "0x450cf0", "_game_lower_box": "0x450d30", "_game_screen_title_ex": "0x450d90", "_buf.21682": "0x7cab60", "_game_screen_title": "0x450e90", "_tile_to_pos": "0x450ec0", "_pos_to_tile": "0x450f00", "_quad_to_pos": "0x450f60", "_pos_to_quad": "0x450fb0", "_thing_set_activity_": "0x451010", "_game_pos_zombify": "0x451020", "_game_room_zombify_chance": "0x451240", "_game_title_render": "0x4512c0", "_game_mrand": "0x451310", "_game_frnd": "0x451330", "_game_rnd": "0x451360", "_game_onein": "0x451390", "_game_rnd5050": "0x4513b0", "_game_rndsign": "0x4513d0", "_game_debris_try_drop": "0x4513f0", "_game_shatter_thing": "0x4515c0", "_game_shatter_spriteid_3d": "0x451920", "_game_shatter_spriteid": "0x451c30", "_game_bits_from_spriteid_3d": "0x451cd0", "_game_bits_from_spriteid_ex": "0x451eb0", "_game_bits_from_spriteid": "0x451f70", "_game_bits_from_thing_ex": "0x451fe0", "_game_bits_from_thing": "0x452230", "_game_chunks_from_thing": "0x452290", "_game_bits_sprite_ex": "0x4522f0", "_game_bits_sprite": "0x452440", "_game_vehicle": "0x452490", "_game_vehicle_drivein": "0x4524a0", "_game_vehicle_driveout": "0x4524f0", "_game_thing_chara_script_event": "0x452580", "_game_thing_script_event_ex2": "0x4525f0", "_thing_new": "0x452710", "_thing_spit_spark.part.30": "0x452890", "_thing_spit_spark": "0x452a80", "_thing_free": "0x452aa0", "___func__.19619": "0x4d4720", "_thing_move": "0x452b90", "_thing_update_map_position": "0x452f80", "_thing_try_burn": "0x453910", "_try_spread_fire": "0x453a10", "_thing_handle_overlap_rect.part.32": "0x453ad0", "_thing_handle_overlap_rect": "0x454120", "_thing_handle_overlap": "0x454150", "_game_thing_script_event_ex": "0x454680", "_game_thing_script_event": "0x4546c0", "_game_wielded_weapon_script_event": "0x454700", "_game_map_script_event": "0x4547a0", "_game_location_script_event": "0x454850", "_game_switch_to_map": "0x4548f0", "_leader_thing_sync": "0x4549d0", "_leader_set_thing": "0x454a20", "_game_title_setup": "0x454a70", "_title_reset": "0x7cb300", "_game_follow_link": "0x454b20", "_game_transfer_chars_to_mission_things": "0x454d40", "___func__.20280": "0x4d4680", "_game_start_mission": "0x455340", "___func__.20349": "0x4d4608", "_enter_begin": "0x455580", "_game_thing_cyoa": "0x4555a0", "___func__.22021": "0x4d45f8", "_game_thing_action": "0x455660", "___func__.22029": "0x4d45e4", "_game_tile_cyoa": "0x455730", "_game_tile_event": "0x4557c0", "_game_stat_smiley_colour": "0x455880", "_game_stat_smiley_chr": "0x455bb0", "_game_stat_smiley_str": "0x455bf0", "_ptr.22068": "0x4d03ec", "_buf.22067": "0x7caa60", "_game_use_coloured_text": "0x455c60", "_turtlecontext": "0x7cb2a0", "_game_plot_stat_smiley": "0x455cc0", "_game_update_special_colours": "0x455dd0", "_clr_table": "0x7cb1e0", "_game_icon_clr_turtle": "0x456020", "_glypher": "0x456340", "_thing_spawn_fly_particle": "0x4564c0", "_game_update_things": "0x456640", "_do_charselect": "0x7cbd7c", "_game_simulate": "0x457490", "_game_title_update": "0x458050", "_game_thing_main_script_event": "0x4582b0", "___func__.22162": "0x4d45c4", "_thing_jump_to_human_room": "0x458370", "_word_reset": "0x4584a0", "_game_mode": "0x7cdda0", "_btn_start_new": "0x4596c0", "_word_applyword": "0x488830", "_word_locked": "0x458540", "_word_icon": "0x4a15c0", "_word_strdesc": "0x4888c0", "_btn_page": "0x4585d0", "_grid_mode": "0x4d0428", "_last_mode_clicked": "0x7cdd80", "_grid_start": "0x7cdd84", "_btn_picker": "0x4586b0", "_draw_mode_icon_flag.isra.2": "0x458780", "_btn_gamemode_desc": "0x4588b0", "_btn_gamemode_brief": "0x458a60", "_word_strmode": "0x458c00", "_gamemodes_init": "0x458c80", "_gamemode_is_locked": "0x458cb0", "_gamemode_applyword": "0x458cd0", "_gamemode_layout": "0x458d10", "_script_gamemode_config": "0x459190", "___FUNCTION__.18510": "0x4d49b8", "_mode_layout": "0x4592b0", "_char_layout": "0x4592c0", "_buddy_layout": "0x4596a0", "_leader_layout": "0x4596b0", "_btn_buddy_toggle": "0x459700", "_btn_random_pick_char": "0x4597c0", "_gamestart_layout": "0x459900", "_start_chars_created": "0x7d09a0", "_btn_image_load_char": "0x459a00", "_btn_char": "0x459a70", "_gamestart_refresh_layout": "0x459c50", "_gamestart_go": "0x459c60", "_update_cooldown_swing": "0x459c90", "_human_hit_check": "0x459d90", "_human_hit_check_extra": "0x459ef0", "_human_check_friends": "0x459f20", "_drop_carried": "0x459f60", "_swoosh_draw": "0x45a000", "_game_particle_draw_3d": "0x45a110", "_game_particle_update_3d": "0x45a140", "_human_handle_overlap": "0x45a230", "_loot_report_update": "0x45a240", "_loot_report": "0x7d0d0c", "_icon_buddy_colour": "0x45a280", "_callback_show_zombies": "0x45a300", "_zombie_particle_draw": "0x45a5c0", "_exit_draw": "0x45a5f0", "_junk_bit.isra.9": "0x45a6b0", "_kicked_update": "0x45a720", "_thing_show_icon": "0x45a8d0", "_check_step_on_stuff": "0x45a980", "_human_char_hair_colour.part.18": "0x45b0c0", "_human_add_fatigue.part.21": "0x45b140", "_human_target_aim_accuracy_ex.part.22": "0x45b1c0", "_human_buddy_id": "0x45b220", "_human_is_a_player": "0x45b260", "_human_is_a_buddy": "0x45b2a0", "_player_id_from_thing": "0x45b300", "_human_get_player_num": "0x45b370", "_human_say": "0x45b3a0", "_human_is_fatigued": "0x45b420", "_human_char_hair_colour": "0x45b440", "_human_char_skin_colour": "0x45b490", "_human_head_spr": "0x45b580", "_human_add_fatigue": "0x45b660", "_human_swap_attack": "0x45b690", "_swung_with": "0x45b6a0", "_human_do_open_anim": "0x45b6c0", "_human_target_aim_accuracy_ex": "0x45b740", "_human_target_melee_accuracy": "0x45b760", "_test_burn": "0x45b780", "_human_cmd_is_new": "0x45b7a0", "_human_cmd_is_released": "0x45b7c0", "_human_is_looting": "0x45b7e0", "_human_is_interaction_dist_ex": "0x45b800", "_human_is_interaction_dist": "0x45b980", "_human_get_cyoa_item": "0x45b9b0", "_human_is_shot_clear": "0x45ba30", "_junk_bits": "0x45ba70", "_human_global_init": "0x45bab0", "_human_carry_thing": "0x45bac0", "_human_effective_stat": "0x45bb10", "_human_weapon_cooldown_time": "0x45bb50", "_human_effective_fitness": "0x45bc30", "_human_effective_strength": "0x45bc50", "_human_nearest_pickupid": "0x45bc70", "_human_is_onscreen": "0x45bcb0", "_human_is_follower_offmap": "0x45bd50", "_human_buddies_used": "0x45bd90", "_human_buddy_set": "0x45bdb0", "_human_player_thing": "0x45bdf0", "_human_float_angst": "0x45be10", "_human_is_grappled": "0x45bea0", "_human_is_bleeding": "0x45bec0", "_human_solid_pos_check_clear": "0x45bee0", "_human_solid_pos_check_clear_func": "0x45c020", "_quad_check_func": "0x45c110", "_human_pathing_mode_here": "0x45c280", "_human_calc_path_map_for": "0x45c2b0", "_human_init": "0x45c410", "_human_set_characterid": "0x45c440", "_human_new": "0x45c480", "_human_free": "0x45c4f0", "_human_char": "0x45c500", "_human_loot_count": "0x45c530", "_human_use_loot_amount": "0x45c560", "_human_use_a_loot": "0x45c5d0", "_human_breath": "0x45c600", "_human_weapon_stack": "0x45c6e0", "___func__.19477": "0x4d4ba8", "_heart_particle_draw": "0x45c750", "_human_script_anim": "0x45c7b0", "_human_health": "0x45c800", "_human_skin_colour": "0x45c820", "_human_draw_head_ex2": "0x45c9a0", "_human_char_draw_head": "0x45cff0", "___func__.19416": "0x4d4bc8", "_human_is_dead.part.28": "0x45d0d0", "_human_is_dead": "0x45d0f0", "_human_players_active": "0x45d120", "_human_leader_report": "0x45d170", "_cycle_set_buddy": "0x45d1f0", "_cycle_buddy": "0x45d350", "_human_buddy_join_logic": "0x45d440", "_human_grapple": "0x45d7e0", "_human_add_health": "0x45d890", "_human_report_health": "0x45d920", "_human_hit_ex": "0x45d9b0", "_human_hit": "0x45dab0", "_human_hit_check_apply_ex": "0x45dae0", "_human_hit_check_apply": "0x45e190", "_human_is_targeting": "0x45e1b0", "_human_is_recruited": "0x45e210", "_human_add_loot_ex": "0x45e230", "_last_.20110": "0x7d0d00", "_last_.20111": "0x7d0cfc", "_human_add_loot": "0x45e4e0", "_human_grab_loot": "0x45e510", "_try_get_loot.part.33": "0x45e5a0", "_human_get_empty_slot": "0x45e610", "_human_has_weapon_ex": "0x45e6a0", "_human_has_weapon": "0x45e740", "_human_add_use_flag_ex": "0x45e770", "_human_add_use_flag": "0x45e800", "_check_for_weapon": "0x45e830", "___func__.20275": "0x4d4b94", "_human_input": "0x45ea80", "_check_for_use_tile": "0x45f080", "_human_is_use_info": "0x45f530", "_human_is_thing_pickupable.part.35": "0x45f560", "_human_check_for_carry_item": "0x45f6b0", "_human_is_use_filtered": "0x45f870", "_human_do_grappled": "0x45f8a0", "_human_anim_walk": "0x45f920", "_last_.20631": "0x7d0cf8", "_human_weapon": "0x45fe70", "_human_gun_ammo_type": "0x45fec0", "_human_ammo_count": "0x45ff00", "_human_fuel_type": "0x45ff60", "_human_fuel_count": "0x45ffa0", "_human_is_using_fuelled": "0x45ffd0", "_human_report_fuel_ex": "0x460000", "_human_report_fuel": "0x460110", "_human_use_an_ammo": "0x460130", "_human_raw_cooldown_time": "0x460220", "_human_do_hit_check_ex": "0x460260", "_human_anim_weapon": "0x460690", "_human_drop_shell": "0x4606e0", "_human_is_using_ranged": "0x460890", "_human_cooldown_time": "0x460900", "_human_draw_human_ex": "0x4609e0", "_human_draw": "0x461a10", "___func__.19473": "0x4d4bbc", "_human_report_ammo_ex": "0x461b90", "_human_report_ammo": "0x461d20", "_human_try_flip": "0x461d40", "_human_aiming": "0x461e30", "_human_face_towards_thing_ex": "0x461f30", "_human_face_towards_thing": "0x461fd0", "_handle_carry": "0x462000", "_human_face_towards_pos": "0x4625a0", "_human_jump_to_leader_room": "0x462600", "_human_target_ranged_accuracy": "0x4626c0", "_human_target_accuracy_radius": "0x4627a0", "_human_show_reticle": "0x462870", "_human_find_targets": "0x462a30", "_human_targeting": "0x462d20", "_find_stuff_callback": "0x462d40", "_human_wielded_weapon": "0x463250", "_human_switch_to_weapon_ex": "0x463280", "_human_switch_to_weapon": "0x463440", "_human_next_weapon": "0x463460", "_human_next_useful_weapon": "0x463500", "_human_alt_wielded_weapon": "0x463510", "_human_weapon_info": "0x463540", "_human_wielded_weapon_info": "0x463560", "_human_set_weapon": "0x463580", "_human_drop_single_weapon": "0x4635c0", "_human_unstack_weapon_": "0x463710", "_do_throw": "0x4637e0", "_human_do_throw_anim": "0x463b40", "_human_do_smash_anim": "0x463d00", "_human_drop_stacked_weapon": "0x463f10", "_take_weapon": "0x464080", "_handle_use_commands": "0x4643b0", "_human_break_weapon": "0x4647a0", "_melee_try_break": "0x464950", "_human_do_melee_hit_check": "0x4649a0", "_human_do_swing_anim": "0x464c00", "_human_do_anim.part.47": "0x4656e0", "_last_.19829": "0x7d0d08", "_last_.19830": "0x7d0d04", "_human_do_anim": "0x465c00", "_human_drop_all_weapons": "0x465c20", "_human_update": "0x465ce0", "_last_.20622": "0x7d0cf4", "_retrigger_delay.20376": "0x7d0cf0", "_human_action": "0x468170", "_human_use_door": "0x4683e0", "_guns_carried": "0x4684b0", "_is_within_allowed_attack_area": "0x468550", "_avoid_point": "0x468610", "_back_off_from_thing": "0x4688e0", "_melee_weapon_base_score.isra.5": "0x468990", "_chara_weapon_pickup_score": "0x468a60", "_threat_score.isra.11": "0x468b50", "_follow_dist": "0x468cb0", "_no_ai_use_slot_weapon": "0x468d90", "_request_swap": "0x468de0", "_pathfind.part.21": "0x468e30", "_try_open_door": "0x4693f0", "_follower_actions": "0x4694a0", "_find_doors.isra.24": "0x4695f0", "_need_space.isra.27": "0x469660", "_human_my_leader": "0x469710", "_chara_melee_slot_score": "0x469740", "_best_melee_weapon_carried_ex": "0x4697b0", "_check_pickup_against_worst_melee": "0x469940", "_wander_actions": "0x4699c0", "_follow_leader": "0x46a400", "_try_swap_worst_melee": "0x46b040", "_human_ai": "0x46b0f0", "_gnomebits_update": "0x46cd30", "_gnome_generic_explosion": "0x46cd60", "_countdown": "0x875368", "_sky_colour": "0x7d0d1c", "_horizon": "0x7d0d10", "_rocketcat": "0x7d0d18", "_gnomey": "0x7d0d14", "_item_new": "0x46deb0", "_item_name": "0x46dee0", "_CSWTCH.31": "0x4d4f5c", "_item_set_open": "0x46df00", "_item_damage_ex": "0x46df50", "_item_damage": "0x46e150", "_item_update": "0x46e1a0", "_item_draw_loot_sparkle": "0x46e8c0", "_item_draw": "0x46eae0", "_item_default_action": "0x46efa0", "_item_action": "0x46f650", "_tint_trigger": "0x46fcb0", "_tint_retrigger": "0x46fd50", "_tint_set_near": "0x46fd70", "_tint_set_far": "0x46fdf0", "_tint_set_near_tile": "0x46fe70", "_tint_set_far_tile": "0x46feb0", "_tint_set_near_thing": "0x46fef0", "_tint_set_far_thing": "0x46ff30", "_tint_default": "0x46ff70", "_tint_update": "0x470080", "_timelight_select": "0x4704d0", "_tl": "0x7d0d60", "_tl_i": "0x7d0d48", "_tl_sel": "0x7d0d44", "_timelight_sel_near_set": "0x4705b0", "_timelight_sel_far_set": "0x470600", "_timelight_sel_near_thing_set": "0x470650", "_timelight_sel_far_thing_set": "0x470680", "_timelight_select_ex": "0x4706b0", "_timelight_dup_last": "0x470760", "_timelight_near_bright": "0x470870", "_timelight_clear": "0x470880", "_timelight_default": "0x4708b0", "_timelight_update": "0x470e00", "_location_tags": "0x4712f0", "_locationdef_info_": "0x7d1020", "_pool_tags": "0x471310", "_locationdef_count": "0x471340", "_curloc": "0x7d1004", "_locationdef_selected": "0x471350", "_loc_def_selected": "0x7d1000", "_locationdef_add": "0x471360", "_locationdef_set_tags": "0x471390", "_locationdef_set_entry_tags": "0x4713d0", "_locationdef_set_script": "0x471410", "_locationdef_set_pre_script": "0x471480", "_locationdef_set_post_script": "0x4714f0", "_locationdef_set_room_script": "0x471560", "_locationdef_set_room_script2": "0x4715f0", "_locationdef_add_roomdef_choice": "0x471680", "_locationdef_set_roomdef_weight": "0x4716f0", "_locationdef_set_roomdef_count": "0x471730", "_locationdef_add_roomdef_mode": "0x471770", "_locationdef_init": "0x4717a0", "_locationdef_get": "0x4717e0", "_locationdef_select": "0x471810", "_locationdef_random_pick_with_tags": "0x471850", "_locationdef_id": "0x4718d0", "_locationdef_here": "0x471900", "_location_pick_room_for_locationid": "0x471940", "_location_pick_room_here": "0x471c00", "_location_peek_room_here": "0x471c40", "_location_add_empty": "0x471c80", "_location_configure": "0x471d00", "_location_add": "0x471de0", "_location_configure_for_locdef_id": "0x471e70", "_location_add_for_locdef_id": "0x471f40", "_do_select_event": "0x471fe0", "_do_info_event": "0x472010", "_word_get_state_index": "0x472050", "_state_index": "0x86cb90", "_load_palette": "0x472070", "_main_tabscreen_blank_tab_layout": "0x472100", "_title_logo_layout": "0x472130", "_load_text": "0x472200", "_edit_field_callback": "0x472260", "_word_set_state_index": "0x472290", "_main_edit_convert_char": "0x4722b0", "_is_screen_size_changed": "0x4722e0", "_last_w": "0x86cb0c", "_last_h": "0x86cb08", "_adjust_layout": "0x472330", "_adjust_mod": "0x86cb04", "_zombhead": "0x4727a0", "_draw_character_head": "0x4b67d0", "_main_do_click.part.10": "0x472900", "_keyctrl.part.13": "0x472970", "_main_do_esc_event.part.17": "0x472980", "_main_do_quit_event.part.18": "0x4729b0", "_main_edit_field.part.19": "0x4729e0", "_load_pet_gfx.constprop.31": "0x472b10", "_load_gfx": "0x472bb0", "_main_state_reset_stack": "0x474520", "_main_state_delayed_func": "0x474530", "_delayed_func": "0x86cb2c", "_main_state_switch": "0x474540", "_no_esc": "0x86cb28", "___func__.19528": "0x4d5cc8", "_reenter_select": "0x4745c0", "_main_state_stack_bottom": "0x474600", "_state_stack": "0x86cb40", "_main_state_render_stack_bottom": "0x474610", "_last_rendered.19535": "0x86c504", "_buttons_set_draw_": "0x4d0448", "_main_state_render_stack": "0x474670", "_last_rendered.19541": "0x86c500", "_main_state_push": "0x474710", "___func__.19550": "0x4d5cb8", "_main_state_pop": "0x4747b0", "_plot_text_set_shadow": "0x474800", "_shadow": "0x4d048c", "_plot_text_set_glow": "0x474830", "_textglow_": "0x86cb24", "_plot_text_ex": "0x474840", "_plot_text": "0x474940", "_plot_text_noshadow": "0x474970", "_main_update_audio_settings": "0x4749a0", "_main_set_window_size": "0x474a60", "_last_window_w": "0x86cb14", "_last_window_h": "0x86cb10", "_main_recreate_window": "0x474ac0", "_main_next_window_size": "0x474b30", "_main_set_fullscreen": "0x474be0", "_main_textf": "0x474c60", "_main_stextf": "0x474ca0", "_destbuf.19740": "0x86c100", "_save_settings": "0x474ce0", "_main_register_hotkey_script": "0x474d80", "_main_do_esc_event": "0x474da0", "_main_do_quit_event": "0x474dc0", "_main_pause_dingle_ex": "0x474de0", "_main_pause_dingle": "0x474e70", "_main_ui_set_click": "0x474e90", "_main_ui_cmd": "0x474ec0", "_main_do_gogo": "0x474ed0", "_gogo_": "0x86cb1c", "_main_do_console_open": "0x474ee0", "_main_do_console_close": "0x474ef0", "_main_do_start_new": "0x474f00", "_main_do_gamestart_layout": "0x474f50", "_main_check_start_button": "0x474f60", "_external_start": "0x86caf4", "_main_check_anycmd": "0x474fa0", "_main_check_back_button": "0x475040", "_main_set_default_start_button": "0x475050", "_default_start_button": "0x86caf0", "_main_set_default_back_button": "0x475060", "_default_back_button": "0x86caec", "_main_default_back_button": "0x475070", "_main_get_default_back_button": "0x475080", "_main_set_buttons_box_from_button": "0x475090", "_main_do_sys_reset": "0x475120", "_sys_reset_": "0x86cae8", "_main_post_textfill_event": "0x475130", "_defer_warn_bleep": "0x475190", "_defer_beep": "0x86cae0", "_defer_err_bleep": "0x4751a0", "_defer_err_buzz": "0x4751b0", "_main_set_last_popup_mode": "0x4751c0", "_popup_cur": "0x86ca24", "_popup": "0x86ca40", "_main_textfile_save": "0x4751e0", "_main_scroll_swap": "0x475230", "_main_rumble_gui": "0x475270", "_gui_rumble_decay": "0x86ca1c", "_main_state_time": "0x4752c0", "_main_do_click": "0x4752d0", "_main_set_fade": "0x475300", "_fade_time": "0x86ca0c", "_fade_counter": "0x86ca10", "_main_turtle_fade": "0x475340", "_main_to_game_mode_selection": "0x475480", "_main_to_char_picker": "0x475490", "_main_new_to_char_maker": "0x4754a0", "_main_select_chars": "0x4754c0", "_main_select_custom_chars": "0x4754d0", "_main_select_game_chars": "0x4754e0", "_main_set_global_echo": "0x4754f0", "_main_buttons_enable_draw": "0x475520", "_main_buttons_draw": "0x475530", "_popup_out": "0x86ca20", "_popup_in": "0x86ca28", "_main_rnd_name": "0x4757b0", "_mnames": "0x86ca08", "_fnames": "0x86ca04", "_buf.20161": "0x86c000", "_main_default_touch_settings": "0x475930", "_main_draw_progress": "0x475990", "_main_reset_sound": "0x4759d0", "_session_reboot": "0x475a20", "_main_mfi_controllers_connected": "0x475ab0", "_joy_connected": "0x86ca00", "_main_should_show_cursor": "0x475ac0", "_app_run": "0x475ae0", "_app_load_url": "0x475b30", "_app_state_info": "0x475b40", "_app_state_save": "0x475dc0", "_app_state_exit": "0x475dd0", "_uppercase": "0x475e20", "_buf.20280": "0x86bf00", "_main_build_stamp": "0x475e70", "_timestat": "0x475f30", "_buf.20296": "0x86bea0", "_wrap_text_ex": "0x476080", "_buffer.20313": "0x86baa0", "_main_calc_image_wrap_lines": "0x4762c0", "_wrap_text_lines": "0x476510", "_wrap_text": "0x476570", "_plot_textf": "0x4765a0", "_plot_text_wrapped_ex": "0x476600", "_text_wrapped_callback": "0x4766a0", "_main_buttons_box": "0x476710", "_main_button_nav": "0x4767a0", "_main_no_esc": "0x4768d0", "_main_is_no_esc": "0x4768e0", "_main_buttons_start": "0x4768f0", "_gui_zoom": "0x86ca14", "__ui_cmd": "0x86caf8", "_quit_enter": "0x476ae0", "_counter": "0x86cb20", "_layout_for_news": "0x476bb0", "_layout_orig": "0x476f00", "_reenter": "0x477170", "_hash1way": "0x4771a0", "_counter.20530": "0x86ba9c", "_hash1way_reset": "0x477270", "_time_scale": "0x477280", "_current_hour": "0x4772d0", "_current_min": "0x477310", "_current_sec": "0x477350", "_current_week_day": "0x477390", "_current_month": "0x4773d0", "_current_month_day": "0x477410", "_current_year_day": "0x477450", "_current_year": "0x477490", "_current_is_dst": "0x4774d0", "_current_ascii_time": "0x477510", "_lunar_phase": "0x477550", "_current_lunar_phase": "0x477600", "_main_rumble_camera": "0x477630", "_main_update_camera": "0x477650", "_main_is_paused": "0x4777f0", "_paused": "0x86c9fc", "_main_pause": "0x477820", "_keyup": "0x477830", "_keydown": "0x477850", "_keyshift": "0x477860", "_keyctrl": "0x477880", "_main_set_fuzz_factor": "0x4778a0", "_fuzz_factor": "0x4d0444", "_main_do_8mm": "0x4778d0", "_toggle": "0x477c60", "_cycle": "0x477ca0", "_bleep": "0x477cf0", "_blip": "0x477d20", "_err_bleep": "0x477d50", "_last_.20754": "0x86ba94", "_err_buzz": "0x477dd0", "_last_.20759": "0x86ba90", "_warn_bleep": "0x477e40", "_last_.20764": "0x86ba8c", "_main_last_assert_msg": "0x477ec0", "_main_register_event_handle": "0x477ee0", "_main_register_stack_handle": "0x477ef0", "_main_register_error_handle": "0x477f00", "_main_trigger_event_ex": "0x477f10", "_main_trigger_event": "0x477f50", "_main_set_screen_title": "0x477f90", "_main_edit_field": "0x478070", "_main_edit_cursor": "0x4780a0", "_main_button_title": "0x478130", "_main_button_label": "0x478190", "_main_common_nav_bar": "0x4781d0", "_main_bottom_box": "0x478200", "_main_options_set_return_override": "0x478250", "_main_common_page_set_return_override": "0x478260", "_main_common_page_setup": "0x478270", "_main_controls_setup_default_mappings": "0x4782d0", "_main_tabscreen_is_tab_switch": "0x4787e0", "_tab_was_switched": "0x86c9f0", "_main_tabscreen_store_last_tab": "0x4787f0", "_tab_last": "0x86c9e0", "_main_tabscreen_tabbox_shrink": "0x478800", "_main_tabscreen_reset": "0x478870", "_tabs": "0x86c920", "_tab_index": "0x86c9f8", "_tab_start_btnfunc": "0x86c9ec", "_tab_exit_btnfunc": "0x86c9e8", "_main_tabscreen_start": "0x4788d0", "_tab_selected": "0x86c9f4", "_tab_left_btn": "0x86c9e4", "_main_strncpy": "0x4788f0", "_main_tabscreen_add_tab_ex": "0x478920", "_main_tabscreen_add_tab": "0x478980", "_main_tabscreen_set_startfunc": "0x4789e0", "_main_tabscreen_set_exitfunc": "0x4789f0", "_main_tabscreen_layout_ex": "0x478a00", "_main_tabscreen_refresh": "0x478c30", "_main_tabscreen_select_tab": "0x478cd0", "_main_tabscreen_layout": "0x478d20", "_main_is_cursor_hover": "0x478d40", "_main_btn_default": "0x478e10", "_gui_rumble_reset": "0x86ca18", "_main_textpad_reset": "0x4791d0", "_main_textpad": "0x4791f0", "_main_textptr": "0x479200", "_main_textpad_alloc": "0x479210", "_main_textpad_append": "0x479240", "_main_update_with_buttons": "0x479290", "_gogo_lite_": "0x86cb18", "_init.19872": "0x86c0e0", "_orig.19871": "0x86c060", "_grainseed": "0x86cae4", "_queued_state": "0x86cb30", "_state_count.20008": "0x86c0f0", "_main_state_update": "0x47a040", "_quit_update": "0x47a050", "_steam_connected": "0x86cb94", "_main_bite_rumble": "0x47a1e0", "_iconify": "0x47a210", "_imagify": "0x47a240", "_labelify": "0x47a290", "_lowercase": "0x47a2b0", "_keyrepeat_ex": "0x47a2e0", "_heldid.21049": "0x86ba88", "_delay.21048": "0x86ba84", "_keyrepeat": "0x47a360", "_get_keyrepeat_event_ex": "0x47a380", "_delay_.21056": "0x86ba78", "_heldid_.21057": "0x86ba80", "_heldch_.21058": "0x86ba7c", "_get_key_event": "0x47a430", "_get_key": "0x47a450", "_text_w": "0x47a470", "_main_sprite_batch_plot": "0x47a4e0", "___func__.21082": "0x4d5ca0", "_main_debug_atlas_render.part.24": "0x47a590", "_main_debug_atlas_render": "0x47a6f0", "_main_btn_frame_draw_ex": "0x47a710", "_main_btn_framed": "0x47aab0", "_main_btn_image_wrap": "0x47ab10", "_main_btn_image_wrap_noframe": "0x47afa0", "_main_btn_image_pop_state": "0x47aff0", "_main_do_esc_event_btn": "0x47b020", "_main_do_quit_event_btn": "0x47b060", "_main_btn_wrap": "0x47b0c0", "_main_btn_toggle": "0x47b2e0", "_main_btn_checkmark": "0x47b350", "_main_btn_radio": "0x47b400", "_main_btn_push_popup_state": "0x47b4e0", "_main_btn_push_state": "0x47b530", "_main_btn_image_push_state": "0x47b580", "_main_btn_pop_state": "0x47b5e0", "_main_btn_range": "0x47b610", "_main_btn_data_func": "0x47b720", "_main_btn_edit_focus": "0x47b770", "_btn_tab": "0x47b9c0", "_main_btn_slider": "0x47ba60", "_main_btn_icon": "0x47be10", "_main_btn_icon_data_func": "0x47be60", "_main_draw_filmgrain_fx": "0x47be90", "_last_.20727": "0x86ba98", "_main_draw_icon": "0x47c120", "_main_sprite_batch_plot_centered": "0x47c220", "___func__.21088": "0x4d5c80", "_zombhead_draw": "0x47c2d0", "_main_sprite_batches_draw_ex": "0x47c310", "_main_sprite_batches_draw": "0x47c590", "_main_draw_clear": "0x47c6b0", "_main_get_str_pixelw_limit": "0x47c6d0", "_main_do_popup": "0x47c760", "_load_settings": "0x47c830", "_app_state_init": "0x47caa0", "_main_edit_field_update_editing": "0x47cdb0", "_main_do_str_pixelw_limit": "0x47cf10", "_main_particles_update": "0x47cf40", "_script_main": "0x47cf50", "_main_update_joy_base": "0x47cfa0", "_joy_id": "0x47cff0", "_SDL_main": "0x47d040", "_map_select": "0x47d0a0", "_curmapid": "0x86cba4", "_layer_": "0x86cbc0", "_curmap": "0x4d04b0", "_map_selected": "0x47d0d0", "_map_exists": "0x47d0e0", "_map_clear": "0x47d100", "_map_init": "0x47d140", "_init_.18935": "0x86cba0", "_map_exit": "0x47d210", "_map_coord_tile_snap": "0x47d250", "_map_snap_x": "0x47d2a0", "_map_snap_y": "0x47d2f0", "_map_tiles_w": "0x47d340", "_map_tiles_h": "0x47d350", "_map_pixels_w": "0x47d360", "_map_pixels_h": "0x47d370", "_tile_w": "0x47d380", "_tile_h": "0x47d390", "_map_set_tile_base": "0x47d3a0", "_map_set_tile_draw_size": "0x47d3d0", "_map_clear_to": "0x47d410", "_map_set_view": "0x47d4d0", "_map_tile": "0x47d4f0", "_map_id_tile": "0x47d540", "_map_set_tile": "0x47d5f0", "_map_id_set_tile": "0x47d660", "_map_coord_tile": "0x47d6f0", "_map_get_dynamic_light_level_ex": "0x47d7e0", "_map_bresenham": "0x47d930", "_map_set_draw_mode": "0x47d940", "_map_reset_dynamic_light": "0x47d950", "_map_add_dynamic_light_ex": "0x47d9e0", "_map_add_dynamic_light": "0x47dd40", "_map_add_static_light": "0x47dd90", "_map_get_dynamic_light_level": "0x47dde0", "_map_get_static_light_level": "0x47de10", "_map_get_floating_light_level": "0x47de40", "_map_do_tile_lighting_ex": "0x47dec0", "_map_do_tile_lighting": "0x47e880", "_map_set_tile_row_callback": "0x47e8d0", "_map_draw": "0x47e8e0", "_pick_list_int": "0x47f630", "_get_edge_shift_tile_pos": "0x47f680", "_delete_here": "0x47fbf0", "_group_tiling": "0x47fc20", "_door_sound.isra.1": "0x47fd50", "_mapgen_build_room.part.4": "0x47ff20", "_mapgen_update_group_tiling_ex": "0x47ffe0", "_mapgen_update_group_tiling": "0x480040", "_mapgen_do_box_ex": "0x480070", "_mapgen_do_box": "0x480170", "_mapgen_do_empty_box": "0x4801d0", "_mapgen_init": "0x4802f0", "_mapgen_set_tile": "0x480310", "_mapgen_put_box_ex": "0x4803a0", "_mapgen_put_box": "0x4804b0", "_mapgen_location": "0x480500", "_mapgen_location_here": "0x480520", "_is_valid_door_location": "0x480570", "_mapgen_room_locid": "0x4806c0", "_mapgen_gen_theme": "0x4806e0", "_mapgen_room_w": "0x480740", "_mapgen_room_h": "0x480770", "_mapgen_room": "0x4807a0", "_mapgen_location_id": "0x4807d0", "_mapgen_edge_tile_shift_value": "0x480800", "_mapgen_add_empty_room": "0x480840", "_mapgen_is_door": "0x4808d0", "_mapgen_door_is_open": "0x4808f0", "_mapgen_pos_is_door": "0x480900", "_mapgen_rooms_available_here": "0x480940", "_mapgen_location_unopened_doors": "0x4809f0", "_mapgen_build_room": "0x480a60", "_scan_for_nearby_door": "0x480a90", "_random_scan_for_door": "0x480ca0", "_mapgen_adjacent_door_edge": "0x481150", "_mapgen_revert_door_here": "0x4811d0", "_mapgen_place_door_here": "0x481260", "_mapgen_place_room_door_link": "0x481350", "_scan_and_place_room_door_link": "0x4815b0", "_mapgen_add_random_doors_here_ex": "0x481890", "_mapgen_add_random_doors_here": "0x481a20", "_build_room_and_link_door": "0x481a50", "_mapgen_complete_door_link": "0x482310", "_mapgen_close_door": "0x482440", "_mapgen_get_if_closed_door": "0x4826c0", "_mapgen_get_if_door": "0x482700", "_mapgen_get_if_linked_door": "0x482730", "_mapgen_get_edge_map": "0x482780", "_mapgen_last_build_size": "0x4827e0", "_last_build_w": "0x86ffac", "_last_build_h": "0x86ffa8", "_mapgen_last_build_door_xy": "0x482810", "_last_door_x": "0x86ffa4", "_last_door_y": "0x86ffa0", "_location_config_entry_link": "0x482840", "_mapgen_plot_cabin_ex": "0x4828f0", "_mapgen_plot_cabin": "0x482cc0", "_mapgen_plot_bunker": "0x482cf0", "_mapgen_plot_house1": "0x482d20", "_mapgen_plot_house2": "0x483290", "_mapgen_plot_house3": "0x4838f0", "_mapgen_plot_yallmart": "0x483e20", "_mapgen_building_start": "0x4840c0", "_mapgen_plot_building": "0x484110", "_mapgen_add_gasbar": "0x4849b0", "_plot_edged_lot": "0x484a10", "_default_layer": "0x86ffb0", "_max_layer": "0x4d04b4", "_plot_block_lot": "0x484da0", "_plot_sidewalk_lot": "0x484eb0", "_put_region_junk": "0x484ec0", "_plot_lot": "0x484ff0", "_mapgen_darken_edges_ex": "0x485160", "_mapgen_darken_edges": "0x4852c0", "_mapgen_set_max_layer": "0x4852e0", "_mapgen_set_no_replace": "0x485300", "_mapgen_set_default_layer": "0x485310", "_plot_edged_grasslot": "0x485330", "_mapgen_place_base_lot": "0x4853b0", "_mapgen_place_base_lot_sidewalk": "0x485400", "_mapgen_place_hollow_lot": "0x485450", "_mapgen_place_edged_box": "0x4854a0", "_mapgen_place_empty_lot": "0x485500", "_mapgen_empty_region_gen": "0x485550", "_mapgen_scatter_junk": "0x485660", "_mapgen_region_gen": "0x4856b0", "_main_music_disable": "0x485920", "_disabled": "0x8701c0", "_main_music_current": "0x485930", "_cur_music": "0x8703e0", "_main_music_last_known": "0x485940", "_last_known": "0x8702e0", "_main_music_set_volume": "0x485950", "_global_vol": "0x4d04b8", "_main_music_load": "0x4859c0", "_filename.15342": "0x86ffc0", "_switch_music": "0x8701e0", "_music_fade_ticks": "0x8701c8", "_main_music_switch": "0x485ad0", "_main_music_set_global_volume": "0x485b10", "_main_music_switch_fade": "0x485b50", "_music_fade_counter": "0x8701c4", "_main_music_update": "0x485ba0", "_script_do_handle_btn": "0x485c10", "_word_set_newsbox_disable": "0x485c50", "_word_set_newsbox_ticker_dur": "0x485c70", "_word_set_news_enable": "0x485c90", "_word_set_news_btn_disable": "0x485cb0", "_word_set_news_btn_text": "0x485cf0", "_word_set_news_bigbox_text": "0x485d50", "_word_set_news_title": "0x485d80", "_word_set_news_btn_handler": "0x485db0", "_word_set_newsbox_ticker_handler": "0x485df0", "_word_newsbox_load_image": "0x485e10", "_loader": "0x8704e0", "_word_get_newsbox_disable": "0x485e90", "_word_get_newsbox_ticker_dur": "0x485eb0", "_word_get_news_enable": "0x485ed0", "_word_get_newsbox_ticker_handler": "0x485ef0", "_word_get_news_bigbox_text": "0x485f30", "_word_get_news_title": "0x485f50", "_image_wrap_bg_btn": "0x485f70", "_newsbox_init": "0x4860a0", "_newsbox_layout": "0x4860e0", "_newsbox_exit": "0x486240", "_newsbox_script_register": "0x486260", "_btn_delete": "0x486470", "_draw_nodes": "0x486500", "_check_for_node.constprop.0": "0x486780", "_node_editor_layout": "0x486820", "_node_editor_render": "0x486940", "_node_editor_update": "0x486b30", "_node_editor_init": "0x4871e0", "_btn_settings_checkmark": "0x487210", "_btn_change_size": "0x487220", "_btn_set_display_mode": "0x487250", "_btn_audio_slider": "0x487290", "_btn_music_slider": "0x4872e0", "_btn_slider_check": "0x487340", "_btn_music_slider_check": "0x4873d0", "_btn_sound_slider": "0x487410", "_last_.18462": "0x8704f4", "_btn_settings_vsync": "0x487510", "_layout.constprop.1": "0x487560", "_options_layout": "0x487bf0", "_minify_surround4": "0x487c00", "_check_func": "0x870504", "_minify_surround4_quad": "0x487d40", "_check_func_quad": "0x870500", "_path_set_check_func": "0x487ef0", "_path_set_quad_check_func": "0x487f00", "_path_reset_goal_map": "0x487f10", "_path_set_goal_tiles": "0x487f80", "_path_set_goal_pos": "0x488000", "_path_set_weight_quad": "0x488030", "_path_get_weight_quad": "0x488080", "_path_pick_lowest_dir_8way": "0x4880d0", "_path_pick_lowest_dir_8way_quad": "0x4881e0", "_path_pick_lowest_dir_8way2": "0x488370", "_path_pick_lowest_dir_4way": "0x488450", "_path_calc_goal_map": "0x488460", "_flip.18487": "0x8704fc", "_path_calc_goal_map_quad": "0x488590", "_flip.18511": "0x8704f8", "_word_perks_init": "0x4887b0", "_perks": "0x870540", "_curperk": "0x870528", "_perks_selected": "0x870524", "_perk_pick_callback": "0x870520", "_word_desc_get": "0x488800", "_word_lock": "0x488860", "_word_lvl": "0x488890", "_do_perk_desc": "0x488b90", "_perkpick": "0x488cb0", "_btn_perk_page": "0x488ce0", "_word_strtrait": "0x488d60", "_word_strperk": "0x488e20", "_btn_perk": "0x488ee0", "_perkntrait_select": "0x4891c0", "_perkntrait_find": "0x4891d0", "_perks_init": "0x489230", "_script_perk_config": "0x489280", "___FUNCTION__.18586": "0x4d62d4", "_perk_info": "0x489400", "_trait_info": "0x489440", "_perkntrait_set_callback": "0x489480", "_perk_count": "0x489490", "_trait_count": "0x4894a0", "_pet_weapon_draw.constprop.1": "0x4894b0", "_pet_bank_type_count": "0x489970", "_pet_char_draw_head": "0x4899a0", "_pet_draw": "0x489a20", "_pet_logic": "0x48a1b0", "_pet_walk": "0x48a5b0", "_last_.18911": "0x875360", "_layout_func": "0x875364", "_main_push_popup_state": "0x48abe0", "_popup_state": "0x4d04ec", "___func__.18557": "0x4d63b0", "_premission_countdown": "0x48ad70", "_set_tags_field.isra.0": "0x48ae40", "_regiondef_id": "0x48aec0", "_regiondef_init": "0x48aed0", "_regiondef_start": "0x48af20", "_regiondef_set_tags": "0x48af50", "_regiondef_set_script": "0x48af60", "_regiondef_set_pre_script": "0x48af70", "_regiondef_set_post_script": "0x48af80", "_regiondef_set_loc_script": "0x48af90", "_regiondef_set_loc_script2": "0x48afb0", "_regiondef_start_locdef_choice": "0x48afd0", "_regiondef_set_locdef_weight": "0x48b010", "_regiondef_set_locdef_count": "0x48b040", "_region_pick_location": "0x48b070", "_regiondef_here": "0x48b170", "_region_configure": "0x48b180", "_del": "0x48b210", "_wibble": "0x48b270", "_btn_reset": "0x48b2d0", "_listening_": "0x87537c", "_listentime": "0x875378", "_btn_joy_select": "0x48b370", "_selected_player": "0x875374", "_keymap": "0x48b540", "_last_keyid": "0x875370", "_enter1": "0x48b9e0", "_enter2": "0x48b9f0", "_enter3": "0x48ba00", "_enter4": "0x48ba10", "_btn_keymap": "0x48ba20", "_last_.18419": "0x87536c", "_rgba_loader_init": "0x48c160", "_rgba_loader_exit": "0x48c280", "_rgba_loader_draw_current": "0x48c2d0", "_rgba_loader_upload_changed": "0x48c3d0", "_rgba_loader_fetch_image": "0x48c490", "_plot_default": "0x48c560", "_room_tags_with_edge": "0x48c570", "_roomdef_info_": "0x876980", "_plot_floor": "0x48c5c0", "_plot_spawnpoint": "0x48c790", "_plot_wallside": "0x48c7a0", "_wall_remap": "0x4d66a0", "_plot_shelf": "0x48c9e0", "_shelfbits.18658": "0x4d6620", "_plot_walltop": "0x48cae0", "_plot_stairs": "0x48cbd0", "_room_apply_wall_theme_here": "0x48cc70", "_room_apply_floor_theme_here": "0x48cda0", "_roomdef_gen_theme": "0x48ce60", "_roomdef_pick_door_theme": "0x48cf10", "_roomdef_id": "0x48cf40", "_roomdef_plot_from_grid_ex": "0x48cf70", "_legend_default_count": "0x875384", "_legend_default": "0x875388", "_roomdef_plot_from_grid": "0x48d450", "_roomdef_plot_box": "0x48d490", "_roomdef_empty_room": "0x48d720", "_roomdef_plot": "0x48d7d0", "_roomdef_set_door": "0x48da00", "___func__.18848": "0x4d6674", "_room_apply_door_theme_here": "0x48db80", "_roomdef_remove_door": "0x48dc90", "___func__.18864": "0x4d6660", "_roomdef_get": "0x48de50", "_room_id_to_roomdef": "0x48de80", "_roomdef_save_all": "0x48deb0", "_roomdef_layout_free": "0x48e150", "_roomdef_layout_alloc": "0x48e180", "_roomdef_scan_layout_for_blocked_edge": "0x48e1e0", "_refresh_blocked_edges": "0x48e540", "_roomdef_dump_layout": "0x48e590", "_roomdef_refresh_all": "0x48e6b0", "_roomdef_free_all": "0x48e6e0", "_roomdef_parse_room": "0x48e720", "_map_def_selected": "0x875380", "_lastroomdef": "0x87538c", "_roomdef_load_all": "0x48ec20", "_room_tags": "0x48ece0", "_roomdef_random_pick_with_tags": "0x48ed00", "_roomdef_here": "0x48ed80", "_roomdef_init": "0x48edc0", "_legends_": "0x8753a0", "_word_gogo": "0x48eff0", "_word_gogogo": "0x48f000", "_glitchforth": "0x48f030", "_script_prompt_enable": "0x48f070", "_prompt_on_": "0x4d0550", "_script_clear_err_state": "0x48f080", "_err_state": "0x8a8808", "_script_clear_last_error_state": "0x48f090", "_lasterrstate": "0x8a8804", "_script_handle_result": "0x48f0a0", "_script_do_handle_ex.constprop.7": "0x48f5a0", "_script_register_const": "0x48f670", "_script_register_const_float": "0x48f6c0", "_script_register_const_string": "0x48f710", "_script_find_word_handle": "0x48f760", "_script_do_input": "0x48f780", "_script_do_handle": "0x48f810", "_script_do_handle_clean": "0x48f820", "_script_do_event": "0x48f830", "_script_do": "0x48f8f0", "_script_inner_eval": "0x48f920", "_scriptf_do": "0x48f980", "_script_load": "0x48f9e0", "_script_exit": "0x48fa30", "_script_is_compiling": "0x48fa50", "_script_abort": "0x48fa70", "_script_compile_it": "0x48fb30", "_script_compile_it_once": "0x48fb80", "_script_reg_accessor_ex": "0x48fc30", "_script_reg_accessor": "0x48fde0", "_script_init": "0x48fe20", "_script_get_sys": "0x490070", "_script_debug_reboot": "0x490080", "_word_set_team_charid": "0x4900f0", "_word_set_leader": "0x490130", "_word_menu_selected_charid": "0x490150", "_word_get_team_charid": "0x490170", "_word_get_leader": "0x4901b0", "_perkfinder": "0x4901d0", "_word_trait_find": "0x490230", "_word_perk_find": "0x490240", "_word_extra_beard_count": "0x490250", "_word_extra_glasses_count": "0x490270", "_word_extra_hat_count": "0x4983c0", "_word_extra_hair_count": "0x4902b0", "_word_extra_body_count": "0x4983a0", "_word_extra_head_count": "0x4902f0", "_word_beard_count": "0x490310", "_word_glasses_count": "0x490340", "_word_hat_count": "0x490370", "_word_hair_count": "0x4903a0", "_word_body_count": "0x4903d0", "_word_head_count": "0x490400", "_word_teamrandomorder": "0x490430", "_word_teamrandom": "0x490470", "_word_teamleader": "0x490490", "_word_teamcountpermanent": "0x4904b0", "_word_teamcountalive": "0x4904d0", "_word_teamcountalivepermanent": "0x490500", "_word_teamcount": "0x490540", "_word_teamcharid": "0x490560", "_word_statname": "0x490590", "_word_gamechar_clone": "0x4905c0", "_word_is_savechar": "0x490640", "_word_sel_gamechars": "0x4906a0", "_word_sel_custchars": "0x4906b0", "_word_clear_custchars": "0x4906c0", "_word_numcharacter": "0x4906d0", "_word_savechar_clone": "0x490760", "___func__.19129": "0x4d8cf4", "_word_char_gen": "0x490810", "_script_char_pop_from_valid_id": "0x490870", "_script_char_pop": "0x4908c0", "_word_clear_modnum": "0x490920", "_word_check_modnum": "0x490950", "_word_set_modnum": "0x490990", "_word_modrecalc": "0x4909c0", "_word_decruit": "0x4909e0", "_word_recruit": "0x490a20", "_word_ai_defaults": "0x490a50", "_word_hair_rgb": "0x490a70", "_word_make_leader": "0x490ad0", "_word_set_job": "0x490b30", "_word_get_job": "0x490b70", "_word_loot_to_trunk": "0x490ba0", "_word_weapons_to_trunk": "0x490bc0", "_word_add_lootamt": "0x490be0", "_word_set_lootamt": "0x490c30", "_word_get_lootamt": "0x490c80", "_word_is_weapon_add": "0x490ce0", "_word_char_free": "0x490d30", "_word_characternum": "0x490d80", "_word_knownstatget": "0x490db0", "_word_knownstatset": "0x490e10", "_word_effstat": "0x490e70", "_word_bonusget": "0x490ec0", "_word_bonusset": "0x490f20", "_word_bonusadd": "0x490f80", "_word_statget": "0x490ff0", "_word_statset": "0x491050", "_word_statadd": "0x4910b0", "_word_clr_usefilter": "0x491110", "_word_set_usefilter": "0x491140", "_word_clr_useinfo": "0x491170", "_word_set_useinfo": "0x4911a0", "_script_characters": "0x4911d0", "_word_cyoa_show": "0x492fe0", "_word_cyoa_is_active": "0x492ff0", "_word_cyoa_set_clickspeed": "0x493010", "_word_cyoa_set_fade": "0x493030", "_word_cyoa_set_icon_hint": "0x493050", "_word_cyoa_set_image_iconrgb": "0x493070", "_word_cyoa_team_loot_text": "0x4930c0", "_word_cyoa_text_cr": "0x4931c0", "_word_cyoa_set_choice_handle": "0x4931d0", "_word_cyoa_text_append": "0x493200", "_word_cyoa_set_choice_text": "0x493220", "_word_cyoa_leftjust": "0x493240", "_word_cyoa_chosen_charid": "0x493250", "_word_cyoa_choice_goes_back": "0x493270", "_word_cyoa_set_choice_iconid": "0x493280", "_word_cyoa_set_choice_charid": "0x4932a0", "_word_cyoa_chosen_text": "0x4932e0", "_word_cyoa_chosen_id": "0x493300", "_word_cyoa_set_choice_id": "0x493320", "_word_cyoa_picked": "0x493340", "_word_cyoa_add_choice": "0x493360", "_word_cyoa_set_text": "0x493370", "_word_cyoa_set_title": "0x493390", "_word_cyoa_start_minus": "0x4933b0", "_word_cyoa_ok_dialog": "0x4933c0", "_word_cyoa_set_image_icon": "0x4933e0", "_word_cyoa_start": "0x493420", "_word_cyoa_set_char_icon": "0x493480", "_script_cyoa": "0x4934c0", "_word_game_over": "0x493860", "_word_intest": "0x493870", "_word_last_linkxy": "0x493880", "_last_door": "0x8a8820", "_word_doors_created": "0x4938f0", "_word_rooms_max": "0x493940", "_word_rooms_created": "0x493980", "_word_get_temps_used": "0x4939c0", "_word_get_killed_countdown": "0x4939e0", "_word_get_leader_playerid": "0x493a00", "_word_get_orders_tactic": "0x493a20", "_word_get_orders_combat": "0x493a40", "_word_get_no_time": "0x493a60", "_word_get_blurb_speed": "0x493a80", "_word_get_fps": "0x493aa0", "_word_get_console_blink": "0x493ac0", "_word_get_console_clr_mode": "0x493ae0", "_word_get_console": "0x493b00", "_word_get_quit_button_mode": "0x493b20", "_word_get_touch_controls": "0x493b40", "_word_timer_get": "0x493b60", "_word_timer_hint_get": "0x493ba0", "_word_get_clr_start_ticks": "0x493be0", "_word_get_clr_ticks": "0x493c00", "_word_get_travel_days": "0x493c20", "_word_get_road_lighting": "0x493c40", "_word_get_global_delay": "0x493c60", "_word_region_zombie_nightspawn_get": "0x493c80", "_word_region_zombie_basespawn_get": "0x493ca0", "_word_region_zombie_aggro_get": "0x493cc0", "_word_get_debug_no_zomb": "0x493ce0", "_word_game_get_road_theme": "0x493d00", "_word_vehicle_get_max_gas": "0x493d20", "_word_vehicle_get_variant": "0x493d40", "_word_vehicle_get_which": "0x493d60", "_word_locediting": "0x493d80", "_word_locseed": "0x493da0", "_word_gameseed": "0x493dd0", "_word_view_h": "0x493df0", "_word_view_w": "0x493e10", "_word_mapview": "0x493e30", "_word_get_premission_check": "0x493e50", "_word_get_gamemode_start": "0x493e70", "_word_gamemode_start": "0x493e90", "_word_get_solo_start": "0x493ea0", "_word_saveslot": "0x493ec0", "_word_mission_total_loot": "0x493ee0", "_word_mission_kills": "0x493f10", "_word_get_nohotkeyblip": "0x493f30", "_word_get_zombie_max_bodies": "0x493f50", "_word_get_zombie_max_heads": "0x493f70", "_word_get_zombie_min_bodies": "0x493f90", "_word_get_zombie_min_heads": "0x493fb0", "_word_get_zombie_body_count": "0x493fd0", "_word_get_zombie_head_count": "0x493ff0", "_word_get_skin_roll_max": "0x494010", "_word_get_unlock_extra_beards": "0x494030", "_word_get_unlock_extra_glasses": "0x494050", "_word_get_unlock_extra_hair": "0x494070", "_word_get_unlock_extra_heads": "0x494090", "_word_get_unlock_extra_bodies": "0x4940b0", "_word_get_unlock_extra_hats": "0x4940d0", "_word_get_female_hattables": "0x4940f0", "_word_get_male_hattables": "0x494110", "_word_minute": "0x494130", "_word_hour": "0x494180", "_word_game_location": "0x4941d0", "_word_get_refresh_layout": "0x4941f0", "_word_get_debug_no_focus_pause": "0x494210", "_word_get_debug_load_delay": "0x494230", "_word_get_touch_transparency": "0x494250", "_word_get_touch_dragzone": "0x494270", "_word_get_touch_deadzone": "0x494290", "_word_get_mappings_loaded": "0x4942b0", "_word_get_loc_here_events": "0x4942d0", "_word_get_item_default_events": "0x494320", "_word_get_zombie_default_events": "0x494360", "_word_get_human_default_events": "0x4943a0", "_word_get_vehicle_default_cyoa": "0x4943e0", "_word_set_loc_here_events": "0x494420", "_word_set_item_default_events": "0x494460", "_word_set_zombie_default_events": "0x494480", "_word_set_human_default_events": "0x4944a0", "_word_set_vehicle_default_cyoa": "0x4944c0", "_word_mapselected": "0x4944e0", "_word_get_room_here_events": "0x494500", "_word_set_room_here_events": "0x494550", "_word_edge_dec": "0x4945a0", "_word_edge_inc": "0x4945e0", "_word_rooms_max_set": "0x494620", "_word_set_killed_countdown": "0x494650", "_word_set_leader_playerid": "0x494670", "_word_set_game_debug_ai_vis": "0x494690", "_word_set_orders_tactic": "0x4946b0", "_word_set_orders_combat": "0x4946d0", "_word_set_no_time": "0x4946f0", "_word_set_blurb_speed": "0x494710", "_word_set_fps": "0x494730", "_word_set_console_blink": "0x494750", "_word_set_console_clr_mode": "0x494770", "_word_set_console": "0x494790", "_word_set_quit_button_mode": "0x4947b0", "_word_set_touch_controls": "0x4947d0", "_word_room_edge_map_get": "0x4947f0", "_word_room_edge_leave_get": "0x494850", "_word_room_edge_leave_set": "0x4948b0", "_word_timer_set": "0x4948f0", "_word_timer_hint_set": "0x494910", "_word_set_clr_start_ticks": "0x494930", "_word_set_clr_ticks": "0x494950", "_word_set_travel_days": "0x494970", "_word_set_road_lighting": "0x494990", "_word_set_global_delay": "0x4949b0", "_word_light_mode_set": "0x4949d0", "_word_region_get_edge_spawn": "0x4949f0", "_word_region_set_edge_spawn": "0x494a30", "_word_region_zombie_nightspawn_set": "0x494a70", "_word_region_zombie_basespawn_set": "0x494a90", "_word_region_zombie_aggro_set": "0x494ab0", "_word_set_debug_no_zomb": "0x494ad0", "_word_set_no_zomb": "0x494af0", "_word_game_set_road_theme": "0x494b10", "_word_game_set_less_blurbage": "0x494b40", "_word_vehicle_set_max_gas": "0x494b60", "_word_vehicle_set_variant": "0x494b90", "_word_locseed_set": "0x494bb0", "_word_gameseed_set": "0x494be0", "_word_ticksim": "0x494c00", "_word_set_premission_check": "0x494c20", "_word_set_gamemode_start": "0x494c40", "_word_set_solo_start": "0x494c60", "_word_saveslot_set": "0x494c80", "_word_set_effects_off": "0x494cb0", "_word_set_hud_off": "0x494cd0", "_word_set_nohotkeyblip": "0x494cf0", "_word_set_zombie_max_bodies": "0x494d10", "_word_set_zombie_max_heads": "0x494d30", "_word_set_zombie_min_bodies": "0x494d50", "_word_set_zombie_min_heads": "0x494d70", "_word_set_zombie_body_count": "0x494d90", "_word_set_zombie_head_count": "0x494db0", "_word_set_skin_roll_max": "0x494dd0", "_word_set_unlock_extra_beards": "0x494df0", "_word_set_unlock_extra_glasses": "0x494e10", "_word_set_unlock_extra_hair": "0x494e30", "_word_set_unlock_extra_heads": "0x494e50", "_word_set_unlock_extra_bodies": "0x494e70", "_word_set_unlock_extra_hats": "0x494e90", "_word_set_female_hattables": "0x494eb0", "_word_set_male_hattables": "0x494ed0", "_word_set_refresh_layout": "0x494ef0", "_word_set_debug_no_focus_pause": "0x494f10", "_word_set_debug_load_delay": "0x494f30", "_word_set_touch_transparency": "0x494f50", "_word_set_touch_dragzone": "0x494f70", "_word_set_touch_deadzone": "0x494f90", "_word_door_theme": "0x494fb0", "_word_wall_theme": "0x494fd0", "_word_floor_theme": "0x494ff0", "_last_link": "0x495010", "_word_last_edge": "0x495060", "_word_randpos": "0x4950b0", "_word_xyzpicklet": "0x495170", "_word_mass_zombify2": "0x4951a0", "_word_mass_zombify3": "0x495230", "_word_mass_zombify": "0x4952d0", "_word_set_wind_force": "0x4953f0", "_word_set_console_bg_b": "0x495410", "_word_set_console_bg_g": "0x495430", "_word_set_console_bg_r": "0x495450", "_word_set_console_clr_b": "0x495470", "_word_set_console_clr_g": "0x495490", "_word_set_console_clr_r": "0x4954b0", "_word_set_grapple_strength": "0x4954d0", "_word_set_water_colour_b": "0x4954f0", "_word_set_water_colour_g": "0x495510", "_word_set_water_colour_r": "0x495530", "_word_set_wipe": "0x495550", "_word_set_fade_count": "0x495590", "_word_set_fade_to": "0x4955d0", "_word_set_bg_hi_a": "0x495610", "_word_set_bg_hi_b": "0x495630", "_word_set_bg_hi_g": "0x495650", "_word_set_bg_hi_r": "0x495670", "_word_set_bg_a": "0x495690", "_word_set_bg_b": "0x4956b0", "_word_set_bg_g": "0x4956d0", "_word_set_bg_r": "0x4956f0", "_word_set_fade_clr_b": "0x495710", "_word_set_fade_clr_g": "0x495730", "_word_set_fade_clr_r": "0x495750", "_word_set_clr_far_set_thing_b": "0x495770", "_word_set_clr_far_set_thing_g": "0x495790", "_word_set_clr_far_set_thing_r": "0x4957b0", "_word_set_clr_near_set_thing_b": "0x4957d0", "_word_set_clr_near_set_thing_g": "0x4957f0", "_word_set_clr_near_set_thing_r": "0x495810", "_word_set_clr_near_set_b": "0x495830", "_word_set_clr_near_set_g": "0x495850", "_word_set_clr_near_set_r": "0x495870", "_word_set_clr_far_old_thing_b": "0x495890", "_word_set_clr_far_old_thing_g": "0x4958b0", "_word_set_clr_far_old_thing_r": "0x4958d0", "_word_set_clr_near_old_thing_b": "0x4958f0", "_word_set_clr_near_old_thing_g": "0x495910", "_word_set_clr_near_old_thing_r": "0x495930", "_word_set_clr_near_old_b": "0x495950", "_word_set_clr_near_old_g": "0x495970", "_word_set_clr_near_old_r": "0x495990", "_word_set_clr_far_thing_b": "0x4959b0", "_word_set_clr_far_thing_g": "0x4959d0", "_word_set_clr_far_thing_r": "0x4959f0", "_word_set_clr_far_tile_b": "0x495a10", "_word_set_clr_far_tile_g": "0x495a30", "_word_set_clr_far_tile_r": "0x495a50", "_word_set_clr_near_thing_b": "0x495a70", "_word_set_clr_near_thing_g": "0x495a90", "_word_set_clr_near_thing_r": "0x495ab0", "_word_set_clr_near_tile_b": "0x495ad0", "_word_set_clr_near_tile_g": "0x495af0", "_word_set_clr_near_tile_r": "0x495b10", "_word_set_lighting": "0x495b30", "_word_set_near_bright": "0x495b70", "_word_set_base_lighting": "0x495b90", "_word_set_gloom_lighting": "0x495bb0", "_word_set_weather": "0x495bd0", "_word_region_zombie_alertscale_set": "0x495bf0", "_word_set_camera_posy": "0x495c10", "_word_set_camera_posx": "0x495c30", "_word_vehicle_set_armour_display": "0x495c50", "_word_vehicle_set_speed_display": "0x495c90", "_word_vehicle_set_engine_display": "0x495cd0", "_word_vehicle_set_chassis_display": "0x495d10", "_word_vehicle_set_motor_q": "0x495d50", "_word_vehicle_set_motor_filt_high": "0x495d70", "_word_vehicle_set_motor_filt_low": "0x495d90", "_word_vehicle_set_motor_duty2": "0x495db0", "_word_vehicle_set_motor_duty1": "0x495dd0", "_word_vehicle_set_motor_freq2": "0x495df0", "_word_vehicle_set_motor_freq1": "0x495e10", "_word_set_main_event_pause": "0x495e30", "_word_set_main_event_period": "0x495eb0", "_word_oclock": "0x495f40", "_word_percent_zombify": "0x495f80", "_word_zomb_count": "0x495fd0", "_word_last_link_tile": "0x495ff0", "_word_last_link_set": "0x496050", "_word_unopened_doors": "0x4960f0", "_word_rooms_left": "0x496110", "_word_peek_room": "0x496130", "_word_pick_room": "0x496190", "_word_revert_door": "0x496230", "_word_row_door": "0x496270", "_word_column_door": "0x496310", "_word_edge_door": "0x4963b0", "_word_inset_door": "0x4964a0", "_word_random_inset_door": "0x4964e0", "_word_random_edge_door": "0x496540", "_word_random_doors": "0x496580", "_word_rdoor": "0x4965b0", "_word_loc_door_theme_set": "0x4965f0", "_word_loc_wall_theme_set": "0x496620", "_word_loc_floor_theme_set": "0x496650", "_word_allow_double_doors_set": "0x496680", "_word_allow_inset_doors_set": "0x4966b0", "_word_percent_auto_door_escape": "0x4966e0", "_word_max_room_doors_set": "0x496750", "_word_auto_doors_set": "0x496780", "_word_roomdef_add_mode": "0x4967c0", "_word_roomdef_count_set": "0x4967e0", "_word_roomdef_weight_set": "0x496800", "_word_roomdef_add": "0x496820", "_word_def_room_max_set": "0x496840", "_word_strroomscript2": "0x496870", "_word_strroomscript": "0x496890", "_word_strpostscript": "0x4968b0", "_word_strprescript": "0x4968d0", "_word_strlocdefscript": "0x4968f0", "_word_strlocdeftags": "0x496910", "_word_strlocdefentrytags": "0x496930", "_word_locations_reset": "0x496950", "_word_get_wind_force": "0x496960", "_word_get_console_bg_b": "0x496980", "_word_get_console_bg_g": "0x4969a0", "_word_get_console_bg_r": "0x4969c0", "_word_get_console_clr_b": "0x4969e0", "_word_get_console_clr_g": "0x496a00", "_word_get_console_clr_r": "0x496a20", "_word_get_grapple_strength": "0x496a40", "_word_get_water_colour_b": "0x496a60", "_word_get_water_colour_g": "0x496a80", "_word_get_water_colour_r": "0x496aa0", "_word_get_wipe": "0x496ac0", "_word_get_fade_count": "0x496ae0", "_word_get_fade_to": "0x496b00", "_word_get_bg_hi_a": "0x496b20", "_word_get_bg_hi_b": "0x496b40", "_word_get_bg_hi_g": "0x496b60", "_word_get_bg_hi_r": "0x496b80", "_word_get_bg_a": "0x496ba0", "_word_get_bg_b": "0x496bc0", "_word_get_bg_g": "0x496be0", "_word_get_bg_r": "0x496c00", "_word_get_fade_clr_b": "0x496c20", "_word_get_fade_clr_g": "0x496c40", "_word_get_fade_clr_r": "0x496c60", "_word_get_clr_far_set_thing_b": "0x496c80", "_word_get_clr_far_set_thing_g": "0x496ca0", "_word_get_clr_far_set_thing_r": "0x496cc0", "_word_get_clr_near_set_thing_b": "0x496ce0", "_word_get_clr_near_set_thing_g": "0x496d00", "_word_get_clr_near_set_thing_r": "0x496d20", "_word_get_clr_near_set_b": "0x496d40", "_word_get_clr_near_set_g": "0x496d60", "_word_get_clr_near_set_r": "0x496d80", "_word_get_clr_far_old_thing_b": "0x496da0", "_word_get_clr_far_old_thing_g": "0x496dc0", "_word_get_clr_far_old_thing_r": "0x496de0", "_word_get_clr_near_old_thing_b": "0x496e00", "_word_get_clr_near_old_thing_g": "0x496e20", "_word_get_clr_near_old_thing_r": "0x496e40", "_word_get_clr_near_old_b": "0x496e60", "_word_get_clr_near_old_g": "0x496e80", "_word_get_clr_near_old_r": "0x496ea0", "_word_get_clr_far_thing_b": "0x496ec0", "_word_get_clr_far_thing_g": "0x496ee0", "_word_get_clr_far_thing_r": "0x496f00", "_word_get_clr_far_tile_b": "0x496f20", "_word_get_clr_far_tile_g": "0x496f40", "_word_get_clr_far_tile_r": "0x496f60", "_word_get_clr_near_thing_b": "0x496f80", "_word_get_clr_near_thing_g": "0x496fa0", "_word_get_clr_near_thing_r": "0x496fc0", "_word_get_clr_near_tile_b": "0x496fe0", "_word_get_clr_near_tile_g": "0x497000", "_word_get_clr_near_tile_r": "0x497020", "_word_get_lighting": "0x497040", "_word_get_near_bright": "0x497060", "_word_get_base_lighting": "0x497080", "_word_get_gloom_lighting": "0x4970a0", "_word_get_weather": "0x4970c0", "_word_light_mode_get": "0x4970e0", "_word_region_zombie_alertscale_get": "0x497100", "_word_get_camera_posy": "0x497120", "_word_get_camera_posx": "0x497140", "_word_camera_pos": "0x497160", "_word_vehicle_get_motor_q": "0x4971a0", "_word_vehicle_get_motor_filt_high": "0x4971c0", "_word_vehicle_get_motor_filt_low": "0x4971e0", "_word_vehicle_get_motor_duty2": "0x497200", "_word_vehicle_get_motor_duty1": "0x497220", "_word_vehicle_get_motor_freq2": "0x497240", "_word_vehicle_get_motor_freq1": "0x497260", "_word_get_main_event_period": "0x497280", "_word_force_refresh": "0x4972b0", "_word_smile": "0x4972c0", "_word_team_lootstr": "0x4972f0", "_word_get_menu_info_text": "0x497310", "_word_players_active": "0x497330", "_word_joy_count": "0x497350", "_word_joy_button_name": "0x497370", "_word_sys_reset": "0x4973f0", "_word_cheevo_post": "0x497400", "_word_popup_set_last_mode": "0x497420", "_word_popup_dis": "0x497440", "_word_window_title": "0x497480", "_word_looticon": "0x4974a0", "_word_plus_textfill": "0x4974d0", "_word_console_close": "0x4974f0", "_word_console_open": "0x497500", "_word_room_edge_map_set": "0x497520", "_word_create_map_wh": "0x497640", "_word_get_specialcharid": "0x497680", "_word_set_specialcharid": "0x4976a0", "_word_seeded_name": "0x4976c0", "_word_rnd_name": "0x497700", "_word_fade_clr": "0x497740", "_word_fade_to": "0x497790", "_word_particles_active": "0x4977b0", "_word_timers_clear": "0x4977d0", "_word_timer_retrigger": "0x4977e0", "_word_timer_add": "0x4977f0", "_word_timelight_select": "0x497820", "_word_timelight_default": "0x497840", "_word_timelight_clear": "0x497850", "_word_tint_retrigger": "0x497860", "_word_tint_trigger": "0x497870", "_word_tint_default": "0x4978a0", "_word_daylight_scale": "0x4978b0", "_word_clear_all_pickles": "0x4978f0", "_word_region_zombie_pickletime_get": "0x497900", "_word_region_zombie_pickletime_set": "0x497930", "_word_vehicle_set_which": "0x497970", "_word_get_mission_vehicle": "0x4979d0", "_word_trunk_open": "0x497a00", "_word_trunk_count": "0x497a10", "_word_get_trunk_weapon": "0x497a40", "_word_trunk_clear": "0x497a70", "_word_set_trunk_lootamt": "0x497a80", "_word_get_trunk_lootamt": "0x497ad0", "_word_add_trunk_weapon": "0x497b20", "_word_set_trunk_weapon": "0x497b70", "_word_weaponidstr": "0x497bd0", "_word_strweaponid": "0x497c20", "_word_p1_cmd_joy_alt": "0x497c50", "_word_p1_btn_name": "0x497cd0", "_word_game_rndsign": "0x497dc0", "_word_game_rnd5050": "0x497e00", "_word_game_onein": "0x497e20", "_word_game_mrand": "0x497e50", "_word_game_rnd": "0x497e70", "_word_game_frnd": "0x497ed0", "_word_reg_tags_here": "0x497f40", "_word_loc_tags_here": "0x497f60", "_word_setmapview": "0x497f80", "_word_mapid_here": "0x497fc0", "_word_room_tags_here": "0x497ff0", "_word_xymsg2": "0x498010", "_xymsg2_particle": "0x8a881c", "_word_xymsg": "0x4980b0", "_word_msg": "0x498130", "_xymsg2_update": "0x4981a0", "_word_tone": "0x4981c0", "_word_gamemode_applyword": "0x498220", "_word_camera_rumble": "0x498270", "_word_gui_rumble": "0x4982b0", "_word_set_hotkey": "0x4982f0", "_word_to_gamestart_setup": "0x498320", "_word_new_to_char_maker": "0x498330", "_word_mission_config": "0x498340", "_word_segue_to_driving_all_team": "0x498350", "_word_segue_to_driving": "0x498370", "_word_segue_to_mission": "0x498380", "_word_quit_to_title": "0x498390", "_word_set_error_handle": "0x4983e0", "_word_main_post_event": "0x498400", "_word_set_main_stack_handle": "0x498420", "_word_set_main_event_handle": "0x498440", "_word_totickpath": "0x498460", "_word_parse_rooms": "0x4985d0", "_word_add_rooms": "0x4985f0", "_word_load_rooms": "0x498610", "_word_free_all_rooms": "0x498650", "_word_sprite_count": "0x498660", "_word_calltest": "0x498680", "_handle.19996": "0x8a8814", "_word_set_menu_info_text": "0x498720", "_word_mad_quit": "0x498750", "_word_fullscreen": "0x498760", "_word_buildstamp": "0x498780", "_word_test_fword": "0x4987a0", "_word_addloot": "0x4987e0", "_word_location_add": "0x498820", "_word_set_mission_vehicle": "0x498850", "_word_beep": "0x4988a0", "_last_.19711": "0x8a8818", "_script_set_map_anchor": "0x4988f0", "_script_map_anchor_tile": "0x498910", "_script_room_defs": "0x498970", "___FUNCTION__.19651": "0x4db790", "_script_locations": "0x498e80", "___FUNCTION__.19706": "0x4db77c", "_script_pop_rgb": "0x499100", "_word_timelight_set_far_thing": "0x499150", "_word_timelight_set_far": "0x499190", "_word_timelight_set_near_thing": "0x4991d0", "_word_timelight_set_near": "0x499210", "_word_tint_near_set": "0x499250", "_word_tint_far_set": "0x499290", "_word_tint_near_thing_set": "0x4992d0", "_word_tint_far_thing_set": "0x499310", "_word_tint_near_tile_set": "0x499350", "_word_tint_far_tile_set": "0x499390", "_script_push_rgb": "0x4993d0", "_word_angle_sat_colour": "0x499410", "_word_angle_colour": "0x499480", "_script_pop_xy": "0x4994d0", "_word_d_light": "0x499510", "_word_s_light": "0x499580", "_script_push_xy": "0x4995f0", "_script_general": "0x499630", "___FUNCTION__.21110": "0x4db76c", "_tbuilding": "0x49d880", "_word_barn": "0x49d8d0", "_word_farmhouse": "0x49d940", "_word_shop2_nogable": "0x49d9b0", "_word_shop2": "0x49da60", "_word_shop": "0x49db10", "_word_fbuilding2": "0x49dbb0", "_word_fbuilding": "0x49dc40", "_word_cbuilding2": "0x49dcd0", "_word_cbuilding": "0x49dd50", "_word_building2": "0x49ddc0", "_word_building": "0x49de50", "_word_add_gasbar": "0x49dec0", "_word_house3": "0x49def0", "_word_house2": "0x49df40", "_word_house1": "0x49df90", "_word_yallmart": "0x49dfd0", "_word_bunker": "0x49e020", "_word_cabin": "0x49e060", "_word_default_layer": "0x49e0a0", "_word_max_layer": "0x49e0c0", "_word_process_map": "0x49e0e0", "_word_last_build_doorxy": "0x49e150", "_word_h": "0x49e1c0", "_word_w": "0x49e1e0", "_word_last_build_size": "0x49e200", "_word_darken": "0x49e270", "_word_pitlot": "0x49e280", "_word_conclot": "0x49e300", "_word_gravellot": "0x49e380", "_word_pavedlot": "0x49e400", "_word_spritelot": "0x49e480", "_word_grasslot": "0x49e500", "_word_baselot_empty": "0x49e580", "_word_baselot": "0x49e5d0", "_word_emptylot": "0x49e620", "_word_add_location": "0x49e670", "_word_str_pick_location": "0x49e6a0", "_word_auto_pick_locid": "0x49e6f0", "_word_pixelh": "0x49e710", "_word_pixelw": "0x49e730", "_word_is_xy_solid": "0x49e750", "_word_set_tile": "0x49e7a0", "_word_tile_at": "0x49e7e0", "_word_init": "0x4a90c0", "_word_is_exists": "0x49e860", "_word_select": "0x49e890", "_word_selected": "0x49e8b0", "_last_loc.isra.0": "0x49e8d0", "_word_set_sign_glow": "0x49e900", "_word_set_sign_shift": "0x49e930", "_word_set_sign_fg_rgb": "0x49e970", "_word_set_sign_bg_rgb": "0x49e9c0", "_word_set_sign_border_rgb": "0x49ea10", "_word_set_sign_text": "0x49ea60", "_tile_pop.part.1": "0x49eaa0", "_word_is_solid": "0x49eac0", "_word_get_layer_rot": "0x49eb10", "_word_set_layer_rot": "0x49eb70", "_word_get_layer_flipx": "0x49ebd0", "_word_set_layer_flipx": "0x49ec30", "_word_get_layer_off": "0x49ec90", "_word_set_layer_off": "0x49ed00", "_word_get_layer_quadlight": "0x49ed70", "_word_set_layer_quadlight": "0x49edd0", "_word_get_layer_spritebits": "0x49ee30", "_word_set_layer_spritebits": "0x49ee90", "_word_get_layer_spriteid": "0x49eef0", "_word_set_layer_spriteid": "0x49ef50", "_script_map": "0x49efc0", "___FUNCTION__.18812": "0x4dbdc4", "_word_nummod": "0x49fbe0", "_get_modnum": "0x49fc40", "_word_statmodplus": "0x49fc80", "_word_statmodstore": "0x49fce0", "_word_statmodfetch": "0x49fd50", "_word_modnum": "0x49fda0", "_script_modifiers": "0x49fdc0", "_word_music_set_vol": "0x49ffa0", "_word_strmusic_fade_switch": "0x49ffc0", "_word_strmusic_load": "0x49fff0", "_script_music": "0x4a0010", "_particle_pop": "0x4a0080", "_word_animtype": "0x4a00b0", "_word_snowtype": "0x4a00d0", "_word_nonglowy": "0x4a0120", "_word_glowy": "0x4a0140", "_word_copy": "0x4a0160", "_snowtype_particle_update": "0x4a0190", "_alpha3_particle_draw": "0x4a0200", "_additive3_particle_draw": "0x4a02a0", "_word_new_gas_smoke": "0x4a0350", "_word_new": "0x4a0390", "_animtype_particle_update": "0x4a0400", "_script_particles": "0x4a0470", "_word_get_no_rest": "0x4a0d50", "_word_set_no_rest": "0x4a0d70", "_word_region_locdef_count_set": "0x4a0d90", "_word_region_locdef_weight_set": "0x4a0db0", "_word_region_locdef_add": "0x4a0dd0", "_word_region_loc_max_set": "0x4a0df0", "_word_region_set_h": "0x4a0e20", "_word_region_set_w": "0x4a0e70", "_word_region_on_foot": "0x4a0ec0", "_word_region_no_prefab": "0x4a0ef0", "_word_region_start_mode": "0x4a0f20", "_word_region_no_outside": "0x4a0f50", "_word_last_picked_script": "0x4a0f80", "_word_region_strlocscript2": "0x4a0fd0", "_word_region_strlocscript": "0x4a1010", "_word_region_strpostscript": "0x4a1050", "_word_region_strprescript": "0x4a1090", "_word_region_strscript": "0x4a10d0", "_word_region_strtags": "0x4a1110", "_word_region_start": "0x4a1150", "_script_regions": "0x4a1160", "___FUNCTION__.18379": "0x4dcce0", "_word_get_blurbtext": "0x4a1420", "_word_blurbloot": "0x4a1440", "_word_blurbreveal": "0x4a1470", "_word_blurbquote": "0x4a14a0", "_word_blurbstat": "0x4a14d0", "_word_blurbemit": "0x4a1510", "_word_flash": "0x4a1540", "_word_txt": "0x4a1560", "_word_pause": "0x4a1580", "_word_tab": "0x4a15a0", "_word_charid": "0x4a15e0", "_word_qmsg": "0x4a1600", "_word_clear": "0x4a1640", "_script_roadmsg": "0x4a1650", "_word_with_thing": "0x4a1840", "_word_last_sysfx": "0x4a1890", "_word_global_echo_off": "0x4a18c0", "_word_global_echo": "0x4a1900", "_word_oversample": "0x4a1970", "_word_nextpri": "0x4a19b0", "_word_pwm": "0x4a19d0", "_word_goat": "0x4a1a10", "_word_catmew": "0x4a1a40", "_word_bzinkt": "0x4a1a70", "_word_nes_tri": "0x4a1aa0", "_word_fm_sweep": "0x4a1ad0", "_word_ringmod": "0x4a1b10", "_word_zelda": "0x4a1b50", "_word_noise": "0x4a1c60", "_word_glass": "0x4a1ca0", "_word_charbabble": "0x4a1cd0", "_word_sing": "0x4a1d10", "_word_charsing": "0x4a1d50", "_word_babble": "0x4a1df0", "_word_organ": "0x4a1e30", "_word_bite": "0x4a1e70", "_word_zombie": "0x4a1ea0", "_word_dutypulse": "0x4a1ed0", "_word_shred": "0x4a1f00", "_word_crunch": "0x4a1f40", "_word_ruffle": "0x4a1f70", "_word_rumble": "0x4a1fb0", "_word_thump": "0x4a1fe0", "_word_growl": "0x4a2010", "_word_fm": "0x4a2050", "_word_dtmf": "0x4a20a0", "_word_pulse": "0x4a20e0", "_word_pip": "0x4a2120", "_word_creepy": "0x4a2160", "_last_.18427": "0x8a8828", "_script_synth": "0x4a2240", "_word_buddy": "0x4a3070", "_word_last_thing": "0x4a30a0", "_word_get_anchor": "0x4a30d0", "_word_tileh": "0x4a3110", "_word_tilew": "0x4a3130", "_word_absentees": "0x4a3140", "_word_things_in_xyradius": "0x4a3260", "_word_zombs_in_xyradius": "0x4a32e0", "_word_alert_lev_ch_xy": "0x4a3360", "_word_xyloudness": "0x4a33f0", "_word_driveout": "0x4a3430", "_word_drivein": "0x4a3440", "_reportx_update": "0x4a3450", "_reportx_particle": "0x8a882c", "_word_player": "0x4a3470", "_word_item_spawn": "0x4a34a0", "_word_list_things": "0x4a3500", "_word_number_thing_active": "0x4a3550", "_word_number_thing": "0x4a3590", "_word_set_anchor": "0x4a35d0", "_scatter": "0x4a3650", "_word_blast": "0x4a3870", "_word_bullet": "0x4a3900", "_check_zomb_rad": "0x4a3970", "_check_thing_rad": "0x4a3a00", "_script_thing_pop": "0x4a3a80", "_word_wielded_score": "0x4a3b00", "_word_jump_human_room": "0x4a3bc0", "_word_hup": "0x4a3bf0", "_word_ugh": "0x4a3c20", "_word_add_fatigue": "0x4a3c50", "_word_wielded_spriteid": "0x4a3c80", "_word_is_absent": "0x4a3cc0", "_word_shudderxy": "0x4a3d00", "_word_is_using_ranged": "0x4a3e20", "_word_to_mapid": "0x4a3e50", "_word_to_mapidxy": "0x4a3e90", "_word_human_breath": "0x4a3f00", "_word_is_fatigued": "0x4a3f30", "_word_gas_smoke": "0x4a3f60", "_word_dust": "0x4a3f80", "_word_pumpme": "0x4a3fa0", "_word_junkbits": "0x4a3fe0", "_word_zbones": "0x4a4010", "_word_zguts": "0x4a4050", "_word_flyme": "0x4a4080", "_word_face_pos": "0x4a40a0", "_word_turn_toward": "0x4a40e0", "_word_face_each_other": "0x4a4120", "_word_try2burn": "0x4a4170", "_word_licks": "0x4a41a0", "_word_embers": "0x4a41d0", "_word_flames": "0x4a4200", "_word_fire": "0x4a4230", "_word_shatter": "0x4a4250", "_word_forcethrow": "0x4a4280", "_word_zsmack": "0x4a42a0", "_word_msmack": "0x4a4310", "_word_smack": "0x4a4380", "_word_swapattack": "0x4a43f0", "_word_slotuse_get": "0x4a4420", "_word_slotuse_set": "0x4a4450", "_word_useanammo": "0x4a44c0", "_word_reportammo": "0x4a44f0", "_word_ammocount": "0x4a4510", "_word_attack": "0x4a4540", "_word_take": "0x4a4570", "_word_drop_weapons": "0x4a45a0", "_word_altdropweapon": "0x4a45c0", "_word_dropminusweapon": "0x4a45e0", "_word_forcedropweapon": "0x4a4600", "_word_dropweapon": "0x4a4620", "_word_altwielded": "0x4a4640", "_word_wielded_stack_inc": "0x4a4670", "_word_wielded_stack_avail": "0x4a46c0", "_word_wielded_stack": "0x4a4700", "_word_wielded": "0x4a4740", "_word_smashychunks": "0x4a4770", "_word_smashybits": "0x4a47d0", "_word_loudness": "0x4a4830", "_word_is_inside_of": "0x4a4860", "_word_inside_id": "0x4a48a0", "_word_leave": "0x4a48d0", "_word_enter": "0x4a48f0", "_word_carry": "0x4a4920", "_word_set_open": "0x4a4950", "_word_thing_say": "0x4a4980", "_word_thing_is_report": "0x4a49b0", "_word_thing_reportdurex": "0x4a49e0", "_word_thing_reportdurnow": "0x4a4a60", "_word_thing_reportdur": "0x4a4ad0", "_word_thing_report": "0x4a4b40", "_word_thing_report_health": "0x4a4b80", "_word_thing_nearest": "0x4a4bb0", "_word_thing_overlap": "0x4a4c00", "_word_is_buddy": "0x4a4c40", "_word_is_grappled": "0x4a4c70", "_word_jump2leader": "0x4a4ca0", "_word_as_human": "0x4a4cc0", "_word_as_pickup": "0x4a4ce0", "_word_as_weapon_num": "0x4a4d20", "_word_set_last_thing": "0x4a4d50", "_word_select_thing": "0x4a4d70", "_word_set_dataint": "0x4a4d80", "_word_get_dataint": "0x4a4dc0", "_word_set_databyte": "0x4a4e00", "_word_get_databyte": "0x4a4e40", "_word_spitspark": "0x4a4e80", "_word_spryoff": "0x4a4ea0", "_word_sprxoff": "0x4a4ee0", "_word_sprh": "0x4a4f20", "_word_sprw": "0x4a4f60", "_word_thing_number": "0x4a4fa0", "_word_container": "0x4a4fd0", "_word_bcircle_set": "0x4a5000", "_word_bcircle": "0x4a5040", "_word_bbox": "0x4a50b0", "_word_scatterxy": "0x4a5140", "_word_scatter": "0x4a5180", "_word_drift": "0x4a51b0", "_word_set_tpos_y": "0x4a51d0", "_word_get_tpos_y": "0x4a5200", "_word_set_tpos_x": "0x4a5230", "_word_get_tpos_x": "0x4a5260", "_word_tpos": "0x4a5290", "_word_vel3_set": "0x4a52e0", "_word_vel_set": "0x4a5330", "_word_pos3_set": "0x4a5370", "_word_pos_set": "0x4a53c0", "_word_vel3": "0x4a5400", "_word_vel": "0x4a5450", "_word_pos3": "0x4a5490", "_word_pos": "0x4a54e0", "_word_jump": "0x4a5520", "_word_jumpy": "0x4a5570", "_word_jumpx": "0x4a55a0", "_word_slide": "0x4a55d0", "_word_slidey": "0x4a5640", "_word_slidex": "0x4a5680", "_script_thing_push": "0x4a56c0", "_script_things": "0x4a56f0", "_word_weapon_spriteid": "0x4a8ba0", "_word_set_weaponfunc": "0x4a8be0", "_selected": "0x8a8830", "_word_get_spriteid": "0x4a8c60", "_word_set_spriteid": "0x4a8ca0", "_word_iget": "0x4a8d00", "_word_iset": "0x4a8d50", "_word_cget": "0x4a8da0", "_word_cset": "0x4a8df0", "_word_set_tags": "0x4a8e40", "_word_set_chargename": "0x4a8ea0", "_word_set_name": "0x4a8f00", "_word_hset": "0x4a8f60", "_word_hget": "0x4a8fd0", "_word_fget": "0x4a9020", "_word_fset": "0x4a9070", "_word_wdup": "0x4a90d0", "_word_sel": "0x4a9130", "_script_weapon_config": "0x4a9180", "___FUNCTION__.18588": "0x4e06f8", "_feedback_effect": "0x4aa250", "_in_fbuff": "0x8a88ee", "_out_fbuff": "0x8a88ec", "_decay_fbuff": "0x4d0554", "_fbuff": "0x8a8900", "_sound_noise_fx": "0x4aa340", "_pip_effect": "0x4aa610", "_goat_effect": "0x4aad20", "_sound_thump_fx": "0x4aafc0", "_bzinkt_fx": "0x4ab340", "_shred_effect": "0x4ab5f0", "_fm_effect": "0x4ab7d0", "_ruffle_effect": "0x4abb30", "_shepard_effect": "0x4abd00", "_dtmf_effect": "0x4ac3d0", "_ringmod_effect": "0x4ac560", "_creepy_effect": "0x4ac970", "_pwm_effect": "0x4acb70", "_warble_effect": "0x4acd50", "_duty_pulse": "0x4acfc0", "_organ_sound": "0x4ad380", "_rumble_effect": "0x4ad580", "_sing_effect": "0x4ad7e0", "_crunch_effect": "0x4adc40", "_babble_effect": "0x4adee0", "_catmew_fx": "0x4ae2c0", "_fm_sweep_effect": "0x4ae500", "_nestriangle": "0x4ae810", "_glass_fx": "0x4ae9c0", "_sound_effect_next_priority": "0x4aeb00", "_next_pri_": "0x8c8900", "_sound_effect": "0x4aeb10", "_sound_effect_ex": "0x4aeb40", "_sound_effect_ready": "0x4aeb80", "_sound_noise": "0x4aeb90", "_sound_thump_ex": "0x4aebf0", "_sound_thump": "0x4aec70", "_sound_shred": "0x4aec90", "_sound_shepard": "0x4aed40", "_fx.15388": "0x8a88e8", "_dummy.15389": "0x8a8840", "_sound_pip": "0x4aede0", "_sound_fm": "0x4aee60", "_sound_ringmod": "0x4aeee0", "_sound_warble": "0x4aef70", "_sound_dtmf": "0x4aefe0", "_sound_rumble": "0x4af0a0", "_sound_duty_pulse": "0x4af0e0", "_sound_ruffle_ex": "0x4af170", "_sound_ruffle": "0x4af200", "_sound_crunch": "0x4af230", "_sound_fm_growl": "0x4af280", "_sound_creepy": "0x4af320", "_sound_pulse_ex": "0x4af380", "_sound_pulse": "0x4af3f0", "_sound_organ": "0x4af420", "_sound_sing": "0x4af4a0", "_sound_babble": "0x4af640", "_sound_glass": "0x4af7b0", "_sound_catmew": "0x4af7f0", "_sound_bzinkt": "0x4af8f0", "_sound_fm_sweep": "0x4af960", "_sound_pwm": "0x4afa50", "_sound_goat": "0x4afb60", "_sound_set_global_echo": "0x4afbf0", "_sound_effects_post_all": "0x4afda0", "_sound_nes_triangle": "0x4afdd0", "_swapmeet_internal_layout_ex": "0x4afe10", "_src_btn": "0x8da068", "_swapmeet_tab_layout": "0x4b00d0", "_do_mission_options_state": "0x4b00e0", "_swapmeet_swap_weapon_slots_btn": "0x4b0110", "_weapon_picker_btn": "0x4b0370", "_swapmeet_tab_locked": "0x4b0ac0", "_swapmeet_layout": "0x4b0ad0", "_last_.18966": "0x8c8920", "_last_tab": "0x4d055c", "_get_selected_charid": "0x4b0ba0", "_team_btn_char_stats": "0x4b0bf0", "_display_order": "0x4e0a40", "_old_selected": "0x8c892c", "_do_driving_options_state": "0x4b1020", "_char_get_statmod_descs.isra.0": "0x4b1040", "_team_btn_walkin": "0x4b1110", "_team_btn_speedometer": "0x4b1190", "_team_btn_fuelgauge": "0x4b1370", "_btn_radio_orders": "0x4b15c0", "_team_get_selected_button": "0x4b1620", "_selected_button": "0x8c8930", "_team_set_selected_button": "0x4b1630", "_team_plot_stat_heart": "0x4b1660", "_team_btn_char_head_lite": "0x4b1970", "___func__.19148": "0x4e09e0", "_team_btn_char_head_mode": "0x4b1ce0", "___func__.19170": "0x4e09c8", "_team_char_get_statmod_icons": "0x4b2110", "_team_btn_char_background.part.7": "0x4b2190", "_team_btn_char_background": "0x4b2240", "_team_update_char_loot_string": "0x4b2270", "___func__.19054": "0x4e0a0c", "_team_update_weapon_loot_string": "0x4b2310", "_team_char_loot_panel.part.10": "0x4b23b0", "_team_char_loot_panel": "0x4b2590", "_team_loot_orders_panel.part.11": "0x4b25b0", "_team_loot_orders_panel": "0x4b2890", "_team_btn_char_head": "0x4b28b0", "___func__.19124": "0x4e09f8", "_team_btn_char_info": "0x4b2c30", "_team_btn_char_info_chara": "0x4b2ca0", "_team_layout_char_panel_ex": "0x4b2ef0", "_team_car_info_layout": "0x4b31a0", "_team_char_loot_layout": "0x4b3240", "_team_char_stats_layout": "0x4b32b0", "_team_layout_char_panel": "0x4b3370", "_team_btn_fuel": "0x4b33a0", "_team_btn_loot": "0x4b36a0", "_team_layout_char_panel_driving": "0x4b37b0", "_team_btn_char_weapon": "0x4b3ac0", "_team_char_info_layout": "0x4b3f10", "_team_char_team_layout": "0x4b3f80", "_team_char_road_tabscreen": "0x4b41e0", "_team_char_road_tabscreen_no_esc": "0x4b4270", "_team_char_mission_trunk_tabscreen": "0x4b42f0", "_mission_trunk_tab.19406": "0x4d0558", "_team_char_mission_tabscreen": "0x4b4400", "_team_leader_charid": "0x4b4480", "_team_slot_char": "0x4b4490", "_team_leader_slot": "0x4b44b0", "_team_random": "0x4b44d0", "_team_random_order": "0x4b4540", "_team_count_loc_ex": "0x4b45f0", "_team_count_loc": "0x4b4650", "_team_count": "0x4b4670", "_team_at_loc": "0x4b4690", "_team_count_temps": "0x4b46f0", "_team_count_permanent_members": "0x4b4730", "_btn_role_text": "0x4b4760", "_btn_radio_lead_mode": "0x4b4800", "_update_weapon_info_text": "0x4b4820", "_team_btn_weapon_desc": "0x4b48d0", "_btn_radio_follow_mode": "0x4b4920", "___func__.19251": "0x4e0d84", "_btn_radio_rest_mode": "0x4b4a20", "_draw_event_icon.part.2": "0x4b4a30", "_charblurbs": "0x8c8ae0", "_draw_event_icon": "0x4b4f10", "_fill_ammo_and_fuel": "0x4b4f50", "___func__.19075": "0x4e0d9c", "_team_organize_trunk": "0x4b5050", "_team_char_equip_layout_ex": "0x4b50e0", "_move_stack_between_trunk": "0x4b53d0", "___func__.19144": "0x4e0d28", "_chara_weapon_swap_slot_with_trunk": "0x4b5670", "___func__.19178": "0x4e0d60", "_trunk_slot_btn": "0x4b5700", "_trunk_trash_btn": "0x4b5bb0", "_btn_char_weapon": "0x4b5fa0", "___func__.19222": "0x4e0d18", "_team_count_trunk_weapon": "0x4b6360", "_team_clear_trunk_weapon": "0x4b63a0", "_team_add_trunk_weapon": "0x4b63e0", "_chara_weapons_loadup": "0x4b6490", "_team_char_role_layout": "0x4b64a0", "_team_char_equip_layout": "0x4b6620", "_team_char_equip_layout_locked": "0x4b6630", "_team_draw_char_head": "0x4b6640", "_draw_character_head.part.4": "0x4b6710", "_draw_double": "0x4b6810", "_char_text_clr": "0x4b68d0", "_btn_blurb": "0x4b69c0", "_team_get_last_blurb_text": "0x4b6e90", "_last_blurbtxt": "0x8c8a60", "_team_queue_blurb": "0x4b6ea0", "_charmsg_queue": "0x8c9060", "_team_set_last_blurb_charid": "0x4b6fa0", "_team_set_last_blurb_mode": "0x4b6fc0", "_team_set_last_blurb_icon": "0x4b6fe0", "_team_set_last_blurb_tab": "0x4b7000", "_team_set_last_blurb_dur": "0x4b7020", "_team_set_last_blurb_flash": "0x4b7040", "_team_set_last_blurb_text": "0x4b7060", "_team_blurb_say": "0x4b70e0", "_team_blurb_emit": "0x4b71a0", "_team_blurb_stat_change": "0x4b7240", "_team_blurb_stat_revealed": "0x4b7460", "___func__.19452": "0x4e0cfc", "_team_blurb_loot_change": "0x4b7570", "_team_update_blurbs": "0x4b76f0", "_team_clear_blurbs": "0x4b7b60", "_team_layout_blurbs": "0x4b7ba0", "_init_.19484": "0x8c8a40", "_tile_action_default": "0x4b7cf0", "_deep_water_action": "0x4b7eb0", "_wreck_action": "0x4b7ec0", "_room_link_action": "0x4b7f80", "_tile_scroll_ex": "0x4b8240", "_orig": "0x8da0a0", "_shelf_action": "0x4b8370", "_stairs_action": "0x4b8490", "_room_door_action": "0x4b8540", "_room_link_door_action": "0x4b8640", "_shop_sign_action": "0x4b8be0", "_check_layer_hit.isra.4": "0x4b8f00", "_floor_action": "0x4b8ff0", "_wall_action": "0x4b9000", "_block_action": "0x4b9010", "_tiledef_set_colour_level": "0x4b9020", "_tile_clear_pickle": "0x4b9030", "_tile_is_pickled": "0x4b9050", "_tile_action_ex": "0x4b9080", "_tile_collides": "0x4b90e0", "_tile_action": "0x4b9120", "_tiledef_init": "0x4b9160", "_tile_wrap": "0x4b97e0", "_tile_check_solid_gfx": "0x4b9820", "_wet_draw": "0x4b98b0", "_tiledef_update": "0x4b9b40", "_btn_touch_config": "0x4b9f40", "_btn_swap_side": "0x4ba250", "_btn_stick": "0x4ba2b0", "_btn_sticky_label": "0x4ba370", "_btn_drag_slider": "0x4ba3c0", "_sticky_label.constprop.2": "0x4ba420", "_btn_reset_touch": "0x4ba930", "_update_car_lights": "0x4baef0", "_engine_effect": "0x4bb0c0", "_smoke_particle": "0x4bb500", "_car_door_sound.part.1": "0x4bb630", "_last_tick.18970": "0x8da240", "_item_vehicle_action": "0x4bb820", "_vehicle_drive_to": "0x4bcac0", "_vehicle_new": "0x4bcaf0", "_flashlight_draw": "0x4bcbc0", "_flashlight_anim_pack": "0x4bcc80", "_flashlight_anim": "0x4bcd10", "_custom_aiming_anim": "0x4bce40", "_gun_particle": "0x4bd0a0", "_bullet_particle": "0x4bd100", "_bullet_particle_update": "0x4bd160", "_cock_effect": "0x4bd180", "_chainsaw_draw": "0x4bd3e0", "_weapon_info_": "0x8da280", "_blast_handle_overlap": "0x4bd560", "___func__.19044": "0x4e124c", "_bullet_pos_solid": "0x4bd750", "_bullet_handle_overlap": "0x4bd7b0", "_weapon_melee_range.part.1": "0x4bd920", "_chainsaw_anim": "0x4bd990", "_weapondef_.constprop.3": "0x4be1b0", "___func__.18874": "0x4e1264", "_weapon_info": "0x4be3a0", "_weapon_info_writeable": "0x4be3d0", "_weapon_bullet_colour": "0x4be3e0", "_weapons_init": "0x4be700", "_weapon_sprite": "0x4be7c0", "_weapon_melee_range": "0x4be7f0", "_weapon_cooldown_time": "0x4be810", "_weapon_setup_new": "0x4be870", "_weapon_new": "0x4be8f0", "_do_bullet_check": "0x4be960", "_weapon_projectile_action": "0x4beb70", "_last_.19070": "0x8da260", "_last_.19075": "0x8da264", "_weapon_new_bullet": "0x4bf1c0", "_weapon_shoot": "0x4bf270", "_shoot_anim": "0x4bf460", "_weapon_find_id": "0x4bff70", "_weapon_is_ranged": "0x4c0010", "_weapon_is_custom_aiming": "0x4c0040", "_zombie_effect": "0x4c0060", "_particle_shake_door": "0x4c0460", "_door_furniture_check": "0x4c04b0", "_blood_bits_draw": "0x4c0540", "_blood_bits_update": "0x4c0570", "_grabby_hands.part.0": "0x4c0770", "_thump_door_tile": "0x4c0a30", "___func__.19173": "0x4e13bc", "_guts_bits_update": "0x4c0c40", "_last_.19242": "0x94b630", "_last_.19241": "0x94b634", "_zombie_smash_overlap": "0x4c0fe0", "_zombie_fall_down.part.7": "0x4c1260", "_zombie_free": "0x4c12b0", "_zombies_quiet": "0x4c12c0", "_zquiet": "0x94b640", "_zombie_sound": "0x4c12d0", "_last_.19041": "0x94b63c", "_zombie_randtype": "0x4c1540", "_zombie_draw": "0x4c15b0", "_zombie_bite": "0x4c1a70", "_last_.19122": "0x94b638", "_zombie_try_shove": "0x4c1b90", "_zombie_try_attack": "0x4c1de0", "_pos_particle": "0x4c2040", "_zombie_bang_door": "0x4c20a0", "_zombie_set_target": "0x4c2590", "_is_on_stairs": "0x4c28b0", "_zombie_slosh_out_some_guts": "0x4c28f0", "_zombie_slosh_out_some_bones_ex": "0x4c2ae0", "_zombie_slosh_out_some_bones": "0x4c2e70", "_game_blood_spray": "0x4c2ea0", "_game_blood_drop": "0x4c3020", "_zombie_max_for_room": "0x4c31b0", "_zombie_fall_down": "0x4c3210", "_zombie_calc_state": "0x4c3240", "_zombie_picklespawn_at_tilepos": "0x4c3260", "_zombie_is_fallen": "0x4c32f0", "_zombie_set_state": "0x4c3310", "_zombie_new": "0x4c3390", "_zombie_tile_try_unpickle": "0x4c34d0", "_zombie_hit": "0x4c36b0", "_zombie_generic_hit": "0x4c3a30", "_last_.19365": "0x94b624", "_zombie_update": "0x4c3bc0", "_last_.19397": "0x94b62c", "_last_.19398": "0x94b628", "_zombie_action": "0x4c5030", "_last_.19382": "0x94b620", "___func__.19415": "0x4e13ac", "_func_alert_zombie": "0x4c5650", "_zombie_pos_alert_here": "0x4c5840", "_zombie_activity_time": "0x4c5920", "_zombie_set_activity_time": "0x4c5930", "_zombie_target_enemy": "0x4c5940", "_is_zombie_pos_clear.isra.1": "0x4c5a00", "_zombie_ai_item_bump": "0x4c5b10", "_zombie_ai_bro_bump": "0x4c5c00", "_zombie_ai": "0x4c5c10", "_last_.18973": "0x94b644", "__setargv": "0x4c6e80", "___cpu_features_init": "0x4c7220", "_main": "0x4cfe30", ".text.startup": "0x4cff00", "___do_global_dtors": "0x4c7330", "___do_global_ctors": "0x4c7360", "___main": "0x4c73b0", "___dyn_tls_init@12": "0x4c7420", "___tlregdtor": "0x4c74b0", ".CRT$XDZ": "0xa3e014", ".CRT$XDA": "0xa3e010", ".CRT$XLA": "0xa3e000", ".tls$ZZZ": "0xa3f01c", ".tls$AAA": "0xa3f000", "____w64_mingwthr_add_key_dtor": "0x4c7520", "____w64_mingwthr_remove_key_dtor": "0x4c75b0", "___mingw_TLScallback": "0x4c7650", "__pei386_runtime_relocator": "0x4c7830", "_console_main": "0x4c7a00", "_WinMain@16": "0x4c7a30", ".debug_info": "0xa487f9", ".debug_abbrev": "0xa4a905", ".debug_loc": "0xa4ef37", ".debug_aranges": "0xa40098", ".debug_ranges": "0xa50108", ".debug_line": "0xa4b7e4", ".debug_frame": "0xa4c068", ".idata$7": "0xa3d978", ".idata$5": "0xa3c7b4", ".idata$4": "0xa3c428", ".idata$6": "0xa3c858", "_emutls_destroy": "0x4c7fb0", "_emutls_alloc": "0x4c7ff0", "_emutls_init": "0x4c8090", "_emutls_mutex": "0x94b698", "_emutls_key": "0x94b694", "___emutls_get_address": "0x4c8100", "_once.35325": "0x4d0610", "_emutls_size": "0x94b690", "___emutls_register_common": "0x4c8370", ".debug_str": "0xa4d000", "_fesetenv": "0x4c83c0", "_sinf": "0x4c8430", "_ceilf": "0x4c8458", "_floorf": "0x4c8484", "_fmodf": "0x4c84b0", "_roundf": "0x4c84d0", "_sqrtf": "0x4c8560", "___mingw_snprintf": "0x4c85a0", "_snprintf": "0x4c85a0", "___mingw_vsnprintf": "0x4c85d0", "_vsnprintf": "0x4c85d0", "___mingw_glob": "0x4c9580", "___mingw_globfree": "0x4c9670", "___mingw_dirname": "0x4c96d0", "___mingw_opendir": "0x4c9c50", "___mingw_readdir": "0x4c9e10", "___mingw_closedir": "0x4c9e60", "___mingw_rewinddir": "0x4c9eb0", "___mingw_telldir": "0x4c9f10", "___mingw_seekdir": "0x4c9f40", "_nanf": "0x4c9fc0", "___fpclassifyf": "0x4c9fd0", "___mingw_pformat": "0x4cbb80", "_mbrtowc": "0x4ccc80", "_mbsrtowcs": "0x4ccd20", "_mbrlen": "0x4cce90", "_wcrtomb": "0x4ccfc0", "_wcsrtombs": "0x4cd040", "___gdtoa": "0x4cd1b0", "___rshift_D2A": "0x4ce7e0", "___trailz_D2A": "0x4ce900", "___rv_alloc_D2A": "0x4ce940", "___nrv_alloc_D2A": "0x4ce980", "___freedtoa": "0x4cea00", "___quorem_D2A": "0x4cea20", "___Balloc_D2A": "0x4ced30", "___Bfree_D2A": "0x4cee00", "___multadd_D2A": "0x4cee70", "___i2b_D2A": "0x4cef60", "___mult_D2A": "0x4cef90", "___pow5mult_D2A": "0x4cf100", "___lshift_D2A": "0x4cf270", "___cmp_D2A": "0x4cf390", "___diff_D2A": "0x4cf3e0", "___b2d_D2A": "0x4cf5c0", "___d2b_D2A": "0x4cf6c0", "___strcp_D2A": "0x4cf7b0", "___mingwthr_remove_key_dtor": "0x4cfb60", "___mingwthr_key_dtor": "0x4cfb70", "___udivdi3": "0x4cfb90", "___umoddi3": "0x4cfcb0", "___FRAME_END__": "0x50a6d8", "___JCR_END__": "0x4d0634", "_register_frame_ctor": "0x4cff00", ".ctors.65535": "0x4cff14", ".idata$2": "0xa3c078", "_memmove": "0x4cf8f8", "_Mix_PlayMusic": "0x4c7e88", "_eventcards": "0x86b9fc", "_male_hats": "0x86b9b8", "_hmod_libgcc": "0x94c060", "_edit_building_state": "0x4d0384", "_male_hair_parts": "0x86b9a0", "_special_chars": "0x86b96c", "__setjmp": "0x4cf9f8", "_mad_settings": "0x94c8e0", "_game_no_collision": "0x7caa34", "___tls_start__": "0xa3f000", "___crt_xt_end__": "0xa3e010", "_inside_tiles_base_id": "0x86b904", "_game_debug_log_mode": "0x86ba58", "_camera": "0xa0a540", "_inside_objects_base_id": "0x86b8e8", "_tolower": "0x4cf810", "_fgetc": "0x4cf990", "__rt_psrelocs_start": "0x4e2dfc", "_test_dude": "0xa3b3f0", "__tls_start": "0xa3f000", "___SNANF": "0x4e1660", "__imp__Mix_LoadMUS": "0xa3c774", "_calloc": "0x4cf9b8", "_view": "0x95cc74", "_SDL_StartTextInput": "0x4c7cb0", "__imp__EnterCriticalSection@4": "0xa3c434", "__libmoldname_a_iname": "0xa3d654", "_atof": "0x4cf9c8", "__imp__glLoadIdentity@0": "0xa3c654", "__end__": "0xa40000", "_Mix_Resume": "0x4c7e78", "_wcslen": "0x4cf7e8", "_localtime": "0x4cf920", "_main_state": "0x4d047c", "_skeletonbits_base_id": "0x86b864", "__imp___pctype": "0xa3c504", "__imp__SDL_GetDisplayBounds": "0xa3c6d8", "__imp__SDL_EnableScreenSaver": "0xa3c698", "__rt_psrelocs_end": "0x4e2dfc", "_TlsAlloc@0": "0x4cfa88", "_female_body_parts": "0x86b950", "_WideCharToMultiByte@32": "0x4cfa58", "_roadscene_count": "0x86b87c", "_sprintf": "0x4cf898", "__imp__fprintf": "0xa3c550", "__imp__sprintf": "0xa3c5bc", "_SDL_SetMainReady": "0x4c7ce0", "___crt_xc_end__": "0xa3e000", "_game_debug_no_follow": "0x7d0ce0", "__errno": "0x4cfa18", "_memcpy": "0x4cf900", "_code_soft_exit_inner_": "0x4d0224", "_SDL_QuitSubSystem": "0x4c7d08", "__imp__glMatrixMode@4": "0xa3c658", "_glOrtho@48": "0x4c7f00", "_LoadLibraryA@4": "0x4cfab8", "__imp__SDL_GameControllerAddMappingsFromRW": "0xa3c6b4", "__imp__GetStartupInfoA@4": "0xa3c460", "_glScissor@16": "0x4c7ef0", "__imp__fseek": "0xa3c560", "__imp__InterlockedExchange@8": "0xa3c46c", "_wcstombs": "0x4cf7e0", "_game_running_mission_state": "0x4d0400", "__imp__wcslen": "0xa3c614", "__imp__SDL_QuitSubSystem": "0xa3c728", "_remap_state4": "0x4d050c", "_locationdef_info": "0x4d043c", "__imp__SDL_GetDisplayMode": "0xa3c6dc", "__imp___beginthreadex": "0xa3c4dc", "__DTOR_LIST__": "0x4cff1c", "___crt_xp_end__": "0xa3e010", "__imp__glColorPointer@16": "0xa3c630", "__tls_end": "0xa3f01c", "__imp__GetProcAddress@8": "0xa3c45c", "_glTexParameteri@12": "0x4c7ed8", "_strncat": "0x4cf850", "_LeaveCriticalSection@4": "0x4cfac0", "_SDL_SetWindowFullscreen": "0x4c7cd8", "_sin": "0x4cf8a0", "_glyphs_set": "0x7caa20", "_main_common_page_return_override_": "0xa0a564", "___crt_xl_start__": "0xa3e000", "__imp__ExitProcess@4": "0xa3c438", "__flsbuf": "0x4cfa10", "_fclose": "0x4cf9a0", "_InitializeCriticalSection@4": "0x4cfae8", "_EnterCriticalSection@4": "0x4cfb40", "_weapons": "0x86b9e8", "_building_tiles": "0x86ba34", "__CRT_fmode": "0x94b648", "_special_objects16_base_id": "0x86b8e4", "__imp__DeleteCriticalSection@4": "0xa3c430", "__imp__mbstowcs": "0xa3c584", "_game_ticks": "0x7caa40", "_strstr": "0x4cf830", "__imp__sin": "0xa3c5b8", "_Sleep@4": "0x4cfa90", "_assert_msg_": "0x86b82c", "__CRT_fenv": "0x4d0604", "__imp__glEnableClientState@4": "0xa3c648", "_male_beard_parts_extra": "0x86b984", "_SDL_GL_GetDrawableSize": "0x4c7e18", "_last_thing": "0x7caa2c", "_SDL2_mixer_dll_iname": "0xa3d958", "__imp__toupper": "0xa3c604", "_strlen": "0x4cf858", "_charsave_state": "0x4d02a0", "_male_hair_parts_extra": "0x86b99c", "__imp__FreeLibrary@4": "0xa3c448", "__imp__Mix_CloseAudio": "0xa3c76c", "_ReleaseSemaphore@12": "0x4cfaa8", "_dirs4xy8": "0x4d621c", "_CreateSemaphoreW@16": "0x4cfb50", "__imp__InitializeCriticalSection@4": "0xa3c464", "_male_bodies": "0x86b9b4", "_DeleteCriticalSection@4": "0x4cfb48", "_error_title": "0x95cc80", "__imp__steam_api_init": "0xa3c7a4", "_game_start_mission_state": "0x4d0410", "_strrchr": "0x4cf838", "__imp__fmod": "0xa3c548", "_strncmp": "0x4cf848", "_exit": "0x4cf9a8", "_inside_tiles_walls_blank_id": "0x86b8f8", "_realloc": "0x4cf8c0", "_perror": "0x4cf8e8", "_main_state_reenter": "0x4d045c", "_error_jumpenv_buffer": "0x94c080", "__imp__steam_api_persona_name": "0xa3c7a8", "_SDL_GetVersion": "0x4c7d88", "_mouse_click_right": "0x86b844", "_strerror": "0x4cf860", "__imp__SDL_Quit": "0xa3c724", "_fseek": "0x4cf950", "_total_sprites_count": "0x86b85c", "_game_debug_zoom_mode": "0x7caa50", "_SDL_HasClipboardText": "0x4c7d78", "_SDL_GameControllerEventState": "0x4c7de0", "_game_debug_spy": "0x86ba68", "_WaitForSingleObject@8": "0x4cfa60", "__head_libopengl32_a": "0xa3c03c", "_glEnableClientState@4": "0x4c7f28", "_vfprintf": "0x4cf7f8", "_keyevent": "0x94c0c0", "__imp__SDL_SetMainReady": "0xa3c73c", "_cars_base_id": "0x86b898", "__imp__glScalef@12": "0xa3c660", "__imp__FindNextFileA@8": "0xa3c444", "_zombies": "0x86b9f0", "__imp__SDL_CreateThread": "0xa3c684", "_pets24_id": "0x86b8d0", "_code_soft_interpreter": "0x4d0234", "_dirs4xy": "0x4d5e60", "___tls_end__": "0xa3f020", "__imp__SetUnhandledExceptionFilter@4": "0xa3c48c", "_settings": "0xa0a580", "__head_libmoldname_a": "0xa3c014", "_fread": "0x4cf960", "__imp__GetCommandLineW@0": "0xa3c450", "_fputc": "0x4cf968", "_GetCommandLineA@0": "0x4cfb10", "_glViewport@16": "0x4c7ec0", "_male_beard_parts": "0x86b988", "__head_SDL2_dll": "0xa3c050", "_driving_state": "0x4d0364", "_inside_tiles_doors_id": "0x86b8f0", "_error_state": "0x4d03dc", "__imp__perror": "0xa3c594", "_special_chars_base_id": "0x86b8b8", "_touch_setup_state": "0x4d0560", "_strcpy": "0x4cf868", "__imp__fread": "0xa3c558", "_memset": "0x4cf8f0", "__imp__InterlockedIncrement@4": "0xa3c470", "__imp__IsDBCSLeadByteEx@8": "0xa3c474", "__imp__fopen": "0xa3c54c", "__imp__InterlockedDecrement@4": "0xa3c468", "__snprintf": "0x4cf9e8", "_localeconv": "0x4cf928", "__imp__strtol": "0xa3c5f4", "__bss_end__": "0xa3b45c", "_female_hats": "0x86b974", "_trees_base_id": "0x86b878", "_mrand_seed": "0x566f60", "_quit_state": "0x4d046c", "__CTOR_LIST__": "0x4cff10", "__imp__atan2": "0xa3c51c", "__imp__Mix_RegisterEffect": "0xa3c788", "__imp__pow": "0xa3c598", "_SDL_GetDisplayMode": "0x4c7da0", "_ungetc": "0x4cf800", "__assert": "0x4cfa38", "__imp__SDL_wcslen": "0xa3c764", "_SDL_GameControllerGetAttached": "0x4c7dd8", "__imp__strerror": "0xa3c5d8", "__argc": "0x50b004", "__imp__SDL_iconv_string": "0xa3c758", "_female_hat_parts_extra": "0x86b95c", "_special_objects96_base_id": "0x86b8d4", "_female_body_parts_extra": "0x86b94c", "_SDL_GameControllerOpen": "0x4c7db8", "_female_glasses_parts_extra": "0x86b944", "__imp____mb_cur_max": "0xa3c4c8", "__imp__strncat": "0xa3c5e0", "__libopengl32_a_iname": "0xa3d824", "___crt_xc_start__": "0xa3e000", "_street_objects": "0x86ba1c", "__imp__atexit": "0xa3c520", "_SDL_GL_SetSwapInterval": "0x4c7e00", "_puts": "0x4cf8d0", "___RUNTIME_PSEUDO_RELOC_LIST_END__": "0x4e2dfc", "_inside_tiles_walltops_id": "0x86b900", "__imp__SDL_JoystickGetAttached": "0xa3c700", "_glMatrixMode@4": "0x4c7f08", "_zombie_heads_base_id": "0x86b8bc", "__imp__FindClose@4": "0xa3c43c", "_female_hair": "0x86b97c", "_male_heads": "0x86b9c8", "_glypher_shadow": "0x7caa38", "__imp__asctime": "0xa3c518", "_main_state_timestamp": "0x86ba74", "__RUNTIME_PSEUDO_RELOC_LIST__": "0x4e2dfc", "__imp__strlen": "0xa3c5dc", "_debug_paused": "0x86b830", "__imp__glViewport@16": "0xa3c67c", "__imp__SDL_GameControllerOpen": "0xa3c6d0", "__imp__SDL_JoystickOpen": "0xa3c718", "__imp__memset": "0xa3c590", "_street_tiles_base_id": "0x86b910", "_atoi": "0x4cf9c0", "___p__fmode": "0x4cfa40", "___INFF": "0x4e1650", "_female_bodies": "0x86b970", "_remap_state3": "0x4d051c", "_zombie_head_count": "0x86b9d0", "_SDL_GetClipboardText": "0x4c7db0", "_particles32": "0x86ba04", "__imp__SDL_GameControllerGetJoystick": "0xa3c6c8", "_abort": "0x4cf9e0", "_special_chars48_base_id": "0x86b8b0", "_inside_tiles": "0x86ba18", "__imp___setmode": "0xa3c50c", "__imp__steam_api_set_achievement": "0xa3c7ac", "_glClear@4": "0x4c7f68", "_trip_position": "0x79cb70", "_skin_pal": "0xa0acc0", "__imp__free": "0xa3c55c", "__imp__Mix_PauseMusic": "0xa3c780", "_SDL_SetWindowPosition": "0x4c7cd0", "_FindNextFileA@8": "0x4cfb20", "___cpu_features": "0x94b64c", "_GetModuleHandleA@4": "0x4cfb00", "__data_end__": "0x4d0638", "__imp__SetLastError@4": "0xa3c488", "_base_scale": "0x4d04a8", "_qsort": "0x4cf8c8", "___QNANF": "0x4e1670", "_glTexImage2D@36": "0x4c7ee0", "_SDL_ShowCursor": "0x4c7cb8", "_building_tiles_base_id": "0x86b928", "_strcat": "0x4cf888", "__imp__TlsSetValue@8": "0xa3c49c", "_weapon_funcs": "0xa3b420", "__imp__atof": "0xa3c524", "_strchr": "0x4cf880", "__imp__strncpy": "0xa3c5e8", "_male_beards": "0x86b9bc", "_cars_unique_base_id": "0x86b890", "__imp__strcat": "0xa3c5c4", "_Mix_VolumeMusic": "0x4c7e58", "__imp__SDL_GameControllerGetAttached": "0xa3c6c0", "_customize_reenter_state": "0x4d0270", "_building_misc_tiles": "0x86ba30", "__imp__strcmp": "0xa3c5cc", "__head_libmsvcrt_a": "0xa3c028", "_vsprintf": "0x4cf7f0", "_mouse_click_mid": "0x86b848", "_glVertexPointer@16": "0x4c7ec8", "_map_anchor": "0x8a880c", "_glScalef@12": "0x4c7ef8", "_remove": "0x4cf8b8", "__imp___cexit": "0xa3c4e0", "_city_florida_tiles": "0x86ba28", "__bss_start__": "0x50b000", "__imp__glClearColor@16": "0xa3c62c", "_options_state": "0x4d04bc", "_fmod": "0x4cf980", "_slowmo": "0x86ba48", "__imp__glDisable@4": "0xa3c638", "_mingw_initltssuo_force": "0x94b654", "___xl_z": "0xa3e00c", "_male_glasses": "0x86b9c0", "__imp__SDL_GL_GetDrawableSize": "0xa3c6a0", "_main_state_reenter_select": "0x4d044c", "__imp__SDL_JoystickNumButtons": "0xa3c714", "_title": "0x86b9f8", "_team_chara_weapon_info_text": "0x8c8940", "_mouse_click": "0x86b84c", "_SDL_GL_CreateContext": "0x4c7e20", "_cur_timer_": "0x7caa28", "_glTexCoordPointer@16": "0x4c7ee8", "_sprites_base_id": "0x86b934", "_GetProcAddress@8": "0x4cfaf8", "__imp__SDL_JoystickGetAxis": "0xa3c704", "_things": "0x95d4e0", "_screen_touch": "0x86b838", "__imp__SDL_GL_SetSwapInterval": "0xa3c6ac", "_tiles_base_id": "0x86b930", "__imp__strrchr": "0xa3c5ec", "__RUNTIME_PSEUDO_RELOC_LIST_END__": "0x4e2dfc", "_zombie_heads": "0x86b9ec", "__head_libkernel32_a": "0xa3c000", "__imp__atoi": "0xa3c528", "__imp__SDL_IsGameController": "0xa3c6f8", "_scaled_w": "0x86b940", "__imp__fflush": "0xa3c53c", "_game_debug_vis": "0x86ba70", "_particles_base_id": "0x86b88c", "__imp__MultiByteToWideChar@24": "0xa3c480", "_SDL_GameControllerClose": "0x4c7de8", "_gnomes_base_id": "0x86b868", "__imp__Mix_Resume": "0xa3c78c", "_mingw_initltsdrot_force": "0x94b65c", "__imp__vsprintf": "0xa3c610", "_glDisable@4": "0x4c7f48", "_rand1": "0x79cb68", "_Mix_ResumeMusic": "0x4c7e70", "_SDL_malloc": "0x4c7c98", "_game_characters": "0x4d0424", "_roadscene_base_id": "0x86b880", "_main_options_return_override_": "0xa0b0c4", "__imp__sscanf": "0xa3c5c0", "__imp__SDL_SetClipboardText": "0xa3c734", "_debug_no_zomb": "0x86ba50", "__imp__glBindTexture@8": "0xa3c620", "__imp__realloc": "0xa3c5a8", "_cyoa_state": "0x4d0354", "_game_debug_profiling": "0x86ba54", "_SDL_GameControllerGetAxis": "0x4c7dd0", "_glColorPointer@16": "0x4c7f58", "__imp__signal": "0xa3c5b4", "_SDL_Delay": "0x4c7e40", "_MultiByteToWideChar@24": "0x4cfab0", "_SDL_Quit": "0x4c7d10", "_inside_tiles_walls_id": "0x86b8fc", "_SDL_SetClipboardText": "0x4c7cf0", "_eventcards_base_id": "0x86b874", "_driving_state_resume": "0x4d0374", "_SDL_GL_SwapWindow": "0x4c7df8", "__imp__CreateSemaphoreW@16": "0xa3c42c", "_SDL_IsGameController": "0x4c7d68", "_SDL_GameControllerGetStringForButton": "0x4c7dc0", "__imp__SDL_GetWindowSize": "0xa3c6ec", "___crt_xt_start__": "0xa3e010", "__imp__SDL_GameControllerGetStringForButton": "0xa3c6cc", "__imp____p__environ": "0xa3c4cc", "_male_hair": "0x86b9c4", "__imp__TlsAlloc@0": "0xa3c494", "_cursor_timeout": "0x4d0340", "_ftell": "0x4cf948", "__imp__tolower": "0xa3c600", "_special_chars48_count": "0x86b8ac", "_trip_duration": "0x79cb6c", "_perkntrait_state": "0x4d04dc", "_special_objects32_base_id": "0x86b8e0", "__imp__SDL_NumJoysticks": "0xa3c71c", "_tab": "0x7caa00", "__tls_index": "0x94b660", "__imp__glTexCoordPointer@16": "0xa3c668", "_keys": "0x94c140", "_strtol": "0x4cf828", "__imp___setjmp": "0xa3c508", "_items": "0x86b9e4", "_SDL_GameControllerGetJoystick": "0x4c7dc8", "_female_glasses": "0x86b978", "__imp__SDL_malloc": "0xa3c760", "__imp__glVertexPointer@16": "0xa3c678", "_weapons16_base_id": "0x86b8a0", "_zombie_body_count": "0x86b9cc", "__imp__SDL_RWFromFile": "0xa3c72c", "_intro_base_id": "0x86b86c", "_session": "0xa0b0e0", "_SDL_JoystickInstanceID": "0x4c7d48", "_glEnable@4": "0x4c7f30", "_glDisableClientState@4": "0x4c7f40", "_Mix_LoadMUS": "0x4c7ea8", "_malloc": "0x4cf910", "_Mix_RewindMusic": "0x4c7e68", "__imp__ungetc": "0xa3c608", "_fprintf": "0x4cf970", "__imp__SDL_DestroyWindow": "0xa3c690", "_team_weapon_info_text": "0x8c89c0", "_joy_state_": "0x94c1c0", "_SDL2_dll_iname": "0xa3d918", "_game_over_state": "0x4d03f0", "_error_string": "0x95cce0", "__imp__SDL_DisableScreenSaver": "0xa3c694", "_female_hat_parts": "0x86b960", "__imp__Mix_VolumeMusic": "0xa3c79c", "___bigtens_D2A": "0x4e1aa0", "__imp__SDL_JoystickInstanceID": "0xa3c708", "__head_SDL2_mixer_dll": "0xa3c064", "_fwrite": "0x4cf940", "_glBindTexture@8": "0x4c7f78", "___CTOR_LIST__": "0x4cff10", "__setmode": "0x4cf9f0", "_pets24_count": "0x86b8cc", "_cars": "0x86b9e0", "__imp__glClear@4": "0xa3c628", "_roomdef_info": "0x4d054c", "_SDL_SetWindowTitle": "0x4c7cc0", "__fullpath": "0x4cfa08", "_female_head_parts": "0x86b968", "_ExitProcess@4": "0x4cfb38", "_mouse_down": "0x86b840", "_SDL_RestoreWindow": "0x4c7cf8", "_fopen": "0x4cf978", "_skeletons": "0x86b9f4", "_steam_api_store_stats": "0x4cfe20", "__imp__GetCommandLineA@0": "0xa3c44c", "__imp__ftell": "0xa3c564", "__imp___snprintf": "0xa3c510", "_glDrawElements@16": "0x4c7f38", "_male_glasses_parts_extra": "0x86b98c", "_glGenTextures@8": "0x4c7f20", "___getmainargs": "0x4cfa50", "_Mix_Pause": "0x4c7e98", "___crt_xp_start__": "0xa3e010", "__imp__glTexSubImage2D@36": "0xa3c674", "_Mix_SetMusicPosition": "0x4c7e60", "_houses_tiles_base_id": "0x86b914", "__imp__strcoll": "0xa3c5d0", "_TlsSetValue@8": "0x4cfa78", "_TITLE_BAR_SPRITE": "0x4d5cdc", "_SetLastError@4": "0x4cfaa0", "__imp__qsort": "0xa3c5a4", "_weapons_base_id": "0x86b8a4", "_strdup": "0x4c83b0", "_rand2": "0x79cb64", "_cyoa_state_resume": "0x4d0344", "__imp__WideCharToMultiByte@32": "0xa3c4ac", "__imp__SDL_isspace": "0xa3c75c", "_VirtualProtect@16": "0x4cfa70", "__imp__SDL_SetWindowPosition": "0xa3c744", "__imp__SDL_GameControllerGetAxis": "0xa3c6c4", "_getenv": "0x4cf938", "__imp___errno": "0xa3c4e8", "__imp__glOrtho@48": "0xa3c65c", "__imp____getmainargs": "0xa3c4c4", "_console_popup_": "0x86b858", "_mouse_state": "0x94c7a0", "_glLoadIdentity@0": "0x4c7f10", "__imp__SDL_Init": "0xa3c6f4", "_glyphs": "0x86ba40", "_free": "0x4cf958", "_zombie_head_parts": "0x86b9d8", "__imp__WaitForSingleObject@8": "0xa3c4a8", "__imp__fputc": "0xa3c554", "_code_soft_exit_inner": "0x4d0220", "_signal": "0x4cf8a8", "_glyphs_base_id": "0x86b938", "__imp____set_app_type": "0xa3c4d4", "_tile_info_": "0xa39da0", "_male_hat_parts_extra": "0x86b9a4", "_glTexSubImage2D@36": "0x4c7ed0", "__tls_used": "0xa3f004", "__imp__GetModuleHandleA@4": "0xa3c458", "__imp__SDL_GetNumDisplayModes": "0xa3c6e0", "___chkstk_ms": "0x4c7f80", "_pow": "0x4cf8e0", "_male_head_parts_extra": "0x86b9ac", "__imp__glScissor@16": "0xa3c664", "__imp__puts": "0xa3c5a0", "_particles32_base_id": "0x86b888", "_dirs8xy8": "0x4d620c", "_special_chars_count": "0x86b8b4", "_longjmp": "0x4cf918", "_FindClose@4": "0x4cfb30", "_fflush": "0x4cf998", "__imp__SDL_HasClipboardText": "0xa3c6f0", "__imp__SDL_GetTicks": "0xa3c6e4", "_code_table": "0x95b160", "_SDL_GetNumDisplayModes": "0x4c7d98", "_game_debug_zombfall": "0x7d0cec", "_charload_state": "0x4d0290", "__imp__SDL_Delay": "0xa3c68c", "_mingw_initltsdyn_force": "0x94b658", "_strncpy": "0x4cf840", "__sine_table": "0x94c920", "__imp__SDL_SetWindowTitle": "0xa3c74c", "__imp__SDL_ShowCursor": "0xa3c750", "_car_wrecks_base_id": "0x86b894", "__imp__glTexImage2D@36": "0xa3c66c", "_female_heads": "0x86b980", "__imp__SDL_GL_SetAttribute": "0xa3c6a8", "_asctime": "0x4cf9d8", "___tens_D2A": "0x4e19a0", "_female_glasses_parts": "0x86b948", "__imp__exit": "0xa3c534", "_skeletons_base_id": "0x86b8a8", "__imp__Mix_RewindMusic": "0xa3c794", "_game_debug_nozomb": "0x7d0ce8", "_intro_state": "0x4d042c", "_main_tabscreen_exit_btn": "0x86b820", "_FindFirstFileA@8": "0x4cfb28", "_SDL_isspace": "0x4c7ca0", "_SDL_JoystickGetAttached": "0x4c7d58", "_SDL_JoystickGetAxis": "0x4c7d50", "__imp__memcpy": "0xa3c588", "_ldexp": "0x4cf930", "_cursor_mode": "0x79ca60", "_GetLastError@0": "0x4cfb08", "__imp__memmove": "0xa3c58c", "_items_base_id": "0x86b89c", "__imp__strcpy": "0xa3c5d4", "_SDL_NumJoysticks": "0x4c7d20", "__imp__GetLastError@0": "0xa3c454", "_game_debug_crash_mode": "0x86ba5c", "_male_glasses_parts": "0x86b990", "___p__environ": "0x4cfa48", "__imp__remove": "0xa3c5ac", "__imp__TlsGetValue@4": "0xa3c498", "_SDL_GL_MakeCurrent": "0x4c7e10", "_glBlendFunc@8": "0x4c7f70", "___RUNTIME_PSEUDO_RELOC_LIST__": "0x4e2dfc", "__imp__Mix_OpenAudio": "0xa3c778", "__imp__LoadLibraryA@4": "0xa3c47c", "__CRT_glob": "0x4d0600", "__imp__localeconv": "0xa3c574", "__imp__SDL_StartTextInput": "0xa3c754", "_city_florida_tiles_base_id": "0x86b91c", "__imp__glGenTextures@8": "0xa3c64c", "_edit_state": "0x4d0398", "_mouse_down_right": "0x86b83c", "__imp__SDL_JoystickName": "0xa3c70c", "_SDL_GetDisplayBounds": "0x4c7da8", "__imp__SDL_GL_CreateContext": "0xa3c69c", "_filmgrain_id": "0x86b870", "_madgarden_id": "0x86b860", "_SDL_JoystickName": "0x4c7d40", "_pause_state": "0x4d04cc", "_InterlockedDecrement@4": "0x4cfae0", "__imp__printf": "0xa3c59c", "_SDL_DisableScreenSaver": "0x4c7e30", "_main_edit_focus_button": "0x86b828", "_syn_stages_active": "0x6a6fc4", "_pets48_id": "0x86b8c8", "__imp__localtime": "0xa3c578", "__imp__getenv": "0xa3c56c", "_city_generic_tiles_base_id": "0x86b920", "__imp__SDL_GL_SwapWindow": "0xa3c6b0", "_Mix_OpenAudio": "0x4c7ea0", "__libkernel32_a_iname": "0xa3d638", "_premission_state": "0x4d04fc", "__imp__glDeleteTextures@8": "0xa3c634", "_debug_display": "0x7caa54", "__imp__system": "0xa3c5f8", "_roadscene": "0x86b9dc", "_city_carolina_tiles": "0x86ba24", "_last_thingid": "0x7caa30", "_male_body_parts_extra": "0x86b994", "_FreeLibrary@4": "0x4cfb18", "__imp__SDL_RestoreWindow": "0xa3c730", "_SDL_EnableScreenSaver": "0x4c7e28", "__imp___fpreset": "0xa3c4f0", "_male_body_parts": "0x86b998", "_floor": "0x4cf988", "_mkdir": "0x4c83b8", "_special_objects48_base_id": "0x86b8dc", "_SDL_JoystickClose": "0x4c7d60", "_zombie_body_parts": "0x86b9d4", "_debug_trace_on": "0x86ba44", "_steam_wrapper_dll_iname": "0xa3d978", "_hair_pal": "0xa39900", "_global_scale": "0x4d04ac", "__imp____p__fmode": "0xa3c4d0", "_SDL_GetTicks": "0x4c7d90", "__imp__SDL_GameControllerEventState": "0xa3c6bc", "_toupper": "0x4cf808", "_street_tiles": "0x86ba20", "_steam_api_set_achievement": "0x4cfe18", "___crt_xi_end__": "0xa3e000", "_game_debug_ai_control": "0x86ba64", "_IsDBCSLeadByteEx@8": "0x4cfac8", "__imp__glGetError@0": "0xa3c650", "_inside_tiles_floors_id": "0x86b8f4", "__imp__FindFirstFileA@8": "0xa3c440", "__imp__fwrite": "0xa3c568", "_dirs": "0x4d5e80", "_SDL_PollEvent": "0x4c7d18", "__imp__Mix_ResumeMusic": "0xa3c790", "_TlsGetValue@4": "0x4cfa80", "_main_tabscreen_start_btn": "0x86b824", "_male_hat_parts": "0x86b9a8", "__imp__glTexParameteri@12": "0xa3c670", "_mad_ticks": "0x52f320", "__imp__strstr": "0xa3c5f0", "_turtle": "0x4d00c0", "_inside_tiles_shelves_id": "0x86b8ec", "_dirs8xy": "0x4d5e20", "_SDL_RWFromFile": "0x4c7d00", "_setlocale": "0x4cf8b0", "_SDL_CreateThread": "0x4c7e50", "_female_head_parts_extra": "0x86b964", "__imp___onexit": "0xa3c500", "__imp___iob": "0xa3c4f8", "_strcoll": "0x4cf870", "_city_carolina_tiles_base_id": "0x86b918", "_sscanf": "0x4cf890", "__imp___assert": "0xa3c4d8", "_InterlockedIncrement@4": "0x4cfad0", "_SDL_SetWindowSize": "0x4c7cc8", "_Mix_CloseAudio": "0x4c7eb8", "__imp__strncmp": "0xa3c5e4", "_font6x8": "0xa39d04", "_game_debug_ai_vis": "0x86ba6c", "_SDL_wcslen": "0x4c7c90", "_game_thing_last_fx": "0x7caa24", "_SDL_CreateWindow": "0x4c7e48", "_InterlockedExchange@8": "0x4cfad8", "_street_tiles_id": "0x86b90c", "_SDL_DestroyWindow": "0x4c7e38", "__head_steam_wrapper_dll": "0xa3c078", "_filer_driver": "0x4d0008", "__data_start__": "0x4d0000", "__isctype": "0x4cfa00", "_game_debug_ai_off": "0x86ba60", "__imp__Mix_PlayMusic": "0xa3c784", "__imp__SDL_SetWindowFullscreen": "0xa3c740", "__imp__ldexp": "0xa3c570", "_mbstowcs": "0x4cf908", "___mingw_output_format_flags": "0x94b6a4", "_SDL_GL_SetAttribute": "0x4c7e08", "__imp__strchr": "0xa3c5c8", "_icons16_id": "0x86b884", "__imp__Mix_Pause": "0xa3c77c", "_script_sys": "0xa39d20", "_male_head_parts": "0x86b9b0", "_female_hair_parts_extra": "0x86b954", "__imp__VirtualQuery@12": "0xa3c4a4", "___xl_a": "0xa3e000", "_game_debug_no_pathfinding": "0x7caa4c", "_console_state": "0x4d02d0", "_VirtualQuery@12": "0x4cfa68", "__imp__fgetc": "0xa3c540", "__endthreadex": "0x4cfa20", "_strcmp": "0x4cf878", "_city_generic_tiles": "0x86ba2c", "_female_hair_parts": "0x86b958", "__imp__SDL_GetVersion": "0xa3c6e8", "__imp__strdup": "0xa3c4b8", "_printf": "0x4cf8d8", "_time": "0x4cf818", "__imp__ReleaseSemaphore@12": "0xa3c484", "_game_debug_no_handle_overlap": "0x7caa44", "__imp__stricoll": "0xa3c4bc", "__imp__Mix_SetMusicPosition": "0xa3c798", "__imp__vfprintf": "0xa3c60c", "__imp__time": "0xa3c5fc", "__imp___isctype": "0xa3c4fc", "_angle_ticks": "0x7caa3c", "_SDL_GameControllerAddMappingsFromRW": "0x4c7df0", "_GetStartupInfoA@4": "0x4cfaf0", "__CRT_MT": "0x94b68c", "_special_objects32": "0x86ba10", "__cexit": "0x4cfa28", "_steam_api_init": "0x4cfe08", "_SDL_iconv_string": "0x4c7ca8", "__imp__mkdir": "0xa3c4b4", "_SDL_GetWindowSize": "0x4c7d80", "_glClearColor@16": "0x4c7f60", "_steam_api_persona_name": "0x4cfe10", "_edit_map_state": "0x4d03a8", "_system": "0x4cf820", "__imp__calloc": "0xa3c52c", "__imp___endthreadex": "0xa3c4e4", "_code_soft_interpreter_": "0x4d0238", "_zombies_base_id": "0x86b8c0", "_scaled_h": "0x86b93c", "__imp__SDL_GL_MakeCurrent": "0xa3c6a4", "___xl_c": "0xa3e004", "_first_build": "0x79cba0", "_customize_state": "0x4d0280", "__beginthreadex": "0x4cfa30", "___DENORMF": "0x4e1640", "__IAT_end__": "0xa3c7b8", "_atan2": "0x4cf9d0", "_remap_state1": "0x4d053c", "_testtmp": "0x4d049c", "__imp__wcstombs": "0xa3c618", "_synraw": "0x954920", "_SDL_JoystickNumAxes": "0x4c7d38", "__imp__malloc": "0xa3c580", "___xl_d": "0xa3e008", "__imp__SDL_JoystickNumAxes": "0xa3c710", "__imp__setlocale": "0xa3c5b0", "__imp__glEnable@4": "0xa3c644", "__imp__SDL_GetClipboardText": "0xa3c6d4", "_pixel_scale": "0x4d04a4", "___dyn_tls_init_callback": "0x4e1524", "__imp__Mix_FreeMusic": "0xa3c770", "_SDL_JoystickOpen": "0x4c7d28", "_clock": "0x4cf9b0", "_game_debug_no_path_map": "0x7caa48", "_game": "0x9d0480", "__imp___fullpath": "0xa3c4f4", "_SDL_Init": "0x4c7d70", "__imp__glDrawElements@16": "0xa3c640", "___EH_FRAME_BEGIN__": "0x4e30b8", "_remap_state2": "0x4d052c", "_cyoa_info": "0x95b660", "_inside_objects": "0x86ba14", "__imp__VirtualProtect@16": "0xa3c4a0", "___crt_xi_start__": "0xa3e000", "__imp__glDisableClientState@4": "0xa3c63c", "__imp__LeaveCriticalSection@4": "0xa3c478", "_SDL_JoystickNumButtons": "0x4c7d30", "__imp__glBlendFunc@8": "0xa3c624", "_tiles": "0x86ba38", "__imp__Sleep@4": "0xa3c490", "__imp__SDL_CreateWindow": "0xa3c688", "__imp__steam_api_store_stats": "0xa3c7b0", "_glGetError@0": "0x4c7f18", "__imp__SDL_GameControllerClose": "0xa3c6b8", "__imp__SDL_JoystickClose": "0xa3c6fc", "_game_debug_attack_disable": "0x7d0ce4", "_special_objects48": "0x86ba0c", "_landscape": "0x4d04a0", "_Mix_PauseMusic": "0x4c7e90", "__imp__abort": "0xa3c514", "___tinytens_D2A": "0x4e1a60", "_street_objects_base_id": "0x86b908", "_building_tiles_count": "0x86b92c", "_Mix_RegisterEffect": "0x4c7e80", "__libmsvcrt_a_iname": "0xa3d7b8", "___DTOR_LIST__": "0x4cff1c", "_filmgrain": "0x86ba00", "__imp___flsbuf": "0xa3c4ec", "__IAT_start__": "0xa3c42c", "_SDL_SetHint": "0x4c7ce8", "_SetUnhandledExceptionFilter@4": "0x4cfa98", "__imp__clock": "0xa3c530", "__imp__fclose": "0xa3c538", "_building_misc_tiles_base_id": "0x86b924", "_Mix_FreeMusic": "0x4c7eb0", "_stricoll": "0x4cfe00", "__imp__SDL_SetWindowSize": "0xa3c748", "_glDeleteTextures@8": "0x4c7f50", "__imp__longjmp": "0xa3c57c", "__argv": "0x50b000", "_debug_atlas": "0x86ba4c", "__fmode": "0x4d0608", "_special_objects64_base_id": "0x86b8d8", "_pets48_count": "0x86b8c4", "__imp__SDL_PollEvent": "0xa3c720", "__imp__SDL_SetHint": "0xa3c738", "__imp__floor": "0xa3c544", "_mouse": "0x86b850", "_gui_rumble": "0x86b834"}'

let iosDocumentPickerResolve = null;
let iosDocumentPickerReject = null;
let iosDocumentPickerDelegateClass = null;
let iosDocumentPickerDelegate = null;
let iosDocumentPickerController = null;
let iosDocumentPickerCancelButton = null;

function installIOSDocumentPickerCancelButton(picker) {
    if (!picker || picker.handle.isNull() || picker !== iosDocumentPickerController) return;

    const view = picker.view();
    const safeInsets = view.safeAreaInsets();
    const button = ObjC.classes.UIButton.buttonWithType_(1);
    button.setTitle_forState_(
        ObjC.classes.NSString.stringWithString_('取消'), 0
    );
    button.setTitleColor_forState_(ObjC.classes.UIColor.systemBlueColor(), 0);
    button.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_(17));
    // The Files remote view uses the leading safe-area position for its
    // sidebar icon. Place Cancel immediately to its right in the same bar.
    button.setFrame_([[safeInsets[1] + 35, 0], [72, 44]]);
    button.addTarget_action_forControlEvents_(
        iosDocumentPickerDelegate,
        ObjC.selector('dr2cCancelDocumentPicker:'),
        64 // UIControlEventTouchUpInside
    );
    button.setAccessibilityLabel_(
        ObjC.classes.NSString.stringWithString_('取消文件选择')
    );
    view.addSubview_(button);
    view.bringSubviewToFront_(button);
    iosDocumentPickerCancelButton = button;
    log('iOS document picker overlay Cancel installed');
}

function getIOSDocumentPickerDelegateClass() {
    if (iosDocumentPickerDelegateClass) return iosDocumentPickerDelegateClass;

    // Objective-C classes cannot be registered twice in one process.  Use a
    // per-script name (Frida hot reload leaves earlier runtime classes alive)
    // and reuse this class for every picker opened by the current script.
    const className = `DR2CIOSDocumentPickerDelegate_${Process.id}_${Date.now()}`;
    iosDocumentPickerDelegateClass = ObjC.registerClass({
        name: className,
        protocols: [ObjC.protocols.UIDocumentPickerDelegate],
        methods: {
            '- documentPicker:didPickDocumentsAtURLs:': {
                retType: 'void',
                argTypes: ['object', 'object'],
                implementation(picker, urls) {
                    log('iOS document picker modern selection callback');
                    try {
                        if (!iosDocumentPickerResolve)
                            throw new Error('Received a document after the picker request had settled');
                        if (urls.count() === 0) throw new Error('No file selected');
                        copyIOSDocumentPickerURL(urls.objectAtIndex_(0));
                    } catch (e) {
                        error('iOS document picker modern callback failed:', e);
                        settleIOSDocumentPicker(null, e);
                    }
                }
            },
            // UIDocumentPicker may still dispatch this deprecated single-URL
            // callback when the host app was linked against an older iOS SDK.
            // Supporting both selectors is harmless: settling the request
            // prevents a late duplicate callback from copying the file twice.
            '- documentPicker:didPickDocumentAtURL:': {
                retType: 'void',
                argTypes: ['object', 'object'],
                implementation(picker, url) {
                    log('iOS document picker legacy selection callback');
                    try {
                        if (!iosDocumentPickerResolve)
                            throw new Error('Received a document after the picker request had settled');
                        copyIOSDocumentPickerURL(url);
                    } catch (e) {
                        error('iOS document picker legacy callback failed:', e);
                        settleIOSDocumentPicker(null, e);
                    }
                }
            },
            '- documentPickerWasCancelled:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    log('iOS document picker system cancellation callback');
                    settleIOSDocumentPicker(null, new Error('No file selected'));
                }
            },
            '- dr2cCancelDocumentPicker:': {
                retType: 'void',
                argTypes: ['object'],
                implementation() {
                    const picker = iosDocumentPickerController;
                    if (picker) {
                        try {
                            picker.dismissViewControllerAnimated_completion_(true, NULL);
                        } catch (e) {
                            warn('iOS document picker cancel dismiss failed', e);
                        }
                    }
                    settleIOSDocumentPicker(null, new Error('No file selected'));
                }
            }
        }
    });
    return iosDocumentPickerDelegateClass;
}

function settleIOSDocumentPicker(path, failure) {
    const resolve = iosDocumentPickerResolve;
    const reject = iosDocumentPickerReject;
    if (!resolve && !reject) return;

    iosDocumentPickerResolve = null;
    iosDocumentPickerReject = null;
    iosDocumentPickerController = null;
    if (iosDocumentPickerCancelButton) {
        try {
            iosDocumentPickerCancelButton.removeFromSuperview();
        } catch (e) {
            warn('iOS document picker Cancel cleanup failed', e);
        }
        iosDocumentPickerCancelButton = null;
    }
    // Preserve UIDocumentPicker's proven system-managed selection/dismissal
    // behavior.  The only lifecycle state we own is the pending Promise.
    if (failure) {
        if (reject) reject(failure);
    } else if (resolve) {
        resolve(path);
    }
}

function copyIOSDocumentPickerURL(url) {
    const scoped = url.startAccessingSecurityScopedResource();
    try {
        const sourcePath = url.path().toString();
        const destinationPath = globalThis.modsDir + '/.selected-mod.zip';
        const fileManager = ObjC.classes.NSFileManager.defaultManager();
        fileManager.removeItemAtPath_error_(destinationPath, NULL);
        const errorOut = Memory.alloc(Process.pointerSize);
        errorOut.writePointer(NULL);
        const copied = fileManager.copyItemAtPath_toPath_error_(sourcePath, destinationPath, errorOut);
        if (!copied) {
            const errorPointer = errorOut.readPointer();
            const message = errorPointer.isNull()
                ? 'Unable to copy selected ZIP into the Mods directory.'
                : new ObjC.Object(errorPointer).localizedDescription().toString();
            throw new Error(message);
        }
        log('iOS document picker selected:', sourcePath);
        settleIOSDocumentPicker(destinationPath, null);
    } catch (e) {
        settleIOSDocumentPicker(null, e);
    } finally {
        if (scoped) url.stopAccessingSecurityScopedResource();
    }
}

/** @returns {Promise<string>}  */
async function filedialog() {
    if (Process.platform === 'linux' && isAndroid) {
        log('filedialog start')
        var Intent = Java.use('android.content.Intent');
        var Activity = Java.use('android.app.Activity');
        return new Promise((resolve, reject) => {
            function dumpFromUri(activity, uri) {
                var File = Java.use('java.io.File');
                var FileOutputStream = Java.use('java.io.FileOutputStream');
                var input = activity.getContentResolver().openInputStream(uri);
                if (input === null) { reject(new Error('Failed to openInputStream from dumpFromUri')); return null; }
                var dst = File.$new(activity.getCacheDir(), 'sel.zip');
                var fos = FileOutputStream.$new(dst);
                var buf = Java.array('byte', new Array(8192).fill(0));
                var n;
                while ((n = input.read(buf)) > 0) fos.write(buf, 0, n);
                fos.close(); input.close();
                log('dump 到:', dst.getAbsolutePath());
                return dst.getAbsolutePath();
            }
            const activity = getActivity();
            var originalOnActivityResult;
            try {
                originalOnActivityResult = activity.onActivityResult.overload('int', 'int', 'android.content.Intent');
                log('使用旧版 onActivityResult（3个参数）');
            } catch (e) {
                try {
                    originalOnActivityResult = activity.onActivityResult.overload('int', 'int', 'android.content.Intent', 'android.app.ComponentCaller');
                    log('使用新版 onActivityResult（4个参数）');
                } catch (e2) {
                    error('无法找到合适的 onActivityResult 重载');
                    reject(new Error('无法找到合适的 onActivityResult 重载'));
                }
            }
            activity.onActivityResult.implementation =
                function (requestCode, resultCode, data) {
                    if (requestCode === 1234) {
                        if (resultCode === Activity.RESULT_OK.value && data !== null) {
                            var uri = data.getData();
                            log('\n========== 文件选择结果 ==========');
                            log('Uri:', uri.toString());
                            log('路径:', uri.getPath());
                            const modDir = dumpFromUri(activity, uri);
                            resolve(modDir);
                            log('===================================\n');
                        } else {
                            log('用户取消了选择');
                            reject(new Error('No file selected'));
                        }
                    }
                    return originalOnActivityResult.call(this, requestCode, resultCode, data);
                };
            log('onActivityResult Hook 成功');
            var intent = Intent.$new();
            intent.setAction(Intent.ACTION_GET_CONTENT.value);
            intent.setType('application/zip');
            intent.addCategory(Intent.CATEGORY_OPENABLE.value);
            activity.startActivityForResult(intent, 1234);
            log('文件选择器已打开');
        });
    } else if (Process.platform === 'darwin' && ObjC.available) {
        // Present the native Files document picker and copy the security-scoped
        // result into the loader's writable Documents directory before JSZip
        // reads it.
        return new Promise((resolve, reject) => {
            try {
                if (iosDocumentPickerResolve || iosDocumentPickerController) {
                    reject(new Error('Document picker is already open'));
                    return;
                }
                iosDocumentPickerResolve = resolve;
                iosDocumentPickerReject = reject;
                const delegateClass = getIOSDocumentPickerDelegateClass();
                if (!iosDocumentPickerDelegate)
                    iosDocumentPickerDelegate = delegateClass.alloc().init();

                ObjC.schedule(ObjC.mainQueue, () => {
                    try {
                        const type = ObjC.classes.NSString.stringWithString_('public.zip-archive');
                        const types = ObjC.classes.NSArray.arrayWithObject_(type);
                        const picker = ObjC.classes.UIDocumentPickerViewController.alloc()
                            .initWithDocumentTypes_inMode_(types, 0);
                        iosDocumentPickerController = picker;
                        picker.setDelegate_(iosDocumentPickerDelegate);
                        picker.setAllowsMultipleSelection_(false);

                        const application = ObjC.classes.UIApplication.sharedApplication();
                        let window = application.keyWindow();
                        if (!window) window = application.windows().objectAtIndex_(0);
                        let controller = window.rootViewController();
                        let presented = controller.presentedViewController();
                        while (presented && !presented.handle.isNull()) {
                            controller = presented;
                            presented = controller.presentedViewController();
                        }
                        controller.presentViewController_animated_completion_(picker, true, NULL);
                        log('iOS document picker presented');
                        // UIDocumentPicker is backed by DOCRemoteViewController
                        // on this iOS build. It replaces the visible navigation
                        // bar after presentation, so install our button once the
                        // remote view has finished attaching. All UIKit work is
                        // explicitly scheduled on the main queue.
                        setTimeout(() => {
                            ObjC.schedule(ObjC.mainQueue, () => {
                                try {
                                    installIOSDocumentPickerCancelButton(picker);
                                } catch (e) {
                                    settleIOSDocumentPicker(null, e);
                                }
                            });
                        }, 350);
                    } catch (e) {
                        settleIOSDocumentPicker(null, e);
                    }
                });
            } catch (e) {
                iosDocumentPickerResolve = null;
                iosDocumentPickerReject = null;
                reject(e);
            }
        });
    } else if (Process.platform === 'windows') {
        // Keep the common dialog in prog.exe itself.  A PowerShell-hosted
        // WinForms dialog can be created behind SDL exclusive fullscreen and
        // then leaves the game's main thread waiting for an invisible window.
        const commonDialog = (() => {
            try {
                return Process.getModuleByName('comdlg32.dll');
            } catch (_) {
                return Module.load('comdlg32.dll');
            }
        })();
        const GetOpenFileNameW = new NativeFunction(
            commonDialog.getExportByName('GetOpenFileNameW'), 'int', ['pointer']
        );
        const CommDlgExtendedError = new NativeFunction(
            commonDialog.getExportByName('CommDlgExtendedError'), 'uint32', []
        );
        const pickerUser32 = Process.getModuleByName('user32.dll');
        const GetPickerOwner = new NativeFunction(
            pickerUser32.getExportByName('GetForegroundWindow'), 'pointer', []
        );
        const pickerOwner = GetPickerOwner();
        try {
            const pickerSdl = Process.getModuleByName('SDL2.dll');
            const SDL_SetHint = new NativeFunction(
                pickerSdl.getExportByName('SDL_SetHint'), 'int', ['pointer', 'pointer']
            );
            const applied = SDL_SetHint(
                Memory.allocUtf8String('SDL_VIDEO_MINIMIZE_ON_FOCUS_LOSS'),
                Memory.allocUtf8String('0')
            );
            log('Windows SDL minimize-on-focus-loss disabled:', applied);
        } catch (e) {
            // The native picker still works if an older SDL build does not
            // expose this optional hint; only the fullscreen safeguard drops.
            warn('Windows SDL minimize-on-focus-loss hint unavailable:', e);
        }
        const isPicker64 = Process.pointerSize === 8;
        const ofn = isPicker64
            ? { size: 152, owner: 8, filter: 24, filterIndex: 44, file: 48, maxFile: 56, title: 88, flags: 96 }
            : { size: 88, owner: 4, filter: 12, filterIndex: 24, file: 28, maxFile: 32, title: 48, flags: 52 };
        const allocateMultiSz = values => {
            const text = values.join('\0') + '\0\0';
            const buffer = Memory.alloc(text.length * 2);
            for (let i = 0; i < text.length; i++) buffer.add(i * 2).writeU16(text.charCodeAt(i));
            return buffer;
        };
        const filenameChars = 32768;
        const filenameBuffer = Memory.alloc(filenameChars * 2);
        filenameBuffer.writeByteArray(new Uint8Array(filenameChars * 2));
        // OPENFILENAME only receives pointers. Keep their backing allocations
        // strongly referenced for the whole modal native call; otherwise QJS
        // may collect them between successive picker openings and Windows
        // will read garbled title/filter text from a dangling pointer.
        const filterBuffer = allocateMultiSz(['ZIP files (*.zip)', '*.zip']);
        const titleBuffer = Memory.allocUtf16String('Install Mod From File');
        const openFileName = Memory.alloc(ofn.size);
        openFileName.writeByteArray(new Uint8Array(ofn.size));
        openFileName.writeU32(ofn.size);
        openFileName.add(ofn.owner).writePointer(pickerOwner);
        // Folders remain navigable in the common dialog; only regular files
        // are restricted to ZIP archives.
        openFileName.add(ofn.filter).writePointer(filterBuffer);
        openFileName.add(ofn.filterIndex).writeU32(1);
        openFileName.add(ofn.file).writePointer(filenameBuffer);
        openFileName.add(ofn.maxFile).writeU32(filenameChars);
        openFileName.add(ofn.title).writePointer(titleBuffer);
        // OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST |
        // OFN_FILEMUSTEXIST | OFN_EXPLORER.
        openFileName.add(ofn.flags).writeU32(0x00000004 | 0x00000008 | 0x00000800 | 0x00001000 | 0x00080000);
        log('Windows native picker owner HWND:', pickerOwner);
        if (!GetOpenFileNameW(openFileName)) {
            const dialogError = CommDlgExtendedError();
            if (dialogError !== 0)
                throw new Error('Windows native picker failed (0x' + dialogError.toString(16) + ')');
            throw new Error('No file selected');
        }
        const selectedPath = filenameBuffer.readUtf16String();
        log('Windows native picker selected:', selectedPath);
        return selectedPath;

        // ===== Windows：CreateProcessW 直接拉 powershell.exe，匿名管道读 stdout，无 cmd 中转 =====
        const title = 'Install Mod From File';

        const k32 = Process.getModuleByName('kernel32.dll');
        const CreateProcessW = new NativeFunction(k32.getExportByName('CreateProcessW'), 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'uint32', 'pointer', 'pointer', 'pointer', 'pointer']);
        const CreatePipe = new NativeFunction(k32.getExportByName('CreatePipe'), 'int', ['pointer', 'pointer', 'pointer', 'uint32']);
        const ReadFile = new NativeFunction(k32.getExportByName('ReadFile'), 'int', ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);
        const CloseHandle = new NativeFunction(k32.getExportByName('CloseHandle'), 'int', ['pointer']);
        const WaitForSingleObject = new NativeFunction(k32.getExportByName('WaitForSingleObject'), 'uint32', ['pointer', 'uint32']);
        const SetHandleInformation = new NativeFunction(k32.getExportByName('SetHandleInformation'), 'int', ['pointer', 'uint32', 'uint32']);

        const HANDLE_FLAG_INHERIT = 0x1;
        const STARTF_USESTDHANDLES = 0x100;
        const CREATE_NO_WINDOW = 0x08000000;
        const INFINITE = 0xFFFFFFFF;
        const is64 = Process.pointerSize === 8;
        const user32 = Process.getModuleByName('user32.dll');
        const GetForegroundWindow = new NativeFunction(user32.getExportByName('GetForegroundWindow'), 'pointer', []);
        const pickerParentHwnd = GetForegroundWindow();
        log('Windows picker parent HWND:', pickerParentHwnd);

        const escTitle = title.replace(/'/g, "''");
        const ps =
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " +
            "Add-Type -AssemblyName System.Windows.Forms; " +
            "$ownerNative = Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class DRTCWindowOwner { [DllImport(\"user32.dll\", EntryPoint=\"SetWindowLongW\")] public static extern IntPtr SetWindowLong(IntPtr hWnd, int nIndex, IntPtr dwNewLong); }' -PassThru; " +
            "$owner = New-Object System.Windows.Forms.Form; " +
            "$owner.ShowInTaskbar = $false; " +
            "$owner.Opacity = 0; " +
            "$null = $owner.Handle; " +
            "$null = $ownerNative::SetWindowLong($owner.Handle, -8, [IntPtr]" + pickerParentHwnd + "); " +
            "$owner.Show(); $owner.Hide(); " +
            "[System.Windows.Forms.Application]::DoEvents(); " +
            "$f = New-Object System.Windows.Forms.OpenFileDialog; " +
            "$f.Title = '" + escTitle + "'; " +
            "$f.Filter = 'ZIP files (*.zip)|*.zip'; " +
            "$f.Multiselect = $false; " +
            "$result = $f.ShowDialog($owner); " +
            "$owner.Dispose(); " +
            "if ($result -eq 'OK') { [Console]::Out.Write($f.FileName) }";

        const b64 = base64(encodeUtf16Le(ps));
        const cmdline = 'powershell.exe -NoProfile -NonInteractive -NoLogo -Sta -EncodedCommand ' + b64;

        return new Promise((resolve, reject) => {
            try {
                // 1. SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpsd; BOOL bInheritHandle; }
                const saSize = is64 ? 24 : 12;
                const sa = Memory.alloc(saSize);
                sa.writeU32(saSize);                                  // nLength
                sa.add(is64 ? 8 : 4).writePointer(NULL);             // lpSecurityDescriptor
                sa.add(is64 ? 16 : 8).writeU32(1);                   // bInheritHandle = TRUE

                // 2. 创建匿名管道（子进程 stdout -> 我们读）
                const hReadPtr = Memory.alloc(Process.pointerSize);
                const hWritePtr = Memory.alloc(Process.pointerSize);
                if (CreatePipe(hReadPtr, hWritePtr, sa, 0) === 0) {
                    reject(new Error('CreatePipe 失败')); return;
                }
                const hRead = hReadPtr.readPointer();
                const hWrite = hWritePtr.readPointer();
                // 读端不被子进程继承
                SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

                // 3. STARTUPINFOW
                //    64位: cb(4)+pad(4)+9指针(72)+ 4DWORD(16)+2WORD(4)+pad(4)+pStdIn/Out/Err(24) = 0x68
                const siSize = is64 ? 104 : 68;
                const si = Memory.alloc(siSize);
                si.writeU32(siSize);                                  // cb
                // dwFlags 偏移：64位 = 60, 32位 = 44
                const dwFlagsOff = is64 ? 60 : 44;
                si.add(dwFlagsOff).writeU32(STARTF_USESTDHANDLES);
                // hStdInput/Output/Error 偏移：64位 = 80/88/96, 32位 = 56/60/64
                const stdHandlesOff = is64 ? 80 : 56;
                si.add(stdHandlesOff + 0 * Process.pointerSize).writePointer(NULL);    // hStdInput
                si.add(stdHandlesOff + 1 * Process.pointerSize).writePointer(hWrite);  // hStdOutput
                si.add(stdHandlesOff + 2 * Process.pointerSize).writePointer(NULL);    // hStdError

                // 4. PROCESS_INFORMATION { hProcess; hThread; dwPid; dwTid; }
                const pi = Memory.alloc(is64 ? 24 : 16);

                // 5. lpCommandLine 必须可写
                const cmdBuf = Memory.allocUtf16String(cmdline);

                const ok = CreateProcessW(
                    NULL,            // lpApplicationName
                    cmdBuf,          // lpCommandLine（可写）
                    NULL, NULL,      // proc/thread security
                    1,               // bInheritHandles = TRUE
                    CREATE_NO_WINDOW,// dwCreationFlags（不弹控制台黑窗）
                    NULL,            // lpEnvironment
                    NULL,            // lpCurrentDirectory
                    si, pi
                );
                if (ok === 0) {
                    CloseHandle(hRead); CloseHandle(hWrite);
                    reject(new Error('CreateProcessW 失败')); return;
                }

                const hProcess = pi.readPointer();
                const hThread = pi.add(Process.pointerSize).readPointer();
                // 写端在父进程必须关闭，否则 ReadFile 永远阻塞
                CloseHandle(hWrite);

                // 6. 读 stdout
                let out = '';
                const bufSize = 4096;
                const buf = Memory.alloc(bufSize);
                const readBytes = Memory.alloc(4);
                while (true) {
                    const r = ReadFile(hRead, buf, bufSize, readBytes, NULL);
                    const n = readBytes.readU32();
                    if (r === 0 || n === 0) break;
                    out += buf.readUtf8String(n);
                }

                WaitForSingleObject(hProcess, INFINITE);
                CloseHandle(hRead);
                CloseHandle(hProcess);
                CloseHandle(hThread);

                const path = out.replace(/\r?\n/g, '').trim();
                if (!path) { reject(new Error('No file selected')); return; }
                log('选择的文件:', path);
                resolve(path);
            } catch (e) {
                reject(e);
            }
        });
    } else {
        // ===== macOS / Linux桌面：popen 调 osascript / zenity =====
        const title = 'Install Mod From File';

        const popen = new NativeFunction(getGlobalExport('popen'), 'pointer', ['pointer', 'pointer']);
        const pclose = new NativeFunction(getGlobalExport('pclose'), 'int', ['pointer']);
        const fgets = new NativeFunction(getGlobalExport('fgets'), 'pointer', ['pointer', 'int', 'pointer']);

        function runCmd(cmd) {
            const fp = popen(Memory.allocUtf8String(cmd), Memory.allocUtf8String('r'));
            if (fp.isNull()) throw new Error('popen 失败');
            let out = '';
            const buf = Memory.alloc(4096);
            while (!fgets(buf, 4096, fp).isNull()) out += buf.readUtf8String();
            pclose(fp);
            return out.replace(/\r?\n/g, '').trim();
        }

        return new Promise((resolve, reject) => {
            try {
                let path = '';
                if (Process.platform === 'darwin') {
                    const escTitle = title.replace(/"/g, '\\"');
                    const script =
                        'try\n' +
                        '  set f to choose file with prompt "' + escTitle + '" of type {"zip", "public.zip-archive"}\n' +
                        '  return POSIX path of f\n' +
                        'on error\n' +
                        '  return ""\n' +
                        'end try';
                    const cmd = 'osascript ' + script.split('\n').map(l => '-e ' + shellQuote(l)).join(' ');
                    path = runCmd(cmd);
                } else {
                    const cmd = 'zenity --file-selection ' +
                        shellQuote('--title=' + title) + ' ' +
                        shellQuote('--file-filter=ZIP files | *.zip');
                    path = runCmd(cmd);
                }
                if (!path) { reject(new Error('No file selected')); return; }
                log('选择的文件:', path);
                resolve(path);
            } catch (e) {
                reject(new Error('No file selected'));
            }
        });
    }
}

// ===== 辅助函数 =====

/** POSIX 单引号转义 */
function shellQuote(s) {
    return "'" + s.replace(/'/g, `'\\''`) + "'";
}

/** 字符串转 UTF-16LE 字节数组 */
function encodeUtf16Le(str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        bytes.push(c & 0xff, (c >> 8) & 0xff);
    }
    return bytes;
}

/** 字节数组 base64 编码（无 Buffer 环境） */
function base64(bytes) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
        const hasB1 = i + 1 < bytes.length, hasB2 = i + 2 < bytes.length;
        out += chars[b0 >> 2];
        out += chars[((b0 & 3) << 4) | (hasB1 ? (b1 >> 4) : 0)];
        out += hasB1 ? chars[((b1 & 15) << 2) | (hasB2 ? (b2 >> 6) : 0)] : '=';
        out += hasB2 ? chars[b2 & 63] : '=';
    }
    return out;
}

/**
 * @param {string|null} mod 
 * @param {string} fun 
 * @returns {NativePointer}
 */
function findExportByName(mod, fun) {
    if (!mod) {
        const result = Module.findGlobalExportByName(fun);
        if (!result) throw Error('Failed to find ' + fun);
        return result;
    }
    const module = Process.findModuleByName(mod);

    if (!module) throw new Error(`Module ${mod} not find`);

    const result = module.findExportByName(fun);

    if (!result) throw new Error(`fun ${mod + ':' + fun} not find`);

    return result
}

/** @param {string} name @returns {string|null} */
function getEnvironmentVariable(name) {
    const address = Module.findGlobalExportByName('getenv');
    if (!address) return null;

    const getenv = new NativeFunction(address, 'pointer', ['pointer']);
    const value = getenv(Memory.allocUtf8String(name));
    return value.isNull() ? null : value.readUtf8String();
}

/** @param {string} source @param {string} destination */
function copyFileIfMissing(source, destination) {
    try {
        fs.statSync(destination);
        return;
    } catch (_) {
        // The destination does not exist yet.
    }

    const data = File.readAllBytes(source);
    const output = new File(destination, 'wb');
    try {
        output.write(data);
        output.flush();
    } finally {
        output.close();
    }
}

/**
 * iOS app bundles are read-only at runtime. Keep the loader's mutable files in
 * the app data container and seed its assets from files packaged in DR2C.app.
 */
function prepareDarwinRuntimeDirectory(gameModule) {
    const home = getEnvironmentVariable('HOME');
    if (!home) throw new Error('Failed to resolve the iOS app data container (HOME)');

    // LiveContainer's process main module is the host app. Always prefer the
    // guest DR2C module supplied by waitForModule() for bundled resources.
    const bundleDir = gameModule
        ? moduleDirectory(gameModule)
        : (mod.bundleDir || mod.dir);
    mod.bundleDir = bundleDir;
    mod.dir = home + '/Documents/dr2c-mod-loader';

    fs.mkdirSync(mod.dir + '/assets');
    for (const filename of [
        'lang.json',
        'font_ucs2_12x12.png',
        'font_ucs2_12x12.png.LICENSE'
    ]) {
        try {
            copyFileIfMissing(bundleDir + '/assets/' + filename, mod.dir + '/assets/' + filename);
        } catch (e) {
            warn('Unable to seed bundled loader asset: ' + filename, e);
        }
    }
}

/** @param {string} path */
function mkdirSync(path) {
    if (Process.platform === 'linux' && isAndroid) {
        let result;
        Java.perform(() => {
            const File = Java.use("java.io.File");
            const dir = File.$new(path);
            if (!dir.exists()) {
                const success = dir.mkdirs();
                if (!success) throw new Error("目录创建失败: " + path);
                result = success;
            } else {
                result = true;
            }
        });
        return result;
    } else if (Process.platform === 'windows') {
        const SHCreateDirectoryExW = new NativeFunction(
            Process.getModuleByName('shell32.dll').getExportByName('SHCreateDirectoryExW'),
            'int', ['pointer', 'pointer', 'pointer']
        );
        const ERROR_SUCCESS = 0;
        const ERROR_ALREADY_EXISTS = 183;
        const ERROR_FILE_EXISTS = 80;

        const wpath = Memory.allocUtf16String(path);
        const ret = SHCreateDirectoryExW(NULL, wpath, NULL);

        if (ret === ERROR_SUCCESS || ret === ERROR_ALREADY_EXISTS || ret === ERROR_FILE_EXISTS) {
            return true;
        }
        throw new Error("目录创建失败: " + path + " (code: " + ret + ")");
    } else if (Process.platform === 'darwin') {
        // iOS forbids spawning a shell from an app sandbox, so call mkdir(2)
        // directly and create every parent component ourselves.
        const mkdir = new NativeFunction(
            getGlobalExport('mkdir'),
            'int', ['pointer', 'uint']
        );
        const absolute = path.startsWith('/');
        const parts = path.split('/').filter(Boolean);
        let current = absolute ? '' : '.';

        for (const part of parts) {
            current += '/' + part;
            const ret = mkdir(Memory.allocUtf8String(current), 0o755);
            if (ret === 0) continue;

            // mkdir also returns -1 for EEXIST. Verify the component instead of
            // relying on errno layout across Darwin versions.
            try {
                if (fs.statSync(current).isDirectory()) continue;
            } catch (_) {
                // Fall through to the useful path-specific error below.
            }
            throw new Error('目录创建失败: ' + current);
        }
        return true;
    } else {
        // 非 Android Linux：全局查找用 getGlobalExportByName
        const system = new NativeFunction(
            getGlobalExport('system'),
            'int', ['pointer']
        );
        const safe = path.replace(/'/g, `'\\''`);
        const ret = system(Memory.allocUtf8String(`mkdir -p '${safe}'`));
        if (ret !== 0) throw new Error("目录创建失败: " + path + " (code: " + ret + ")");
        return true;
    }
}

/** @param {string} target */
function rmrfSync(target) {
    let st;
    try {
        st = fs.statSync(target);
    } catch (e) {
        return;
    }

    // 符号链接(即使指向目录)也按文件删,绝对不能递归进去
    if (!st.isDirectory() || st.isSymbolicLink()) {
        fs.unlinkSync(target);
        return;
    }

    // 是真目录:先把里面清空
    for (const entry of fs.readdirSync(target)) {
        if (entry === '.' || entry === '..') continue;  // frida-fs 不会自动过滤
        rmrfSync(target + '/' + entry);
    }

    // 再删空目录本身
    fs.rmdirSync(target);
}

main();
