const JSZip = require('jszip');
const fridaFS = require('frida-fs');
const Java = require('frida-java-bridge').default;

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

const cm = new CModule(`
#include <stdint.h>
#include <string.h>

int
markChar (const uint8_t * restrict input,
             uint8_t * restrict output,
             int FULL_WIDTH,
             int HALF_WIDTH,
             uint8_t * restrict markCharUni,
             int fillChar)
{
  int len = 0;
  const uint8_t fw = (uint8_t) FULL_WIDTH;
  const uint8_t hw = (uint8_t) HALF_WIDTH;
  const uint8_t fc = (uint8_t) fillChar;
  const uint8_t *p = input;
  uint8_t *out = output;

  uint8_t b0;
  while ((b0 = *p) != 0)
  {
    if (b0 < 0x80)                      /* ASCII (最常见，最先判断) */
    {
      *out++ = b0;
      p++;
      continue;
    }

    if (b0 >= 0xC2 && b0 < 0xE0)        /* 2 字节 */
    {
      uint8_t b1 = p[1];
      if ((b1 & 0xC0) == 0x80)
      {
        markCharUni[len]     = b0;
        markCharUni[len + 1] = b1;
        markCharUni[len + 2] = 0;
        len += 3;
        out[0] = fc;
        out[1] = hw;
        out += 2;
        p += 2;
        continue;
      }
    }
    else if (b0 >= 0xE0 && b0 < 0xF0)   /* 3 字节 */
    {
      uint8_t b1 = p[1];
      if ((b1 & 0xC0) == 0x80 &&
          !(b0 == 0xE0 && b1 < 0xA0) &&
          !(b0 == 0xED && b1 >= 0xA0))
      {
        uint8_t b2 = p[2];
        if ((b2 & 0xC0) == 0x80)
        {
          markCharUni[len]     = b0;
          markCharUni[len + 1] = b1;
          markCharUni[len + 2] = b2;
          len += 3;
          out[0] = fc;
          out[1] = fc;
          out[2] = fw;
          out += 3;
          p += 3;
          continue;
        }
      }
    }

    *out++ = b0;                        /* 非法序列 */
    p++;
  }

  *out = 0;
  return len;
}

int getBmpCodePoint (const uint8_t *buf, int offset, int totalLen)
{
  if (offset >= totalLen)
    return 0;

  uint8_t b0 = buf[offset];

  /* 1. ASCII (0x00-0x7F): 0xxxxxxx —— 最常见, 最先判断 */
  if (b0 < 0x80)
    return b0;

  /* 续字节(0x80-0xBF)出现在起始位置, 或过长编码(0xC0-0xC1) → 非法 */
  if (b0 < 0xC2)
    return 0;

  /* 2. 2 字节: 110xxxxx 10xxxxxx */
  if (b0 < 0xE0)
  {
    if (offset + 2 > totalLen)
      return 0;
    uint8_t b1 = buf[offset + 1];
    if ((b1 & 0xC0) != 0x80)            /* 验证续字节 10xxxxxx */
      return 0;
    return ((b0 & 0x1F) << 6) | (b1 & 0x3F);
  }

  /* 3. 3 字节: 1110xxxx 10xxxxxx 10xxxxxx */
  if (b0 < 0xF0)
  {
    if (offset + 3 > totalLen)
      return 0;
    uint8_t b1 = buf[offset + 1];
    if ((b1 & 0xC0) != 0x80)
      return 0;
    if (b0 == 0xE0 && b1 < 0xA0)        /* 过长编码 (< U+0800) */
      return 0;
    if (b0 == 0xED && b1 >= 0xA0)       /* 代理区 (U+D800-U+DFFF) */
      return 0;
    uint8_t b2 = buf[offset + 2];
    if ((b2 & 0xC0) != 0x80)
      return 0;
    return ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
  }

  /* b0 >= 0xF0 : 4 字节及以上, 超出 BMP → 0 */
  return 0;
}
`);

/**
 * @brief 标记并替换 UTF-8 字符串中的多字节字符
 *
 * 遍历输入的 UTF-8 字符串，将所有有效的 2 字节、3 字节 UTF-8 字符
 * 替换为指定填充字符构成的占位序列，同时将被替换的原始字节序列
 * 保存到 markCharUni 数组中。ASCII 字符原样保留，非法 UTF-8 序列
 * 的首字节也原样保留。
 *
 * @param input         输入字符串，以 '\0' 结尾的 UTF-8 编码字节流
 * @param output        输出缓冲区，存放替换后的字符串（调用者需确保空间足够：
 *                      ASCII 字符 1:1 复制；2字节字符变为 2 字节填充；
 *                      3字节字符变为 3 字节填充）
 * @param FULL_WIDTH    全角字符（3字节）的第三个填充字节
 * @param HALF_WIDTH    半角宽字符（2字节）的第二个填充字节
 * @param markCharUni   输出缓冲区，连续存放所有被替换字符的原始 UTF-8 字节序列，
 *                      每个序列后追加一个 '\0' 作为分隔符。
 *                      例如：被替换一个 2字节序列，写入 b0, b1, 0x00 共 3 字节
 * @param fillChar      填充字符的主字节，用于替换序列的第1和第2字节（3字节时）
 *
 * @return              写入 markCharUni 的总字节数（包含分隔符 '\0'）。
 *                      若返回 0，表示未替换任何多字节字符。
 *
 * @note  本函数只处理 2 字节（U+0080 ~ U+07FF）和 3 字节（U+0800 ~ U+FFFF）
 *        的 UTF-8 字符。4 字节序列（U+10000 以上）不会被识别，其首字节
 *        会被当作非法序列处理。
 * @note  对 2 字节序列的合法性做了基本校验（检查 C2~DF 范围及后续字节格式），
 *        对 3 字节序列额外排除了超长编码（E0 A0~BF）和 UTF-16 代理区（ED A0~BF）。
 */
const markCharNav = new NativeFunction(cm.markChar, 'int', [
    'pointer', // input
    'pointer', // output
    'int',     // FULL_WIDTH
    'int',     // HALF_WIDTH
    'pointer', // markCharUni
    'int'      // fillChar
]);

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
const getBmpCodePointNav = new NativeFunction(cm.getBmpCodePoint, 'int', [
    'pointer',
    'int',
    'int'
]);

/**
 * @param {...any} args
 * @returns {void}
 */
function log(...args) {
    console.log('[+]', ...args);
}

/**
 * @param {...any} args
 * @returns {void}
 */
function error(...args) {
    console.error('[-]', ...args);
}

/**
 * @param {...any} args
 * @returns {void}
 */
function info(...args) {
    console.info('[*]', ...args);
}

/**
 * @param {...any} args
 * @returns {void}
 */
function warn(...args) {
    console.warn('[!]', ...args);
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

try {
    if (Process.getModuleByName('liblog.so')) {
        globalThis.isAndroid = true;
    } else {
        globalThis.isAndroid = false;
    }
} catch (e) {
    globalThis.isAndroid = false;
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
            var mod = {
                dir: Process.mainModule.path.substring(0, Process.mainModule.path.lastIndexOf('/')),
                script: ''
            }
            break;
        default:
            throw new Error("Failed to get mod dir");
            break;
    }
}

/**
 * @param {string} modsDir 
 * @returns {{ dir: string; script: string; }[]} 
 */
function loadMods(modsDir) {
    /** @type {{ dir: string; script: string; }[]} */
    let modsScript = [];
    fs.mkdirSync(modsDir);

    fs.readdirSync(globalThis.modsDir).forEach(ele => {
        if (ele === '.' || ele === '..') return;
        const modDir = `${globalThis.modsDir}/${ele}`;
        const stats = fs.lstatSync(modDir);

        if (stats.isDirectory()) {
            try {
                modsScript.push({ dir: modDir, script: File.readAllText(modDir + '/index.js') });
            } catch (e) {
                error(e);
            }
        }
    });

    for (const mod of modsScript) {
        const fun = new Function('require', 'mod', mod.script);
        fun(requireAgent, mod);
    }

    return modsScript;
}

/** @type {{ [key: string]: NativePointer }} */
var LANG_STR = Object.fromEntries(
    Object.entries({}).map(([k, v]) => [k, allocMixedString(v)])
)
/** @param {string} iso639_1  */
function loadLangEx(iso639_1, override = false) {
    const path = mod.dir + '/assets/lang.json';
    try {
        const s = File.readAllText(path);
        const o = JSON.parse(s);
        if (!o['selected_lang'] || override) o['selected_lang'] = iso639_1;
        LANG_STR = Object.fromEntries(
            Object.entries(o['string_literal'][o['selected_lang']]).map(([k, v]) => [k, allocMixedString(v)])
        );

        const file = new File(path, 'w');
        file.write(JSON.stringify(o, null, 4));
        file.close();

        log('load lang', path, Object.keys(LANG_STR).length);
    } catch (e) {
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
    if (!globalThis.activity)
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
    /**
    * @param {Module} module 
    */
    function main_body(module) {
        info('module loaded @ ' + module.base + ' size=' + module.size);
        globalThis.mainModule = module;
        info('mod path:', Process.mainModule.path, globalThis.modsDir, mod.dir);

        if (!globalThis.modsDir) {
            globalThis.modsDir = mod.dir + '/mods';
            const modsScript = loadMods(modsDir);
            if (modsScript.length === 0) {
                loadLang();
                hook();
                hookUtf8();
            }

        } else {
            loadLang();
            hook();
            hookUtf8();
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
                main_body(module);
            });
}

// ── 初始化 ────────────────────────────────────────────────────────────────────
function hook() {

    var START = '\uE0F5\uE0FB\uE0E7\uE0F0\uE0FC  START  \uE0F5\uE0FB\uE0E7\uE0FC';
    const button_ex = new NativeFunction(findSymbol('button_ex'), 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']);
    Interceptor.replace(button_ex, new NativeCallback(function (a1, a2, a3, a4, a5) {
        const ret = button_ex(a1, a2, a3, a4, a5);
        if (a4.isNull()) return ret;

        const str = readByteString(a4);

        if (str === START || (LANG_STR[START] && a4.equals(LANG_STR[START]))) {
            const btn = button_ex(a1, a2 - 1, 0, L("Mods"), findSymbol('main_btn_data_func'));
            setOnClickListenerEx(btn, modCallback);
        }

        if (str === 'Fast Text' || (LANG_STR['Fast Text'] && a4.equals(LANG_STR['Fast Text']))) {
            const btn = button_ex(a1, a2 + 2, 0, L("Language"), findSymbol('main_btn_data_func'));
            setOnClickListenerEx(btn, navFun('langCall', () => {
                const main_trigger_event = new NativeFunction(findSymbol('main_trigger_event'), 'int', ['int']);
                const main_tabscreen_start = new NativeFunction(findSymbol('main_tabscreen_start'), 'int', []);
                const main_push_popup_state = new NativeFunction(findSymbol('main_push_popup_state'), 'int', ['pointer']);
                main_trigger_event(11);
                main_tabscreen_start();
                main_push_popup_state(LangLayout);
            }));
        }
        return ret;
    }, 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']));

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

            if (!mods_init) {
                mods_init = true;

                const dirPath = globalThis.modsDir

                fs.readdirSync(dirPath).forEach(ele => {
                    if (ele === '.' || ele === '..') return;

                    const fullPath = `${dirPath}/${ele}`;
                    const stats = fs.lstatSync(fullPath);

                    if (stats.isDirectory()) {
                        try {
                            const mstr = File.readAllText(fullPath + '/' + 'package.json');
                            /** @type {Mod} */
                            const mjson = JSON.parse(mstr);
                            mjson.modDir = fullPath;
                            mods.push(mjson);
                        } catch (e) {
                            error(e)
                        }
                    }
                });
            }

            button_set_layout(1.0, 1.0);
            main_tabscreen_blank_tab_layout();
            button_set_layout(2.0, 3.0);
            main_tabscreen_tabbox_shrink();
            mods.slice(0 + modPage * 6, 6 + modPage * 6).forEach((mod, i, array) => {
                const btn = button_ex((i % 6 % 2), Math.floor(i / 2), modPage + i, L(mod.name + '-' + mod.version), main_btn_data_func);
                setOnClickListener(btn, () => {
                    log('desc_' + mod.name);
                    cyoa_just_ok(L(mod.description));
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

                            cyoa_just_ok(L(`Delete the mod '${mod.name}'?`));
                            cyoa_set_choice_func(navFun('desc_delete_confirm_no_' + mod.name,
                                () => {
                                    return 1;
                                }
                            ));
                            cyoa_set_choice_text(L("NO"));
                            cyoa_add_choice();
                            cyoa_set_choice_func(navFun('desc_delete_confirm_delete_' + mod.name,
                                () => {
                                    const dirPath = globalThis.modsDir
                                    fs.readdirSync(dirPath).forEach(ele => {
                                        const fullPath = `${dirPath}/${ele}`;
                                        const stats = fs.lstatSync(fullPath);

                                        if (ele === `${mod.name}.config` && stats.isFile()) {
                                            rmrfSync(fullPath);
                                        }

                                        if (ele === `${mod.name}.js` && stats.isFile()) {
                                            rmrfSync(fullPath);
                                        }

                                        if (ele === `${mod.name}` && stats.isDirectory()) {
                                            rmrfSync(fullPath);
                                        }
                                    });
                                    mods.splice(i, 1);
                                    new NativeFunction(modLayout, 'int', [])();
                                    return 1;
                                }
                            ));
                            cyoa_set_choice_text(L("DELETE"));
                            cyoa_set_title(L("DELETE"));

                            return 1;
                        }
                    ));
                    cyoa_set_choice_text(L("DELETE"));
                    cyoa_set_title(L(mod.name + '-' + mod.version));
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

                    const path1 = await filedialog();
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

                            const mdir = globalThis.modsDir + '/' + mod.name;
                            fs.mkdirSync(mdir);

                            File.writeAllText(`${mdir}/package.json`, s1);
                            const jsfile = zip.file('index.js');
                            if (jsfile)
                                File.writeAllText(`${mdir}/index.js`, await jsfile.async('text'));
                            for (const path of Object.keys(zip.files)) {
                                const entry = zip.files[path];
                                if (path.startsWith('assets/')) {
                                    if (entry.dir) {
                                        fs.mkdirSync(mdir + '/' + path.slice(0, -1));
                                        log('DIR:', mdir + '/' + path.slice(0, -1));
                                    } else {
                                        const data = await entry.async('array');
                                        File.writeAllBytes(mdir + '/' + path, data);
                                        log('File:', mdir + '/' + path);
                                    }
                                }
                            }

                            mods = mods.filter(item => item.name !== mod.name);
                            mods.push(mod);
                            mod.modDir = mdir;

                            cyoa_just_ok(L('Install Mod Success.'));
                            cyoa_set_title(L('SUCCESS'));
                        } else {
                            const tdir = mod.dir + '/assets/dr2c';

                            rmrfSync(tdir);

                            fs.mkdirSync(tdir);

                            for (const path of Object.keys(zip.files)) {
                                const entry = zip.files[path];
                                if (path.startsWith('data/') || path.startsWith('deathforth/') || path.startsWith('gfx/')) {
                                    if (entry.dir) {
                                        fs.mkdirSync(tdir + '/' + path.slice(0, -1));
                                        log('目录:', tdir + '/' + path.slice(0, -1));
                                    } else {
                                        const data = await entry.async('array');
                                        File.writeAllBytes(tdir + '/' + path, data);
                                        log('文件:', tdir + '/' + path);
                                    }
                                }
                            }

                            cyoa_just_ok(L('Install Mod Success.'));
                            cyoa_set_title(L('SUCCESS'));
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

            main_common_page_setup(L('CHANGE LANGUAGE'), 0);
            button_set_layout(1.0, 1.0);
            main_tabscreen_blank_tab_layout();
            button_set_layout(4.0, 6.0);

            const path = mod.dir + '/assets/lang.json';
            const jsonStr = File.readAllText(path);
            const json = JSON.parse(jsonStr);
            const langs = Object.keys(json['string_literal']);

            langs.forEach((lang, i, array) => {
                const btn = button_ex((i % 4), Math.floor(i / 4), i, L(lang), main_btn_data_func);
                setOnClickListener(btn, () => {

                    cyoa_yesno(L('Change Language to ' + lang + '?'), L('YES'), L('NO'),
                        navFun('', (ptr) => {
                            if (ptr instanceof NativePointer) {
                                const yes = ptr.add(80).readInt();
                                if (yes) {
                                    loadLangEx(lang, true);
                                }
                            }
                        }, 'void', ['pointer'])
                    );
                });
            });
            return 0;
        },
        'uint',  // 返回值: LRESULT
        []
    );
}

// ── 初始化 ────────────────────────────────────────────────────────────────────
function hookUtf8() {
    // ── 适配不同的build_stamp ─────────────────────────────────────────
    const main_build_stamp = new NativeFunction(findSymbol('main_build_stamp'), 'pointer', []);
    const build_stamp = main_build_stamp().readCString();

    /** @type {NativePointer} */
    let load_gfx;
    /** @type {NativePointer} */
    let btn_music_slider;

    switch (build_stamp) {
        case 'OCT-15-2025.15.11':
            load_gfx = globalThis.mainModule.base.add(0xEE0FC);
            btn_music_slider = globalThis.mainModule.base.add(0x100F64);
            log('main_build_stamp', build_stamp);
            break;

        case 'MAY-04-2023.09.30':
            load_gfx = globalThis.mainModule.base.add(0xB07D4);
            btn_music_slider = globalThis.mainModule.base.add(0xC4D98);
            log('main_build_stamp', build_stamp);
            break;

        default:
            load_gfx = findSymbol('load_gfx');
            btn_music_slider = findSymbol('btn_music_slider');
            log('main_build_stamp', build_stamp);
            break;
    }


    // ── （NativeFunction） ─────────────────────────────────────────

    const SPRITE_GET = new NativeFunction(findSymbol('sprite_get'), 'pointer', ['int16']);
    const TURTLE_TRANS = new NativeFunction(findSymbol('turtle_trans'), 'void', ['double', 'double']);
    const ATLAS_GET = new NativeFunction(findSymbol('atlas_get'), 'pointer', ['int']);
    const ATLAS_UPLOAD = new NativeFunction(findSymbol('atlas_upload'), 'int', ['pointer', 'int', 'int']);
    const WRAPPER_SET_TITLE = new NativeFunction(findSymbol('wrapper_set_window_title'), 'void', ['pointer']);
    const WRAPPER_FILE_DATA_PATH = new NativeFunction(findSymbol('wrapper_file_data_path'), 'pointer', []);
    const WRAPPER_FILE_SAVE_PATH = new NativeFunction(findSymbol('wrapper_file_save_path'), 'pointer', []);
    const FILE_DATA_PATH = new NativeFunction(findSymbol('file_data_path'), 'pointer', ['pointer']);
    const FILE_OPEN_DATA_READ = new NativeFunction(findSymbol('file_open_data_read'), 'pointer', ['pointer']);
    const ATLAS_LOAD_SPRITESHEET = new NativeFunction(findSymbol('atlas_load_spritesheet'), 'int', ['pointer', 'int', 'int', 'int', 'int', 'int', 'pointer']);
    const SPRITE_COUNT = new NativeFunction(findSymbol('sprite_count'), 'int', []);
    const SPRITE_BATCH_PLOT = new NativeFunction(findSymbol('sprite_batch_plot'), 'int', ['pointer', 'int', 'int']);
    const TURTLE_SET_SCALE = new NativeFunction(findSymbol('turtle_set_scale'), 'void', ['double']);
    const TURTLE_SET_SCALEX = new NativeFunction(findSymbol('turtle_set_scalex'), 'void', ['double']);
    const TURTLE_SET_SCALEY = new NativeFunction(findSymbol('turtle_set_scaley'), 'void', ['double']);
    const GLYPHS_SET_CALLBACK = new NativeFunction(findSymbol('glyphs_set_callback'), 'pointer', ['pointer', 'pointer']);
    const GLYPHS_BATCH_PLOT_EX = new NativeFunction(findSymbol('glyphs_batch_plot_ex'), 'int', ['pointer', 'pointer', 'int', 'int', 'int']);
    const ATLAS_CREATE_TEXTURE = new NativeFunction(findSymbol('atlas_create_texture'), 'int', ['int', 'int', 'int']);
    const ATLAS_FREE_IMAGE_DATA = new NativeFunction(findSymbol('atlas_free_image_data'), 'void', ['int']);
    const text_w = new NativeFunction(findSymbol('text_w'), 'int', ['pointer']);
    const chara_stat_name = new NativeFunction(findSymbol('chara_stat_name'), 'pointer', ['int']);
    const button_ex = new NativeFunction(findSymbol('button_ex'), 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']);
    const fs_pop_string = new NativeFunction(findSymbol('fs_pop_string'), 'pointer', ['pointer']);
    const main_stextf = findSymbol('main_stextf');
    const snprintf = findSymbol('snprintf');
    const WRAP_TEXT_EX = new NativeFunction(findSymbol('wrap_text_ex'), 'pointer', ['pointer', 'int', 'int']);
    const TURTLE_BASE = findSymbol('turtle');

    const _strlen = new NativeFunction(findSymbol('strlen'), 'size_t', ['pointer']);


    // ── 主逻辑 ────────────────────────────────────────────────
    /** @type {NativeFunction<number, [number, number, NativePointer]> | null} */
    let originalGlyphCb = null;
    /** @type {NativePointer} */
    let originalGlyphCtx;
    /** @type {number} */
    let font_base_id;  // 由 load_gfx 中的 hook 初始化
    let load_gfx_hooking = 0;

    const FULL_WIDTH = 0x11;
    const HALF_WIDTH = 0x28;

    // 预分配 turtle 保存缓冲区（96 字节）
    const savedTurtle = Memory.alloc(96);

    // 预分配 text 保存缓冲区（2048 字节）
    const markCharOut = Memory.alloc(10240);


    // ── Replace glyphs_set_callback ───────────────────────────────────────
    Interceptor.replace(GLYPHS_SET_CALLBACK, new NativeCallback(
        (a1, a2) => {
            if (!unifont) return GLYPHS_SET_CALLBACK(a1, a2);

            if (!a1.isNull()) {
                originalGlyphCb = new NativeFunction(a1, 'int', ['int', 'int', 'pointer']);
            } else {
                originalGlyphCb = null;
            }
            originalGlyphCtx = a2;
            return a2;
        },
        'pointer', ['pointer', 'pointer']
    ));
    log('Replace glyphs_set_callback 已安装');

    let unifont = NULL;
    let unifont_x = 0;
    let unifont_y = 0;

    // ── Replace glyphs_batch_plot_ex ──────────────────────────────────────
    const GLYPHS_BATCH_PLOT_EX_HOOK = Interceptor.replace(GLYPHS_BATCH_PLOT_EX, new NativeCallback(
        (a1, a2, a3, a4, a5) => {
            if (!unifont) return GLYPHS_BATCH_PLOT_EX(a1, a2, a3, a4, a5);
            if (a1.isNull()) return 0;

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

                if (!originalGlyphCb ||
                    !originalGlyphCb(charV14, 0, originalGlyphCtx)) {

                    const v15 = a1.add(8).readU32();
                    if (v14 >= v15) v14 = v15 - 1;
                    const v16 = font.add(sprite_offset * v14);

                    if (v13) {
                        TURTLE_TRANS(v16.add(12).readS16() * 0.5, 0.0);
                    }

                    if (!_utf8Len)
                        SPRITE_BATCH_PLOT(v16, 0, a5);
                    else {
                        /* TODO: 解决问题, 游戏在显示低分辨率时, 在显示换行字符时纹理会向下移动一个或两个像素 */
                        unifont.add(0).writeU16(unifont_x + 12 * (bmpCodePoint & 0xFF));/* 纹理x轴 */
                        unifont.add(2).writeU16(unifont_y + 12 * ((bmpCodePoint >> 8) & 0xFF));/* 纹理y轴 */

                        unifont.add(4).writeU16(_utf8Len === 3 ? 12 : 6);/* 宽度 */
                        unifont.add(6).writeU16(12);/* 高度 */

                        const scale = TURTLE_BASE.add(0x18).readDouble();
                        TURTLE_SET_SCALEX(scale * (_utf8Len === 3 ? 8 : 7) / 12);
                        TURTLE_SET_SCALEY(scale * 8 / 12);
                        SPRITE_BATCH_PLOT(unifont, 0, a5);
                        TURTLE_SET_SCALE(scale);

                        v13 += _utf8Len - 1;
                    }
                    TURTLE_TRANS(v16.add(12).readS16() * 0.5, 0.0);
                }

                if (originalGlyphCb)
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

    // ── Attach load_gfx ──────────────────────────────────────
    const load_gfx_hook = Interceptor.attach(load_gfx, {
        onEnter(args) {
            cm.markChar;
            load_gfx_hooking = 1;
        },
        onLeave(retval) {
            load_gfx_hooking = 0;

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
                throw new Error('字体图集加载失败');
            }
            unifont = SPRITE_GET(font_base_id);
            unifont_x = unifont.readU16();
            unifont_y = unifont.add(2).readU16();
        }
    });
    log('Attach load_gfx 已安装');

    // ── load_gfx_hooking ──────────────────────────────────────
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
                args[1] = ptr(4096);
                args[2] = ptr(4096);
                log(`atlas_create_texture: ${width}x${height} → 4096x4096`);
            }
        }
    });

    // ── 使用MOD路径加载data ──────────────────────────────────────
    let skip_path_rep = 0;

    Interceptor.attach(WRAPPER_FILE_DATA_PATH, {
        onLeave(retval) {
            if (skip_path_rep) return;

            retval.replace(L(mod.dir + '/assets/dr2c/'));
        }
    });

    Interceptor.attach(FILE_DATA_PATH, {
        onEnter(args) {
            const str = args[0].readCString();
            try {
                const f = fs.statSync(mod.dir + '/assets/dr2c/' + str);
            } catch (e) {
                /* 如果assets不存在对应文件则不替换 */
                skip_path_rep = 1;
            }
        },
        onLeave(retval) {
            skip_path_rep = 0;
        }
    });

    Interceptor.attach(FILE_OPEN_DATA_READ, {
        onEnter(args) {
            const str = args[0].readCString();
            try {
                const f = fs.statSync(mod.dir + '/assets/dr2c/' + str);
            } catch (e) {
                /* 如果assets不存在对应文件则不替换 */
                skip_path_rep = 1;
            }
        },
        onLeave(retval) {
            skip_path_rep = 0;
        }
    });

    // ── utf8自动换行逻辑 ──────────────────────────────────────
    const markCharUni = Memory.alloc(10240 * 2);
    const FILL_CHAR = 0xFF;
    Interceptor.attach(WRAP_TEXT_EX, {
        onEnter(args) {
            if (args[0].isNull()) return;
            this.a1 = args[0];
            const strPtr = args[0].readPointer();
            this.a1_str_ptr = strPtr;

            this.markLen = markCharNav(strPtr, markCharOut, FULL_WIDTH, HALF_WIDTH, markCharUni, FILL_CHAR);

            this.a1.writePointer(markCharOut);
        },

        onLeave(retval) {
            if (retval.isNull()) return;

            const retLen = _strlen(retval).toNumber();

            if (retLen !== 0) {
                const buf = new Uint8Array(retval.readByteArray(retLen) ?? new ArrayBuffer(0));
                const saved = new Uint8Array(markCharUni.readByteArray(this.markLen * 3) || []);
                let idx = 0;

                for (let i = 0; i < retLen - 1; i++) {
                    const s1 = buf[i];
                    const s2 = buf[i + 1];
                    const s3 = buf[i + 2];
                    if (s1 === FILL_CHAR && (s2 === FULL_WIDTH || s2 === HALF_WIDTH)) {
                        const b1 = saved[idx++];
                        const b2 = saved[idx++];
                        idx++;
                        buf.set([b1, b2], i);
                        i += 1;
                    } else if (s1 === FILL_CHAR && s2 === FILL_CHAR && (s3 === FULL_WIDTH || s3 === HALF_WIDTH)) {
                        const b1 = saved[idx++];
                        const b2 = saved[idx++];
                        const b3 = saved[idx++];

                        buf.set([b1, b2, b3], i);
                        i += 2;
                    }
                }

                retval.writeByteArray(buf.buffer);
            }

            const move_len = this.a1.readPointer().sub(markCharOut);
            this.a1.writePointer(this.a1_str_ptr.add(move_len));
        }
    });


    Interceptor.attach(text_w, {
        onEnter(args) {
            if (args[0].isNull()) return;

            markCharNav(args[0], markCharOut, FULL_WIDTH, HALF_WIDTH, markCharUni, FILL_CHAR);

            args[0] = markCharOut;
        }
    });

    Interceptor.attach(chara_stat_name, {
        onEnter(args) {
            // if (args[0].isNull()) return;
            this.a1 = args[0].toInt32();
        },

        onLeave(retval) {
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
                retval.replace(LANG_STR[str]);
            }
        }
    });

    if (Process.platform === 'linux') {
        Interceptor.attach(button_ex, {
            onEnter(args) {
                if (args[1].isNull()) return;
                const str = readByteString(args[1]);
                if (!str || !LANG_STR[str]) return;
                args[1] = LANG_STR[str];
            }
        });
    } else if (Process.platform === 'windows') {
        Interceptor.attach(button_ex, {
            onEnter(args) {
                if (args[3].isNull()) return;
                const str = readByteString(args[3]);
                if (!str || !LANG_STR[str]) return;
                args[3] = LANG_STR[str];
            }
        });
    } else if (Process.platform === 'darwin') {
        Interceptor.attach(button_ex, {
            onEnter(args) {
                if (args[1].isNull()) return;
                const str = readByteString(args[1]);
                if (!str || !LANG_STR[str]) return;
                args[1] = LANG_STR[str];
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
            this.a1.add(200).writePointer(LANG_STR[str]);
        }
    });

    Interceptor.attach(main_stextf, {
        onEnter(args) {
            const str = readByteString(args[0]);
            if (!str || !LANG_STR[str]) return;
            // log(`main_stextf ${str}`);
            args[0] = LANG_STR[str];
            const matches = str.match(/%./g);
            if (!matches) return;
            matches.forEach((item, index) => {
                if (item === '%s') {
                    const vastr = args[index + 1].readCString();
                    if (vastr && LANG_STR[vastr])
                        args[index + 1] = LANG_STR[vastr];
                }
            });
        }
    });

    Interceptor.attach(snprintf, {
        onEnter(args) {
            const str = readByteString(args[2]);
            if (!str || !LANG_STR[str]) return;
            // log(`snprintf ${str}`);
            args[2] = LANG_STR[str];
            const matches = str.match(/%./g);
            if (!matches) return;
            matches.forEach((item, index) => {
                if (item === '%s') {
                    const vastr = args[index + 3].readCString();
                    if (vastr && LANG_STR[vastr])
                        args[index + 3] = LANG_STR[vastr];
                }
            });
        }
    });

    /** @type {NativePointer[]} */
    const perkDesc = [];
    if (build_stamp === 'MAY-04-2023.09.30') {
        /** @param {number} offset @param {number[]} arr  */
        function repAss(offset, arr) {
            // log("修改前:", Instruction.parse(globalThis.mainModule.base.add(offset)).toString());
            Memory.patchCode(globalThis.mainModule.base.add(offset), arr.length, code => {
                code.writeByteArray(arr);
            });
            // log("修改后:", Instruction.parse(globalThis.mainModule.base.add(offset)).toString());
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


    log('hook 初始化完成');
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

/**
 * @param {string} name 
 * @returns {NativePointer}
 */
function findSymbol(name) {
    if (Process.platform === 'linux' || Process.platform === 'darwin') {
        let exp = globalThis.mainModule.findExportByName(name);
        if (!exp) {
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
        try { callback(m); } catch (e) { error('callback error: ', e); }
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

/** @returns {Promise<string>}  */
async function filedialog() {
    if (Process.platform === 'linux' && isAndroid) {
        log('filedialog start')

        // 1. 准备需要用到的 Java 类
        var Intent = Java.use('android.content.Intent');
        var Activity = Java.use('android.app.Activity');


        return new Promise((resolve, reject) => {
            /**
            * @param {*} activity 
            * @param {*} uri 
            * @returns {*} 
            */
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
            /** @type {*} */
            var originalOnActivityResult;

            try {
                // 先尝试旧版本重载（3个参数）
                originalOnActivityResult = activity.onActivityResult.overload('int', 'int', 'android.content.Intent');
                log('使用旧版 onActivityResult（3个参数）');
            } catch (e) {
                // 如果失败，尝试新版本重载（4个参数）
                try {
                    originalOnActivityResult = activity.onActivityResult.overload('int', 'int', 'android.content.Intent', 'android.app.ComponentCaller');
                    log('使用新版 onActivityResult（4个参数）');
                } catch (e2) {
                    error('无法找到合适的 onActivityResult 重载');
                    reject(new Error('无法找到合适的 onActivityResult 重载'));
                }
            }

            // 替换实现
            activity.onActivityResult.implementation =
                /**
                 * @param {*} requestCode 
                 * @param {*} resultCode 
                 * @param {*} data 
                 * @returns {*} 
                 */
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

                    // 调用原始方法
                    return originalOnActivityResult.call(this, requestCode, resultCode, data);
                };
            log('onActivityResult Hook 成功');

            // ========== 2. 然后打开文件选择器 ==========
            var intent = Intent.$new();
            intent.setAction(Intent.ACTION_GET_CONTENT.value);
            intent.setType('application/zip');
            intent.addCategory(Intent.CATEGORY_OPENABLE.value);

            activity.startActivityForResult(intent, 1234);
            log('文件选择器已打开');
        });

    } else {
        // 发送消息给 Python
        send({ type: "filedialog" });

        // 等待 Python 回复
        return new Promise((resolve, reject) => {
            recv("filedialog", function (obj) {
                log("Python:", JSON.stringify(obj));

                if (obj.success) {
                    resolve(obj.result);
                } else {
                    reject(new Error(obj.error || "Failed to open filedialog"));
                }
            });
        });
    }
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
                // log("目录创建成功:", path);
                result = success;
            } else {
                // log("目录已存在:", path);
                result = true;
            }
        });
        return result;
    } else {
        send({ type: "mkdir", data: { path: path } });

        /** @type {*} */
        let response = null;
        const op = recv("mkdir", function (obj) {
            response = obj;
        });
        op.wait();   // 阻塞,直到上面的回调被触发

        // log("Python:", JSON.stringify(response));
        if (response.success) {
            return response;
        } else {
            throw new Error(response.error || "目录创建失败");
        }
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