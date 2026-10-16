#!/usr/bin/env node
const { error } = require('console');
const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const crypto = require('crypto');
const os = require('os');
const { execFileSync } = require('child_process');

function findGameAssetsDir() {
    if (process.platform === 'win32') {
        const stdout = execFileSync('powershell.exe', [
            '-NoProfile',
            '-Command',
            '(Get-ItemProperty -Path "HKLM:\\SOFTWARE\\WOW6432Node\\Valve\\Steam" -Name "InstallPath" -ErrorAction SilentlyContinue).InstallPath'
        ], { encoding: 'utf8' });

        const steamPath = stdout.trim();

        if (!steamPath) {
            return '';
        }
        if (!fs.existsSync(path.join(steamPath, 'steamapps', 'common', 'DeathRoadToCanada'))) {
            return '';
        }
        return path.join(steamPath, 'steamapps', 'common', 'DeathRoadToCanada');
    }

    if (process.platform === 'linux') {
        return path.join(
            os.homedir(),
            '.steam/steam/steamapps/common/DeathRoadToCanada'
        );
    }

    if (process.platform === 'darwin') {
        return path.join(
            os.homedir(),
            'Library/Application Support/Steam/steamapps/common/DeathRoadToCanada/DR2C.app/Contents'
        );
    }

    return null;
}
const assetsDir = findGameAssetsDir();

/**
 * 基于 MD5 的 64 位指纹。不同文本几乎不碰撞(非局部敏感)。
 * @param {string} text
 * @returns {bigint}
 */
function md5hash64(text) {
    const hex = crypto.createHash('md5').update(text, 'utf8').digest('hex'); // 32 hex = 128 bit
    return BigInt('0x' + hex.slice(0, 16)); // 取高 64 位
}



const program = new Command();
program
    .description('')
    .option('--copy')
    .option('--source <directory>', 'Deathforth source directory to instrument')
    .option('--output <directory>', 'assets/dr2c output directory')
    .option('--baseline-zh <file>', 'existing zh.json used to reuse matching translations')
    .option('--lang <file>', 'lang.json used to localize perk/trait identity values')
    .option('--identity-lang <language>', 'target language for perk/trait identity values', 'zh')
    .parse(process.argv);

const args = program.opts();
if (args.copy) {
    fs.cpSync(assetsDir + '/deathforth', 'assets/dr2c/deathforth', { recursive: true });
    fs.cpSync(assetsDir + '/gfx', 'assets/dr2c/gfx', { recursive: true });
}

const sourceDeathforthDir = path.resolve(
    args.source || path.join(assetsDir, 'deathforth')
);
const outputDr2cDir = path.resolve(args.output || 'assets/dr2c');

if (!fs.existsSync(sourceDeathforthDir)) {
    throw new Error(`Deathforth source directory does not exist: ${sourceDeathforthDir}`);
}


/**
 * @param {string} src 
 * @returns {string[]} 
 */
function tokenize(src) {
    // 字符串字面量 或 非空白序列
    const tokens = src.match(/"(?:[^"\\]|\\.)*"|\S+/g) ?? [];
    return tokens;
}

/**
 * 移除 Deathforth 的 // 与 \\ 行注释，但绝不触碰双引号字符串内部的字符。
 *
 * 以前直接使用 /\/\/.*$/gm，会把 "^///^" 之类的显示文本截断为 "^，
 * 进而写出无法解析的 .df 文件。这里按字符扫描，同时正确处理 \" 转义。
 *
 * @param {string} src
 * @returns {string}
 */
function stripLineComments(src) {
    let result = '';
    let inString = false;
    let escaped = false;

    for (let index = 0; index < src.length; index++) {
        const ch = src[index];

        if (inString) {
            result += ch;
            if (escaped) {
                escaped = false;
            } else if (ch === '\\') {
                escaped = true;
            } else if (ch === '"') {
                inString = false;
            }
            continue;
        }

        if (ch === '"') {
            inString = true;
            result += ch;
            continue;
        }

        if ((ch === '/' && src[index + 1] === '/') || ch === '\\') {
            while (index < src.length && src[index] !== '\n') index++;
            if (index < src.length) result += '\n';
            continue;
        }

        result += ch;
    }

    return result;
}

/**
 * Forth 的 $perk/$trait 名称不只是显示文本：原生角色创建器会把所选名称
 * 直接写进角色的 .perk/.trait 字段，而 perk-find/trait-find 按字节精确匹配。
 *
 * 因此在中文包中，注册值、比较值和自定义角色的赋值必须使用同一套中文
 * 身份值；只用 i18n.code-strlit! 改显示并不能修复随机角色。该映射仅限
 * 已在 lang.json 中明确提供译名的 $perk/$trait 项，未翻译的模组名称保留英文。
 */
function loadPerkTraitIdentityMap() {
    if (!args.lang) return new Map();

    const lang = JSON.parse(fs.readFileSync(path.resolve(args.lang), 'utf8'));
    const literals = lang?.string_literal?.[args.identityLang];
    if (!literals || typeof literals !== 'object') {
        throw new Error(`Language ${JSON.stringify(args.identityLang)} is missing from ${args.lang}`);
    }

    const perkDefPath = path.join(sourceDeathforthDir, 'perkdef.df');
    if (!fs.existsSync(perkDefPath)) {
        throw new Error(`perkdef.df is required for perk/trait identity localization: ${perkDefPath}`);
    }

    const names = new Set();
    const perkDef = stripLineComments(fs.readFileSync(perkDefPath, 'utf8'));
    for (const match of perkDef.matchAll(/^\s*"((?:[^"\\]|\\.)*)"\s+\$(?:perk|trait)\b/gm)) {
        names.add(match[1]);
    }

    const map = new Map();
    for (const name of names) {
        const translated = literals[name];
        if (typeof translated === 'string' && translated.length > 0 && translated !== name) {
            map.set(name, translated);
        }
    }

    // Deathforth has a few historical capitalization inconsistencies, such as
    // "Bow and Arrows" versus "Bow And Arrows". Treat only casing as equal.
    for (const [name, translated] of [...map]) {
        map.set(name.toLocaleLowerCase('en-US'), translated);
    }

    const untranslated = [...names].filter(name => !map.has(name));
    console.log(
        `Localized ${names.size - untranslated.length}/${names.size} perk/trait identity value(s) to ${args.identityLang}; ` +
        `${untranslated.length} intentionally remain source-language.`
    );
    if (untranslated.length > 0) {
        console.log(`Untranslated identities: ${untranslated.join(', ')}`);
    }
    return map;
}

/**
 * @param {string} content
 * @param {Map<string, string>} identityMap
 * @returns {{content: string, changes: number}}
 */
function localizePerkTraitIdentifiers(content, identityMap) {
    if (identityMap.size === 0) return { content, changes: 0 };

    let changes = 0;
    const translate = value => identityMap.get(value) ?? identityMap.get(value.toLocaleLowerCase('en-US'));
    const replaceLiteral = (whole, value) => {
        const translated = translate(value);
        if (!translated || translated === value) return whole;
        changes++;
        return `"${translated}"`;
    };

    // Registry values consumed by the native perk/trait selection UI.
    content = content.replace(
        /"((?:[^"\\]|\\.)*)"(?=\s+\$(?:perk|trait)\b)/g,
        replaceLiteral
    );

    // Runtime checks, e.g. `.perk@ "Trademark Weapon" $=`.
    content = content.replace(
        /(\.(?:perk|trait)@\s*)"((?:[^"\\]|\\.)*)"(?=\s+\$=)/g,
        (whole, prefix, value) => prefix + replaceLiteral(`"${value}"`, value)
    );

    // Assignment lines, including modcustchars.df's serialized `quoted` code.
    content = content.replace(/^([^\r\n]*\.(?:perk|trait)![^\r\n]*)$/gm, line => {
        line = line.replace(/"((?:[^"\\]|\\.)*)"/g, replaceLiteral);

        // modcustchars.df serializes an inner string as
        // `" .. "Gungineer" "quoted .. "`. The identity is a code token
        // between two quote operators, so it is deliberately not a normal
        // JavaScript/Forth string literal and needs its own narrow rewrite.
        return line.replace(
            /("\s+\.\.\s+")([^"\r\n]+?)("\s+"quoted\s+\.\.\s+")/g,
            (whole, prefix, value, suffix) => {
                const translated = translate(value);
                if (!translated || translated === value) return whole;
                changes++;
                return `${prefix}${translated}${suffix}`;
            }
        );
    });

    // Keep explicit direct registry lookups coherent if a mod uses them.
    content = content.replace(
        /"((?:[^"\\]|\\.)*)"(?=\s+(?:perk-find|trait-find)\b)/g,
        replaceLiteral
    );

    return { content, changes };
}

const perkTraitIdentityMap = loadPerkTraitIdentityMap();


/**
 * @param {string} src 
 * @param {string} type 
 * @param {boolean} argInsert 
 * @returns {{ src: string; tokens: string[]; i18nTokens: string[]; template: string; strCount: number; varCount: number; strlits: string[]; codeStrlitIndexes: number[]; id: string;}}
 */
function toTemplate(src, type, argInsert = true) {
    let strCount = 0;
    let varCount = 0;

    /** @type {string[]} */
    const stack = [];

    /** @type {string[]} */
    const strlits = [];
    /** @type {number[]} String slots that contain executable Deathforth source. */
    const codeStrlitIndexes = [];
    src = stripLineComments(src).replace(/[ \t]+$/gm, '');
    const tokens = tokenize(src);
    const i18nTokens = [...tokens];
    let i18nTokensOffset = 0;

    const id = type + '.' + md5hash64(tokens.join(' '));

    for (let index = 0; index < tokens.length; index++) {

        function i18nArgPush() {
            stack.push(`{${varCount}}`);
            i18nTokens.splice(index + i18nTokensOffset++, 0, `${varCount++}`)
            i18nTokens.splice(index + i18nTokensOffset++, 0, 'i18n.arg!')
        }

        /** @type {Object.<string, {arity: number, fn: Function}>} */
        const STACK_OPS = {
            '($': {
                arity: 0, fn: () => {
                    stack.push('')
                }
            },
            '$)': {
                arity: 2, fn: () => {
                    if (stack.length === 0) {
                        stack.push(``);
                        i18nArgPush();
                    }
                    if (stack.length === 1) {
                        i18nArgPush();
                    }
                    const args = stack.splice(stack.length - 2, 2);
                    stack.push(args[0] + args[1]);
                }
            },
            '..': {
                arity: 2, fn: () => {
                    if (stack.length === 0) {
                        stack.push(``);
                        i18nArgPush();
                    }
                    if (stack.length === 1) {
                        i18nArgPush();
                    }
                    const args = stack.splice(stack.length - 2, 2);
                    stack.push(args[0] + args[1]);
                }
            },
            'if': {
                arity: 0, fn: () => {
                    // Deathforth commonly writes the closing token as
                    // `then;`.  More importantly, an extracted candidate
                    // can be incomplete; never walk past the token array in
                    // search of a terminator, as that would spin forever.
                    const thenIndex = tokens.findIndex(
                        (token, tokenIndex) => tokenIndex > index &&
                            (token === 'then' || token === 'then;')
                    );
                    if (thenIndex === -1) {
                        throw new Error(
                            `Unclosed if expression in ${type} candidate; refusing to instrument this block.`
                        );
                    }
                    index = thenIndex;
                }
            },
        };
        STACK_OPS['weegeetm'] = STACK_OPS['..'];
        STACK_OPS['choice('] = STACK_OPS['($'];
        STACK_OPS[')choice'] = STACK_OPS['$)'];

        const colorNames = ["WHITE", "BLUE", "GREEN", "RED", "PURPLE", "SKULL", "FLICKER", "TOGGLE", "RAINBOW", "FLASHY", "BLINKY", "BOUNCY", "BOUNCY_OFF", "ROLLCLR", "BRIGHTER", "GLOW"];

        colorNames.forEach(name => {
            STACK_OPS[name] = {
                arity: 0,
                fn: () => { stack.push(`{${name}}`) }
            };
        });
        /*
: ORANGE GREEN ROLLCLR .. ;
: TEAL PURPLE ROLLCLR .. ;
: NAVY RED ROLLCLR .. ;
: LIME BLUE ROLLCLR .. ;
: NAVYBLUE RED ROLLCLR .. ;
: YELLOW ORANGE BRIGHTER .. ;
: ICE PINK ROLLCLR .. ;
: BPFLASH SKULL ROLLCLR .. ; // blue and pink
: BWFLASH BLINKY ROLLCLR .. ; // black and white
: PBFLASH ORANGE BWFLASH .. ; // purple and black
: PINKFLASH LIME BWFLASH .. ; // pink and black
: LIMEFLSAH BLUE BWFLASH .. ;  // lime and black
: BLUEFLASH RED BWFLASH .. ;  // black and blue
: PINKFLASH2 YELLOW BWFLASH .. ; // a softer pink flash
: ICY PINKFLASH2 BWFLASH .. ; // light blue and black!
: YELLOWFLASH ICY BWFLASH .. ; // yellow and black
: LIMEFLASH NAVYBLUE BWFLASH .. ; // lime and black
: REDFLASH LIMEFLASH BWFLASH .. ; // red and black 
: MONTY GREEN BWFLASH .. ;

: rbold ($ RED .. swap .. WHITE $) ;
: rainbold ($ RAINBOW .. swap .. WHITE $) ;
: pbold ($ PURPLE .. swap .. WHITE $) ;
: bbold ($ BLUE .. swap .. WHITE $) ;
: obold ($ ORANGE .. swap .. WHITE $) ;
: ybold ($ YELLOW .. swap .. WHITE $) ;
: pibold ($ PINK .. swap .. WHITE $) ;
: navybold ($ NAVYBLUE .. swap .. WHITE $) ;
: limebold ($ LIME .. swap .. WHITE $) ;
: ice ($ ICE .. swap .. WHITE $) ;
: fbold ($ 5 textclr$ .. swap .. 0 textclr$ $) ;
: orangeflash ($ ORANGE .. swap .. RAINBOW $) ;
: icepulse ($ ICE .. swap .. FLASHY $) ;
: redflash ($ RED .. swap .. RAINBOW $) ;
: iceflash ($ TEAL .. swap .. WHITE $) ;
         */
        STACK_OPS['rbold'] = {
            arity: 1,
            fn: () => { stack.push(`{RED}${stack.pop()}{WHITE}`) }
        };
        STACK_OPS['rainbold'] = {
            arity: 1,
            fn: () => { stack.push(`{RAINBOW}${stack.pop()}{WHITE}`) }
        };
        STACK_OPS['pbold'] = {
            arity: 1,
            fn: () => { stack.push(`{PURPLE}${stack.pop()}{WHITE}`) }
        };
        STACK_OPS['bbold'] = {
            arity: 1,
            fn: () => { stack.push(`{BLUE}${stack.pop()}{WHITE}`) }
        };
        STACK_OPS['fbold'] = {
            arity: 1,
            fn: () => { stack.push(`{SKULL}${stack.pop()}{WHITE}`) }
        };

        const tok = tokens[index];
        // a) 字符串字面量 → 去引号压栈
        if (tok.startsWith('"')) {
            if (tok.length < 2 || !tok.endsWith('"')) {
                throw new Error(`Unterminated string literal in candidate block: ${JSON.stringify(tok)}`);
            }
            const strlit = tok.slice(1, -1);
            stack.push(strlit);
            // A literal consumed directly by evaluate is Deathforth source,
            // not display text. Translating e.g. RED to 红色 makes INTERPRET
            // execute an unknown word. Keep the slot for stable translation
            // indices, but make the generated runtime path translation-proof.
            if (tokens[index + 1]?.toLocaleLowerCase('en-US') === 'evaluate') {
                i18nTokens.splice(index + 1 + i18nTokensOffset++, 0, 'i18n.code-strlit!');
                codeStrlitIndexes.push(strCount);
            } else {
                i18nTokens.splice(index + 1 + i18nTokensOffset++, 0, `${strCount}`);
                i18nTokens.splice(index + 1 + i18nTokensOffset++, 0, 'i18n.strlit!');
            }
            strlits.push(strlit);
            strCount++;
        }
        // b) 已知操作符 → 从栈上取参数,执行,压回
        else if (argInsert && Object.prototype.hasOwnProperty.call(STACK_OPS, tok)) {
            const { arity, fn } = STACK_OPS[tok];
            fn();
        }
        else {
            // const prev = tokens[index - 1];
            // if (prev === '..' || prev === '$') {
            //     stack.push(`{${varCount}}`);
            //     varCount++;
            // }
        }
    }

    if (argInsert && stack.length !== 1) {
        throw new Error(`Stack not converged, ${stack.length} item(s) remaining: ${JSON.stringify(stack)}, \ntokens: ${JSON.stringify(tokens)}, \nsrc: ${JSON.stringify(src)}`);
    }
    return { src, tokens, i18nTokens, template: argInsert ? stack[0] : undefined, strCount, varCount, strlits, codeStrlitIndexes, id };
}

// require('util').inspect.defaultOptions.breakLength = Infinity;
require('util').inspect.defaultOptions.maxStringLength = Infinity;
require('util').inspect.defaultOptions.compact = Infinity;

// ---------- 6. 主流程 ----------


const files = fs.readdirSync(sourceDeathforthDir, { recursive: true, withFileTypes: true });
const allFiles = files
    .filter(file => file.isFile())
    .map(file => path.join(file.parentPath, file.name));  // 使用 parentPath

const dfFiles = allFiles.filter(file => {
    return path.extname(file) === '.df' && path.basename(file) !== 'base.df';
});

console.log(`Found ${dfFiles.length} .df file(s)`);

const XRegExp = require('xregexp');

/**
 * 通用：用一对定界符提取配对块（支持嵌套）
 * @param {string} src - 源文本
 * @param {string} leftDelim - 左定界符（字面量，函数内部会转义为正则）
 * @param {string} rightDelim - 右定界符（字面量，函数内部会转义为正则）
 * @returns {string[]} 包含定界符的完整块数组
 */
function findDelimitedBlocks(src, leftDelim, rightDelim) {
    // 把字面量转义成正则安全的形式
    const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const inners = XRegExp.matchRecursive(
        src,
        escape(leftDelim),
        escape(rightDelim),
        'g',
        {
            unbalanced: 'skip',   // 遇到不平衡时跳过,不抛错
            // todo: Annotate this line as a temporary fix
            escapeChar: '\\',     // 反斜杠转义
        }
    );
    return inners.map(inner => leftDelim + inner + rightDelim);
}

/**
 * 通用：用一对 Forth 风格的 token(或字符定界符)提取配对块,支持嵌套
 *
 * - 若定界符是「单词类」token(以字母/数字/下划线为边界),则要求两侧
 *   是空白、字符串首尾或非单词字符,避免 END 误匹配 ENDPOINT。
 * - 若定界符是符号类(如 {、[、(),则按字面量直接匹配。
 *
 * @param {string} src        - 源文本
 * @param {string} leftDelim  - 左定界符 token(字面量)
 * @param {string} rightDelim - 右定界符 token(字面量)
 * @param {object} [opts]
 * @param {boolean} [opts.includeDelims] - 返回结果是否包含定界符本身(默认 true)
 * @param {boolean} [opts.leftNotRequireSep] - 返回结果是否包含定界符本身(默认 true)
 * @returns {string[]} 匹配到的块数组
 */
function findDelimitedBlocksFs(src, leftDelim, rightDelim, opts = {}) {
    if (typeof leftDelim !== 'string' || typeof rightDelim !== 'string'
        || leftDelim.length === 0 || rightDelim.length === 0) {
        throw new TypeError('leftDelim 和 rightDelim 必须是非空字符串');
    }

    const leftNotRequireSep = opts.leftNotRequireSep ?? false;

    const includeDelims = opts.includeDelims ?? true;

    // Forth 分隔符:空白字符或字符串首尾
    const isForthSep = ch => ch === undefined || /\s/.test(ch);

    const results = [];
    const stack = [];
    const lLen = leftDelim.length;
    const rLen = rightDelim.length;
    let i = 0;

    while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }

        // 左定界符:前面必须是 Forth 分隔符
        if (src.startsWith(leftDelim, i) && (leftNotRequireSep || isForthSep(src[i - 1]))) {
            stack.push(i);
            i += lLen;
            continue;
        }

        // 右定界符:后面必须是 Forth 分隔符
        if (stack.length
            && src.startsWith(rightDelim, i)
            && isForthSep(src[i + rLen])) {
            const start = stack.pop();
            if (stack.length === 0) {
                const end = i + rLen;
                results.push(includeDelims
                    ? src.slice(start, end)
                    : src.slice(start + lLen, end - rLen));
            }
            i += rLen;
            continue;
        }

        i++;
    }

    return results;
}

const map = { error: [] };

dfFiles.forEach(file => {

    switch (path.basename(file)) {
        case 'boot-end.df':
        // case 'game-select.df':
        case 'cyoa.df':
        case 'locals.df':
            return;
            break;

        default:
            break;
    }

    const mapTemp = {};

    const filePath = file;
    // console.log(`正在执行: ${file}`);
    try {
        // @ts-ignore
        const content = fs.readFileSync(path.resolve(filePath), 'utf-8');
        if (content.includes('\0')) {
            console.warn(`Skipping binary .df file: ${filePath}`);
            return;
        }


        /** @param {string[]} tokens  @param {number} idPos  @param {number} idPopPos @param {string} id */
        function tokenId(tokens, idPos, idPopPos, id) {
            tokens.splice(idPos, 0, `"${id}"`);
            tokens.splice(idPos + 1, 0, `i18n.id!`);
            tokens.splice(idPopPos, 0, `i18n.id@`);
        }

        const matchs = [
            {
                type: 'text-block',
                result: findDelimitedBlocks(content, '($', '$)'),
                argInsert: true,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokens.splice(1, 0, `"${id}"`);
                        tokens.splice(2, 0, `i18n.id!`);

                        tokens.push(`i18n.fmt`);
                    }
            },
            {
                type: 'choice-block',
                result: [
                    ...findDelimitedBlocks(content, 'choice( ', ' )choice')
                ],
                argInsert: true,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokens.splice(1, 0, `"${id}"`);
                        tokens.splice(2, 0, `i18n.id!`);

                        tokens.splice(-1, 0, `$)`);
                        tokens.splice(-1, 0, `i18n.fmt`);
                        tokens.splice(-1, 0, `($`);
                        tokens.splice(-1, 0, `swap`);
                    }
            },
            {
                type: 'choice',
                result: [
                    ...(content.match(/"[^"]*?" choice-card/g) ?? []),
                    ...(content.match(/"[^"]*?" cyoa-choice-text!/g) ?? [])
                ],
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'cyoa-title',
                result: content.match(/"[^"]*?" cyoa-title!/g) ?? [],
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'cyoa-text',
                result: [
                    /"[^"]*?" cyoa-text!/g,
                    /"[^"]*?" [a-z]+bold text!/g,
                    /"[^"]*?" text!/g,
                    /"[^"]*?" [a-z]+bold \+crtext/g,
                    /"[^"]*?" \+crtext/g
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        let pos = -1;
                        if (tokens.at(-2).endsWith('bold') || tokens.at(-2) === '+cr') {
                            pos = -2;
                        }
                        tokenId(tokens, 0, pos, id);
                    }
            },
            {
                type: 'cyoa-text-append',
                result: [
                    /"[^"]*?" \+text/g,
                    /"[^"]*?" [a-z]+bold \+text/g,
                    /"[^"]*?" \+cr \+text/g
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        let pos = -1;
                        if (tokens.at(-2).endsWith('bold') || tokens.at(-2) === '+cr') {
                            pos = -2;
                        }
                        tokenId(tokens, 0, pos, id);
                    }
            },
            {
                type: 'shove',
                result: content.match(/"[^"]*?" shove/g) ?? [],
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'sign-text',
                result: [
                    /"[^"]*?" sign-text!/g,
                    /^(.*) sign-text!$/gm
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'blurbsay',
                result: [
                    /"[^"]*?"[a-zA-Z\s]*blurbsay/g,
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'desc',
                result: [
                    /"[^"]*?" \$desc/g,
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        tokenId(tokens, 0, -1, id);
                    }
            },
            {
                type: 'colon-def',
                result: [
                    /: [^\n]+? if [^\n]+? else [^\n]+? then ;/g,
                    /: [a-zA-Z]+?-oneline[\d]*? "[^"]*?"/g,
                    /: [a-zA-Z]+?-emote[\d]*? "[^"]*?"/g,
                    /: swarmforecast[\s\S]*?\n;/g,
                    /: timeforecast[\s\S]*?\n;/g,
                    /: aggroforecast[\s\S]*?\n;/g,
                    /: siegeforecast[\s\S]*?\n;/g,
                    /: siegetime[\s\S]*?\n;/g,
                    /: car-menu-setup args\( me \)[\s\S]*?\n;/g,
                ].flatMap(re => [...content.matchAll(re)].map(m => m[0])),
                argInsert: false,
                i18nTokenInsert:
                    /** @param {string} id  @param {string[]} tokens  @param {string} type */
                    (id, tokens, type) => {
                        // tokenId(tokens, 2, -1, id);

                        tokens.splice(2, 0, `"${id}"`);
                        tokens.splice(2 + 1, 0, `i18n.id!`);
                        for (let i = tokens.length - 1; i >= 0; i--) {
                            if (tokens[i] === ";" || tokens[i] === 'then;') {
                                tokens.splice(i, 0, "i18n.id@");
                            }
                        }
                    }
            },
        ]
        for (const mat of matchs) {
            for (const item of mat.result) {

                try {
                    const t = toTemplate(item, mat.type, mat.argInsert);

                    if (t.strCount === 0) continue;

                    mat.i18nTokenInsert(t.id, t.i18nTokens, mat.type)

                    if (!mapTemp[mat.type]) mapTemp[mat.type] = {};

                    if (mapTemp[mat.type][t.id]) {
                        mapTemp[mat.type][t.id].orig = [...new Set([...mapTemp[mat.type][t.id].orig, item])];
                    } else {
                        mapTemp[mat.type][t.id] = {
                            orig: [item],
                            tokens: t.tokens.join(' '),
                            i18n: t.i18nTokens.join(' '),
                            template: t.template,
                            strlits: t.strlits,
                            ...(t.codeStrlitIndexes.length > 0
                                ? {'code-strlits': t.codeStrlitIndexes}
                                : {})
                        };
                    }
                } catch (e) {
                    map.error.push({ file: file, error: String(e) + e.stack });
                }
            }
        }
    } catch (e) {
        console.error(e);
    }

    function relocate(fullPath) {
        return path.join(outputDr2cDir, 'deathforth',
            path.relative(sourceDeathforthDir, fullPath));
    }


    // 在循环外读一次内容，循环内累积所有替换
    const targetPath = relocate(file);
    let currentContent = fs.readFileSync(file, 'utf-8');
    let totalChanges = 0;

    for (const [key, value] of Object.entries(mapTemp)) {
        if (key === 'error') continue;
        if (Object.keys(value).length === 0) continue;

        const rep = replaceInContent(currentContent, value);
        if (rep.modified) {
            currentContent = rep.content;
            totalChanges += rep.changes;
        }
    }

    const identityRep = localizePerkTraitIdentifiers(currentContent, perkTraitIdentityMap);
    if (identityRep.changes > 0) {
        currentContent = identityRep.content;
        totalChanges += identityRep.changes;
    }

    if (totalChanges > 0) {
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        const rules = [
            ['chara .trait@ +text', 'chara .trait@ i18n.code-strlit! +text'],
            ['chara .perk@ +text', 'chara .perk@ i18n.code-strlit! +text'],
            ['<- name $upper pbold', '<- name i18n.code-strlit! $upper pbold'],
            ['<- level unlockupgrade? 0 i18n.arg! .. <- name pbold', '<- level unlockupgrade? 0 i18n.arg! .. <- name i18n.code-strlit! pbold'],
            ['<- chara .weapona@ weaponid$ +text', '<- chara .weapona@ weaponid$ i18n.code-strlit! +text'],
            ['<- chara .weaponb@ weaponid$ +text', '<- chara .weaponb@ weaponid$ i18n.code-strlit! +text'],
            ['<- chara .weaponc@ weaponid$ +text', '<- chara .weaponc@ weaponid$ i18n.code-strlit! +text'],
        ];

        rules.forEach(([re, to]) => currentContent = currentContent.replace(re, to));
        fs.writeFileSync(targetPath, currentContent);
    }


    for (let [key, obj] of Object.entries(mapTemp)) {
        if (!map[key]) {
            map[key] = obj;
        } else {
            map[key] = { ...map[key], ...obj }
        }
    }
});

// choice-card: historically used its visible label as the name of the
// dynamically created Forth word.  i18n.strlit! therefore changed the word
// name as well as the label (for example, Chicken -> 鸡).  Saved decks contain
// symbolic word references, so a save made in one language could not be
// evaluated after restarting in another language.
//
// Keep the translated label in the word body, but derive the private word name
// from the stable handler token and deterministic definition order.  The
// serial suffix also keeps two cards which intentionally share one handler
// distinct.  cyoa.df is skipped by the normal text pass, so patch/copy it
// explicitly here.
function installStableChoiceCardIdentity() {
    const sourcePath = path.join(sourceDeathforthDir, 'cyoa.df');
    const targetPath = path.join(outputDr2cDir, 'deathforth', 'cyoa.df');
    const inputPath = fs.existsSync(targetPath) ? targetPath : sourcePath;
    if (!fs.existsSync(inputPath)) return;

    const legacy = ': choice-card: (\') swap dup >r char - 32 r> $replace _choicer last shove ;';
    const replacement = [
        '0 value i18n-choice-card-save-id',
        ': choice-card: (\') "" 0 "" args( text handler stable stable-word legacy )',
        '    <- handler >name "i18n.choice." swap $cat',
        '    "." $cat i18n-choice-card-save-id $cat -> stable',
        '    i18n-choice-card-save-id 1 + to i18n-choice-card-save-id',
        '    <- text dup >r char - 32 r> $replace -> legacy',
        '',
        '    <- handler <- text <- stable _choicer',
        '    last -> stable-word',
        '',
        '    // Keep the pre-fix name available for same-language old saves,',
        '    // but never put that language-dependent alias into new decks.',
        '    <- legacy <- stable $= not if',
        '        <- handler <- text <- legacy _choicer',
        '    then',
        '    <- stable-word swap drop shove',
        ';'
    ].join('\n');

    const content = fs.readFileSync(inputPath, 'utf8');
    const hasStableChoiceCard =
        content.includes('0 value i18n-choice-card-save-id') &&
        content.includes('args( text handler stable stable-word legacy )');
    if (hasStableChoiceCard && content.includes('<- stable-word swap drop shove')) return;

    let nextContent;
    if (hasStableChoiceCard) {
        // Upgrade the first stable-name implementation.  args(...) leaves the
        // original display string on the data stack, so it must be discarded
        // before the stable word is shoved into the target card stack.
        nextContent = content.replace(
            '<- stable-word shove',
            '<- stable-word swap drop shove'
        );
        if (nextContent === content) {
            throw new Error(`Unsupported stable choice-card definition in ${inputPath}`);
        }
    } else {
        if (!content.includes(legacy)) {
            throw new Error(`Unsupported choice-card definition in ${inputPath}`);
        }
        nextContent = content.replace(legacy, replacement);
    }

    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, nextContent);
    console.log('Installed language-stable choice-card save identities.');
}

installStableChoiceCardIdentity();

fs.mkdirSync(outputDr2cDir, {recursive: true});
fs.writeFileSync(path.join(outputDr2cDir, 'data.json'), JSON.stringify(map, null, 4));
const i18n = {};

for (const [key, value] of Object.entries(map)) {
    if (key === 'error') continue;
    if (Object.keys(value).length === 0) continue;

    for (const [key2, value2] of Object.entries(value)) {
        i18n[key2] = {
            tokens: value2.tokens,
            strlits: value2.strlits,
            ...(value2['code-strlits']?.length > 0
                ? {'code-strlits': value2['code-strlits']}
                : {})
        };
    }
}

const i18nOutputDir = path.join(outputDr2cDir, 'i18n');
fs.mkdirSync(i18nOutputDir, {recursive: true});
fs.writeFileSync(path.join(i18nOutputDir, 'en.json'), JSON.stringify(i18n, null, 4));

if (map.error.length > 0) {
    const filesWithSkippedBlocks = [...new Set(map.error.map(entry => entry.file))];
    console.warn(
        `Skipped ${map.error.length} non-convertible text block(s) in ` +
        `${filesWithSkippedBlocks.length} file(s); their original text was left untouched.`
    );
}

if (args.baselineZh) {
    const baselineZh = JSON.parse(fs.readFileSync(path.resolve(args.baselineZh), 'utf8'));
    const zh = {};
    let reusedTranslations = 0;
    const normalizeLineEndings = value => String(value).replace(/\r\n?/g, '\n');
    const compatibleStrlits = (left, right) =>
        Array.isArray(left)
        && Array.isArray(right)
        && left.length === right.length
        && left.every((item, index) =>
            normalizeLineEndings(item) === normalizeLineEndings(right[index])
        );
    const compatibleCodeStrlits = (baseline, current) => {
        // A baseline made by an older generator has no marker. It can still
        // be reused safely because current code slots are restored below.
        if (!Array.isArray(baseline)) return true;
        return Array.isArray(current)
            && baseline.length === current.length
            && baseline.every((item, index) => item === current[index]);
    };
    const compatibleTranslatedStrlits = (translated, source) =>
        Array.isArray(translated)
        && Array.isArray(source)
        && translated.length === source.length;
    const compatibleEntry = (candidate, entry) =>
        candidate
        && typeof candidate.tokens === 'string'
        && normalizeLineEndings(candidate.tokens) === normalizeLineEndings(entry.tokens)
        && compatibleStrlits(candidate.strlits, entry.strlits)
        && compatibleTranslatedStrlits(candidate['translated.strlits'], entry.strlits)
        && compatibleCodeStrlits(candidate['code-strlits'], entry['code-strlits']);
    const baselineByNormalizedTokens = new Map();
    for (const entry of Object.values(baselineZh)) {
        if (!entry || typeof entry.tokens !== 'string') continue;
        const key = normalizeLineEndings(entry.tokens);
        const entries = baselineByNormalizedTokens.get(key) ?? [];
        entries.push(entry);
        baselineByNormalizedTokens.set(key, entries);
    }
    for (const [id, entry] of Object.entries(i18n)) {
        const candidates = [
            ...(baselineZh[id] ? [baselineZh[id]] : []),
            ...(baselineByNormalizedTokens.get(normalizeLineEndings(entry.tokens)) ?? [])
        ];
        // Never trust the numeric/hash id alone. A stale file or an extremely
        // unlikely id collision must also match the complete source tokens,
        // string-slot layout and code-slot layout before reuse.
        const baseline = candidates.find(candidate => compatibleEntry(candidate, entry));
        const compatible = Boolean(baseline);
        if (compatible) {
            const translatedStrlits = [...baseline['translated.strlits']];
            for (const index of entry['code-strlits'] ?? []) {
                // Older translation files may already have translated an
                // executable word. Repair it while reusing all display text.
                translatedStrlits[index] = entry.strlits[index];
            }
            zh[id] = {
                ...entry,
                ...(baseline.template ? {template: baseline.template} : {}),
                'translated.strlits': translatedStrlits
            };
            reusedTranslations++;
        } else {
            // Deliberately keep the source strings. The runtime i18n hook
            // falls back to them when a matching Chinese translation is absent.
            zh[id] = entry;
        }
    }
    fs.writeFileSync(path.join(i18nOutputDir, 'zh.json'), JSON.stringify(zh, null, 4));
    console.log(`Reused ${reusedTranslations}/${Object.keys(i18n).length} compatible Chinese entries.`);
}

/**
 * 在内容字符串上执行替换
 * @param {string} content - 源内容
 * @param {Object<string, {orig: string[], i18n: string}>} replacements
 * @returns {{modified: boolean, changes: number, content: string}}
 */
function replaceInContent(content, replacements) {
    let modifiedContent = content;
    let changes = 0;
    for (const { orig, i18n } of Object.values(replacements)) {
        for (const o of orig) {
            if (!o) continue;
            const parts = modifiedContent.split(o);
            if (parts.length > 1) {
                changes += parts.length - 1;
                modifiedContent = parts.join(i18n);
            }
        }
    }
    return { modified: changes > 0, changes, content: modifiedContent };
}
