#!/usr/bin/env node
const { error } = require('console');
const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const crypto = require('crypto');


/**
 * @param {string} text 
 * @returns {bigint} 
 */
function simhash64(text) {
    // 1. 分词（中文建议用 nodejieba，英文按空格切）
    const tokens = text.split(/\s+/).filter(Boolean);

    // 2. 64 维向量
    const vector = new Array(64).fill(0);

    for (const token of tokens) {
        // 用 MD5 取前 64 位作为 token 的哈希
        const hash = crypto.createHash('md5').update(token).digest();
        const bigHash = BigInt('0x' + hash.toString('hex').slice(0, 16));

        // 3. 按位累加/累减
        for (let i = 0; i < 64; i++) {
            const bit = (bigHash >> BigInt(i)) & 1n;
            vector[i] += bit === 1n ? 1 : -1;
        }
    }

    // 4. 生成最终指纹
    let fingerprint = 0n;
    for (let i = 0; i < 64; i++) {
        if (vector[i] > 0) {
            fingerprint |= (1n << BigInt(i));
        }
    }

    return fingerprint; // BigInt
}



const program = new Command();

program
    .description('')
    .parse(process.argv);

const args = program.opts();

const deathforth = 'assets/dr2c/deathforth_orig';


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
 * @param {string} src 
 * @param {string} type 
 * @param {boolean} argInsert 
 * @returns {{ src: string; tokens: string[]; i18nTokens: string[]; template: string; strCount: number; varCount: number; strlits: string[]; id: string;}} 
 */
function toTemplate(src, type, argInsert = true) {
    let strCount = 0;
    let varCount = 0;

    /** @type {string[]} */
    const stack = [];

    /** @type {string[]} */
    const strlits = [];
    src = src.replace(/\/\/.*$/gm, '').replace(/[ \t]+$/gm, '');
    const tokens = tokenize(src);
    const i18nTokens = [...tokens];
    let i18nTokensOffset = 0;

    const id = type + '.' + simhash64(tokens.join(' '));

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
                    while (tokens[index] !== 'then') {
                        // console.log('if步进token', tokens[index])
                        index += 1;
                    }
                    // index += 1;
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
            const strlit = tok.slice(1, -1);
            stack.push(strlit);
            i18nTokens.splice(index + 1 + i18nTokensOffset++, 0, `${strCount}`);
            i18nTokens.splice(index + 1 + i18nTokensOffset++, 0, 'i18n.strlit!');
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
    return { src, tokens, i18nTokens, template: argInsert ? stack[0] : undefined, strCount, varCount, strlits, id };
}

// require('util').inspect.defaultOptions.breakLength = Infinity;
require('util').inspect.defaultOptions.maxStringLength = Infinity;
require('util').inspect.defaultOptions.compact = Infinity;

// ---------- 6. 主流程 ----------


const files = fs.readdirSync(deathforth, { recursive: true, withFileTypes: true });
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
                        tokenId(tokens, 2, -1, id);
                    }
            },
        ]
        for (const mat of matchs) {
            for (const item of mat.result) {

                try {
                    const t = toTemplate(item, mat.type, mat.argInsert);

                    if (t.strCount === 0) continue;

                    mat.i18nTokenInsert(t.id, t.i18nTokens, mat.type)

                    !mapTemp[mat.type] ? mapTemp[mat.type] = {} : '';
                    mapTemp[mat.type][t.id]
                        = { orig: item, i18n: t.i18nTokens.join(' '), template: t.template, strlits: t.strlits };
                } catch (e) {
                    map.error.push({ file: file, error: String(e) + e.stack })
                }
            }
        }
    } catch (e) {
        console.error(e);
    }

    // 在循环外读一次内容，循环内累积所有替换
    const targetPath = file.replace('deathforth_orig', 'deathforth');
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

    if (totalChanges > 0) {
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
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

fs.writeFileSync('assets/dr2c/data.json', JSON.stringify(map, null, 4));
const i18n = {};

for (const [key, value] of Object.entries(map)) {
    if (key === 'error') continue;
    if (Object.keys(value).length === 0) continue;

    for (const [key2, value2] of Object.entries(value)) {
        i18n[key2] = { orig: value2.orig, strlits: value2.strlits };
    }
}
fs.writeFileSync('assets/dr2c/i18n/en.json', JSON.stringify(i18n, null, 4));

/**
 * 在内容字符串上执行替换
 * @param {string} content - 源内容
 * @param {Object<string, {orig: string, i18n: string}>} replacements
 * @returns {{modified: boolean, changes: number, content: string}}
 */
function replaceInContent(content, replacements) {
    let modifiedContent = content;
    let changes = 0;

    for (const { orig, i18n } of Object.values(replacements)) {
        const parts = modifiedContent.split(orig);
        if (parts.length > 1) {
            changes += parts.length - 1;
            modifiedContent = parts.join(i18n);
        }
    }


    return { modified: changes > 0, changes, content: modifiedContent };
}