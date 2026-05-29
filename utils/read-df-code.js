#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

// ---------- 1. 命令行参数解析 ----------

/**
 * 
 *
 * @param {*} argv 
 * @returns {{ file: any; encoding: string; }} 
 */
function parseArgs(argv) {
    const args = { file: null, encoding: 'utf-8' };
    const rest = argv.slice(2);
    for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (a === '-h' || a === '--help') {
            console.log('用法: node script.js <file> [-e|--encoding <enc>]');
            console.log('  读取文本文件，匹配所有非空白字符串并输出');
            process.exit(0);
        } else if (a === '-e' || a === '--encoding') {
            args.encoding = rest[++i];
        } else if (a.startsWith('--encoding=')) {
            args.encoding = a.split('=')[1];
        } else if (!args.file) {
            args.file = a;
        }
    }
    if (!args.file) {
        console.error('错误: 缺少文件路径参数');
        process.exit(1);
    }
    return args;
}

const args = parseArgs(process.argv);



// 过滤测试用(对应 Python 里的 test 变量,目前未使用)
// const test = result.filter(s => s.includes('gstats{ best-gamemode-streak }'));

// ---------- 3. 栈操作定义 ----------



// ---------- 4. 分词 ----------

/**
 * @param {*} src 
 * @returns {*} 
 */
function tokenize(src) {
    // 字符串字面量 或 非空白序列
    const tokens = src.match(/"(?:[^"\\]|\\.)*"|\S+/g) || [];
    return tokens;
}

// 带参调用 gstats{ key }(目前未使用,保留供后续启用)
// const CALL_RE = /^([a-zA-Z_][\w-]*)\{\s*([^}]*?)\s*\}$/;

// ---------- 5. 解释器 ----------

/**
 * @param {string} src 
 * @returns {{}} 
 */
function toTemplate(src) {
    let strCount = 0;
    let varCount = 0;

    /**
     * @type {string[]}
     */
    const stack = [];
    const tokens = tokenize(src);
    const i18nTokens = [...tokens];
    let i18nTokensOffset = 0;

    for (let index = 0; index < tokens.length; index++) {

        /** @type {Object.<string, {arity: number, fn: Function}>} */
        const STACK_OPS = {
            // 'bbold':   { arity: 1, fn: (s) => '{{bbold}}' + s },
            // '($': {
            //     arity: 0, fn: () => {
            //         stack.push('')
            //     }
            // },
            '$)': {
                arity: 2, fn: () => {
                    if (stack.length === 0) {
                        stack.push(``);
                        stack.push(`%${varCount + 1}$s`);
                        i18nTokens.splice(index + i18nTokensOffset, 0, 'i18n.arg.push')
                        varCount++;
                        i18nTokensOffset++;
                    }
                    if (stack.length === 1) {
                        stack.push(`%${varCount + 1}$s`);
                        i18nTokens.splice(index + i18nTokensOffset, 0, 'i18n.arg.push')
                        varCount++;
                        i18nTokensOffset++;
                    }
                    const args = stack.splice(stack.length - 2, 2);
                    stack.push(args[0] + args[1]);
                }
            },
            '..': {
                arity: 2, fn: () => {
                    if (stack.length === 0) {
                        stack.push(``);
                        stack.push(`%${varCount + 1}$s`);
                        i18nTokens.splice(index + i18nTokensOffset, 0, 'i18n.arg.push')
                        varCount++;
                        i18nTokensOffset++;
                    }
                    if (stack.length === 1) {
                        stack.push(`%${varCount + 1}$s`);
                        i18nTokens.splice(index + i18nTokensOffset, 0, 'i18n.arg.push')
                        varCount++;
                        i18nTokensOffset++;
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

        const tok = tokens[index];
        // a) 字符串字面量 → 去引号压栈
        if (tok.startsWith('"')) {
            stack.push(tok.slice(1, -1));
            strCount++;
        }
        // b) 已知操作符 → 从栈上取参数,执行,压回
        else if (Object.prototype.hasOwnProperty.call(STACK_OPS, tok)) {
            const { arity, fn } = STACK_OPS[tok];
            fn();
        }
        else {
            // const prev = tokens[index - 1];
            // if (prev === '..' || prev === '($') {
            //     stack.push(`%${varCount + 1}$s`);
            //     varCount++;
            // }
        }
    }

    if (stack.length !== 1) {
        throw new Error(`栈未收敛, 剩余 ${stack.length} 项: ${JSON.stringify(stack)}, \ntokens: ${JSON.stringify(tokens)}, \nsrc: ${JSON.stringify(src)}`);
    }
    return { src, tokens, i18nTokens, template: stack[0], strCount, varCount };
}

// require('util').inspect.defaultOptions.breakLength = Infinity;
require('util').inspect.defaultOptions.maxStringLength = Infinity;
require('util').inspect.defaultOptions.compact = Infinity;

// ---------- 6. 主流程 ----------


const files = fs.readdirSync(args.file);
// console.log(files)
const dfFiles = files.filter(file => { return path.extname(file) === '.df' && path.basename(file) !== 'base.df' });

console.log(`找到 ${dfFiles.length} 个 .df 文件`);

const XRegExp = require('xregexp');

/**
 * @param {string} src 
 * @returns 
 */
function findTextBlocks(src) {
    // matchRecursive 返回的是“去掉定界符的内部内容”,
    // 我们想要包含定界符的完整块,所以手动拼回去。
    const inners = XRegExp.matchRecursive(
        src,
        '\\(\\$ ',          // 左定界符正则(注意双反斜杠)
        ' \\$\\)',          // 右定界符正则
        'g',
        {
            unbalanced: 'skip',   // 遇到不平衡时跳过,不抛错
            escapeChar: '\\',     // 反斜杠转义(让 \$) 不当作定界符)
        }
    );
    return inners.map(inner => '($ ' + inner + ' $)');
}

dfFiles.forEach(file => {
    const filePath = path.join(args.file, file);
    // console.log(`正在执行: ${file}`);

    try {
        // @ts-ignore
        const content = fs.readFileSync(path.resolve(filePath), args.encoding);
        const result = findTextBlocks(content);
        const matchs = [
            {
                type: '($',
                result: findTextBlocks(content),
                i18nTokenInsert:
                    /**
                     * 
                     * @param {string} src 
                     * @param {string[]} tokens 
                     */
                    (src, tokens) => { tokens.push(`"${src.replaceAll('"', '\uE034')}"`); tokens.push(`i18n.format`) }
            },
            {
                type: 'shove',
                result: content.match(/"[^"]*?" shove/g) || [],
                i18nTokenInsert:
                    /**
                     * 
                     * @param {string} src 
                     * @param {string[]} tokens 
                     */
                    (src, tokens) => { tokens.splice(-1, 0, `"${src.replaceAll('"', '\uE034')}"`); tokens.splice(-1, 0, `i18n.format`) }
            },
            // {
            //     type: 'choice(',
            //     result: content.match(/choice\([\s\S]*?\)choice/g) || []
            // },
            // {
            //     type: 'choice-card',
            //     result: content.match(/""[^"]*?" \w?choice-card/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // },
            // {
            //     type: 'shove',
            //     result: content.match(/"[^"]*?" shove/g) || []
            // }
        ]
        const map = {};
        for (const mat of matchs) {
            for (const item of mat.result) {

                try {
                    const t = toTemplate(item);
                    // @ts-ignore
                    mat.i18nTokenInsert(JSON.stringify(t.tokens), t.i18nTokens)

                    // @ts-ignore
                    map[JSON.stringify(item)] = t.i18nTokens.join(' ');
                } catch (e) {
                    console.error(e);
                }

                // @ts-ignore
                // if (t.strCount !== 0 && mat.type === 'shove')
                //     console.log(JSON.stringify(t, null, 4));
            }
        }
        console.log(map);


    } catch (e) {
        console.error(`执行 ${file} 失败:`, e);
    }
});
// @ts-ignore
// const content = fs.readFileSync(path.resolve(args.file), args.encoding);

// const BLOCK_RE = /\(\$ [\s\S]*? \$\)/g;
// const result = content.match(BLOCK_RE) || [];

// for (const item of result) {
//     //   console.log(JSON.stringify(item));
//     const t = toTemplate(item);
//     if (t.strCount !== 0)
//         console.log(JSON.stringify(t, null, 4));
// }