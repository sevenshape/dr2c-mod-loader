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

/** @type {Object.<string, {arity: number, fn: Function}>} */
const STACK_OPS = {
    // 'bbold':   { arity: 1, fn: (s) => '{{bbold}}' + s },
    '($': { arity: 0, fn: () => '' },
    // @ts-ignore
    '$)': { arity: 2, fn: (a, b) => a + b },
    // @ts-ignore
    '..': { arity: 2, fn: (a, b) => a + b },
};

// ---------- 4. 分词 ----------
// 字符串字面量 或 非空白序列
const TOKEN_RE = /"(?:[^"\\]|\\.)*"|\S+/g;


/**
 * @param {*} src 
 * @returns {*} 
 */
function tokenize(src) {
    const tokens = src.match(TOKEN_RE) || [];
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


    tokens.forEach(

        /**
         * @param {*} tok 
         * @param {*} index 
         */
        (tok, index) => {
            // a) 字符串字面量 → 去引号压栈
            if (tok.startsWith('"')) {
                stack.push(tok.slice(1, -1));
                strCount++;
            }
            // b) 已知操作符 → 从栈上取参数,执行,压回
            else if (Object.prototype.hasOwnProperty.call(STACK_OPS, tok)) {
                const { arity, fn } = STACK_OPS[tok];
                if (stack.length < arity) {
                    throw new Error(`栈下溢: ${tok} 需要 ${arity} 个参数, 当前栈: ${JSON.stringify(stack)}`);
                }
                // 从栈顶取 arity 个,按原顺序传入(Python 里 pop 后再反转)
                const args = stack.splice(stack.length - arity, arity);
                stack.push(fn(...args));
            }
            // c) 带参调用 gstats{ key }(已注释,保留)
            // else if (CALL_RE.test(tok)) {
            //   const m = tok.match(CALL_RE);
            //   stack.push(`{{${m[1]}:${m[2]}}}`);
            // }
            // d) 其他光秃秃的标识符 → 视前一个 token 决定是否当变量占位符压栈
            else {
                const prev = tokens[index - 1];
                if (prev === '..' || prev === '($') {
                    stack.push(`%${varCount + 1}$s`);
                    varCount++;
                }
            }
        });

    if (stack.length !== 1) {
        throw new Error(`栈未收敛, 剩余 ${stack.length} 项: ${JSON.stringify(stack)}, \ntokens: ${JSON.stringify(tokens)}, \nsrc: ${JSON.stringify(src)}`);
    }
    return { key: JSON.stringify(tokens), tokens, template: stack[0], strCount, varCount };
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
function findBlocks(src) {
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
        const BLOCK_RE = /\(\$ [\s\S]*? \$\)/g;
        const result = findBlocks(content);
        // console.log(result);
        for (const item of result) {
            const t = toTemplate(item);
            // if (t.strCount !== 0)
            //     console.log(JSON.stringify(t, null, 4));
        }
        
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