import re
import argparse
import html
import json

# 创建解析器
parser = argparse.ArgumentParser(description='读取文本文件，匹配所有非空白字符串并输出')
parser.add_argument('file', help='文件路径')
parser.add_argument('-e', '--encoding', default='utf-8', help='文件编码，默认 utf-8')

args = parser.parse_args()

# 读取文本文件
with open(args.file, 'r', encoding=args.encoding) as f:
    content = f.read()

# 匹配所有非空白字符串为数组
result = re.findall(r'\(\$ [\s\S]*? \$\)', content)

test = [s for s in result if 'gstats{ best-gamemode-streak }' in s]



STACK_OPS = {
    # "bbold":   (1, lambda s: "{{bbold}}" + s),
    "($":      (0, lambda : ''),
    "$)":      (2, lambda a, b: a + b),
    "..":      (2, lambda a, b: a + b),
}

# ---------- 2. 分词 ----------
TOKEN = re.compile(r'''
    "(?:[^"\\]|\\.)*"            # 字符串字面量
#   | \.\.                          # 拼接
#   | \(\$                          # 裸 ($
#   | \$\)                          # 裸 $)
  | [\S]+              # 普通标识符
''', re.VERBOSE)

CALL = re.compile(r'([a-zA-Z_][\w-]*)\{\s*([^}]*?)\s*\}')

def tokenize(src):
    print(TOKEN.findall(src))
    return TOKEN.findall(src)

# ---------- 3. 解释器 ----------
def to_template(src):
    strCount = 0
    varCount = 0
    stack = []
    tokens = tokenize(src);
    for index,tok in enumerate(tokens):
        # a) 字符串字面量 → 去引号压栈
        if tok.startswith('"'):
            stack.append(tok[1:-1])
            strCount+=1

        # b) 已知操作符 → 从栈上取参数,执行,压回
        elif tok in STACK_OPS:
            arity, fn = STACK_OPS[tok]
            if len(stack) < arity:
                raise ValueError(f"栈下溢: {tok} 需要 {arity} 个参数",stack)
            args = [stack.pop() for _ in range(arity)][::-1]  # 反转回正常顺序
            stack.append(fn(*args))

        # c) 带参调用 gstats{ key } → 当作占位符压栈
        # elif (m := CALL.match(tok)):
        #     name, arg = m.group(1), m.group(2)
        #     stack.append("{{" + name + ":" + arg + "}}")

        # d) 其他光秃秃的标识符 → 当占位符压栈
        else:
            if tokens[index-1]=='..':
                stack.append("{{v" + str(varCount) + "}}")
                varCount+=1
            elif tokens[index-1]=='($':
                stack.append("{{v" + str(varCount) + "}}")
                varCount+=1
            # else:
            #     stack[-1] = stack[-1] + "<" + html.escape(tok) + ">"

    if len(stack) != 1:
        raise ValueError(f"栈未收敛, 剩余 {len(stack)} 项: {stack}")
    return stack[0],strCount,varCount

# for item in test:
#     print(repr(item))

for item in result:
    print(json.dumps(item))
    print(json.dumps(to_template(item)))
# src = '($ "Beat 6 different game modes to " $)'
# print(src)
# print(to_template(src))

# 输出结果
# print(result)