---
tool_name: angr
mcp_server: angr.mcp.server
version: 1.0
author: AI Assistant
created: 2026-07-08
updated: 2026-07-08
tags: [binary-analysis, symbolic-execution, constraint-solving, automated-reasoning]
---

# angr MCP Skill

## 概述

angr 是一个强大的二进制分析框架，支持静态分析、符号执行和约束求解。通过 MCP Server，AI Agent 可以自动化分析二进制文件、探索执行路径、求解约束条件。

### 主要功能

- **二进制加载**: 加载各种格式的二进制文件
- **函数分析**: 列出、反汇编和分析函数
- **符号执行**: 自动探索程序路径
- **约束求解**: 求解符号约束找到输入
- **路径探索**: 发现所有可能的执行路径
- **字符串提取**: 从二进制中提取字符串
- **交叉引用**: 分析函数调用和数据引用

### 适用场景

- CTF Reverse/Pwn 题自动求解
- 二进制漏洞自动发现
- 恶意代码行为分析
- 程序路径覆盖分析
- 输入约束自动求解

## 工具选择指南

### 何时使用 angr

- 需要自动探索程序所有执行路径
- 需要求解复杂的输入约束
- 需要找到到达特定代码路径的输入
- 需要进行二进制文件的静态分析
- 需要自动化逆向工程任务

### 与其他工具的对比

| 工具 | 类型 | 优势 | 劣势 |
|------|------|------|------|
| angr | 符号执行 | 自动化程度高、路径探索 | 性能开销大、状态爆炸 |
| pwndbg | 动态调试 | 实时分析、交互式 | 需要手动探索 |
| Ghidra | 静态分析 | 反编译、可视化 | 无法自动求解 |
| radare2 | 静态/动态 | 轻量级、多平台 | 学习曲线陡峭 |

### 典型使用场景

1. **CTF 自动求解**: 自动找到到达 "You win!" 的输入
2. **漏洞路径发现**: 找到触发特定漏洞的代码路径
3. **密码/密钥恢复**: 从约束中恢复加密密钥
4. **混淆代码分析**: 自动分析混淆后的程序逻辑

## 支持的工具

### 核心工具

- `load_binary` - 加载二进制文件
- `get_functions` - 列出所有函数
- `disassemble` - 反汇编指令
- `find_strings` - 提取字符串
- `get_xrefs` - 获取交叉引用
- `symbolic_execution` - 符号执行
- `solve_constraint` - 约束求解
- `explore_paths` - 路径探索

## 参数最佳实践

### load_binary

```python
# 推荐：指定分析选项
result = load_binary(
    binary_path="/path/to/binary",
    auto_load_libs=True,  # 自动加载共享库
    perform_analysis=True  # 执行自动分析
)

# 对于大型二进制，禁用自动分析以提高速度
result = load_binary(
    binary_path="/path/to/large_binary",
    perform_analysis=False
)
```

### symbolic_execution

```python
# 推荐：明确指定 find 和 avoid 地址
result = symbolic_execution(
    start_address=0x401000,
    find_address=0x401200,  # 目标地址
    avoid_address=0x401300  # 避免地址
)

# 对于复杂程序，设置超时
result = symbolic_execution(
    start_address=0x401000,
    find_address=0x401200,
    timeout=60  # 60 秒超时
)
```

### solve_constraint

```python
# 推荐：使用具体的变量名
result = solve_constraint(
    constraint="x > 100 && x < 200 && x % 7 == 0",
    variables=["x"]
)

# 多变量约束
result = solve_constraint(
    constraint="x + y == 100 && x > 50 && y > 30",
    variables=["x", "y"]
)
```

### explore_paths

```python
# 推荐：限制路径数量避免状态爆炸
result = explore_paths(
    start_address=0x401000,
    max_paths=100,  # 限制最大路径数
    max_depth=20    # 限制探索深度
)
```

## 错误处理

参考 [MCP_ERROR_HANDLING.md](../MCP_ERROR_HANDLING.md) 中的错误码定义。

### 二进制分析错误 (2000-2999)

| 错误码 | 名称 | 解决方案 |
|--------|------|----------|
| 2001 | BINARY_LOAD_FAILED | 检查文件格式是否支持、文件是否损坏 |
| 2002 | INVALID_BINARY_FORMAT | 确认是有效的 ELF/PE/Mach-O 文件 |
| 2003 | ARCHITECTURE_NOT_SUPPORTED | 检查架构是否在支持列表中 |
| 2004 | ANALYSIS_FAILED | 减少分析范围或禁用自动分析 |
| 2005 | SYMBOL_NOT_FOUND | 使用地址而非符号名称 |
| 2006 | ADDRESS_INVALID | 检查地址是否在有效范围内 |
| 2007 | DISASSEMBLY_FAILED | 确认地址指向有效指令 |
| 2008 | DECOMPILATION_FAILED | 尝试使用反汇编代替反编译 |

### 常见错误及解决方案

**错误 1: 状态爆炸**
```
Error: ANALYSIS_FAILED - Too many states, analysis aborted
```
解决方案：
- 使用 `avoid_address` 排除不需要的路径
- 减少 `max_paths` 和 `max_depth`
- 使用 `explore_paths` 的 `prune` 选项

**错误 2: 约束无解**
```
Error: CONSTRAINT_UNSATISFIABLE - No solution found
```
解决方案：
- 检查约束条件是否矛盾
- 放宽约束条件
- 检查 find/avoid 地址是否正确

**错误 3: 符号未找到**
```
Error: SYMBOL_NOT_FOUND - Symbol 'main' not found
```
解决方案：
- 使用 `get_functions` 列出可用函数
- 使用函数地址而非名称
- 检查二进制是否被 strip

## Workflow 示例

### 基础工作流：CTF 挑战自动求解

```python
async def solve_ctf_challenge(binary_path):
    # 1. 加载二进制
    binary = await load_binary(binary_path=binary_path)
    print(f"Architecture: {binary['architecture']}")

    # 2. 查找关键字符串
    strings = await find_strings(min_length=4)
    for s in strings["strings"]:
        if "flag" in s["value"].lower() or "win" in s["value"].lower():
            print(f"Found: {s['value']} @ {hex(s['address'])}")

    # 3. 列出函数
    functions = await get_functions()
    main_func = next(f for f in functions["functions"] if f["name"] == "main")

    # 4. 符号执行找到获胜路径
    result = await symbolic_execution(
        start_address=main_func["address"],
        find_address=0x401200,  # "You win!" 地址
        avoid_address=0x401300  # "You lose!" 地址
    )

    # 5. 求解输入约束
    if result["status"] == "success":
        solution = await solve_constraint(
            constraint=result["constraints"],
            variables=["input"]
        )
        print(f"Solution: {solution['solutions']}")
```

### 高级工作流：漏洞路径分析

```python
async def find_vulnerability_path(binary_path, vuln_address):
    # 1. 加载二进制
    await load_binary(binary_path=binary_path)

    # 2. 获取所有函数
    functions = await get_functions()

    # 3. 对每个函数进行符号执行
    for func in functions["functions"]:
        result = await symbolic_execution(
            start_address=func["address"],
            find_address=vuln_address,
            max_depth=10
        )

        if result["status"] == "success":
            print(f"Found path from {func['name']} to vulnerability")
            print(f"Constraints: {result['constraints']}")

            # 求解输入
            solution = await solve_constraint(
                constraint=result["constraints"],
                variables=["input"]
            )
            return solution["solutions"]

    return None
```

### 多工具协作：结合静态和符号执行

```python
async def combined_analysis(binary_path):
    # 1. 使用 Ghidra 进行初步分析
    ghidra_result = await ghidra_client.call_tool(
        "get_functions", {}
    )

    # 2. 识别可疑函数
    suspicious = [f for f in ghidra_result["functions"]
                 if any(kw in f["name"].lower() for kw in ["vuln", "check", "verify"])]

    # 3. 使用 angr 进行符号执行
    await load_binary(binary_path=binary_path)

    for func in suspicious:
        # 探索从函数入口到关键代码的路径
        paths = await explore_paths(
            start_address=func["address"],
            max_paths=10
        )

        for path in paths["paths"]:
            # 分析每个路径
            disasm = await disassemble(
                address=path["address"],
                count=20
            )
            print(f"Path: {disasm}")
```

## Prompt 模板

### 基础调用模板

```python
# 调用 angr MCP 工具
async def analyze_with_angr():
    # 加载二进制
    result = await mcp_client.call_tool(
        tool_name="load_binary",
        arguments={"binary_path": "/path/to/binary"}
    )

    if result["status"] == "success":
        binary = result["data"]
        print(f"Loaded: {binary['architecture']}")
    else:
        print(f"Error: {result['error_message']}")
```

### 高级分析模板

```python
# 自动化 CTF 求解
async def automated_ctf_solver(binary_path, target_address):
    """
    自动化 CTF 求解流程：
    1. 加载二进制
    2. 查找关键字符串
    3. 符号执行找到路径
    4. 求解输入约束
    """
    # 加载
    await mcp_client.call_tool("load_binary", {"binary_path": binary_path})

    # 查找字符串
    strings = await mcp_client.call_tool("find_strings", {"min_length": 4})
    interesting = [s for s in strings["data"]["strings"]
                  if "flag" in s["value"].lower()]

    # 符号执行
    result = await mcp_client.call_tool("symbolic_execution", {
        "start_address": 0x401000,
        "find_address": target_address
    })

    if result["status"] == "success":
        # 求解
        solution = await mcp_client.call_tool("solve_constraint", {
            "constraint": result["data"]["constraints"],
            "variables": ["input"]
        })
        return solution["data"]["solutions"]
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
"""
angr MCP 自动化分析脚本
"""
import asyncio
from mcp import Client

async def main():
    async with Client("angr") as client:
        # 加载二进制
        binary = await client.call_tool("load_binary", {
            "binary_path": "challenge"
        })
        print(f"Architecture: {binary['data']['architecture']}")

        # 查找字符串
        strings = await client.call_tool("find_strings", {"min_length": 4})
        for s in strings["data"]["strings"][:10]:
            print(f"String: {s['value']}")

        # 符号执行
        result = await client.call_tool("symbolic_execution", {
            "start_address": 0x401000,
            "find_address": 0x401200
        })

        if result["status"] == "success":
            print(f"Found path with {len(result['data']['path'])} steps")

if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 性能优化建议

1. **控制探索范围**
   - 使用 `avoid_address` 排除不需要的路径
   - 设置合理的 `max_paths` 和 `max_depth`
   - 使用 `explore_paths` 的剪枝选项

2. **优化约束求解**
   - 简化约束表达式
   - 使用具体的变量类型
   - 避免过于复杂的约束

3. **分批分析**
   - 对大型二进制分段分析
   - 优先分析关键函数
   - 缓存分析结果

### 安全注意事项

1. **资源限制**
   - 设置超时避免无限分析
   - 限制内存使用
   - 在隔离环境中运行

2. **输入验证**
   - 验证二进制文件来源
   - 检查文件大小和格式
   - 避免分析恶意构造的文件

3. **结果验证**
   - 验证求解结果的正确性
   - 检查路径的可行性
   - 交叉验证多个工具的结果

### 常见问题解答

**Q: 如何处理状态爆炸问题？**
A: 使用 `avoid_address` 排除不需要的路径，设置 `max_paths` 限制，使用 `explore_paths` 的剪枝选项。

**Q: 如何加速分析过程？**
A: 禁用自动分析（`perform_analysis=False`），优先分析关键函数，使用缓存机制。

**Q: 如何处理加密/混淆的代码？**
A: 先使用动态调试（pwndbg）找到解密后的代码，再使用 angr 分析。

**Q: 如何分析大型二进制？**
A: 分段分析，优先分析关键函数，使用 `get_functions` 识别目标函数。

**Q: 如何处理多线程程序？**
A: angr 对多线程支持有限，建议使用动态调试工具（pwndbg、Frida）分析多线程程序。

---

**相关资源**
- [angr 项目](https://github.com/angr/angr)
- [MCP 协议](https://modelcontextprotocol.io/)
- [错误处理规范](../MCP_ERROR_HANDLING.md)
