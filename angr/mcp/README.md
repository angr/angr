# angr MCP Server

AI Agent 接口，用于通过 Model Context Protocol 访问 angr 的二进制分析功能。

## 功能特性

- **二进制加载**: 加载和分析二进制文件
- **函数分析**: 列出和反汇编函数
- **符号执行**: 执行符号执行和约束求解
- **路径探索**: 探索程序执行路径
- **字符串提取**: 从二进制中提取字符串
- **交叉引用**: 分析函数调用和数据引用
- **约束求解**: 求解符号约束

## 工具列表

### 1. `load_binary`
加载二进制文件进行分析。

```python
result = load_binary(binary_path="/path/to/binary")
# 返回: {"binary_path": "/path/to/binary", "architecture": "AMD64", "bits": 64, ...}
```

### 2. `get_functions`
列出二进制中的所有函数。

```python
result = get_functions()
# 返回: {"functions": [{"name": "main", "address": 0x401000, "size": 100}, ...]}

# 使用过滤器
result = get_functions(filter_pattern="main")
```

### 3. `disassemble`
反汇编指定地址的指令。

```python
result = disassemble(address=0x401000, count=10)
# 返回: {"instructions": [{"address": 0x401000, "mnemonic": "push", "operands": "rbp"}, ...]}
```

### 4. `find_strings`
从二进制中提取字符串。

```python
result = find_strings(min_length=4)
# 返回: {"strings": [{"value": "Hello", "address": 0x402000, "length": 5}, ...]}
```

### 5. `get_xrefs`
获取交叉引用信息。

```python
result = get_xrefs(address=0x401000)
# 返回: {"xrefs": [{"from": 0x401100, "to": 0x401000, "type": "call"}, ...]}
```

### 6. `symbolic_execution`
执行符号执行。

```python
result = symbolic_execution(
    start_address=0x401000,
    find_address=0x401100,
    avoid_address=0x401200
)
# 返回: {"status": "success", "path": [...], "constraints": [...]}
```

### 7. `solve_constraint`
求解符号约束。

```python
result = solve_constraint(
    constraint="x > 100 && x < 200",
    variables=["x"]
)
# 返回: {"solutions": [{"x": 150}, ...]}
```

### 8. `explore_paths`
探索程序执行路径。

```python
result = explore_paths(
    start_address=0x401000,
    max_paths=10
)
# 返回: {"paths": [{"address": 0x401000, "depth": 0}, ...]}
```

## 安装

```bash
pip install angr mcp
```

## 使用方法

### 作为独立服务器运行

```bash
python -m angr.mcp.server --stdio
```

### 传输方式

支持三种传输方式：

1. **stdio**（默认）:
   ```bash
   python -m angr.mcp.server --stdio
   ```

2. **SSE**:
   ```bash
   python -m angr.mcp.server --sse --host 127.0.0.1 --port 8000
   ```

3. **HTTP**:
   ```bash
   python -m angr.mcp.server --http --host 127.0.0.1 --port 8000
   ```

## AI Agent 集成示例

### Claude Desktop 配置

```json
{
  "mcpServers": {
    "angr": {
      "command": "python",
      "args": ["-m", "angr.mcp.server", "--stdio"]
    }
  }
}
```

### 使用示例

```python
from mcp import Client

async def analyze_binary():
    async with Client("angr") as client:
        # 加载二进制
        binary = await client.call_tool("load_binary", {
            "binary_path": "/path/to/binary"
        })
        print(f"Architecture: {binary['architecture']}")
        
        # 列出函数
        functions = await client.call_tool("get_functions", {})
        for func in functions["functions"]:
            print(f"{func['name']} @ {hex(func['address'])}")
        
        # 符号执行
        result = await client.call_tool("symbolic_execution", {
            "start_address": 0x401000,
            "find_address": 0x401100
        })
        print(f"Found path: {result['path']}")
```

## 常见使用场景

### 1. CTF 挑战求解

```python
# 1. 加载二进制
await client.call_tool("load_binary", {"binary_path": "challenge"})

# 2. 查找关键字符串
strings = await client.call_tool("find_strings", {"min_length": 4})
for s in strings["strings"]:
    if "flag" in s["value"].lower():
        print(f"Found: {s['value']} @ {hex(s['address'])}")

# 3. 符号执行找到获胜路径
result = await client.call_tool("symbolic_execution", {
    "start_address": 0x401000,
    "find_address": 0x401200  # "You won!" 地址
})

# 4. 求解输入约束
solution = await client.call_tool("solve_constraint", {
    "constraint": result["constraints"],
    "variables": ["input"]
})
print(f"Solution: {solution['solutions']}")
```

### 2. 漏洞路径分析

```python
# 1. 加载二进制
await client.call_tool("load_binary", {"binary_path": "vulnerable"})

# 2. 探索所有路径
paths = await client.call_tool("explore_paths", {
    "start_address": 0x401000,
    "max_paths": 100
})

# 3. 分析每个路径
for path in paths["paths"]:
    print(f"Path depth: {path['depth']}, final address: {hex(path['address'])}")
```

### 3. 逆向工程辅助

```python
# 1. 反汇编函数
disasm = await client.call_tool("disassemble", {
    "address": 0x401000,
    "count": 50
})

# 2. 获取交叉引用
xrefs = await client.call_tool("get_xrefs", {"address": 0x401000})
print(f"Called from: {[hex(x['from']) for x in xrefs['xrefs']]}")
```

## 测试

运行测试套件：

```bash
pytest angr/tests/test_mcp_tools.py -v
```

测试覆盖率：80%

## 错误处理

所有工具返回统一的错误格式：

```python
{
    "status": "error",
    "message": "Error description"
}
```

## 依赖项

- Python 3.8+
- angr
- mcp (Model Context Protocol SDK)

## 许可证

与 angr 项目相同。

## 相关链接

- [angr 项目](https://github.com/angr/angr)
- [Model Context Protocol](https://modelcontextprotocol.io/)
