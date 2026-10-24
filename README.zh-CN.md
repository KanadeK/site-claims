# site-claims 中文说明

诊断 Python 环境中“多个包声明拥有同一个文件”的问题。即使 `pip check` 通过，
不同发行包仍可能相互覆盖模块；卸载其中一个后，另一个需要的文件也可能消失。

本工具读取明确指定的 `site-packages` 目录，列出共享文件、每个包记录的哈希与当前
磁盘内容的匹配情况，并模拟移除指定发行包集合后，哪些剩余包仍声明拥有这些文件。
相同字节的共享文件也会报告，因为卸载风险仍然存在。共享命名空间目录内的不同文件
不会被误判成同一个文件。

Python 3.10+，仅标准库，MIT。建议安装到独立的工具虚拟环境。安装与完整命令参见
[英文 README](README.md)。Windows 示例（工具环境已激活）：

```powershell
site-claims target-venv\Lib\site-packages
site-claims target-venv\Lib\site-packages --removing example-beta --format json
site-claims target-venv\Lib\site-packages --verify --format json
```

Linux/macOS 通常指定 `target-venv/lib/python3.13/site-packages`，版本号按目标目录调整。
不要启动可疑环境的解释器来检查它。扫描器不会导入目标包、执行目标 `.pth`、联网、
安装、修复或删除文件。`--removing` 只是推演，可以重复指定多个发行包名称。

安装后运行 `python examples/demo.py`，会在临时虚拟环境中用两个原创测试 wheel
实际执行 pip 安装、依赖检查、冲突诊断、卸载和丢失文件验证；结束后自动清理。

默认只对共享路径读取并校验内容；`--verify` 扩展到所有已声明的内部文件。退出码：
0 表示当前限定范围无发现，1 表示有共享文件、内容异常、元数据问题或排除项需要查看，
2 表示参数、目录、移除名称或总体资源上限错误。正常的命令行脚本常在目录外，也会
列为排除项并使退出码为 1，这不代表恶意软件。请查看 JSON 的明细与覆盖范围。

当前版本仅处理一个库目录；不读取目录外路径、符号链接、junction、特殊文件或旧式
`.egg-info`。哈希不能证明可信来源，元数据也可能过期或不诚实。未知哈希保留为未知。
POSIX 按精确路径拼写比较，大小写不敏感的 macOS 卷可能有未合并的别名。请检查静止
目录或快照；并发恶意修改文件系统不属于安全隔离保证。具体资源上限、报告格式和
局限见 [设计文档](docs/DESIGN.md)。

卸载时使用工具环境中的 `python -m pip uninstall site-claims`。工具不会在目标目录
生成状态；不再使用时可通过文件管理器删除工具虚拟环境及源码目录。
