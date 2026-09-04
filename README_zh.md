# diego

当前工作树目标版本为 v0.22.0。crates.io 发布暂时暂停，开发流程仅使用本地和离线验证。

面向获授权的防御人员和评估人员的只读 Active Directory 诊断工具。它以标准域用户权限通过 LDAP、Kerberos 和可选的被动监听收集证据，并输出 JSON、Markdown 或 HTML。

diego 不修改目录、不执行操作系统命令、不破解哈希，也不是漏洞利用或横向移动框架。Pure Rust 只能减少操作主机上的解释器运行时遥测，不能规避 DC 或网络侧检测。详见 [Threat Model](docs/THREAT_MODEL.md)。

功能包括 LDAP 风险发现、AS-REP/TGS 请求、LLMNR/NBT-NS 与明文协议观察，以及基线差异、Finding 解释、有限暴露图、修复模拟、治理、SARIF、Webhook、多域计划和 MCP stdio 服务。Claude 分析需要 ANTHROPIC_API_KEY。

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

普通扫描需要 --dc、--domain、--username。密码按 --password、DIEGO_PASSWORD、keytab/TGT 缓存、交互提示的顺序获取。默认 --mode audit 会隐藏可破解哈希；仅在获授权且确有需要时使用 --mode full --export-hashes。常用选项还包括 --baseline、--explain、--sarif-output、--webhook-output、--plan-validate、--plan-state、--mcp 和 --mcp-init。

多域计划使用 `max_parallel` 限制并发。加入 `--plan-state PATH` 可在批次之间保存并恢复本地状态；计划指纹或 SHA-256 不匹配时会拒绝恢复。使用 `--plan PATH --plan-validate` 可在没有凭据和网络连接时验证 scope、并发上限和目标。

请只检查你拥有或明确获授权的环境。开发命令和贡献规则见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。MIT License。
