# diego

已发布的当前版本是 **v0.24.0**：包括 Active Directory 诊断，以及无需凭据的邮件 DNS、指定 TLS 端点、指定 Unix 路径、Web 响应头和 WordPress 检查，以及本地 Web UI。本地 UI 可切换英语、日语、简体中文和繁体中文。

面向获授权的防御人员和评估人员的只读 Active Directory 诊断工具。它以标准域用户权限通过 LDAP、Kerberos 和可选的被动监听收集证据，并输出 JSON、Markdown 或 HTML。

diego 不修改目录、不执行操作系统命令、不破解哈希，也不是漏洞利用或横向移动框架。Pure Rust 只能减少操作主机上的解释器运行时遥测，不能规避 DC 或网络侧检测。详见 [Threat Model](docs/THREAT_MODEL.md)。

功能包括只读 LDAP/Kerberos 诊断、可选的本地被动观察、邮件 DNS、指定 TLS 端点和 Unix 文件权限检查。开发中的 Web/WordPress 功能只接受明确指定的 URL 或站点根目录：每个 URL 只发出有限的未认证请求，不跟随重定向、不爬取、不认证、不枚举用户或插件、不验证 CVE，也不发送攻击载荷。

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

普通扫描需要 `--dc`、`--domain`、`--username`。请用 `--password` 或 `DIEGO_PASSWORD` 提供密码；未提供时会交互提示。keytab/TGT 缓存认证尚未支持。默认 `audit` 模式会隐藏可破解材料；仅在获授权且确有需要时才同时使用 `--mode full --export-hashes`。

多域计划使用 `max_parallel` 限制并发。加入 `--plan-state PATH` 可在批次之间保存并恢复本地状态；计划指纹或 SHA-256 不匹配时会拒绝恢复。使用 `--plan PATH --plan-validate` 可在没有凭据和网络连接时验证 scope、并发上限和目标。

请只检查你拥有或明确获授权的环境。开发命令和贡献规则见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。MIT License。
