# diego

目前工作樹目標版本為 v0.22.0。crates.io 發佈暫停，開發流程僅使用本機與離線驗證。

提供給獲授權的防禦人員與評估者使用的唯讀 Active Directory 診斷工具。它以標準網域使用者權限透過 LDAP、Kerberos 與可選的被動監聽收集證據，輸出 JSON、Markdown 或 HTML。

diego 不修改目錄、不執行作業系統命令、不破解雜湊，也不是利用或橫向移動框架。Pure Rust 只能降低操作主機上的直譯器執行期遙測，不能規避 DC 或網路側偵測。詳見 [Threat Model](docs/THREAT_MODEL.md)。

功能包括 LDAP 風險發現、AS-REP/TGS 請求、LLMNR/NBT-NS 與明文協定觀察，以及基線差異、Finding 說明、有限暴露圖、修復模擬、治理、SARIF、Webhook、多網域計畫和 MCP stdio 伺服器。Claude 分析需要 ANTHROPIC_API_KEY。

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

一般掃描需要 --dc、--domain、--username。請用 --password 或 DIEGO_PASSWORD 提供密碼；未提供時會互動提示。keytab/TGT 快取認證尚未支援。預設 --mode audit 會隱藏可破解雜湊；只有在獲授權且確有需要時使用 --mode full --export-hashes。常用選項還包括 --baseline、--explain、--sarif-output、--webhook-output、--plan-validate、--plan-state、--mcp 和 --mcp-init。

多網域計畫使用 `max_parallel` 限制並行數。加入 `--plan-state PATH` 可在批次之間保存並恢復本機狀態；計畫指紋或 SHA-256 不相符時會拒絕恢復。使用 `--plan PATH --plan-validate` 可在沒有憑證和網路連線時驗證 scope、並行上限和目標。

請只檢查你擁有或明確獲授權的環境。開發與貢獻規則見 [CONTRIBUTING.md](CONTRIBUTING.md)，安全問題請依 [SECURITY.md](SECURITY.md) 私下回報。MIT License。
