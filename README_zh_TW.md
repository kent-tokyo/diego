# diego

目前已發佈版本為 **v0.24.0**：包括 Active Directory 診斷，以及不需憑證的郵件 DNS、指定 TLS 端點、指定 Unix 路徑、Web 回應標頭與 WordPress 檢查，以及本機 Web UI。本機 UI 可切換英文、日文、簡體中文與繁體中文。

提供給獲授權的防禦人員與評估者使用的唯讀 Active Directory 診斷工具。它以標準網域使用者權限透過 LDAP、Kerberos 與可選的被動監聽收集證據，輸出 JSON、Markdown 或 HTML。

diego 不修改目錄、不執行作業系統命令、不破解雜湊，也不是利用或橫向移動框架。Pure Rust 只能降低操作主機上的直譯器執行期遙測，不能規避 DC 或網路側偵測。詳見 [Threat Model](docs/THREAT_MODEL.md)。

功能包括唯讀 LDAP/Kerberos 診斷、可選的本機被動觀察、郵件 DNS、指定 TLS 端點與 Unix 檔案權限檢查。開發中的 Web/WordPress 功能只接受明確指定的 URL 或網站根目錄：每個 URL 只發出有限的未驗證請求，不追蹤重新導向、不爬取、不驗證身分、不列舉使用者或外掛、不驗證 CVE，也不傳送攻擊載荷。

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

一般掃描需要 `--dc`、`--domain`、`--username`。請用 `--password` 或 `DIEGO_PASSWORD` 提供密碼；未提供時會互動提示。keytab/TGT 快取認證尚未支援。預設 `audit` 模式會隱藏可破解資料；只有在獲授權且確有需要時才同時使用 `--mode full --export-hashes`。

多網域計畫使用 `max_parallel` 限制並行數。加入 `--plan-state PATH` 可在批次之間保存並恢復本機狀態；計畫指紋或 SHA-256 不相符時會拒絕恢復。使用 `--plan PATH --plan-validate` 可在沒有憑證和網路連線時驗證 scope、並行上限和目標。

請只檢查你擁有或明確獲授權的環境。開發與貢獻規則見 [CONTRIBUTING.md](CONTRIBUTING.md)，安全問題請依 [SECURITY.md](SECURITY.md) 私下回報。MIT License。
