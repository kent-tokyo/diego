# diego

現行の作業対象は v0.22.0 です。crates.io 公開を一時停止し、ローカル・オフラインで開発しています。

認可された防御者・評価者向けの、読み取り専用 Active Directory 診断ツールです。標準ドメイン
ユーザー権限で LDAP、Kerberos、任意のパッシブ観測を行い、JSON・Markdown・HTML の証拠レポートを出力します。

ディレクトリを変更せず、OS コマンドを実行せず、ハッシュをクラックしません。攻撃・横展開の
フレームワークでもありません。Pure Rust は実行ホストのインタプリタ由来テレメトリを減らす
だけで、DC 側やネットワーク側の検知を回避するものではありません。詳細は
[Threat Model](docs/THREAT_MODEL.md) を参照してください。

## 機能

- LDAP: AS-REP候補、SPN、委任、RBCD、特権グループ、古いサービスパスワード、description内の資格情報候補、パスワードポリシー
- Kerberos: AS-REP/TGS要求と、任意の Hashcat 互換証拠
- パッシブ: ローカルインターフェース上の LLMNR/NBT-NS と平文プロトコルの観測
- 出力: JSON、Markdown、HTML、ベースライン差分、Finding説明、限定露出グラフ、修正シミュレーション、ガバナンス、SARIF、Webhook、複数ドメイン計画、MCP stdio サーバー
- Claude 分析・チャット（ANTHROPIC_API_KEY が必要）

## クイックスタート

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

通常のスキャンでは --dc、--domain、--username が必須です。パスワードは --password、DIEGO_PASSWORD、
keytab/TGT キャッシュ、対話プロンプトの順に取得します。既定の --mode audit ではクラック可能なハッシュを除外します。
必要な認可済み作業に限り、--mode full --export-hashes を明示してください。

主なオプションは --modules、--format、--output、--baseline、--timeout、--interface、--explain、--exposure-graph、
--simulate-remediation、--plan、--plan-validate、--plan-state、--governance-*、--sarif-output、--webhook-output、
--attack-path、--attack-path-output、--ai-analyze、--chat、--mcp、--mcp-init です。

複数ドメイン計画は `max_parallel` の範囲内で実行され、`--plan-state PATH` を付けると完了済み対象をスキップして再開できます。計画のフィンガープリントまたは SHA-256 が一致しない場合は再開を拒否します。認証情報なしで `--plan PATH --plan-validate` を実行すると、scope・並列上限・対象だけを検証できます。

## 開発と責任ある利用

~~~bash
cargo test --all
cargo clippy --all -- -D warnings
~~~

[CONTRIBUTING.md](CONTRIBUTING.md)、[TESTING](docs/TESTING.md)、[BENCHMARKS](docs/BENCHMARKS.md)、[ROADMAP](ROADMAP.md) も参照してください。
所有または明示的に認可された環境だけを対象にし、脆弱性は [SECURITY.md](SECURITY.md) の手順で非公開に報告してください。MIT License です。
