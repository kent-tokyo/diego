# diego

公開済みの現行版は **v0.24.0** です。標準ユーザー権限で利用できる、読み取り専用のメール DNS、TLS、ファイル権限、Web ヘッダー、WordPress ポスチャ診断とローカル Web UI を含みます。

認可された防御者・評価者向けの、読み取り専用 Active Directory 診断ツールです。標準ドメイン
ユーザー権限で LDAP、Kerberos、任意のパッシブ観測を行い、JSON・Markdown・HTML の証拠レポートを出力します。

ディレクトリを変更せず、OS コマンドを実行せず、ハッシュをクラックしません。攻撃・横展開の
フレームワークでもありません。Pure Rust は実行ホストのインタプリタ由来テレメトリを減らす
だけで、DC 側やネットワーク側の検知を回避するものではありません。詳細は
[Threat Model](docs/THREAT_MODEL.md) を参照してください。

## 機能

| 対象 | 内容 |
|---|---|
| Active Directory | 読み取り専用の LDAP／Kerberos 診断と、任意のローカル受動観測。 |
| メール DNS | SPF、DMARC、一般的な DKIM セレクタ、MTA-STS、TLS-RPT、CAA、限定的な DNSSEC。 |
| TLS／ファイル権限 | 明示指定した TLS エンドポイントまたは Unix パスのみ。ポートスキャンも内容の読み取りも行いません。 |
| Web ヘッダー | 正確な URL に対する HTTPS リダイレクト、ヘッダー、フレーム保護、Cookie 属性。 |
| WordPress | 指定ルートの generator、X-Pingback、XML-RPC、REST index、`readme.html` を限定確認。 |

Web／WordPress は、URL ごとに未認証の限定リクエストだけを送ります。リダイレクト追跡、クロール、パス探索、認証、フォーム送信は行いません。プラグイン／ユーザー列挙、CVE 検証、攻撃ペイロード送信も対象外です。HTTPS のエラー応答はヘッダー不足と断定せず、判定不能として扱います。

## クイックスタート

~~~bash
cargo build --release
./target/release/diego --dc 10.0.0.1 --domain corp.local \
  --username jdoe --modules all --format json --output report.json
~~~

メールモジュールは読み取り専用で、認証情報もDCも不要です（ドメインとリゾルバのみ）:

~~~bash
./target/release/diego --modules email --domain example.com \
  --dns-resolver 1.1.1.1 --format json --output email.json
~~~

TLS モジュールは読み取り専用で、指定したエンドポイントのみを対象とします（ポートスキャンなし・認証情報不要）:

~~~bash
./target/release/diego --modules tls \
  --tls-target www.example.com:443 --format json
~~~

Web モジュールは、指定した `http://` または `https://` の URL だけを確認します。リダイレクトは追跡せず、認証情報を含む URL・クエリ文字列・フラグメントは拒否します:

~~~bash
./target/release/diego --modules web \
  --web-target https://www.example.com/security --format json
~~~

WordPress モジュールは明示指定したサイトルートだけを対象にし、公開レスポンスの先頭部分と 3 つの標準エンドポイントを確認します。バージョン固有の CVE が存在するという結論は出しません:

~~~bash
./target/release/diego --modules wordpress \
  --wordpress-target https://www.example.com/ --format json
~~~

ローカル UI は `127.0.0.1` にだけ待受し、1 件の URL と診断権限の確認を必須にします。英語・日本語・簡体字中国語・繁体字中国語を切り替えられ、Web ヘッダー確認と WordPress 確認では CLI と同じ限定リクエストだけを送ります:

~~~bash
./target/release/diego --web-ui
# http://127.0.0.1:8787/ を開く
~~~

ファイル権限モジュールは指定パスのみを走査し、権限ビットのみ確認します(内容は読みません)・認証情報不要:

~~~bash
./target/release/diego --modules fs \
  --fs-path ~/.ssh,~/.aws --format json
~~~

通常のスキャンでは --dc、--domain、--username が必須です。パスワードは --password または
DIEGO_PASSWORD で与え、未指定時は対話入力します。keytab/TGT キャッシュ認証は未対応です。既定の
--mode audit ではクラック可能なハッシュを除外します。必要な認可済み作業に限り、--mode full
--export-hashes を明示してください。

主なオプションは `--modules`、`--format`、`--output`、`--baseline`、`--explain`、`--plan`、`--plan-validate`、`--plan-state`、`--sarif-output`、`--webhook-output`、`--mcp`、`--web-target`、`--wordpress-target`、`--web-ui` です。

複数ドメイン計画は `max_parallel` の範囲内で実行されます。`--plan-state PATH` を付けると再開でき、計画のフィンガープリントまたは SHA-256 が一致しない場合は拒否します。`--plan PATH --plan-validate` は認証情報もネットワークも使わずに scope・並列上限・対象を検証します。

## 開発と責任ある利用

~~~bash
cargo test --all
cargo clippy --all -- -D warnings
~~~

- [ロードマップ](ROADMAP.md) — 現在地とリリース条件
- [脅威モデル](docs/THREAT_MODEL.md) — 対象範囲と非対象
- [テスト](docs/TESTING.md) — カバレッジの境界
- [ベンチマーク](docs/BENCHMARKS.md) — 測定方法。実測値は未掲載
- [貢献ガイド](CONTRIBUTING.md)、[セキュリティポリシー](SECURITY.md)、[変更履歴](CHANGELOG.md)

所有または明示的に認可された環境だけを対象にしてください。MIT License。
