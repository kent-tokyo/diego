# DIEGO - Domain Intranet Elusive Guardian & Offensive-Scouter

Pure Rust で実装された非特権 Active Directory セキュリティ診断エージェント

---

**DIEGO** は、Active Directory 環境での攻撃後の偵察とセキュリティ診断を行うエージェントです。標準的なドメインユーザー認証情報のみで動作し、ノイズの多いネットワーク動作を生成せず、単一の静的バイナリとして提供されます。

## 主な特徴

- **非特権実行** — 標準的なドメインユーザー認証情報のみで動作。管理者権限は一切不要です。
- **ステルス性 (OPSEC 対応)** — 正規の AD クエリのみを発行。攻撃的なスキャンなし。リクエスト間の設定可能な遅延により、通常のドメイン トラフィックに溶け込みます。
- **ポータブル** — ランタイム依存なしの単一静的バイナリ。任意のターゲットホストで実行可能。
- **Pure Rust** — .NET CLR、PowerShell、Python インタープリタなし。Kerberos ASN.1 フレーム、LDAP、RC4-HMAC のすべてのプロトコル相互作用は Pure Rust (RustCrypto) で実装。EDR 製品が最も積極的に監視する ETW / AMSI / Script Block Logging の攻撃面を完全に排除。
- **AI 統合** — Claude API 統合により、スキャン結果を一貫性のある攻撃ナラティブに合成。MCP サーバーモードにより、LLM クライアントが個別の診断ツールを直接調整できます。

---

## クイックスタート

```bash
# CLI モード — すべての診断モジュールを実行
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss

# AI 分析付き (ANTHROPIC_API_KEY が必要)
diego --dc 10.0.0.1 --domain corp.local --username jdoe --password P@ss --ai-analyze

# スキャン後のインタラクティブ AI チャット
diego ... --ai-analyze --chat

# MCP サーバーモード (Claude Desktop / MCP クライアント用)
diego --mcp
```

---

## 診断モジュール

### Kerberos — `Asn1Kerberos`

ポート 88 経由で KDC と直接 ASN.1/Kerberos フレームを使用して相互作用。

- **AS-REP Roasting** — Kerberos 事前認証が無効なアカウントを特定し、AS-REP ハッシュをキャプチャ
- **Kerberoasting** — SPN 付きアカウントのすべてのTGS チケットを要求
- すべてのハッシュは Hashcat 互換形式 (`$krb5asrep$`, `$krb5tgs$`) で出力

### LDAP — `LdapQuery`

ドメインコントローラーに対して読み取り専用 LDAP クエリを実行。

- AD トポロジー列挙 (ドメイン、フォレスト、サイト、信頼)
- Description フィールド認証情報漏洩検出
- 制約のない委任の発見
- パスワードポリシー抽出 (ロックアウト閾値、最小長、複雑性)

### パッシブ監視 — `PassiveListen`

パケット送信なしでローカルネットワークトラフィックを監視。

- LLMNR / NBT-NS ブロードキャスト検出 → 名前ポイズニング攻撃に対して脆弱なホストを特定
- クリアテキストプロトコル監視 (LDAP、HTTP、FTP、Telnet)

### AI 分析

`ANTHROPIC_API_KEY` が必要です。

- Claude による未加工スキャン結果からの攻撃ナラティブ生成
- ドメイン管理者への重要なパスを特定
- 優先順位付きの復旧勧告
- フォローアップ調査のためのインタラクティブチャットモード

---

## MCP サーバーモード

`diego --mcp` で起動時、バイナリは Model Context Protocol サーバーを公開します。MCP 互換クライアント (Claude Desktop、カスタム LLM エージェント) が個別の診断ツールを直接起動できます。

| ツール | 説明 |
|---------|-------------|
| `enumerate_asrep_candidates` | 事前認証が無効なアカウントをリスト |
| `enumerate_spn_accounts` | SPN が登録されているアカウントをリスト |
| `enumerate_constrained_delegation` | S4U2Self → S4U2Proxy 委任を持つアカウント/コンピューターを検索 |
| `enumerate_rbcd` | リソースベース制約付き委任を持つオブジェクトを検索 |
| `enumerate_privileged_groups` | 高権限グループ (DA/EA/Backup Ops など) のメンバーをリスト |
| `enumerate_stale_service_passwords` | パスワード >365 日前の SPN アカウントを検索 |
| `check_unconstrained_delegation` | 制約のない委任を持つコンピューター/アカウントを検索 |
| `check_password_policy` | ドメインパスワード/ロックアウトポリシー + スプレー推定を取得 |
| `scan_description_leaks` | AD Description 内の埋め込み認証情報を検索 |
| `run_asrep_roasting` | AS-REP ハッシュをキャプチャしてオフラインクラッキング用に取得 |
| `run_kerberoasting` | TGS ハッシュをキャプチャしてオフラインクラッキング用に取得 |
| `listen_llmnr` | パッシブ LLMNR/NBT-NS ブロードキャスト監視 |
| `full_scan` | すべてのモジュールを実行して統合 JSON レポートを返却 |

---

## 類似ツールとの比較

| 機能 | **diego** | BloodHound / SharpHound | Impacket (GetUserSPNs 他) | PowerView | Rubeus | PingCastle |
|---------|-----------|-------------------------|-----------------------------|-----------|--------|------------|
| 言語 / ランタイム | Rust — 単一静的バイナリ | C# (.NET) + Python | Python 3 | PowerShell | C# (.NET) | C# (.NET) |
| **Pure Rust / C ランタイムなし** | **はい** | いいえ (.NET CLR) | いいえ (CPython) | いいえ (PS ランタイム) | いいえ (.NET CLR) | いいえ (.NET CLR) |
| 必要な権限 | **標準ユーザーのみ** | エンドポイント上のローカル管理者 | ドメインユーザー (一部操作は管理者必要) | ドメインユーザー | ドメインユーザー | ドメイン管理者推奨 |
| EDR 検出可能性 | **低** — .NET/PS/Python なし | 高 — .NET リフレクション、AMSI | 中 | 高 — AMSI / Script Block Logging | 高 — .NET、既知署名 | 中 |
| アクティブスキャン / ノイズ | **なし** — 読み取り専用 LDAP + Kerberos のみ | あり — SMB、RPC、大量 LDAP ダンプ | 中程度 | 中程度 | あり | あり — 広範な LDAP/RPC |
| Jitter / OPSEC スロットリング | **あり** | なし | なし | なし | なし | なし |
| AS-REP Roasting | **あり** | なし (データのみ) | あり (`GetNPUsers.py`) | なし | **あり** | なし |
| Kerberoasting | **あり** | なし (データのみ) | あり (`GetUserSPNs.py`) | なし | **あり** | なし |
| 制約なし委任 | **あり** | **あり** | 部分的 | **あり** | なし | **あり** |
| パスワードポリシー | **あり** | なし | なし | **あり** | なし | **あり** |
| Description 認証情報漏洩 | **あり** | なし | なし | 部分的 | なし | なし |
| LLMNR/NBT-NS 検出 | **あり** | なし | なし | なし | なし | なし |
| クリアテキストプロトコル検出 | **あり** | なし | なし | なし | なし | なし |
| クロスプラットフォーム (Linux) | **あり** | なし | **あり** | なし | なし | なし |
| AI 分析 (Claude API) | **あり** | なし | なし | なし | なし | なし |
| MCP サーバーモード | **あり** | なし | なし | なし | なし | なし |
| 構造化 JSON 出力 | **あり** | **あり** (Neo4j) | 部分的 | なし | 部分的 | なし (HTML) |
| ゼロインストール / ドロップ実行 | **あり** | なし | なし | なし | なし | なし |

### まとめ

- **BloodHound** は攻撃パス可視化のゴールドスタンダードですが、SharpHound 収集にはローカル管理者が必要で、大量のノイズ (SMB、RPC、LDAP 一括ダンプ) が発生します。Roasting のようなアクティブ攻撃は実施しません。
- **Impacket** は Roasting をよくカバーしていますが、攻撃側マシン上に Python 環境が必要で、侵害されたホスト上で実行できません。
- **Rubeus** は最も高度な Kerberos 攻撃ツールですが、.NET のみ、Windows のみ、EDR に大きく署名されています。
- **PowerView** は LDAP 列挙に強力ですが、PowerShell は最新の SOC で最も監視される実行環境です。
- **PingCastle** は意図面で diego に最も近い (ドメインヘルスチェック) ですが、昇格特権が必要で、HTML のみの出力、ステルスポスチャがありません。
- **diego** はそのギャップを埋めます: Linux または Windows 上の標準ユーザーセッションから実行される単一バイナリ、EDR トリガースタイルのランタイムを回避、および AI への発見を直接供給してナラティブ合成を実施。

---

## ビルド

```bash
cargo build --release

# 静的 Linux バイナリ (musl ターゲットが必要)
cargo build --release --target x86_64-unknown-linux-musl
```

リリースプロファイルは LTO、単一コードジェン単位、およびバイナリストリップを適用して、サイズを最小化し、パフォーマンスを最大化します。

---

## OPSEC 注意事項

- いかなる時点でも OS コマンド実行なし — すべての操作は純粋なネットワークプロトコル相互作用です。
- ランダム化された遅延は LDAP および Kerberos リクエスト間に適用され、均一なタイミング署名を回避します。
- すべてのクエリは、標準的な Windows ドメインワークステーション およびドメイン管理ツールで発行されるクエリと機能的に同一です。
- ディレクトリへの書き込みなし、すべての操作は厳密に読み取り専用です。

---

## ライセンス

MIT
