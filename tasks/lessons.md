# Diego — 教訓 (Lessons Learned)

## Rust / 言語

### `ThreadRng` は `Send` でない
`rand::thread_rng()` は `!Send` なので、`async fn` で `.await` をまたいで保持するとコンパイルエラーになる。
解決策: `let n: u32 = rand::random();` か、rng使用をブロック内に閉じてdropさせる。

### Edition 2024 では `gen` が予約語
`rng.gen()` が `gen` キーワード衝突でコンパイル不可になる。
`rand::random::<u32>()` に置き換えるのが最もシンプル。

### `async-trait` なしに async fn をトレイトに入れると複雑になる
Rust 1.75+ の `async fn in trait` (RPITIT) は対応しているが、`Send` 境界の扱いが煩雑。
`async-trait` クレートを使うと `Send + Sync` を自動補完してくれるため、今は素直に使うべき。

### rasn-kerberos のAPIより手書きDERの方が安定
`rasn-kerberos` のフィールド名はASN.1仕様のスネークケース変換だが、`from` (Rustキーワード) が `r#from` になるなど、バージョン間で変動する可能性がある。
AS-REQのような決まったパケット構造は手書きDERエンコーダーの方が将来的に安定。

### DER INTEGER エンコーディング: 符号拡張を厳密に
`der_int(-1)` でループが回らずパニックするバグがあった。原因は負数を `!n >> ...` でループするロジック。
**解決策**: `i64::to_be_bytes()` で常に8バイル得てから、冗長な符号拡張バイトを前からstrip。
```rust
let all8 = n.to_be_bytes();
let mut start = 0;
while start < 7 && ((all8[start] == 0x00 && all8[start+1] & 0x80 == 0) || 
                     (all8[start] == 0xFF && all8[start+1] & 0x80 != 0)) {
    start += 1;
}
tlv(0x02, &all8[start..])
```

### MD4実装: マクロ内で変数スコープ衝突に注意
inline MD4実装で大量マクロを使うと変数名衝突やスコープ混乱が生じる。
**解決策**: マクロを廃止して48ステップ全て明示的に展開。読みづらくなるが正確性が上がる。

### MD4テストベクタ：`"Password"` (大文字P) vs `"password"` (小文字)
RFC 1320テストベクタは全て小文字。大文字Pは異なるハッシュを生成する。
NTLMハッシュテストでは大文字小文字を区別して両方テストすること。

### `Md4::digest()` は `GenericArray<u8, 16>` を返す
`finalize().into()` で直接 `[u8; 16]` へ変換できない。
**解決策**: `let result = Digest::digest(input); let mut hash = [0u8; 16]; hash.copy_from_slice(&result);`

## アーキテクチャ

### LDAP→Kerberosの依存関係
LDAPでSPNリストとAS-REP候補リストを取得してからKerberosモジュールに渡す必要がある。
並列実行するとKerberosモジュールのターゲットが空になる。「先行実行→並列実行」の順序を守ること。

### MCP toolsでの `Config` 再構築
MCPツールは各callに `dc_ip/domain/username/password` を受け取り、都度 `Config` を組み立てる。
既存のCLIの `Config::from_cli()` に依存せず、MCP用の `build_minimal_config()` を別に用意するのが明確。

### `pnet` のblocking I/OはSpawnBlockingで包む
`pnet::datalink::DataLinkReceiver::next()` はブロッキング。
`tokio::task::spawn_blocking` でスレッドプールに逃がさないとtokioのランタイムを詰まらせる。

### ライブラリクレート (`lib.rs`) は integration test で必須
`tests/` ディレクトリの統合テストが diego の内部 API にアクセスするには、
`src/lib.rs` で public モジュールを宣言する必要がある。
binary crate としての `src/main.rs` とは独立した `[lib]` セクションを Cargo.toml に追加。

## AI統合

### Claude APIのレスポンスをJSONでパースする際のフェンス除去
`--ai-analyze` でClaude にJSONを返すよう指示しても、```json ... ``` のコードフェンスで囲んで返すことがある。
`trim_start_matches("```json")` 等でフェンスを除去してからパースする必要がある。

### MCPのtoolsの粒度
粒度が粗すぎると（`full_scan` 一択）Claudeが状況に応じた判断を挟めない。
粒度が細かすぎると会話が長くなりすぎる。
「列挙系」と「実行系」に分けるのがちょうどよい（例: `enumerate_spn_accounts` → `run_kerberoasting`）。

## テスト・CI

### 統合テストは mock を最小化
実際のKDCサーバーをmockするとき、テスト対象の部分（AS-REQ → TCP → AS-REP パース）だけを
正確に再現すればよい。フル KRB5仕様の完全なAS-REPを作る必要はなく、
`[APPLICATION 11] SEQUENCE { [0] pvno, [1] msg-type, [6] enc_part }` で十分。

### cargo test は全テストスイートを実行
`cargo test --lib` (unit only), `cargo test --test mock_kdc` (specific integration test),
`cargo test` (all) の違いを意識。デフォルトは全て実行。

## OPSEC・セキュリティ

### Pure Rust = EDR回避の基本
C依存がなく、.NET / PowerShell / Python を経由しないことは強力なセキュリティ特性。
ただし TCP / UDP 通信自体は検知可能なので、jitter や read-only 操作に徹することで検知を難化させる。

### Password spray 推定値の算出
ロックアウト閾値と間隔から「安全なスプレーレート」を計算できる。
例: lockoutThreshold=5 の場合、最大4回まで試行可能。lockoutDuration=30分なら、30分ごとに1アカウント試行。
Finding の `evidence` フィールドにこの推定値を含めることで、LLMが戦術を立てやすくなる。

### Windows FILETIME 変換
`pwdLastSet` は Windows FILETIME（1601-01-01 からの100ナノ秒単位）。
Unix秒に変換: `(filetime - 116_444_736_000_000_000) / 10_000_000`。
逆方向（日数オフセット）: `now_unix_secs * 10_000_000 + 116_444_736_000_000_000`。
