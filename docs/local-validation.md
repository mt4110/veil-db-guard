# 実装・ローカル検証記録

実施日: 2026-11-02。対象はT01/T02からRust実装・ローカル検証までの継続作業です。AWS認証・API・実RDS/Proxyへの接続、課金、公開・pushは行っていません。

## 到達点

**M1のローカル共通契約は完了しました。M2は主要なCLI・adapter・試験器・評価器を実装し、L層で確認しましたが、一部producerが未実装のため全体完了とはしません。** 状態の正本は [タスク一覧](tasks.md) です。

| 部分 | 実装と確認 |
| --- | --- |
| 対象・依存 | PG16.15/東京/E2E IAM、Rust1.98.1、macOS ARM64を固定。実AWS値はT16へ分離 |
| config/domain | strict YAML、未知/重複/未展開/不正対象/不正SQL識別子/上限の拒否。秘密を取る設定fieldなし |
| store | privateな新規run、上書き拒否、manifest/byte上限/hash、部分失敗、directory fdによる出力先固定 |
| plan | 現状の不足/差分/変更・復旧・再確認、専用新規sandbox CFN、別bootstrap SQLの生成 |
| inventory | 6種の固定Describe、限定selector、partial/拒否/未取得、target/SG/parameter/class/AZの正規化。fixture runnerで検証 |
| probe | 明示suite、SigV4、標準TLS検証、段階別接続観測、固定合成SQL、再接続、期限/取消し、COMMIT結果不明の照合、計測時系列 |
| evaluator | 固定case、profile/phase別評価、実artifactとbefore/after、許可差分、復旧後条件、管理主体、比較条件の照合。不足はUnknown |
| report/CLI | plan→inspect fixture→probe記録→reportの統合、JSON/Markdown、操作と防御判定の分離、固定エラー、秘密非出力 |

ソースは一つのRust crate内で責務を分けています。AWS inventoryは既設AWS CLI v2のadapterで、巨大なRDS/EC2 SDKへの初期依存を避けました。理由と仕様根拠は [依存判断](dependency-decisions.md) を参照します。

## 最終チェック

| チェック | 結果 | 範囲 |
| --- | --- | --- |
| `cargo test --locked` | 76件成功、失敗0、実DB用2件は明示ignored | 内部署名2、CLI7、config/store10、評価35、inventory9、planner4、probe9 |
| `PG_BIN=… cargo test --locked --test probes_postgres -- --ignored --nocapture` | 2件成功、失敗0 | 新規PG17.7/TLS/合成データ、実CLI、COMMIT応答喪失 |
| Homebrew `cargo-clippy clippy --all-targets --locked -- -D warnings` | 成功 | 警告抑制・MSRV緩和なし |
| Homebrew `cargo-fmt fmt --all -- --check` | 成功 | source/test全体 |
| cfn-lint 1.59.0、東京指定 | 成功 | 生成sandboxのローカルschema/static検査。未適用 |
| cargo-audit 0.22.2 | 既知脆弱性0、警告0 | 最終Cargo.lock、RustSec DB commit `2295466c4e9df26647fd67d8fa1c705ac2fc7f81`（DB更新表示2026-10-30） |

Homebrew Rust/Cargo 1.98.1を使用しました。rustupと混在するtoolchainの探索差を避け、Clippy/fmtはHomebrew実体を明示しました。既定toolchainを変更したり、検査失敗を無効化したりしていません。

ローカルでの依存取得と検査toolの導入は行いました。cargo-auditとcfn-lint環境は `target/local-audit-tool/` と `target/cfn-lint-env/` に置き、製品のruntime依存へ混ぜていません。

## 動かした一連の操作

`examples/local.yaml`と`examples/aws-responses.json`を使い、実バイナリで以下を確認しました。

1. plan: 終了0、未適用CFN/SQLを生成、operation_only=true。
2. inspect fixture: 終了0、LocalFixtureとして正規化、AWSを呼ばない。
3. probe fixture: 終了0、試験未実施の空観測を記録、operation_only=true。
4. report: **終了3、Unknown**。空観測をPassにしない。
5. 同じ生成物をcfn-lintで検査し、終了0。

保持先: `runs/local-verification-20261102-x64w3bqx/`。この一連操作のbuild fingerprintは `7168108b554556bef626410d459b4678b9d2684d774f1e3e0c6dee25cf3dc902` です。詳細summaryは `target/verification/demo-result.json`、通常試験logは `target/verification/cargo-test.log` に保持します。

このpipelineは試験器/記録/評価の統合確認です。DB防御の成立やIAM拒否を確認した結果ではありません。実際のloopback SQL/TLSは次の実DB試験で確認しています。

## ローカル実DB試験

既設Nix storeのPostgreSQL **17.7** とOpenSSL **3.6.4** を使い、既存DBを再利用せず、新規cluster・一日有効の専用CA/localhost証明書・合成DB/userを作りました。127.0.0.1だけで起動し、終わったclusterは停止、証拠とデータは保持しました。

- 正しいCA/ホスト名のTLS成功、TLS無効/誤CA/ホスト名不一致の拒否。
- 合成CRUD、commit/rollback、途中エラー後rollback、別session可視性、prepare/session state/reset。
- 明示した短いtransaction、切断・期限・取消し後の再接続、server statement_timeout。
- COMMIT応答だけを失うfaultで、結果不明→新規接続のread-only marker照合→行数1を確認。書込を再送しない。
- 固定SQLの接続確立/再利用SQLの時系列と集計。標本不足ではp99を出さない。
- 実CLIのlocal-lab/password-stdin/書込分岐、manifest、LocalConnection種別、COMMIT後条件、出力全体のダミーpassword非漏出。

最終保持先は `/tmp/vdg-pg-lab-58PCgZ` と `/tmp/vdg-pg-lab-chw5Pw`、logは `target/verification/postgres-test.log` です。[接続試験記録](probe-validation.md)に再現手順と以前の試験も記載しています。**PG17.7の成功をRDS16.15/Proxy互換性の実証にはしません。**

## レビューで修正した主な不整合

- 任意snapshotのendpointを信用してtokenを作らないよう、live CLIは明示許可のAWS再読取で照合してから接続する。
- artifactとmanifestを含む総予算をwriter/verifierで統一し、正常保存物が読めなくなる境界を修正。
- 出力directoryを開いたfdへ固定し、rename/symlink差替えで別directoryのmanifestを上書きしない。
- sourceだけでなくtarget/compiler/profile/features等もbuild fingerprintへ含める。
- APIのProxy target識別子をDB名とresource IDで区別し、bootstrapのDB CREATE権限とprobeのrun固有schema作成を揃える。
- 負例で期待した認証/TLS拒否は試験完了として記録し、timeout等と分ける。TLS無効負例で正規秘密を送らない。
- AWSのPassに旧式Fact自己申告だけを使うfallbackを除去し、実artifact/前後snapshot/計画/後条件を要求。
- 性能のphase流用、source kind/address familyの変更、class/AZ/runner条件の不一致、操作記録の欠落を反例で検査。

主担当と3担当で実装・検証・レビューを分担しました。既知の指摘は修正済みですが、レビューや試験数を全欠陥不存在・本番安全性の証明とは扱いません。[評価器検証記録](evaluator-validation.md)にも評価の境界を記載しています。

## 依存監査とライセンスの範囲

最初の監査で `rustls-pemfile` と `unsafe-libyaml` の保守終了警告が出ました。前者をrustls-pki-types標準PEM機能へ、後者に依存するYAML parserをserde-saphyrへ置換して再監査し、警告も0件になりました。警告のignore設定は追加していません。

Cargo metadataの依存221パッケージ（dev/target別を含む）のlicense宣言を確認し、未宣言はありませんでした。MIT/Apache系のほかBSD/ISC/Unicode/CDLA等の表記があります。これは宣言の棚卸しで、配布物の完全な第三者帰属・ライセンス文書の完成ではありません。製品自身のライセンス選定と配布時の帰属整備はT25へ残します。

## 未実装と未検証

**コードの不足:** 送信元/ENI/SG・IAM主体の客観照合を自動取得するproducer、AWS CLI chainの実credential expiry、DNS/経路障害の注入・観測producer、Proxy pinning/CloudWatch、runner identityの自動取得が残ります。対応caseを架空値で埋めずUnknownにします。評価器は十分な構造化合成証拠を使って照合規則を試験していますが、実collectorがその証拠を揃えたという意味ではありません。

**コードはあるが実AWS未検証:** inventoryの実API/最小権限、IAM署名による実接続・拒否、実ProxyのTLS/SQL/プール、901秒後のIAM session、新規CFNの作成/SQL bootstrap、性能の業務受入、実Linux runner/既存DB導入です。

計画のpaths/sources集合がprotected/recovered間で変わる構成は、現版のvalidatorで非対応として拒否します。追加された未試験経路を評価から落としてPassにはしません。デコイ、継続運用、既存DBの導入先別profile等の将来caseも実証していません。

ハッシュは保存整合性・参照の照合用で、証拠や実験計画の真正性を署名で保証しません。SourceDeclaredを自動昇格せず、外部の事実と運用者の申告を区別します。次に進む際も、M1の達成を維持し、M2の残作業とT16以降のクラウド承認を分けます。
