# K09：要求別の事前判定と操作・保護の完了判定

2026-11-02。[設計照合](design-implementation-audit.md)で残したK09を実装し、PostgreSQLを優先してローカル検証しました。単一Rustクレート・単一CLIを維持しています。実AWS/GCP CLI、cloud API、実DB操作、追加フィジビリティ、公開は行っていません。検証は合成policy、SQLite、偽provider／transport／CLI、既存のローカル回帰です。

## 変更した振る舞い

| 入口 | K09後 |
| --- | --- |
| `guard plan`、`reconcile/recover/revoke`の計画生成 | 現在のadapter契約・SQL compiler・bindingで、選択stepの要求をoffline照合。構造化した`intent-qualification.json`と説明を保存する |
| `guard approve` | 保存された肯定reportを信用せず再計算。静的非対応があれば承認台帳を作る前に`INTENT_NOT_QUALIFIED`で拒否する |
| `guard begin` | 古いapprovalからの操作登録も現在コードで再判定し、非対応ならdesiredやoperationを変更しない |
| `guard apply-gcp/apply-aws` | opt-in・台帳scope確認後、native config／checkpoint／所有artifact／実行fileを読む前に判定。不適格な新規dispatchを止める |
| composed executor | 最初のstepから全選択要求の事前判定を適用。CLIを通さない組立てでもavailable／preflight／submitで新規書込みを止める |
| 受付済み・結果不明のquery | 現在のidentity・generation等の照合を維持してread-only queryを続ける。別stepの非対応を理由に受付済み結果を消さず、後続writeは解禁しない |
| 記録済みCompletedの表示 | native config／toolなしで過去のoperation結果を返す。現在の保護を再確認したとは表示しない |

coreへprovider、SQL driver、SQLiteの依存は追加していません。`adapters/qualification.rs`が既存compilerとregistryを合成し、CLIでの表示・gateは`qualification_cli.rs`へ置きました。coreのhash／approval形式を変更せず、既存計画には現在コードでの再判定をかけます。新しい依存は追加していません。

## 事前判定の内容と限界

PGの署名を指定できないroutine要求、識別子やSQL scopeの制約、共有login、MySQLのrole付与・table以外のscope、engine／版／region・adapter contract不一致などを現在の実装に照合します。非対応はtarget／grant／step／actionとSQL object等のscope、固定理由コードとして返します。raw SQLやdriverエラーを理由へ貼り付けません。

reportは`schema_version: 1`、policy revision hash、change hash、`readiness_only: true`、`runtime_verified: false`、整列したfindingsを持ちます。静的な`unsupported`と、実行時に別途確認する`runtime_prerequisite`を区別します。

- `.is_qualified()`は既知の静的非対応がないことです。planのstdoutへ`static_qualified=<bool> intent_gaps=<件数>`を追加しました。終了コード3は従来どおり「計画生成で保護成立を示さない」という意味です。
- `.is_dispatch_qualified()`は上記に加え、policyへ固定するidentity／target generation参照の不足を拒否します。入力参照のないpreviewを保存・承認できても、そのままnative dispatchはできません。固定値はreviewしたpolicyと新しい計画へ入れる必要があります。
- 実DBの現在状態、権限、排他window、SQL所有receipt、未来のアプリ切替・復旧宣言を確認済みにしません。特にSQL revokeの所有receiptはruntime prerequisiteで、現在の限定factoryの検証を維持します。
- reconcile/recoverの静的SQL判定は選択されたstepが対象です。関係しないdesired SQLを理由に、選択したread-only照合を不要に拒否しません。native observer／factoryが全主体を扱う場合のidentity数・復旧参照等の制約は別に照合します。

plan.jsonの従来capability gapと、要求の細部に対するintent gapは別です。対象にaction実装があっても、その入力SQLを実行できるとは限りません。承認・native実行で再計算するため、保存reportの改変や旧planの粗いcapabilityから許可を作りません。

## 受付済み操作と不明結果

旧計画に後段の非対応要求があっても、台帳に`Dispatching / Submitted / ConfigApplied / OutcomeUnknown`があれば、受付済み結果の照会経路を残します。これは新規writeの許可ではありません。composed executorのavailable／preflight／submitは引き続き不適格な計画を拒否し、query完了後も後続stepを開始しません。

forwardを禁止した計画では、将来SQL stepの所有artifact読込みをcloud queryの開始条件にしません。受付済みSQL自体の安全な照合条件・所有contextが不足すれば、そのSQLはUnknownに残ります。不明を成功へ変換したり、再送したりしません。queryの実行には依然として正しいnative config、読取資格情報、対象・identity確認が必要です。

## GCPの送信元帰属

production用`classify_cli_connection_evidence`を導入し、接続確認と失効確認で共用しました。CLI実行元のTCP refusal、principal名を宣言しただけのdirect sampleから、各workload sourceの拒否証拠を生成しません。現在のproduction collectorの`direct_denied_principals`は空のままです。

connector陽性は、完了したfreshな試行、認証済みSQL、正確なDB user／databaseという条件を維持します。現在のAllowedを削除せず、TCP診断・raw capture・artifact参照も保存します。source coverageが不足してPendingでも、妥当なgeneration・鮮度・hashを満たす観測参照はreceiptへ残します。

これにより、GCPもAWSと同様、設定反映だけでは直通閉鎖stepを完了せずWaitingEffectに残り、期限後にFailedPartialとなり得ます。timeoutを拒否へ格上げしません。各workload sourceに結び付くproducerはK10に残っています。trustedなfake providerが与える全scope証拠は合成workflowの検証用で、productionの不足へ転用しません。

## 完了表示

GCP／AWS native出力を共通の意味へ揃えました。

| field | 意味 |
| --- | --- |
| `operation_scope_completed` | 台帳の当該operationがCompletedか |
| `protection_evaluated` | K09のnative出力ではfalse。全policy/source/effectの評価を代用しない |
| `current_protection_rechecked` | false。Completedの再表示や通常statusを新しいライブ検査へ扱わない |
| `intent_qualification` | 現在コードで再計算した静的要求・入力参照の判定 |
| `forward_dispatch_blocked` | 静的非対応または固定参照不足により新規dispatchを止めているか |

記録済みCompletedを返す場合は`native_dispatch_available: false`、`native_queries_performed: false`も出します。通常のnative query中でも、forward禁止なら`native_dispatch_available: false`です。

`guard plan`の生成説明も、GCP/PG・AWS/PG・AWS/MySQLの限定実装、現在desiredを維持するrecover、旧Allow復元・一般の補償が未実装という区別へ更新しました。

## ローカル検証

固定Rust 1.98.1／macOS ARM64で`mise run check`を完了しました。format check、Clippy warnings denied、**357件成功・0件失敗・実DB用2件ignored**です。

新しい回帰は、PG routine／MySQL role等のscope付きgap、現行contract照合、固定参照不足、偽の肯定reportと旧approvalの拒否、最初のnative stepのprovider読取・write前停止、受付済み／不明結果のquery継続、Completed表示、GCP source未確認のPendingと証拠参照の保持を確認します。既存PG・MySQL・SQLite・core依存境界の回帰も含みます。

`runs/core-k09-local-20261102-1/check.log`と`summary.json`へ全体結果を保存しました。別processのoffline CLI記録は同directoryの`cli-smoke/`です。GCP/PG・AWS/PG・AWS/MySQLの非対応previewと承認拒否、通常PGの計画・承認・登録・offline再開を計13コマンドで確認し、外部tool呼出し0、native dispatch0、拒否した承認台帳の作成0を確認しました。

これは追加フィジビリティや実環境での防御成立の証拠ではありません。次の未完了はK10のnative証拠producer／bundle／共通effectiveへの接続です。K11の導入契約、K12の選択した補償・緊急effectは未着手です。
