# GCP PostgreSQLへの導入実装（K05）

2026-11-02。単一Rustクレート・単一CLIを保ち、依存整理とK05のコード、ローカル検証を実装しました。実行backendを含みますが、今回クラウドAPI・既存DB・実Auth Proxyは操作していません。以前の専用環境の実測を、このexecutorの実導入成功とは扱いません。

目的は既存DBの保護導入です。フィジビリティや環境構築の追加ではありません。後続の[K06](k06-lifecycle.md)で維持・失効・現在desiredの限定復旧を実装しました。session/JIT自動回収、旧Allow復元、AWS/MySQL、production導入・公開は未完了です。

## モジュールの境界

| 内側から外側 | 実装 |
| --- | --- |
| Domain / Application | `core/policy`, `capability`, `observation`, `plan`, `change`, `approval`, `operation`, `orchestrator`, `ports` |
| 台帳インターフェース | 内側の`OperationLedger`を外側のSQLite `OperationStore`が実装。再開処理はSQLiteをimportしない |
| 観測の変換 | `adapters/control_observation`がGCP/AWSの生payloadの対象・完全性を検証し、provider中立の`ChangeObservation`へ投影 |
| Native実装 | `adapters/deployment/gcp`、`adapters/engine/postgres`、`binding` |
| 組立て・表示 | `adapters/executor`、`guard_cli`、`native_cli`。旧`core/cli`は外側へ移動 |

`tests/architecture.rs`は実際のcoreを、SQLite・provider・CLIモジュールの存在しない独立したモジュールグラフとしてコンパイルします。ディレクトリ名だけの分割ではなく、外側への依存が入ればコンパイルが失敗します。crate分割、service化、plugin ABIは追加していません。

## 実行する順序

初期対象はCloud SQL PostgreSQL **16.15 / asia-northeast1**、専用SAのStanding Allow、一つの登録済みtargetです。対応コードと、その環境への導入済み保証を区別します。

| 順序・action | 実装する処理と完了の意味 |
| --- | --- |
| PrepareNativeRoute | `cloudsql.iam_authentication=on`。他databaseFlagsを保持しsettingsVersionで条件付き更新。完了は当該設定のreadback |
| ConfigureIdentity | 対象instance名に条件を絞ったclient/instanceUserのVeil所有bindingだけを追加。既存bindingを保持しIAM etagで条件付き更新 |
| RegisterNativeDbIdentity | 対応する`CLOUD_IAM_SERVICE_ACCOUNT`ユーザーを登録。IAM設定と別dispatch・native operationとして追跡 |
| ConfigureSqlPrivileges | 対象DB・管理scope内の既存role membershipとdatabase/schema/table権限だけを一つのtransactionで付与し、catalogを照合 |
| PublishBinding | 秘密なし接続profileを生成し、操作者が既存deploymentへ配布した旨のhash付き宣言を確認 |
| ConfirmRecoveryReadiness | アプリと独立した復旧主体・経路の準備宣言を確認。宣言を接続成功の証拠にしない |
| AwaitApplicationCutover | targetに登録された全Allowアプリと各workloadの切替宣言を確認 |
| ConstrainDirectPath | 全handoffと全アプリ・復旧主体の直近connector接続成功を確認してからconnector必須化。設定後も直通拒否を観測するまで効果待ち |

SQLは`GRANT ALL`や任意SQLを受け取りません。識別子を引用し、63バイト超・別DB scope・未管理role/objectを拒否します。管理roleは既存の限定roleを参照する方式で、自動作成・既存権限の削除は行いません。既存membershipのADMIN/SET有効状態は自動採用しません。routineはoverload signatureをpolicyで表せるまでUnsupportedです。

管理接続は明示したCloud SQL Auth Proxyの一時loopback接続、自動IAM、明示的SA impersonationを使用します。通常アプリのcredential sourceはworkload identityです。任意DSNや運用者のOwner資格情報をアプリへ渡す方式ではありません。SQL前にもGCP世代と実行主体を再照合し、接続先DB/versionおよびsession_user/current_userを照合します。

## 受付・反映・効果・中断再開

- 台帳へDispatchingを保存してから一つのnative書込みを送ります。IAM更新、DBユーザー登録、connector設定を一つの不透明な処理にまとめません。
- 非同期APIの受付はSubmitted、設定readbackだけの直通制限はConfigApplied/Pendingです。setup stepのEnforcedはその設定postconditionだけの成立を表し、アプリの実接続成功を代用しません。
- ConfigAppliedでも直通SQLが通る場合、明示拒否が未観測の場合、証拠が古い場合はCompletedにしません。最終完了にはSQL権限・全handoff・正規/復旧connector成功・直通拒否のすべてが必要です。
- Queryはprovider operation/configurationとSQL readbackを読み、GRANTやnative書込みを再送しません。応答喪失でoperation IDも不明ならOutcomeUnknownとして残します。SQLの不在readbackも未commitの証明にしません。
- 承認やhandoff宣言が期限切れでも、既に受理された操作はread-only照会できます。新規dispatchには期限・取消し・limits・現在のdesired headを再確認します。
- driverのlease budgetは最大3600秒、標準offline driverは30秒です。照会直前にもrenewし、期限を超えたworkerのreceiptをfenceで拒否します。キャンセルは以後のdispatchを止め、受理済み処理をなかったことにしません。

## CLIの使い分け

通常の`guard plan/approve/begin/resume/status/cancel/revoke-approval`は引き続きローカル処理です。`guard resume`が勝手にGCPを操作する変更はありません。`guard apply-gcp`だけが明示opt-inでnative処理を組み立てます。

次の2コマンドはローカル台帳の読取・宣言だけです。出力ファイルを保存する場合は新規パスを使います。

```sh
veil-db-guard guard binding --ledger runs/operations.sqlite --operation operation-1 --grant billing-access
veil-db-guard guard attest --ledger runs/operations.sqlite --operation operation-1 --target billing-db \
  --kind application-cutover --operator-subject recovery-operator --valid-for 300
```

`attest --kind`は`binding-published`, `recovery-ready`, `application-cutover`, `exclusive-native-change-window`の4種です。実際の配布・切替・復旧準備・外部変更の排他調整を済ませた操作者が宣言します。policy/change hash、target generation、全アプリのprofile hash、復旧例外ID、宣言者・時刻・期限へ束縛します。hashは署名や独立した本人認証ではありません。通常handoffは最大24時間、外部変更windowは最大1時間です。

Native実行の起動形は次です。**この作業では実行していません。具体的なクラウド・既存DB変更は別の実行範囲です。**

```text
veil-db-guard guard apply-gcp --ledger <existing-ledger> --operation <operation-id>
  --expected-version <current-version>
  --execution-identity gcp-service-account:<email>:<immutable-unique-id>
  --native-config <secret-free-tools.json>
  --checkpoint <binding-published.json> --checkpoint <recovery-ready.json>
  --checkpoint <application-cutover.json> --checkpoint <exclusive-window.json>
  --allow-native-changes
```

`--allow-native-changes`がなければ、設定ファイルを読む前に拒否します。承認・beginで指定した実行identityと同じidentityを使います。秘密なしtools JSONのfieldは`schema_version:1`, `gcloud`, `curl`, `proxy`, `psql`, `work_dir`, `probe_config`です。executableは絶対パスを明示し、work_dirは自分が所有する既存の0700 directoryにします。tokenやpasswordは設定に入れません。SDKのendpoint/SSL/credential/proxy上書きを検査し、REST tokenはstdin経由で渡します。

Probe configは既存`gcp` schemaです。targetをpolicyと一致させ、全アプリ・復旧SAそれぞれのProxy AllowとDirect Deny caseを登録します。`total_timeout_ms`は**120000以下**、関係主体は**最大8**です。既存`examples/gcp.yaml`は180000であり、そのままnative用には使えません。Auth Proxyは既存probeと同じ2.26.3、psqlは17系が現行observerの条件です。Rust/SQLiteの固定は[ビルド環境](../build-environment.md)を参照します。

観測は`work_dir/native-evidence-*/`へmanifestとartifactを新規保存します。snapshot/capture/typed直通観測を保全し、receiptは保存したartifactのSHA-256を参照します。失敗runもPartialとして残します。台帳とこの証拠directoryを一緒に保全します。statusは台帳の最後の記録であり、毎回のライブ再検査や常駐監視ではありません。

## 未確認を成功へ変えない境界

直通TCPの明示拒否として採用するのは`ConnectionRefused`だけです。timeout、routing failure、reset、資格情報発行失敗、DBユーザー不一致を拒否成功へ変換しません。connector必須化に起因するtimeoutと、別のnetwork障害を今回のコードだけで確定帰属できません。この場合、設定の反映が確認できても**ConfigApplied / WaitingEffect**を返します。ConnectionRefused自体も、原因が必ずconnector設定であることや全networkの恒久拒否を証明しません。同じrunで直通SQL成功があればその主体の拒否を取り消します。

この保守的な判定のため、Cloud SQLが直通をtimeoutとして落とす配置では、今回の観測方式だけでterminal Completedにはなりません。拒否原因をさらに確定するevidence adapterは残る拡張点です。基準を弱める代わりに未確認を報告できるところまでが今回の実装範囲です。

設定generationは`H("gcp-cloud-sql-generation-v1", project, instance, createTime)`をJSON tupleのSHA-256で算出します。登録policyのgenerationとSAのimmutable IDが未指定ならnative変更を拒否します。既存の観測bridgeはこれらを確認済みへ自動昇格しません。GCP APIにcreateTimeのCAS条件はないため、外部変更windowと直前照合を併用します。IAM conditionはresource nameを制約するもので、将来の削除・同名再作成を永続的に防ぎません。

接続証拠の鮮度はcapture**開始**から60秒以内としています。長いcapture、権限反映待ち、取得不足では安全側へ停止します。今回、実環境での所要時間・権限伝播・CLI導入成功を確認していません。既存session停止、JIT期限回収、SQL権限縮小、reconcile/revoke/recover実行はK06以降です。

## ローカル検証と互換性

`k05_workflow`は実際のSQLite台帳、GCP/PG/bindingの組立て、typed graphを使い、provider/DBだけをfakeに差し替えています。複数回の台帳再open、Submitted→WaitingEffect→Completed、効果待ち中の書込み再送なし、承認/宣言期限後の照会、切替欠落で閉鎖しないこと、同名再作成でSQLへ進まないことを検証します。native CLIのopt-in、秘密なしbindingと宣言も別プロセスで確認します。fakeの成功をnativeの成功とは扱いません。

PreparedChangeは**schema 2**、GCP実行step契約は**core-adapter-v2**です。K04以前のprepared-change/approvalは新executorへ暗黙流用せず、現policyから新しいplanと承認を作ります。古いrun/台帳は保全します。台帳のoperation/status読み取りと、旧変更計画の実行互換性は別です。SQLiteのschema 1は変更していません。

今回の全体検証はRust 1.98.1で`mise run check`を実行し、format・Clippy（warnings denied）・**229件成功、失敗0、実DB試験2件ignored**でした。ログと集計は`runs/core-k05-local-20261102-1/check.log`、`check-summary.json`に保持しています。

同directoryには、新しい別プロセスCLIでのplan→approve→begin→binding→offline resume→cancel→statusも保全しています。最終状態Cancelled、native attempt 0、置いた外部tool trapの起動0でした。これはoffline既定動作の確認であり、fake providerを通した8step完了の統合試験とは区別します。クラウド課金・資源作成・撤収作業・push・公開は発生していません。
