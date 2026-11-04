# K06：状態評価・維持・失効・復旧

K09更新: GCPのCLI実行元の拒否を全workloadへ拡大しない判定と、操作完了・保護未評価の表示へ修正しました。[現在の境界](k09-qualification.md)を参照します。以下のK06時点の実装・検証記録は保持します。

2026-11-02。K05に続き、単一Rustクレート・単一CLIで、現在状態の評価、限定reconcile/recover、Denyへのpolicy更新、GCP IAM許可の回収、PostgreSQL NOLOGIN・所有SQL差分の回収を実装しました。今回の検証はローカルfake・ファイル・SQLite・CLIのみです。追加フィジビリティ、cloud/API、実DBの操作は行っていません。

## 初期対応と残る境界

| 項目 | 実装と完了の意味 |
| --- | --- |
| desired/observed/effective | policyから要求効果を導出し、target世代・登録・revision・grant・主体・DB login・source・route・layer・effectが一致する観測だけを評価 |
| 現在のAllowed | PendingやPartialでも消さない。反映待ちの説明には前後permission inventoryと事前の成功を必要とする。情報不足はUnknown |
| 有限の待機 | 伝播期限後はNeedsAction/FailedPartial。operation全体もmax_operation_secondsに達した未完了処理をFailedPartialにする。受付済み結果の照会は継続可能 |
| Reconcile | 現在のdesired policyの限定stepを新しい計画と承認で修復。独立した旧許可を暗黙に再利用しない |
| Revoke | 選択grantを新revisionでDenyにする。Veil所有の完全一致IAM bindingだけをetag付きで除去し、DB loginをNOLOGINへ変更し、最後に実効を別観測 |
| SQL権限回収 | 前回applyの成功stepと、管理grantorのbefore/after・追加差分artifactがある場合だけ、その追加差分をREVOKE RESTRICTで回収 |
| Recover | 中断・取消し・部分失敗した操作から、**現在のdesiredを保つ修復計画**を作る。取り消したAllowや昔のsnapshotへ戻す機能ではない |
| Session/JIT | 選別session終了、常駐監視、自動期限回収は未対応のcapability gap。新規ログイン停止をsession終了と表示しない |

対象native組合せはK05と同じCloud SQL PostgreSQL 16.15 / asia-northeast1 / 専用SAのStanding Grantです。主要RDBMS全体を対応済みとする変更ではありません。AWSは後続[K07](k07-aws.md)で限定実装しました。MySQL、実導入、公開は後続範囲です。

## 状態の評価

`core/state`はprovider/SQLite/CLIから独立した純粋な評価器です。新規接続、既存session、個別role/object/action、binding、lease expiryを別々の行として扱います。fixture・操作者の宣言、世代未確認、違うbuild、古い証拠、別source/routeの失敗から保護成立を返しません。部分的なcaptureでも、鮮度内の同一対象の接続成功を表示に残します。login拒否には、資格情報・DB登録と独立した同時刻の正例を必要とします。

権限削除に対応するPendingは、同じscopeの完全な前後inventory、実際に消えたpermission、変更前の成功を結び付けた場合だけです。単なる削除宣言やAPI受付で「伝播待ち」と断定しません。期限は有限とし、現在Allowed・部分失敗・残るsessionを保持します。

CLIは次のように使い分けます。

```text
veil-db-guard guard status --ledger <ledger> --operation <id>
veil-db-guard guard state --ledger <ledger> --operation <id>
veil-db-guard guard state --ledger <ledger> --operation <id> --evidence <verified-gcp-check-run>
veil-db-guard guard status --ledger <ledger> --operation <id> --native-state-run <guard-state-run>
```

すべてローカル読取です。`status`はdesired、operation/steps/events、effectiveと必要なら保存済みnative観測を返します。観測を指定しないeffectiveはUnknownで、台帳の過去のCompletedを現在の保護へ昇格しません。`state --evidence`はmanifestと元captureを再検証し、保存済み判定を信用しません。

既存の`gcp-check` captureは世代・workload source・immutable identityの証明が足りないため、この共通policy評価ではUnknownを保ちます。ただし現在のAllowedは見えます。過去のGCP固有check判定と、共通policyの全条件成立を区別するためです。

Native実行の`ObserveRevocation`は最新の`RevocationEvidence`をキャッシュし、stdoutの`revocation_observation`とprivate `work_dir/guard-state-*/effective-state.json`へ保存します。再保存のための追加probeはしません。PartialでもAllowedを保持し、manifest、operation ID、change/policy hashで記録を結びます。`--native-state-run`はその対応とartifact hashを検証します。`native_observation_fresh`は60秒以内の観測かを示し、通常status自身が再接続試験をしたとは表示しません。manifest/hashは真正性の署名ではありません。

## 計画・承認・実行の流れ

以下の計画コマンド自体は外部操作をしません。sourceには台帳の実在するoperationが必要です。

```text
veil-db-guard guard reconcile --ledger <ledger> --source-operation <source-id> --grant <grant-id> --out <new-plan-dir>
veil-db-guard guard recover   --ledger <ledger> --source-operation <failed-id> --grant <grant-id> --out <new-plan-dir>
veil-db-guard guard revoke    --ledger <ledger> --source-operation <source-id> --grant <grant-id> --out <new-plan-dir> [--revoke-sql]
```

出力は従来の`guard-plan` runです。`plan.json`、`prepared-change.json`、policy、hash/manifest、説明を新規保存し、終了コード3を返します。必要なら同じtargetの`--evidence <gcp-check-run>`を渡せます。`recover`のsourceはCancelled/NeedsAction/FailedPartialに限定します。sourceのpolicyが現在のdesired headでない計画は拒否します。

次に既存の`guard approve`で**新しい限定承認**を記録し、`guard begin`に現在の`--expected-desired-head`を指定して新operationを登録します。`begin`のdesired head CASとsource・上限の確認は同じSQLite transactionで行います。旧approvalに別のchange hashを読み替えて実行することはできません。

Native実行は既存の`guard apply-gcp --allow-native-changes`です。tool/probe configと、今回のchangeへ束縛したfresh `exclusive-native-change-window` checkpointを渡します。reconcile/recoverでconnector閉鎖を扱う場合は、K05と同様、全アプリ切替・独立復旧と新しい接続成功の確認も必要です。通常`guard resume`は引き続きofflineです。

新しいDenyだけになったtargetにもwindow宣言を作れるようにしました。新規アプリ配布の宣言を失効処理の前提にせず、独立した復旧例外・対象世代・change hashへの束縛は維持します。

修復はsourceの操作上限を増やせません。`max_repair_executions`を台帳で原子的に消費し、repairを次のrepairのsourceにして予算をリセットすることを拒否します。元操作をsourceに指定します。Revokeは新desired revisionの明示承認であり、そのDenyを修復することはできます。自動daemonや旧repair recipeだけによる無承認の起動は追加していません。

## 失効の順序と部分失敗

1. 新policy revisionで選択grantをDenyにし、同じ対象・主体・DB loginと独立復旧経路を保持する。Denyの`sql_access`は空で、新しいSQL許可を混ぜない。
2. `DisableNativeIdentity`でVeil所有の条件付きIAM bindingだけを回収する。広い既存grant・他のbinding・監査設定を削除せず、所有タイトルの衝突は停止する。
3. `DisableNewConnections`で管理scope内の専用DB roleをNOLOGINにする。別Allowが同じnative instanceとroleを共有する場合は、database/regionのラベルを変えても拒否する。
4. 明示`--revoke-sql`があれば、証拠付きの限定SQL差分を回収する。
5. `ObserveRevocation`で現在の接続状態を確認する。設定完了stepのEnforcedは当該設定postconditionだけを表す。

最後の観測には対象SAの新規connector接続のIAM connect/login層での拒否、独立した復旧主体の成功、直通拒否、同一世代、鮮度・完全性が必要です。まだAllowedなら、その事実とConfigApplied/Pendingを保持します。timeout・SQL object ACL不足・token発行失敗をIAM拒否にしません。NOLOGIN設定が見えるだけの場合や、未分類のNOLOGIN診断しかない場合も、IAM拒否を観測したことにはしません。追加の権限が別経路で残る場合、今回の所有binding回収だけで全許可が消えたとは報告しません。

操作期限に達したらFailedPartialとして残し、失効前のAllowへ自動復帰しません。取消し後も受理済み操作のread-only queryができ、許可を復元する書込みは行いません。現在のdesiredがDenyなら、古いAllowのrecoverをbegin/dispatchのCASで拒否します。

K09以降、Cloud SQLの直通timeoutだけでなく、CLI実行元のConnectionRefusedやdeclared principal付きの拒否でも、各workload sourceの帰属が未確認ならWaitingEffect/期限後FailedPartialになり得ます。実行元の結果を全sourceの拒否へ格上げしません。

## SQL回収の所有証拠

K06以降のnative SQL applyは、管理grantorが今回追加したdirect role/object/actionのbefore/after差分を`postgres-ownership-run-*/postgres-ownership.json`へ保存し、成功step receiptにartifact hashを記録します。native SQL revoke時は`--ownership-run <source-ownership-run>`でこのrunを渡します。

source SQL step ID、成功状態、apply batch hash、policy/target/login、管理grantor、artifact hash、追加差分を照合します。古いK05のbatch hashだけのreceipt、結果不明のapply、所有証拠の欠落、他Grantとの共有・範囲拡大は自動回収しません。適用済みGRANTの証拠保存だけが失敗した場合も、その許可を勝手に戻したり所有済みと捏造したりしません。

元からあった権限・別grantor・PUBLIC・継承権限は残します。table REVOKEに巻き込まれるcolumn ACLがある場合も拒否します。これは**Veilが追加した直接権限の回収**であり、別経路の権限を含む全SQL実行能力の消失保証ではありません。共通stateは要求された個々の実効を別に評価し、観測のないSQL効果はUnknownです。

外部actorが同じ管理grantorで並行変更すると、PostgreSQL ACLだけで変更主体を区別できません。外部変更windowを要求し、現在のscope/authorityを再確認しますが、この同一grantorの並行変更に完全な所有識別保証はありません。Native SQL構文・catalog挙動も今回実DBでは未検証です。

## 復旧の提供範囲

`recover`は現在のdesired protectionを再成立させる限定実行です。旧Allowの復元、NOLOGIN→LOGIN、connector制限の解除、IAM/SQL snapshot全体の上書き、失効の取消しは自動化していません。これらの保護水準を下げる変更は、現在状態と別の変更計画・承認が必要です。RecoveryPlanでも失効actionを`NoAutomaticAllowRestoration`へ分類します。

sessionの選別終了、JIT期限のnative強制/常駐回収、管理例外の資格情報回収、任意の過去状態への補償は初期実装の外です。capabilityの不足を表示し、今回のK06ローカル実装をこれらの完了へ数えません。

## ローカル検証

core state、既存captureの検証bridge、実SQLite台帳でのsource/新approval/CAS/修復予算、旧Allow復旧の拒否、有限待機、Deny用window、所有SQL artifact、GCPの正確なbinding回収、native組立ての再開をfake/ローカルartifactで確認します。native組立て試験はAllow導入からDeny更新、Allowed+Pending、取消し後の拒否照会まで通し、IAM/SQLの再送・Allow復元がないことを検証します。実クラウドの拒否・伝播・復旧成功とは区別します。

最終検証はRust 1.98.1で`mise run check`（format、Clippy warnings denied、回帰）を実行し、**272件成功、失敗0、実DB試験2件ignored**でした。`runs/core-k06-local-20261102-1/check-final.log`と`check-summary.json`に保持しています。

同directoryの別プロセスCLI記録は、source plan/approve/begin、offline resume、reconcile/recover/revokeの計画、新Denyのapprove/begin、古いAllow recoverの拒否、state/status、取消しまでを保存しています。native attempt 0、外部tool trapの起動0、最終操作Cancelled、desired Denyを確認しました。これはnative組立てfake試験とは別のoffline既定動作の証拠です。

SQL撤回後のDenyを修復する場合も、直近のRevoke操作と、元のAllow SQL ownership操作を台帳で別々に照合します。native factoryは正しい祖先・元成功step・artifactを解決し、直近の新承認への束縛を維持します。実台帳・所有artifactを通したfactory regressionと、Pg executorの両方で確認しました。必要な所有証拠がないSQL回収は、native呼出し前の組立てで拒否します。
