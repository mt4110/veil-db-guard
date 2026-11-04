# K01〜K08の設計・実装照合と残る基幹作業

2026-11-03現在：[K11-Aの詳細設計と部分実装](k11-a-runtime-binding-design.md)を追加しました。以下のK11未着手表記は以前の照合時点です。process/socket資料は受入・再読込可能ですが、実session・認証・TLS・poolとの結合、全RuntimeBindingは未完了です。

2026-11-03最終引継ぎ: [K10共通基盤のL受入とK11着手条件](k10-k11-handoff.md)を参照します。root probe/過去ログ/限定IAMの保証scopeを固定し、個別profileのUnknown・未対応は維持しました。次の実装はK11-Aです。以下は前チェックポイントの記録です。

2026-11-03継続更新: [管理TLS境界と拒否層の設計・実装](k10-trust-and-denial-design.md)へ進みました。旧厳密TLS契約と未対応範囲は維持します。以下は以前の設計・検証の記録です。

2026-11-03追記: [残producerの実装と観測限界](k10-producer-gaps.md)でGCP connect拒否・限定完全IAM/Pending・MySQL named ACL不在を共通stateへ接続しました。AWS backend CA/hostname証拠など元の要求の残差は維持し、K10全完了とは扱いません。以下は前チェックポイントの記録です。

K10追記: A〜D、初回E/Fに続き、[EC2 source・PG/MySQL取得/GCP・AWS実行接続](k10-native-source-execution.md)を実装しました。新契約のGCP実行は現在source証拠を段階別に再確認します。E2/F2のMySQL取得・AWS実行接続も実装し、native拒否recipe・backend TLS・完全なinventory等は残ります。以下はK01〜K08監査時点の事実を保持する履歴です。現在の残タスクは[タスク一覧](../tasks.md)を参照します。

更新: この文書はK09実装前の照合記録を保持しています。以下の課題1（source範囲と完了表示）・2（要求別事前判定）と生成reportの説明は、継続指定を受けて[K09](k09-qualification.md)で実装・ローカル検証しました。現在の未完了はK10以降です。workload source producerそのものをK09で完成させた意味ではありません。

照合日: 2026-11-02。対象は現在のローカル作業ツリーです。未コミットの実装・既存証拠を保持し、今回はコード変更、追加試験、クラウド操作、公開を行っていません。以下の後続作業は提案であり、実装着手や外部操作の承認を意味しません。

## 結論

**K01〜K08は、各作業で限定した初期範囲のコードとローカル検証が一巡しています。プロジェクト内の基幹設計をすべて踏破した状態ではありません。**

共通policy、計画・承認、SQLite操作台帳、中断再開、限定したGCP/PG・AWS/PG・AWS/MySQLの適用・失効はあります。残る中心は、要求の細かさに応じた実行可否の事前判定、実際の対象・主体・送信元に結び付く現在の実効状態、既存アプリの導入・復旧契約です。DBの種類を増やすことより、この接続を先に完成させます。PostgreSQLを優先して完成させ、MySQLには同じ基幹を使います。

目的は、既存DBを移し替えず、正規アプリを認証された経路で動かし、不要な直通・不許可主体を制限し、その状態を維持・変更・復旧できるようにすることです。観測やレポートだけを最終成果へ置き換えません。

## 照合対象と証拠

- [要求 R01〜R18](../requirements.md)、[基本設計](../basic-design.md)、[詳細設計](../detailed-design.md)、[検証設計](../verification.md)。旧AWS観測系列と現在の基幹系列は区別しました。
- [基幹全体](README.md)、[control plane](control-plane.md)、[data plane](data-plane.md)、[security lifecycle](security-lifecycle.md)、[K01〜K08の作業定義](implementation-plan.md)。
- `src/core/*`、`src/operation_store.rs`、`src/binding.rs`、`src/guard_cli.rs`、native CLI組立て、adapter registry、AWS/GCP provider・state bridge、PG/MySQL engineとtransport、対応するtests。
- 直近の既存記録 `runs/core-k08-local-20261102-1/summary.json` はRust 1.98.1／macOS ARM64、335件成功・0件失敗・実DB用2件ignored。今回は再実行していません。試験件数は設計全条件の達成証明ではありません。

ここでいう「実装済み」はコードと既存のローカル記録に基づきます。「実環境で未確認」はコード欠落とは別です。外部CASがない等の運用上の制限は、単なる実装追加で解消したと扱いません。

## K01〜K08の現在地

| ID | 現在ある実装 | 設計との残差・完了の範囲 |
| --- | --- | --- |
| K01 | `core/policy.rs`、`capability.rs`。対象・主体・経路・DB権限・管理範囲、版付きprofile、hash、入力検証 | 初期型は実装済み。主要DB全組合せ、native expiry、session等を対応済みにしていない。設計のcapability情報は初期subsetへ縮約されている |
| K02 | `adapters/registry.rs`、`import.rs`、`control_observation.rs`、既存AWS/GCP観測bridge | 配置先×engineの登録と観測の整合検証はある。現在のnative観測・SQL・bindingを共通実効評価へ一貫して流すproducer/bridgeは未完成 |
| K03 | `core/plan.rs`、`change.rs`、`approval.rs`。DAG、影響・差分、対象世代、scope付き承認、repair/compensationの記述 | 基盤は実装済み。ただしadapterの対応判定が対象・action単位で、SQL intentの細部が後段compilerで初めて拒否される。計画時の要求別qualificationが残る |
| K04 | `core/ports.rs`、`orchestrator.rs`、`operation_store.rs`。transaction台帳、CAS、lease、dispatch前記録、取消し、不明結果の照合 | 初期ローカルkernelは実装済み。1 stepずつの実行は意図した制限。遠隔承認認証・分散controllerは初版の必須条件ではない |
| K05 | GCP Cloud SQL PostgreSQL 16.15／東京。IAM、login、限定SQL、binding、manual handoff、connector必須化 | 限定executorは実装済み。source別拒否の帰属に改善点があり、実アプリruntime／pool境界の具体化と実導入は未完了 |
| K06 | `core/state.rs`、`lifecycle.rs`。現在Allowedの保持、有限Pending、Deny、所有IAM/SQL回収、現在desiredを維持するrecover | 純粋評価器と限定lifecycleはある。native→共通effectiveの連携、所有差分の補償、session/drain、期限回収は別の残作業。recoverは旧Allowへ戻すrollbackではない |
| K07 | AWS RDS PostgreSQL 16.15／東京／既存専用Proxy。IAM、SG、PG transport、同じ台帳・失効へ接続 | 限定実装済み。実observerのworkload source別直通拒否が未接続でWaitingEffectに残る。実AWS未確認 |
| K08 | AWS RDS MySQL 8.0.43／東京／既存専用Proxy。user@host、IAM/TLS、table CRUD権限、暗黙commit・所有差分 | 限定実装済み。準備済み専用accountが前提。role付与・共有account移行・一般的な1045からのIAM原因特定は未対応。実AWS/MySQL未確認 |

coreをadapter／CLI／SQLiteから分離する方向は守られています。`tests/architecture.rs`はcoreを単独module graphとしてコンパイルします。一方、`engine/mysql/aws.rs`はPG側に置かれたAWS認証型・`PgError`へ依存しています。共通AWS認証・resource bindingをengine中立の外側moduleへ移す整理は残ります。単一crateのままで可能で、service分割や大規模な作り直しは不要です。

## 優先して埋める差

### 1. 根拠の送信元範囲と完了表示を統一する

設計上はsource／route／target generation／identity／effectが一致する必要があります。AWS observerはこれを満たさないCLI実行元のTCP結果から`direct_denied_principals`を作らず、空にしています（`adapters/aws_observation.rs`の`AwsObserver`実装）。

対してGCP providerには、単一の`ExplicitRefusal`を`needed`の主体全体へ展開する処理が、`observe_connections`と`observe_revocation`にあります（`adapters/deployment/gcp.rs`）。これは当該CLI実行元の到達性であり、各workload sourceの認証ではありません。connector必須設定の確認、IAM主体の確認、ネットワーク送信元の確認は別です。

さらにGCP native stdoutは初回operationのCompletedを条件に`protection_evaluated`を立てます（`native_cli.rs`）。共通state bridge側はsource等が足りないためUnknownを維持します。**native操作完了と、共通policy全条件の保護完了を同一視しない判定へ揃える必要があります。** これはコード読取で確認した不整合で、今回新たに実環境の不具合を実証したという意味ではありません。

### 2. 実行できないintentを計画時に返す

`adapters/registry.rs`は対象engine／版／regionとActionKindで実装有無を返します。一方、MySQL compilerはrole付与、table以外のscope等を拒否し、PG compilerもroutine署名を持たないroutine intentを拒否します。これらの細部をregistry／plannerがすべて事前照合しているわけではありません。

そのため「actionの実装がある」ことから、入力intent全体を実行可能とは判定できません。SQL stepで安全に停止しても、その前のProxy/IAM準備が進んでいる可能性があります。静的に分かるunsupportedはplanでgrant/object/action付きgapにし、native変更の前に止める必要があります。

これは広い権限へ変換して実行する欠陥ではありません。現compilerの拒否は維持し、拒否を前段へ伝える改善です。未来のhandoff宣言や、まだ準備していない経路の成功を全step開始前に要求する設計にはしません。静的qualificationと各段階のruntime preconditionを分けます。

### 3. native観測を共通effectiveへ接続する

`core/state.rs`には対象・主体・source・route・layer・effect、証拠の鮮度と拒否原因を評価する実装があります。しかし`adapters/state.rs`と`aws_state.rs`は既存captureの保証不足から`identity_confirmed: false`を保持し、SQL/session等の観測も揃っていません。`guard status`のeffectiveはUnknownから作り、保存済みnative観測は別欄へ添付する実装です。

また、計画用importは旧`gcp-check`とAWS旧`inspect/probe`が中心です。新しい`aws-guard-inspect/check`、SQL ownership／postcondition、binding checkpointを、同一revisionとscopeに結んだ現在状態として使う流れが揃っていません。MySQLの追加によりこの差が消えたわけではありません。

必要なのはfixtureや操作者宣言を真の観測へ昇格する変更ではなく、実行文脈を検証するproducerとscope付き証拠bundleです。単に`identity_confirmed`をtrueに変更したり、ローカルhashへ署名しただけでsource確認済みにしたりしません。現在のAllowed、曖昧な1045、timeout、不完全・古い証拠は引き続き保持します。

### 4. 既存アプリが導入・復旧できる契約を完成させる

bindingと切替・復旧の手動checkpointはあります。一方、設計で求めるアプリ配置、connectorのprocess/container/socket境界、driver・poolのtoken更新／drain／再接続、正確な復旧手順までを、一つの導入成果物へまとめてはいません。特にGCP bindingは接続先・identity参照が中心で、runtime境界の具体的設定は別途必要です。

既存の共有loginから専用identityへ分ける移行、未登録の管理・batch・migration経路の棚卸しも初期executorの前提外です。AWSは既存専用Proxy、MySQLは既存IAM accountが前提です。「利用者が準備すべき前提」と「Veilが適用する差分」を導入計画に明確に出す必要があります。自動deploymentや任意shell hookを新たな必須条件にはしません。

### 5. repairと補償・緊急停止の範囲を区切る

現在のrecoverは現在desiredを保つ限定修復です。設計には所有差分の補償、bindingや切替の復旧、session/drain、緊急遮断、期限付き許可の回収もありますが、そのexecutorはすべて揃っていません。

旧Allowへの自動復元、直通の自動開放、全snapshot上書きを追加する意味ではありません。必要な補償を別の承認scopeへ束縛する実装が残ります。session選別終了とJIT自動回収は、要求しない初期Standing profileの必須条件ではありません。必要なeffectを要求された場合は、実装されるまでgapとして拒否します。

## 次の実装順序の提案

同時に複数項目を最優先にはしません。照合時には**K09だけ**を最優先として提案しました。その後K09を実装・L検証しました。現在の次の候補はK10です。以下は照合時に整理した作業範囲です。

| 候補 | 優先・順序 | 実装するもの | 完了条件 |
| --- | --- | --- | --- |
| K09 | 実装・L検証済み | 要求別qualificationと、根拠の範囲を越えないnative完了判定。GCPのsource帰属・stdout、PG/MySQLの静的SQL制約、CLI生成説明の整合 | source未確認を全workload拒否へ広げない。静的unsupportedを最初のnative書込み前に返す。Operation完了と保護完了を別表示。ローカル回帰で確認 |
| K10 | K09後 | 同一target generation／identity／source／route／effectを結ぶnative evidence producer・bundle・importと共通effectiveへの接続。まずPG、次にMySQL | 真に確認した対象・scopeだけを成立扱いでき、Allowed／Pending／Unknownと鮮度を維持する。SQL・bindingのpostconditionも統合。模擬証拠の昇格を拒否 |
| K11 | K10後 | PostgreSQLの既存アプリ導入bundle。現状inventory、管理・batch経路、runtime/socket境界、token/pool、manual切替と復旧手順。AWS共通認証のmodule整理 | 運用者が何を事前準備し、どの差分を適用し、どの段階で戻すかをレビューできる。勝手なdeployment実行・共有account削除はしない |
| K12 | 必要範囲を選択後 | 所有差分の限定補償、source確定済みの緊急操作、必要ならsession/drain・期限回収 | 選んだeffectと承認範囲だけを実装。未実装effectを「復旧済み」「期限失効済み」に含めない |

K09/K10もクラウド資源の作成や追加フィジビリティを開始条件にしません。コードとローカル検証を先に進められます。実対象での受け入れをしない限り、コード完了を実環境の保証へ変更しません。

## 今すぐ広げない項目と運用上の制約

- DB／region／minorの追加、MySQL role・database全体権限、MariaDB／SQL Server／Oracle、自己管理配置。構想は保持し、まず現在のPostgreSQLを一つの導入から現在状態・復旧までつなぐ。
- daemon、自動deployment、IaC連携、遠隔・複数操作者の承認認証。初版local-first／manual handoffを満たすだけなら必須ではない。
- デコイ・通知・継続監視は旧T23/T24の別枝。現在の保護導入を終える前の追加必須条件にしない。
- AWSの非CAS API、PG同一grantor、MySQL grantorを追えない権限変更は、外部操作者との競合を完全には解消できない。専用資源・所有証拠・外部排他windowという運用条件を表示し続ける。
- 実AWS／新executorの実対象導入、Linux実行、負荷、利用者価値、公開用license／transitive帰属・advisory監査は別の未確認・未完了。今回の依頼では実行しない。旧AWS実験系列を自動再開しない。

## 文書・表示で見つかった追従漏れ

全体設計にK01/K02を「次の着手」とする記述、AWS/PGを「次段」とする表、MySQLの配置先を未決とする記述が残っていました。今回の照合に合わせて現在地へ修正します。旧T系列の実験・未達条件は書き換えません。

`guard plan`の生成report文字列には「GCP/PGのみ」「復旧executor未実装」と読める古い説明が残っています（`src/guard_cli.rs`）。限定recoverと補償未実装の違いを反映するコード修正はK09へ残しました。今回の文書整理を、表示コードの修正済みという記録にはしません。
