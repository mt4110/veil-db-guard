# タスク一覧

## 現在の基幹作業

設計照合: **K01〜K08は各初期範囲の実装が一巡した状態で、基幹設計全体の完了ではありません。** K09で要求別事前判定とGCPのsource帰属・完了表示を修正しました。native観測から共通effectiveへの接続、既存アプリ導入・補償は残ります。[設計・実装照合と次の順序](core/design-implementation-audit.md)を正とします。

2026-11-02、K06/K07に続きK08のMySQLアダプターを実装し、PostgreSQLの回帰を含めローカルで検証しました。単一クレートのcoreからSQLite/provider/CLIへの依存を分離し、GCP/PG、AWS/PGおよびAWS/MySQLの限定native executor、binding/handoff、直通制限を接続しています。追加フィジビリティ・クラウド操作は行っていません。[K08の実装・判定境界](core/k08-mysql.md)、[K07のAWS PostgreSQL](core/k07-aws.md)と[K06の失効・修復](core/k06-lifecycle.md)を参照します。

| ID | 到達点 | 作業 | 依存 | 状態 |
| --- | --- | --- | --- | --- |
| K00 | C0 | 基幹の基本/詳細設計、導入・失効・復旧、マイルストーンとAI作業設計、分担レビュー | 既存GCP実測と現行実装 | 完了（設計） |
| K01 | C1 | 共通policy・target・subject・grant・capabilityの型と不変条件 | K00 | 完了（L） |
| K02 | C1 | 二軸adapter契約と既存AWS/GCP観測bridge | K01の契約固定 | 完了（L） |
| K03 | C2 | step DAG、差分、precondition、影響範囲、限定承認、repair/復旧recipe | K01,K02 | 初期基盤実装済（L）。要求別の静的qualificationはK09で実装・L検証済み |
| K04 | C2 | SQLite OperationStore、target lease、orchestrator、結果不明照合・中断再開 | K01,K03 | 完了（L、SQLite port・注入driver・別プロセスCLI） |
| K05 | C3 | GCP/PG限定executor、DB role、アプリbinding/handoff、切替後の直通制限 | K02,K03,K04 | 実装・L検証完了（native実導入未確認。timeoutのみではWaitingEffect） |
| K06 | C4 | 実効状態、反映待ち・鮮度、維持・失効・独立復旧 | K04,K05 | 初期対応を実装・L検証済（session終了・JIT自動回収・旧Allow復元は対象外） |
| K07 | C5 | AWS PostgreSQLのnative構成を共通基幹へ接続 | K06 | 実装・L検証済（既存専用Proxy。実AWS・workload sourceの拒否証拠は未確認） |
| K08 | C5 | MySQL engine adapterとAWS RDS MySQL 8.0.43 binding | K06/K07 | 実装・L検証済（専用account／table権限。実AWS・MySQL・workload sourceは未確認） |

旧T系列は当時の条件と到達点を保持します。K系列の着手をAWS追加実験待ちにはしません。具体的なクラウド・既存DB変更や公開の承認は、汎用の設計・実装作業とは別です。

## K10管理境界・拒否層の継続実装

[採用した設計と今回の範囲](core/k10-trust-and-denial-design.md)を参照します。AWS内部TLSは従来要件の自動緩和ではなく、新policy/hash/承認で選ぶmanaged backend契約を追加しました。PG16.15のNOLOGINは実startup error＋独立Recovery catalogと照合し、GCP直通は明示EGRESS DENYログ候補を取得しますが、ログ生成元が裏付けられないためUnknownです。前回GCP IAM監査ログによる拒否も同じ境界を修正しました。AWSの遅延route証拠と完全IAM、K11は残ります。以下の表は前チェックポイントです。

| 継続単位 | 今回の状態 | 残り |
| --- | --- | --- |
| K10-G：管理TLS契約 | v2 AWS PG/MySQLに明示opt-in契約を実装・ローカル検証 | 実AWS未確認。従来strict要件は内部CA/hostname不足を維持 |
| K10-H：PG NOLOGIN | GCP/AWSの固定認証後応答＋独立Recovery catalog、受入・共通評価へ接続 | 改変/翻訳/不足したprovider応答はUnknown。全認証拒否を包括しない |
| K10-I：ログ候補取得とorigin | GCP firewall候補の取得・照合・受入、origin不足を明示。監査ログも不足を修正 | ログ生成元の信頼境界、AWSの遅延route取得は未完了 |


## K10からK11への現在地

[受入照合と引継ぎ](core/k10-k11-handoff.md)を正とします。K10共通基盤のローカル受入と、各profileの実保護成立を分けました。[K11-Aの詳細設計とprocess/socket部分実装](core/k11-a-runtime-binding-design.md)を追加しました。実session・認証・TLS・poolとの結合が残り、RuntimeBinding全体は未完了です。

| 単位 | 今回の状態 | 残る境界 |
| --- | --- | --- |
| K10-J：保護された生成元 | GCE root kernelの直接probeとsealed factを実装・L検証 | rootと実appのscope結合はK11。Cloud Logging originはK10-X1 |
| K10-K：AWS遅延route | native JSON読取、single-use SQLite/archive履歴、ACCEPT/Allowed保持を実装・L検証 | 単一probe帰属と現在性は未対応。K10-X2 |
| K10-L：AWS IAM | direct IMDS role・同一Proxy/user/action・無条件policy等の限定完全性を実装・L検証 | org member/任意条件/別roleはUnknown。K10-X3 |
| K10-M：K11引継ぎ | offline readiness CLI、runtime入力契約とscope、不足一覧を実装・L検証 | native実行許可ではない。K11の現在の部分実装は下記Aを参照 |
| K11-A：runtime入力・生成・受入 | 固定Linux observerでTCP標本と相互Unix peerを取得し、既存GCE sealed payloadへ接続 | 同一接続に対するIAM/TLSの独立証拠は未接続 |
| K11-B/C：アプリ接続 | GCP PGの接続bundle・管理pool切替・復旧接続からのセッション照合、型付き三資料のSQLite/archive受入 | 別UIDのコネクタとpoolが同一checkoutから署名を発行し、実Linux peerとSQLite/archiveでローカル受入済み。Cloud SQL管理APIとGCE認証は模擬 |
| K11-D/E：閉鎖gateとAWS展開 | 独立sourceの復旧条件を強化し、AWS PostgreSQL/MySQLのbundle・IAM token・厳格TLS接続を追加 | GCPの同一checkoutで閉鎖前判定をローカル検証。AWS両engineの管理pool切替とAWS PostgreSQLの独立runtime受入をローカル検証。AWS実環境とMySQLの独立runtimeは未確認 |
| K10-X1〜X4 | origin/遅延帰属/一般IAM/MySQL追加scopeの拡張タスクとして保持 | 未実装を合格扱いせず、該当policyの閉鎖を止める |

## K09以降の基幹実装

K09とK10-A〜Dの初期範囲に続き、[K10-E/Fの続編](core/k10-native-source-execution.md)でEC2固有source collector/verifier、AWS PostgreSQL取得とGCPの新契約による実行接続を実装しました。設定受理と効果完了を分け、変更直前と設定後に現在証拠を読み直します。E2のMySQL取得・F2のAWS実行接続も実装しました。native拒否・backend TLS・完全なinventory等は残ります。このチェックポイントではK11/K12も未着手でした。K11の現在の部分実装は上記を参照します。追加フィジビリティ・クラウド操作は行っていません。

| ID | 優先・依存 | 作業と完了条件 | 状態 |
| --- | --- | --- | --- |
| K09 | K01〜K08の初期実装 | unsupported intentをplan／native書込み前に返す。GCPの単一CLI元の拒否を全workloadへ拡大しない。native操作完了・保護未評価・生成reportの説明を揃える | 実装・L検証済（357成功／実DB2件ignored。source producerはK10） |
| K10 | K09後 | policy v2、受入台帳、source確認、共通実効評価、実行への接続。拒否層・TLS・SQL/binding・鮮度・Allowed保持 | 共通基盤をL受入、K11入力契約を固定。個別profileの不足はK10-Xへ保持し、全環境の防御成立と区別。[受入照合](core/k10-k11-handoff.md) |
| K10-A | K09、K10設計 | source snapshot参照・policy v2・証拠/評価契約の型、v1 hash/plan/approval維持、v2適用の事前停止 | 完了（L）。[範囲と証拠](core/k10-a-contract.md) |
| K10-B | K10-A | nonce/request/bundle/trust epochのatomic受入、整合性と確認済み型の生成境界 | 完了（L）。[範囲と証拠](core/k10-b-admission.md)。Cのnative source verifier接続を追加済み |
| K10-C | K10-A/B | 既存GCE sourceのchannel/native identity/contextと固定collectorを結ぶ。未検証wireをsource確認済みにしない | 完了（L、root host profile）。実GCE/SSH/Linux未確認。[範囲と証拠](core/k10-c-source.md) |
| K10-D | K10-B/C | PG認証/拒否層・TLS/SQL producer、資料の正規化とpure stateの共通評価へ接続 | 完了（L、初期GCP PG profile）。native拒否根拠/IAM全inventory/runtimeは不足ならUnknown。[範囲と証拠](core/k10-d-postgres.md) |
| K10-E | K10-D | AWS PostgreSQL、次にMySQLのsource/normalizerを共通契約へ接続。未対応runtimeを明示 | EC2 source collector/verifier・AWS PG native取得を実装・L検証。MySQL DB取得もE2で接続。[範囲](core/k10-native-source-execution.md) |
| K10-F | K10-D/Eの対応分 | observe、offline state/status、native実行契約と互換性 | GCP PGのsource-aware実行adapter接続を新契約で実装・L検証。変更前/後・直前hook・query-onlyを分離。AWSもF2で接続。[範囲](core/k10-native-source-execution.md) |
| K10-E2 | K10-E | AWS MySQLのmetadata-only DB認証・TLS/SQL取得producer。EC2 sourceとwire正規化は再利用 | 実装・L検証。接続/TLS/accountとpositive SQL観測。続編で全role closureによるnamed fresh ACLのtable action不在を追加。既存session・incarnation等は対象外 |
| K10-F2 | K10-E/F | AWSのsource-aware閉鎖/失効stepを実行adapterへ接続。新契約と現在source、ownership、SG限定操作を維持 | 実装・L検証。新v3契約・変更直前hook・ConfigApplied/query-only・MySQL暗黙COMMIT境界を維持 |
| K11 | K10共通契約後 | PostgreSQLの既存アプリ導入bundle、経路inventory、runtime境界、token/pool・切替・復旧手順。共通AWS認証をengine中立moduleへ整理 | AのUnix peer、B/Cの管理poolと型付き受入、Dの復旧gate、EのAWS接続を実装・ローカル検証。GCPは同一checkoutの署名と実Linux Unix peerの台帳受入をローカル検証。AWS PostgreSQLは同一checkout・同一トランザクションの独立照合、署名とSQLite/archive受入をローカル検証。AWS実環境の観測元構成とMySQLの独立runtimeは残る。[作業設計](core/k11-work-plan.md) |
| K12 | K04/K06の台帳・recover。実効再判定はK10/K11 | 停止済みGCP PostgreSQL導入で `ConfigureIdentity` が追加した条件付きIAM 2行を一つの差分として補償。元操作の所有receipt、新承認、etagのCASと再開時の照会が受入条件 | [限定補償の設計](core/k12-owned-compensation.md)を作成。実装・検証未着手。session/drain・期限回収は今回の対象外 |

詳細な根拠と受入条件は[照合記録](core/design-implementation-audit.md)へ記載します。追加フィジビリティやクラウド操作はこれらのローカル実装の開始条件にしません。

## 既存実装・実験のタスク記録

状態の正本です。2026-11-02、T01/T02から実装・ローカル検証までの継続承認後、複数クラウド調査・検証準備、合計上限50米ドル、専用GCPの作成・試験・撤収への継続指定を受けました。GCP PostgreSQLの部分実験と撤収確認を実施しました。[準備記録](multicloud-preparation.md)と[実機結果](gcp-feasibility.md)を参照します。AWS資源作成・実RDS接続・公開は未実行です。Lはfixture/loopbackでの確認を意味し、AWS成立やタスク全条件の達成へ読み替えません。

状態: `完了` / `完了（L）` / `一部実装` / `一部完了` / `未着手` / `承認待ち` / `将来具体化`。依存は成果の利用順を表します。未着手は失敗を意味しません。優先度はP0を直近の共通基盤、P1を初期機能、P2を実証・導入、将来を拡張・公開準備とします。

| ID | 到達点 | 優先 | 作業・完了条件 | 依存 | 状態 | AI作業設計 |
| --- | --- | --- | --- | --- | --- | --- |
| T00 | M0 | P0 | 要求、基本/詳細/検証設計、マイルストーン、タスク、作業設計を作り整合確認する | なし | 完了 | [統合](work-packages/00-integration.md) |
| T01 | M1 | P0 | engine/version/region/auth/source/OSの対象行列と未決事項D03〜D05/D07を固定する | T00 | 完了 | [対象と依存](work-packages/01-target-and-dependencies.md) |
| T02 | M1 | P0 | Rust/SDK/DB/TLS依存を選定・固定し、protocol/CA/cancel/ライセンスを確認する | T00 | 完了 | [対象と依存](work-packages/01-target-and-dependencies.md) |
| T03 | M1 | P0 | 設定、Snapshot、Observation、Assessment、CLI終了コードの契約と独立fixtureを実装する | T01,T02 | 完了（L） | [統合](work-packages/00-integration.md) |
| T04 | M1 | P0 | 新規run保存、権限、manifest/hash、部分失敗、サイズ上限、秘密非出力を実装する | T03 | 完了（L） | [証拠と判定](work-packages/02-evidence-and-report.md) |
| T05 | M1 | P0 | 純粋な判定器、証拠種別/鮮度/対象対応、全N/A/空結果処理を実装する | T03,T04 | 完了（L） | [証拠と判定](work-packages/02-evidence-and-report.md) |
| T06 | M2 | P1 | 対象限定のAWS inventory、権限表、部分取得/ページングのadapter試験を実装する | T05 | 完了（L） | [AWS読取](work-packages/03-aws-inventory.md) |
| T07 | M2 | P1 | IAM署名、TLS検証、DB transport、対象照合、期限/取消しを実装する | T05 | 完了（L） | [接続試験](work-packages/04-probes.md) |
| T08 | M2 | P1 | 専用合成領域でCRUD/transaction/後条件、所有範囲だけのcleanupを実装する | T07 | 完了（L） | [接続試験](work-packages/04-probes.md) |
| T09 | M2 | P1 | 認証/TLS/直接経路の負例と正例の対、管理例外の結果を実装する | T06,T08 | 一部実装 | [接続試験](work-packages/04-probes.md) |
| T10 | M2 | P1 | 更新/切断/結果不明COMMIT/取消し/復帰とretry境界を実装する | T08 | 一部実装 | [接続試験](work-packages/04-probes.md) |
| T11 | M2 | P1 | 条件固定のbaseline/Proxy計測と生データ/集計、標本不足表示を実装する | T08,T10 | 一部実装 | [接続試験](work-packages/04-probes.md) |
| T12 | M2 | P1 | planの差分/復旧とsandbox用CFN・DB bootstrap手順を生成する。適用しない | T05,T06 | 完了（L） | [構築計画](work-packages/05-planner.md) |
| T13 | M2 | P1 | JSON/Markdownレポート、実行状態と判定、未実施/例外/次の確認を実装する | T05 | 完了（L） | [証拠と判定](work-packages/02-evidence-and-report.md) |
| T14 | M2 | P1 | CLIと各部分を接続し、plan→snapshot→probe→reportのfixture統合試験を行う | T06,T09,T10,T11,T12,T13 | 一部実装 | [統合](work-packages/00-integration.md) |
| T15 | M2 | P1 | 対象/秘密/依存/異常系を確認し、実行/未検証手順を文書化。必要なローカルチェックを完了する | T14 | 一部完了 | [統合](work-packages/00-integration.md) |
| T16 | M3 | P2 | AWS実験計画、費用/時間上限、変更/削除対象、停止/復旧を具体化して承認を得る | T15 | 一部完了 | [AWS実証](work-packages/06-aws-experiment.md) |
| T17 | M3 | P2 | 承認済sandbox構築、DB user/schema、baseline、主体/送信元確認を実施する | T16 | 承認待ち | [AWS実証](work-packages/06-aws-experiment.md) |
| T18 | M3 | P2 | AWS正規/負例/直接経路/管理/更新/復旧/互換性を実証し証拠を保存する | T17 | 承認待ち | [AWS実証](work-packages/06-aws-experiment.md) |
| T19 | M3 | P2 | 固定した受入値と条件でAWS性能比較を行う | T17,T18 | 承認待ち | [AWS実証](work-packages/06-aws-experiment.md) |
| T20 | M3 | P2 | 承認範囲の復旧/片付けと残資源/残課金を確認し、証拠を保持。T18/T19を含め最終profileを評価する | T17 | 承認待ち | [AWS実証](work-packages/06-aws-experiment.md) |
| T21 | M4 | P2 | 既存DB導入先の依存/管理経路/変更前後/切戻し計画を具体化する | T18,T19,T20 | 将来具体化 | [導入・拡張・公開](work-packages/07-adoption-and-extensions.md) |
| T22 | M4 | P2 | 対象別承認後、既存DBの段階導入・復旧・互換性と利用者検証を行う | T21 | 承認待ち | [導入・拡張・公開](work-packages/07-adoption-and-extensions.md) |
| T23 | M5 | 将来 | デコイ隔離・検知源・通知方式を設計し、合成データで独立実証する | T18 | 将来具体化 | [導入・拡張・公開](work-packages/07-adoption-and-extensions.md) |
| T24 | M5 | 将来 | 手動再確認から継続実行へ拡張し、差分/証拠失効/通知を検証する | T13,T18 | 将来具体化 | [導入・拡張・公開](work-packages/07-adoption-and-extensions.md) |
| T25 | M6 | 将来 | 公開範囲、ライセンス/依存帰属、再現/導入/復旧文書、公開物をレビュー可能にする | T22 | 将来具体化 | [導入・拡張・公開](work-packages/07-adoption-and-extensions.md) |
| T26 | GCP初期対応 | P1 | 追加承認の範囲でGCPのstrict config/adapter/評価をCLIへ統合。接続可否・拒否層・根拠付き反映確認待ちをローカル/実機で検証し、専用資源を撤収する | T04,T05,T13、GCP追試 | 完了 | [GCP実装・確認](gcp-cli.md) |

## 担当と状態の更新

着手時に担当、対象タスク、編集範囲、根拠の版を記録します。実装承認後は、依存が満たされた同じ範囲のタスクを工程ごとに再承認せず進めます。課金・外部通知・公開・対象環境変更等の権限境界は別です。

完了時は検証結果と未実施を参照し、タスクの状態を更新します。T20はT18/T19が失敗・中断しても必要な停止/復旧処理として実行します。通常完了ではT18/T19の後に片付けますが、障害時cleanupを成功試験への依存で妨げません。

タスクが大きくなったら、このID配下の作業として分割し、元の要求・検証IDを保持します。工数や性能値を未測定のまま埋めません。将来具体化タスクは、対象と承認範囲が決まるまでそのまま実行可能とは扱いません。

## ローカル実装の到達点と残作業

M1の共通契約は完了しました。M2ではplan/inspect/probe/reportと局所的な実DB試験が動きますが、次のproducer不足があるためM2全体を完了とはしません。[実装・検証記録](local-validation.md)と[接続試験記録](probe-validation.md)を参照します。

- T09: IAM/TLS負例・直接TCP観測は実装。送信元のホスト/ENI/SGとIAM主体の客観照合、管理主体の分離を自動取得するproducerは未実装です。declaredをcorroboratedへ昇格させません。
- T10: 再接続・期限/取消し・結果不明COMMITの照合と長時間token試験の明示経路を実装。CLI credential chainの実資格情報期限の観測、DNS/経路障害注入とphase実測producerは未実装です。署名前の期限切れ拒否やtransport faultはローカルで確認済みです。
- T11: 固定SQLの両経路用時系列・集計と、構造化した比較条件の評価を実装。Proxy pinning/CloudWatchの実計測producerとrunner identityの客観資料は未実装です。
- T14: 主要CLIのfixture統合とprotocol参照検査は完了。上記producerを含む全core実行は未完了です。
- T15: ローカル試験、静的検査、依存監査、文書と独立レビューを実施。M2全機能の完了条件を弱めず、一部完了として残します。

これらの未実装と、コードはあるが実AWSで未検証の部分を区別します。追加承認の範囲でT16のアカウント・費用確認へ着手しましたが、RDS読取権限不足、費用総額、runner配布、具体的な構築・撤収承認が残るため、T17以降へは進んでいません。GCP等の先行部分実験案をAWS M3の完了へ読み替えません。

GCPの先行部分実験では、IAM DBログイン、専用schemaのSQL、commit/rollback、再接続、取消しを確認しました。その後の[追加実機検証](gcp-rejection-validation.md)で、直通に対する許可リストとConnector必須化の効果、有効だが不許可のIAM主体に対するconnect/login拒否を別々に確認しました。続くT26では[GCP CLI adapter](gcp-cli.md)を実装し、check12回/report4回のnative実機・再評価でPending時のAllowed保持、根拠なしのFail、Mixed履歴、timeout Unknownを確認し撤収しました。GCP上のTLS証明書負例、自動token更新、既存DB導入、全送信元の迂回不存在は未確認です。GCP構築適用のコードは後続K05で実装しましたが、そのnative実行は未確認です。GCPの完了範囲を上表のAWS向けT17〜T20やM4の完了には数えません。
