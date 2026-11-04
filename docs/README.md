# 設計文書の入口

K09更新: 要求別の事前判定と、操作完了・保護未評価の区別を実装・ローカル検証しました。[現在の判定・CLI・残るK10の境界](core/k09-qualification.md)を参照します。追加フィジビリティ・実クラウド操作は行っていません。

K01〜K08の初期実装後の現在地は[設計・実装照合](core/design-implementation-audit.md)を正とします。限定実装の完了と、基幹設計全体・実対象への導入完了を区別します。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](core/k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存RDS PostgreSQL／専用RDS Proxy向けのコードとローカル検証を追加しました。[現在の対応・操作・効果待ちの境界](core/k07-aws.md)を参照します。実AWS操作やworkload sourceに束縛した直通拒否の確認は行っていません。

K06更新: 状態評価、限定reconcile/recover、Deny更新、所有IAM/SQL差分の回収、DB login停止を実装・ローカル検証しました。[使い方・完了範囲・残る制限](core/k06-lifecycle.md)を参照します。cloud/実DBの操作は行っていません。

更新日: 2026-11-02。K01〜K04に続き、依存整理とK05の実装・ローカル検証まで進めました。[K05の利用・実装・判定境界](core/k05-native.md)を参照します。K06の維持・失効・限定復旧はローカル実装済みで、実環境での動作は未確認です。

## 読む順番と文書の責務

| 文書 | 正本とする内容 |
| --- | --- |
| [K10-C GCE送信元確認](core/k10-c-source.md) | 初期root host profile、固定SSH/collector・Google署名/context照合、B接続、418成功と実GCE/Linux未確認の境界 |
| [K10-B証拠の受入・保存](core/k10-b-admission.md) | atomic受入、source trust epoch、nonce、保存後commit、offline再読取、B完了時のverifier portとC接続の境界 |
| [K10-A実装・互換性](core/k10-a-contract.md) | policy v2とsource参照・未信頼/確認済み型の分離、旧v1互換、v2適用停止、A完了時点の記録 |
| [K10基本設計](core/k10-evidence-design.md) | 最初のsource profile、信頼境界、取得・受入・評価の構成、K10の区切り。A/B/Cの型・互換性・受入・初期sourceは実装済み、D〜Fは未実装 |
| [K10証拠・評価契約](core/k10-evidence-contract.md) | policy v2のsource参照、request／bundle／受入台帳、assurance・層・TLS・SQL・binding・互換性 |
| [K10作業設計](core/k10-work-plan.md) | A〜Fの実装順序・担当境界・受入シナリオと未実行の条件 |
| [要求](requirements.md) | 目的、要求ID、最終構想と初期範囲、成功条件 |
| [K09の要求別判定と完了判定](core/k09-qualification.md) | 非対応の事前拒否、旧planの再判定、受付済みquery継続、source未確認のPendingと現在の完了表示 |
| [設計・実装の照合と残作業](core/design-implementation-audit.md) | K01〜K08の到達点、コード上の残差、次のK09〜K12候補と優先順 |
| [基幹の全体設計](core/README.md) | 製品の中心、共通control planeとnative実効制御、初期GCP profile、モジュール責務 |
| [基幹control plane](core/control-plane.md) | ポリシー・計画・承認・操作状態・journal・再開の詳細契約 |
| [基幹data plane](core/data-plane.md) | 配置先×DBの二軸adapter、アプリbinding、認証更新、DB権限とnative効果 |
| [基幹security lifecycle](core/security-lifecycle.md) | 導入・失効・期限・管理例外・復旧・障害時の境界 |
| [K08のMySQLとPostgreSQL継続対応](core/k08-mysql.md) | RDS MySQL固有account／暗黙commit／driver／所有差分、共通CLIと実効未確認の境界 |
| [K07のAWS PostgreSQL](core/k07-aws.md) | RDS Proxy・IAM・SG・AWS PG transportの共通基幹接続、read-only観測とsource未確認の境界 |
| [K06の維持・失効・復旧](core/k06-lifecycle.md) | 状態・反映待ち、限定修復/復旧、新policyでの失効、所有SQL回収と未対応の効果 |
| [K05のnative導入実装](core/k05-native.md) | modular monolithの依存境界、native action、CLI、ローカル結果・未確認事項 |
| [基幹実装計画](core/implementation-plan.md) | C0〜C5とK01〜K08、AI担当の編集範囲、並列化、引継ぎ |
| [基幹のローカル利用](core/local-usage.md) | K01/K02・導入graphの使い方、保存物、実装と未実装の境界 |
| [変更・承認・操作台帳](core/operation-ledger.md) | K03/K04のCLI、承認scope、永続記録、中断再開、ローカル結果とnative境界 |
| [基本設計](basic-design.md) | 構成、責務、信頼境界、設計判断、未決事項 |
| [詳細設計](detailed-design.md) | CLI・型・証拠・判定・エラー・並行処理の契約 |
| [AWS調査](aws-findings.md) | 確認した一次資料、事実、対象条件、調査上の限界 |
| [複数クラウド検証準備](multicloud-preparation.md) | Cloudflare/GCP/AWSの利用可能環境・費用、Azure利用状況、専用labの実験案 |
| [GCP実機フィジビリティ](gcp-feasibility.md) | PostgreSQLのIAM接続・SQL・取消しの実測、未確認条件、撤収・費用概算 |
| [GCP直通・IAM拒否の追試](gcp-rejection-validation.md) | 許可リスト/Connector必須化の切り分け、不許可主体のconnect/login拒否、権限伝播の観測 |
| [GCP保護状態の確認CLI](gcp-cli.md) | GCP adapter・check/reportの使い方、Pending/Unknownの境界、CLI実機結果と撤収 |
| [検証設計](verification.md) | 検証ID、手順の目的、期待結果、証拠の範囲 |
| [マイルストーン](milestones.md) | 到達状態と完了条件、承認が必要になる境界 |
| [タスク一覧](tasks.md) | タスクID、依存、状態、担当する作業設計書 |
| [AI作業設計](work-packages/README.md) | 担当ごとの編集範囲、入力、作業手順、受入条件、引継ぎ |
| [レビュー記録](design-review.md) | 独立レビューの指摘と修正、文書検査、実施/未実施 |
| [対象行列](support-matrix.md) | 初期engine/version/region/auth/OSと未確認条件 |
| [依存判断](dependency-decisions.md) | ライブラリとAWS CLI backend、保守判断 |
| [固定ビルド環境](build-environment.md) | Rustの単一版指定、mise tasks、同梱SQLite、Linux対応表示の境界 |
| [ローカル実行](local-usage.md) | ビルド、fixture pipeline、隔離実DB試験の手順 |
| [ローカル検証記録](local-validation.md) | 今回の実装、検査結果、コードの不足とAWS未検証の区別 |
| [接続試験記録](probe-validation.md) | TLS/SQL/応答喪失等の実DB検証、保持証拠 |
| [判定器検証記録](evaluator-validation.md) | 合成protocol、phase/比較/後条件の反例と評価範囲 |

仕様の本文は上表の正本に置きます。作業設計書はその参照と担当境界を記載し、仕様を別の言い方で複製しません。変更は要求→設計→検証→タスクの関係を確認して反映します。

## 出発点

参照した会話: [AIの最適化V2テスト](codex://threads/01a19524-3c47-7d20-9ce5-90a503f8feaa)。案の再評価後に選ばれたI27を中心とし、I28・I29への拡張を維持します。別系統の複数クラウド・ヴァリデータDBの実装は、この計画には含めません。

開始時のリポジトリは `9194205` のREADME見出しのみで、実装・既存設計・未コミット変更はありませんでした。適用対象の祖先ディレクトリとリポジトリ内に、追加のAGENTS.md / Agent.md / CLAUDE.md / Claude.mdは見つかりませんでした。今回提示された協働指示に従います。

## 設計時の範囲と、今回の継続承認

- 基本・詳細設計、検証設計、マイルストーン、一般タスク、AI作業設計書を作る。
- 技術仕様は一次資料で確認し、事実と設計案を区別する。
- 文書の参照・ID・依存関係と、独立担当による内容の整合確認を行う。
- 上記の設計作業後、ユーザーからT01/T02から実装・ローカル検証までの継続承認を受けた。
- 当初の実装承認ではコード作成・fixture・新規loopback DBによる検証までを実施し、AWS認証/操作/接続、課金、公開・push・既存環境変更は行わなかった。
- その後、複数クラウドの利用可能環境・費用とAzure利用状況の調査から実機検証準備までをSol/highで進める承認と、課金してよいという意思を受けた。認証・限定したread-only APIを確認したが、資源作成・権限変更・接続試験・撤収・公開は未実行。[追加調査と具体案](multicloud-preparation.md)を参照する。
- 続いて合計上限50米ドルと、専用GCPの作成・試験・撤収案への継続指定を受けた。新規Cloud SQL PostgreSQL 16.15でIAM接続・SQL・取消しを確認し、instance 0件、課金紐付け解除、専用project削除要求済みまで確認した。[実機結果](gcp-feasibility.md)を参照する。Veil CLIのGCP対応やAWS M3完了とは区別する。
- さらに不許可IAM主体と直通拒否原因の追加検証・撤収までの承認を受け、新規projectとkeyless SA 2件で[追試](gcp-rejection-validation.md)を実施した。対照付きの拒否確認、権限反映遅延の観測、試験用IAM binding/SA/instanceの除去とproject課金解除・削除要求まで完了した。
- 続いてGCP PostgreSQLの検証をVeil CLIへ組み込む承認を受け、既存DBを守る導入運用の一段としてcheck/reportを実装した。接続事実と期待条件を分け、実測role履歴のある反映確認待ちでも現在のAllowedを隠さない。ローカル検証とCLI実機確認、専用環境の撤収まで完了した。[仕様・使い方・結果](gcp-cli.md)を参照する。
- その後、ユーザーから「他のテストはせず基幹部分の設計へ進む」指定を受けた。Sol/highを引き継ぎ、共通ポリシー、二軸adapter、限定executor、アプリ切替、操作台帳、失効・復旧と作業分割を設計した。基幹コードの実装、追加試験、クラウド操作は今回行わない。旧AWS M3の追加実験を基幹着手の先行条件にはしない。
- 続いてK01/K02から基幹実装を進める指定を受け、policy/capabilityと既存観測bridge、K03のdesired graphを実装した。必要なローカル回帰・静的検査を行い、追加フィジビリティ・クラウド操作は行わない。C1完了と、まだexecutorのないC2以降を分ける。
- さらにK03の残りとK04までの継続指定を受け、差分・競合scope・限定承認・repair/復旧計画、SQLite台帳、dispatch前記録、結果照会を先に行う再開kernelを実装した。ローカル注入driverと別プロセスCLIで確認し、C2の共通基盤を完了した。native適用、追加フィジビリティ、クラウド操作、公開は行っていない。

## 読み方

「採用案」は実装の出発点として選んだ設計であり、実測で成立したという意味ではありません。「未決」は解決すべき問いです。未決事項が特定タスクを妨げる場合だけ、そのタスクを止めます。

タスクの状態は [tasks.md](tasks.md) で管理します。設計・実装・ローカル試験と、AWS実証・既存DB導入を区別します。AI作業設計書があることだけでは、その作業を実行する承認や完了を意味しません。

継続指定により、単一クレートでの依存整理とK05の実装・ローカル検証を実施しました。追加フィジビリティ・クラウド操作・公開は行っていません。
