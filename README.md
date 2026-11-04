# Veil DB Guard

K11更新。Unix peer観測、GCP PostgreSQL管理poolの世代切替、証拠受入の照合契約と復旧gate、AWS PostgreSQL/MySQLのアプリ接続をローカル検証しました。実アプリ接続のIAM/TLS・pool利用を独立して確認する資料が揃うまでRuntimeBindingはUnknownです。[実装・検証範囲](docs/core/k11-work-plan.md#unix-peerpool切替受入の接続)

K10→K11引継ぎ: [共通基盤のローカル受入と残る拡張](docs/core/k10-k11-handoff.md)、[K11作業設計](docs/core/k11-work-plan.md)。生成元とapp scope、遅延履歴と現在証拠、限定IAM完全性を分離し、`guard k11-readiness`で次の入力と不足をexportできます。K11-Aの詳細設計とprocess/socket部分の取得・受入・共通state接続まで実装しました。[現在の範囲と不足](docs/core/k11-a-runtime-binding-design.md)を参照します。実session・認証・TLS・pool世代は未結合で、RuntimeBindingはUnknownです。全profileの防御成立やnative実行許可の宣言ではありません。

K10管理境界・拒否層更新: [設計と実装範囲](docs/core/k10-trust-and-denial-design.md)。AWSの明示的なmanaged backend TLS契約、GCP/AWS PGの認証後NOLOGIN＋独立catalog対照、GCPのfirewallログ候補取得を追加しました。ログ生成元の裏付けが足りない場合はUnknownを維持します。従来の厳密TLSは維持し、取得できないAWS遅延ログや完全IAMの不足は隠しません。

K10残producer更新: [拒否・IAM・MySQL不在inventoryとbackend TLS境界](docs/core/k10-producer-gaps.md)を実装・ローカル検証しました。GCP監査ログ候補と完全に評価できた関連IAM集合、承認台帳からの有限Pending、MySQL named ACLの不在を共通stateへ接続しました。監査ログ候補は生成元の裏付け不足を検出しUnknownへ修正しました。AWS Proxy内部CA/hostname、AWS完全IAM、他のnative拒否層は不足を残し、K10全体の完了とは扱いません。このK10チェックポイントでは追加クラウド操作・追加フィジビリティ・K11実装を行っていません。現在のK11部分実装は冒頭の更新を参照します。

K10-E/F更新: [EC2 source確認・PG/MySQL取得とGCP/AWS実行接続](docs/core/k10-native-source-execution.md)を実装・ローカル検証しました。新しい`source-bound-execution-v3`契約は、変更前の許可経路・独立復旧経路・runtime証拠と、設定後の拒否確認を分けます。旧承認を自動昇格せず、設定受付を防御完了にしません。A〜Fの初期接続は一巡しましたが、native拒否根拠・backend TLS・完全なinventory等は不足を残し、K10全体の完了や実環境の防御成立とは区別します。実クラウド・SSH・DB操作や追加フィジビリティ試験は行っていません。

K09更新: 要求別の事前判定と、操作完了・保護未評価の区別を実装・ローカル検証しました。[現在の判定・CLI・残るK10の境界](docs/core/k09-qualification.md)を参照します。追加フィジビリティ・実クラウド操作は行っていません。

現在地: K01〜K08の限定した初期実装とローカル検証が一巡しました。基幹設計全体の完了ではありません。[設計・実装の照合、残る基幹部分、次の実装順序](docs/core/design-implementation-audit.md)を参照してください。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](docs/core/k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存AWS RDS PostgreSQL／専用RDS Proxyのアダプターを共通台帳・承認・再開へ接続しました。[対応範囲・CLI・未確認事項](docs/core/k07-aws.md)を参照します。クラウド操作は行っておらず、実workload sourceの直通拒否は未確認のため実CLIの保護完了判定は効果待ちです。

K06更新: 状態評価、限定reconcile/recover、Deny更新、所有IAM/SQL差分の回収、DB login停止を実装・ローカル検証しました。[使い方・完了範囲・残る制限](docs/core/k06-lifecycle.md)を参照します。cloud/実DBの操作は行っていません。

主要RDBMSの認証・接続経路・防御設定の構築と検証を支援することを目指す、開発中のローカルファーストCLIです。保護導入executorはGCP Cloud SQL PostgreSQL、AWS RDS PostgreSQL、AWS RDS MySQLの限定した組合せを実装し、ローカルで検証しています。

Local-first, open-source tooling that aims to configure and verify authentication, access paths, and security controls for major relational databases. Native protection executors implement bounded profiles for GCP Cloud SQL PostgreSQL, AWS RDS PostgreSQL, and AWS RDS MySQL, with local validation; deployment on real targets remains unverified.

既存DBを置き換えず、正規アプリの接続を認証された経路へ集約し、その防御が実際に機能するか確認することを目指します。接続防御に加え、本番から隔離したデコイと、設定・経路・通知の継続確認を拡張構想として保持します。

## 現在の状態

2026-11-02時点でRust CLI、構築計画、証拠保存・判定・レポート、AWS読取adapter、接続試験器を実装し、fixtureと新規ローカルPostgreSQLで検証しています。実AWS/RDS Proxyでの認証・経路・性能は未検証です。AWS/GCPの承認済みnative操作は明示コマンドとして実装し、ローカルで検証しています。AWSの実機実行は未確認です。

初期実装の対象はRDS PostgreSQL 16.15、東京リージョン、RDS Proxyの両区間IAM認証とTLSです。実環境の利用可能性はAWS着手前に再確認します。Veil DB GuardはDB通信の中継には入りません。[対象行列](docs/support-matrix.md)と[ローカル実行手順](docs/local-usage.md)を参照してください。

GCP Cloud SQL PostgreSQL 16.15/東京向けに`gcp check`と`gcp report`を追加し、CLIからの実機確認と専用環境の撤収まで実施しました。正規接続、不許可IAM主体の拒否、権限変更に対応する実測履歴を持つ反映確認待ちを分けて報告します。拒否したい接続がまだ通る場合は保護済みにせず、timeoutだけでも合格にしません。`gcp check/report`は設定変更を行いません。[GCPの使い方・判定境界・実機結果](docs/gcp-cli.md)を参照してください。

## ローカルで試す

Rust 1.98.1を`rust-toolchain.toml`で固定し、miseも同じファイルを読みます。`mise run check`で整形確認・Clippy・ローカル回帰、`mise run build`でbuildできます。台帳用SQLiteもCargo.lockで決まる同梱版を使います。[環境の固定と初回手順](docs/build-environment.md)を参照してください。次の例は合成設定だけを使い、AWSやDBへ接続しません。出力先は毎回新しいパスにします。

```sh
cargo build --locked
cargo test --locked
mkdir -p runs
cargo run --locked -- plan --config examples/local.yaml --sandbox --out runs/plan-1
cargo run --locked -- inspect --config examples/local.yaml --fixture examples/aws-responses.json --out runs/inspect-1
cargo run --locked -- probe --config examples/local.yaml --snapshot runs/inspect-1/snapshot.json --suite positive --source-id application --fixture examples/empty-observations.json --out runs/probe-1
cargo run --locked -- report --config examples/local.yaml --evidence runs/probe-1 --out runs/report-1
```

最後のreportは、試験未実施のためUnknown・終了コード3になるのが期待結果です。`plan / inspect / probe`の操作完了（`operation_only`）と、防御条件の合格を区別します。ローカル実DB試験は[接続試験の検証記録](docs/probe-validation.md)の明示手順で実行できます。

## 設計と作業計画

[基幹設計](docs/core/README.md)に続き、共通ポリシー（K01）、配置先×DBのadapterと観測bridge（K02）、変更計画と限定承認（K03）、SQLite操作台帳と中断再開kernel（K04）を実装しました。管理範囲外の変更を拒否し、共有DBの全許可主体の切替を直通制限の前提にします。`guard plan/approve/begin/resume/status/cancel/revoke-approval`はローカルで動きます。依存整理とK05のGCP/PG executor、SQL権限、秘密なしbinding、全アプリ切替確認、直通制限まで実装しました。単一クレートを維持し、coreはSQLite/provider/CLIへ依存しません。native操作は`guard apply-gcp`または`guard apply-aws`と`--allow-native-changes`への明示指定が必要です。通常の`guard resume`は外部変更を行いません。今回の検証はローカルfakeのみで、新executorによる実導入は未確認です。timeoutだけならWaitingEffectのままです。[K05の対応範囲・使い方・制限](docs/core/k05-native.md)を参照してください。[操作台帳の利用例と実装境界](docs/core/operation-ledger.md)、[実装作業](docs/core/implementation-plan.md)を参照してください。

[文書の入口](docs/README.md)から、次を参照できます。

- [目的・要求・対象範囲](docs/requirements.md)
- [基本設計書](docs/basic-design.md)
- [詳細設計書](docs/detailed-design.md)
- [検証設計](docs/verification.md)
- [マイルストーン](docs/milestones.md)
- [タスク一覧](docs/tasks.md)
- [AI用の作業設計書](docs/work-packages/README.md)
- [AWS一次資料と成立条件](docs/aws-findings.md)
- [依存の選定と保守判断](docs/dependency-decisions.md)
- [実装・ローカル検証結果](docs/local-validation.md)

ローカル代替試験とAWS実環境の証拠は区別します。設定ファイルの生成や構成情報の確認だけで、接続防御が成立したとは判定しません。

OSSとして進める方針です。ライセンスの選定・ファイル追加、公開・配布は今後の作業です。Cargoのpublishは無効で、今回push・公開は行っていません。
