# 基幹実装のローカル利用

K10更新: [source取得と新実行契約の対応範囲](k10-native-source-execution.md)を追加しました。GCP PG16.15/東京/GCE root host、AWS PG16.15・MySQL8.0.43/東京/EC2 root hostの初期接続を実装・ローカル検証します。native拒否・TLS区間・inventory・runtimeの不足はUnknownを維持します。以下の旧単位の手順・結果は履歴として保持します。

K09更新: 要求別の事前判定と、操作完了・保護未評価の区別を実装・ローカル検証しました。[現在の判定・CLI・残るK10の境界](k09-qualification.md)を参照します。追加フィジビリティ・実クラウド操作は行っていません。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存RDS PostgreSQL／専用RDS Proxy向けのコードとローカル検証を追加しました。[現在の対応・操作・効果待ちの境界](k07-aws.md)を参照します。実AWS操作やworkload sourceに束縛した直通拒否の確認は行っていません。

K06更新: 状態評価、限定reconcile/recover、Deny更新、所有IAM/SQL差分の回収、DB login停止を実装・ローカル検証しました。[使い方・完了範囲・残る制限](k06-lifecycle.md)を参照します。cloud/実DBの操作は行っていません。

2026-11-02。K01/K02に続き、K03の差分・限定承認・復旧計画と、K04のSQLite操作台帳・中断再開kernelを実装しました。[操作台帳の利用と実装境界](operation-ledger.md)を参照します。続いて依存整理とK05のGCP/PG native executorを実装しました。[K05の利用・制限](k05-native.md)を参照します。K06のrecoverは現在desiredの限定修復で、旧状態への自動補償は未実装です。

## ポリシーから導入計画を作る

[合成policy例](../../examples/core-policy.yaml)はGCP PostgreSQLのアプリ、限定SQL権限、独立した復旧主体とconnector経路を定義しています。アカウントや資格情報を必要としません。`runs`がなければ作り、出力先は毎回新規にします。

```sh
cargo run --locked --offline -- guard plan \
  --policy examples/core-policy.yaml \
  --out runs/core-plan-1
```

現時点の期待する終了コードは`3`です。計画生成の失敗ではなく、実行可能性が未充足であることを表します。stdoutは`operation_only=true protection_evaluated=false execution_available=false`とstep/gap件数を表示します。入力・保存の失敗は`2`です。既存の出力先は上書きしません。

| artifact | 内容 |
| --- | --- |
| `config.normalized.json` | 正規化した秘密なしpolicy。token/passwordを受け取るfieldはない |
| `plan.json` | policy hash、対象、typed actionと依存graph、前提条件、capability gap、未実装の境界 |
| `prepared-change.json` | policy・graph・観測差分・競合scope・上限・repair/復旧計画を束縛したimmutable change |
| `snapshot.json` | 既存観測runを指定した場合だけ生成する正規化観測 |
| `report.md` | 要約と、適用・保護成立ではないことの表示 |
| `manifest.json` | artifactのbytes/hash、実行ID/build、保存状態 |

policyの`revision_hash()`は版付きprefixと正規化した意味から、`manifest.config_hash`は保存対象のtyped JSONから算出します。別のdigestであり、hashは承認者やproviderの真正性を証明しません。

## 既存観測を接続する

`gcp-check`またはAWSの`inspect/probe` runを、登録したtarget IDとともに指定できます。新しいcloud/DB読取は行いません。

```sh
cargo run --locked --offline -- guard plan \
  --policy my-policy.yaml \
  --evidence runs/existing-observer-run \
  --evidence-target billing-db \
  --out runs/core-plan-with-observation-1
```

provider、account/project、region、native resource、engine/version、DB scopeを照合します。manifest/artifactの整合を検査し、`assessment.json`を信用せず既存evaluatorから再評価します。snapshotがないpartial runも対象対応を照合し、取得不足を保持します。

GCP native resourceは`projects/PROJECT/instances/INSTANCE`、AWSはplacementのaccount/regionと一致するDB ARNです。registration IDや宣言fingerprintを、実DBの世代を確認した証拠にはしません。現在のbridgeのgeneration assuranceはUnconfirmedです。

fixture、古いbuild/時刻、途中終了、欠落はそのまま残します。Allowed/Denied/Unknownの接続事実と、旧profileのPass/Fail/Pending/Unknownは別です。旧profileの評価を新policyの保護成立へ転記しません。GCPの旧principal IDと宣言SA、AWSのsource IDと照合段階を区別します。

単一runのCLI取込では独立した削除前baselineを追加しないため、削除宣言だけからPendingを作りません。純粋な`bridge_gcp` APIは検証済みhistoryを明示的に渡せる契約を持ち、根拠付きPendingでも現在のAllowedを保持します。

## 実装済みと残作業

- K01: strict YAML/JSON、入力上限、未知・重複field拒否、参照・競合・managed scope、常設/JIT、GCP専用IAM login、独立復旧経路、canonical policy hash。
- K02: `DeploymentAdapter × EngineAdapter`、target/version/region別capability、boundedな既存run取込、出所・鮮度・欠落・主体対応を残す正規化。観測bridgeをnative変更能力へ昇格させない。
- K03: 導入graph、取得できた構成と旧policyとの差分、共有資源scope、限定承認、repair/復旧計画。共有DBの全許可主体の切替を閉鎖の前提とし、未取得の権限/TLS実効はUnknownに残す。
- K04: SQLite台帳、transactionとCAS、dispatch前記録、結果照会・stable keyによる再開、共有資源lease/fencing。CLIは計画・承認・登録・再開・状態表示・取消しまで接続する。

GCP/PG native executor、限定SQL grantとbinding/handoffはK05で実装・ローカル検証済みです。実導入とnativeのrepair/補償実行は未確認・未実装です。未取得fieldを確認済みにしません。標準CLIの再開はNeedsActionで止まり、合成成功や外部変更を実行しません。

## ローカル確認

Rust 1.98.1で`cargo test --locked --offline`と`cargo clippy --locked --offline --all-targets -- -D warnings`を使用します。strict policy、意味のhash、管理範囲外、共有DBの切替barrier、対象/版/region違い、fixture/partial/stale、Allowedを保持するPending、timeout Unknown、秘密非表示、新規private保存を対象とします。CLIはPATH上のcloud toolを起動していないことも確認します。

追加フィジビリティ、実cloud/DB接続、権限変更・作成・課金・公開は今回行っていません。既存の明示実DB試験はignoredのままです。

実行結果: K01/K02時点は153件成功でした。K03/K04の35件を追加した現在は`cargo test --locked --offline`188件成功、明示実DB試験2件はignoredです。`cargo fmt --all`と`cargo clippy --locked --offline --all-targets -- -D warnings`も完了しました。

分担レビューでは、共有targetの全許可主体を待つ閉鎖barrier、artifactの実bytesへ一致する参照hash、観測capabilityの対象region、旧logical IDとnative主体の区別、partial importでもengine/DBを照合する条件、StandingとLeaseExpiredの矛盾を修正しました。対応stepがない必須effectも`required_effect_gaps`へ残し、計画から黙って省略しません。

合成例の生成物は[計画要約](../../runs/core-plan-20261102-k01-k02-2/report.md)と[plan.json](../../runs/core-plan-20261102-k01-k02-2/plan.json)です。7 step、変更capabilityのgap 7件、未対応の必須effect 0件、終了コード3を確認しました。これはnative設定の適用結果ではありません。
