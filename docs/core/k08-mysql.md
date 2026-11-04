# K08：MySQLを既存DB保護の共通基幹へ接続する

2026-11-02。既存RDS MySQL／専用RDS Proxyを、K01〜K07のpolicy、承認、操作台帳、アプリ切替、直通制限、失効・限定修復へ接続しました。単一Rustクレート・単一CLIを維持しています。今回の検証は合成設定、fake provider／transport、SQLite、ローカル偽CLIとloopback protocolだけです。実AWS CLI／API／実DB操作、追加フィジビリティ試験、公開は行っていません。

PostgreSQLは引き続き主要対象です。K08はMySQLを追加する作業で、既存のGCP PostgreSQLとAWS PostgreSQLを置き換えません。対応済みコードとローカル検証、実対象への導入成功、継続的な保護完了は別に扱います。

## 現在の組合せ

| 配置先 × DB | コード・今回の回帰 | native導入の境界 |
| --- | --- | --- |
| GCP Cloud SQL × PostgreSQL 16.15 / asia-northeast1 | K05/K06のexecutorを維持し回帰確認 | 既存のSA／connector／SQL条件。新executorの実導入は未確認 |
| AWS RDS × PostgreSQL 16.15 / ap-northeast-1 | K07のexecutorを維持し回帰確認 | 専用Proxy・既存login。workload sourceの直通拒否が未接続 |
| AWS RDS × MySQL 8.0.43 / ap-northeast-1 | K08で追加 | 既存専用Proxy／IAM account、3306、table privilege限定。実AWS未確認 |

別minor／engine／region、Aurora、GCP MySQL、MariaDB、自己管理MySQLの対応を推定しません。版更新はpolicy・capability・fixture・native照合の同時変更です。

## 明示するaccountと管理範囲

[合成policy](../../examples/core-aws-mysql-policy.yaml)は`aws_rds_mysql_proxy_v1`と`Target.mysql`を使います。`db_identity`はusername、`mysql.account_host`はアプリaccountのHost、`mysql.management_account_host`は管理accountのHostです。`'user'@'host'`を完全なDB accountとして扱い、GCPのSA suffix変換やPGのcluster roleへ置き換えません。username・database名・host・管理account・engine・portのすり替えを拒否します。

最初のnative実装では以下を前提にします。

- DBのIAM認証が有効。専用の既存accountが`AWSAuthenticationPlugin`とTLS必須設定で準備済み。password accountの認証方式変更、新account作成、自動unlockを行わない。
- 専用RDS Proxyのtarget DB、ARN、DbiResourceId、service role ARN／RoleId、IAM backend policy、空の`Auth`、SG・所有ruleを照合する。DBとProxy両方のengine familyを照合し、MYSQLとPOSTGRESQLを混同しない。
- `lower_case_table_names=0`、正確なdatabase／table名、BASE TABLEだけを扱う。アプリaccountの別host、anonymous account、継承role、mandatory role、global／schema／column／routine／dynamic権限、GRANT OPTION、proxy grantは拒否する。照合に必要なmetadataを管理主体から読めない場合も停止する。
- 一つの専用アプリaccountを、同一instance上の別Allowと共有しない。`SELECT / INSERT / UPDATE / DELETE`の直接table privilegeだけを扱う。MySQLのdatabaseとschemaは別の階層にせず、policyのtable scopeのschemaはdatabaseと同じ値にする。

既存roleの付与、database全体の権限、PGの`CONNECT / USAGE`、任意SQL、sessionの選別終了、JIT自動回収はこの初期subsetで未対応です。[MySQL accountの一次資料](https://dev.mysql.com/doc/mysql-security-excerpt/8.0/en/account-names.html)、[AWSのIAM account設定](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.DBAccounts.html)を契約の根拠としています。

## 導入と中断再開

共通8stepの順序を使います。既存ProxyのIAM／TLS確認、アプリIAM policy設定、既存MySQL accountの準備検証、限定SQL権限、秘密なしbinding、独立復旧、全アプリ切替、所有直通rule回収の順です。MySQLの`RegisterNativeDbIdentity`は、既存plugin／TLS／account状態を検証する書込みなしのstepです。PGの`GRANT rds_iam`を送信しません。

AWS用の共通executorは、engineの`StepExecutor` portを受け取ります。engine選択と資格情報・driverの組立てはcomposition rootに置き、coreへMySQL driver、AWS CLI、SQLiteをimportしません。core単独コンパイルの依存検査を維持しています。MySQLは`core-adapter-v3`、既存PGは`core-adapter-v2`として照合します。

MySQLの`GRANT / REVOKE / ALTER USER`には暗黙commitがあります。全statementをtransactionで囲んで一括rollbackできると扱いません。各statement送信前に不明扱いのindexをprivate artifactへ保存し、受付が確認できたindex、前後の直接権限、追加差分、Partial／Unknownを記録します。途中まで成功して次で失敗した場合は、その事実を残します。保存失敗、timeout、取消し、通信切断後は不明として扱い、read-only queryから書込みを再送しません。[MySQLの暗黙commit](https://docs.oracle.com/cd/E17952_01/mysql-8.0-en/implicit-commit.html)

所有記録runの`Complete`は記録保存の完了であり、SQL全適用の成功ではありません。不明送信後にdesired状態が見えても、それだけで「Veilが全差分を追加した」という所有証明へ変換しません。

## 失効と所有差分

Denyは新しいpolicy revision・承認として扱います。アプリの所有IAM policyを外し、明示accountへ`ALTER USER ... ACCOUNT LOCK`を適用し、新規接続を確認します。既存sessionが終了したとは判定しません。[MySQL account locking](https://dev.mysql.com/doc/refman/8.0/en/account-locking.html)

SQL回収には、先行適用の成功step receipt、batch hash、private ownership artifact、全statementのacknowledgement、適用前後の正確な差分を要求します。追加したtable privilegeだけを回収し、先在権限を保持します。partial／unknownの所有記録を回収権限として使いません。REVOKE後のqueryでは、先在権限が残り、所有追加分だけが減った状態を確認し、再送しません。

MySQLにはここで使えるgrantor単位の所有権や外部GRANTとのCASがありません。専用account、正確なsnapshot照合、外部で調整した排他変更windowが前提です。外部操作者による同一権限の変更を常に識別できる保証ではありません。AWS側も同様に[K07の排他制限](k07-aws.md#aws側の排他制限)を持ちます。

Proxyの準備baselineはDB／Proxyのengine familyを含む`aws-rds-native-preparation-v2`になりました。K07旧版で取得したbaseline hashは再取得・再宣言が必要です。今回native metadataの取得は行っていません。

## CLIと接続情報

MySQLも既存`guard`コマンドで扱います。通常の計画・承認・台帳・再開・状態表示はofflineです。

```sh
cargo run --locked --offline -- guard plan \
  --policy examples/core-aws-mysql-policy.yaml --out runs/mysql-plan-1
```

未観測なので期待終了コードは3です。`guard binding`はschema 3、Proxy host／3306／region、正確なusername・account Host、role ARN／RoleId、workload identity参照を出力します。token/passwordを含みません。アプリ側のtoken更新・pool・TLS対応をbinding出力が自動実装したとは扱いません。

native操作は[K07の`guard apply-aws`とtools設定](k07-aws.md#cliと秘密なしbinding)を使い、承認済みpolicyのengineからdriverを選びます。`--allow-native-changes`がなければ設定を読む前に拒否します。`inspect-aws`も`--allow-aws-read`が必要です。今回これらのフラグ付きnativeコマンドは実行していません。

`ca_file`は登録ProxyのACM証明書チェーンとhostnameを検証できる信頼CA PEMです。MySQL driverは指定CAだけを信頼し、hostname検証、TLS必須、socket fallback無効を固定します。IAM tokenは同じSTS検証済み資格情報から署名し、memory内の接続設定だけへ渡します。argv、DSN、ログ、artifactへ出しません。LOCAL INFILE handlerを登録せず、任意local fileの読取を許可しません。packet上限はhandshake前4 MiB、設定反映後1 MiB、全I/Oにdeadlineとcancelを適用します。

## 接続可否と未確認の原因

MySQLのread-only observerは、CA／hostnameを検証したTLS、正確な`CURRENT_USER()`、database、version、SSL sessionを確認した場合にAllowedを記録します。一般的な1045／Access denied、token失敗、timeoutは原因未確認のUnknownです。IAM拒否や権限反映待ちを、原因の証拠なしに捏造しません。失効後も接続できればAllowedを残します。

CLI実行元のTCP refusalは各workload sourceの直通拒否証拠になりません。`direct_denied_principals`は空のまま保持します。**現在の実CLIは、設定が反映しても直通制限stepがWaitingEffectに残り、期限後にFailedPartialとなり得ます。MySQLのIAM拒否原因を確定する追加観測も未接続です。** これらを実環境の保護完了として表示しません。

## ローカル検証記録

共通policy・plan・binding、MySQL SQL compiler、durable ownership、AWS native provider、実SQLite/orchestratorを使う合成導入・fresh Deny、部分失敗と書込み非再送を確認しています。実driverを使うloopback protocolでは、TLSなし、未信頼CA、hostname不一致が認証情報送信前に拒否されることを確認します。PostgreSQLの既存回帰も全体checkに含めます。

macOS ARM64、固定Rust 1.98.1で`mise run check`を完了しました。format check、Clippy（warningsをerror扱い）、335件成功・0件失敗・実DB用2件ignoredです。PostgreSQL transportの既存12件、共通GCP/PG lifecycle、core依存境界の検査も含みます。

別processのoffline CLIはGCP PostgreSQL・AWS PostgreSQL・AWS MySQLの3経路で24コマンドを確認しました。合成policyからplan／approval／begin／binding／resume／statusを扱い、MySQLではreconcile／recover／revoke計画とnative opt-inなしの拒否も確認しました。AWS/MySQL bindingは3306・schema 3、AWS/PGは5432・schema 2を維持しています。PATHの外部toolをtrapし、呼出し0回・native dispatch0回・NeedsActionを確認しました。

最終checkとoffline CLI操作の記録は`runs/core-k08-local-20261102-1/`へ保存しました。`check.log`／`summary.json`と`cli-smoke/summary.json`、各stdout／stderrを保持しています。fake／loopbackの成功を実MySQL server、実RDS Proxy、実ネットワーク、実復旧の成立へ読み替えません。
