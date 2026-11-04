# K07：AWS PostgreSQLを共通基幹へ接続する

2026-11-02。単一Rustクレート・単一CLIのまま、既存RDS PostgreSQL／既存RDS Proxyを共通policy、限定承認、SQLite操作台帳、再開・失効・修復へ接続しました。今回の検証は合成設定、fake provider、ローカル偽CLI、SQLite、ファイルのみです。実AWS CLI・AWS API・実DBへの操作、追加フィジビリティ試験、公開は行っていません。

K07のコードとローカル検証、AWS実環境での成立、workload sourceを含む保護完了は別です。後述のsource検証が未接続のため、**現在の実CLIは直通制限の設定が反映してもWaitingEffectに残ります**。fakeの完了を実環境の完了へ転用しません。

## 初期対応の前提

| 項目 | 今回の実装範囲 |
| --- | --- |
| DB | 既存RDS PostgreSQL 16.15、ap-northeast-1、5432、IAM DB認証有効、登録済みDbiResourceId |
| Proxy | 登録済みの専用RDS Proxy、POSTGRESQL、一つの既存DB target、専用SG一つ。Secrets Manager `Auth`は未指定／空配列だけ |
| DB側network | DBに付いたSGは一つ。既存のProxy SG→DB:5432経路を保持し、計画に固定した一つ以下の所有ingress ruleを回収 |
| アプリ | 専用AWS role ARN＋immutable RoleId、専用の既存PostgreSQL login、workload identity参照 |
| 管理・復旧 | アプリ・Proxy service roleとは別の一つのrole、既存管理login、承認済みProxy経路 |
| Proxy backend role | 登録したARN＋RoleId、明示した既存inline policyに、当該DBIResourceId／対象DBユーザーへの正確な`rds-db:connect`許可がある |
| 実行 | Standing Grant。CLIで既承認のtyped stepだけを進める。native前進には排他変更windowが必要 |

新しいDB／Proxy／SG／IAM role／DB loginの作成は行うexecutorではありません。既存の専用資源を登録・検証し、許可した構成差分を適用します。共有Proxyや、現在password認証で使っている共有loginを自動で無停止移行する範囲ではありません。専用loginへの`rds_iam`付与はcluster全体の認証契約を変え、password認証に影響し得ます。既存clientの棚卸しと、旧clientと分離された準備用Proxy/loginが前提です。同じinstanceで別Allowとloginを共有する変更は拒否します。

`DefaultAuthScheme=IAM_AUTH`だけではSecrets Manager認証の併存を排除できません。このため非空・不正な`Auth`を拒否し、自動で既存認証設定を削除しません。[AWSのProxy作成設定](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-creating.html)

## 承認する対象と依存の境界

`ProfileKind::AwsRdsPostgresProxyV1`と`Target.aws`に、DBIResourceId、DB／Proxy endpoint、Proxy ARN、service role ARN／RoleId、backend policy名、SG ID、アプリ用inline policy名、管理DB login、閉じるruleのID・protocol・port・source・所有タグを固定します。別account、Proxy経路そのものを閉じる指定、範囲外のruleを拒否します。

DB generationはaccount・region・DB ARN・DbiResourceIdを版付きtupleとしてhashします。DbiResourceIdがpolicyにある場合、正規化でこの**期待値**を補完します。これは登録値からの計算で、遠隔の真正性やConfirmedへの昇格ではありません。native処理では実際のDBIResourceId、Proxy ARN、RoleIdを再取得・比較します。同名再作成のARN文字列だけをidentity証拠にしません。

Proxy targetの`RdsResourceId`はDB instanceの名前です。DbiResourceIdと同一視せず、target ARN／名前／endpoint／portと実DB metadataを照合します。[AWS DBProxyTarget](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxyTarget.html)

coreはAWS CLIやSQL driverをimportしません。`adapters/deployment/aws`、`adapters/engine/postgres/aws`、`adapters/aws_observation`を外側で組み立て、既存`OperationLedger`／`StepExecutor`と共通PG engineを使います。共有Proxyのconflict keyも追加し、DBが別でも同じProxyへの変更を直列化します。外部consoleや別hostとの排他をこの台帳が保証するわけではありません。

## 導入・失効と中断再開

Allow導入の順序は共通8stepです。

1. PrepareNativeRoute：既存ProxyのIAM_AUTH／RequireTLSを確認する。変更が必要なら、後述のbaseline付き準備宣言と排他変更windowを照合し、狭いModifyDBProxyを送る。
2. ConfigureIdentity：アプリroleに、Proxy resource ID／専用DBユーザーだけの`rds-db:connect` inline policyを設定する。存在しないか、Veil所有の完全一致文書だけを扱い、衝突を上書きしない。
3. RegisterNativeDbIdentity：既存の専用loginへ固定SQLで`rds_iam`を付与する。任意roleや新しいuserを作らない。
4. ConfigureSqlPrivileges：管理scope内の既存roleと個別SQL privilegeをtransactionで設定する。
5. PublishBinding：秘密なしのAWS用接続profileを生成し、操作者が既存deploymentへ反映した宣言を確認する。
6. ConfirmRecoveryReadiness：独立した管理・復旧経路の準備を確認する。
7. AwaitApplicationCutover：全登録アプリ／workloadの切替宣言を確認する。
8. ConstrainDirectPath：アプリと復旧roleの新しいProxy IAM/TLS/SQL成功を確認後、所有した一つのSG ruleだけを回収し、設定と実効を別に追跡する。

アプリroleの許可先は`dbuser:<prx-resource-id>/<db-user>`、Proxy backend roleは`dbuser:<DbiResourceId>/<db-user>`です。前者へ直接DBの許可を代用しません。既存backend policyは検証するだけで、広い権限への拡張は行いません。[Proxy IAM設定](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-iam-setup.html)、[IAM DB policy](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html)

Deny更新はK06と同じ新revision・新承認です。所有inline policyの削除、NOLOGIN、必要なら所有SQL差分の回収、現在の拒否観測を別stepにします。SQL回収は元applyの成功receiptとownership artifactを必要とし、`--ownership-run`へ接続しています。別grantor／PUBLIC／継承権限を削除しません。

すべての書込みはdispatch前に台帳へ記録します。不明応答は照会へ戻り、IAM／SG／Proxyの書込みを再送しません。受付・設定反映・接続可否を分け、承認やwindow期限後も受理結果だけをread-only照会できます。取消し・部分失敗でAllowや直通ruleを自動復元しません。sessionの選別終了やJIT自動回収は未対応です。

## 既存Proxyの準備宣言

排他変更windowはconsole等との競合調整であり、現在のclientを安全に移せることの宣言ではありません。Proxy全体のIAM/TLSを変える前には別に`native-preparation-ready`を要求します。

この宣言は「専用の準備用Proxy/loginであり、未登録clientや既存password clientを切り捨てない前提を操作者が確認した」という意味です。change／policy／target generation／Proxy ARNと、変更前DB・Proxy構成のhashへ束縛し、最大1時間とします。タグやhashを実利用者の自動発見・認証へ読み替えません。すでにIAM/TLS条件を満たすProxyのNoOpには追加宣言を要求しません。

baselineは明示したread-onlyコマンドで取得できます。**今回このnativeコマンドは実行していません。**

```text
veil-db-guard guard inspect-aws --ledger <ledger> --operation <id>
  --execution-identity aws-role:<role-arn>:<role-id>
  --native-config <aws-tools.json> --out <new-inspect-run> --allow-aws-read
```

選択metadataと`preparation_configuration_hash`を新しいrunに保存します。`guard attest --kind native-preparation-ready --configuration-hash <hash>`で、内容を確認した操作者が宣言します。構成が変われば同じ宣言では書込みできません。

## CLIと秘密なしbinding

[合成policy例](../../examples/core-aws-policy.yaml)は外部操作なしで計画できます。syntheticなARN／ID／endpointを実資源の証拠にはしません。

```sh
cargo run --locked --offline -- guard plan \
  --policy examples/core-aws-policy.yaml --out runs/aws-plan-1
```

期待する終了コードは3です。`guard approve/begin/resume/status/cancel/revoke-approval`、`binding/attest`、`reconcile/revoke/recover`の計画生成は引き続きofflineです。`guard resume`が自動的にAWSへ接続する変更はありません。

AWS接続profileはschema 2、`rds_proxy`経路、正確なDB login、Proxy host／port／region、role ARN／RoleId、workload identity参照を持ちます。token/passwordを含みません。アプリ側はAWS SDK等で新規接続に使うIAM tokenを取得・更新し、TLS・接続poolを管理します。GCPのservice-account suffix変換は使いません。

Native実行は次の別コマンドです。**今回の実行対象ではありません。**

```text
veil-db-guard guard apply-aws --ledger <ledger> --operation <id>
  --expected-version <version> --execution-identity aws-role:<role-arn>:<role-id>
  --native-config <aws-tools.json> --checkpoint <exclusive-window.json>
  --checkpoint <binding.json> --checkpoint <recovery.json> --checkpoint <cutover.json>
  [--checkpoint <native-preparation.json>] [--ownership-run <source-sql-ownership-run>]
  --allow-native-changes
```

opt-inがなければ設定を読む前に拒否します。tools JSONは`schema_version:1`, `aws_cli`（実行ファイル絶対パス）, `management_profile`, `profiles`（subject_id／明示profileの配列）, `ca_file`（登録ProxyのACM証明書チェーンとhostnameを検証できる信頼CA PEM）, `work_dir`（既存の自分所有0700 directory）です。Proxy用の信頼CAとDB直接接続用のRDS CAを混同しません。profileは秘密値ではなく、実行時に固定資格情報を解決する参照です。

実行主体はpolicyの独立復旧roleと一致する必要があります。管理主体には対象に絞ったRDS／IAM／EC2 metadata読取、対象ProxyのModifyDBProxy、対象アプリroleのPutRolePolicy／DeleteRolePolicy、対象DB SGのRevokeSecurityGroupIngress等が必要です。自動的な権限拡大は行いません。管理SQL loginには既存role／objectの必要なGRANT権限が必要です。

アプリのobserverは管理用metadata権限を要求しません。明示profileから一度取得した同じ資格情報でSTS RoleId／ARN sessionを照合し、同じ資格情報をSigV4署名へ使います。DB／Proxy／各RoleId等は管理資格情報でobserver前後に照合します。資格情報の再解決によるaccount／roleの取り違えを防ぎ、token／鍵をargv・ログ・artifactに出しません。子プロセスは時間・出力量・cancel・子孫の停止と回収を制限しています。

## 観測と保護完了の境界

`work_dir/aws-access-*/`に、manifestと`aws-access.json`を保存します。観測は最大8主体、Proxy側の一連の試行は120秒、最後のTCP診断は最大5秒です。鮮度はcapture開始から60秒で判定します。ProxyでCA／hostname検証を伴うTLS、署名済みIAM、正確なcurrent_user／DB／version／backend SSLを確認します。generic PAM/login失敗、token取得失敗、timeout、SQL ACL不足をIAM拒否へ変換しません。

Proxy roleで接続成功したことと、実アプリのworkload sourceで接続したことは別です。現在のobserverはCLI実行元から動き、policyの各source_idに帰属するremote runnerを持ちません。そのため、実行元のConnectionRefused／timeout等を記録しても、全アプリや復旧sourceの`direct_denied_principals`には転記しません。**実CLIの直通閉鎖stepは設定反映後もWaitingEffectとなり、操作期限後はFailedPartialになり得ます。** sourceに束縛した観測executorは残る拡張点です。

共通`guard state --evidence <aws-guard-check-run>`はmanifest／policy／captureのhashと対応を再検証します。現在のProxy Allowedは表示に残し、世代・workload sourceの保証を足さず、SQL/session等の未観測もUnknownにします。保存済みverdictを信用して保護へ昇格しません。

失効時の観測は`aws-state-*/effective-state.json`へoperation/change/policyとともに保存し、`guard status --native-state-run <aws-state-run>`で読めます。これは最後の保存記録であり、status自体は再接続しません。Partial時のAllowedも残します。native stdoutも`operation_scope_completed`と`protection_evaluated`を分け、現在の実装では後者を成功扱いにしません。

## AWS側の排他制限

PutRolePolicy、ModifyDBProxy、SG rule revokeには、今回必要な期待version／ARN／rule tupleのCASがありません。完全一致の直前照合と、外部で調整した排他変更windowを要求しますが、照合直後の外部変更とのraceが消えたとはしません。

IAM文書はgrant単位の所有名と正確な内容、SGはrule ID・所有account・group・direction・protocol・port・source・所有tagを照合します。SGはstatefulなので、新規経路の制限を既存session終了と扱いません。複数SG、prefix list、複数ruleの一括閉鎖、共有Proxy／共有login、legacy secret-backed Proxy移行、Auroraや他engine・他regionへは対応を主張しません。[SG rule API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SecurityGroupRule.html)、[SG接続追跡](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)

## ローカル検証

実際の共通policy・8step graph・SQLite・orchestrator・AWS合成executor・binding・PG executorに、provider／DBだけfakeを注入しています。適用、効果待ち、期限後のread-only再開、fresh approvalによるDeny、Allowed/Pendingの保持、書込み非再送を確認します。補助の偽CLIでは固定資格情報／STS／metadata、型不正、秘密を含まないargv、子孫processのcancel/reapを検証します。

macOS ARM64、固定Rust 1.98.1で`mise run check`を完了しました。format check、Clippy（warningsをerror扱い）、全local testで310件成功・0件失敗、明示した実DB試験2件はignoredです。core単独コンパイルによる依存境界の確認も含みます。ログは`runs/core-k07-local-20261102-1/check.log`、集計は同directoryの`summary.json`です。

別processのoffline CLIで合成policyから計画・承認・操作登録・AWS接続profile出力・準備宣言・再開・状態表示・reconcile/recover/revoke計画を確認しました。外部toolをtrapしたPATHでnative dispatchは0回、再開後はNeedsActionです。apply-aws／inspect-awsは明示opt-inなしでPERMISSION_REQUIREDとなり、設定読取や外部tool起動へ進みません。stdout／stderrと集計は`runs/core-k07-local-20261102-1/cli-smoke/`に保存しています。合成hashを使った準備宣言はnative構成の証拠ではありません。

これらの成功はAWSの接続・経路・SQL・権限伝播・負荷・復旧の実証ではありません。旧AWS M3／既存DB導入を完了へ変更していません。[K08](k08-mysql.md)でMySQLの限定実装を追加しました。PostgreSQLの回帰と対応範囲は維持しています。

K08更新: 準備baselineはDB／Proxyのengine familyを含むv2へ更新しました。旧v1のhashは再取得・再宣言が必要です。AWS executorはengineの既存portを受け取り、PGとMySQLで同じ操作順序・承認・台帳を使います。
