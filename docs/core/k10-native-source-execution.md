# K10-E/F 続編：EC2 source・PG/MySQL取得とGCP/AWS実行接続

2026-11-03追記: [残producerの実装と観測限界](k10-producer-gaps.md)でGCP connect拒否・限定完全IAM/Pending・MySQL named ACL不在を共通stateへ接続しました。AWS backend CA/hostname証拠など元の要求の残差は維持し、K10全完了とは扱いません。以下は前チェックポイントの記録です。

2026-11-03。既存DBを移し替えず守る本体へ、**EC2固有のsource collector/verifierとAWS PostgreSQL/MySQL観測、GCP/AWSのsource-aware実行アダプター**を接続しました。単一Rust crate/CLIのモジュラーモノリスと、coreへ向く依存を維持しています。Cargo依存の追加はありません。

追加フィジビリティ、実AWS/GCP API、実SSH、実DB接続、collector配置、権限変更、公開・commit/pushは行っていません。以下の成功はローカルの合成署名・選択資料・fake provider/SQL・実SQLite/archiveによる検証です。実環境で防御が成立した証拠とは分けます。

## 今回の到達点

| 範囲 | 実装 | 残る制限 |
| --- | --- | --- |
| EC2 source | AWS専用snapshot、固定SSH、root Linux host context、IMDSv2、IID署名、request/時刻/collector前後照合、sealed verifier、台帳受入とoffline再読取 | root管理hostを信頼するprofile。container/app PIDや悪意あるrootの証明ではない。実EC2/Linux/SSHは未確認 |
| AWS PostgreSQL | metadata-only資格情報、STS role/RoleId、RDS DB/Proxy/target mapping前後照合、固定CA/hostname/IP、IAM新規login、固定read-only catalog | PostgreSQL 16.15・東京限定。Proxy→DBのCA/hostnameを含むTLS、native拒否層、完全な関連IAM inventoryは未提供 |
| AWS MySQL | EC2 source、metadata-only IAM資格情報、pinned CA/hostname/IP、新規login、USER/CURRENT_USER/account@host、固定read-only catalog | MySQL8.0.43・東京限定。SQL privilegeはpositive presenceのみ。negative inventory、EffectiveSqlRole、backend TLSは不足を保持 |
| GCP PostgreSQL実行 | 新契約・新承認、段階別source判定、変更直前/SQL COMMIT前の再確認、設定受付と効果完了の分離、中断再開のqueryへ接続 | GCE root host / Cloud SQL PG16.15・東京限定。runtime bindingや拒否根拠が不足する閉鎖は進めない |
| AWS native実行 | PG/MySQLの新v3契約、source gate、SG/role/target所有範囲・native再読取後の最終hook、SQL前guard、query-only再開を接続 | 証拠不足・未提供RuntimeBinding・拒否根拠は停止/Unknown。実AWSでの適用は未確認 |

**K10全体の完了ではありません。** [前回記録](k10-ef-observation-cli.md)から、EC2 source・PG/MySQL取得とGCP/AWS実行の接続まで進めました。実アプリのRuntimeBinding producerはK11に残ります。

## AWSの信頼経路

`RegisteredSourceSnapshot`は旧GCE `SourceRegistrationSnapshot`と新AWS `AwsSourceRegistrationSnapshot`のuntagged unionです。GCEへAWSの架空project/VM情報を入れません。旧GCE JSONとhash domainは維持し、AWSは別domainを使います。

AWS snapshotはaccount、region/AZ、instance ID、image、pendingTime、private IP、SSH peer/key、collector build/binary/config、host context、trust epochを固定します。PG/MySQL producerを使う場合だけ、metadata role ARN/不変RoleId/credential referenceも登録します。別名のrecoveryへ同じphysical VMを再登録できません。

認証経路は固定のroot SSHと、署名されたIID・request digest・controller capture window・collector/context前後照合の組合せです。IID自体にnonceや現在の起動を保証する機能はないため、署名だけをfresh source証明と扱いません。SSH clientの環境を消し、固定host key、専用known-hosts、固定collector commandを使い、暗黙のSDK/profile/proxy/agentへfallbackしません。

初期IID recipeは `/latest/dynamic/instance-identity/signature` のraw RSA SHA256です。`/rsa2048`はPKCS7なので別形式として扱います。公式Tokyo証明書の公開鍵をbuildにpinし、既存ringの検証専用legacy定数で検証します。この鍵は1024-bitで、証明書有効期間は2024-04-29〜2029-04-28です。未登録region、形式違い、署名不正・期限外は確認済みにせず、更新はbuild変更を伴います。[AWS署名検証](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html)、[AWS公開証明書](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html)

PG/MySQL producerはIMDSv2だけから資格情報を取り、同じ資格情報で固定regional STS/RDS APIを署名します。STSのaccount/assumed role/RoleId/sessionを登録と照合します。署名URL・session tokenはcurlのstdinだけへ渡し、argv・環境・artifact・raw errorへ保存しません。RDS DBの不変resource ID、engine版、Proxy ARN/endpoint、target mappingを接続前後に確認します。[STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)、[DescribeDBProxyTargets](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBProxyTargets.html)

手書き`--cases`でも、policyのAWS DB/proxy endpointとengine別portを共通admission層で照合します。同じDBへ着く別Proxyをapproved routeとして持ち込めません。返却されたPG資料も要求caseとdiagnosticの集合へ完全一致させ、孤立資料や秘密を含む選択値をartifactへ入れません。

## AWS取得設定とCLI

CLI操作順とread-only観測contextは[前回の使い方](k10-ef-observation-cli.md#k10-fcliの使い方)と同じです。`source-register`はprovider別snapshotを解釈し、`observe-plan`は対応configを選びます。`source-build-info`はprofile/schema対応を表示しますが、実source確認済みとは表示しません。`source-context-v1`は従来GCE digestに加えてAWS用context digestを返します。context previewは未署名のbootstrap資料です。

既存の信頼する運用経路で、root所有の固定collector/configを用意する前提です。CLIはVM/role/Proxyを新設せず、installやIAM設定変更も行いません。

AWS `AwsCollectorConfig`は`schema_version: 1`、registration、context、固定endpoint inventoryを持ちます。任意の`postgres`または`mysql`を追加すると、対応するDB producerを明示的に選択します。`AwsPostgresConfig` / `AwsMysqlConfig`は`ca_sha256`と対象ごとのDB ARN/resource ID/endpoint、Proxy name/ARN/endpointを固定します。CAは固定のroot所有 `/etc/veil-db-guard/aws-rds-ca.pem` から読み、digestを照合します。snapshotの`metadata_credential`も必要です。configなしでmetadata credentialを探す動作はありません。

`guard observe --allow-native-read`は、実行時にはsource SSH・IMDS・STS/RDS・DB接続を行う明示readです。今回はそのnative取得を実行していません。未許可時は台帳・key・toolより前に止めます。case分割、元のnonce/時刻/receiptの再利用、offline state/status、部分成功の終了code 3は従来と同じです。

接続成立後のcatalogや前後metadataが欠けても、観測できたAllowedは消しません。target/principal/route/完全性の不足を別facetへ残します。client→ProxyのTLSとProxy→DBのTLSを分離し、前者の成功やbackend `ssl=true`だけで後者のCA/hostname確認を満たしません。timeout、一般SQLSTATE/1045、credential/API失敗をIAM拒否やRouteBlockedへ変換しません。

## MySQLのaccountとSQL観測

MySQL caseにはoptionalな`mysql_account_host`を加え、policyのapp/recovery host selector、request digest、collector、CURRENT_USER照合へ束縛します。新規MySQL requestでは未指定・別hostを拒否し、非MySQLへの指定も拒否します。GCE/PGはNoneを省略して旧wire/hashを維持します。旧MySQL source-only requestは不足のあるUnknownとして読み、account確認済みへ昇格しません。

`aws_native.rs`がcredential/STS/RDS metadata/CAをengine中立に共有し、PG/MySQL固有のSQL/driverは別moduleに置きます。MySQLは登録CAだけを使い、検証hostnameとpinned接続IPを分けます。TLSを広告しない相手にはhandshake response/IAM tokenを送らず拒否します。

MySQL catalogはread-only transactionと固定information_schema queryです。USERのusername、CURRENT_USERの正確なaccount@host、DB・版・case設定・SSLを照合します。権限のpositive一致だけを扱い、partial_revokes有効時やnegative lookup、動的/mandatory/inactive roles、PROXY、column権限等の完全性が不明ならUnknownを保持します。account/objectの名前をpolicy hashと不変DB世代へscopeしますが、PostgreSQL OIDや削除・再作成の証明を捏造しません。

## GCP/AWSの実行契約と中断再開

実行可能なGCP PG / AWS PG・MySQLの新planの契約は **`source-bound-execution-v3`** です。policy schemaはv2、評価は`source_bound_v2`のままです。既存の`source-bound-evaluation-v2` plan/hash/approvalは読取可能ですが、現在のcontract照合でforward dispatchを許可しません。新しいregistryで再planし、reviewと新承認が必要です。v1 policy/plan/approval/hashも維持します。

`core/source_execution.rs`が段階別条件をpureに判定し、`SourceStepCheck`はprivate field/非Deserializeです。持込JSONや保存済みSatisfiedから実行資格を作れません。`LocalSourceGate`は同じoperation/changeの元台帳・archive・現在source head/build/期限を毎回読み直し、読取り全体にも時間上限を設けます。forward承認と観測sessionは別で、read-only contextを実行operationへ転用しません。

| action/段階 | 必要な現在証拠 |
| --- | --- |
| ConfirmRecoveryReadiness | 独立recovery sourceの許可経路接続と必須TLS区間。手動checkpointのみでは完了しない |
| ConstrainDirectPath・変更前 | 影響する全grantの許可経路接続/TLS、RuntimeBinding、独立recovery接続/TLS。まだ閉じていない直通の拒否を先に要求しない |
| DisableNativeIdentity / DisableNewConnections / SQL revoke・変更前 | 独立recovery接続/TLS。所有差分、対象世代、change window等の既存条件も維持 |
| ConstrainDirectPath・設定後 | 必須直通の原因付き拒否、許可アプリとrecoveryの接続/TLS |
| DisableNewConnections / ObserveRevocation・設定後 | 現在の要求に対応する拒否とrecovery接続/TLS。一般的なlogin失敗で完了にしない |

設定後の確認には、controllerが記録したcapture開始秒がdurable dispatch秒より**厳密に後**の受入資料だけを使います。同秒の記録や古い資料の再受入を事後証拠にしません。native拒否根拠が未提供ならConfigApplied/Unknownに残します。根拠のない伝播Pending/deadlineを作りません。

GCP/AWS providerでは遅いmetadata/config/IAM読取の後、変更直前にsourceを再読取します。登録digestや対応profileが既知の非対応・変更済みなら、準備のIAM操作から停止します。declaration確認はruntimeの観測証拠とは別です。PG transportにもguardを渡し、遅い接続・catalog読取後、各変更SQLとCOMMIT前に再確認します。guard非対応transportの既定動作は拒否です。source読取後にchange window/handoff期限も再確認します。COMMIT前にguardが拒否したtransactionはcommitせず、既知のNotAppliedと、COMMIT結果不明を区別します。

MySQLの変更は暗黙COMMITを持つため、guardは各statement直前に確認します。最初のstatement未送信ならNotAppliedとできますが、先行statement送信後のguard拒否はUnknownを永続化し、全batchを未適用として再送しません。native SG操作は承認済み所有tupleを維持し、source証拠で現在のrole/RoleId・DB/Proxy世代の再確認を置換しません。

公開low-level cloud/PG/MySQL/binding executorから新契約の変更や手動recovery成功を迂回できないよう、composition内だけのscopeを設けます。native適用の明示許可、immutable approval、lease/CAS、ownership、native target確認は別々に必要です。

`apply-gcp` / `apply-aws`の`--source-archive ... [--source-request ...]`がこのcompositionを使います。source不足の次stepはnative config/tool/credential前にも表示し、途中で不足になればNeedsActionとして停止します。runtime producerがない既存アプリについて、手動cutover申告をRuntimeBindingの代用にして閉鎖を進めません。

設定が受理済みなら再開時はqueryし、source失効やarchive破損を再送の理由にしません。照会だけ可能な場合は`query_only`を固定し、同じresume内でqueryが完了しても後続writeへ進みません。将来のSQL revoke用ownership資料が欠けても、既存のcloud queryを止めず、そのSQL queryはUnknownに残せます。完了済みoperationの読取りはnative toolを起動せず、現在の全体保護を宣言しません。

## 検証と残り

ローカル検証結果・source hash・対象外操作は `runs/core-k10-native-local-20261103-2/summary.json` とcheck logへ保存します。`mise run check`は**516成功・0失敗・実DB用2件ignored（47 suites）**、fmtとClippy `-D warnings`も通過しました。Rust 1.98.1 / macOS ARM64、locked/offlineです。最初の496成功のチェックポイントも`runs/core-k10-native-local-20261103-1/`へ保存しています。

MySQLのローカル疑似protocol試験では、実mysql_asyncによるread-only transaction/ROLLBACK、TLS非対応serverへの認証情報送信前の拒否を確認しました。管理DBへ接続した試験ではありません。

重要な回帰は、署名/世代/nonce/context/alias/trust rotation、AWS endpoint/portと孤立PG資料、部分Allowed/TLS区間、旧GCE/v1互換、read-only context分離、core単独コンパイル、旧v2承認の不適格、preclose/postcloseの条件差、変更直前の失効・checkpoint期限、ConfigApplied→query、破損資料・別context・元の受入時刻の保持です。件数自体を実環境の安全性の証明にしません。

E2のMySQL native取得とF2のAWS実行接続も、この継続作業で実装しました。次のproducer/導入条件は残ります。

1. **native拒否recipe。** 一般的な接続失敗をIAM認可・native境界での拒否へ格上げしない。
2. **Proxy→DBのTLS根拠と完全な関連IAM inventory。** client TLSや設定受理を他区間の検証・反映待ちの証明にしない。
3. **MySQLの完全なnegative SQL/role inventory。** positive presenceを、削除・再作成を含む権限不在の証明へ広げない。
4. **K11：実アプリのRuntimeBinding。** source host確認と実アプリのtoken/pool切替を分ける。K12の限定補償等も未着手。

これらが必要な条件の全体保護はUnknown/NeedsActionのままです。A〜Fの初期接続が一巡したことと、K10の全producer・全profile、実環境の防御成立は区別します。
