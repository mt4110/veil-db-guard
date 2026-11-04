# AWS技術調査

確認日: 2026-11-02。基本設計・詳細設計へ反映するため、AWS公式のUser Guide、API Reference、CloudFormation Template Reference、Service Authorization Reference、Rust公式例を実際に開いて確認した記録です。AWSへの認証・接続、リソース作成、設定変更、課金操作は実施していません。仕様上の対応と、実環境での成立確認を区別します。

## 1. 調査の結論と適用条件

**設計上の含意:** 初期の主候補はRDS PostgreSQL + RDS Proxy + end-to-end IAM + TLS + アプリからDBへの直接経路制限です。CLIは通信経路に常駐せず、計画・構成読取・許可した接続試験・レポートを担当します。標準IAMも別モードとして保持し、自動降格はしません。

**仕様の事実:** RDS ProxyとIAM DB認証には、それぞれエンジン・バージョン・リージョンの対応条件があります。RDS ProxyではVPC/AZ等の制約もあります。対応表の「利用可能」は、対象アプリの互換性やサンドボックスでの成功を保証しません。[Proxy対応表](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.RDSProxy.html)、[IAM DB認証対応表](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.IamDatabaseAuthentication.html)。

**未確認:** 採用するリージョン、PostgreSQLの具体的バージョン、インスタンス種別、実行元、単価と費用上限は未確定です。T01/T16で固定し、M3の実行直前にも上記対応表を再確認します。Aurora、MySQL等への結果の一般化はしません。

## 2. 標準IAMとend-to-end IAM

| 項目 | 標準IAM | end-to-end IAM |
| --- | --- | --- |
| クライアント→Proxy | IAM | IAM |
| Proxy→DB | Secrets Managerに登録したDB認証情報 | IAM DB認証 |
| DB認証用Secret | 必要 | 不要 |
| Proxy設定の重要項目 | Secret別の`Auth`と`IAMAuth` | `DefaultAuthScheme=IAM_AUTH` |
| DBユーザー | パスワード認証を使う構成 | PostgreSQLでは`rds_iam`が必要 |

**仕様の事実:** E2E IAMには、Proxyロールの対象DBユーザーへの`rds-db:connect`、DB側IAM有効化、DBユーザーの設定が必要です。PostgreSQLの`rds_iam`は直接・間接の付与が可能で、ユーザー名の大小文字一致も必要です。[接続方式](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-connecting.html)、[E2E IAMへの移行](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-iam-migration.html)、[DBユーザー設定](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.DBAccounts.html)。

**設計上の含意:** モード、IAM principal、Proxy/DB resource ID、DBユーザー、DB権限を対応づけます。IAM認証が成功しても、DB内権限が最小である証拠にはなりません。管理ユーザーとアプリユーザーを分け、`CONNECT`と必要なSQL権限を別に設計します。既存ユーザーへの`rds_iam`付与は、認証方式を変える変更として扱います。

**上流の記述不一致:** 接続方式ページはE2E IAMを説明する一方、後段Tipには「Proxyは常にSecrets ManagerのパスワードでDBへ接続する」という旧方式を一般化した文があります。E2E専用手順、DBProxy API、CloudFormationはE2E IAM対応で一致しています。標準IAM向け注意をE2Eに無条件適用しません。[接続方式](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-connecting.html)、[DBProxy API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxy.html)。

**未確認:** 対象環境でのIAMポリシー、SCP、permissions boundary、セッションポリシー等を含む実効権限、DBロール、接続成功・拒否は未検証です。構成の整合と実接続を別々に確認します。

## 3. CloudFormationとSQL bootstrap

**仕様の事実:** `AWS::RDS::DBProxy`は`DefaultAuthScheme: IAM_AUTH | NONE`に対応し、`IAM_AUTH`はE2E IAMを意味します。`Auth`は省略可能で、指定する場合は最低1件です。`RoleArn`は必須、`VpcSubnetIds`は最低2件です。`DefaultAuthScheme`更新は仕様上`No interruption`です。[DBProxy Template Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbproxy.html)、[AuthFormat](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbproxy-authformat.html)。

**設計上の含意:** E2E専用サンドボックスでは`DefaultAuthScheme=IAM_AUTH`と`RequireTLS=true`を明示し、Secret用`Auth`は省略する案です。Proxy用IAMロール、SG、subnet、target group、DBのIAM有効化等も必要です。CloudFormationのDBInstance指定だけではアプリDBユーザーの作成・`GRANT rds_iam`・DB権限付与は完了しないため、SQL bootstrapを独立した承認済み作業にします。自動applyやSQLを実行するカスタムリソースは初期範囲に追加しません。

CloudFormation上の`No interruption`を、アプリ切替・ユーザー変更・接続中トランザクションを含む無停止移行の実証として扱いません。既存DBは初期テンプレートへ取り込まず、追加Proxy等の計画と既存環境向け差分・復旧手順を生成します。公式DBInstance仕様にはインポート時の構成差分適用や、更新時の置換・削除への注意があります。[DBInstance Template Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html)。

**未確認:** 具体テンプレートの構文検証、対象リージョンでの作成、SQL bootstrapの適用、スタック失敗・復旧は未実施です。

## 4. TLS区間、CA、証拠の限界

| 区間 | 仕様の事実 | 設計上の含意 |
| --- | --- | --- |
| クライアント→Proxy | API/CloudFormationの`RequireTLS`はProxyへのTLS接続を要求する設定。Proxy証明書はACM管理 | 設定値と、クライアントでのチェーン・ホスト名検証を別証拠にする |
| Proxy→DB | 別のTLS接続。DB側にもSSL強制設定がある | `RequireTLS`単独で両区間を観測済みとしない |
| クライアント→DB直接 | RDS CAを用いた検証方法がある | 管理・baseline接続のCAをProxyのACM証明書と混同しない |

根拠: [DBProxy API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxy.html)、[ProxyのTLSと証明書](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html)、[RDS PostgreSQL SSL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)。

**仕様の事実:** RDS PostgreSQLの`rds.force_ssl`既定値は15以降で1、14以前で0です。RDS PostgreSQL 16以降はTLS 1.3対応です。`sslmode=require`と、証明書チェーン・ホスト名検証を行う設定は同義ではありません。[RDS PostgreSQL SSL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)。

**上流の記述不一致:** Proxy概念ページには`Require Transport Layer Security`をProxy→DBのTLS強制として説明する箇所もあります。API/CloudFormationの「Proxyへの接続」という定義を記録し、DB側設定・適用状態・接続観測を分離する保守的設計を採ります。

**未確認:** 実際の証明書・信頼ストア、TLSバージョン、DB実行時設定、Proxy→DB区間の取得可能な証拠は未確認です。Proxy経由のSSL関連SQLだけでクライアント→ProxyのTLSを立証しません。両区間を「end-to-endで一つのTLSセッション」とも表現しません。

## 5. ローカル実行元、SG、管理経路

**仕様の事実:** ProxyはDBと同一VPCが必要で、公開アクセス可能にはできません。ローカルPCは到達経路を別途用意しないと接続できません。SGはdenyではなくallowルールで、複数SGの許可は合算されます。SG参照は関連インターフェースの通信許可であり、DBユーザーやアプリプロセスの認証ではありません。[Proxy制約](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)、[SGルール](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)。

**設計上の含意:** ローカルファーストは計画・解析・証拠保管を利用者側で行う意味です。接続試験はVPC内ホストや既存VPN等、承認済みの到達経路で実施します。SSM等の転送を使う場合はトンネル終端側の接続元条件を検証するため、アプリ実行元の代替証拠としません。ホスト名検証をlocalhost接続のために無効化せず、driverが接続先と検証対象名を適切に扱えるか確認します。

経路案は`app-sg → proxy-sg → db-sg`です。DBに付く全SG、IPv4/IPv6、追加endpoint、バッチ・管理・移行等の例外を評価します。管理経路は理由と復旧手順を明示し、アプリ経路と分けます。SG読取だけでルート、NACL、VPN、他VPC等を含む到達性全体を保証しません。

**未確認:** 接続元の客観的照合、既存管理経路、直接接続拒否は未実施です。単なるtimeoutは拒否原因の確証にせずunknownとし、接続が成立しなかったという観測を残します。

## 6. トークン、プール、再接続

**仕様の事実:** IAMトークンは15分有効で、確立後のセッション寿命を決めません。一時AWS資格情報も接続時点で有効な必要があります。Proxyクライアント接続の最大寿命は24時間で変更不可、アイドル期限既定は30分、借用timeout既定は120秒です。[IAM DB認証](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)、[接続時のトークン期限](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html)、[Proxy接続設定](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-connections.html)。

**設計上の含意:** 新規接続・再接続では有効な資格情報から署名し、トークンを固定パスワードとして保存しません。プール寿命とアイドル期限はProxyの制約より短くする条件を確認します。IAM権限削除・トークン期限を確立済みセッションの即時終了と扱いません。期限切れ負例は新規接続として確認します。切断後のCOMMIT結果が不明なら書込を自動再送せず、後条件を照合します。

**未確認:** driverのcredential更新、プール再接続、失効反映、failover・中断時の挙動は実環境未検証です。

## 7. PostgreSQL driver・protocol・pinning

**仕様の事実:** ProxyのPostgreSQL接続にはprotocol 3.0、direct SSL negotiation非対応、CancelRequest非対応等の制約があります。streaming replication非対応、`postgres` DB必須、`lastval()`の注意もあります。アプリ互換性の条件として扱います。[Proxy PostgreSQL制約](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.html)。

`SET`、SQLの`PREPARE`等、一時オブジェクト、カーソル、`LISTEN`、セッション単位アドバイザリロック等はpinning条件です。`DISCARD ALL`をpool resetに使う構成も注意が必要です。トランザクション単位アドバイザリロックには例外があります。[PostgreSQL pinning](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-pinning.html)。

**設計上の含意:** driverを固定し、通常SSL negotiation、prepared statementの利用形態、pool reset、サーバー側statement_timeout、切断後の状態を検証します。クライアント側timeoutや取消しをDB側クエリ終了の保証にしません。Proxyがあるだけで長いトランザクションやpinningが解消すると主張せず、互換性とプール効果を別評価にします。

**未確認:** 採用driver/版、SQL実行・取消し挙動、対象ワークロードのpinning率は未確定です。

## 8. AWS読取、Rust、最小権限

| 読取候補 | 取得する選択情報 | 読取だけでは判定しないこと |
| --- | --- | --- |
| DescribeDBProxies | 認証モード、RequireTLS、ARN/endpoint、RoleArn、SG/subnet、status | 実効IAM認可、クライアント証明書検証、実接続成功 |
| DescribeDBProxyTargets/TargetGroups | 対象、port、health、pool設定 | 全ユーザー・全経路の成功/拒否、実pinning率 |
| DescribeDBInstances/Parameters | engine/version、IAM/public設定、SG、parameter group・適用状態、証明書情報 | DB内権限、設定の実行時値、直接経路の完全遮断 |
| DescribeSecurityGroups | 全関連SGの許可、IPv4/IPv6、SG参照、port | ネットワーク全体の到達性証明 |

根拠: [DBProxy](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxy.html)、[DBProxyTarget](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBProxyTarget.html)、[TargetHealth](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_TargetHealth.html)、[DBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html)、[SG読取](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html)。`TargetHealth=AVAILABLE`は全ユーザーの認可が正常という保証ではありません。

**仕様の事実:** AWS公式Rust例には`aws_config`、資格情報provider、`aws_sigv4`によるRDS IAMトークン生成があります。トークン生成をリモートのRDS APIとして設計する必要はありません。[Rust公式RDS例](https://docs.aws.amazon.com/code-library/latest/ug/rust_1_rds_code_examples.html)。

**設計上の含意:** Rust SDKの具体的な版と型はT02で固定し、上記APIに対応する読取を実装します。`latest`の細かな型名や返却値が固定されているとは扱いません。SQL接続driverは別依存です。SDKレスポンス全体、初期化SQL、説明文、タグ、health description等をそのまま証拠保存しません。`GetSecretValue`、IAM変更、DB変更の権限はinspectに不要です。

### IAM resource scopeの確認結果

**仕様の事実:** Service Authorization Referenceでは、以下のresource型が示されています。`*`付き型は同表でrequired resource typeを表します。APIのfilterがIAM権限境界を作るわけではありません。

| IAM action | 表にあるresource型 |
| --- | --- |
| rds:DescribeDBInstances | db |
| rds:DescribeDBParameters | pg* |
| rds:DescribeDBProxies | proxy |
| rds:DescribeDBProxyTargetGroups | proxy* |
| rds:DescribeDBProxyTargets | proxy*、target-group* |
| ec2:DescribeSecurityGroups | resource型なし。Resource `*`が必要。ec2:Region条件あり |

根拠: [RDS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html)、[EC2 Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)。

**設計上の含意:** 必要なactionを個別列挙し、対応するDB/Proxy/target-group/parameter-group ARNへ絞ります。全Describeを一律Resource `*`にしません。Resource制約できないSG読取にはリージョン条件、CLIの明示ID/filter、応答後のaccount/region/対象照合を併用し、CLI上の限定とIAMによる強制を区別します。DB接続用`rds-db:connect`と構成読取を別権限セットにします。

**未確認:** 完成した最小権限policyと実アカウントでの許可/拒否は未検証です。対象IDを指定した取得・ページング・部分失敗・アクセス拒否をT06で確認し、Deniedを構成不適合や空結果へ変換しません。

## 9. 費用と実証条件

**仕様の事実:** provisioned RDS向けProxyはDB容量のvCPU時間に基づく料金で、課金状態変更後の最低10分料金があります。既定Proxy endpoint自体の追加料金はありませんが、追加endpointにはPrivateLink料金が発生します。[Proxy料金](https://aws.amazon.com/rds/proxy/pricing/)。

**設計上の含意:** Proxy、RDS本体・storage、試験実行元、VPN/NAT等の到達経路、追加endpoint、ログを分けて見積もります。単価、通貨、税、保持時間、片付け後に残るsnapshot等も実行計画で確認します。ローカルモックやテンプレート検証は、AWS IAM拒否・実通信の証拠にはなりません。

**未確認:** 金額、予算上限、課金資源、保持・削除対象、終了条件は未確定です。M3着手前に具体化して承認対象とし、実行直前に対応表と価格を再確認します。

実証の最低条件案:

1. 宣言したアプリ実行元・principal・DBユーザーで、チェーン/ホスト名検証付きProxy接続が成功する。
2. 到達性を確認した同じ経路で、connect権限を持たないprincipalが認証拒否される。
3. 非TLS接続がProxyで拒否される。
4. アプリ実行元からDBへの直接接続が、現在の構成と対象に対応する証拠で拒否される。原因不明timeoutはunknown。
5. 管理例外を別経路として確認し、アプリ経路の結果へ混ぜない。
6. 期限切れトークンの新規接続拒否、有効トークンでの再接続、代表トランザクションとpool挙動を確認する。

結果には対象・時刻・実行元・経路・構成hash・観測・判定を残します。「IAM設定あり＝防御成立」「Proxyあり＝直接経路なし」「TLSあり＝相手検証済み」「15分＝セッション失効」「正規経路集約＝侵害済み正規アプリやSQL injectionも防御」は主張しません。隔離デコイと継続確認は将来構想として保持し、今回の未実施項目を実証済みに扱いません。
