# 初期対象行列（T01）

K10更新: [source取得と新実行契約の対応範囲](core/k10-native-source-execution.md)を追加しました。GCP PG16.15/東京/GCE root host、AWS PG16.15・MySQL8.0.43/東京/EC2 root hostの初期接続を実装・ローカル検証します。native拒否・TLS区間・inventory・runtimeの不足はUnknownを維持します。以下の旧単位の手順・結果は履歴として保持します。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](core/k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存RDS PostgreSQL／専用RDS Proxy向けのコードとローカル検証を追加しました。[現在の対応・操作・効果待ちの境界](core/k07-aws.md)を参照します。実AWS操作やworkload sourceに束縛した直通拒否の確認は行っていません。

現在の導入executorは[K08の組合せ一覧](core/k08-mysql.md#現在の組合せ)を正とします。[K05](core/k05-native.md)のGCP PostgreSQL、K07のAWS PostgreSQLを維持してMySQLを追加しました。実環境の適用成功・Linux動作は未確認です。直通timeoutのみはWaitingEffectのままです。以下は履歴を含むAWS初期観測対象の表です。

環境固定の追加: Rust 1.98.1を`rust-toolchain.toml`で指定し、miseから同じ版を利用します。台帳用SQLiteは同梱3.54.1へ変更しました。[固定ビルド環境](build-environment.md)に現在の構成を記載します。以下T01時点の行列は履歴を保持し、Linux動作確認済みへは広げません。

[基幹設計](core/README.md)は配置先とDBを二軸に分け、K05〜K08で限定executorを実装・ローカル検証しました。以下T01時点の表は旧観測CLIの固定対象で、現在のnative executorの全組合せを表すものではありません。

確認日: 2026-11-02。この表は実装・ローカル検証の固定対象です。AWS上で動作確認済みという表示ではありません。既存の設計資料は保全し、対象の具体化をここへ記録します。

追加調査: 実機検証準備の承認後にSTS本人確認は成功しましたが、RDSの版/instance option読取APIはAccessDeniedでした。以下の表の「認証/API未実行」「今回は呼びません」は当初のローカル検証時点の記録です。最新の利用可能環境・費用と未解決点は[複数クラウド検証準備](multicloud-preparation.md)を参照します。実装対象自体は広げていません。

その後、新規GCP Cloud SQL PostgreSQL 16.15を標準ツールで部分検証し、専用環境の撤収状態まで確認しました。[GCP実機結果](gcp-feasibility.md)は手動の別実験であり、以下のVeil CLIの対応対象とは区別します。

追加承認後にGCP adapterを実装し、`gcp check/report`でCloud SQL PostgreSQL 16.15・asia-northeast1・同一projectのkeyless SA・Public IPv4/instance固有CAを検証しました。[対応範囲・CLI実機記録](gcp-cli.md)を参照します。以下の表はAWS向け旧観測CLIの初期対象として維持し、GCP設定は別schemaです。K08のMySQL native実装と、旧CLIの対応範囲を混同しません。

## 固定する対象

| 項目 | 初期対象 | 根拠・状態 |
| --- | --- | --- |
| 開発環境 | macOS ARM64 | ローカル`uname -m`でarm64確認。OSの配布互換性全体は未検証 |
| Rust/Cargo | 1.98.1 | ローカル`rustc --version`/`cargo --version`で確認。Rust toolchain変更は行っていない |
| AWS inventory backend | AWS CLI v2の固定read-onlyコマンド | 手元は2.36.50、arm64。確認したのは`aws --version`のみ。認証/API未実行 |
| engine | `postgres` / RDS PostgreSQL | Auroraや自己管理PostgreSQLとは区別 |
| engine version | `16.15` | 公開資料に基づく実装・サンドボックス候補。実リージョンでの作成可能性はT16 |
| region | `ap-northeast-1`（東京） | 対応表でPG16のProxy対応を確認。CLI設定で明示限定 |
| 認証 | `end_to_end_iam`のみ | 初期実装はStandardIamをUnsupportedTargetとして拒否。将来の標準IAM対応は別検証 |
| TLS | チェーン・ホスト名検証を伴うTLS、通常のPostgreSQL SSL negotiation | direct SSL negotiationは対象外 |
| Proxy | `POSTGRESQL`、5432、対象DB一つ、`target.proxy_name`必須 | ARNのresource IDからProxy名は導けないため名前を明示。API構成と接続観測を分離 |
| 試験元 | `sources[]`のid/kindとpath.source_id | kindはvpc_host/vpn/tunnel/local_lab。descriptionは入力専用で保存・表示・hashに含めない |
| 実証runner | Linux候補 | 具体的OS/arch/ホストはT16で固定。今回の動作確認対象ではない |
| 今回の接続先 | ローカルfixture/loopbackのみ | AWS認証、AWS API、実RDS/Proxy、VPN/SSM操作は今回実行しない |

RDSのrelease calendarは16.15のRDS公開日を2026-08-25、minorの標準サポート期限を2027年9月と記載しています。Proxy対応表は東京のPG16をall available versions、IAM対応表はPG16を全リージョンのall available versionsとしています。これは対象リージョンの現在のorderableな構成をAPI確認した結果ではありません。[RDS release calendar](https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html)、[Proxy対応表](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.RDSProxy.html)、[IAM対応表](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RDS_Fea_Regions_DB-eng.Feature.IamDatabaseAuthentication.html)。

E2E IAMの公式発表ではMySQL/PostgreSQLとProxy対応リージョンが対象です。実構成では`DefaultAuthScheme=IAM_AUTH`に加えDB側IAMとユーザー設定が必要です。[E2E IAM発表](https://aws.amazon.com/about-aws/whats-new/2025/09/amazon-rds-proxy-end-to-end-iam-authentication/)、[設定手順](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-iam-migration.html)。

## 受け入れる版と非対象

初期の接続試験対象版は16.15へ固定します。別minorのsnapshotを無条件に同等と評価せず、対象設定との不一致として扱います。将来のsecurity update等で固定版を変更する場合は、この表・設定例・fixture・試験条件を合わせて更新します。現在の実装進捗とローカル検証結果は別の検証記録に置きます。

標準IAM、PostgreSQL 17/18、MySQL/MariaDB/SQL Server、Aurora、Windows配布、Linuxでの実行、実AWS防御、既存DBへの導入、性能上限、デコイ、継続運用は今回のローカル検証では未確認です。別エンジン・版・リージョンを入力して、対応済みに見せる推測はしません。

## T16まで残す条件

| 未決事項 | AWS着手前の確認 |
| --- | --- |
| account ID、DB/Proxy ARN、endpoint | 明示対象と実行主体を照合。未設定のままAWSを探索しない |
| 16.15のリージョン内availability | 承認後にDescribeDBEngineVersionsと作成可能なinstance class等を確認。公開表だけで保証しない |
| instance class、AZ/subnet、費用 | IAMのメモリ負担、Proxy対応、実行時間・費用上限を固定 |
| 実行元・管理例外 | アプリと同じ経路の試験元、VPN/SSM利用の影響、復旧経路を固定 |
| 最小IAM/DB権限 | inventoryと接続を分離し、権限の許可/拒否を確認 |
| TLS/driver/プール | 実証に用いる版、信頼ストア、再接続・取消し・pinningの試験条件を固定 |
| 構築・片付け | CFN、SQL bootstrap、保持/削除対象、復旧と停止条件をレビュー |

`DescribeDBEngineVersions`はengine/version/statusを条件にでき、既定では利用可能な版だけを返します。T16で実行する候補であり、今回は呼びません。[公式API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBEngineVersions.html)。

synthetic account ID `000000000000`は例示用で、実CLIを起動するinspectでは認証処理前に拒否します。fixture用runnerとローカル検証はsynthetic IDを受け入れ、AWS実証へ昇格させません。

実行直前にも対応表・release calendar・料金を確認し、サンドボックス結果を既存本番DBの検証へ昇格させません。TLS・IAM・ネットワーク・証拠の詳しい限界は[AWS調査](aws-findings.md)を参照します。
