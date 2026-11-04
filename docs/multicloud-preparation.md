# 複数クラウド・主要RDBMSの実機検証準備

確認日: 2026-11-02。調査・検証準備時点の記録です。その後、合計上限50米ドルとGCP実機試験への継続指定を受け、専用環境の作成・試験・撤収を実施しました。後続の実測・最終状態は[GCPフィジビリティ結果](gcp-feasibility.md)を参照します。下記のアカウント調査は実機試験開始前の観測です。

## 目的と今回の承認

製品構想は主要RDBMSの接続経路・認証・防御設定を扱うことです。DBエンジンと配置先クラウドを別の軸にします。現在の実装はAWS RDS PostgreSQL 16.15/東京/E2E IAMに限定され、MySQL・Cloud SQL・D1対応を実装した状態ではありません。

ユーザーはCloudflare・GCP・AWSの利用可能環境と費用、Azureの日本・世界の利用状況の調査から実機検証準備まで、Sol/highで進めることを選択しました。課金してよいという意思に続き、最初の実機検証のAWS・GCP・Cloudflare合計費用上限として **50米ドル以内** を明示選択しました。資源作成・権限変更・撤収は未実行です。費用上限の選択と、具体的な作成・撤収範囲の承認は分けて記録します。

既存AWS向けM3の完了条件は維持します。先行する他クラウドの手動試験は、プラットフォームの成立条件を確かめる部分実験であり、現CLIの対応認定やM3完了にはしません。

## 手元のアカウントと権限の観測

認証情報ファイルは読み出さず、既存CLIで本人確認・一覧等を取得しました。秘密、完全なaccount ID/メールアドレス、既存DB名・内容はこの文書へ保存しません。Wranglerが生成したローカルaccount cacheのディレクトリ`.wrangler/`はgit除外へ追加し、削除せず保持しています。

| 環境 | 確認済み | 未確認・制約 |
| --- | --- | --- |
| AWS | default profileのSTS本人確認成功。IAM userによる認証 | `rds:DescribeDBEngineVersions`、`rds:DescribeOrderableDBInstanceOptions`、`pricing:GetProducts`がAccessDenied。作成・接続・IAM変更権限は未確認 |
| GCP | gcloud認証、ACTIVEなプロジェクト4件、openな課金アカウント1件を確認 | 現在のproject未選択。専用project作成・課金紐付け・Cloud SQL作成権限、quotaは未確認 |
| Cloudflare | Wrangler本人確認成功、account 1件、D1一覧取得成功（既存DB 2件） | D1新規作成、Hyperdrive/Workers権限、現在のプランと残quotaは未確認 |
| Azure | 公開資料による利用状況調査 | az未導入。アカウント、subscription、権限の確認・作成は未実施 |

認証成功は作成可能の証明ではありません。AWSの権限不足に対して自分で権限を追加せず、必要なsandbox roleが用意できるまでAWS実行を待ちます。GCPは既存の業務用・別目的のprojectを流用せず、専用lab project案にします。

## DBとサービスの違い

| 対象 | 役割 | この検証との関係 |
| --- | --- | --- |
| Cloudflare D1 | SQLiteのSQL semanticsを持つマネージドserverless DB。Workers binding/HTTP APIから利用 | API/binding権限とSQL処理を別枠で検証。PostgreSQL/MySQLのwire protocol・IAM・TLS・直通防止の実証へ代用しない |
| Cloudflare Hyperdrive | 外部にあるPostgreSQL/MySQL等への接続をWorkersからpoolするサービス | DB本体のホスティングではない。origin DBの料金・認証・TLS・到達性を別に確保する |
| GCP Cloud SQL | PostgreSQL/MySQL/SQL ServerのマネージドDB | PostgreSQLを先に、次いでMySQLを検証する候補。現CLIへのadapterは未実装 |
| AWS RDS + RDS Proxy | 今回の実装の初期対象 | 権限とrunner配布の準備後、既存のAWS計画へ接続する |

Hyperdrive公式対応表はPostgreSQL 9〜18、MySQL 5.7〜8.x、MariaDB互換を挙げています。SQL Serverは対象外です。ベンダー対応表は、このツールでその全版を検証済みという意味ではありません。[D1](https://developers.cloudflare.com/d1/)、[Hyperdrive](https://developers.cloudflare.com/hyperdrive/)、[対応表](https://developers.cloudflare.com/hyperdrive/reference/supported-databases-and-features/)

## 料金の確認と見積もりの境界

通貨はUSD。税・為替・割引・無料クレジットを含めません。残quotaや契約単価は未確認です。試験開始時に再取得します。

### GCP: 東京、Enterprise汎用、単一zone

公式料金表の地域を **Tokyo (asia-northeast1)** に切り替えて確認しました。既定のIowa単価を東京へ転用していません。

- CPU: 0.0537/vCPU-hour、メモリ: 0.0091/GiB-hour。
- SSD: 0.00030274/GiB-hour、使用済みbackup: 0.000142466/GiB-hour。
- 2 vCPU/8 GiB/SSD 20 GiBを4時間: `(2×0.0537 + 8×0.0091 + 20×0.00030274)×4 = 0.7450192`。
- internet egressは0.19/GiB。試験データは合成のみ、結果転送100 MiB以内を計画する。

DB・ストレージ分は約0.75ドルです。backup・ログ・通信・構築待ち時間等を含む最初のPG試験の管理枠として **5ドル/最大4時間** を提案します。MySQLを追加する場合は同じ資源を流用できるとは考えず、別instanceの費用と時間を加算します。停止後もstorage等が残るため、停止だけで撤収完了としません。[Cloud SQL料金](https://cloud.google.com/sql/pricing)

### AWS: 東京、既存テンプレート候補

認証付きPricing APIは拒否されましたが、認証不要の公式regional offer catalogで次を取得しました（catalog publicationDate: 2026-10-29）。通常のSingle-AZインスタンスのSKUを確認し、未使用capacity reservation単価とは区別します。

- RDS PostgreSQL db.t4g.medium: 0.101/instance-hour。
- RDS PostgreSQL向けProxy: 0.018/vCPU-hour。2 vCPUなら0.036/hour。
- この2項目の4時間小計: `(0.101 + 2×0.018)×4 = 0.548`。

**0.548ドルは総額ではありません。** 生成テンプレートはEC2 runner 3台、20 GiB gp3、3種のInterface endpointを2 AZずつ（6 endpoint-AZ）、Secrets Manager、EBS、ログ等を伴います。各単価を含む総額、PG 16.15のorderability、AMIとartifact配布を確定するまでAWS構築へ進めません。Proxy追加endpointは別料金となります。[公式東京catalog](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/current/ap-northeast-1/index.json)、[Proxy料金](https://aws.amazon.com/rds/proxy/pricing/)

既存テンプレートのDBは`DeletionPolicy: Snapshot`、backup保持1日です。stack削除後のsnapshot保管料も見積もりと撤収承認へ含める必要があります。

### Cloudflare

D1 Free枠は読み取り500万行/日、書き込み10万行/日、保存合計5 GBです。専用の小さい合成DBを使い、利用中のプランと残quota内であれば増分0ドルを見込みます。既存使用分との合計と、必要ならWorkers料金を別途確認します。自動でpaidプランへ変更しません。

HyperdriveはWorkers Free/Paidに含まれ、Freeは10万query/日です。origin DBの料金は含まれません。[D1料金](https://developers.cloudflare.com/d1/platform/pricing/)、[Hyperdrive料金](https://developers.cloudflare.com/hyperdrive/platform/pricing/)

ユーザーが選択した合計上限は **50米ドル以内** です。初回GCP PostgreSQLの管理枠は、その内数として5ドル/最大4時間の提案を維持します。50ドルを使い切る計画にはしません。cloud budget通知には遅延があり、請求額を即時に強制停止する機構ではありません。作成時からの経過時間と資源台数に基づく見積もりを追跡し、予定を超える場合は新規作成を止め、承認済み撤収を行います。初回は並列に複数cloudを立ち上げません。

## 最初の実験の具体案: GCP PostgreSQL

AWSの権限待ちを避けて、まずGCPの接続方式を確かめる案です。製品全体の構想をGCPへ限定する決定ではありません。

| 項目 | 提案 |
| --- | --- |
| project | 新規専用`vdg-lab-20261102-01`を候補とし、未使用であることを確認する。名前が既に使用済みなら新規専用のsuffixに変更し記録する。既存projectは流用しない |
| DB | `vdg-pg-lab`、Cloud SQL PostgreSQL 16系の利用可能な保守版を確認して固定 |
| 構成 | asia-northeast1、Enterprise汎用2 vCPU/8 GiB、SSD 20 GiB、単一zone、HA/replicaなし |
| 経路 | Cloud SQL Auth ProxyをmacOSのloopback/Unix socketへ限定。connectorEnforcement=REQUIRED。public IP方式の場合authorized networksは空で、0.0.0.0/0を追加しない |
| 身元 | Cloud IAM接続権限とDBログイン権限を区別。IAM DB認証を検討し、長期service-account JSON keyを発行しない。権限設定案を確定してから適用 |
| データ | 専用DB`vdg_lab`/専用user、合成値のみ。既存DBを読み込まない |
| 時間・費用 | 最初の作成要求から最大4時間、PG試験の管理枠5ドル（合計上限への内数として提案） |
| 保存 | 実ID/identityを含む証拠はgit除外の`runs/`へ。公開用文書には秘密や完全なidentityを転記しない |

Cloud SQL Auth ProxyはGoogle側へのTLS/接続認可を担当しますが、アプリ→ローカルProxyの区間は暗号化されません。loopback/Unix socketとローカル利用者の境界を明示します。connector enforcementは、RDSのSGによるネットワーク隔離と同じ仕組みではありません。[公式接続手順・connector enforcement](https://docs.cloud.google.com/sql/docs/postgres/connect-auth-proxy)

実行前に必要な操作権限（専用projectの作成、課金紐付け、Service Usage、専用project内のCloud SQL管理・接続）とquotaを確認します。最初の実行承認案は既存のログイン主体の権限で行える範囲とし、クラウドIAMロールの追加付与、service-account key発行、AWS側への権限追加を含めません。追加権限が必要なら、その操作・主体・専用project内のscopeを具体化して確認します。現在のユーザー権限だけで可能かは未確認です。

### 観測するもの

1. instance設定と対象identityを保存し、許可主体のProxy経由接続・DBログイン・合成CRUD・rollbackを確認する。
2. 不許可主体の接続拒否と、許可主体の正例を対にする。認証失敗と通信障害を混同しない。
3. authorized networks空とconnector enforcement有効の設定を確認し、直接接続の結果を記録する。TCP到達だけをSQL認可成功と扱わない。
4. Proxy→Cloud SQLのTLS検証設定とサーバー側観測を照合する。RDS Proxy→DB TLSの実証として扱わない。
5. 接続取消し・再接続・合成データの後条件を記録する。root原因が確定しなければUnknownにする。
6. 撤収後のinstance/backup/IP等の残資源を照合し、証拠を保持する。

この試験はvendor CLI等を用いる部分実験です。Veil CLIの設定検証を無効化してGCP接続を通すことはしません。実験から必要なengine/provider adapter設計を具体化します。障害注入・性能比較・長時間credential更新は初回の必須項目へ追加せず、元のAWS M3の未完了項目として残します。

### 撤収の承認対象

専用labで今回作成したinstance、合成DB/user、backup/snapshot、専用IAM設定等のみを対象にします。DB削除は合成データを失わせ、backupも削除するなら復元できません。検証証拠はローカルに残します。既存project、既存D1、他用途のIAM・ネットワークは変更/削除しません。

資源作成と同時に、この限定された不可逆な撤収も一括で明示承認の対象にします。今回の承認案は、新規lab project自体も試験後に削除対象とします。これはユーザーの協働指示第7節の「削除は、具体的な対象・目的・影響・復旧可否を示し、明示承認を待つ」に従います。承認後は同じ撤収を工程ごとに再確認しません。作成に失敗して部分資源が残った場合も所有を照合し、承認範囲内で撤収します。

## 後続の順序

1. **GCP PostgreSQL**: 上記の狭い部分実験。AWS権限が先に用意できれば既存AWS実装を優先する選択もある。
2. **AWS PostgreSQL**: 対象限定roleと読取権限、料金全項目、Linux runnerへの成果物搬入を解決して既存T16〜T20へ進む。テンプレートはCLI/psql等を自動導入しないため、承認済みAMIまたはoffline artifactの配布計画が必要。
3. **MySQL**: まず一方のcloudで別engineとして検証し、認証・SQL・transaction・取消し等の差を洗い出す。driver追加/対応版は別途設計する。
4. **Cloudflare D1**: 新規の小さい合成D1でAPI/binding認可・SQL処理を確かめる。現D1には触れない。公開Workersを必要条件にしない。
5. **Hyperdrive**: origin PostgreSQL/MySQLと、Workers実行経路を別途定義する。private originにはTunnel/AccessかWorkers VPC（Beta）の制約を確認。公開DBポート、Access token、Workers公開、ドメイン変更を無断で追加しない。[private DB接続](https://developers.cloudflare.com/hyperdrive/configuration/connect-to-private-database/)
6. **Azure**: 下記の理由から対応候補へ含める。今回subscription作成や課金はしない。

MariaDB/SQL Server/Oracle/SQLite等もengine別の候補として維持します。「主要RDBMSすべてに対応済み」とは表現せず、実装・検証済みの組合せを行列へ追加します。

## Azureの優先度判断

世界の2026年Q3クラウドインフラ売上シェアはAWS 26%、Microsoft 19%、Google 16%です。IaaS/PaaS/hosted private cloudを含む売上推計であり、人数やDB利用率ではありません。[Synergy Research Group、2026-10-29発表](https://www.srgresearch.com/articles/cloud-market-growth-rate-surges-to-well-over-50-per-year-q3-revenues-reach-168-billion)

Stack Overflow 2026の任意回答・複数選択の開発者調査では、cloud platform設問の回答者10,889人中Azure利用は25.1%です。世界人口・全企業を代表する統計や、Azure DBの利用率ではありません。[Stack Overflow 2026 cloud platforms](https://survey.stackoverflow.co/2026/technology/data/cloud-plat)

日本について今回確認できた一次調査は、ＭＭ総研の**2022年6月調査**です。国内のPaaS利用企業でAzure 48.2%、IaaS利用者で44.0%という値です。国内法人担当者へのWeb調査で、2026年の現在率や日本人全体の割合へ読み替えません。2026年の別調査のAzure「認知率」は実利用率と異なるため採用していません。[ＭＭ総研、2022-08-24発表](https://www.m2ri.jp/release/detail.html?id=549)

判断として、Azureを対応構想から除外する根拠はありません。世界で大きな基盤であり、日本でも法人利用の実績が確認できます。既存コード・保有アカウントを使う初回試験の後に、Azure PostgreSQL/MySQLのID・接続経路を検証する優先候補とします。最新の国内利用率とAzure DB単独の採用割合は未確認です。

## 次の実行前に残る点

- 合計費用上限50ドル以内は選択済み。その後の継続指定を受け、初回GCP先行案の専用project/課金紐付け/API有効化/Cloud SQL作成・合成DB/user設定・試験・限定撤収を実施した。詳細は実機結果を参照する。
- GCPの初回に必要な作成権限と実際の版・構成は確認できた。続く追加承認で、[別IAM主体の拒否・直通原因の分離を追試](gcp-rejection-validation.md)し、さらに[GCP CLI adapter](gcp-cli.md)を実装・native実機確認して撤収した。権限削除の即時反映を保証できないことを観測しており、自動token更新・TLS証明書負例・構築適用等は今後に残る。
- AWSはRDS読取権限不足の解消が必要。総額・runner搬入・残snapshotを確定するまでT16全体を完了にしない。
- CLIの他cloud/engine対応は未実装。現在の製品対応表を試験案だけで広げない。

担当: 主担当が公開一次資料の照合とCLI読取を実施し、既存の検証担当サブエージェントが費用の境界・承認範囲・対応表現・元のM3条件との整合を独立レビューしました。重大な修正指摘はありませんでした。文書6ファイルの空白とローカル参照を検査し、不備はありませんでした。コード・ビルド・既存ローカル試験の再実行はしていません。
