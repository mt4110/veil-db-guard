# GCP PostgreSQLのフィジビリティ試験

実施日: 2026-11-02。対象は新規専用GCP project内のCloud SQL PostgreSQLのみです。主要RDBMS全般、Veil CLIのGCP対応、AWS M3の完了を証明する試験ではありません。

後続の追加承認に基づき、この初回試験で残した直通原因と不許可IAM主体を[別の専用環境で追試](gcp-rejection-validation.md)しました。以下は初回の観測として保全し、追試の結果・権限反映遅延とは分けて読みます。

## 判断する問いと承認

「Cloud SQLの標準の接続・認証機構を使い、権限を絞ったDBユーザーが合成SQLを実行できるか。接続制限・失敗時の整合性・撤収を観測できるか」を確かめます。

合計50米ドル以内の上限選択後、専用GCP環境の作成・試験・撤収案に対する「これで、フィジビリティ、GCPで試してみて、出来なさそうだったらペンディングにするか？」という継続指定を受けて実施しました。初回は最大5米ドル/4時間とし、追加のcloud IAM role付与、service-account key発行、既存project変更は行っていません。権限・準備不足と方式の不成立を分けて判断します。

## 実際の構成

| 項目 | 実測・取得した構成 |
| --- | --- |
| DB | Cloud SQL PostgreSQL 16.15（API: POSTGRES_16_15） |
| 配置 | asia-northeast1、Enterprise、単一zone、db-custom-2-8192、SSD 20 GiB |
| 接続制限 | connectorEnforcement=REQUIRED、authorizedNetworks空 |
| 暗号化設定 | sslMode=ENCRYPTED_ONLY |
| DB設定 | cloudsql.iam_authentication=on、合成DB vdg_lab/専用schema vdg_fixture |
| Proxy | 公式配布Cloud SQL Auth Proxy 2.26.3、macOS ARM64、127.0.0.1の動的portのみで待受 |
| SQLクライアント | psql 17.7 |
| 管理 | 今回のinstanceのpostgresユーザーへメモリ上だけのランダムpasswordを設定し、bootstrap時だけ使用 |
| アプリDB権限 | IAM DB userに専用vdg_app_roleを割当。専用schemaのUSAGE/CREATEとDB CONNECT |
| backup/撤収 | 合成試験用として自動backup・final backupなし。試験後に専用instanceとprojectを撤収する計画 |

DB内のsuperuser、CREATEDB、CREATEROLE、REPLICATION、cloudsqlsuperuserのmembershipがすべてfalseであることを、アプリユーザー自身の接続から確認しました。クラウド管理には既存のログイン主体を使っており、本番用アプリIAMの最小権限を実証したという意味ではありません。

## 接続方式で判明したこと

既存のgcloudユーザー資格情報を使う`--gcloud-auth`と、Proxyの`--auto-iam-authn`は併用できませんでした。これは起動時にProxyが明示的に拒否しました。ADCの追加ログインや長期key発行へ変更せず、同じ既存主体の短期IAM DB login tokenを取得し、psqlへメモリ上の環境変数で供給する手動IAM認証へ切り替えました。token/passwordをコマンド引数や試験記録へ保存していません。

このため、自動IAM token更新・期限を越えた継続接続は今回の確認範囲外です。[IAM DB認証の公式説明](https://docs.cloud.google.com/sql/docs/postgres/iam-authentication)、[Proxy公式接続手順](https://docs.cloud.google.com/sql/docs/postgres/connect-auth-proxy)

Cloud SQL Auth Proxyのローカル区間は平文loopback、Google向け接続はProxyのTLS接続方式です。今回は暗号化設定と当該Proxyを通した接続成功を照合しましたが、独立したpacket captureや証明書異常の負例は実施していません。backendのSQLによるSSL情報だけで外側の暗号化を判定していません。

## 実機の結果

| 項目 | 結果 | 言えること・限界 |
| --- | --- | --- |
| IAM DBログイン | 成功 | 短期tokenを使い、権限を絞ったIAM DB userで接続できた |
| 不存在DBユーザー | 拒否 | 正例のある同じProxy経路でDB認証の負例を確認。別の有効なIAM主体の認可拒否とは区別 |
| CRUD/commit/rollback | 成功 | commitした更新値が残り、rollbackした行が存在しないことを照合 |
| SQLエラー後の整合性 | 成功 | transaction中のdivision by zeroでpsqlが終了し、別接続で未commit行が残っていないことを確認。切断に伴うrollbackの試験 |
| 再接続 | 成功 | Proxyを停止・再起動し、新規接続から既存のcommit値を確認して削除後の空状態を照合 |
| 取消し | 成功 | pg_stat_activityで対象queryのPgSleepを確認後、psqlへSIGINTを送り、serverのuser-request cancellationと別接続での未commit行消失を確認 |
| 直接接続 | 原因未確定 | 同じ主体の有効な短期IAM login tokenを用意した直接SQL接続とTCP試行がtimeout。バイパス成功は観測していないが、allowlist/connector enforcement/通信経路それぞれの効果は分離できていない |
| 有効だが不許可の別IAM主体 | 未実施 | 追加の主体・IAM権限設定を今回の範囲へ広げなかった |
| TLSの独立した負例 | 未実施 | 証明書不一致・期限切れ等は未実施 |

初期試行では、固定ローカルportが使用中だったため空きportへ変更しました。既存の待受プロセスには触れていません。また、stable gcloudのinstance作成にlabelsフラグがなく、API呼出し前に拒否されたため、そのフラグを外しました。専用projectのlabel・番号と作成記録による所有照合を維持しました。これらの準備上の修正を、Cloud SQL方式の不成立とは扱いません。

## 撤収と費用

2026-11-02 12:41 JSTに、次の状態まで照合しました。

- 削除前のbackup一覧は0件。自動backup/final backupを作らない試験構成でした。
- instance削除operationのDONEと、Cloud SQL instance一覧0件を確認しました。
- 専用projectの課金紐付けを解除し、billingEnabled=falseを確認しました。
- 専用projectの削除を要求し、lifecycleState=DELETE_REQUESTEDを確認しました。完全な物理消去が終わったという意味ではありません。
- Proxyプロセスは各試験終了時に停止し、ローカル証拠は保持しました。

project作成から撤収確認まで約15分、instance作成要求から削除確認までは約11.2分です。確認済みの東京のCPU・メモリ・SSD単価を、作成待ちも含む約0.18693時間へ掛けたDB/storageの概算は **約0.0348米ドル** でした。これは通信・ログ・税・割引等を含む実請求額ではありません。実請求額は未取得です。初回5ドル/4時間、全体50ドル以内という管理枠で実施しました。[料金の根拠と計算方法](multicloud-preparation.md#料金の確認と見積もりの境界)

## 判断と残る問い

**GCPで、選んだ標準接続方式と権限を絞ったDBユーザーによる基本SQL・整合性の成立を確認できました。** この結果から構想全体を保留にする技術的理由は得られていません。ただし、直通拒否原因と別の有効な不許可IAM主体は未確認で、完全な防御成立とは評価しません。

次の判断材料は、この未確認点の切り分けです。今回の経路に必要な製品側adapterはまだ実装していません。追加主体の作成やIAM role付与が必要な試験は、具体的なscopeを決めてから扱います。成立条件を揃えても必須の接続制御が成立しない場合は、方式変更または対象を限定した保留を判断します。保留時は原因・保持する成果・再開条件を記録します。

## 証拠とレビュー

生のidentity、project ID、endpoint、API応答、SQL結果、各試行の失敗記録は、git除外の`runs/gcp-feasibility-20261102-e82a5c/`へ保存しました。最初の2試行の記録はattempt-1/attempt-2/に保持しています。公開用のこの記録には完全なidentityやendpointを転記しません。

主担当がクラウド操作・実機試験・撤収を実施。検証担当サブエージェントが試験設計・結果の判定範囲・撤収記録を独立レビューし、重大な偽passは見つかりませんでした。製品コード変更、AWS/Cloudflare/Azureの資源操作、push・公開は行っていません。
