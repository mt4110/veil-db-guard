# GCP接続状態の確認CLI

状態: **CLI実装・ローカル検証・CLI経由の実機確認と専用環境の撤収を完了**。`gcp check` / `gcp report`を製品CLIへ組み込みました。対象はCloud SQL PostgreSQL 16.15/東京、同一projectのkeyless SA、CLIを実行した環境からのIPv4接続です。

## 製品の目的と今回の範囲

製品の目的は、既存の主要DBを大きく作り替えず、正規アプリの接続を通し、不正な接続や許可していない迂回経路を防ぐ導入・運用を支援することです。接続確認CLIは、そのために現在の構成と実際の接続状態を結び付け、運用者が不足と次の対応を判断できるようにする一段です。

今回の範囲はCloud SQL for PostgreSQLの構成読取、明示した接続元・主体からの接続確認、証拠保存とローカル評価です。構成を自動適用する機能、既存アプリへの導入完了、全接続元に迂回経路が存在しないことの証明、継続監視の完成は含みません。以前の[実機追試](gcp-rejection-validation.md)は設計の根拠として参照し、今回のCLIで取得した証拠とは分けます。

AWS向けの既存コマンドと設定を維持し、GCPには別の厳密な設定型`GcpConfig`を使います。未知のキー・重複・別projectのSA・未対応版・不正な上限を拒否します。例は[examples/gcp.yaml](../examples/gcp.yaml)、正本は[src/gcp/model.rs](../src/gcp/model.rs)と[config.rs](../src/gcp/config.rs)です。公開例の架空projectは、live CLIで認証前に拒否します。

## 操作と結果

| 操作 | 今回の役割 | 変更の境界 |
| --- | --- | --- |
| `gcp check` | 宣言した対象の構成を読み取り、選択した接続確認を行い、結果を新規runへ保存する | Cloud SQL、IAM、ネットワーク、課金設定を変更しない。DBのデータ・スキーマを変更しない |
| `gcp report` | 保存したrunの整合性と適用条件を確認し、期待と観測を評価する | ネットワーク接続とクラウド変更を行わない |

project、instance、DB、SA、Proxy/直接経路、期待する許可・拒否を定義します。送信元はCLIを実行する環境であり、全送信元・ENI・ルート不存在・管理例外を網羅した確認ではありません。結果には最後の到達・ログイン状態、期待との一致、拒否の層、未確認事項と次の対応を残します。操作完了や定義したcaseの合格を、DB全体の安全・既存DB導入の完了と同一に扱いません。

### 実行例

実project/SAへ置き換えた設定と、必要な権限・APIを用意した環境で実行します。以下の例はDBやIAM設定を自動変更しません。

```sh
veil-db-guard gcp check --config gcp.yaml \
  --allow-gcp-read --allow-network --out runs/gcp-check-1
veil-db-guard gcp report --config gcp.yaml \
  --evidence runs/gcp-check-1 --out runs/gcp-report-1
```

各出力先は新規ディレクトリにします。実行ファイルがPATHにない場合は`--gcloud-bin`、`--proxy-bin`、`--psql-bin`で明示できます。liveには両方のallowフラグが必要です。`--fixture FILE`はネットワーク許可と併用できず、外部CLIを起動しません。

終了コードは0=定義したcaseを確認、1=期待条件未達、3=反映確認待ち/未確認、2=入力・操作エラー、130=取消しです。JSON summaryの`protected`は定義したcaseの観測範囲に限り、未定義の迂回経路や全DBの安全を意味しません。

## 証拠と判定

- `fixture`はローカルの再生・評価試験です。入力ファイルに実機相当のラベルが書かれていても、実機証拠へ昇格させません。
- `live`はこのCLIが明示した対象へ接続して取得する証拠です。認証済みAPIから取得した対象情報と、Proxy・DB接続・SQLの観測を対応付けます。
- `partial`は取得状態であり、証拠の取得元とは別です。中断・期限切れ・一部取得失敗のrunを完了済みの保護証拠にしません。取得できた個別結果と不足は残します。

runには対象、設定・build・成果物のhash、取得時刻、構成の前後情報と各接続試行を対応付けます。reportは別対象、別設定、古い証拠、参照切れ、不足を検出し、確認できない条件を合格にしません。ローカルhashは成果物の整合確認であり、第三者による真正性の署名ではありません。

接続事実はAllowed/Denied/Unknown、期待に対する評価はPass/Fail/Pending/Unknownとして別々に保持します。

| 観測 | 扱い |
| --- | --- |
| 期待する主体・DBでSQL接続成功 | 現在の接続許可として記録し、宣言した期待と比較する |
| Cloud SQL APIの`cloudsql.instances.connect`不足403 | transportのIAM拒否。token発行失敗や別API権限の403で代用しない |
| PostgreSQLのIAM認証拒否と独立した同runの正規Proxy接続成功 | 登録済みDBユーザーと対照caseへの参照を照合し、DB IAM認証層の拒否として評価する。具体的なlogin権限不足403を採取したという意味ではない |
| TCP timeout、到達不能、原因不明の切断 | 接続状態・拒否原因は未確定。これだけで不正接続防止の合格にしない |
| 証明書不一致やtoken取得失敗 | 対応する失敗として保存し、期待するIAM拒否に読み替えない |

## 権限変更と過去の履歴

Cloud SQLのtransport接続とIAM DBログインは別の権限です。`roles/cloudsql.client`は`connect`/`get`、`roles/cloudsql.instanceUser`は`executeSql`/`get`/`login`を含みます。最新の取得情報では、取得範囲、取得成否、主体と権限を明示します。選択したproject policyの読取だけで、上位階層・group等を含む全実効権限を確認したとは扱いません。[公式ロール定義](https://docs.cloud.google.com/iam/docs/roles-permissions/cloudsql)

IAMのpolicy変更は結果整合であり、削除後も新規ログインが一時的に成功する場合があります。公式の目安は通常約2分、7分以上の場合もあり、上限保証ではありません。[公式伝播説明](https://docs.cloud.google.com/iam/docs/access-change-propagation)

`Pending`として権限変更の反映待ちを表示する場合も、現在の観測が`Allowed`なら、その事実と期待からの逸脱を隠しません。待機中であることを理由に合格へ変更しません。変更の申告だけでなく、同じ対象・主体・権限層に関する保存済み構成の差分と時刻に対応付けます。

`permission_changes`には主体ID、connect_iam/login_iamの層、実際の変更Unix時刻、変更前後のrole列を定義します。除去対象はCloudSqlClientまたはCloudSqlInstanceUser一つに限定します。role差分の実測baselineを明示して実行します。

```sh
veil-db-guard gcp check --config after-change.yaml \
  --baseline runs/before-change --allow-gcp-read --allow-network \
  --out runs/after-change-1
veil-db-guard gcp report --config after-change.yaml \
  --evidence runs/after-change-1 runs/after-change-2 \
  --history runs/before-change --out runs/change-report
```

baseline側も同じ主体・経路・期待を定義し、変更前の接続とrolesを取得します。元configのhashを検証し、permission_changesだけを除いた設定のhashが一致するhistoryのみ関連付けます。historyの元runは保持し、再評価でも`--history`へ渡します。時刻・roles・build・登録・正例等が対応しない宣言をPending根拠にせず、待機windowを越えてもAllowedならFailです。取得できなかった最新current runを、古いPassで置き換えません。

[前回追試](gcp-rejection-validation.md#権限削除は即時遮断ではない)では、権限削除後に成功と拒否の混在を観測しました。reportはその履歴を保持し、直近の一回の拒否や連続拒否を、全接続への安定した失効や既存セッションの即時切断の保証にしません。過去の別instanceでの成功・拒否も、現在の対象の不足証拠を埋めるためには使いません。

## TLSの区間

アプリ・CLIからローカルCloud SQL Auth Proxyまでと、ProxyからCloud SQLまでを区別します。loopback接続をremote TLSの直接検証と呼ばず、Proxyの認証・暗号化とAPI上の設定を対応付けます。Proxyの待受はローカルに限定します。

直接TLSはPublic IPv4とinstance固有CAだけに対応し、APIで取得した当該CAを指定して`verify-ca`を使います。公開CAのPEMは新規run内のtransport/へ0600で保存し、snapshotはDERのSHA-256 fingerprintを保持します。shared CAはDNS名に対するverify-full等が必要なため、このadapterではtoken/TCP取得前に直接試験を止めます。黙ってCA検証を省略しません。片区間の成功や設定値だけで全区間のTLS検証完了にしません。[Cloud SQLのCA別条件](https://docs.cloud.google.com/sql/docs/postgres/configure-ssl-instance#server-identity-verification)

## 依存・権限・秘密の扱い

今回の実機ではmacOS ARM64、Rust 1.98.1、Google Cloud SDK 561.0.0、公式Cloud SQL Auth Proxy 2.26.3、psql 17.7を使用しました。runtimeはProxy 2.26.3とpsql 17系の版を確認し、PATHまたは明示pathを正規化します。追加crate依存はありません。SDKはinstance指定describe、project policy、DB user一覧、明示SAのlogin token生成だけに使い、raw応答は選択した型へ縮約します。

keylessな短期service account impersonationを基本とし、ユーザー管理のSA秘密鍵を要求・発行しません。操作者の`roles/iam.serviceAccountTokenCreator`は指定SA単位、SAのCloud SQL権限は指定対象のproject内を基本とします。Service Account Credentials API、Cloud SQL Admin APIと必要なAPI利用権限は事前条件として確認し、check自身で有効化・付与しません。[impersonationの前提](https://docs.cloud.google.com/docs/authentication/use-service-account-impersonation)

checkは`gcloud`の既定project、impersonation設定、ADCを暗黙変更せず、ログイン操作も自動実行しません。Veilが捕捉したtokenを引数、標準出力、stderrの転記、設定、証拠へ保存しません。外部CLIの失敗文も未加工のまま取り込みません。SDK HTTP/file loggingとtoken表示を子環境で抑止します。ただしgcloud自身の既存credential/token cache更新はSDKの通常動作であり、Veilの成果物非保存とは区別します。

Proxy等の子プロセスには期限と終了処理を設け、完了・失敗・キャンセル時に停止します。取得した証拠は制限付きの新規runに残し、既存成果物を上書きしません。実機検証時の資源作成・権限変更・撤収は、通常のcheck/reportとは別の、承認済み試験作業として記録します。

## 統合・検証状況

ローカルは既存AWS回帰を含む`cargo test --locked`が119件成功、明示実DBの旧PG試験2件は今回再実行していません。GCP内訳は評価21、CLI統合7、adapter/mock13、共有store境界2です。fmtとHomebrew Clippy 1.98.1のall-targets/-D warningsを通しました。PATH上の別ClippyがRust 1.95を選んだ初回はツールチェーン不一致で停止したため、Rust要件を下げずHomebrew側を明示して成功確認しました。

CLIによる実機check 12回とoffline report 4回を、固定した同一バイナリで実行しました。

| 実機条件 | CLIで確認した表示・評価 |
| --- | --- |
| 正規SAのProxy接続、不許可SAのclient不足 | Allowed/Deniedを分離し、connect permission拒否を確認。定義した2caseでPass |
| 直接接続のtimeout | Unknown、protected=false。timeoutだけをNetworkBlockedのPassにしない |
| /32のみ一時許可、Connector非必須 | 直接接続でCA検証/SQL/SSL確認成功 |
| 拒否したいSAにまだ両権限があるbaseline | Allowed/Fail、protected=false |
| InstanceUser削除後もログイン成功、対応baselineあり | 5回のcheckでAllowed/Pending、protected=false、終了コード3 |
| 同じPending記録をbaselineありでoffline評価 | Pendingを再現 |
| 同じ記録をhistoryなしでoffline評価 | Allowed/Fail。変更の申告だけで待機を正当化しない |
| 反映後のIAMログイン拒否 | 3回のcheckでDenied/Pass、独立したapplication-proxyの正例linkを検証 |
| 取得した8runとbaselineをoffline評価 | Mixed=true、直近3拒否と過去の成功を保持。即時失効や安定失効とは表現しない |

nativeのLoginIam拒否はFATAL・登録・正規対照・project role差分を使う認証層の評価です。具体的なcloudsql.instances.loginの403やサーバーDETAILを今回CLIが採取したと説明しません。前回の手動追試のserver logsを今回の不足証拠へ流用していません。

生のAPI準備記録、nativeのconfig/run、実行条件、固定binaryはgit除外のruns/gcp-cli-validation-20261102-119a62/へ保存しました。build IDは1148f97284f4df3c3613de8d2e858f7267bdd553a4415d957aeb1cde6d7de5ddです。構築・IAM変更は専用labの外側の試験手順が実施し、native CLIはcheck/reportだけを実行しました。

2026-11-02 14:24 JSTに、試験用SA2件と追加したproject/tokenCreator bindingの除去、ユーザー管理key 0、削除前backup 0、DB削除operation DONE、instance一覧0、billingEnabled=false、projectのDELETE_REQUESTEDまで確認しました。物理消去や既発行tokenの即時失効の証明ではありません。Proxyは停止し、ローカル証拠を保持しました。

instance作成要求から削除確認までは約12分。東京のCPU/メモリ/SSD単価で、今回のDB/storage概算は約0.0371米ドル、初回・追試との累計は約0.1447米ドルです。通信・ログ・税等を含む実請求額ではなく、実請求額は未取得です。全体50米ドル、今回管理枠5米ドル/4時間の範囲で実施しました。[計算根拠](multicloud-preparation.md#料金の確認と見積もりの境界)

独立担当がnativeのmanifest全artifact hash/bytes、capture/run/build、固定binary SHA、各caseとoffline再評価、撤収のAPI原記録を照合し、重大な不整合は見つかりませんでした。ソース・証拠を保全し、公開・push・既存DBへの導入はしていません。
