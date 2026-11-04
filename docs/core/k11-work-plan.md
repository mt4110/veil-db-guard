# K11：既存PostgreSQLアプリ連携の着手設計

2026-11-03更新。**K11-Aの詳細設計と、process/socket部分観測の生成・受入・共通state接続を実装しました。** [詳細設計と現在の範囲](k11-a-runtime-binding-design.md)を参照します。実session・認証・TLS・pool世代との結合は未完了であり、RuntimeBinding全体の完了ではありません。K10の部分状態を受け取り、実際のアプリ・接続pool・切替・復旧経路へ結びます。K10の未確認や履歴を消してから始める必要はありません。native閉鎖に必要な現在証拠が揃うまで、実行gateは停止を維持します。

## 入口と出力

`guard k11-readiness`で、現在のimmutable planから`k11-runtime-evidence-input-v1`の引継ぎを生成します。入力は検証済みplan runと、任意で既存ledger/context/archiveです。native tool、credential、cloud、SSHを呼ばず、承認・desired headを変更しません。planだけの場合は現在の実効状態をUnknownとして出力します。

```sh
mise exec -- cargo run --locked --offline -- guard k11-readiness \
  --plan-run /path/to/prepared-plan-run \
  --out /path/to/new-k11-handoff
```

既存資料も読む場合は`--ledger /path/to/existing.sqlite --context CONTEXT --archive /path/to/archive`をまとめて渡します。必要なら`--request REQUEST_ID`を指定します。存在しないledgerを作るfallbackや、古いadmission時刻へ戻す再受入はありません。

出力は`k11-handoff.json`、`source-state.json`、`intent-qualification.json`、`report.md`、manifestです。`k11_implementation_can_start`は選択policy/target/source/adapterの実装契約が対応しているという意味です。native実行可能、実導入済み、全保護成立ではありません。静的unsupported、v1、契約不一致、別change、欠けた/重複したdesired行をReadyへ変換しません。保存したreportを承認・SourceStepCheckとして読む入口はありません。

## K10から受け取る契約

- current source-bound factsは既存EvidenceLedger/Archive、source snapshot・trust/build・nonce・scope・世代・鮮度を再検証して使用する。
- host-kernel事実は生成元確認とapp scopeが別。UID/netns/cgroup/security digestの一致だけで適用policy全体の一致を証明したとしない。
- 遅延routeはobserved/receivedを分けた履歴専用。ACCEPT/現在Allowedを保持し、closureや現在のRouteBlockedへ変換しない。
- IAM completeは一つのprincipal/resource/actionという明示scopeの完全性。組織memberや未対応条件・別credential経路へ一般化しない。
- TLSは元のstrict契約、または新policy/hash/承認で選んだAWS managed backend契約を使用し、後者を内部CA/hostname実測に変換しない。
- 操作完了、設定受付、現在の接続効果、全保護成立は別々に報告する。Unknownを落として全体greenにしない。

## 実装単位と依存

| 単位 | 入力・所有境界 | 受入条件 |
| --- | --- | --- |
| K11-A | coreのRuntimeBinding要求、adapters/sourceの固定runtime producer、受入型 | process incarnation、UID/GID、namespace、cgroup/LSM/seccomp等のscope、source/trust、target generation、実session/route/transportを選択。欠損・再利用PID・context違いはUnknown。operator booleanやraw JSONから確認済み型を作らない |
| K11-B | PostgreSQLアプリ向け接続bundleとnative token取得port | endpoint/db/user、認証provider、更新・失効・pool切替の識別を生成。秘密値をartifactへ含めず、任意SDK環境へfallbackしない。bundle配布だけでRuntimeBinding成立にしない |
| K11-C | アプリ側cooperationとpool generationの観測 | アプリが実際に使用する新規接続とpool世代を証拠へ結ぶ。管理CLIのprobe成功をアプリの接続へ拡大しない。旧sessionの存続は別effectとして残す |
| K11-D | independent recovery、cutover、閉鎖直前のSourceStepGate | 別source/subjectの復旧確認、binding反映、実app新規接続が揃った後だけ閉鎖へ進む。query-only、中断再開、設定受付と効果完了の区別を維持 |
| K11-E | GCP PostgreSQLの縦接続後、AWS PG・MySQLへ展開 | 共通contractを再利用し、provider/engine固有の差をadapterへ閉じる。AWS認証型のengine中立整理は必要な範囲で行い、サービス分割しない |
| K11-F | ローカルの合成producer・実SQLite/archive・fake app/pool | 正常/部分取得、PID再利用、token/世代違い、Pool未切替、late expiry、cancel、復旧不足、現在Allowed、origin不足、過去ログ混入を検証 |

K11-Aの今回の部分実装は既存`RuntimeBinding` effectとK10の受入portを拡張し、不要な並列評価系を作りません。現在のSourceStepGateが要求するrow・独立recovery・変更後時刻の条件を削って通すことはしません。単一crateのcore→port→adapter→CLIを維持します。

## 対応範囲と外部操作

最初はGCP PostgreSQL 16.15・既存GCE host profileで縦に接続し、その後AWS PostgreSQL、MySQLへ拡げます。Linux runtime、既存アプリとの実接続、collector導入・ログ設定・権限変更・cloud資源は別の実行範囲です。今回の着手設計とローカル引継ぎ生成は、その外部操作を行った意味ではありません。

## K10の残るprofile拡張

Cloud Loggingの生成元閉包、AWS Flow Logsの単一probe帰属と現在性、組織member/任意IAM条件の完全評価は未対応です。これらを拡張タスクとして記録し、K11がUnknown/Unsupportedを受け取れる形に固定しました。全providerの全保証を完成したとするためにK10を閉じるのではなく、元の[K10受入条件](k10-work-plan.md)に従い、共通契約・部分結果・非対応の可視化を次工程へ渡します。個別profileのnative閉鎖を許す条件は引き続き厳密です。

## K11-Aの現在の実装と次の範囲

固定GCE collector設定の`runtime.bindings`にtarget/grant/subject、process selectorとsocket FDを明示した場合に限り、既存`guard observe-plan`の計画にruntime caseを追加します。未設定時の旧wire/configは省略形を維持します。新設定はsourceのconfig digestとrevisionを変えるため、再登録・policy/plan/承認/requestの更新が必要です。今回それらを実環境へ適用していません。

正常な部分capture、または取得失敗をsealed source payloadへ含め、既存のnonce・SQLite/archive・鮮度・trustを再利用します。claimの`runtime_capture`は観測元の標本を保持しますが、常にUnknown/Configurationであり、TLS・SQL・拒否・完了booleanの持込みで肯定へ変換できません。offline stateのrow/historyから同じ資料と不足を読めます。

**次はK11-BのPostgreSQL接続bundle/token port、その後K11-Cのdriver/pool結合です。** 元のA行に含まれる実session/route/transportへの結合の受入はこの縦接続で完了させます。K11-Dの独立recoveryと閉鎖gateも未実装です。process/socket部分を取得できたことを、この残差の完了に数えません。

## Unix peer・pool切替・受入の接続

`guard connection-bundle --ledger LEDGER --operation OP --grant GRANT --source SOURCE --route ROUTE --pool-generation GENERATION` は、既存operationの検証済みchangeから対象世代・source・経路を選んでbundleを生成します。GCPアプリは信頼済みchangeから `binding::runtime::ConnectionBundle::prepare` で同じbundleを組み立て、CLI出力を受け取る場合は `verify_export` で照合できます。

| 単位 | 実装した範囲 | 現在の境界 |
| --- | --- | --- |
| A | root設定の `runtime_unix` に明示したtarget/grant/subject/routeに限定。固定したapp/connectorのPID開始時刻・実行image・UID・FDと、Linuxが返す相互peer inode・socket cookie・パスの所有情報を前後で照合。既存GCE署名付きpayloadへ保存 | 取得はLinux root・既存のUnix診断機能が必要。同じsocketを観測できても、IAM主体や上流TLS peerの証拠は別に必要 |
| B/C | `SessionPool` が新しい物理接続群を事前作成し、期待旧世代を再確認して新規checkoutを一括切替。旧貸出は返却まで保持。現在世代のcheckoutからrequest-bound候補を生成。別の復旧用PostgreSQL接続からbackend PID・開始時刻・DB/user・marker・PostgreSQL側SSLを読み合わせる | 初期対応は同一の変更・接続scope内の管理対象pool。復旧用readは呼出し側が渡す接続を使う診断。stock Cloud SQL Auth Proxyの個別接続から独立したIAM主体・TLS peer・現行pool利用の全証拠を生成する実装は未接続 |
| C受入 | Unix peer・正確なPostgreSQLセッションの認証/TLS・現在のpool checkoutを別資料で照合。型で照合済みと判定された三資料が、同じrequest/case・時刻・artifact digestで揃う場合にSQLite/archiveへ受入。最も早い証拠期限で失効 | 肯定側は合成verifierでローカル検証。既存GCE collectorのUnix標本は `Unknown` のまま受入 |
| D | 既存の閉鎖直前gateを使い、アプリとは別source ID・登録・snapshotの復旧証拠を要求。元の証拠有効期限、変更直前の再確認、設定後の別観測を使用 | 本番producerの証拠が揃うまで直通閉鎖は進まない |
| E | `--aws-proxy-ca-sha256` を指定すると、台帳の現在EC2 source登録からAWS向けbundleを生成。アプリではIMDSv2・署名付きEC2 identity・STSで固定roleを照合し、接続ごとにメモリ内でIAM tokenを発行。PostgreSQL/MySQLの両driverでProxyのCA/hostnameを確認し、返すセッションのDBとログインを照合 | AWSの管理poolとPostgreSQLの独立runtime受入は後述。MySQLの独立runtime受入は未接続 |
| F | Unix peer fixtureと改変拒否、実driver＋Unixの合成PostgreSQL、世代切替・旧貸出の保持・取消し、実SQLite/archiveでの受入・再読込・期限切れ、復旧source alias拒否、AWS両engineのbundle・token・事前停止をローカルで検証 | Linux arm64はオフライン型検査。利用したコンテナでUnix診断機能が確認できず、実カーネルでの成功取得は未確認 |

GCP側は自動IAM認証を行うCloud SQL Auth Proxyを使います。復旧セッションから見える `pg_stat_ssl` はPostgreSQL backend側のSSL情報です。実際のapp接続について、コネクタの上流TLS peerと使用したIAM主体を同じソケットに結ぶ証拠が必要です。[Cloud SQL Auth Proxy](https://docs.cloud.google.com/sql/docs/postgres/sql-proxy) · [Cloud SQL IAM認証](https://docs.cloud.google.com/sql/docs/postgres/iam-authentication) · [PostgreSQLの統計ビュー](https://www.postgresql.org/docs/16/monitoring-stats.html)

次の受入条件は、管理対象コネクタの同一接続に対するIAM/TLS証拠と、現行pool checkoutの独立資料を既存の照合portに接続することです。AWSへは各Proxyの後段証拠を区別しながら同じ原則を適用します。

## 1の継続実装と残る取得経路

GCEの認証済みcaptureに対して、`GceCapture::corroborate_runtime` がコネクタ観測とpool観測を受け取ります。入力は既存のissued request、登録済みcollector設定の元バイト列、アプリ候補と署名付き二資料です。鍵・bundle digest・切替前後世代・credential binding digest・切替基準時刻は、設定内の `runtime_unix[].witnesses` で固定します。設定digestと登録snapshotが一致し、コネクタとpoolの公開鍵が別の場合だけ使用できます。設定追加にはsourceの再登録と、それを参照する計画の更新が必要です。

二資料は別々のEd25519鍵で署名します。署名対象は `veil-db-guard/k11/connector/v1\0` または `veil-db-guard/k11/pool/v1\0` のバイト列に、観測のJSONバイト列を続けたものです。エンベロープは `statement_base64` と `signature_base64` を持ちます。観測本文は `context`、`observed_at`、`valid_until`、`observation` を持ち、最後の欄はそれぞれ `NativePostgresSessionObservation` と `NativePoolUseObservation` です。最外層は `candidate`、`connector`、`pool` を持ちます。

同じrequest/case、登録したUnix peer、DBセッション、IAM/TLS、現行pool世代、時刻がすべて一致した場合だけ、GCE標本と二つの署名済み資料を既存の受入経路へ渡します。各鍵は、アプリ申告から独立して該当接続を計測する観測側が保持します。署名は観測元の認証であり、未計測の事実を補う仕組みではありません。

今回は合成鍵と署名資料で受入口を検証しました。標準Cloud SQL Auth Proxyを使う現在の構成には、個別接続のIAM主体と上流TLS peerを測定してこの形式で出すコネクタ側実装、および現行checkoutを独立観測して署名するpool側実装が残っています。実運用経路の `RuntimeBinding` は `Unknown` です。1の完了後に2の閉鎖判定、その後に3のAWS展開、4の残る結合検証を行います。

## 管理対象コネクタとpoolの署名発行

`guard observation-issue` で、観測を開始する前に台帳へ期限付きのリクエストを発行できます。`guard observe` は `--runtime-collector-config` と `--runtime-witnesses` を指定すると、登録digestを照合し、GCEのUnix peer採取と二つの署名資料を既存の受入処理へ渡します。

新しい `ConnectorWitnessConfig` は登録GCEの資格情報を使い、Cloud SQL Admin APIの接続設定・対象世代・短命クライアント証明書を取得する管理対象コネクタ向けの組込みAPIです。TLS 1.3でCAとDNS名を検証し、クライアント鍵によるハンドシェイク署名を確認します。同じPostgreSQLストリームで起動時のDB・ユーザー・backendを観測してからアプリへ渡し、接続が生きている間だけ署名資料を発行します。起動時のロール照合は、その後のSQLロール変更の観測とは別です。

管理対象アプリのpoolは、切替後の実checkoutに対してソケット・プロセス・現行世代を調べ、登録したpool鍵で署名するAPIを持ちます。コネクタとアプリは異なるUIDと鍵を使います。pool側の署名は登録したアプリの固定buildとpool実装を信頼します。コネクタ側の制御ハンドルは信頼済みの運用側が保持し、checkout後に発行を要求します。初期範囲は固定したFDで保持する一つのcheckoutです。

TLS・PostgreSQLプロトコル・pool発行・GCE受入を個別にローカル検証します。異なるUIDの実プロセスで、同一checkoutを保持したまま二つの署名とLinux Unix peerを採取し、台帳へ受け入れる結合試験が1の残りです。

## 登録順と他環境への転用

GCPの登録設定にある `witnesses.bundle_digest` には、`ConnectionBundle::witness_scope_digest()` を使います。これはDB・grant・実行主体・source登録ID・経路・pool世代を固定し、登録の結果として決まるsnapshot digestや計画のhashを含めません。先に同じ接続範囲でこの値を計算して設定を登録し、その登録を参照する正式な計画とbundleを作ります。署名時は正式なbundleのhashと、issued requestの計画・policy・source snapshotも別に照合します。bundle全体の `digest()` はエクスポート照合に使います。

K11の実装対象はGCP Cloud SQL PostgreSQLとAWS RDS Proxy PostgreSQL／MySQLとします。他のクラウドや自前サーバーへ移す場合は、provider別に以下を実装・検証します。

1. **接続先と実行主体を固定する。** インスタンスやクラスタの再作成を区別できる識別子と、実際に接続に使った実行主体を取得します。固定パスワードや別の認証方式を使う場合は、その方式の契約を明示し、IAM用の成功条件を流用しません。
2. **アプリの同一接続を観測する。** 実checkoutの世代とsocket、実際のDBセッション、TLSを区間ごとに対応付けます。Unixソケットを使わない構成では、その配置に合う独立した接続の照合方法を用意します。
3. **観測元と鮮度を検証する。** 登録した観測側に鍵を分離し、同一リクエスト・接続・対象世代・観測時刻に結び付けます。取得できない項目は `Unknown` とします。
4. **閉鎖を別に検証する。** 独立した復旧経路を確かめ、現在の証拠が揃ったときにだけ閉鎖判定へ進みます。対応追加の受入には、実際に使うOS・ドライバーでの同一接続の結合試験が必要です。

当初のローカルLinuxコンテナでは `/sys/module/unix_diag` が見えず、固定observerは非対応として扱っていました。承認を受けてColima VMにモジュールをロードし、下記の実ソケット採取試験が通りました。同一checkoutの結合試験には、この診断機能が利用できるLinux上で、異なるUIDのアプリとコネクタ、固定したsocket選択、署名の制御ハンドル、ローカルの模擬上流を組み合わせる必要があります。

### Linuxのpeer採取を単独で確認する

ローカルのLinuxで既に `unix_diag` が利用可能な状態にしてから、隔離コンテナ内で次の対象テストを実行します。Rust 1.98.1、Python 3、別UIDのprocfsを参照できる権限が必要です。既存Colimaのカーネルにはモジュールファイルがありましたが、検査時点でロードされていませんでした。

```sh
cargo test --locked --offline --lib native_observer_correlates_distinct_uid_socket_peers -- --ignored
```

テストは、異なるUIDの2プロセスで実Unixソケットを開き、既存observerで相互peerとcookieを採取します。誤ったFDが拒否されることも確認します。この段階を通した後、同一checkoutのIAM/TLS署名、pool署名、peer採取、台帳受入を一連で検証します。

Colima Linux arm64で、実カーネルから得たpeer・cookieをGCEの照合処理へ渡す試験も成功しました。TLS/IAMとpoolの署名は合成資料を使い、誤った署名鍵は拒否されました。次に残る試験は、管理コネクタとアプリpoolを起動し、同一checkoutから両署名を発行して実SQLite/archiveへ入れるものです。 [Linux検証ログ](../../runs/core-k11-native-peer-local-1/native-join.log)

### 同一checkoutのローカル受入と閉鎖前判定

Colima Linux arm64で、管理コネクタとアプリpoolを別UIDで実行しました。アプリが旧世代から新世代へ切り替えた一つのcheckoutを保持したまま、コネクタとpoolがそれぞれ署名し、collectorは実カーネルから相互peerを採取しました。同じリクエストに結び付けてSQLite/archiveへ受け入れ、台帳を開き直して `RuntimeBinding=Present` と証拠3点を確認しました。上流のCloud SQL管理API、IAM主体の設定、GCEの認証応答はローカルのfixtureです。TLS 1.3の相互認証、PostgreSQLプロトコル、pool切替、Unixソケット、署名生成、SQLite/archiveは実装を通っています。

同じ試験で、再読込したcheckout証拠を閉鎖前判定へ渡しました。独立復旧と接続/TLSの別証拠はこの試験用の資料を使用します。全部が有効な場合に判定が通り、checkout欠落・独立復旧欠落・checkout証拠期限切れでは拒否されます。

```sh
timeout 120 cargo test --locked --offline --lib same_checkout_real_witnesses_admit_and_reload -- --ignored --nocapture
```

Linux rootと、既にロード済みの `unix_diag`、別UIDのprocfsを読める権限が必要です。試験は外部ネットワークを無効にしたコンテナ内で実行できます。 [受入と判定のLinuxログ](../../runs/core-k11-same-checkout-local-1/linux-gate.log)

### AWSの管理poolと残る受入条件

`AwsSessionPool` は、既存のIAMトークン・CA・ホスト名検証を通るPostgreSQL／MySQL接続を各世代に束ねます。新世代の接続作成と旧世代の一致確認が済んだ時点でcheckoutを切り替え、貸出中の旧接続を返却まで保持します。接続先、CA、DB、実行主体等が変わるbundleの切替は拒否します。MySQLのアプリ接続では、ドライバーがProxyのTLSを検証した上でDBとユーザーを照合します。AWSによるとRDS Proxy経由ではSSLセッション変数が設定されません。 [RDS ProxyのTLS仕様](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html)

AWS側のcheckout標本は診断用です。RDS Proxyはトランザクション単位でDB側の接続を切り替えられるため、接続時のPG backend PIDやMySQL Proxyの接続IDから、アプリのTCP socketと現在のDB backendを対応付けることはできません。既存のAWS collectorは別の接続を観測します。AWSの独立した `RuntimeBinding` には、同じcheckoutを保持した区間の観測とDB側の証拠を対応付けます。PostgreSQLの受入契約は次節を参照してください。 [RDS Proxyの接続多重化](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html#rds-proxy-connection-pooling)

### AWS PostgreSQLの貸出中backend観測

`AwsPoolCheckout::observe_postgres_backend` は貸出中の物理接続を観測専用に取り出します。セッション状態を初期化し、読み取り専用トランザクション内でDB・ログイン・backend PID・開始時刻・サーバー側SSLを取得します。観測ハンドルが同じトランザクションを保持し、終了時にROLLBACKします。失敗や取消しで状態が曖昧な接続はpoolに戻しません。消費した枠はpoolの世代切替で補充します。ローカル試験はPostgreSQLのwire応答を使い、起動時と観測時のPIDが異なる場合と、観測区間のトランザクション境界を確認します。

この標本はアプリ側の観測です。独立受入は次節の観測元と照合して行います。サーバー側SSL標本ではProxy→DB間のCA・hostname検証は判定できません。AWS MySQLの同一区間の観測は未実装です。

### AWS PostgreSQLの独立照合と台帳受入

AWS collector設定の任意フィールド `postgres_runtime` に、対象・grant・主体、世代切替の範囲、Proxy CAのdigest、独立DB観測用ユーザー、poolとDB観測元のEd25519公開鍵を登録します。鍵は観測元ごとに分離します。設定の元バイト列が登録済みsource snapshotのdigestと一致することを確認し、正式なchangeとsnapshotから期待する接続bundleを再構築します。

貸出側は読み取り専用トランザクションを保持し、issued requestとcaseから導出した64桁のチャレンジを付けた固定SQLを送ります。独立したDB観測元は、別の認証済み接続から `pg_stat_activity` と `pg_stat_ssl` を読み、最後のSQL全体と `idle in transaction`、DB・ログイン・PID・backend開始時刻・トランザクション開始時刻・SSLを照合します。観測元は別のDBユーザーで、対象の統計を読める権限が必要です。観測元の接続先と対象世代は署名側で確認します。プール側は独立read後に現行世代を再確認し、切替前から保持したcheckoutは証拠にしません。観測用トランザクションのidle timeoutは15秒です。

両方の署名資料を同じissued request／case、source登録、対象世代、bundle、トランザクションに束縛します。照合した資料は共通の受入処理でSQLite／archiveへ保存し、早い方の証拠期限を採用します。この証拠で確認するのは観測時点の貸出・DB側トランザクションと暗号化です。Proxy→DB間の証明書CA・ホスト名検証は別の証拠が必要です。RDS Proxy経由でチャレンジが取得できない場合や、AWS上の署名元の構成を確認できない場合は受入条件を満たしません。

ローカル結合試験には専用のTLS付きPostgreSQL、`billing` DB、別ユーザー `billing_app`、`veil_recovery`（`pg_read_all_stats`）、`veil_test_unprivileged` が必要です。接続先はloopbackに固定し、テスト専用パスワードを使います。

```sh
VEIL_K11_TEST_PG_PORT=<port> VEIL_K11_TEST_PG_CA=<ca.pem> mise exec -- \
  cargo test --locked --offline --lib postgres_backend_corroboration_uses_an_independent_session -- --ignored
```

`guard observe-plan` がAWS PostgreSQLのruntime caseを単独のbatchに分けます。そのcaseを使い `guard observation-issue` で先にリクエストを発行します。観測元はそのcontextで資料を作ります。受入時は同じ `--request-id` と `--cases` に加え、`--runtime-collector-config`、`--aws-runtime-pool-witness`、`--aws-runtime-database-witness` を `guard observe` に渡します。このモードは登録済みの設定と署名資料をローカルで照合し、SSHやDB接続を開始しません。

ローカル結合試験では、専用PostgreSQL 17の別ロール・別TLS接続で同じトランザクションを観測しました。SQLiteとarchiveを開き直し、署名原本と `RuntimeBinding=Present`、期限切れを確認しました。AWS用bundleのEC2/IAM、RDS Proxy、署名元の配置・鍵管理はこの試験ではfixtureです。
