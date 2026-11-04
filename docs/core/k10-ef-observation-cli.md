# K10-E/F：AWS正規化、取得CLIとoffline実効評価の進捗

現在の追加実装は[残producer記録](k10-producer-gaps.md)を参照します。以下はそれ以前の履歴です。

更新（2026-11-03）：[EC2 source・AWS PostgreSQL取得/GCP実行接続の続編](k10-native-source-execution.md)を実装しました。**以下は初回E/Fの履歴**で、当時の463成功と未実装事項を保存します。現在はEC2 source、PG/MySQL native取得とGCP/AWSの新実行契約が接続済みで、native拒否・backend TLS・完全なinventory等が残ります。

2026-11-03。**K10-EのAWS PostgreSQL/MySQL正規化と、K10-Fの取得・offline state/status・native実行前の不足表示を実装・ローカル検証しました。K10全体の完了ではありません。** AWS固有sourceのcollector/verifierと、source-boundな閉鎖stepの実行アダプターへの本接続は残っています。v2 forward dispatchは引き続き停止します。

目的は、既存DBを移し替えず守る本体へ、対象・主体・送信元・経路に結び付く現在の証拠を接続することです。今回の観測CLIを最終製品の全体と置き換えず、実行系へつなぐ前の境界を明示します。追加フィジビリティ、クラウド操作、実sourceへの接続/配置、実DB操作、公開・commit/pushは行っていません。

## 実装したものと境界

| 箇所 | 今回の実装 |
| --- | --- |
| `adapters/source/aws.rs` | AWS PostgreSQL 16.15/MySQL 8.0.43・東京の選択資料を同じclaim/assurance形式へ正規化。IAM主体・世代・Proxy・DB/account/host・TLS区間・SQL効果を区別 |
| `adapters/source/support.rs` | 取得処理と正規化処理の対応を別々に表示。AWS source未対応をGCEの署名やCLI-hostの接続で補わない |
| `core/admission.rs` | snapshotとsubjectのmetadata専用資格情報の宣言を共通照合。元の受入時刻・元資料を再検査する、現在の確認済み型とは別の履歴読取り |
| `evidence_store.rs` | read-only観測session。forward approval/operation/stepを作らず、desired headも更新しない。通常operationとID衝突・転用を拒否 |
| `adapters/source/requests.rs` | 指定policy・固定collector configからケースを作り、8件ずつに分割。IPv6/aliasの宣言を黙って落とさず、未取得の必須effectも記録 |
| `adapters/source/state.rs` | 元の受入台帳/資料からoffline再評価。失効/期限切れ/build変更は不適格履歴へ分離し、部分Allowedを保持。破損した履歴を表示用の成功根拠にしない |
| `core/state_v2.rs` | 独立recovery sourceの新規接続/TLSも必須行にする。アプリだけの成功で復旧経路を代用しない |
| `observation_cli.rs`, `guard_cli.rs` | source登録、read-only context開始、ケース作成、明示取得、v2 state/statusへ接続。v1の読取・承認・hashは維持 |
| `adapters/source/native_gate.rs`, native CLI | source-bound stepごとの不足とadapter contractをnative実行前に表示。証拠表示だけでdispatch資格を与えない |

単一Rust crate/CLIとcoreへ向く依存を維持しました。Cargo依存を追加していません。既存のevidence schemaに観測session用の任意tableを、明示setup時だけ追加します。`open_existing`やv1 statusからtableを自動作成しません。

## K10-E：AWS側で現在できること

`AwsSelectedCapture::parse_untrusted`と`normalize`は、strictな選択資料を同じ`ObservationClaim`へ整形する内部APIです。request nonce/digest・change/policy・source boundary・target generation・Proxy ARN/resource ID・接続先/portを照合し、engineとaccountを取り違えません。

- PGのsession/current user・login/object OIDと、MySQLのlogin user/current account・hostを分けます。MySQLへPGのOIDを捏造しません。
- 接続成立はAllowedのwire claimとして残します。一般のSQLSTATE/1045/認証失敗、TLS失敗やtimeoutをIAM拒否・RouteBlockedへ読み替えません。
- client→ProxyとProxy→DBを分けます。一方のTLSだけで他方を満たしません。
- SQLのPresent/Absent、所有差分、接続、runtimeを別effectにします。完全性やincarnationの根拠がない資料で全体保護を成立させません。
- 任意の`source_verified`、raw error、credential等のfieldは拒否します。型/長さ/件数を制限し、外部資料のboolを受入済みの証拠へ変換しません。

**AWS固有sourceの認証済み取得は未実装です。正規化の出力は未信頼wireのままです。** SourceはUnsupported、他のassuranceもUnconfirmedで、`VerifiedObservationFacts`を生成しません。既存のv1 AWS CLI-host captureやGCE tokenを、この契約の送信元確認へ昇格するimportはありません。`observation-coverage`と`observe`は、この不足をnative toolやcredential/cases fileに触る前に明示します。

## K10-F：CLIの使い方

sourceの配置・host key・登録snapshot・metadata主体・collector configは、既存の信頼する運用経路で用意する前提です。CLIはinstall/VM作成/SSH設定変更/IAM変更を行いません。初期の実装済み取得profileは、root管理GCE Linux host network + GCP Cloud SQL PGです。

最初にsource snapshotのdigestを登録し、そのdigestと不変主体IDをpolicy v2へ固定してplanを作ります。source登録だけではnative verificationになりません。source更新はCASと単調増加trust epochを必要とし、既存policy/approvalを暗黙更新しません。

```sh
veil-db-guard guard source-register \
  --ledger ./guard.sqlite --snapshot ./source-snapshot.json

veil-db-guard guard plan \
  --policy ./policy-v2.yaml --out ./plan-v2

veil-db-guard guard observation-start \
  --ledger ./guard.sqlite --plan-run ./plan-v2 --context inspect-01

veil-db-guard guard observe-plan \
  --ledger ./guard.sqlite --context inspect-01 --source billing-runtime \
  --collector-config ./collector-v1.json --out ./observation-plan
```

`plan`の終了code 3は従来どおり「準備が完全でない」で、成果物はreview可能です。`observation-start`はread-onlyの照合contextを作り、forward承認の代わりにはなりません。指定したreview済みplanへの照合であり、稼働中のdesired headを更新しません。

`observe-plan`はsource snapshotに固定されたconfig bytes/digest、実行profile、metadata主体の宣言を確認します。sourceごとに計画し、8件を超えれば`cases-1.json`、`cases-2.json`等へ分けます。RuntimeBinding等、取得できない必須行は`uncollected_required_effects`へ残します。alias/IPv6の全inventoryを自動発見する処理ではありません。

次のcommandは、実行する際にsourceへのSSH・metadata/Google鍵・SQLAdmin・DB接続等を伴う明示readです。**今回の作業ではこのnative取得を実行していません。** SSH key等が用意された運用環境で、実行範囲を確認して使用します。

```sh
veil-db-guard guard observe \
  --ledger ./guard.sqlite --context inspect-01 --source billing-runtime \
  --request-id inspect-01-batch-1 --cases ./observation-plan/cases-1.json \
  --archive ./observations --identity-file ./source-ssh-key \
  --work-directory ./ssh-work --allow-native-read
```

archive/work directoryが未作成なら、その親directoryが存在する場所へprivateに作ります。既存の権限を緩めません。key/configへの暗黙探索やSDK fallbackはありません。`--allow-native-read`なしでは、台帳・archive・key・toolの読取りやnonce発行より前に停止します。

request/nonceは台帳側で発行します。同じrequest IDを別case/contextへ貼り替えられません。受入済みrequestの再実行は元資料を再確認し、新しいSSH/token/取得時刻を作りません。元の期限が切れたら新request IDで取得し直します。受入と全体保護は別で、部分状態は新規取得・再利用のどちらも終了code 3です。

独立recovery sourceも個別に計画/取得します。初期metadata-only profileでは、そのsourceに登録されたSA・不変ID・credential referenceと`workload_identity`の宣言が一致する必要があります。native SDKを用いる一般的なrecovery宣言を、metadataへ暗黙変換しません。同じphysical VMを別名のrecovery sourceへ重複登録できません。

保存済み資料のoffline読取りは次です。`--context`は既存`--operation`のaliasです。従来のforward operation IDでも利用できます。

```sh
veil-db-guard guard state \
  --ledger ./guard.sqlite --context inspect-01 --archive ./observations

veil-db-guard guard status \
  --ledger ./guard.sqlite --context inspect-01 --archive ./observations
```

`--request ID`を繰り返せば対象requestを限定できます。省略時は同じcontextのrequestだけを台帳から列挙します。`--archive`を付けないv2 state/statusは、未取得をUnknownとして表示し、外部取得や証拠table作成を行いません。

stateは`effective`とsource coverage、受入のcurrent/history判定、stepごとの不足をJSONで返し、必須条件が揃わなければ終了code 3です。statusの終了code 0は読取り成功であり、保護成立を意味しません。通常operationでは`operation_scope_completed`と`protection_evaluated`を分けます。観測contextにforward operationの完了を付けません。

## 失効・部分成功・native適用

期限切れ、source trust epoch変更、verifier build変更は元のcapture/受入時刻を保った不適格履歴です。既存のAllowedを履歴から消さず、現在の保護根拠にはしません。通常の古い履歴は、別にあるfreshな証拠を打ち消しません。資料が改変/欠落していればIntegrityErrorとして、未検査の内容を履歴の成功へ読み替えません。

v1 `--evidence`のprovider runや保存済みverdictをv2へimportしません。contextが異なる資料を、同じchange hashというだけで流用することも拒否します。現在source headと元のarchiveの整合をofflineで確認し、新tokenやnative callで資料を更新しません。

`apply-gcp/apply-aws`にも、`--source-archive`と任意の`--source-request`による同じoffline判定・不足表示を、native config/tool/credentialを読む前へ接続しました。**これはv2の閉鎖stepの実行アダプターを有効にする変更ではありません。** 全effectの保存済み表示をSatisfiedにしてもnative dispatchを許可せず、旧approvalや旧contractを流用しません。K09の既存受付済みqueryだけを残す条件も維持します。

## ローカル検証

`runs/core-k10-ef-local-20261103-1/`へlog/summary/source hashを保存します。`mise run check`は**463成功・0失敗・2件ignored（47 suites）**。fmt・Clippy（警告をerror扱い）も通過しました。

- AWS PG/MySQLのscope・世代・endpoint・account/host・engine取り違え、TLS区間、拒否原因、任意trust flagの拒否。
- 観測sessionがforward承認・step・desired headを作らず、operation IDにも転用できないこと。元時刻より前のsession/requestの拒否。
- CLIのsource登録→context→固定case計画→state/status。IPv6/aliasの分割、recovery TLSを省略しないこと。
- 合成verifierで受入れたローカル資料の再利用・再評価。部分Allowed、期限切れ/epoch変更、破損履歴、別context混入、古い履歴とfresh資料の併存。
- 明示read許可前やAWS source未対応時に、credential/cases/外部toolへ進まないこと。
- v1のhash/reader/approval、v2 native適用の停止、core単独コンパイル、既存GCP/AWS/PG/MySQLの回帰。

実GCE/EC2、実Google token、実SSH、実Cloud SQL/RDS/Proxyの試験は行っていません。ローカルの合成資料やCLI成功を実環境の成立へ昇格しません。

## 残る実装

1. **K10-E：AWS固有sourceの登録・認証channel・native identity/context・collector/verifier。** PGを先に実装し、その後MySQLへ同じsource確認を適用する。現在はUnsupported。
2. **K10-F：source-boundな閉鎖stepの実行アダプター接続と新契約の適用。** 今回は取得・表示・native前段の不足判定まで。dispatchを解禁する本接続は未実装。
3. native拒否を特定する境界記録、登録NOLOGIN等の拒否recipe、完全な関連IAM inventoryのproducer。足りない場合はUnknownで、伝播Pendingを捏造しない。

実アプリのRuntimeBindingはK11で、K10の未提供状態を保持します。追加の実機フィジビリティやクラウド操作を、これらのローカル実装の開始条件へ戻しません。
