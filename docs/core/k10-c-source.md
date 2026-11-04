# K10-C：GCE送信元確認・固定collectorと受入接続

更新（2026-11-03）：[EC2 source・AWS PG取得/GCP実行接続の続編](k10-native-source-execution.md)を追加しました。以下は本単位の完了時点の記録と当時の未実装・検証結果を保持します。現在の対応範囲・残差は続編を参照します。

2026-11-03。K10-Cの初期source profileを実装・ローカル検証しました。**既存GCE Linux VMの、管理者を信頼するrootセッションによるhost network観測**が対象です。実VMへの接続・配置・設定変更、Google署名の実token取得、実DB接続は行っていません。実環境での成立とは分けます。

## 実装と境界

| 箇所 | 責務 |
| --- | --- |
| [`core/source.rs`](../../src/core/source.rs) | source registration v2。SSH IP/port、Ed25519公開key、実行UID、collector binary digestを既存snapshotの信頼設定へ束縛。旧v1/Noneのdigestを維持 |
| [`adapters/source/gce_host.rs`](../../src/adapters/source/gce_host.rs) | 固定SSH呼出し、登録とreply/context照合、署名確認、選択資料への変換、sealed verifier生成、K10-B受入APIへの接続 |
| [`adapters/source/jwt.rs`](../../src/adapters/source/jwt.rs) | Google固定TLS endpointの鍵取得、ringのRS256検証、issuer/audience/期限/SA/VM世代の照合。任意issuer/鍵URLの設定なし |
| [`adapters/source/collector.rs`](../../src/adapters/source/collector.rs) | root所有config/binary、固定Linux context、metadata専用ID取得、許可endpointのTCP診断。任意shell/SQL/credential hookなし |
| [`adapters/source/process.rs`](../../src/adapters/source/process.rs) | 環境の消去、stdin/stdout/stderr上限、timeout/cancel、子process group停止と直接子の回収 |

単一crate/CLIのモジュラーモノリスを維持しました。coreはprovider/SSH/SQLiteへ依存しません。`guard observe`、v2 state/statusの表示接続、PG認証/SQL producerは後続D/Fです。v2 native dispatchは引き続き停止します。

## 初期profileと信頼する条件

recipe IDは`gce-host-network-root-v1`です。source registrationのschemaは2、source bindingのboundaryは`gce_host_network`、collector protocolは1です。

- controllerは固定の`/usr/bin/ssh`と`/usr/bin/curl`を使います。root所有でgroup/otherから書換えられないtoolを確認します。SSH用の明示private keyとprivateなwork directoryを用意し、管理credentialをrequestやsourceへ転送しません。
- sourceはLinux/systemd/cgroup v2のhost contextと、固定`/usr/sbin/ip`を必要とします。既定のlocal/main/default routing rule以外のselector、別namespace、未知cgroup、UID/実効UID差、登録との不一致は確認済みにしません。
- root所有・書換え制限済みのcollector/config、信頼するroot管理者とOSが前提です。一般ユーザーが変更できるshell初期化/rc/environmentからcollectorを差し替えられる構成を、このprofileでは採用しません。非rootの制限login shellは別契約の候補です。
- 観測scopeはVMのhost network境界と登録実行contextです。アプリPID、pool、container、ユーザー別の全経路を証明するprofileではありません。DB認証主体には登録済みVMサービスアカウントを使う契約とし、現在のCではDB認証そのものを未評価に残します。

root SSHの可否、必要tool、configの用意、Linux動作は実環境で未確認です。collectorからsudo/install/SSH設定変更/VM作成/IAM変更は行いません。sourceを使う具体的な配置・権限変更は、別途レビューする導入作業です。

## 取得・検証の流れ

1. `allow_native_read`を最初に確認します。未許可ならtool/key読取り・networkより前に停止し、cancelと元requestの期限も区別します。
2. source snapshotへ固定したEd25519公開keyだけを専用known-hostsへ保存します。既存ファイルの差替えを拒否します。未知keyをscanして登録する処理はありません。
3. SSHは`-F /dev/null`、StrictHostKeyChecking、固定host key alias、明示identityを使います。ProxyCommand/Jump、接続共有、forwarding、agent、password/keyboard-interactive、local command等を無効にし、remote commandは固定の`/usr/local/libexec/veil-db-guard source-collector-v1`です。requestをcommand文字列へ展開せずbounded stdinで渡します。[OpenSSH仕様](https://man.openbsd.org/ssh.1)、[設定仕様](https://man.openbsd.org/ssh_config)
4. collectorは`/etc/veil-db-guard/collector-v1.json`と自身のbinary/build、実行UID、namespace、boot/cgroup、interface名、routeとrouting ruleのfingerprintを前後で確認します。packet counterやsession番号の変動と、実際の設定変更を分けます。before/after一致をnative CASや変更不存在の一般保証とは扱いません。
5. VM内の固定`169.254.169.254`へ、Metadata-Flavor付きでfull identity tokenを要求します。metadata URL、ADC、gcloud、proxy環境変数、資格情報fileへのfallbackはありません。audienceはrequest nonce/digestへ束縛し、URLとしてfetchしません。
6. controllerでGoogleの署名、issuer/audience/時刻、SA email/sub/azp、project/zone/不変instance ID/作成時刻を照合します。Googleのfull tokenをVM identityの材料として使い、channel/collector/contextも合わせて確認します。[GoogleのVM identity仕様](https://docs.cloud.google.com/compute/docs/instances/verifying-instance-identity)
7. raw tokenを外し、VM識別情報、選択context、collector/config/binary digest、token digest・発行/期限/key ID、診断だけを資料化します。raw reply/tokenはSSH pipeとmemory内のephemeral protocolです。ログ・argv・artifactへ保存しません。
8. `capture_and_admit_gce`からK10-Bへ渡し、元のwindow/requestに一致するsealed verifierを一回だけ消費します。native取得と受入を別transactionにし、受入時にも現在trust/期限を再確認します。

Google署名keyの取得先は、公式OpenID設定にある`https://www.googleapis.com/oauth2/v3/certs`へ固定しています。TLS検証を有効にしたcurlをconfig/proxy環境の影響なしで使い、redirect/任意key URLを追いません。許可algはRS256、未知kid・不適合key・古いkey取得時刻は拒否します。[GoogleのOpenID設定](https://accounts.google.com/.well-known/openid-configuration)

## 現在の結果と拒否原因

固定caseのうちCで実行するのは、許可済みIP/portへの直通TCP診断です。Connected/Refused/TimedOut等を記録し、いずれも**新規DB接続のAllowed/Denied、IAM拒否、RouteBlockedへ昇格しません**。target/principal/route/TLSはUnconfirmed、DB認証/SQL/実runtime binding等のcaseはUnsupportedProducerとして残します。全体のcaptureもcompleteにしません。

source確認を通った資料はSource assuranceに限定してVerifiedとします。PG認証、native拒否根拠、TLS/SQLとcurrent effectの導出はDです。完成したCLIの全体保護判定は、現在まだ提供していません。

collectorのfailureはrequest digest付きの限定enumで返し、ContextUnverified/IdentityUnverified/Unsupported/期限切れ/Timeout等を区別します。stderrの生文を拒否原因へ流用せず、秘密の混入やIAM拒否への読み替えを避けます。SSHの認証/接続失敗は、ネイティブDBの拒否原因として推定しません。受入でのExpired/TrustChanged/Integrity等は内側のtyped errorを保ちます。

## 設定・bootstrapの用意

source registration v2は`gce_host`にSSH IP/port、Ed25519公開keyのbase64、collector binary SHA-256、execution UID 0を含みます。`execution_user`は`root`です。既存のhost key/config/network/build digestとtrust epoch、policy v2のsource snapshot参照も結びます。v1にprofileをdefaultで足すmigrationはありません。

collector configは`CollectorConfig`の厳格schemaです。registration ID、固定context、target ID/native ID/generation/databaseとendpoint/IP/portのallowlistだけを持ちます。任意SQL、shell、metadata/key URL、credential pathは受け付けません。

次の補助commandは、既に信頼するbuild/管理経路でのレビュー材料を得るものです。自動登録・承認・配置は行いません。

```sh
# Linux用collector artifactのbuild/protocol情報。networkを使わない。
./veil-db-guard source-build-info

# 許可済みのsource管理セッションでのみ、local contextを読取り。
./veil-db-guard source-context-v1 --allow-local-context-read
```

contextの出力は`source_verified=false`、`bootstrap_only=true`です。このJSON単体をnative証拠として受け入れません。operatorがVM/host keyの対応をtrusted経路で確認し、適切なsource snapshot/policyへ固定します。config digestは実ファイルbytes、自身のbinary digestは配置artifactのSHA-256、network digestは補助commandのcanonical `context_digest`です。registration revision digestは既存のlibrary/台帳APIが返すcanonical値を使います。

この作業では上記の実source command実行、root権限付与、key作成/配置、config作成、sshd変更をしていません。補助commandの非許可時停止とoffline build infoのみをローカルで検証しています。

## ローカル検証と依存

Rust 1.98.1/macOS ARM64の`mise run check`でformat、Clippy `-D warnings`、locked/offline回帰を実施しました。**418成功、失敗0、既存実DB2件ignored、45 test result**です。Bの392成功から、source unit 21件、CLI 4件、sealed verifierのcompile-fail doctest1件を追加しています。

- 一時RSA鍵をmemory内で生成し、実際のRS256署名検証を実行。issuer、audience、SA/VM/世代、期限、不正alg/未知kid/任意URL、重複keyを拒否。
- 正しい署名でもcontext/build/config/nonce/case/資料/windowが異なる場合の拒否、tokenの保存/Debug非露出、sourceだけVerified/DB側Unknownを確認。
- K10-Bの実SQLite/archiveへsealed verifierを接続し、offline再読取まで確認。肯定側はテスト専用鍵であり、productionのGoogle trust anchorへの置換機能はありません。
- 固定SSH argv/known-hosts差替え拒否、metadata HTTPの上限/長さ/header/redirect拒否、root contextのschema/UID rule/namespace境界、route/interface counterの扱いを確認。
- 環境消去、stdout/stderr上限、timeout/cancel、process group停止、loopback TCPの実tuple/拒否、CLIでの秘密非出力と任意hook拒否を確認。
- v1 policy/plan/change/approval、K10-Bの原子的受入/期限/破損、core単独コンパイル、v2 native適用停止を回帰。

実GCE、Googleが発行した実token、SSH handshake、Linux上のcollector実行は未確認です。Linux collector本体のUnix helperはmacOSでもtype checkしますが、Linuxの実行証拠へは読み替えません。追加フィジビリティ、クラウド操作、DB操作、公開、commit/pushは行っていません。

JWTの暗号演算は既存lockfile中の`ring =0.17.14`へ委譲し、encodingは既存`base64 =0.22.1`を直接依存として固定しました。新しいpackageや他の依存版は追加・更新していません。licenseはringがApache-2.0 AND ISC、base64がMIT OR Apache-2.0で、配布時の既存帰属を保持します。既知公告の対象範囲はRustSecで確認しました。[ringの修正版範囲](https://rustsec.org/advisories/RUSTSEC-2025-0009.html)、[旧系列の対象範囲](https://rustsec.org/advisories/RUSTSEC-2025-0010.html)、[base64の修正版範囲](https://rustsec.org/advisories/RUSTSEC-2017-0004.html)

実行記録は`runs/core-k10-c-local-20261103-1/check-verified.log`と`summary.json`です。**次はK10-D**で、PGの認証/拒否層・TLS/SQL資料を取得・正規化し、既存のpure state評価へ接続します。
