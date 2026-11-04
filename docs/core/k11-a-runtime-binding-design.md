# K11-A：runtime入力・生成・受入の詳細設計

2026-11-03。[K11作業設計](k11-work-plan.md)の最初の単位を、既存GCE host profile・PostgreSQL優先で具体化する。単一crateのcore → port → source adapter → CLIを維持する。今回実装する肯定的な事実は、**登録collectorが、選択したLinux process incarnationのFDと特定TCP socketとの対応を前後の標本で観測したこと**である。実DB session、認証主体、TLS、pool世代までを確認した`RuntimeBinding`ではない。

これはK11-Aの入力・生成・部分受入を実装するsliceであり、作業設計のA行全体の完了とは区別する。A行の実session/route/transportの結合に必要な未確認を保持する。アプリ向けbundle/token portはK11-B、driver/poolのcooperationはK11-C、復旧と閉鎖直前の結合はK11-Dに残す。今回の範囲だけで既存`RuntimeBinding` effectをSatisfiedにする方法は設けない。

## 1. 今回の成果と完了条件

runtimeの観測入力をimmutable request/source/target intentへ固定し、固定producerがprocess/socket観測を生成し、既存EvidenceLedger/Archiveへ保存・受入・offline再読取できるようにする。正常な部分観測からは有用なprocess/socket情報を取得でき、全effectの評価では不足をUnknownとして残す。

| 今回確認するもの | 肯定できる範囲 | 肯定しないもの |
| --- | --- | --- |
| process incarnation | boot ID、PID、開始tick、実行image digestを指定したprocessの前後標本 | PID番号だけによる同一process、標本間の継続実行、全threadの同一context |
| process context | UID/EUID、GID/EGID、net/mount/user namespace、cgroup/securityの選択値の前後一致 | 全LSM/seccomp/BPF programの同一性、root probeへの同じ許可関数 |
| FD/socket | 指定FDの`socket:[inode]`と同一network namespaceのTCP行のinode・exact tuple・ESTABLISHEDの対応 | FDの排他的所有、socket作成者、アプリdriverがそのFDを使用したこと、成功したDB認証 |
| source/context | 登録snapshot・trust epoch・build・request nonce・case・scopeに束縛されたcapture | 外部JSONの自己申告、host管理者やkernelを敵対者とした保証 |
| target intent | requestとendpoint設定で選んだnative ID・generation fingerprint・database・route | socketが接続したDB実体の世代、実sessionのDB/user、TLS peer、pool世代 |
| admission | K10の保存・commit・元時刻・現在trust・鮮度を再利用した部分受入 | 受入成功による`RuntimeBinding`、`NewConnectionsDenied`、native closureの成立 |

外部操作は行わない。Linux native producerのコードを追加しても、今回macOSで実施する合成fixture/ローカル試験をLinux配置・GCE実行・実DB接続の検証と呼ばない。cloud API、SSH、collector配置、権限変更、実DB、公開は今回の実行範囲に含めない。

## 2. 信頼境界と入力

アプリやoperatorのJSONは要求・選択値であり、確認済み事実ではない。アプリが返すPID、FD、connection ID、pool generation、`confirmed`等からauthorityを作らない。登録されたroot-owned collector設定とbinary digestをsource snapshotへ固定し、その設定が対象grant/subjectに対して選んだprocess selectorとFDだけを取得対象にする。PID discovery、任意command、環境変数credential、SDK fallback、任意procfs pathのimportは設けない。

既存host trust boundaryと同様、kernel、procfs、root/collector管理者、固定binary/config、認証channelの完全性を前提にする。untrusted workloadがそれらを変更できる環境はこのprofileの外である。特定processをgrant/subjectへ選ぶ設定自体は管理上の選択であり、それをDB認証主体の観測と表現しない。

core入力は以下を分離する。

| 型/資料 | 役割 |
| --- | --- |
| `RuntimeProcessSelector` | `pid`、`expected_boot_id`、`expected_start_ticks`、`expected_executable_digest`。processの同名再起動やimage差替えを自動追従しない |
| `RuntimeCaptureContext` | issued request/caseから導出したrequest digest、policy/change/operation、source snapshot/trust epoch/build、`EffectAddress`。`RuntimeBinding`のapplication caseに限定 |
| `LinuxProcessSocketSnapshot` | boot/PID/start/image、UID/GID、namespace、cgroup/security digest、FD/inode、TCP state、`ConnectionTuple`の一標本 |
| `LinuxRuntimeCaptureWire` | version、context、before/after。Deserializeできる未信頼のwire |
| `ValidatedProcessSocketCapture` | pure core validatorを通った整合的な部分値。private field、Serializeのみ。生成元の認証やadmissionを代替しない |

core validatorのexpected contextはissued requestから導出する。native producerは固定設定のselector・FDと固定endpointに対して観測値を照合する。controllerは認証済みの固定producerがこの照合を行ったことを信頼し、responseの前後標本をさらに構造検証する。controllerが応答から組み立てたselector/tupleの自己照合だけで、設定との独立した照合を行ったとは表現しない。この経路はraw JSON向けの認証APIではない。target generationはcontextに含まれるが、ここで確認したのはrequestとの一致である。実DB世代をnative readで再確認した意味を持たせない。

## 3. Linux producerの選択手順

固定root collectorは既存budget/cancel/期限内で次を実施する。IPv4 TCP・指定FDを初期対応とし、IPv6、Unix socket、別namespace/container profile、任意pool発見を暗黙に補完しない。

1. root、固定設定、source context、requestのcase/target/subject/route対応を確認する。selectorとFDの数・範囲を制限し、追加権限や外部toolを取得しない。
2. `/proc/sys/kernel/random/boot_id`と`/proc/<pid>/stat`のstarttimeをselectorと照合する。PIDやprocess名だけをincarnationとしない。`stat`のcomm内の空白・括弧を考慮し、field 22を正確に読む。
3. processの実行imageをhashし、選択したdigestと照合する。`cmdline`、`environ`、process memoryを取得・保存しない。imageのhashは実行中memory全体や依存libraryの完全性を示さない。
4. `status`からUID/EUID、GID/EGIDと、security digestの対象となるUID/GID各値・Groups・capability・NoNewPrivs・Seccomp等の固定fieldを読む。`attr/current`のLSM label、`cgroup`、net/mount/user namespaceを選択する。security digestはこの選択集合のdigestであり、適用policy全体のdigestではない。
5. `/proc/<pid>/fd/<fd>`のreadlinkからsocket inodeを取り、`/proc/<pid>/net/tcp`でそのinodeとexact IPv4 source/destination address/port・TCPを照合する。ESTABLISHED以外、行欠損、曖昧な複数一致を肯定しない。table読取後にFD linkとstatを読み直す。
6. 二つのsnapshotを取得し、全固定値・context・FD/inode/tuple/stateの一致をcoreで確認する。権限不足、process終了、parse失敗、取得上限超過、context変更、cancel、期限切れは部分事実を肯定しない。

`/proc/<pid>/net`はそのprocessのnetwork namespaceの情報であり、process固有socket一覧ではない。従ってnet tableだけでは帰属せず、FD linkのinodeとの対応を必須にする。socketを継承・共有・受け渡しできるため、この対応も「当該processが標本時点でFD参照を持つ」という範囲である。TCP行のUIDを現在のprocess UIDと同一視しない。[Linux man-pages: proc_pid_net(5)](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html)、[proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)。

実装は最初に`O_DIRECTORY|O_NOFOLLOW`で開いたprocess directory descriptorに対して`openat`/`readlinkat`で相対読取する。Linux kernel資料では、開いたproc descriptorはprocess終了後に同番号の新processへ切り替わらず、通常ESRCHとなる。ただしPIDの再利用そのものは防がない。boot IDだけは固定global proc pathから読む。[Linux v6.12 proc filesystem](https://www.kernel.org/doc/html/v6.12/filesystems/proc.html)。

前後一致は取得した標本の整合性であり、その間にFD、実行image、security contextが一度変わり戻ったことを一般に排除しない。pidfdを採用しても、この観測全体がatomicになるわけではない。pidfdはprocess参照や終了監視のための別手段であり、proc pathnameやFD利用の全履歴を証明しない。[pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)。この制限のまま全RuntimeBindingへ昇格しないことが、今回の受入境界である。

proc小資料は32 KiB、TCP tableは1 MiB、linkは256 byte、実行imageは128 MiBを上限とする。実行imageは16 KiBごとにcancelを確認する。同期filesystem readの最中はcooperative cancelであり、remote/FUSE由来の実行image等に対するhard deadlineをin-processのtimeoutだけで保証しない。controllerがcollector subprocessへ持つ既存の外側deadlineが停止の境界になる。今回そのLinux運用を実測したものではない。

## 4. 生成元確認・admission・再読取

coreのpure validationはshape/scope/整合性確認であり、署名やnative originではない。adapterは既存の固定collector、pinned source channel、VM identity、binary/config digest、capture windowの確認を通したcaptureだけを正規化する。saved wireからこの認証経路を再作成するpublic constructorやCLI importは設けない。

観測資料と選択された部分captureを既存payloadへ保存し、そのdigestをbundle/source proofへ結ぶ。`ObservationVerifier`はrequest/source/window/bundle/payloadとの対応を検証し、通常のEvidenceAdmissionでarchive保存 → 整合性再読取 → atomic ledger commitを通す。別のruntime専用台帳・別state evaluator・operator approval booleanを追加しない。

受入後のoffline loadは、原request、receipt、source snapshot、現在trust epoch、許可build、payload digest、元時刻と期限を再確認する。再読取によって観測時刻を更新しない。保存JSONをcopyしても台帳の受入記録がなければauthorityを持たず、rawな`ValidatedProcessSocketCapture`単独もnative実行gateの入力にならない。部分情報をAPIで公開する場合、その公開値にadmissionの有無・元request・payload digestを失わせない。capture認証とadmission済みの型・説明を分離する。

## 5. stateとnative gate

既存`FixedObservationCase::RuntimeBinding`と`EffectKindV2::RuntimeBinding`を使う。process/socketの有用な部分値を保存しても、claimは`Unknown(RuntimeBindingUnverified)`を保持する。source authenticityが確認されることと、actual application/session attribution・effect satisfactionが確認されることは別である。

以下は常に未確認として明示する。

- DB protocol・接続先DB実体の世代・native session ID・認証DB user/principal。
- TLSの有無・証明書・hostname検証・各区間のtransport保証。
- 実アプリdriverによるsocket利用、credential provider、refresh/revocation。
- pool/connection generation、新規接続への切替、旧sessionの存続。
- root kernel probeとapp socketに同じ許可関数が適用されること、独立recovery、cutover成立。

`BindingApplied`の新しいruntime成立条件を弱めず、現在のSourceStepGate、独立recovery、変更後の新規接続・時刻・鮮度の要求を維持する。root probeの拒否やruntime socketのESTABLISHEDを、`RouteBlocked`、`NewConnectionsDenied`、全保護成立へ変換しない。明示的な成功・現在Allowedが既存観測にある場合も消去しない。

## 6. ローカル受入試験

| 試験 | 必須期待値 |
| --- | --- |
| 合成fake app/socketの正常な前後標本 | process/socket部分値を取得できる。RuntimeBindingと閉鎖gateは未成立 |
| process再起動、PID同番号、boot/start/image差分 | selector不一致で肯定しない |
| UID/GID/ns/cgroup/security/FD/inode/tuple/state変更 | そのcaptureを肯定しない。欠けた値を既定値で補完しない |
| net tableの別process socket・別FD・重複・非ESTABLISHED | 部分帰属を肯定しない |
| grant/subject/case/target generation/route/source/trust/build/requestの差分 | 別contextからの貼付けを拒否 |
| TLS/session/pool/credential等の持込JSON、unknown field | trusted factへ昇格できない |
| SQLite/archiveへの部分受入とoffline load | 元digest/時刻/不足を維持し、RuntimeBinding Unknown |
| payload改変、台帳なし持込、replay、trust更新、保存中expiry | K10の既存拒否条件を維持 |
| 非Linux、非root、permission/missing proc/cancel/budget | Unsupportedまたは明示失敗。root化・権限変更・別producerへのfallbackなし |
| v1・runtime未設定・既存K10 source producer | bytes/旧契約・挙動の互換性を維持 |

fake app/poolはローカル合成入力であり、PostgreSQL driverとの接続を模倣したと主張しない。macOS上でLinux専用native読取を実行できない項目は未実施と記録する。既存の`mise run check`、architecture試験、必要な新しい正常/境界/異常/回帰でローカル受入を判断する。

## 7. A内で残せる改善とB/Cへの引継ぎ

Aを空のUnknown生成器にしないため、requestと固定producerを接続し、process incarnation、FD/inode/exact tuple、source証明、保存digest、元時刻を再利用可能な部分値として残す。追加改善は、process directory descriptorによる固定、bounded proc読取、厳密なparse、contextの重複/省略拒否、部分値のadmission済み再読取APIに限定できる。新サービス、eBPF導入、driver改修、全thread policy追跡は今回の必須範囲に追加しない。

B/Cでは、この同じrequest/source/process/socketの参照を、実アプリ側のnative session・driver transport・認証provider・pool世代の観測へ結ぶ必要がある。アプリの自己申告だけで確認済みにする設計にはせず、DB側sessionとの対応、接続生成時点、target世代、channel/producerの信頼根拠を別途定義する。その契約が満たされて初めて共通RuntimeBinding評価への肯定的な入力を追加する。今回の部分観測はその入力材料であり、将来の成立を先取りしない。

## 8. 設定例と利用経路

以下は既存collector configへ追加する**合成例の断片**であり、実プロセスの観測値ではありません。selector値とFDは管理者が対象appの実際の値へ置き換え、config digest/source revision/policy/plan/承認/requestを更新する必要があります。今回この登録・配置操作は実行していません。

```json
{
  "runtime": {
    "bindings": [{
      "target_id": "billing-db",
      "grant_id": "billing-access",
      "subject_id": "billing-app",
      "selector": {
        "pid": 4242,
        "expected_boot_id": "11111111-2222-3333-4444-555555555555",
        "expected_start_ticks": 123456,
        "expected_executable_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      "socket_fd": 12
    }]
  }
}
```

`guard observe-plan`は一致するtarget/grant/subjectのRuntimeBinding caseを追加します。`runtime`未設定・対象不一致なら従来どおり未取得effectへ残します。実取得は既存の明示native-read権限とsource登録を要求する`guard observe`経由です。取得済みstate/statusは従来のoffline経路を使い、`row.history[].claim.runtime_capture`で元の部分標本を保持します。観測の失敗codeはsource payloadのdiagnosticへ保存し、未知の欄を成功値で補完しません。

新しいpackage/service/DB/schema台帳や依存は追加していません。Unixのdescriptor primitiveはmacOSでも型検査されますが、Linux procfsの実動作は今回実行していません。

## 9. 実session結合への設計判断

OS観測だけで任意の既存アプリのDB利用・認証・poolを保証する方式は採用しません。最初の完全結合は**管理対象アプリのPostgreSQL driver協調方式**とします。初期adapterは既存依存と同系統のRust/tokio-postgres、Linux上の同一process内でconnection生成を所有するwrapperを対象とし、任意言語・任意poolへの無改修適用はUnsupportedとして残します。これは次のB/Cの実装対象を選ぶ設計判断であり、このwrapperを今回実装・検証した意味ではありません。

信頼契約は「登録された管理対象appの固定buildとdriver instrumentationを信頼する」です。root collectorの署名だけでappの任意自己申告を信頼する契約へ変えません。app build/imageと同じprocess incarnationで動く固定instrumentationが、実際に生成しappへ渡すconnectionを所有し、そのconnectionからのみreceiptを作る必要があります。悪意あるapp、任意memory改変、未登録driver、poolがそのwrapperを迂回する構成は保証範囲外です。新契約はpolicy/hash/承認に明示して選び、旧RuntimeBinding証拠を自動昇格しません。

B/Cの実装へ渡す境界を以下に固定します。

1. Bのconnection bundleはendpoint/database/userとtarget/source世代、credential provider reference、desired connection/pool generationを持ちます。password/tokenをartifactへ入れず、native token portからメモリ内だけでdriverへ渡します。bundle発行はRuntimeBinding成立ではありません。
2. Cのwrapperは新connection作成時に実際のsocket FD/tupleとdriver TLS設定・結果を取得し、同じdriver connectionで固定read-only session identity queryを実行します。DB名・session/current user・backend PID・session開始識別・target世代の独立native取得と相関させ、別のcollector probeをapp connectionへ転記しません。Proxyによってbackend対応が観測不能なら、その項目はUnknownです。
3. collector発行nonceを持つ固定local protocolでreceiptを回収し、Linux peer credentialのPID/UIDと今回のincarnation/FD標本、固定app build、request/case、connection generation、pool generationを照合します。受け取ったJSON、peer credential、backend PIDのいずれか単独で完全成立にしません。local endpoint・message size・deadline・同時数は固定し、任意commandの入口を作りません。
4. 同じconnectionでの観測と、appがそのpool世代へ切替済みであることを分けます。pool切替receiptは新旧generationと、wrapper経由の実app利用を持ち、旧sessionの残存は別effectに残します。process再起動・token refresh・pool未切替・capture途中変更はUnknown/Pendingを維持し、generationを自動追従して成功にしません。
5. この契約の選択と必要なreceiptが揃うまで、K11-Aの部分captureはRuntimeBinding Unknownのままです。Dの独立recovery・変更直前再取得・閉鎖gateも別条件として維持します。

次の作業は追加のクラウド実験ではなく、Bのbundle/token portとCの最小driver wrapper・fake app/poolによるローカル実装です。source/nonce/SQLite/archive/共通stateは今回の実装をそのまま利用します。

## 10. 今回のローカル検証結果

`mise run check`の最終実行は、fmt、all-target Clippy（`-D warnings`）、**652成功・0失敗・実DB用2件ignored（48 result groups）**で完了しました。Rust 1.98.1 / macOS ARM64、locked/offlineです。結果は[summary](../../runs/core-k11-a-local-20261103-1/summary.json)、[最終check log](../../runs/core-k11-a-local-20261103-1/check-final.log)に保存します。実SQLite/archive、合成procfs資料、合成署名source fixture、型のcompile-fail試験を含みます。kernelを分離したarchitecture試験も通過しました。

Linux/GCEへの配置、SSH、実アプリ/実PostgreSQL接続、クラウド操作、追加フィジビリティ試験、依存追加、権限変更、公開・commit/pushは行っていません。Linux producerと実DB/driver/poolの統合が実運用で確認済みという結果ではありません。
