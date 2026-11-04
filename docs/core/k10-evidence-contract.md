# K10 詳細契約：source参照・bundle受入・実効評価

2026-11-03更新。[EC2 source・PG/MySQL取得とGCP/AWS実行接続](k10-native-source-execution.md)を実装・ローカル検証しました。A〜Fの初期接続が一巡し、AWS sourceは独立したidentity/channelから受け入れます。GCP PGとAWS PG/MySQLは`source-bound-execution-v3`契約で変更前/後を分け、旧v1/evaluation-v2の読取・hash・承認の意味は維持します。新契約には再plan/再承認が必要です。native拒否・backend TLS・完全なinventory等が残り、全体保護の成立やK10全条件の完了とは区別します。実クラウド・SSH・DB操作や追加フィジビリティ試験は行っていません。

## 1. sourceの意味を承認へ固定する

policy v2では、既存の`workload_sources`が参照する各IDについて、`source_bindings`へ次を含めます。

| 要素 | 意味 |
| --- | --- |
| source ID | policy内で使う論理ID |
| registration ID／revision digest | ローカルregistryの不変snapshotへの参照 |
| boundary kind | 初期は`gce_host_network`。app PID／containerの意味へ読み替えない |
| 許可するsubjectと用途 | application／recovery／controlを分離し、管理credentialのapp source利用を禁止 |

registry snapshotにはnative VM世代、SSH host key、collectorの許可build／配置・実行境界、network context、trust epoch、credential取得方式の参照を含めます。秘密鍵・tokenは含めません。source定義の差替え、VM再作成、host keyやcollector trustの変更は、新snapshot・policy revision・新承認を必要とします。IDが同じという理由で既承認operationへ差し替えません。

新証拠を利用するnative閉鎖・失効確認stepは、source snapshot digestと評価契約版をparametersへ束縛し、当該actionのadapter contract版を更新します。registry／qualificationもpolicy文脈で契約を選びます。既存のtargetだけを受けるAPIはlegacy用wrapperとして残し、v2対応を暗黙に推定しません。

v2のcanonical hashはv1と別のdomain/versionで計算します。v1を読んでから新しいdefault fieldを足して再hashする方式にはしません。旧approvalが参照するchange／policy bytesの意味を保持し、source定義や受け入れる拒否層を変える場合は新しいdiffへ出します。

## 2. 三つの入力と受入台帳

| 設計上の型 | 主な内容・役割 |
| --- | --- |
| `ObservationRequest` | request ID、暗号学的乱数nonce、policy/change/operation、target世代、source snapshot、subject、route/endpoint/family、許可した固定case、契約/build、期限・上限。書込み権限を含まない |
| `ObservationBundleWire` v1 | request digest、collector情報、選択したnative応答、試行とcontrol、時刻、artifact参照。**全体を未信頼inputとして扱う** |
| `VerifiedObservationFacts` | verifierが受け入れたtyped factsとassurance coverage。外部JSONから直接deserializeできる「確認済み」型にしない |
| `EvidenceAdmission` | verifier build／契約、source trust epoch、request・bundle・policy・target・source digest、受入時刻と期限、検証結果の参照をローカル台帳へ保存 |

policyの任意payload、任意shell、任意SQLをrequestへ入れません。wireの`confirmed:true`や保存済みverdictを受理するAPIも作りません。code内のverifier portは既存executorと同じtrustedなRust組立て境界です。差替え可能な未信頼pluginへ確認権限を渡しません。

受入の順序は、bounded parse→request/registry照合→channel・native identityとcontext確認→対象・route・資格情報・時刻・case確認→artifact保存完了→受入台帳commitです。保存が先に終わり台帳commit前に停止したbundleは未受入のまま保持します。受入済みartifactが欠ける／digestが変わる場合はIntegrityErrorとし、空の「成功」を作りません。

同じnonceは一つのbundle digestへだけ原子的に受け入れます。同じbundleの期限内再評価は許可し、再評価で観測時刻を更新しません。別payloadへの使い回し、期限切れrequest、新nonceへの古い試行の貼付けを拒否します。

manifest/hashはファイル整合性です。受入台帳なしの持込bundle、tokenのclaimsだけをコピーしたJSON、自己署名した結果は確認済みになりません。ID token／access token／IAM token／秘密鍵はmemory内に留め、wireの永続版・ログ・argvへ保存しません。選択claims・digest・受入参照を保存します。別hostへの完全な真正性付きportable exportは初期K10の対象外です。

## 3. 独立したassurance

各項目は`Verified / Unconfirmed / Unsupported`と根拠参照を持ちます。scopeに不要な項目は、契約が理由を示して`NotApplicable`にできます。単一の`identity_confirmed`へ自己申告を集約しません。

| 項目 | Verifiedにする条件 |
| --- | --- |
| Target | 登録native ID・generation・engine/databaseと、認証済みnative取得・実接続routeの対応 |
| Principal | credentialを発行・使用した不変主体と、policyの主体・DB identityの対応。管理者のcredential取得成功だけでapp主体を確認しない |
| Source | source snapshot、認証channel、native VM identity、固定collector・network contextが一致 |
| Route | 登録hostname・実際の宛先IP/family・port・経路、試行のlocal/peer tupleが一致。aliasやNAT先を推測で広げない |
| Transport | 区間別のTLS／local IPC条件。暗号化とCA／hostnameの検証を別factにする |
| Temporal | request・試行・control・metadataの時間範囲と期限が整合。新しい保存時刻で古い試行をfreshにしない |
| Completeness | 必須case、address family、negativeとcontrol、必要なmetadataがscope内で揃う。capture全体と行別の完全性を分ける |

native metadataの前後一致は観測できたdriftを拒否する材料です。read-compare-readをCASやsession中の変更不存在の証明にはしません。nativeのidentity／route契約で世代を束縛できない場合、または契約が必要とする外部変更window等の前提が不足する場合は、当該assuranceをUnconfirmedに残します。既存AWSの非CAS制約は消えません。

controllerとcollectorのbuild IDは分離します。許可したcollector artifact/build、verifier build、evidence/evaluation contractの組合せを検証し、異なるbuildを同じ文字列へ書換えて通しません。旧記録の現在評価に必要な組合せが未承認なら履歴・diagnosticのみです。

## 4. 効果と拒否層を分ける

評価v2は次の二つを分離します。

- **EffectAddress**: target世代、grant／subject／DB identity、source snapshot、route、効果の安定した宛先。
- **ObservationClaim**: その宛先について、実際に得た結果、native層・原因、TLS、時刻、controlと根拠。

policy revisionと要求する原因・層は別に保持し、現在revisionへ正確に結びます。AllowedからDenyへの承認済み移行で、古いAuthenticationの正例をConnectionAuthorizationの証拠へ書換えません。前後比較は同一EffectAddressと台帳のrevision遷移を使い、旧claimの層・hashを保持します。

| 要求する効果 | 受け入れる根拠 | 代用しないもの |
| --- | --- | --- |
| 正規経路の新規接続Allowed | 確認したsource／principal／targetで、新しい接続・必要なTLS・正確なDB user/database | 設定反映、token発行だけ、管理接続だけ |
| direct routeの拒否 | 同じsource／宛先／familyの試行と、原因を照合したnative route拒否。証拠recipeを満たす場合だけ成立 | timeout、単独RST/ConnectionRefused、SQL login拒否 |
| IAM接続認可の拒否 | 有効credentialの不変主体と対象actionを確認し、対象に対応した明示的認可拒否 | token取得失敗、別APIのAccessDenied、NOLOGINだけ |
| DB loginの拒否 | 検証済みtarget/channelからの明示login拒否、対象loginの登録・状態、適切な健全性control | 一般的なPAM/1045、TLS失敗、DB不調 |
| 所有SQL deltaの回収 | 先行成功receipt、所有delta、現在の同じdeltaがないこと | 全実効権限の消失 |
| 実効SQL権限のPresent/Absent | 確認したDB identityに対するengine固有の現在の実効権限。継承・PUBLIC・scopeを含む必要範囲を確認 | GRANT/REVOKE成功だけ、owned delta absentだけ |
| Bindingの稼働 | 信頼するruntime連携が返す、実行中binding revision／route／principalとの対応 | ファイル生成、操作者のhandoff宣言だけ |

policy v2では、停止要求に許す拒否層を明示します。「新規接続停止」にDB login拒否を許す契約と、「IAM認可で停止する」契約は別です。IAM必須の要求をDB側の拒否へ弱めません。旧v1のDeny意味はそのまま保持し、v2の選択を新しい承認対象にします。

SQLの先在権限が残ればPresentを残します。全実効権限Absentが要求されているのに先在権限が残る場合はNeedsAction／Unknownであり、greenにするために未所有権限を削除しません。

## 5. controlと原因の根拠

controlは`SameSourceRouteReachability / TargetHealth / CredentialValidity / NativeBoundaryDecision`等の用途を持ちます。取得元の異なる成功を、同じsourceの到達性へ流用しません。

認証済みtargetからDB拒否応答を取得している場合、そのchannelの到達証拠と独立recovery sourceのTargetHealthを組み合わせられます。TLSすら成立していない負例に、別sourceの成功を付けて「本人のIAM拒否」にしません。正例control自体もrequest・世代・時刻・sourceの検証対象で、自己参照・循環参照・未確認controlを拒否します。

direct拒否recipeは、取得したtuple・試行時間と、既存の認証済みnative拒否記録／境界の決定を対応付けます。例えばGCP firewall logにはconnection tuple、disposition、rule参照があるため、該当する記録を照合するadapterを作れます。ただしrecord単体・別経路・Cloud SQL側の全拒否をカバーする証拠とはしません。[Googleのlog形式](https://docs.cloud.google.com/firewall/docs/vpc-log-format)

ログが未設定・取得不能・欠落・遅延なら、原因未確認を残します。ログなしを通信なし／拒否の証拠にせず、K10からログ有効化・rule追加をしません。既存loggingのAPI読取・費用・権限も実行時の明示scopeです。native connector必須化等を使うrecipeも、設定だけでは完了せず、そのnative拒否を識別できる証拠と対象範囲を必要とします。

tupleの再利用、複数候補、時刻の不確実性、NAT前後の対応不明がある記録は、一件を都合よく選んで該当試行へ結びません。相関を一意にできない場合はRouteUnconfirmedに残します。

## 6. TLSとlocal IPCの必須条件

VerifiedTlsの要求を、接続Allowed一行の裏に隠しません。評価v2はprofileの各区間を必須coverage／効果行として導出します。

- AWS Proxy等へのclient TLSは、driverが同じhostname・CA条件を検証した実接続を根拠とする。
- GCPのlocal Auth Proxy接続は、登録した保護IPC／process境界と、その先の認証されたconnector transportを分ける。localでsslmode=disableだからといって、remote区間を未暗号化／検証済みと推定しない。
- DB側の`pg_stat_ssl`等は、そのDB sessionでの暗号化の材料であり、上流clientやProxyによるCA／hostname検証の証明ではない。
- 実際に起動した許可buildのconnectorと設定・native target契約から導出する場合は、adapter recipeと根拠を明示する。観測できないbackend検証条件はUnconfirmed／Unsupportedに残す。

TLS区間が不足したprofileを、認証成功だけで全必須条件成立にしません。TLS失敗はUnauthorizedやRouteBlockedへ変換しません。

## 7. Binding・設定・SQLの正規化

手動checkpointは`PublicationAcknowledged / CutoverDeclared`という操作上のfactとして保存します。`OperatorAttestation`をAdapterValidatedへ変換しません。`RuntimeBindingVerified`のproducerは独立portとし、K11のapp/pool連携がない環境ではその必須行がUnknownに残ります。

native設定、SQL postcondition、所有receiptは現在の世代・identity・取得時刻と照合します。過去のapply成功を現在の状態へ使いません。K10のSQL producerは固定catalog／権限照会だけを使い、顧客行や任意の業務SQLを取得・試行しません。role membershipの存在と、そのrole経由の全実効権限は別factです。parseできない継承や共有影響をAbsentへ変換しません。

SQLのfactには、session_user／current_user／active role等の該当する認可contextと、取得できるDB identity／objectのcatalog identityを結びます。同名のlogin／tableの再作成を古い所有差分と同一視しません。旧ownership記録に新契約で必要な識別根拠がなければ、v2の所有回収根拠には昇格しません。権限のPresentは宣言したACL契約内の結果であり、RLS、trigger、制約、業務transactionの正常動作全体を確認した意味ではありません。

## 8. freshness・部分結果・Pending

初期実装の設計上限は、1 request＝1 source、同時source最大2、source内試行最大8、request TTL最大120秒、capture全体最大45秒、単一接続最大10秒、固定SQL最大3秒、bundle最大8 MiBとします。これらは予算値で、実測性能や全case完了の保証ではありません。上限で打ち切った行はPartial／Unknownです。

一回のobserveはsource最大8、全artifact最大64 MiBとし、個別bundle上限だけで無制限に取得しません。台帳へ同時発行する未完了requestも16件に制限します。保存quota不足は部分結果・未受入を残して停止し、古い証拠の自動削除や上限の自動引上げをしません。token・鍵資料・metadata・SSH stdout/stderrにも個別byte上限を設け、未知field・重複ID・過深な構造・無制限paginationを拒否します。

current評価の既定freshnessはcapture開始から60秒です。controllerの送受信時刻・monotonic経過とremote時刻を検証し、許容skew初期値5秒を超える場合はTemporalUnconfirmedとします。controllerの時間範囲で保守的に有効期限を狭めます。control近傍の許容幅も明示し、時間不確実性が幅を超えればcontrolを成立にしません。tokenの期限から将来の接続拒否や既存session終了を導きません。

部分bundleでも、受入条件を満たす個別のAllowedは保持できます。capture全体の未完了で成功事実を消さず、部分結果から全体をSatisfiedにはしません。重なるAllowed/DeniedはAllowedを隠さず矛盾／Mixedとして残し、成功したから必ず安全とも、後の拒否一件で前の成功が消えたとも扱いません。

Pendingには、同じEffectAddressの承認済み変更、完全な関連permission前後差分、変更前Allowed、現在Allowed、有限deadlineを必要とします。管理binding一件の削除を全permission inventory completeへ変換しません。残る別grantや継承権限が未取得なら、原因未確認／NeedsActionと現在Allowedを残します。期限後はNeedsAction／FailedPartialへ進み、古いAllowを自動復元しません。

## 9. 評価器と互換性

評価v2では、Layerを含む旧scopeのまま全claimを複製する方式を採りません。EffectAddress、要求条件、assurance、control graphを受け、明示したadapter recipeの導出結果だけをpure evaluatorへ渡します。state v1の鮮度・履歴・矛盾・有限Pendingのロジックは可能な範囲で共通化し、別の状態機械を二重保守しません。

旧policy／state／capture／approval／ownership記録は既存readerを保持します。source定義・TLS coverage・新しい拒否層選択を、v1のhashやboolをそのまま使って新契約へ昇格しません。policy v2と評価契約版の導入、影響actionのcontract更新、再plan・再承認を必要とします。

`protection_evaluated`は対象scopeでfreshな受入証拠を評価したこと、`all_required_effects_satisfied`は現在の全必須効果・assuranceが成立したことです。前者trueでも後者falseになれます。scope外、unsupported、欠落の行を集計から落としてgreenにしません。Operation Completedは独立の表示です。

設計上のCLIは`guard observe ... --allow-native-read`で明示的な取得・受入を行い、`guard state/status --evidence-bundle ...`は受入済み証拠のoffline再評価とします。後者から資格情報取得・live query・SSH・cloud APIを起動しません。初期K10のreaderは受入台帳とtrust epochを参照し、移入しただけのbundleを確認済みにしません。
