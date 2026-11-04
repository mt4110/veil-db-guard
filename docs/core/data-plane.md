# 接続経路と実効制御の設計

設計日: 2026-11-02。対象は、既存DBを移し替えず、アプリの正規接続を通し、許可していない主体・経路・DB操作を制限するデータプレーンです。本書は次の実装に向けた契約案であり、共通adapter・導入操作・常駐運用が現在すべて実装済みという意味ではありません。今回は設計だけを行い、追加試験・API操作・環境変更は行いません。

[要求](../requirements.md)の主要RDBMS構想を保ちます。最初の縦切りはGCP上のPostgreSQL 16、続いてAWS上のPostgreSQLとMySQLを対象とします。他の配置先・エンジンもadapterを追加できる対象として残し、対応済みとは表示しません。

## 1. データプレーンが担う保護

アプリのDB通信は、選択した配置先・エンジンで利用できるnative Proxy、connector、DBの認証・権限、ネットワーク境界を通ります。Veilの共通control planeは、その経路を構成・移行・維持するための意図、差分計画、承認、操作履歴、実効状態を扱います。

検証CLIはこの構成の観測部品です。CLIが停止しても通常のDB通信を止める構成にはしません。Veil独自のSQL wire proxyや、すべてのSQLをVeilサーバーへ送る仕組みを前提にしません。

| 保護する性質 | 主な実効制御 | 区別する事実 |
| --- | --- | --- |
| 新規接続の主体制限 | native接続認可、DBログイン認証、到達経路 | TCP到達とDBログイン |
| 迂回経路の制限 | firewall/SG、network policy、native connector必須化等 | 認証拒否とネットワーク境界 |
| DB操作の制限 | DB user/account、role、object権限、native制約 | クラウド接続権限とSQL権限 |
| 通信区間の保護 | 区間ごとのTLS・信頼先検証、local endpointのアクセス制御 | connectorのローカル区間とクラウド側区間 |
| 既存sessionの扱い | pool drain、特定したsessionの終了、native運用機構 | token期限、新規ログイン禁止、既存session終了 |
| 保護状態の維持 | native構成の保持、credential更新、差分観測と承認済み変更 | 一度の接続成功と継続的な保護 |

共通の入口は、誰の、どの実行元からの、どのDBに対する、どの接続・操作を許可するかです。正規アプリが持つ権限を使った全操作の防止までは含めません。共有DB accountや、アプリ実行元を特定できない経路があれば、その制約を移行計画と保護状態へ残します。

## 2. 配置とエンジンを分ける

一つのクラウド名を一つのDB機能と結び付けず、次の二軸を組み合わせます。

| 境界 | 責務 | 担当範囲外 |
| --- | --- | --- |
| `DeploymentAdapter` | 実resourceの同一性、配置、native接続経路、cloud/workload identity、接続認可、network、Proxy/connector runtime、provider側の変更・復旧 | 任意SQLの解釈、DB権限をcloud IAMだけで代用すること |
| `EngineAdapter` | DB identity、account/roleの対応、SQL権限、継承・既定権限、catalogの選択読取、session特性、DB側の変更・復旧 | firewallやcloud IAMをDBのGRANTとして扱うこと |
| 共通control plane | `PolicyRevision`、`CapabilityDescriptor`、`ChangePlan`、`ApprovalGrant`、`Operation`、`StepAttempt`、実効状態の集約 | 通常のSQL通信の中継、未対応機能の推測実行 |
| アプリ側integration | 接続設定の適用、workload identity/credential取得、pool・再接続、互換性に関する状態通知 | DB管理者権限、暗黙の直通fallback |

組合せは例えば`GcpCloudSql × PostgreSql`、`AwsRds × PostgreSql`、`AwsRds × MySql`、`SelfManaged × PostgreSql`です。同じPostgreSQLでも、Cloud SQL connectorとRDS Proxyを同じ常駐部品として表現しません。同じクラウドでも、PostgreSQLのDB identity・GRANT・session動作をMySQLへそのまま流用しません。

adapterはまず一つのRust実装内で明示登録します。設定から任意の実行ファイル、plugin、shell、SQLを読み込む仕組みは作りません。native toolやIaCは、adapterが定義した入力・操作の範囲で選択します。

### 実resourceの世代と状態

接続先の名前やendpointだけを、登録済みDBの同一性にしません。

| 参照 | 内容 |
| --- | --- |
| `TargetHandle.registration_id` | Veilに登録した対象の安定ID |
| `TargetHandle.native_ref` | 配置先、account/project、region、native resource識別子 |
| `TargetHandle.generation_fingerprint` | adapterが確認したnative世代識別情報と、その根拠・確かさ |
| `TargetHandle.engine_binding` | エンジン種別・版、native resourceとの対応 |
| `ObservedState.configuration_epoch` | 認証・network・接続設定等の可変状態の版/hash |

`TargetHandle`は現在の観測handleとし、計画と承認には`TargetBinding`としてregistration/native参照/世代fingerprintを固定します。共通型の正本は[control plane](control-plane.md)です。

名前を再利用して作られた別DBを、以前のDBとみなして権限変更しないことが目的です。世代根拠と、証明書・IP・設定の変更を区別します。正当な証明書更新を自動でDBの作り直しと判定せず、IPやCA fingerprintだけで世代同一性を保証しません。

nativeの世代識別情報やエンジン側の対応情報が十分に取得できなければ、`generation_assurance=unconfirmed`を保持します。その状態での破壊的・権限縮小操作は、対象の再照合と明示した運用手順へ戻します。情報不足を、別resourceを操作してよい根拠にはしません。

## 3. Capabilityを実装の契約にする

`CapabilityDescriptor`はprovider・engine・actionの組に、対象版、配置、runtime、制約、効果範囲、保証段階を持たせます。「PostgreSQL対応」「IAM対応」という一つのbooleanで計画しません。

共通control planeが版付き型を所有します。本書で別のcapability schemaを作らず、[control planeのCapabilityDescriptor](control-plane.md#4-capability契約)へ次を対応付けます。

- `placement_kind / engine_family / action / target_version_constraint / contract_revision`で組合せと契約を固定する。
- `support=Supported / Unsupported / Unknown`（対応可否）、`implementation=Planned / Implemented`（実装有無）、`coverage=None / LocalCovered / PlatformObserved / TargetObserved`（観測範囲）の三軸を分ける。実装済み未観測は`Implemented + None`として表現する。
- `identity_mode / conditional_write / idempotency / required_permissions`で識別・競合・再試行・権限の条件を宣言する。
- `effect_contracts`にnative機構、適用scope、前提、変更・読取方法、伝播、対象粒度、復旧可能性と実効性の根拠を持たせる。
- `limitations`と対応する観測参照に、runtime/配置の制約、対象・時刻・build、未確認事項を残す。coverageは環境・対象・版と併記し、品質認定やproduction適格性に変換しない。

少なくとも次のactionを分けます。

| Action | 約束する効果 | 追加条件 |
| --- | --- | --- |
| `IssueConnectionCredential` | 指定identityの新規接続用credentialを供給できる | provider、driver、取得元、寿命、失敗時動作 |
| `RefreshConnectionCredential` | 更新後のcredentialで次の接続を開始できる | callback等のintegrationとpoolの扱い |
| `DisableNewConnections` | 対象主体・経路の新規接続を止める | nativeの適用範囲、反映状態、新規接続の根拠 |
| `RestrictSqlPrivileges` | 対象DB権限を宣言した範囲へ変更できる | engine固有の継承、共有影響、権限反映 |
| `DrainExistingSessions` | 明示した期限・範囲で既存処理を減らす | 対象pool/runtimeの所有、アプリ側の協力 |
| `TerminateSelectedSessions` | 特定できた既存sessionを終了できる | 主体との対応、管理権限、transaction影響 |
| `ConstrainDirectPath` | 明示経路の直通をnative機構で制限できる | 全関連endpoint/address family/管理例外 |
| `OperateNativeEndpoint` | 選択したnative経路を設置・更新・復旧できる | runtimeの配置、所有、必要権限 |

`DisableNewConnections`が使えても、`TerminateSelectedSessions`が使えるとは返しません。SQL権限の変更も、新規session・既存session・実行中statementへの効果をdescriptor内で分けます。上限時刻を確認できていない伝播へ、架空の即時反映保証を付けません。

要求に必要な能力が不足すれば`CapabilityGap`を返します。別のnative経路・認証・運用手順による代替を提案できますが、意図を弱めた方式へ自動で切り替えません。計画を通すためにdescriptorの保証段階を引き上げません。

## 4. アプリへ渡す接続契約

アプリに渡すのは秘密を含まない`ApplicationConnectionBinding`です。

| フィールド | 内容 |
| --- | --- |
| `binding_id / policy_revision / target_handle` | どの意図・DBに対する設定か |
| `route_id / endpoint_kind` | native server endpoint、local endpoint、組込connector等 |
| `endpoint_ref` | 宛先とport、local socket等。任意の発見先やfallback先ではない |
| `identity_ref / db_identity_mapping` | workloadの主体とDB user/accountの正確な対応 |
| `credential_source_ref` | 取得元・取得方式・利用scopeの参照。値は含めない |
| `transport_profile` | 各区間のTLS、信頼先、hostname/instance照合、localアクセス制御 |
| `engine_profile` | driver/protocol、DB名、session/pool条件、非対応機能 |
| `renewal_policy / session_policy` | 新規接続時の取得、更新余裕、既存接続の扱い |
| `cutover_revision / recovery_binding_ref` | 適用対象の版と、選択できる復旧先 |

productionアプリのidentityは、配置先のworkload identity、metadata/federation、native SDKを基本にします。人間のgcloudログインや操作用impersonationを、アプリの恒常的な認証基盤として配布しません。アプリへ人間のToken CreatorやOwnerを渡す設計にしません。

今回のgcloudユーザーから試験用SAへのimpersonationは操作・観測用です。アプリ用identityと、その環境での取得・更新integrationを別に具体化します。

### Credential sourceと更新

| Source | 用途 | 契約 |
| --- | --- | --- |
| native connector/SDK | 対応する配置・エンジン・driverでの認証 | nativeの更新と失敗時動作をdescriptorで確認する |
| driver callback/provider | 新規接続ごとの短期credential取得 | callbackが使えるdriver/poolへintegrationする |
| 外部secret参照 | 明示採用したnative DB認証等 | 保管・取得・rotation・旧credential停止を別stepにする |

値を設定や`ChangePlan`へ埋め込まず、`CredentialLease`として必要なプロセスのメモリへ渡す契約にします。外部CLI/SDKの管理cacheは別の保存経路としてdescriptorと運用資料に明示します。

論理interfaceは次です。

`CredentialSource.acquire(identity_ref, target_handle, minimum_validity, cancellation, deadline) -> CredentialLease`

leaseは秘密値と分離して、発行対象、用途、新規接続に使える期限、更新判断に必要なmetadataを返します。秘密値をDebug・journal・通常ログへ出すinterfaceは持ちません。

native connector/SDKが秘密値や期限を公開しない場合、leaseはopaqueなnative取得元への参照と、確認できる契約metadataだけを持ちます。Veilがtokenの抽出・発行代行を始める前提にはしません。要求したminimum validityを確認できなければ、その条件を満たすと推測せずcapabilityの制限へ返します。

取得元が更新できない場合に新規接続を止めるか、有効な既存leaseを一定条件で使えるかを事前のpolicyで決めます。期限切れを黙って再利用したり、長期password・別主体・直通へ降格したりしません。credentialの期限到来が、既存sessionの切断を意味するとは扱いません。

poolは、新規物理接続のcredential取得、再接続、返却時のsession state、最大接続寿命、drain通知をintegrationで扱います。Veilが扱っていないpoolを、endpointを変えただけでreset・更新対応済みとは表示しません。接続やtransactionを無制限に再送せず、結果不明の書込を自動replayしません。

### identityの対応

`PrincipalDbMapping`は配置先・engineの組で解決し、元のidentityとDBの正確な名前を保持します。GCP PostgreSQLのSA名変換等を、全PostgreSQL・全MySQLの共通規則にはしません。

`EngineAdapter`は、DB識別子をエンジン固有の識別子として検証・quoteします。値はbindし、識別子と値を分けます。名前の大小文字やprovider固有の正当な文字を、共通のASCII規則に押し込めて別userへ変えません。

## 5. DB権限とネットワークの合成

DB権限の入力は、アプリが必要とする対象・操作の宣言です。具体的なDB account、role membership、object権限、既定権限等への変換は`EngineAdapter`が行います。

共通intentに`Read / Insert / Update / Delete / Execute`等を置く場合も、engine側で対象scopeを表現できる場合だけ変換します。schema、database、table、routineの違いを無視して、広いGRANTへ近似しません。表現できないscope・未解析の継承・共有roleは`CapabilityGap`または`SharedImpact`として計画に残します。

既存userを複数アプリで共有している場合、一つのアプリだけの失効・権限縮小を保証できるとは限りません。データを移すのではなく、専用DB identity/roleへ分ける移行案を示します。共有roleや既存accountの権限を、所有と影響の確認なしに削りません。

network側は、登録したendpoint、IPv4/IPv6、既存proxy/connector、別名、管理・batch・migration経路を`AccessMatrix`へ対応付けます。制限できない経路や列挙できない範囲は未確認として残します。

local connector endpointがloopbackにあることだけでは、同じhostのプロセスを正規アプリと区別できません。process/container境界、local socket権限、workload identityとDB認証のどこで区別するかをbindingに含めます。

## 6. Adapter interfaceと操作の境界

以下は実装する論理interfaceです。現行コードのtrait名や動作済みAPIを表すものではありません。

| 操作 | 入力・出力 | 副作用 |
| --- | --- | --- |
| `capabilities(target, context)` | `CapabilityDescriptor[]` | 静的情報と明示読取のみ |
| `observe(scope, deadline, cancellation)` | `ObservedState`、取得状態、同一性根拠 | 承認された対象の読取 |
| `plan_step(desired_change, observed, policy_revision)` | typed `PlanStep`のDAG断片とgap | 変更なし |
| `apply_step(step, approval_grant, operation_context)` | `StepApplied`または結果不明を含むreceipt | grantに束縛した一stepだけ |
| `read_step_status(receipt, expected_effect)` | API受理状態と`EffectiveState` | 明示読取 |
| `compensate_step(step, receipt, recovery_intent, approval_grant)` | 復旧stepのreceipt | 承認範囲内の復旧だけ |

`DeploymentAdapter`は接続経路・identity・network・runtimeのstepを、`EngineAdapter`はDB identity・GRANT・sessionのstepを提案します。相手の領域まで勝手に変更せず、共通control planeが依存関係を合成します。

adapterは変更するcanonical resourceとfield/domainの範囲も返し、control planeが`ChangePlan.conflict_keys`を構成します。DBの登録IDが異なっても、共有IAM binding・network資源・roleへの影響を別物として扱いません。包含・交差surfaceのleaseとdispatch条件はcontrol planeの共通契約に従います。

例えば「native経路準備→アプリidentity準備→DB identity/権限→binding配布→アプリ切替→不要な直接経路縮小」は複数adapterにまたがるDAGです。engine側準備にprovider側特権が必要なら、別step・別実行主体・別承認として表します。

`PlanStep`のpayloadはadapterが定義した版付きのtyped操作です。任意shellや任意SQL文字列をapproval内容として渡す方式にはしません。初期profileのnative構築・変更は、ローカルCLI内の限定native executorで適用します。provider操作とengine側の固定生成文をそれぞれのadapterが所有し、同じ承認済みDAGで進めます。

アプリ・Auth Proxy等のアプリ側runtimeの配置と切替は、初版は運用者の既存deploymentへの手動handoffです。bindingとruntime設定の生成・受領を、適用・稼働・保護成立と同一視しません。既存IaCとの変更bridge等は将来のadapter追加対象とし、初期方式の選択を未決へ戻しません。

適用時には次を照合します。

- `ApprovalGrant`が同じ`PolicyRevision / ChangePlan / PlanStep / target世代 / action scope`を許可し、期限内である。
- resource同一性と変更に関係する構成・DB権限がpreconditionを満たす。
- 実行主体の権限と対象範囲がstepの要求に一致する。
- 必要な前stepが受理されたか実効になったかを、依存条件どおりに区別する。
- API etag/CAS等が利用できれば、そのnative競合制御を使う。

内部lockは同じOperationStoreを使うVeil操作同士の競合を減らすものです。別のstoreを使うVeil、外部console、別IaCの変更まで止めるとは扱いません。native CASがない場合、直前照合・適用・再読取の間の競合余地をcapabilityの条件と制約へ残します。危険差分には運用者との変更窓の調整や再計画が必要であり、内部lockで解決済みとは表示しません。

### 結果不明と再実行

`StepApplied`はAPI/DBが変更を受理した事実で、control planeの`Submitted`に相当します。`ConfigApplied`、必要な効果が満たされた`EffectSatisfied`とは分けます。実効状態は共通`EffectiveRecord`の`Enforced / Pending / Unknown / NotSatisfied / Unsupported`へ対応付け、`valid_until`を越えた過去のEnforcedを現在の保護として使いません。

receiptには`Operation / StepAttempt`、対象、native operation参照、変更前後の選択fingerprint、所有を確認できた資源、結果の確かさを保存します。秘密値やDB行は保存しません。

通信断で結果が分からない変更を、汎用retryへ流しません。`read_step_status`でnative状態と所有を照合し、適用済み・未適用・不明を区別します。idempotency keyの保証がある操作だけ、そのnative契約内で再試行します。

## 7. 既存DBへの導入と管理例外

アプリの稼働を維持する段階と、最終的な保護を満たす段階を分けます。

| 段階 | 設計上の操作 | 表示する状態 |
| --- | --- | --- |
| `Registered` | 実DB世代、アプリ、管理・batch・migration、変更できない条件を登録 | 保護を宣言しない |
| `Prepared` | native経路、workload identity、DB user/role、復旧経路を準備 | 準備済み。旧経路が残る可能性 |
| `CanaryConnected` | 限定アプリへbindingを渡し、必要な接続・操作を成立させる | 切替途中 |
| `ApplicationCutover` | アプリ・pool・jobを新経路へ切り替える | 旧接続の残存を別管理 |
| `BoundaryConstrained` | 宣言済み例外以外の直接経路・旧権限を縮小する | 実効反映を待つ可能性 |
| `EnforcedRevision` | revisionの必要な効果が根拠付きで実効 | その対象・範囲の保護状態 |
| `RecoveryRequired` | 切替や制限の条件を満たせず、復旧判断へ移る | 成立分と残った影響を保持 |

この段階名はcontrol planeのOperation状態を置き換えず、データプレーンの移行位置を表します。中断しても、アプリbinding、経路、権限、sessionの残存をjournalから復元できる形にします。

アプリ設定の適用は、運用者の既存deployment手段へ接続します。最初は秘密なしのbindingと変更差分を生成し、適用・稼働の受領を記録します。再起動やdeploymentの自動化は、対象・権限・取消し・復旧を明示したintegrationとして追加します。設定内の任意コマンドを実行するhookにはしません。

管理例外は`AccessMatrix`の独立entryとし、主体、実行元、宛先、DB権限、用途、期限、承認、復旧用途の有無を持たせます。アプリidentityへ管理経路を再利用させません。緊急経路も、期限付きの明示したbreak-glass手順として分けます。

既存の管理・batch・監視・migrationが未登録であることを、不要という意味にしません。境界を閉じる前に運用者が判断できる未登録経路として返し、黙って停止させません。

## 8. 失効と既存session

policyには今回どこまで失効させたいかを含めます。

- `NewConnectionsOnly`: 新しい接続を拒否し、既存sessionの扱いを別欄に残す。
- `DrainByDeadline`: アプリ側pool等の所有範囲をdrainし、残sessionを扱う。
- `TerminateSelected`: nativeに特定できたsessionを承認範囲で終了する。

native経路の停止を選んでも、どの既存client/backend sessionへ影響するかをdescriptorで示します。Proxy停止だけで、DBの実行中statementやcommit結果まで確定したとは扱いません。

共有DB userやpoolによってsessionの主体を特定できなければ、他アプリを巻き込む終了は行いません。`TerminateSelectedSessions`の不足として、専用identityへの分離、アプリ側drain、管理者の限定操作等を計画へ戻します。

権限変更のAPI受理、反映待ち、新規接続の成功/拒否、既存sessionの存続を別に記録します。反映待ち中に接続できた事実を隠さず、その間は必要な失効が完了した保護状態にしません。

## 9. 復旧とcontrol plane停止時

復旧は、すべてのstepの逆操作ではありません。`compensate_step`は所有、現在状態、共有影響、復旧先policyを確認して行います。

DB accountの新設、既存roleの縮小、network例外の解除、証明書更新は同じ可逆性を持ちません。期限切れtokenや失効済み秘密を戻さず、必要なidentity/credentialを適切な取得元から再取得します。

接続障害が起きても、DB公開や直通の自動開放を共通fallbackにしません。旧経路へ戻すなら、その影響、対象、期限、許可する主体を含む復旧stepとして承認範囲に束縛します。稼働を戻せたことと、元の保護profileを満たしたことを分けます。

control planeが停止しても、適用済みnative IAM/network/DB制御と、配置先で管理されるProxy/connectorはnative契約に従って動作する構成を採ります。新規credential取得がcontrol planeへ依存しないこともアプリintegrationの条件です。取得元自体の障害時に既存sessionをどこまで維持するかは、lease/session policyとnative機構の能力を明示します。

再開時はjournalだけを信用して変更を続けず、resource世代と現在状態を再照合します。外部変更・名前の再利用・所有不明・結果不明があれば関係stepを再計画し、他の既知の保護まで自動で解除しません。

## 10. 初期の縦切りと拡張対象

| 組合せ | この設計での位置付け |
| --- | --- |
| GCP Cloud SQL × PostgreSQL 16 | 初期の縦切り。既存観測adapterを再利用し、policy→計画→承認済み導入→アプリbinding→実効状態へつなぐ |
| AWS RDS × PostgreSQL | K07で16.15／東京／既存専用Proxyを限定実装・L検証。source別拒否のproducerと実導入は未完了 |
| AWS RDS × MySQL | K08で8.0.43／東京／専用Proxy・IAM account／table権限を限定実装・L検証。実導入未確認 |
| GCP Cloud SQL等 × MySQL | 後続。account/role/認証/driverのcapabilityを個別に具体化する |
| 自己管理PostgreSQL/MySQL等 | 設計上の追加対象。DB host/runtime、network、認証取得元と復旧の所有者を明示する |
| MariaDB、SQL Server、Oracle等 | 主要RDBMS構想として保持。native経路、account/権限、driver、運用機構を組合せごとに追加する |
| D1/SQLite等 | APIアクセスやfile/process境界の別形態。同一TCP Proxy/IAM DBログインへ押し込めず、別のdata-access capabilityとして設計する |

初期profileは`gcp-cloudsql-postgres-connector-v1`です。現時点の観測実測はPostgreSQL 16.15/東京の専用環境であり、このprofile全体やproduction workloadの導入・認証更新が実装済みという意味ではありません。

GCPのCloud SQL Auth Proxyはアプリ側runtimeです。RDS Proxyと同じserver-side proxyとして表現しません。Cloud SQL側の接続認可、connector必須化等のnetwork/DB設定、DBログイン・SQL権限が実enforcerであり、Auth Proxyは選択した経路の一部です。

初期GCPでは、現在の操作・観測用の手動IAM token経路を、そのままproductionアプリ用の更新機構にしません。初期profileではアプリと同じ保護された実行境界に置くAuth Proxyとnative IAM認証更新を第一候補として具体化し、配置・driver/pool・対応版をbindingに固定します。native connector/SDKやcredential providerを使う別の組合せもcapabilityで表現できますが、自動的な方式変更はしません。

SQLiteをcontrol plane内部のOperationStoreに採用する案は、製品が保護対象としてSQLiteに対応したことを意味しません。内部ledgerの実装と保護対象のadapterを分けます。

## 11. 次の実装で固定するもの

共通境界は、本書の二軸adapter、版付きcapability、秘密なしbinding、承認に束縛したtyped step、API受理と実効性の分離で固定します。初期の変更方式はローカルCLIの限定native executor、アプリ・runtime切替は手動handoffに決定済みです。次に残るのは個別操作・配置の具体化であり、基幹実装を待たせる方式選択ではありません。

| 未決 | 決める対象 | 先に実装できる部分 |
| --- | --- | --- |
| 初期GCPアプリの配置・driver | workload identity、connector/SDK/provider、pool integration | binding/credential境界、capability選択とgap表示 |
| native stepの個別payload・必要権限 | 限定executorが扱うprovider操作、engine固定生成文、対象fieldと最小権限 | PlanStep、依存関係、precondition、receipt、approval照合 |
| 既存DBの権限移行 | 共有account/roleの影響、新identityへの分離 | engine選択読取、権限差分、SharedImpact、固定生成文のinterface |
| 世代識別・外部競合制御の実値 | provider/engineが提供する根拠とCAS | TargetHandle、generation assurance、再照合 |
| 既存session失効範囲 | pool所有、nativeに特定可能なsession、許容中断 | 新規接続停止とsession終了を分けたcapability、drain/復旧step |
| MySQLの最初の配置先・版 | K08でAWS RDS MySQL 8.0.43／東京に固定し限定実装済み | 他の版・配置先、role・共有account移行は後続 |

追加試験を今始める計画ではありません。K05〜K08で限定bindingと導入DAGは実装しました。次は[照合記録](design-implementation-audit.md)に従い、要求別の事前判定、根拠範囲、現在effectiveと導入・復旧契約の残差を埋めます。観測機能の拡張自体を製品の目的へ置き換えません。
