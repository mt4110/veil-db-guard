# 基幹設計: Policyと接続保護のControl Plane

設計日: 2026-11-02。実装へ移すための採用案です。この作業では設計文書だけを作成し、追加実装・試験・クラウド操作は行いません。

## 1. 製品の責務

Veil DB Guardは、既存の主要RDBMSを置換せず、正規アプリが使う接続とSQL権限を届け、不許可の接続・迂回を防ぐための導入運用プロダクトです。Control Planeはその意図を永続化し、レビュー可能な変更を組み立て、承認された範囲で適用・維持・失効・復旧を進めます。接続観測と評価は、適用結果や維持すべき保護状態を判断する下位部品です。

初期実装はローカルCLI内のorchestratorとします。常駐agent、独自のSQL中継プロキシ、管理用SaaSを初版の必須条件にしません。アプリの通常通信は、選んだnative connector/proxyまたは明示的な管理経路を通ります。

対象は二軸で保持します。

| 軸 | 例 | 決めること |
| --- | --- | --- |
| Placement / provider | GCP Cloud SQL、AWS RDS、将来の他cloud・自己管理配置 | 資源identity、native接続経路、IAM、ネットワーク、設定変更・復旧 |
| Engine | PostgreSQL、MySQL、将来の主要RDBMS | DB identity、role/GRANT、SQL権限、transaction、sessionの扱い |

`provider=GCP`を`engine=PostgreSQL`の別名にしません。DeploymentAdapterとEngineAdapterの組合せに、対応版・操作・制約を持たせます。初回の縦切りはGCP/PostgreSQL、続いてAWS/PostgreSQL、MySQLの組合せを同じ核へ追加します。未実装の組合せを構想から除外せず、対応済みとも表示しません。

## 2. 共通ドメイン

以下は論理型です。既存Rust型へ実装済みという意味ではありません。IDは安定した識別子、Hashは版付きcanonical形式のdigestとします。設定に任意SQL・shell・自由なAPI request bodyを埋め込ませません。

```rust
struct PolicyRevision {
    policy_id: PolicyId,
    revision: u64,
    parent_revision_hash: Option<Hash>,
    revision_hash: Hash,
    subjects: Vec<Subject>,
    targets: Vec<Target>,
    grants: Vec<Grant>,
    protection_profiles: Vec<ProtectionProfile>,
}

struct Subject {
    id: SubjectId,
    kind: Application | Operator | Batch,
    identity: ExternalIdentityRef,
    workload_sources: Vec<SourceRef>,
}

struct Target {
    id: TargetId,
    placement: PlacementRef,  // provider / account or project / region
    resource: ResourceIdentity,
    engine: EngineRef,        // family / observed version / database scope
    managed_surface: ManagedSurface,
}

struct Grant {
    id: GrantId,
    subject: SubjectId,
    target: TargetId,
    admission: AdmissionIntent,
    sql_access: SqlAccessIntent,
    profile: ProtectionProfileId,
    lifetime: Standing | Lease { expires_at: Timestamp, expiry_mode: ExpiryMode },
}

struct ProtectionProfile {
    id: ProtectionProfileId,
    allowed_routes: Vec<RouteRef>,
    application_direct_path: Deny | ExplicitException(ExceptionRef),
    authentication: AuthenticationRequirement,
    encryption: EncryptionRequirement,
    management_exceptions: Vec<ExceptionRef>,
    required_effects: Vec<EffectRequirement>,
}
```

- `ExternalIdentityRef`は名前だけでなく、providerが提供できる主体の不変ID・世代を保持します。名前しか照合できない場合はidentity capabilityの制限として扱います。実行する操作者のidentityと、接続を保護するアプリのSubjectは別です。
- `SqlAccessIntent`は既存roleへの参照と、engineが解釈する型付き権限・object scopeで表します。クラウド接続権限が付いたことをDB内権限の付与と同一視しません。
- `ManagedSurface`は変更してよい資源・設定field・DB identity/role/objectを列挙します。対象DBを管理対象へ登録しただけで、全IAM policy、全ネットワーク、既存schema/dataの変更権限を得る設計にしません。
- 管理・バッチ等の例外は主体、送信元、経路、理由、lifetimeを持つ独立したルールです。通常アプリへ管理権限を流用しません。
- 認証情報の値は持たず、`SecretRef { store, key_id, version }`または資格情報providerの参照だけを保持します。変更対象のpassword等は不変のsecret versionへ束縛し、実行者の短期token更新とは分けます。

同一Subject/Targetの矛盾したAllow/Deny、未定義参照、管理範囲外の権限、capability上表現できない要求をPolicy正規化で検出します。provider固有の名前やDB識別子の正規化・quotingは各adapterが担当し、その結果をplanへ固定します。

## 3. Desired / Observed / Effective

三つを別のrecordとして保持し、最新時刻一つで上書きしません。

| record | 内容 | 権威・限界 |
| --- | --- | --- |
| Desired | 有効化したPolicyRevisionと、その版が要求するGrant/ProtectionProfile | 利用者の意図。承認や適用済みを意味しない |
| Observed | native API・DB・クライアントから取得した設定、role、操作状態、接続結果 | 対象・主体・版・時刻・取得範囲を持つ事実。欠落はUnknown |
| Effective | desired effectと観測を対応付けた適用範囲付き評価 | 設定受理と、実際の接続可否・権限を分離する |

```rust
struct EffectiveRecord {
    policy_revision_hash: Hash,
    grant_id: GrantId,
    effect: EffectKind,
    scope: EffectScope,       // target incarnation / subject / route / DB scope
    status: Enforced | Pending | Unknown | NotSatisfied | Unsupported,
    actual_access: Option<Allowed | Denied | Unknown>,
    basis: NativeContract | ConfigurationObserved | ConnectionObserved | EngineObserved,
    observed_at: Timestamp,
    valid_until: Timestamp,
    evidence_refs: Vec<EvidenceRef>,
    limitations: Vec<ReasonCode>,
}
```

`EffectKind`は少なくとも次を区別します。

1. native設定・bindingの反映。
2. 新規接続の許可または停止。
3. 確立済みsessionの終了。
4. DB内SQL権限の付与・縮小。
5. lease期限到達時の失効処理と、その実効状態。

tokenの有効期限、Grantの期限、上記effectは別です。IAM APIが削除を受理しただけでは新規接続停止をEnforcedにせず、既存session終了へも転記しません。Pending中に接続できた事実を保存し、画面・CLIで「接続可能／保護条件未成立」と表示します。途中のAllowed/Denied混在と、最後に観測した時刻も残します。

Enforcedは`scope`と`basis`が示す範囲で使います。native契約から効果を導ける操作は、そのcapabilityが指定する設定・完了条件を満たして判断できます。実接続を根拠にする場合も、観測した主体・経路・時間範囲を越えて一般化しません。Operatorの申告は別の入力であり、実効を確認した証拠へ変換しません。

`valid_until`はeffect/capabilityに応じた鮮度の上限です。期限切れや新しいdrift観測で評価が失効した場合、過去のEnforcedは履歴へ残し、現在の保護状態をUnknown等へ更新します。プロセス停止中に設定維持や失効を確認し続けたことにしません。

## 4. Capability契約

```rust
struct CapabilityDescriptor {
    placement_kind: PlacementKind,
    engine_family: EngineFamily,
    action: ActionKind,
    target_version_constraint: VersionConstraint,
    contract_revision: Hash,
    support: Supported | Unsupported | Unknown,
    implementation: Planned | Implemented,
    coverage: None | LocalCovered | PlatformObserved | TargetObserved,
    identity_mode: IdentityMode,
    conditional_write: ConditionalWriteMode,
    idempotency: IdempotencyMode,
    effect_contracts: Vec<EffectContract>,
    required_permissions: Vec<PermissionRef>,
    limitations: Vec<ReasonCode>,
}
```

対応可否、実装の有無、確認した環境、保証するeffectを別に宣言します。`support`は要求をnative契約で満たせるか、`implementation`はadapter実装があるか、`coverage`はどの範囲で観測根拠があるかを表す独立した三軸です。

| coverage | 観測根拠の範囲 |
| --- | --- |
| None | 実行・観測の根拠なし。設計だけの場合を含む |
| LocalCovered | ローカル環境の根拠。実cloudでの成立へ昇格させない |
| PlatformObserved | 明示したplatform・版・隔離環境での観測。別の導入対象には一般化しない |
| TargetObserved | 登録した対象世代・版・取得範囲に対応する観測 |

各coverageには環境、対象、版、観測時刻、evidence refsと限界を付けます。coverageは品質認定、本番適格性、現在の全effect成立を表しません。過去のTargetObservedも現在のEffectiveRecordの鮮度やpreconditionを代替しません。GCPの結果をAWSへ、PostgreSQLのrole操作をMySQLへコピーしません。未知のnative expiryやsession停止機能を前提にしません。

`Lease`を選べるのは、native expiryで要求effectを満たせるか、明示的に稼働するreconcilerが失効処理を担う場合です。どちらもなければ、自動失効を約束するlease planを生成しません。Standingの正規アプリ許可は別に提供できます。CLIを終了しただけで後刻のrevokeが実行されるという説明はしません。

`contract_revision`はadapter actionの解釈と安全条件を固定する版です。実行時に異なる契約へ自動変換せず、互換性が確認できないplanは再生成します。tool build IDは各実行記録へ残しますが、無関係な文書変更とPolicyの意味変更を同じものとして扱いません。

## 5. ChangePlanと承認

```rust
struct ChangePlan {
    id: PlanId,
    plan_hash: Hash,
    policy_revision_hash: Hash,
    intent: Apply | Reconcile | Revoke | Rollback,
    target_bindings: Vec<TargetBinding>,
    conflict_keys: Vec<ConflictKey>, // canonical resource identity + managed field/domain
    observation_refs: Vec<ObservationRef>,
    steps: Vec<PlanStep>,       // stable step IDs + dependency DAG
    repair_recipes: Vec<RepairRecipe>,
    recovery: RecoveryPlan,
    limits: OperationLimits,
}

struct PlanStep {
    id: StepId,
    action: TypedAction,
    adapter_contract: Hash,
    target: TargetBindingId,
    parameters_hash: Hash,
    dependencies: Vec<StepId>,
    preconditions: Vec<Precondition>,
    config_postconditions: Vec<Postcondition>,
    required_effects: Vec<EffectRequirement>,
    compensation: Option<CompensationRef>,
}

struct ApprovalGrant {
    id: ApprovalId,
    plan_hash: Hash,
    policy_revision_hash: Hash,
    target_scope_hash: Hash,
    allowed_step_ids: Vec<StepId>,
    allowed_repair_recipe_hashes: Vec<Hash>,
    recovery_scope_hash: Hash,
    execution_identity_constraints: Vec<IdentityConstraint>,
    forward_valid_until: Timestamp,
    recovery_valid_until: Timestamp,
    limits_hash: Hash,
    approver: ApproverRef,
}
```

`TypedAction`は例として、native経路の準備、主体とDB identityの対応、DB権限付与、接続profileの発行、client切替checkpoint、直接経路の制限、権限削除、session停止を持ちます。汎用shell実行をactionにしません。どのactionをDeploymentAdapterまたはEngineAdapterへ渡すかをplan内で固定します。

`approve`のレビュー対象には、差分、正規アプリへの影響、対象・世代、操作順、必要権限、外部checkpoint、期限、費用・資源制限、失敗時の分岐、復旧内容を含めます。承認はplan hash、Policy版、対象、操作、実行主体の条件、期限へ束縛します。承認後のparameter差替えや、別project/DBへの付け替えは認めません。

初版は信頼するローカル操作者の明示的approveを承認recordへ保存するモデルです。manifest/hashは参照整合性のためのもので、同じOSユーザーが記録とCLIを自由に改変できる環境に対する承認者の真正性を保証しません。複数利用者・遠隔実行の承認認証は別capabilityとします。

### 承認を工程ごとに取り直さない範囲

- 同じstepの同じ意図・parameterで、未完了状態を照会し、許可された回数内で再試行する。
- planに列挙した復旧、対象を限定したcompensation、部分作成資源の回収を進める。
- 承認済みrepair recipeから、同じPolicy版のdesired値へ戻す限定的な子実行を導出する。
- forward期限までに受理された操作の状態照会と証拠保存を続ける。

`RepairRecipe`には対象集合、変更可能field、設定すべきdesired値、許容する観測前提、最大回数・頻度、期限、復旧分岐を固定します。子実行は`recipe hash + bindings + observation refs`を記録し、承認済みrecipeからの導出であることを検査します。これによりreconcileのたびに無制限の新planを実行することも、同じ限定修復を毎回承認し直すことも避けます。

対象世代、Policyの意味、操作範囲、許可外の差分、必要権限、復旧内容が変わればReplanRequiredです。forward期限を過ぎて新しい変更は開始しません。事前承認に含む復旧だけは`recovery_valid_until`内で継続できます。それを越える変更は、新しい復旧承認の対象にします。

## 6. Target bindingとprecondition

既存DBは`ExistingResource`へ固定し、別DBへの置換を通常の導入手段にしません。必要なproxy等の新規資源は`CreatedByStep`へ束縛します。

```rust
enum TargetBinding {
    ExistingResource {
        identity: ResourceIdentity,
        generation_fingerprint: Hash,
        expected_native_version: Option<NativeVersion>,
    },
    CreatedByStep {
        creation_step: StepId,
        logical_resource_id: LogicalResourceId,
        creation_intent_hash: Hash,
        ownership_constraints: OwnershipConstraints,
    },
}
```

作成前に未知のnative IDを架空値で承認しません。作成stepのreceiptからIDを解決し、作成意図・所有条件と照合してOperationStoreへ固定します。後続stepはそのbindingだけを使います。既存資源の同名再作成を同じ対象とみなさず、providerの不変ID・世代、またはcapabilityで宣言したfingerprintで照合します。

Data Planeの`TargetHandle`は登録した対象の現在の観測handleです。`TargetBinding::ExistingResource`は、そのhandleのregistration ID/native ref/generation fingerprintを計画へ固定したものとします。変更可能な設定epoch/etagは資源の世代と分け、step前提と自stepのreceiptにより更新を追跡します。

preconditionはPolicy版、対象binding、必要なnative版/etag、engine版、設定fieldのownership、前stepのpostcondition、実行者identity、権限、外部checkpointを型付きで表します。読み取り時と書き込み時の版を結べる場合はconditional writeを使います。

内部target leaseは別のCLI実行との競合を抑えるだけで、外部consoleや他controllerの変更を止めません。conditional writeがない操作は、その制限をplanへ出します。限定memberの追加・削除等の狭い操作を優先し、field全体の置換は、明示したownershipと外部調整の条件がない限り自動で行いません。単なるread-compare-writeをatomicだと表示しません。

DB targetが別でも、project IAM policy、共有SG、共有DB role等のmanaged surfaceが重なれば競合します。adapterは`ConflictKey { resource_identity, field_or_domain }`を正規化してplanへ列挙し、field全体とmember部分のように範囲が包含・交差するkeyも競合として扱います。対象DBのleaseに加えて必要なresource/field leaseを安定順で取得し、全leaseを確保するまでdispatchしません。native CASがない共有fieldへの変更は、外部変更窓を調整できなければ停止します。内部leaseだけでcloud consoleまで排他したことにしません。

既存アプリの切替は独立checkpointです。初版では接続profileを渡して操作者が切替を確認する方式を持てます。切替をCLIが実施したことにせず、確認前に旧経路を閉じない順序をplanへ定義します。一時的に残す経路も例外として承認し、閉鎖を担う操作・期限管理の手段を明示します。

## 7. Operationとstepの状態

実行状態と実効状態を直積で持ちます。

```rust
struct Operation {
    id: OperationId,
    request_id: RequestId,
    input_hash: Hash,
    plan_hash: Hash,
    approval_id: ApprovalId,
    policy_revision_hash: Hash,
    expected_desired_head: Hash,
    state: ExecutionState,
    store_version: u64,
    parent_operation: Option<OperationId>,
    repair_recipe_hash: Option<Hash>,
    resolved_bindings: Vec<TargetBindingRef>,
    consumed_limits: LimitConsumption,
}

struct StepAttempt {
    operation: OperationId,
    step: StepId,
    attempt: u32,
    idempotency_key: Hash,
    input_hash: Hash,
    state: StepState,
    execution_identity: IdentityRef,
    native_operation_ref: Option<NativeOperationRef>,
    receipt_ref: Option<ReceiptRef>,
    evidence_refs: Vec<EvidenceRef>,
    started_at: Timestamp,
    finished_at: Option<Timestamp>,
}
```

`PolicyRevision`作成時はcandidateであり、承認・適用済みではありません。`apply`開始または承認済みrevokeの開始で、対象Policyのdesired headを期待旧版から新revisionへCASし、同じtransactionでOperationを登録します。実効前でもdesiredは新revisionを指し、適用中/部分失敗を別状態で示します。別の新revisionへ進んだ場合、旧Operationは新しいforward変更を停止します。残るnative結果の照会と既承認の安全な復旧だけを検討し、新しいdesiredと矛盾する復旧は自動実行しません。

| Execution state | 意味 |
| --- | --- |
| Prepared | immutable planを保存し、未実行 |
| AwaitingApproval | 必要な承認がない・期限等を満たさない |
| Running | 承認とpreconditionを満たすstepを実行中 |
| WaitingProvider | native非同期操作の完了待ち |
| WaitingEffect | 設定は反映したが、要求した実効を確認中 |
| NeedsAction | 対象変更、外部checkpoint、権限不足等で自動継続できない |
| Recovering | 承認済み復旧を実行中 |
| Completed | planが定義した実行・実効の完了条件を満たした |
| FailedPartial | 一部変更済みで、要求条件を満たせない |
| Cancelled | 新規変更のdispatchを停止。既存native操作と残資源は別途追跡 |

stepは`Prepared → Dispatching → Submitted → ConfigApplied → EffectSatisfied`を基本にします。副作用のない照会、既にdesired値の操作は、根拠付きでNoOpSatisfiedにできます。OutcomeUnknown、Failed、Compensating、Compensatedを別状態として持ちます。

native APIの受理receiptをSubmittedとして保存し、観測設定がpostconditionと一致した時点をConfigAppliedとします。要求するeffectが残ればWaitingEffectです。設定変更の実行成功を報告することはできますが、それをPolicyの保護完了へ昇格させません。

DB/権限削除の反映待ちは、対象主体・layer・変更時刻・実測差分・接続観測を対応付けます。期限超過時は待ち続けずNeedsAction/FailedPartialとし、現在Allowedならその事実を明示します。繰返し拒否を観測しても即時失効や全接続の安定拒否とは表示しません。

## 8. 永続化とidempotency

内部のtransactionalなOperationStoreは初期SQLite採用案とします。これは保護対象のRDBMSとは別のローカルledgerです。最初は一台のcontrollerを正本とし、同じtargetへ複数ホストから並行applyする構成は提供しません。

| collection/table | 不変・更新する情報 |
| --- | --- |
| policy_revisions | immutableなPolicy本文、親版、revision hash |
| desired_heads | policyのactive desired版。CASで更新 |
| plans / approvals | immutableなplan・承認と、それぞれのhash |
| approval_events | 承認取消し・失効の履歴。元の承認本文を改変しない |
| operations | intent、参照版、現在state、store version、limits消費 |
| target_bindings | native ID・世代・作成stepとの対応 |
| step_attempts | step、試行番号、idempotency key、request意図hash、receipt、結果 |
| operation_events | append-onlyの遷移・原因・時刻・参照 |
| target_leases / resource_leases | targetと共有resource/fieldのconflict key、holder、fencing token、期限。複数leaseは安定順で取得 |
| observation_refs / effective_records | immutable証拠への参照、範囲付き実効評価の履歴 |

秘密値は格納しません。証拠は既存RunWriterへ新規runとして保存し、artifact hashとrefをledgerへ持ちます。既存ファイルを上書きして過去の失敗やAllowedを消しません。SQLiteの実装ライブラリ、暗号化・backup方式は実装時の依存選定で固定します。

新しいdispatchごとに承認の期限・取消し・limits消費を再確認します。承認取消しも既に受理されたnative操作を自動で取り消すものではなく、以後のforward変更を止め、受理済み結果と残存effectを追跡します。

一つのmutating stepは次の順序です。

1. 短いSQLite transaction内で、operation版・承認・lease・preconditionを確認し、試行とDispatchingを永続化する。
2. transactionを閉じてnative操作を実行する。資格情報はこの時点で解決し、実際の実行者を承認条件と照合する。
3. receipt/エラー/timeoutを新しいtransactionで記録する。成功応答がなくても失敗と決めず、OutcomeUnknownを保存する。
4. native operation ID、provider idempotency token、対象のpostconditionを使って結果を解決する。
5. ConfigAppliedとeffectiveを別に更新し、依存する次stepだけを開始する。

`idempotency key = H(operation ID, step ID, target binding/generation, parameters hash)`を固定し、retryでも変えません。native idempotencyがない操作は、adapterが宣言した自然なidempotencyまたは結果照会で二重実行を防ぎます。DB commit結果不明・作成結果不明を、そのまま再送しません。照会で判別できなければOutcomeUnknownのままNeedsActionへ進めます。

lease取得・更新にはfencing tokenとstore versionを使います。期限切れleaseを引き継いだworkerは、未解決のDispatching/Submittedを先に照会します。古いworkerがremoteへ送信できる可能性があるため、local fencingだけでnative二重実行を防げるとはしません。照会できない不明操作があるtargetへ、別のmutating stepを重ねません。

## 9. 公開operation契約

すべてのrequestはrequest IDとexpected store/policy版を持ちます。同じrequest IDの同じ入力は同じOperation/Planを返し、異なる入力の再使用を拒否します。

| 操作 | 入力と出力 | mutation・完了条件 |
| --- | --- | --- |
| `plan` | PolicyRevision、対象観測ref、intent → ChangePlan / capability不足 | native変更なし。差分・依存・復旧・限界を具体化 |
| `approve` | plan/revision/target hash、scope、期限、approver → ApprovalGrant | 承認recordだけを保存。資源変更なし |
| `apply` | plan ID/hash、approval ID、request ID → Operation ID | 事前承認したDAGを実行。実効待ちを含め状態照会可能 |
| `resume` | Operation ID、expected store version → 同Operation | 未解決結果を照会してから、既承認scope内だけ継続 |
| `reconcile` | active Policy版、観測ref、repair承認ref → 差分 / 子Operation | 初期は明示呼出し。承認済みrecipe外の修復は実行しない |
| `revoke` | Grant ID、停止したいeffect、期限、expected Policy版 → 新revision/plan | 明示した新規接続・session・SQL権限等を別stepで失効 |
| `rollback` | Operation ID、checkpoint、復旧scope → Recovery Operation | 過去の状態を無条件に丸ごと復元せず、現状態との差と承認を確認 |
| `get/status` | Operation/Policy/Target ID → execution + observed + effective | 読取のみ。最後の観測時刻・不明・残作業を表示 |

`revoke`はGrantのdesiredをDeny/Removedへ進める新revisionです。失効を試して失敗したからといって、以前のAllowを自動復元しません。新規許可・移行操作のrollbackと、侵害対応のrevokeを同じ復旧規則にしません。

## 10. 部分失敗と復旧

| 発生点 | 継続・復旧の規則 |
| --- | --- |
| dispatch前の権限不足・target世代不一致 | 変更せずNeedsAction。権限拡大や別対象への切替は自動実行しない |
| 作成APIのtimeout | idempotency/作成intent/所有条件で照会。重複作成しない |
| proxy等の準備後、DB権限付与が失敗 | 正規接続の切替・旧経路閉鎖を開始しない。所有資源の保持/回収を承認済み分岐で選ぶ |
| client切替の未確認 | checkpoint待ち。既存アプリを切り捨てる変更を先行させない |
| 直接経路閉鎖後の正規アプリ問題 | 明示した復旧経路だけを使用。無制限公開や広いIAM roleを即席で追加しない |
| revoke受付後もAllowed | 設定受理と実効Pendingを残す。承認済みの代替停止手段があれば進め、なければ未保護を表示 |
| cancellation / controller停止 | 新規dispatchを停止。既送信操作を取り消したことにせず、再起動後にreceiptと残状態からresume |
| rollback中の外部drift | 現在の未管理変更を上書きしない。既承認分岐で処理できなければNeedsAction |

復旧にはSQL権限、native経路、client binding、追加資源を含めます。DB data/schemaそのものの復元を、接続保護設定のrollbackへ暗黙に含めません。不可逆な削除・session終了等はplanで明示し、同じ意味の逆操作が存在すると仮定しません。

## 11. 初回縦切りと下位部品の再利用

初回のGCP/PostgreSQLでは、既存target登録、正規アプリSubject、Standing Grant、native connector経路、DB role mapping、直接経路制限、管理例外を一つのPolicyへ通します。主となる操作は次です。

1. 対象・管理field・主体・正規接続profileを登録する。
2. provider/engine adapterからtyped stepsを得て、一つのChangePlanに統合する。
3. plan単位でapproveし、DB identity/権限とnative接続条件を適用する。
4. client切替checkpointを経て、承認した順序で迂回経路を制限する。
5. 設定状態と実効状態を表示し、必要なら同一Operationをresumeする。
6. reconcile/revoke/rollbackを同じledger・承認・target bindingで扱う。

既存のread-only inventory、GCP/AWSの接続観測とevaluator、strict設定解析、RunWriterの新規保存・manifest/hash検査を再利用します。evaluatorのPassをoperation全体の成功へ直接転記せず、対象effectへの根拠として取り込みます。RunWriterをtransactional OperationStoreの代用にせず、SQLiteを証拠ファイルの上書き装置にもしません。

AWS/PostgreSQLへ進む際は、Policy/Approval/Operation/Storeを作り直さず、Placement capabilityとnative actionの実装を追加します。MySQLはEngineAdapterのidentity/role/SQL/session対応を差し替えます。共通kernelへcloud別の条件分岐を散らす拡張は避けます。

## 12. 実装前に固定する未決

- 初回GCP/PostgreSQLのmanaged field ownershipと、外部console変更があり得る場合のconditional-write/外部調整モード。
- client切替checkpointの初期UXと、操作者の確認・実際に管理できるclient設定の境界。
- SQLiteのライブラリ、schema migration、ledgerとimmutable証拠のbackup/復旧単位。追加依存を採用するなら必要性・保守・ライセンス・導入負担をその時点で判断する。
- 初版で実装するnative effectの範囲。Standingの接続許可・直接経路制限から始め、JIT自動失効や既存session停止はcapabilityを満たす組合せだけで提供する。
- 遠隔・複数利用者の承認認証は将来capability。初版の信頼するローカル操作者モデルと混ぜない。

これらは設計上の選択です。新しいフィジビリティ実験やbenchmarkを開始する指示ではありません。未決を理由に主要RDBMSという製品構想を縮めず、実装する縦切りと提供できるeffectを明示して進めます。
