# 詳細設計書

次期基幹の詳細契約は[control plane](core/control-plane.md)、[data plane](core/data-plane.md)、[security lifecycle](core/security-lifecycle.md)を正本とします。共通policy、capability、immutable plan、限定承認、OperationStore、結果不明の照合、アプリ切替と復旧を定義しています。[実装計画](core/implementation-plan.md)のC/K系列が次の実装順序です。これらは設計であり、現行CLIの型・コマンドを実装済みに変更しません。

継続実装でK01/K02、K03の変更・承認、K04の台帳・再開kernelを追加しました。[実装契約・使い方](core/operation-ledger.md)を参照します。policy型は`src/core/policy.rs`、変更・承認は`src/core/change.rs`と`approval.rs`、台帳は`src/operation_store.rs`、再開は`src/core/orchestrator.rs`を正本とします。以下のAWS契約を上書きせず、`guard`の別schemaとして統合しています。

以下の既存AWS契約を維持し、追加GCPコマンドの型・引数・判定・実機範囲は[GCP CLI仕様](gcp-cli.md)を正本とします。GCPは`gcp check/report`の別schemaで、AWSの設定・証拠へ読み替えません。

設計契約と実装上の境界を記録します。現在のCLIは `--help`、型の正本は `src/domain.rs`、実施/未実施は [ローカル検証記録](local-validation.md) を参照します。共通契約を変えるときは利用側・検証・作業設計書も更新します。

## 1. CLIと副作用

コマンド名は `veil-db-guard` です。

| コマンド | 入力 | 出力 | 許可する副作用 |
| --- | --- | --- | --- |
| `plan` | `--config`、任意の `--snapshot`、新規 `--out` | 期待構成、差分、不足情報、変更・復旧手順。指定時はsandbox用CFN | ローカル新規保存のみ。AWS/DBに接続しない |
| `inspect` | `--config`、任意の `--aws-profile`、新規 `--out` | 正規化した構成snapshotと取得状態 | 明示対象のAWS読取APIのみ |
| `probe` | `--config`、`--snapshot`、`--suite`、`--source-id`、`--allow-network`、liveは `--allow-aws-read`、任意 `--experiment-plan`、新規 `--out` | 接続試験の観測。必要時だけ合成データの後条件 | 許可したendpointへの接続。liveは直前AWS再照合。書込は追加条件を要求 |
| `report` | `--config`、一つ以上の `--evidence`、複数phase時は `--experiment-plan`、新規 `--out` | `assessment.json` と `report.md` | ローカル読取と新規保存のみ。参照先URL等へ接続しない |

`--suite` は `positive / auth-negative / tls-negative / direct-path / recovery / performance` の明示選択です。`all` は初期版に作らず、障害・負荷・書込を暗黙に実行しません。複数suiteの結果はreportへ別々に渡せます。

書込試験は `--allow-test-writes` と、設定内の専用DB/schema/user/run用領域の宣言を両方要求します。さらに実行主体がその環境への試験を承認済みである必要があります。フラグが作業者への新しい権限を与えるわけではありません。M3の対象・資源削除・障害注入等は承認済み計画の具体的範囲を別途保持します。

未指定対象の探索、アカウント/リージョンの自動拡張、外部通知、テレメトリー送信は初期版に含めません。`plan` はsnapshotなしでも案を作れますが、現状との差分と適用可能性は未確認と表示します。

実装したfixtureモードでは `inspect --fixture` がCLI応答を正規化し、`probe --fixture` は観測を再生します。再生は必ずLocalFixtureへ変更し、外部のsource照合主張・protocolを取り除きます。ローカル実DB用 `--local-lab --local-password-stdin` はloopback専用のpassword注入で、live IAM経路と分離します。plan/inspect/probeは観測・生成操作の完了を `operation_only=true` で表示し、防御の判定はreportで行います。

live probeは入力snapshotのhashだけを信用せず、明示許可の下で対象ARN/Proxy名からendpoint/portを再取得して照合します。`--experiment-plan`指定時は事前のphase/window/configを照合し、before/after構成を別artifactへ保存します。after取得不能・取消しでも取得済み観測を保持し、部分完了とします。sourceの客観照合や未取得のIAM期限・pinning等を自動で確認済みにはしません。

終了コード案: `0`=要求された処理が完了し、評価対象の必須項目にfail/unknownなし、`1`=評価にfail、`2`=設定/引数/保存等の実行エラー、`3`=failなしでunknownを含む不完全な評価、`130`=キャンセル。評価をしないinspect/planは処理完了なら0でもよいが、`operation_only`を必須表示し、防御合格の0と区別します。reportで全件N/A・評価ゼロの場合は3です。保存失敗が併発した場合は2を優先し、既に得た判定をstderrへ秘密なしで要約します。

## 2. 対象設定の契約

形式は厳格なYAMLとし、未知のフィールド・重複キー・未展開プレースホルダー・非対応schema_versionを拒否します。任意コマンド、SQL、URL取得、環境変数展開を設定に埋め込む機能は設けません。秘密値を受けるフィールドを作らず、設定に秘密らしい任意値があってもその値をエラーへ引用しません。

| フィールド | 型・制約 |
| --- | --- |
| `schema_version` | 初版は整数1 |
| `assessment_profile` | バージョン付き固定評価目的。[検証設計](verification.md)の必須集合を参照。suiteで縮めない |
| `experiment_id / phase_id / configuration_epoch` | 実験、実行段階、構成状態のID。構成変更を行う試験はepochを分ける |
| `target.id` | runをまたいで利用する論理対象ID。非空の安全な文字集合 |
| `target.account_id / region / db_instance_arn / proxy_arn / proxy_name` | 明示必須。アカウント・リージョンが一致すること。Proxy ARNから名前を推定しない |
| `target.engine / engine_version` | 初期はpostgres。対象版を実装前に固定し、未対応は拒否 |
| `auth.mode / db_user` | `end_to_end_iam` または明示対応した `standard_iam`。ユーザー名の大小文字を保持 |
| `paths[]` | path ID、送信元ID、`application / unauthorized / admin`、宛先種別、許可/拒否期待、管理例外の理由コード |
| `sources[].id / kind / description` | 試験元の宣言。VPCホスト、VPN、トンネル等を区別。任意のdescriptionは入力専用で保存/表示/hash対象外。globalは予約ID |
| `test_scope.database / schema_prefix / db_user` | 合成試験専用の領域。書込suiteで必須 |
| `limits` | connect/query/total timeout、最大並行数、最大再試行数、最大結果件数・保存サイズ |
| `evidence_policy.max_age_seconds` | reportが受け入れる鮮度。対象試験計画で固定 |
| `performance_profile` | ワークロードID、測定条件、反復数、測定前に決めた受入値。performance suiteで必須 |
| `tls.ca_file` | 任意の公開CA PEMパス。未指定はbundled public roots。検証無効化オプションなし |
| `auth_negative` | 明示した不許可profile/userの参照。秘密値は含めない。未指定actorは作らない |
| `recovery_profile` | 長いtoken期限試験の明示許可と、有限のlong transaction時間。901秒待機は総期限905000ms以上も要求 |

AWS core profileでは最低限、アプリ→Proxy許可と同じアプリ→DB拒否のpathを必須にします。管理元と宣言した全関連endpoint/address familyも検証行列へ展開します。未試験のpathや必須の負例を設定から省いてpassにできないよう、T01で固定する対象行列とprofileの必須caseを照合します。任意のdescription等の自由文は保存せず、正規化設定は判定に影響する安全な選択フィールドのみです。`config_hash`もこの正規化データに対して計算します。

初期の保守的既定値案は接続10秒、SQL10秒、全体120秒、並行数1、再試行0です。長時間の認証期限試験・性能試験は用途別profileで明示的に延長します。具体値はT01/T11で妥当性を確かめ、固定した試験計画を記録します。設定しただけで適切な性能や安全性を保証する値とは扱いません。

endpoint/portはARNに対応するsnapshotから解決します。利用者が明示したendpointを使う拡張は、対象との対応を検証できる場合に限定します。DNS名はTLSのホスト名検証にも使い、IPへの置換で検証を省略しません。run開始時の解決先、port、対応対象、snapshot時刻を記録し、別対象への差し替わりを検出した場合は中断します。AWS標準のDNS変更を固定IPで妨げず、再接続時の対象確認方法はT07で具体化します。

## 3. 型とインターフェース

以下はRust側の論理的な契約です。traitを汎用フレームワーク化せず、外部I/Oを試験で差し替える最小境界にします。

| 型/操作 | 内容 |
| --- | --- |
| `TargetConfig` | 検証済み設定。秘密を持たない |
| `InventorySnapshot` | 対象ID、account/region、DB/Proxy/target/全関連SG等の選択フィールド、各取得の状態 |
| `ChangePlan` | 現状/期待/差分/前提/未確認/影響/順序/復旧/再検証ID。変更実行機能なし |
| `Observation` | 一つの試験・構成取得の観測。推論とは分ける |
| `PathStage` | `transport_reachable / tls_established / db_authenticated` をそれぞれ `observed_true / observed_false / unknown` で保持。後段の拒否で前段の到達を打ち消さない |
| `Assessment` | 要求ごとのverdict、必要証拠、理由、不足、対象範囲 |
| `InventoryReader::read` | TargetConfigと期限/取消しを受け、部分失敗を含むSnapshotを返す |
| `ProbeRunner::run` | 検証済み設定、snapshot、明示suite、期限/取消しを受け、Observationsを返す |
| `evaluate` | 設定と検証済み証拠からAssessmentを作る純粋な処理。ネットワーク不要 |
| `render` | Assessmentと参照からJSON/Markdownを作る。任意HTMLや外部内容を実行しない |

AWS APIのページングと部分失敗は取得状態として表現します。結果ゼロと未取得を区別し、必須対象が複数/不在/別accountなら実接続を始めません。

## 4. SnapshotとAWS adapter

対象候補APIは `DescribeDBProxies / DescribeDBProxyTargets / DescribeDBProxyTargetGroups / DescribeDBInstances / DescribeDBParameters / DescribeSecurityGroups`、実行主体の照合には `GetCallerIdentity` を検討します。APIごとの必要権限とresource scope対応はT06で公式仕様を確認し、権限表を作ります。AWS IAM上resource指定できないDescribe操作には、CLI側のfilter・読取後照合・account/region限定を併用します。IAMで強制できる範囲とCLIの限定を混同しません。

取得するのは判定に使う選択フィールドです。SDKレスポンスを丸ごと保存しません。初期化SQL、説明文、タグ、health description等はそのまま保存せず、必要な列挙値と機密を含まない理由コードへ変換します。`GetSecretValue`、DB変更API、IAM変更APIは構成読取adapterに含めません。

ProxyのIAMモード、RequireTLS、RoleArn、VPC/subnet/SG、対応targetとport、health、DB engine/version、IAM有効、public設定、parameter groupと適用状態、関連SGの許可を記録します。DB実行時parameter/roleの確認が必要なら、別の明示read-only probeで取得し、APIのdesired値と混ぜません。

## 5. 証拠の契約と保存

各コマンドは存在しない出力ディレクトリへ書き込みます。存在するパス、想定外のsymlink、外へ出る相対参照は拒否します。run作成時に厳しい権限（Unixではディレクトリ0700、ファイル0600）を設定し、他OSの権限対応は対象OSを決めてT04で確認します。初期の動作確認対象は利用者のmacOSと、AWS検証元のLinuxを候補とし、Windows対応は未確定です。

```text
<new-run-directory>/
  manifest.json          # schema、run、対象、時刻、tool version、完了/中断、各成果物hash
  config.normalized.json # 秘密なしの検証済み設定
  snapshot.json          # inspectの場合
  plan.json              # planの場合
  sandbox.yaml           # 明示生成時のみ。未適用
  observations.json      # probeの場合
  assessment.json        # reportの場合
  report.md              # reportの場合
```

`manifest.json`は開始時にin-progressとして作り、終了時にatomicに置き換えます。既存ファイルを壊さず、同じrunの内部状態だけ更新します。途中失敗はpartial/interruptedを残します。書けなかった結果を保存済みと報告しません。ハッシュは保存事故の検出と参照同一性用で、悪意ある編集に対する真正性の保証ではありません。

Observationの必須項目:

```json
{
  "schema_version": 1,
  "run_id": "example-run",
  "experiment_id": "example-experiment",
  "phase_id": "protected",
  "configuration_epoch": "example-epoch",
  "assessment_profile": "aws_sandbox_core_v1",
  "verification_id": "V09",
  "case_id": "V09.application-db.transport",
  "attempt_id": "example-attempt",
  "requirement_ids": ["R05"],
  "evidence_kind": "aws_connection",
  "target_id": "example-target",
  "path_id": "application-to-db",
  "source_id": "example-source",
  "source_verification": "declared",
  "config_hash": "example-sha256",
  "snapshot_hash": "example-sha256",
  "observed_at": 1793577600,
  "duration_ms": 10000,
  "execution": "timeout",
  "outcome": "connection_not_established",
  "path_stages": {
    "transport_reachable": "unknown",
    "tls_established": "unknown",
    "db_authenticated": "unknown"
  },
  "reason_code": "connect_timeout",
  "evidence_refs": []
}
```

これは形式説明用の架空例であり実測値ではありません。`source_verification`は `declared / corroborated` とし、宣言のみで送信元の客観確認済みとは報告しません。AWS上のホスト識別子・SG対応や実行手順の記録等で、何を照合したか参照を持たせます。

実装では時刻はUnix秒で保存し、CLIの入力値やparser/driver/CLIのエラー全文をエラー表示へ引用しません。YAMLはserde-saphyrの重複拒否・構造予算とstrict型を使い、anchor/alias/tag/補間を許可しない小さな部分集合です。保存はUnixのprivate権限と開いたdirectory fdを使い、出力pathをsymlinkへ差し替えても別directoryへ書き込みません。

`case_id`はprofile/検証仕様が定義する固定IDで、T03で全必須caseを列挙します。自由入力の検証名を充足判定に使いません。experiment/phase/epoch/profile/verification/case/path/sourceの組を照合し、attempt_idが異なる同じcaseの反復を別caseの充足として数えません。manifestはこれらへの対応とtool version/build IDを保持します。V14のローカル結果をAWS実験へ添える場合も、試験したbuild IDと実行したbuild IDが一致することを要求し、AWS接続証拠とは別欄にします。

証拠種別は `local_fixture / local_connection / aws_configuration / aws_connection / operator_attestation`。実行状態は `completed / error / timeout / cancelled / not_run`。観測のoutcomeと要求へのverdictは別の値です。

レポートに含めるのは許可した列挙値、ID、集計、理由コードと必要な識別情報だけです。token/password/DSN、SDK/driverのエラー全文、SQLバインド値、顧客行、秘密を含み得る任意文字列は出力しません。詳細診断でも秘密除外を解除するオプションは設けません。

## 6. 判定アルゴリズム

1. schema、サイズ、参照hash、対象、account/region、設定とsnapshotの対応を検証する。
2. assessment_profileから必須検証/case/pathの集合を展開する。未実施もunknownとして結果に必ず含める。対象試験に必要な証拠種別・path/source・時刻・設定状態を確認する。鮮度超過、変更済み、前提不明の証拠を現在の合格/不合格に使わず、履歴として残す。
3. 要求に対する確実な違反を観測したらfail。原因不明や未実施はunknown。
4. 必要な正例・負例と後条件がそろった場合だけ、その範囲でpass。
5. not_applicableは適用外の理由とスコープ定義を要求し、初期必須要求を除外してマイルストーンを達成したことにしない。

たとえば認証拒否には、同じ到達可能な経路の正規接続成功と、認証異常に対応した失敗の証拠を要求します。ネットワークタイムアウトを認証成功の防御とは判定しません。直接経路拒否の試験は、同一アプリ送信元からのProxy成功とDB直接経路のネットワーク到達性、対象/現在構成の対応を組み合わせます。ネットワーク閉鎖を期待するpathでTCP到達を観測したらfailであり、その後のTLS/認証拒否をネットワーク閉鎖のpassにしません。TCP拒否も宛先サービス停止による可能性があるため、正規経路とDBの稼働を確認します。理由を確定できないtimeoutだけならunknownとし、「接続できなかった」という観測を残します。

全体の要約は、必須項目にfailがあればfail、failがなくunknownがあればunknown、適用される必須項目が一件以上あり全件passならpassです。必須項目がゼロ・全件N/Aならunknown。構成上の適合とAWS実接続上の適合は別の集計欄にし、local_fixtureのpassをAWS接続のpassへ昇格させません。

reportにはprofile、展開した必須集合、対象・時刻・試験元・未実施/適用外・判定理由・必要な次の確認を必ず表示します。同一状態の正負例等を組み合わせる証拠群は、同じexperiment/phase/epoch/対象/正規化設定、計画で定めた短い試験区間、前後の関連フィールドのsnapshot一致、区間中に関連変更を行わない実行記録を要求します。変更しないという運用者申告はoperator_attestationとして別記し、構成の絶対的不変の証明にはしません。この条件で認めるのは「記録した試験区間と観測範囲内の適合」です。前後照合がなく申告のみ、途中の未説明変更、関連フィールド欠落の場合はunknownです。鮮度内であることだけでは条件を満たしません。

一方、実験全体は `baseline / protected / fault / recovered / cleanup` 等の複数phase/epochを持てます。T16で試験前に作る `experiment-plan.json` に、experiment ID、profile版、phaseと順序、各phaseの対象・設定hash・必須case/path、phase間の許可差分、性能の比較条件、復旧期待状態、片付け/保持対象を記載します。reportは各caseを対応するphase/epoch内で評価してから、同じexperiment内の個別評価をprofileへ集約します。V13はbaselineとprotectedの許可された条件差を照合し、V11/V12はfaultからrecoveredへの遷移と復旧後の再試験、V21はcleanup後の最終状態を評価します。異なるepochの正負例を同時状態の証拠へ合成したり、削除後snapshotを削除前と一致させたりしません。未計画の差分・対象の変化は対応する評価をunknownにします。計画は実行後に受入条件を緩める形で上書きせず、変更時は版と理由を残します。

## 7. 接続試験とSQL

正規試験では、専用schema内でrun固有の領域に合成値を作り、INSERT/SELECT/UPDATE/DELETE、commit、rollback、途中エラー後のrollbackを確認します。SQLは製品側の固定セットと型付きバインドに限定し、設定から任意SQLを実行しません。スキーマ名等の識別子は検証済みの安全な形式から生成します。cleanupは同じrunで所有を確認した試験対象に限定し、残ったものは報告します。実顧客領域の自動削除は行いません。実際の試験用領域の削除は、対象・目的・影響・復旧可否を示した承認範囲内でだけ行います。

IAMトークンはAWS資格情報から必要時にSigV4署名で生成し、認証時だけメモリ上で使います。`generate-db-auth-token`をリモートAWS APIとして設計しません。新規接続とプール再接続で有効な認証情報・トークンを取得します。意図的な期限切れ試験以外では、期限切れトークンを再利用しません。

TLSはホスト名と信頼チェーンを検証する設定を必須にします。負例では、TLS無効、信頼しないCA、ホスト名不一致を別試験にし、ユーザーの通常接続設定を恒久的に弱めません。Proxy経由で得たDB SSL関連SQLだけで、クライアント→ProxyのTLSを立証しません。

Query timeout時にDBへのCancelRequestが効く前提を置きません。初期案ではサーバー側statement_timeoutと接続切断・上限を組み合わせ、タイムアウト後も実行中となり得る操作を明示します。Proxy対応のdriver/protocolとtimeout挙動はT02/T07で確認します。接続切断後のCOMMIT結果が不明なら、同じ書込を自動再送しません。試験用operation IDと後条件で結果を照合し、照合不能ならunknownとします。

## 8. 並行処理・障害・性能

最初は並行数1で実装し、performance profileに限って上限内で増やします。接続確立・SQL・全体の期限は別々に持たせ、取消しを子処理へ伝播させます。取消し後は新規接続/新規試験を開始せず、既知の状態・残資源を保存します。

再試行は対象操作ごとに許否を固定し、読取API等の一時障害だけ有限回にします。IAM拒否、TLS検証失敗、DB権限不足、結果不明の書込は汎用retryに入れません。

性能比較は同一DB/engine/class、配置、TLS、ユーザー権限、driver、データ、SQL、同時数、retry条件を固定し、直接接続とProxyを交互または順序の影響を説明できる方法で測定します。接続確立とプール済みSQL、pinningあり/なしを分け、ウォームアップ、反復数、生の時間系列、p50/p95/p99、エラー率、DB接続数の取得条件を記録します。標本不足なら分位点を断定せず、観測数と範囲を出します。

防御後のアプリ→DB経路を性能測定のために無断で開きません。直接接続のbaselineは経路を閉じる前か、別途承認した専用baseline経路で取得し、条件差を記録します。受入値は測定前に用途と基準から固定します。

## 9. エラーと互換性

理由コード例: `CONFIG_INVALID / TARGET_MISMATCH / UNSUPPORTED_TARGET / AWS_ACCESS_DENIED / SNAPSHOT_INCOMPLETE / IAM_DENIED / TLS_REJECTED / DB_AUTH_FAILED / DB_PERMISSION_DENIED / NETWORK_UNREACHABLE / CONNECT_TIMEOUT / QUERY_TIMEOUT / WRITE_OUTCOME_UNKNOWN / CANCELLED / EVIDENCE_STALE / EVIDENCE_INCOMPATIBLE / STORAGE_FAILED / UNKNOWN`。

driverのエラーから原因が一意に分からない場合はUNKNOWNに留めます。reason codeと表示文字列は分け、自由なエラー本文を証拠に複製しません。

スキーマの未知majorは拒否し、旧形式を推測してpassにしません。初版では自動移行を作らず、対応した形式だけを受け入れます。製品版、設定hash、対象条件、driver/SDK版を記録し、再現条件を追えるようにします。
