# 基幹実装のマイルストーンとAI作業設計

K10の設計見直しを完了し、[基本設計](k10-evidence-design.md)・[詳細契約](k10-evidence-contract.md)・[実装単位A〜Fと受入条件](k10-work-plan.md)を追加しました。[K10-A](k10-a-contract.md)のsource参照・policy v2・証拠/評価契約の型とv1互換性を実装・ローカル検証しました。続いて[K10-B](k10-b-admission.md)の受入台帳・保存・offline再読取を実装・L検証しました。[K10-C](k10-c-source.md)のGCE source署名/context確認・固定取得・B接続も実装・L検証しました。初期はroot host profileで、実GCE/Linuxは未確認です。PG producer・評価器は未実装で、v2 native適用は停止します。次の実装単位はK10-Dです。

K01〜K08の初期実装後の照合と後続候補は[設計・実装照合](design-implementation-audit.md)に記載しました。K09の要求別事前判定・根拠範囲・完了表示は実装・L検証済みです。[K09の結果](k09-qualification.md)を参照します。次の未完了はK10のnative→共通effectiveです。下表K01〜K08の初期完了を、全体設計の全条件達成へ読み替えません。K10-D〜FとK11/K12は未着手です。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存RDS PostgreSQL／専用RDS Proxy向けのコードとローカル検証を追加しました。[現在の対応・操作・効果待ちの境界](k07-aws.md)を参照します。実AWS操作やworkload sourceに束縛した直通拒否の確認は行っていません。

K06更新: 状態評価、限定reconcile/recover、Deny更新、所有IAM/SQL差分の回収、DB login停止を実装・ローカル検証しました。[使い方・完了範囲・残る制限](k06-lifecycle.md)を参照します。cloud/実DBの操作は行っていません。

更新: 依存整理とK05の実装・ローカル検証済みです。[実装契約と未確認事項](k05-native.md)を参照します。クラウド操作は行っていません。

2026-11-02に基幹設計を作成し、継続指定でK01/K02、続いてK03/K04、依存整理とK05を実装しました。フィジビリティは区切り、クラウド操作は行っていません。共通kernelのローカル回帰・静的検査まで完了しています。[使い方と実装境界](operation-ledger.md)を参照します。

## マイルストーン

| ID | 到達点 | 完了する振る舞い | 依存・対象 |
| --- | --- | --- | --- |
| C0 | 基幹設計 | 保護の目的、二軸adapter、policy、変更lifecycle、アプリ切替・復旧、作業分割が揃う | 本文書群。今回の成果 |
| C1 | 共通policyとcapability | クラウド/DBを分けて登録し、必要な保護を表現できない組合せを変更前に返す | K01/K02 |
| C2 | 操作の一貫性 | immutable plan、限定承認、永続journal、結果不明照合、中断再開、handoffがつながる | C1、K03/K04 |
| C3 | GCP PostgreSQLへの導入 | 新保護経路・限定権限の準備、アプリbinding配布・切替、旧経路閉鎖を一つのoperationで扱う | C2、K05。具体的環境へ適用する承認は別 |
| C4 | 保護の変更・回収・復旧 | 新規接続/session/SQL権限の効果を分け、反映待ち・部分失敗・外部変更を残して操作できる | C3、K06 |
| C5 | 配置先・DBの拡張 | AWS PostgreSQL、次にMySQLを二軸へ追加し、共通操作モデルを再利用する | C4、K07/K08 |

C3/C4は、単に計画や観測を出すだけでなく、限定executorを含む導入・維持機能の完成を指します。実装完了と実導入の成功は別に記録します。今回の設計完了のために追加環境や試験を用意しません。

## 作業パッケージ

型と契約の正本は[control plane](control-plane.md)、[data plane](data-plane.md)、[lifecycle](security-lifecycle.md)です。以下のpathは提案する編集境界であり、まだ存在しないmoduleを実装済みとは扱いません。

| ID | 担当範囲・入力 | 出力・完了条件 | 依存 |
| --- | --- | --- | --- |
| K01 | `src/core/policy*`, `src/core/capability*`。core設計と既存strict configを入力 | PolicyRevision、TargetHandle、Subject、Grant、ProtectionProfile、CapabilityDescriptorと不変条件。未知field・秘密・unsupported conditionを拒否し、provider名で保護達成を推定しない | C0 |
| K02 | `src/adapters/*`のinterfaceとread-only bridge。現行AWS/GCP観測を入力 | DeploymentAdapter/EngineAdapter、target世代と構成版、観測の欠落・保証段階を正規化。観測bridgeだけで変更能力をimplementedへ昇格させない | K01の契約固定。骨格の設計は並行可 |
| K03 | `src/core/plan.rs`, `change.rs`, `approval.rs`。policy/capability/観測を入力 | step DAG、diff、precondition、blast radius、manual handoff、失効効果、限定補償/repair。plan hashと承認scopeを固定し、実行不能な条件を実行前に返す | K01/K02 |
| K04 | `src/operation_store*`, `src/core/operation*`, `src/core/orchestrator*` | transaction journal、target lease、native operation参照、再開/照合/部分失敗。結果不明の無条件retryや全体snapshot rollbackをしない。秘密を保存しない | K01/K03。store骨格はK03と並行可 |
| K05 | `src/adapters/deployment/gcp*`, `src/adapters/engine/postgres*`, `src/binding*` | 初期profileのtyped native executor、DB login/限定role、秘密なしbinding、手動切替受領、直通制限の順序。既存API/DB権限のscopeを越える変更を拒否し、未切替のclientを隠して閉鎖しない | K02/K03/K04 |
| K06 | `src/core/state*`とGCP/PGのrevoke/recover処理 | desired/observed/effective、鮮度、Allowedを残すPending、承認済みreconcile、独立復旧。共有sessionの帰属不足は明示gap、CLI停止時の期限回収を保証しない | K04/K05 |
| K07 | `src/adapters/deployment/aws*`とPG組合せ | RDS Proxy等の配置差分、native認証、SG、DB権限を同じ操作modelへ接続。既存AWS probe契約と未完了記録は保持 | K06 |
| K08 | `src/adapters/engine/mysql*`と選択した配置先binding | MySQL固有account/role/driver/認証/sessionのcapabilityと導入処理。PG専用SQLやSA名変換を流用しない。初期組合せはAWS RDS MySQL 8.0.43／東京に固定して実装・L検証済。実導入は未確認 | K06。K07との優先順はAWS PG→MySQL |

K09は`adapters/qualification`とCLI/composed executorで現在の要求を再判定し、GCP source未確認の証拠範囲とnative完了表示を整合しました。coreのhash/approval形式は維持し、受付済みqueryと新規writeのgateを分離しています。実装・L検証済みで、次はK10候補です。

共通CLI、`main.rs`、`lib.rs`、`Cargo.toml`/lock、文書入口は主担当が所有します。各Kの責務が固まった時点でCLIへ統合し、別担当が同じ共有fileを同時編集しないようにします。外部ライブラリ追加は必要性・保守・ライセンスを確認し、依存追加だけを別の大調査にしません。

## 並列化と引継ぎ

最初にK01の型と用語を短く固定し、K02の観測bridge、K03のplanner、K04のstoreを分けます。plannerが受け取る観測schemaと、executorが記録するreceiptを先に一致させます。K05ではprovider変更とDB変更の担当を分けられますが、同じtargetへの副作用はorchestratorが直列に制御します。

一回の引継ぎには、担当したK、変更file、公開した型・版、成立する振る舞い、残るgap、次担当が使う入力だけを残します。各担当が別々のpolicy型や状態機械を作ること、既存AWS/GCP evaluatorを全置換することは避けます。

アプリhandoffは単なる「完了」booleanにせず、binding revision、適用したdeployment、申告者、時刻、稼働の根拠を区別します。初版に任意script hookや汎用deployment engineを追加しません。

## 実装時の判断と停止条件

設計時に追加試験を区切り、その後の基幹実装指定に従ってコードの必要なローカル確認を行います。本書は新たなフィジビリティ・負荷・クラウド試験を予約するものではありません。既存の実機結果を未実装基幹の実証へ読み替えません。

具体的な導入先への権限変更・課金・既存アプリ切替・公開は対象と影響を示した承認範囲で扱います。同一plan内の許可済み再試行やrepairまで毎回聞き直す設計にはしません。未知のtarget世代、権限scope拡大、共有clientへの影響増加、回復不能な操作が必要なら、そのstepを止め、残った保護と安全な復旧先を提示します。

既存のM0〜M6/T00〜T26は旧AWS系列とGCP観測実装の到達点として保持します。C/K系列は保護を導入・維持する基幹の順序であり、旧AWS M3/T17〜T20の追加実験を先行必須にしません。過去の未完了を完了へ変更せず、次の製品実装の依存だけを分けます。
