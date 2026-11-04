# 変更・承認・操作台帳と中断再開

K09更新: 要求別の事前判定と、操作完了・保護未評価の区別を実装・ローカル検証しました。[現在の判定・CLI・残るK10の境界](k09-qualification.md)を参照します。追加フィジビリティ・実クラウド操作は行っていません。

K08更新: PostgreSQLのGCP/AWS対応を維持し、既存AWS RDS MySQL 8.0.43／専用Proxyのアダプターを追加しました。[現在の組合せ・CLI・部分失敗と未確認の境界](k08-mysql.md)を参照します。実クラウド・実DBへの操作は行っていません。

K07更新: 既存RDS PostgreSQL／専用RDS Proxy向けのコードとローカル検証を追加しました。[現在の対応・操作・効果待ちの境界](k07-aws.md)を参照します。実AWS操作やworkload sourceに束縛した直通拒否の確認は行っていません。

K06更新: 状態評価、限定reconcile/recover、Deny更新、所有IAM/SQL差分の回収、DB login停止を実装・ローカル検証しました。[使い方・完了範囲・残る制限](k06-lifecycle.md)を参照します。cloud/実DBの操作は行っていません。

2026-11-02。K03の残契約とK04の共通kernelを実装しました。追加フィジビリティ・クラウド操作は行っていません。続いてK05のnative executorを実装し、[依存境界と実装範囲](k05-native.md)を記録しました。本書の`guard resume`はローカルのみで、native適用は別の明示コマンドです。

## 計画と限定承認

`guard plan`は従来の`plan.json`に加えて`prepared-change.json`を生成します。正規化policy、導入graph、取得できた構成との差分、共有資源の競合key、操作上限、限定repair recipe、復旧・補償計画を一つのhashへ束縛します。読込時は元policyからgraphと派生情報を再構築し、JSONの再hashだけでは異なるstepやscopeを混入できないようにしています。

実構成を取得していないfield、SQL権限、TLSの実効等はUnknownです。generic profileからIAM認証やconnector制限の解除を推定しません。元の観測は対象・時刻・出所・native資源と保存artifactのhashへ対応付けます。

revision 2以降の作成には`--previous-policy`で完全な旧policyを渡します。parent hashだけで旧許可の回収を推定しません。現graphで扱えない旧Grant/targetの削除、主体・DB login・native資源の付替えは`RevokePlanRequired`とし、明示的な失効計画へ戻します。

承認はchange hash、policy revision、対象、step、repair recipe、復旧scope、実行主体、発行時刻、通常/復旧期限、操作上限へ束縛します。同じ承認内で許可された再試行は継続できます。期限延長・対象差替え・scope拡大は同じ承認を変更せず、新しい計画・承認で扱います。これは信頼するローカル操作者の意思記録であり、独立した承認者の認証や電子署名ではありません。

## CLIで台帳へ登録する

`runs`を既存の保存先として使う例です。出力planは毎回新規にし、ledgerの親directoryは自分が所有し、group/worldから書込みできない場所にします。

```sh
cargo run --locked --offline -- guard plan \
  --policy examples/core-policy.yaml --out runs/core-plan-3

cargo run --locked --offline -- guard approve \
  --plan-run runs/core-plan-3 --ledger runs/operations.sqlite \
  --approval-id approval-1 --approver operator --execution-identity runner

cargo run --locked --offline -- guard begin \
  --ledger runs/operations.sqlite --approval-id approval-1 \
  --operation-id operation-1 --request-id request-1 --execution-identity runner

cargo run --locked --offline -- guard status \
  --ledger runs/operations.sqlite --operation operation-1

cargo run --locked --offline -- guard resume \
  --ledger runs/operations.sqlite --operation operation-1 \
  --expected-version 0 --execution-identity runner
```

`plan`は現在も終了3です。`approve`はローカル記録完了なら0、未完了operationの`begin/resume/cancel`は3、`status`の読取完了は0、入力・期限・競合・台帳失敗は2です。いずれもnative保護の合格コードではありません。

初回`begin`のversionは0です。変更後は`status`が返す最新versionを指定します。新revisionの開始は`--expected-desired-head`へ現在のpolicy revision hashを渡します。同じrequest ID・同じ入力の再送は既存operationを返し、別の入力への再使用は拒否します。desired head更新とoperation作成は一つのtransactionです。

標準CLIには`UnavailableExecutor`しか設定していないため、`resume`は`NeedsAction`、native attempts 0で止まります。任意shell、receiptファイル、合成driverをCLIから実行する入口はありません。実行主体名はローカルの役割参照であり、nativeの資格情報を認証した証拠ではありません。

停止は`guard cancel --ledger ... --operation ... --expected-version ...`、承認の回収は`guard revoke-approval --ledger ... --approval-id ...`です。どちらも受理済み処理や既存sessionを取り消したことにはせず、desired policyを過去のAllowへ自動復元しません。

## 中断・再開の契約

| 状況 | 共通kernelの動作 |
| --- | --- |
| dispatch前 | 承認・取消し・期限・予算・desired head・version・lease・依存stepをtransaction内で照合 |
| 外部処理の直前 | stable idempotency keyと`Dispatching`をcommitし、その後にexecutorへ渡す |
| 送信後に中断/結果不明 | 再開はqueryから。結果を照合できなければOutcomeUnknownを保持し、再送しない |
| 未適用を確認できた | 許可された予算・期限内で同じidempotency keyを使い再試行 |
| provider受付だけ確認 | Submittedと実効Unknown/Pendingを分ける。全stepの効果が成立するまでCompletedにしない |
| 承認取消し・期限到来 | 新規dispatchは拒否。既に受理された処理の読取照会・結果保存は継続可能 |
| 旧workerの遅れた応答 | leaseのfencing token・期限・operation versionで拒否。未解決のdurable記録を次workerが照会 |
| 処理中に期限を超過 | Clockを各dispatch/保存時に読み直す。pass開始時刻を使い回して期限内とは扱わない |

leaseはtargetと共有resource/fieldを安定順で取得します。別DBでも同じproject IAM等のscopeが重なる場合は競合します。内部leaseは外部consoleや別のIaCを排他しません。nativeの同一性・版・所有と前提条件の再照合は、実行adapterの必須契約です。

repairは世代・構成epoch・desired parameter・回数・間隔・期限へ限定したrecipeを承認に含めます。復旧も所有receiptと変更後条件を必要とし、広いIAM/SQL権限や直接経路を自動復元しません。recipe/補償の計画・承認scopeは実装済みですが、現在desiredの限定repairはK06で実装し、旧状態へのcompensationは自動実行しません。

## SQLiteの保存と限界

`rusqlite 0.41.0`とCargo.lockで版を固定した同梱SQLite 3.54.1を使い、transaction、DELETE journal、FULL同期を行います。VDG1 application ID・schema version 1以外の既存DBは変更せず拒否します。statusのpath誤りで新しいDBを初期化しません。private file、owner、symlink/hardlink、sidecarと親directoryの条件を確認します。token/passwordや顧客行を台帳へ格納するfieldはありません。SQLiteの暗号化は提供していません。[ビルド環境の固定](../build-environment.md)を参照します。

初期上限は台帳256MiB、event読取16,384件。上限超過はエラーとして返し、過去の履歴を削除・黙って切り捨てません。操作予算の既定値は総dispatch試行128回、操作時間3600秒、recipe当たり回収/修復回数上限2、並行step 1です。変更する場合は`guard plan`の`--max-attempts/--max-operation-seconds/--max-repair-executions`で計画に固定します。

正本controllerは一台です。台帳を複数hostへコピーして同じtargetを並列操作する構成は提供しません。ライブbackup・schema upgradeは未実装です。保存は既存のimmutable証拠runと分離しているため、保全対象は台帳と参照する証拠の両方です。同じOSユーザーによる悪意あるファイル改変まで署名で防ぐ構成ではありません。

## ローカル確認結果

Rust 1.98.1で全体`cargo test --locked --offline`は188件成功、既存の明示実DB試験2件はignoredです。K03/K04の追加35件には、crash後のreopen、query前の再送禁止、stable key、期限/取消し後の照会、古いworkerの書込拒否、7step完走、別プロセスCLIの永続化、foreign DBの無変更拒否を含みます。合成driverの成功は実環境の防御成立に数えません。

`cargo fmt --all`と`cargo clippy --locked --offline --all-targets -- -D warnings`も完了しました。読み取りレビューの指摘を反映しています。追加フィジビリティ、クラウド/API操作、公開は行っていません。

合成例の別プロセスCLI記録: [workflow.json](../../runs/core-ledger-20261102-k03-k04-1/workflow.json)、[再開後status](../../runs/core-ledger-20261102-k03-k04-1/status-after-resume.json)。Prepared→NeedsAction→Cancelled、native attempts 0を記録しています。
