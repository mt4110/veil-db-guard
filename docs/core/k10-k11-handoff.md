# K10からK11への引継ぎと受入判定

2026-11-03追記：その後、[K11-Aの詳細設計とprocess/socket部分観測](k11-a-runtime-binding-design.md)を実装しました。以下の「K11未実装」は引継ぎ時点の記録です。実session・認証・TLS・pool結合と全RuntimeBindingは引き続き未完了です。

2026-11-03。K10の共通基盤は、source/evidence/admission/effective/executionの契約、対応範囲、Unknown/Unsupportedの扱いをローカルで受け入れ、K11の実装へ渡します。**全クラウド・全拒否層の防御が完成したという判定ではありません。** 個別profileの不足はnative閉鎖を引き続き止めます。

元の[K10作業設計](k10-work-plan.md)第5節は、部分状態・未対応を正しく示す共通契約を受入条件としています。K11が実装するアプリruntimeとの結合をK10側で確認済みとすることも、未確認を隠してK10完了にすることもしません。全環境の包括証明を追加の無限gateにせず、範囲ごとの状態を以下へ固定します。

| 今回の残項目 | 実装したもの | 判定の境界 |
| --- | --- | --- |
| 生成元を確認する観測 | 登録GCE root collectorの直接kernel syscall結果、UID/ns/cgroup/security選択値、sealed getter | 生成元確認とapp scopeは別。root EPERMをアプリ全体のRouteBlockedへ使わずUnknown。Cloud Logging候補のoriginは未確認 |
| AWS遅延route | source失敗時の5tuple、現在admissionからのsingle-use ticket、固定CloudWatch読取、非同期SQLite/archive履歴、改ざん検証付き再読取 | observed/receivedを分離。REJECT/ACCEPT/現在Allowedを保持し、履歴を現在の閉鎖証拠へ転用しない |
| 関連IAMの完全性 | GCP固定3permissionに加え、AWSの同一account・直接IMDS role・単一Proxy/user/action・無条件policy/boundary・組織条件を閉じた限定inventory | full flagは取得経路と前後資料から導出。組織member、未対応条件、取得欠損、別role経路、scope外はUnknown |
| K11の入口 | version付きRuntimeBinding入力契約とoffline `guard k11-readiness`、必要入力・現在不足・静的qualificationのexport | 実装開始の契約適合と、実環境の保護/承認/native dispatchを別にする。reportを承認へ流用できない |

個別仕様は[kernel origin](k10-origin-contract.md)、[AWS遅延route](k10-deferred-route.md)、[AWS IAM](k10-aws-iam-inventory.md)、[K11作業設計](k11-work-plan.md)を参照します。

## K10の受入条件との照合

1. GCP/AWS PGとAWS MySQLについて、sourceを確認する入力と不足する入力を分離し、native選択→sealed verifier→SQLite/archive→共通評価をローカルで確認する。未提供runtimeでは未知を維持する。
2. source snapshot、nonce、build/trust、target generation、policy/change/approval/request、現在と過去の時間を別に固定する。旧v1の意味・hashと旧wire省略時bytesを維持する。
3. SQL/TLS/binding/拒否層、Allowed/Unknown/Partial/有限Pendingを混同しない。今回の遅延履歴は現在のConfirmed型に変換できない。
4. native取得は明示opt-in、offline readはnative toolを呼ばず、write gateの直前再確認・query-only・所有範囲・承認条件を維持する。
5. provider/runtimeの取得可能部分とUnsupportedを明示する。root probe、API取得、policy列挙、ログfield一致を、app防御成立や全IAM完全性へ拡大しない。

この範囲を**K10共通基盤のローカル受入**とし、次はK11-Aを実装できます。全profileの実運用保証、native delayed-denialの帰属、一般組織IAMの完全評価が残ることは撤回しません。

## 継続拡張として残すもの

| ID | 内容 | 現在の安全な動作 | K11との関係 |
| --- | --- | --- | --- |
| K10-X1 | Cloud Logging writer/route/sink/委任を含むorigin閉包、またはprovider attestation | NativeLogOriginUnconfirmed | K11は不足を表示し、これを閉鎖根拠にしない |
| K10-X2 | AWS Flow Logsの単一probe帰属、source port再利用排除、native source実行契約 | historical-only / current Unknown | 遅延履歴のconsumerを実装できる。現在証拠とは分ける |
| K10-X3 | Organizations memberの全祖先policy、任意IAM条件・別credential/role経路 | incomplete inventory / Unknown | fixed scopeの完全性だけを使い、scope外の失効を保証しない |
| K10-X4 | MySQL role-host selector、既存session、同名再作成や間接操作の扱い | 既存の限定ACL scopeのみ | PGのK11-Aを待たせず、必要なengine拡張として扱う |

K10-Xは削除・合格扱い・実装済みへの言い換えではありません。いずれも独立した残タスクとして保持します。native閉鎖に該当証拠が必要なpolicyは、K11に進んでもその不足を残します。

## K11への具体的な最初の依頼

「K11-AのRuntimeBinding入力・生成・受入契約を実装する。PostgreSQL優先、GCP既存host profileから開始し、PID incarnation・実appのsecurity/network context・実session/route/transportをsourceとtarget generationへ束縛する。operator申告のみを確認済みにせず、実装後はlocal fake app/pool＋SQLite/archiveで検証する。モジュラーモノリスを維持し、追加フィジビリティ・実クラウド操作はしない。」

この依頼単位と入出力・受入条件は[K11作業設計](k11-work-plan.md)へ記述済みです。今回K11本体のruntime producerを作成した意味ではありません。

## 最終検証記録

`mise run check`はfmt・Clippy（`-D warnings`）成功、**621成功・0失敗・実DB用2件ignored（48 result groups）**。Rust 1.98.1 / macOS ARM64、locked/offlineです。[最終summary](../../runs/core-k10-handoff-local-20261103-1/summary.json)へ保存しました。

[ローカル引継ぎ見本](../../runs/core-k10-handoff-local-20261103-1/example-handoff/k11-handoff.json)はexample policy由来の合成設計入力です。`k11_implementation_can_start=true`、現在保護未評価、全effect未成立、native dispatch=falseで、1つのRuntimeBinding入力と13の現在不足を出力しました。実環境でReadyを確認したものではありません。
