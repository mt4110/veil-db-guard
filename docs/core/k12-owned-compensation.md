# K12 GCP PostgreSQLの所有IAM差分の限定補償

2026-11-05。設計のみ。GCP Cloud SQL PostgreSQL 16.15、asia-northeast1、専用サービスアカウントのStanding Grantを対象に、導入中にVeilが追加したIAM許可だけを一度の更新で取り除く。既存の復旧経路を使い、元の導入操作と補償操作を別々に台帳へ残す。

## 補償する差分

`ConfigureIdentity`が対象インスタンスだけに条件付けしてプロジェクトIAMに追加する `roles/cloudsql.client` と `roles/cloudsql.instanceUser` の2行を、**一つの所有差分**として扱う。各行のmemberは対象の専用SA一つ。両方を同じ元操作の一回の `setIamPolicy` で追加した場合だけ、同じ組を一回の更新で除く。片方の既存行を補った導入や、同じ条件タイトルの既存行を見つけて完了した導入には補償資格がない。

この差分を選んだ理由は、現在のアダプターに対象と主体を絞ったコンパイラーがあり、同一のプロジェクトIAM policyに対する更新を `etag` で条件付けできるため。条件タイトルはpolicy・登録・対象世代・grant・主体から決まる。同じタイトルや内容は元操作による追加の証明には使えない。従来の `StepReceipt` と `set_iam_policy` はその追加を証明する前後差分と更新応答のetagを保存しない。[GCPアダプター](../../src/adapters/deployment/gcp.rs)、[操作台帳](operation-ledger.md)、[IAM allow policyの競合制御](https://docs.cloud.google.com/iam/docs/allow-policies#etag)。

除去後も、IAM伝播中や別経路の許可による新規接続、既存セッション、SQL権限は残り得る。Cloud SQLフラグ、connector enforcement、ユーザー登録、NOLOGIN、SQL権限、資格情報、pool、セッション、JIT期限は補償対象外。旧Allowの復元やIAM policyのスナップショット復元も範囲外とする。

## 所有を立証する元操作の記録

新しいハッシュ領域の型付き `gcp-iam-owned-delta-v1` をアダプターから台帳へ渡す。次を照合し、アダプターが確定した記録だけを所有receiptとして受理する。

| 項目 | 照合する内容 |
| --- | --- |
| 台帳 | 元operation、change hash、policy revision hash、`ConfigureIdentity` のstep、dispatch attempt、idempotency key、実行主体、確定したstep receipt |
| 対象 | プロジェクトIDとimmutable project number、Cloud SQL native resource ID、登録ID、generation fingerprint、engine/version、grant ID、SA emailとunique ID、DB login |
| 変更前 | 完全なプロジェクトIAMの読み取り、etag、両タイトルが不存在、対象member・role・conditionの型検証。直前確認時点と正規化したpolicy内容のdigest |
| 書き込み | 直前etagを付けたリクエストとprovider成功応答。成功応答のetagは直前etagと異なり、内容差分がコンパイラーで求めた2行の追加だけであること |
| 変更後 | 別のfresh readが成功応答と同じetagおよび内容digestを返し、対象・主体の世代が一致。role、唯一のmember、conditionの全フィールドを含む2行を正規化して保存 |

policy全体は読み取り時だけ保持し、台帳へは照合に必要なdigest、etag、対象の2行、取得時刻を保存する。正規化はIAMで順序に意味がない配列と、条件を全て除いた場合にversion 1で返る仕様に限る。未知・重複・欠落により比較の完全性を保証できない読み取りは停止する。更新はversion 3を明示し、`bindings,etag,version` の範囲を使う。監査設定や他のバインディングは保持する。[IAM policyのversion規則](https://docs.cloud.google.com/iam/docs/allow-policies#versions)、[Resource Managerの更新契約](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/setIamPolicy)。

元操作の証拠は、元stepの結果・イベントを確定するSQLiteトランザクションに紐付ける。ハッシュだけを提示する任意ファイル、旧receipt、NoOp、書き込み応答を失った操作、証拠確定前のクラッシュから所有資格を後付けしない。通常の読み取りで構成を照合できても、所有は未確認のまま扱う。

## 計画と承認

K06の `guard recover` は現在desiredを修復する。K12は同じ入口の明示モード `guard recover --compensate-owned-iam --ledger <path> --source-operation <id> --grant <id> --out <dir>` を設計上の入口とし、フラグを指定しない場合は既存動作を維持する。このモードはローカルで計画を作る。補償を専用lifecycleと単一のtyped stepに束縛し、`DisableNativeIdentity` の汎用失効コンパイラーへフォールバックしない。新しいplan/change/approvalのハッシュ領域を使い、旧artifactと台帳の既存レコードを読める状態を維持する。[現行recover](k06-lifecycle.md)、[現行CLI](../../src/guard_cli.rs)。

- 元操作は停止済みの元導入に限る。取消し等でforward承認を無効化し、保留中または結果不明のnative書き込みがないことを台帳で確認する。公開・アプリ切替・直通閉鎖へ到達した操作は対象外。台帳の履歴に加え、対象SAが本番workloadや復旧経路で使用されていないことを現在の利用・経路確認で確かめる。判断材料が不足する場合は停止する。
- 元操作のAllow revisionが同じpolicyの現在desired headであることを計画・beginでCAS確認する。K06の失効時と同様に選択grantをDenyへ変更した子revisionを生成する。補償は2行の除去だけを計画し、Deny revisionの他の要求effectを達成済みにしない。他のAllowや管理例外が同じnative instance・SA、または対象バインディングを利用していれば停止する。
- 新しい承認は補償change hash、元operation/step/receipt、元と新desired revision、対象世代、grant・SA、差分、元の書き込み後etag、実行主体、期限・回数を束縛する。別revisionや新しいetagへの読み替えは拒否する。planで示す影響範囲はSAへの接続・IAMログイン許可の消失で、データ変更は含まない。
- beginは既存のdesired head CASと同じSQLiteトランザクションで元記録・停止状態・重複を再確認する。元operationとstepと所有receiptの組につき補償operationは一つ。既存のrequest ID再送は同一操作を返す。元操作の修復回数を増やさず、別operation IDの再発行で上限をリセットしない。

## 書き込みと再開

通常の `guard resume` はローカルのまま。native書き込みには既存の `guard apply-gcp --allow-native-changes` と、このchangeに束縛した新しい専用変更windowを使う。targetとproject IAMの既存conflict key、lease、dispatch ticketを再利用し、ネットワーク呼び出しは台帳トランザクションの外で行う。

1. 事前に承認・Denyのdesired head・dispatch lease・回数と期限、source証拠、対象世代・SA unique ID、重複利用の不存在、独立したRecoveryの正例を確認する。変更windowはIAM更新だけでなく対象・SAの再作成も禁止する前提。project IAMのetagはCloud SQLの世代やSAのIDをサーバー側で条件付けできないので、これらは書き込み直前に再読し、windowを維持できない環境では実行しない。
2. 最新のIAM読み取りから候補を作る。**元操作の書き込み後etagと現在etagが同一**で、全体digestと2行が一致するときだけ、その2行を取り除く。無関係な更新でもetagが変わった時点で停止する。etagを貼り替えて競合後に再適用しない。この制約で、同じタイトルの削除・再追加を内容比較だけで見逃すことを防ぐ。
3. 再照合した承認・leaseの下で、条件付きpolicy更新を一回送る。成功応答のetagと期待する構成digestを既存のreceipt CASとイベントで `ConfigApplied` として先に確定し、独立した再読で「承認済み2行だけが消えた」ことを確認する。fresh readでは世代とSAを再確認する。
4. 補償結果と実効評価を別々に出す。補償の完了は `owned_iam_delta_removed` に限定し、保護判定はその時点で未評価。通常の保護operation完了条件や要求effectのgapはそのまま保持し、補償stepの結果を代用しない。過去の元stepは履歴として残し、元stepの成功や失敗を上書きしない。

| 事象 | 照合と再試行 |
| --- | --- |
| 書き込み前に明示的に停止し、未送信が確定 | 同一operation内でのみ、台帳が `NotApplied` を記録済みかつ残り回数・期限内なら、同じ承認と同じetagで直前確認から再試行できる |
| etag競合、対象世代・SA・重複利用・承認・desired headの不一致 | 書き込み停止。新しいetag、別のSA、別revisionを今回の承認で使用しない |
| 応答喪失、送信中の取消し、クラッシュ、lease失効 | `OutcomeUnknown` を維持し、照会専用で再開する。ローカルidempotency keyはproviderの重複排除を意味しない。元etagが見えても送信が遅れて成立する可能性があるため再送しない |
| 両行不在を読み取れたが対応する成功応答が台帳にない | IAM構成上の不在を別記録する。補償主体の帰属はUnknownで、補償完了にしない。追加書き込みもしない |
| 成功応答は記録済みだが再読が未完了 | 読み取りだけ再開し、成功応答のetagと想定内容が確認できれば補償完了。期限切れ・不整合は要対応として残す |

## 補償後の実効確認

構成上の2行の不在から新規接続拒否を導かない。現在のDeny revision、対象世代、主体、route、source、観測時刻が一致する新しいK10/K11証拠で評価する。独立Recoveryの成功、残すべきworkloadのK11 RuntimeBinding・実接続、対象主体の要求された拒否層の証拠を区別する。拒否された主体に成功RuntimeBindingを要求しない。成功が観測されればAllowedを保持する。伝播中や別権限の残存、既存session・SQL権限、証拠不足は独立の行に残す。[共通の観測契約](k10-evidence-contract.md)、[K11作業設計](k11-work-plan.md)。

## 実装後のローカル受入

| 確認 | 期待結果 |
| --- | --- |
| 元操作で両行が不在 → 成功応答 → 同じetagの再読 → SQLite確定 → 補償 | 専用SAの2行だけを1回の更新で除去。無関係なbinding・監査設定・Cloud SQL設定・SQL・sessionは保持。最後の条件付き行が消えた場合の正当なversion 1応答も照合できる |
| 既存の両行／片方、改変・重複タイトル、NoOp、旧receipt、別step/attemptのreceipt | 補償の所有資格なし。native更新0回 |
| desired head・世代・SA入替、兼用SA、利用中・利用不明、Recovery欠落、切替済み、失効承認、lease競合 | 更新0回。別policyからの競合を含め、同一台帳ではproject IAM conflict keyで直列化する |
| 元操作以後の無関係なIAM更新、同内容の再作成、更新直前の競合 | etagを再採用せず停止。他の設定に変更を加えない |
| 書き込み前後にプロセス停止、応答喪失・遅延、receipt確定失敗、複数プロセスからのbegin・resume | 承認範囲の拡大と曖昧な再送がない。現在の行の不在だけで所有や成功を作らず、再開後も元履歴を保持 |
| 2行除去後に接続成功、古い証拠、独立Recoveryの失敗、新鮮で同一scopeの観測 | 構成補償と保護評価を分離し、Allowed、Unknown、確認できた効果を現在の証拠に従って出す |

実装順は、所有receiptの生成・保存、補償plan/承認/CAS、GCPの限定executorと再開、実効表示と回帰の順とする。最初の受入はfake provider、実SQLite、別プロセスCLIで行う。この文書の作成時点では機能実装、実クラウド更新、実DB検証は行っていない。
