# K10：固定GCP connectorの関連IAM permission inventory

2026-11-03最終引継ぎ: [K10共通基盤のL受入とK11着手条件](k10-k11-handoff.md)を参照します。root probe/過去ログ/限定IAMの保証scopeを固定し、個別profileのUnknown・未対応は維持しました。次の実装はK11-Aです。以下は前チェックポイントの記録です。

2026-11-03。`source/iam_inventory.rs` はGCE sourceの同じmetadata service accountについて、Cloud SQL PostgreSQL 16.15・東京・固定native connectorに必要な `cloudsql.instances.connect`、`cloudsql.instances.get`、`cloudsql.instances.login` の実効的な集合を取得するproducerです。所有bindingだけの一覧ではありません。全IAM grant pathや、AWS/GCP全profileの完全取得が終わったとは扱いません。

## native取得と信頼境界

collector設定の `postgres.collect_iam_inventory: true` による明示選択が必要です。既存設定の既定値はfalseです。設定digest、固定collector binary、既存source/request検証を維持します。metadata tokenをメモリ内だけで取得し、固定の `https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot` に3permissionを問い合わせます。credentialはargv、継承環境、artifactへ入れず、curlの標準入力へ渡します。レスポンスは各256KiB、通信は各5秒の上限、source captureの期限・cancelにも従います。

request digest、case、sourceのprincipal、Cloud SQL full resource name、target generation、capture時刻を照合します。IAM照会の直前・直後にもSQLAdmin APIでinstance metadataを読み、要求したgenerationと一致し前後不変であることを確認します。APIのrequest echoもprincipal/resource/permission、condition時刻とresource contextに一致させます。公開資料のresource名は `//cloudsql.googleapis.com/projects/PROJECT_ID/instances/INSTANCE_ID` です。raw policy、group一覧、providerのエラー文は保存せず、選択したdecisionとresponse hashを既存のsource proofへ含めます。

Policy Troubleshooter **v3beta** はallow/deny/Principal Access Boundaryを扱います。v3はPABを含まず、Cloud Assetの `analyzeIamPolicy` はallow policy用なので、その `fullyExplored: true` をこのinventoryの完全性へ読み替えません。参照：[v3beta API](https://docs.cloud.google.com/policy-intelligence/docs/reference/policytroubleshooter/rest/v3beta/iam/troubleshoot)、[取得権限とgroupの制約](https://docs.cloud.google.com/policy-intelligence/docs/troubleshoot-access)、[Cloud SQL full resource name](https://docs.cloud.google.com/iam/docs/full-resource-names)。

## completeの限定した意味

3permissionのoverall/allow/deny/PABの全decisionが既知で整合し、説明中のUNKNOWN、未指定、error、欠けたpolicy資料がない場合にのみcompleteとなります。組織・folder・projectの継承、広いrole、group経由もAPIが返す実効decisionに反映します。group、custom role、deny、PABの可視性が不足した状態をcompleteへ上げません。

条件は、既存native adapterが生成する現在targetへの正確な `resource.name == 'projects/.../instances/...' && resource.type == 'sqladmin.googleapis.com/Instance'` だけを限定的に扱います。raw bindingとnative binding explanationの順序・role・条件式を照合し、対応する `conditionExplanation` と全subexpressionのtrue、error無しを要求します。APIへ送るresource name/type/serviceもechoと照合します。時刻・group・tagなどを含む任意CELや、別resourceの式、条件説明の欠落・未知は、瞬間的なoverall結果が既知でもincompleteです。汎用CEL evaluatorは実装していません。

このためnative実行には、対象祖先のallow/deny policyとcustom role、principal側のPAB、必要なgroup/domain membershipを閲覧できる権限が必要です。API未有効、source identityに照会権限がない、閲覧不足、timeout、未知enumは成功扱いしません。producerはAPI有効化・権限付与を行いません。広い監査権限をアプリsourceへ追加する運用判断も別です。

接続成功の観測はIAM取得が失敗しても保持します。inventory claimは `Unknown` で、拒否や伝播Pendingを単独では生成しません。既存のtarget generation、source、route、DB transport等のassuranceを引き継ぎ、IAM APIのHTTPS成功でDB transportを確認済みにはしません。`PermissionRemovalV2` の前後inventory、以前のAllowed、承認change/operation、時刻・鮮度・全facetの検証は従来どおり必要です。

広い別bindingが同じpermissionを保持すれば、所有bindingを削除しても前後集合は同じです。その場合はpermission除去を証明できません。DB接続が拒否されtransportを取得できないcaptureも、このproducerだけでは全facetを満たせません。変更後のIAM集合で実効permission減少を確認し、その取得が完了した後の新しいcaptureでも接続Allowedを観測した場合は、既存の制限付きPending評価へ渡せる構成です。

同sourceの `cloudsql.instances.get` が既に実効拒否になれば、generationの前後SQLAdmin読取りもできず、after inventoryを取得できない場合があります。別の管理credentialへ切り替えて補完する動作はありません。標準revokeの後に必ずPendingを生成できるという保証はなく、実際のDB/API側でまだ許可が観測される伝播期間と、必要な証拠が取得できることを分けます。

## operationに結びついたPending

offline `source/state::read_local` は、実OperationStoreに登録されたv2 lifecycle Revokeの承認、直前source operationと旧change、現在のdesired head、`DisableNativeIdentity` の成功receiptとnative postcondition hashを再検証します。根拠を一意にする初期範囲では、旧operationはCompleted、現在の削除stepは1attempt・1dispatch・1receiptで、NoOp・再試行・結果不明・失敗・補償・取消しは使いません。通常のprevious policyだけを持つchangeについて、無関係な古いoperationから根拠を探索して補完しません。

旧operationの完全inventoryとAllowedがdispatchより前、現在operationの完全inventoryがreceiptより後で、集合が厳密に減少し、現在Allowedも新鮮な場合に限り `PermissionRemovalV2::from_approved_change` を構成します。旧資料も現在のsource head・build・期限・archive完全性で読み直します。別contextの持込参照や、古いadmission時刻へ戻した再受入は使いません。

native collectorは1captureでPG接続を観測してからIAMを取得します。PG claimの時刻はcapture全体なので、**変更後の1captureだけではIAM取得後の現在Allowedを証明できずPendingにしません**。少なくとも、そのIAM取得完了後に始まる後続captureのAllowedが必要です。最新のAllowedを含むbundleの同caseにも、完全かつ同じpermission集合のIAM claimが必要です。API取得失敗でIAM補助claim自体が欠落した場合も、現在Allowedは保持し、Pendingにはしません。後続inventoryが不完全・異なる場合や、最新の変更前inventoryが不完全なら、古いcompleteへfallbackしてPendingを作りません。

旧資料はcoreの専用before-reference poolへ渡します。before inventory/prior Allowedの参照だけに使い、現在の接続判定、TargetHealth等のcontrol、通常historyへ混ぜません。現在の操作snapshotが読み取り中に変わった場合はPendingを外して再評価します。証拠が不足していても、現在観測したAllowedはNeedsActionとして残します。

有限deadlineは、**承認した観測待ちの上限**としてforward承認期限と承認済みoperation時間上限の早い方へ制限します。providerの伝播完了時刻を予測・保証する値ではありません。before evidenceの鮮度は60秒のままなので、待ちの上限内でも証拠が古くなればPendingは成立しません。操作の成功と保護の成立は引き続き別です。

3permissionは固定connectorの接続関連範囲です。DB内部のSQL role/ACL、runtime binding、既存token/sessionの失効、VPC Service Controls、全経路の防御成立を証明しません。Policy Troubleshooter自体のPAB対応はpreviewであり、native環境での応答・実効反映は今回未確認です。

## AWS profileに残る境界

現EC2 profileのSTS identityとrole/RoleId照合は、関連permission集合の完全取得ではありません。AWS IAM simulatorはlive requestと同じではなく、RCPを扱わず、roleのresource-based policy simulationにも制限があります。実際のSTS session policyや実行contextを現collectorが復元しているわけでもありません。`SimulatePrincipalPolicy` のAllowed/Deniedやroleのattached/inline policy一覧だけで、boundary/SCP/RCP/session/resource側を取得済みと主張しません。[AWS simulatorの制限](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)、[policy評価](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)。

AWSで完全性を主張するには、採用するRDS/Proxyの認可経路を固定した上で、適用されるidentity policies、permissions boundary、Organizations階層のSCP/RCP、対象resource/VPC endpoint側policy、実STS session policyとcontextの全取得または不適用の根拠が必要です。IMDSの現在credentialだけからsession policy全体を遡って取得できるとは確認していません。session発行時の信頼できるreceipt等を追加しない現profileはincompleteのままです。AWSのcomplete producerを実装済みとは扱いません。

## ローカル検証の範囲

synthetic native responseからの正規化について、広い継承grantの保持、全既知の不在と部分取得の区別、group/role/deny/PABの不明、条件、echo差替え、request/case/actor/target/generation/時刻の不一致、応答上限、矛盾するdecision、DB transportの非昇格を検証します。実SQLite/archiveとtest-only synthetic verifierによるPending統合では、operation承認・receipt、前後差分、before pool分離、不完全・古い・別context・取消し・失敗・時刻overlapによる不成立を確認します。公開一次資料の確認とローカル試験に限り、実AWS/GCP API、SSH、実DB、collector配置、課金・権限変更は行っていません。
