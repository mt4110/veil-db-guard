# K10：AWSの限定した完全IAM inventory

2026-11-03。EC2 metadata-only source profileから、**同一accountの、承認されたRDS Proxy一つとDB user一つに対する`rds-db:connect`**を取得・評価します。全AWS権限、別roleへ切り替えた主体、network/SQL/既存sessionまで完全に取得する意味ではありません。

## 実取得と完全性の条件

collector configで`collect_iam_inventory: true`を明示的に選択します。既存configはfalseを省略し、旧bytes/digestを維持します。新しいconfig/binary/buildはsource登録とrequestへ固定します。対応するNewConnection caseで、既存PG/MySQL取得に続いて固定read-only APIを実行します。

- IMDSv2から登録instance-profile roleのcredentialを直接取得し、STS GetCallerIdentityでrole ARN/RoleId/accountを確認します。環境・SDK profile・管理者credential・追加AssumeRoleへfallbackしません。
- 現在のDB generation、専用Proxy ARN・endpoint・単一DB targetを前後で読み、固定`arn:aws:rds-db:ap-northeast-1:ACCOUNT:dbuser:prx-ID/USER`を評価します。
- GetRole、ListRolePolicies、GetRolePolicy、ListAttachedRolePolicies、GetPolicy/GetPolicyVersionからinline/attached/default-version/permissions boundaryを取得します。role inventoryを2回比較し、Organizations状態も前後一致を要求します。
- Organizations DescribeOrganizationが明示的に未所属を返す場合、または対象accountがmanagement accountの場合だけ、SCP/RCPをこのscopeの制限経路から除外します。member account、権限不足、判定不能はUnknownです。組織を離脱する処理はありません。
- policyは無条件のAllow/Deny、literal Action/Resourceまたは単独`*`に限定します。明示Denyを優先し、identity Allowとboundary Allowの積を評価します。Condition、NotAction/NotResource、Principal、policy variable、部分wildcard、未対応version/grammar、重複JSON、部分page、上限超過はcompleteにしません。

最大32policy等の取得上限、各native response上限、case/全capture deadlineとcancelを維持します。取得不能を空policyへ変換しません。role/境界policyのraw文やcredentialをarchiveせず、固定scope・取得結果・document digestを保持します。署名・選択・受入の信頼は既存root collector/SSH/EC2 source profileの境界に従います。

`NativePermissionInventory.complete`はverifierがversion、request digest、case、principal、resource、generation、時間、前後資料、policy subset、Organizations状態から導出します。callerが渡すcomplete booleanはwire型にありません。完全な場合でもclaim自体はUnknownです。permission集合を取得したことから、DB接続拒否や保護成立を作りません。DB transport等のassuranceも既存観測を引き継ぎ、IAM APIのHTTPS成功で置換しません。

## 前提の根拠と制限

[EC2 metadata credentials](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)は、直接取得したinstance-role credentialを利用でき、追加session policyやsession tagを渡す場合に別のAssumeRoleを行うと説明します。この固定producerは追加role assumptionを行わないため、その経路のsession policyを持ち込みません。これは任意のapplicationが別role/credentialを使えないという証明ではありません。

[RDS IAM DB認証policy](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html)と[rds-db service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds-db.html)のDB user resourceに限定します。[RDS IAM対応](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/security_iam_service-with-iam.html)と同一accountのidentity-based認可を前提とし、任意serviceのresource-based policyを評価する実装ではありません。

[Organizations認可policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies.html)と[Organizations security](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/organizations-security.html)はmanagement accountにSCP/RCPの制限を適用しないことを説明します。member accountの全祖先policy、委任、条件付きcontextは今回取得しません。一般組織環境をcompleteと宣言しません。取得間の既知の変化を拒否しますが、API間の完全なatomic snapshot/ABA不可能性を証明するものでもありません。

IAMの現在policy評価と、AWSサービスへの反映、DB側認証・role/ACL、token/session lifecycle、既存pool、VPC/SG/NACL、別principalへの到達経路は別です。simulatorのAllowed/Deniedを実環境の完全な認可証明として使いません。

## 接続と検証

AwsCollectorConfig → 固定native read → optional reply資料 → sealed EC2 verifier → 選択artifact → NativePermissionInventory → 既存受入/共通評価へ接続しました。PG/MySQLの双方で利用でき、現在のAllowedをinventoryで上書きしません。AWSの反映待ちをこのinventoryだけで生成するadapterは追加していません。

local transcriptはnative固定query、URL-encoded policy、boundary、Deny、取得欠損、condition/wildcard/variable、組織member/未読/変更、世代/actor/case/time改変、caller completeの拒否を検証します。合成署名captureから実SQLite/archive受入・再読取りまでの試験もあります。実IAM/Organizations/RDS/IMDSへの呼出しは実施していません。最終全体結果は`runs/core-k10-handoff-local-20261103-1/`へ保存します。
