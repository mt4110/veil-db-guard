# 03 AWS構成読取

担当: AWS adapter担当。対象: T06。開始条件: T05。予定所有範囲: `src/aws_inventory.rs / tests/aws_inventory/ / docs/aws-permissions.md`。Cargo依存と共通型は主担当へ依頼します。

## 入力と成果

詳細設計§2〜4、AWS調査、対象行列、検証V03/V15を読みます。成果は対象限定のInventoryReader、必要権限表、選択フィールドのsnapshot、API fixture試験です。実AWS読取は別承認・実行計画がある場合だけです。

## 作業

1. RDS/EC2 APIごとに、必要操作・resource scope・filter・ページング・取得状態を整理する。
2. 明示したaccount/region/ARNを使い、SDK読取後も対象とDB-Proxy対応を照合する。
3. DB/Proxy/target/target-group/parameter/全関連SGを、判定に必要な選択フィールドへ正規化する。
4. 部分取得、空結果、権限拒否、一時障害、取消しを区別する。自由文をそのまま保存しない。
5. APIごとのresource制限可否と、CLI側の対象制限を別に示す。Resource '*'が必要な読取で、IAM上も対象限定できると装わない。
6. `GetSecretValue`、変更API、未指定アカウント/リージョン探索を呼ばないことを確認する。

## 試験と受入

fixtureで少なくとも、正例、複数ページ、ページ途中失敗、対象不在/重複、別account/region、別Proxy target、複数SGの許可合算、IPv4/IPv6、未適用parameter、target health異常を確認します。

API設定/TargetHealthが正常でも接続防御をpassにしません。取得失敗を空の安全な設定に変換しないこと、IAM/TLS/SGの観測範囲を維持することが受入条件です。

## 引継ぎ

snapshotの例、取得状態、必要権限、APIで分からない点をT09/T12/T14へ渡します。AWS実接続・最小権限の実アカウント検証はM3の未検証として残します。
