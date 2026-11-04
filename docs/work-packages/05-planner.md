# 05 構築・変更計画

担当: 構築計画担当。対象: T12。開始条件: T05/T06。予定所有範囲: `src/planner.rs / templates/sandbox/ / tests/planner/ / docs/sandbox-bootstrap.md`。

## 入力と成果

要求R02/R08/R17、基本設計の構築・認証・許可行列、詳細設計§1/2/4、AWS調査のCFN/DB SQL、検証V02/V12/V15/V21を読みます。成果は差分計画とsandbox用CFN、bootstrap・復旧の手順です。適用やAWS接続はしません。

## 作業

1. snapshotなし、完全取得、部分取得を区別して計画を作る。未知の現状を既知の差分として表示しない。
2. 期待状態、観測、変更の順序、影響、必要権限、未確認、復旧、再検証IDを出す。
3. sandboxテンプレートは専用の新規資源に限定し、既存DBの取り込み/置換/削除を含めない。
4. E2E IAMのProxy/role/DB設定と、SQLによるDB user/権限/bootstrapを分ける。テンプレート生成だけで接続可能と扱わない。
5. SQL bootstrapは運用者が承認した手段で実行する手順として示す。秘密を生成物に埋め込まず、CloudFormationのCustom Resourceから任意SQLを自動実行する仕組みは初期版に作らない。
6. 管理元、試験元、baseline経路、防御後の経路、片付け対象と保持対象を記載する。
7. 既存DBには構成差分/段階導入/復旧の計画を出し、既存DBを新規sandboxスタックへ移す提案をしない。

## 試験と受入

fixtureで認証モード、TLS、複数SG、管理例外、対象不一致、未適用parameter、snapshot欠落を含めます。生成物の決定性、構文、必要プロパティ、誤対象への置換/削除を含まないことを確認します。AWSが必要なtemplate validation/deploymentはT17の実行計画へ回します。静的検査をAWS適用成功に言い換えません。

## 引継ぎ

T14へplan契約とfixture、T16へ資源・権限・SQL・経路・費用要素・復旧/片付け一覧を渡します。利用者が実行するAWSコマンドを記載する場合、具体的な対象と影響をレビュー可能にし、記載しただけで実行しません。
