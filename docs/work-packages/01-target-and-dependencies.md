# 01 対象と依存の固定

担当: 技術調査担当。対象: T01,T02。編集範囲案: `docs/support-matrix.md / docs/dependency-decisions.md`。共通設計の変更は主担当へ提案します。

## 入力

[AWS調査](../aws-findings.md)、基本設計D02〜D07、詳細設計§2/4/7/8、検証V07/V08/V10/V16を読みます。ローカルの実装環境の確認はできますが、AWSの認証情報取得や実環境の探索はしません。

## T01: 対象と前提

- engine/version/region、end-to-end IAMかstandard IAMか、実行元OS/接続元、endpoint/address familyの対象行列を作る。
- AWS対応表を実際に開いて確認し、確認日・URL・前提を残す。未確定の導入先を勝手に推定しない。
- CloudFormationの必要プロパティ、DB user/GRANTのbootstrap、管理・復旧経路を計画項目にする。
- 試験元はアプリと同じ条件にできるかを示す。VPN/SSMをアプリ経路の証拠へすり替えない。
- profileの必須case/path行列を具体化する。対象を省いてpassにできない入力条件を主担当へ渡す。

成果は対象行列、採用理由、非対応条件、未決事項と解決先です。D03〜D05/D07を更新できる根拠が揃えば完了し、費用承認や実行元が未取得なら、その情報をT16で固定する項目として明示します。実環境値がないことを架空値で埋めません。

## T02: Rustと依存

- Rust toolchain、AWS RDS/EC2/credential/SigV4、PostgreSQL driver、TLS、serialization、CLI/asyncに必要な依存を最小限で選ぶ。
- 対象版の一次資料と既存リリースを確認し、CA/ホスト名検証、トークン更新、protocol 3.0、direct SSL negotiationの回避、CancelRequestに依存しない停止を扱えるか確かめる。
- prepared statement、pool reset、session pinningの相性を検証項目へつなぐ。
- 依存の保守、ライセンス、脆弱性、MSRV/OS条件を記録する。未確認項目は未確認のまま渡す。
- manifest変更は候補と固定版を主担当へ渡し、他担当と同時にCargo.lockを編集しない。

外部DBなしで可能なコンパイル/設定確認と、実Proxyでしか確かめられない点を分けます。独立した実装実験が必要なら目的と承認範囲を主担当に伝えます。

## 受入と引継ぎ

T03が型・profile・依存を固定でき、T07がTLS/署名/driver実装へ着手できることを確認します。正規接続やAWS認証が成立したという報告は、この調査の成果に含めません。
