# ローカル実行手順

GCP Cloud SQL PostgreSQLの`gcp check/report`は[専用手順](gcp-cli.md#実行例)を参照します。以下のAWS fixture/loopback手順と設定を混用しません。

## 用途と現在の範囲

Rust 1.98.1、macOS ARM64で実装・検証しています。通常のローカル開発にAWS資格情報は不要です。合成設定とfixtureだけで `plan → inspect → probe記録 → report` を試せます。例示accountはsyntheticで、live AWS実行は拒否します。

依存はCargo.lockへ固定しています。toolchainの既定設定は変更していません。AWS CLI v2はlive inventory/token取得にだけ必要で、今回のfixture試験では呼びません。

## ビルドと通常試験

```sh
cargo build --locked
cargo test --locked
```

通常試験は設定、証拠保存、判定の反例、CLI統合、AWS応答正規化、構築計画、loopback transport、ダミー資格情報の署名を確認します。実AWSへの接続はありません。実DB試験はignoredとして分けています。

Homebrew Rustとrustupが混在する環境では、`cargo clippy`が別toolchainを選ぶ場合があります。今回の環境では次でHomebrew 1.98を明示しました。既定toolchainの切替や検証の無効化は行っていません。

```sh
/opt/homebrew/opt/rust/bin/cargo-clippy clippy --all-targets --locked -- -D warnings
/opt/homebrew/opt/rust/bin/cargo-fmt fmt --all -- --check
```

## AWSへ接続しない一連の操作

[README](../README.md)のコマンドを実行します。各出力先が存在すると拒否されます。再試験では新しい名前を使い、既存の証拠を削除しません。

- `plan`はローカルだけで計画を出します。`--sandbox`指定時は未適用の専用新規CFNとbootstrap SQLも出します。
- `inspect --fixture`は選択したAPI応答の正規化であり、AWSから取得した証拠にはなりません。
- `probe --fixture`は観測の再生です。入力にAWSラベルがあってもLocalFixtureへ変更し、source照合済みの主張を引き継ぎません。
- `report`はmanifestとartifact hashを検査し、固定profileの必須caseへ対応させます。欠落・未実施はUnknownです。

終了コードは、評価Pass=0、Fail=1、実行/入力/保存エラー=2、Unknown=3、取消し=130です。操作だけのコマンドが0で完了しても、`operation_only=true`の場合は防御合格を意味しません。

## 新規ローカルPostgreSQLによる検証

[接続試験記録](probe-validation.md)に実施環境・手順・保持先があります。

```sh
PG_BIN=/nix/store/1r3winn5zfalbmwinc6lq88b9xraby8a-postgresql-17.7/bin \
  cargo test --locked --test probes_postgres -- --ignored --nocapture
```

パスはこのMacの既設バイナリです。別環境では所有するPostgreSQLのbinへ変更します。新規cluster、専用CA・localhost証明書、合成DB/userだけを作り、loopbackで起動し、そのclusterだけを停止します。証拠・cluster・合成データは自動削除しません。ローカル17.7の成功をRDS16.15/Proxyの検証済み結果にしません。

CLIから独自の承認済みloopback labへ接続する場合は `--allow-network --local-lab --local-password-stdin` が必要です。snapshotの両endpointもlocalhost/loopbackに限定し、passwordはbounded stdinだけからメモリへ読みます。CLI引数や設定ファイルにpasswordを入れません。通常のlive IAM経路と別の注入providerを使用します。

## 構築生成物の静的検査

任意のローカル開発toolとしてcfn-lintで検査できます。今回の版は1.59.0です。

```sh
cfn-lint -t runs/plan-1/sandbox.yaml -r ap-northeast-1
```

この検査はテンプレート構造の確認です。AWSの作成成功・費用・IAM実効権限・SQL適用を確認しません。bootstrap SQLは専用新規sandbox限定で、対象DBと管理ユーザーのガードを持ちます。既存DB向けprofileでは生成を拒否します。

## live操作に進む前の境界

今回live操作は実施していません。`inspect`の実APIには `--allow-aws-read`、live `probe`には `--allow-network --allow-aws-read` を要求します。live probeは、指定された対象をAWSから再取得し、入力snapshotとendpoint/portを照合した後で認証処理へ進みます。ファイルhashだけをAWS応答の真正性として信用しません。

資格情報連鎖はcredential_process等の外部処理を含み得ます。liveの利用にはT16の対象・資源・費用・権限・変更・保持/片付けを具体化した承認が必要です。この手順書やフラグ自体がその承認を与えるものではありません。
