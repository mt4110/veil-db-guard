# 固定した開発・ビルド環境

2026-11-02。Rustと依存の版を固定し、miseから同じ設定を利用します。Nixは開発・実行の必須条件にしません。

| 対象 | 固定する場所 | 現在の版・扱い |
| --- | --- | --- |
| Rust / Cargo / rustfmt / Clippy | `rust-toolchain.toml` | Rust 1.98.1、minimal profile、rustfmt/clippyを指定 |
| Rust crate | `Cargo.lock` | 正確な版・checksumを固定。build/checkは`--locked` |
| 台帳用SQLite | `rusqlite`の`bundled` featureとCargo.lock | rusqlite 0.41.0、libsqlite3-sys 0.39.1、SQLite 3.54.1の同梱sourceをコンパイル |
| 開発コマンド | `mise.toml` | Rustの版は重複記載せず`rust-toolchain.toml`から読む |

`Cargo.toml`の`rust-version = "1.98"`は最低必要版です。ビルドに選択する正確な版は`rust-toolchain.toml`で管理します。Rustの更新時はこの一箇所を更新し、依存・回帰結果との組合せを確認します。[rustupのtoolchain設定](https://rust-lang.github.io/rustup/overrides.html)、[miseのRust設定](https://mise.jdx.dev/lang/rust.html)に沿った構成です。

## 使い方

```sh
# 初回。repo内の設定内容を確認してtrustし、指定Rustを利用可能にする。
mise trust mise.toml
mise install

# 依存cacheが空の場合の初回取得。AWS/GCP認証やAPI操作は行わない。
mise exec -- cargo fetch --locked

# 以降の確認はCargoのnetwork取得を使わない。
mise run check
mise run build
```

`mise run check`はformat check→Clippy→local testsを順に実行します。実DB用の明示試験はignoredのままです。`mise run fmt/lint/test`で個別にも実行できます。指定Rustが既にある環境では、新しいtoolchainの取得は不要です。mise未導入でも、rustupのproxy経由で同じtoolchain fileを使えます。

確認する場合は`mise exec -- rustc --version`と`mise ls --current rust`を使います。別のpackage managerによるrustcを直接起動した場合や、`RUSTUP_TOOLCHAIN`等で明示overrideした場合まで、ファイルだけで固定を強制する仕組みではありません。

## 固定する範囲とLinux対応

台帳は従来のOS付属SQLiteへのdynamic linkから、lockされた同梱SQLiteへ変更しました。OSのSQLite更新だけで台帳の実装が変わらない構成です。runtimeのSQLite version/source IDをlocal testで照合します。C compiler・OS SDK・kernel・libcまで固定した、bit単位のreproducible buildを主張するものではありません。

mise本体はbootstrap toolとして既存版を利用し、今回の確認版は2026.1.4です。グローバルの既定Rustやmise自体は更新していません。外部のAWS/GCP CLI、Auth Proxy、psqlは別の対象環境依存であり、今回のcore offline tasksでは起動しません。native adapterの配布・対応版はK05側で管理します。

Nixを追加する場合も、対応するOS/CPUとruntime条件を示します。Nixの利用だけで「どのLinuxでも動作する」とは表示しません。[Nix自身の対応platform](https://nix.dev/manual/nix/stable/installation/supported-platforms.html)と、Veilの動作確認範囲は別です。現在の確認はmacOS ARM64で、Linux上の実行は未確認です。Linux対応の追加検証を今回開始するものではありません。

## 今回の確認結果

- miseがこのrepoの`rust-toolchain.toml`からRust/Cargo 1.98.1を選択することを確認。
- `mise run check`完了。format check、Clippy（warningsをerror扱い）、環境固定を行った時点では189件のlocal testが成功。実DB試験2件はignored。
- SQLite 3.54.1と同梱source IDの一致を確認。macOS binaryのdynamic dependenciesにsystem libsqlite3がないことを確認。
- cloud/API操作、追加フィジビリティ、Linux実証、公開は行っていない。

SQLiteの更新はCargo.lock、crate feature、version/source IDの確認をまとめてレビューします。版固定は更新の禁止ではなく、使う版と変更のタイミングを明示する方針です。

続く依存整理・K05の実装後にも同じ`mise run check`を実行し、229件成功・2件ignoredを確認しました。[K05の検証記録](core/k05-native.md)を参照します。

K06後の同じ固定環境の最終回帰は272件成功・2件ignoredでした。[K06の結果と制限](core/k06-lifecycle.md)を参照します。

K07後も同じ固定環境で`mise run check`を完了し、310件成功・0件失敗・2件ignoredを確認しました。[K07の結果と制限](core/k07-aws.md)を参照します。

K08後は同じ固定環境で335件成功・0件失敗・2件ignoredでした。MySQL用にmysql_async 0.37.1を追加し、Cargo.lockでtransitive版も固定しています。[K08の結果と制限](core/k08-mysql.md)を参照します。

K09後も同じ固定環境で`mise run check`を完了し、357件成功・0件失敗・2件ignoredでした。新規依存はありません。[K09の結果と残るK10](core/k09-qualification.md)を参照します。
