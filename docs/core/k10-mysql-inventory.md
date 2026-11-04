# K10 MySQL: named table actionの不在inventory

MySQL 8.0.43のsource観測に、限定した`SHOW GRANTS` inventoryを追加しました。通常accountで見えないinformation schemaの空行を、権限不在に変換しません。固定read-only取得からsealed source verifier、`SqlAuthorizationContext.permission_inventory_complete`を経て、共通stateの`EffectiveSqlPrivilege=Absent`へ接続する範囲です。実MySQL／RDS／EC2への接続・操作は行っていません。

## 証明する対象と前提

対象は、承認したDB generation内の正確な`account@Host`に対する、現在のnamed base-table ACLです。inventory proofの`scope`は`named_acl_fresh_connections`に固定し、未知の値は受け入れません。SELECT／INSERT／UPDATE／DELETEを対象に、accountと利用可能な全roleのいずれにも対象actionがないことだけを判定します。

この判定は対象tableへの直接ACLの範囲です。definer view、別tableのtriggerなどを経由するデータ到達や間接操作まで含めた不可能性は示しません。未対応のroutine権限はUnknownにしますが、stored objectの依存関係を網羅した証明を追加したわけではありません。

これは既存sessionや既存connection poolの権限消失を示すものではありません。MySQLのstatic global privilegeは接続時にsessionへ保持され、DB権限の反映にも`USE`の境界があります。`SHOW GRANTS`は現在のserver ACLから再計算されるため、probe sessionに保持された全security contextと同じとは限りません。既存sessionの停止は別の`ExistingSessions` effectです。

既存K08のnative操作と同様に、外部操作者との調整済みの排他変更windowが前提です。取得したclosureを2回比較して検出可能な変化を拒否しますが、読み取り間のABAや、接続から最初の取得までに起きた変更を完全には排除しません。時点のACL評価と、外部変更を排除する運用条件を区別します。

account／tableの識別子はpolicy hash・DB generation・承認した名前に束縛したscopeです。MySQL accountやtableに不変のincarnation IDを発行できたとは扱いません。同名account／tableの削除再作成、以前のobjectへの権限回収、owned deltaの除去を証明する用途には使いません。

## read-only recipe

native接続は従来どおり、STS確認済みIAM credentials、登録hostname／IP、固定CAのTLS、正確な`USER()`／`CURRENT_USER()`、database、MySQL 8.0.43、`lower_case_table_names=0`を確認します。catalog取得はread-only transaction、statement deadline、全体deadlineとcancelの範囲内で行います。

1. 対象tableがinformation schemaで`BASE TABLE`として見えることを確認します。見えない場合は、存在／不存在を推定せずUnknownです。
2. `@@skip_grant_tables=OFF`と`@@partial_revokes=OFF`を確認し、`@@mandatory_roles`を記録します。
3. `SHOW GRANTS`を`FOR`なしで実行します。MySQLのこの形には、現accountに明示されたroleに加えてmandatory roleが含まれます。
4. role grantを厳密に解析し、すべての直接／再帰roleについて`SHOW GRANTS FOR role@host`を取得します。active roleだけでなくinactive roleも含みます。role queryのaccount名は固定validatorを通し、quote、backtick、空白、任意SQLを許しません。
5. closure全体を再取得し、環境値を読み直します。2回のaccount集合・grant文・環境値が同じで、取得済みactive roleもclosureに含まれる場合だけ、不在判定へ進みます。
6. global／schema／table／columnのstatic grantを調べます。schema grantの`%`・`_`・backslash escapeをMySQLのpatternとして扱い、table名は正確に照合します。対象actionがどこにもなければ、named ACLのAbsentを記録します。

観測対象account以外のroleの`SHOW GRANTS`にはmysql schemaのSELECT権限が必要です。role metadataの閲覧が拒否された場合、そのroleを空と扱いません。inventoryを未取得としてUnknownへ戻します。roleがないaccount自身の`SHOW GRANTS`は、通常accountの権限で取得できます。

全roleのどれかが対象actionを持つ場合、たとえそのroleがinactiveでもAbsentにしません。一方、この事実だけでPresentにもせず、従来のactive contextでのpositive観測と分けます。

## 対応profileと停止条件

parserが受理するstatic grantは`USAGE`、`SELECT`、`INSERT`、`UPDATE`、`DELETE`、`REFERENCES`、`INDEX`、`SHOW VIEW`です。この限定集合以外のgrantが一つでもあればUnknownです。dynamic privilege、管理権限、`ALL PRIVILEGES`、`PROXY`、`EXECUTE`／routine、`GRANT OPTION`／`ADMIN OPTION`、partial REVOKEを含むprofileは不在判定しません。mysql schemaを書き換えられるDML権限も不在判定を止めます。これはMySQL全機能の一般的な権限解析器ではありません。

role graphのcycleはvisited集合で処理し、未取得role、重複account、到達不能な混入account、空の`SHOW GRANTS`、文法未対応、account不一致を拒否します。各closureは最大32 account、128 grant行、grant文字列合計16 KiBです。上限超過・アクセス拒否・timeout・欠落・不一致はUnknownです。negative lookupだけの旧captureもUnknownを維持します。

対象tableが見え、承認scopeがtable／database／schemaと正確に一致し、上述の全条件を満たしたときだけ`permission_inventory_complete=true`になります。bare role名にはHost selectorがない既存契約のため、`EffectiveSqlRole`の不在・存在は引き続きUnknownです。roleを含むtable action inventoryの完全性とは別の境界です。

## ローカル検証

pure parser／normalizerで、global・schema pattern・table・column privilege、role cycle、inactive／mandatory role、metadata欠落、重複、上限、環境変化、部分取得、未対応grant、scope不一致を確認します。実mysql_async driverを使うloopbackのfake MySQL protocolでは、read-only transaction、固定queryとvalidated role template、closureの2回取得、role query拒否、空結果、変更検出、column grantによる不在停止、rollbackを確認します。fake serverの成功は実MySQLの振る舞いや実クラウドの保護成立の証拠にはしません。

## 一次資料

- [MySQL 8.0 SHOW GRANTS](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html): 明示／mandatory roleの表示、他accountの表示に必要な権限、partial revokeの表示。
- [MySQL 8.0 When Privilege Changes Take Effect](https://dev.mysql.com/doc/refman/8.0/en/privilege-changes.html): grant table直接更新とin-memory ACLの差、既存sessionへの反映境界。
- [MySQL 8.0 Grant Tables](https://dev.mysql.com/doc/refman/8.0/en/grant-tables.html): table／column／PROXY／role／dynamic privilegeの保存先。
- [MySQL 8.0.43 sql_authorization.cc](https://github.com/mysql/mysql-server/blob/mysql-8.0.43/sql/auth/sql_authorization.cc): `mysql_show_grants`のACL再計算と表示生成。
