# dmarc_python

DMARC 集約レポート（Aggregate Report）の XML を、人が読みやすい HTML レポートに変換するツールです。

各メールプロバイダ（Google, Microsoft など）から送られてくる DMARC 集約レポートは
RFC 7489 で定義された XML 形式で、そのままでは読みにくいため、集計・可視化した
HTML を生成します。

## 特徴

- **追加インストール不要** — Python 標準ライブラリのみで動作
- **複数入力形式に対応** — `.xml` / `.xml.gz` / `.gz` / `.zip` / ディレクトリ
- **複数レポートを横断集計** — 総メッセージ数・DMARC 準拠率・送信元 IP / 組織別サマリー
- **見やすいダッシュボード** — 準拠率のドーナツグラフ、IP 別の準拠率バー、レポート別の折りたたみ詳細
- **出力ファイル名を自動生成** — ドメインと集計期間からわかりやすいファイル名を付与
- **逆引き（PTR）表示に対応**（オプション）

## 必要環境

- Python 3.8 以上（動作確認: 3.12）

## 使い方

```bash
# sample フォルダ内のレポートをまとめて変換
# （出力ファイル名はドメインと集計期間から自動生成される）
python dmarc_report.py sample
#   → dmarc_morinoichigo.net_20260721-20260722.html

# 出力ファイル名を明示的に指定
python dmarc_report.py sample -o report.html

# 複数のファイルを指定（圧縮ファイルも可）
python dmarc_report.py a.xml b.xml.gz c.zip

# 生成後にブラウザで自動的に開く
python dmarc_report.py sample --open

# 送信元 IP の逆引き（PTR）ホスト名も表示する
python dmarc_report.py sample --resolve-dns
```

## オプション

| オプション | 説明 |
|-----------|------|
| `-o`, `--output` | 出力 HTML ファイル名。省略時はドメインと集計期間から自動生成 |
| `--resolve-dns` | 送信元 IP の逆引き（PTR）を実行（ネットワークアクセスが発生し遅くなる場合あり） |
| `--open` | 生成後に既定ブラウザで開く |

### 出力ファイル名の自動生成

`-o` を省略した場合、出力ファイル名は `dmarc_<ドメイン>_<開始日>-<終了日>.html` の形式で
自動生成されます（日付は UTC・`YYYYMMDD` 形式）。

- 例: `dmarc_morinoichigo.net_20260721-20260722.html`
- 開始日と終了日が同じ場合は日付を 1 つだけ付与（例: `dmarc_example.com_20260721.html`）
- 複数ドメインが混在する場合はドメイン部分が `multi` になります

## レポートの見方

- **DMARC 準拠** … DKIM または SPF のいずれかが DMARC 整合（認証成功）したメッセージ。
- **DMARC 非準拠** … DKIM と SPF の両方が失敗したメッセージ。なりすまし等の可能性があるため要確認。
- **disposition（処理）** … 受信側がポリシーに基づいて行った処理。
  - `none`（配信）/ `quarantine`（隔離）/ `reject`（拒否）
