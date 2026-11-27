<p align="center">
  <a href="README.md">English</a> | <a href="README.ko.md">한국어</a> | <strong>日本語</strong>
</p>

# Dandi (단디)

> **ファイル名が絶対に文字化けしない、高速・安全なオープンソース macOS / Windows / Linux アーカイバ**
>
> *Dandi (단디)* — 韓国語の方言で **「きっちり・抜かりなく・確実に」** を意味します。

---

## なぜ Dandi なのか？

macOS・Windows・Linux 間でアーカイブを共有すると、いまでも日常的にファイル名破損やセキュリティ事故が発生します。

- **macOS → Windows**: macOS は日本語の濁点・半濁点（`が` → `か+゙`、`ぱ` → `は+゚`）、韓国語（`한` → `ㅎ+ㅏ+ㄴ`）、欧州アクセント記号（`é`, `ü`）を **Unicode NFD** で保存し、`__MACOSX/` や `.DS_Store`、`._*` を混入させます。Dandi は既定で **Unicode NFC UTF-8（ZIP Bit 11）** に正規化し、OS 不要ファイルを除外します。
- **Windows → macOS**: 従来の Windows ツールが作成した ZIP は UTF-8 フラグなしで **Shift_JIS（`0x5C` バイトを含む `表`・`能`・`ソ` 等）**、**CP949**、**GB18030/GBK**、**Big5**、**Windows-1251/IBM866**、**Windows-1252** を格納するため macOS で文字化けします。Dandi は OS ロケールに依存しない **アーカイブ全体のコーパス自動判定** とワンクリック切り替え、NFC 修復（`dandi fix`）を提供します。
- **大容量・機密・`.rar` ファイル**: メールやメッセンジャーの容量制限に合わせて `.z01`/`.zip`（PKWARE）または `.001` に分割し、ファイル名まで隠す AES-256 の `.7z` を作成し、RAR4/RAR5 を GPL 互換の純 Rust リーダーで展開します。展開される全バイトは同じ安全検査を通ります。
- **実運用エッジケースと安全性**: UTC `0x5455` タイムスタンプの付与、macOS `.app` の実行権限（`+x`）と安全な相対シンボリックリンク保持、**Zip Slip・シンボリックリンク脱出・Zip Bomb** の防御、Windows 禁止文字・予約デバイス名（`CON`, `NUL`, `COM1`–`9`）のサニタイズ、大文字・小文字衝突の安全な回避、Windows `Zone.Identifier` ADS の引き継ぎを備えています。

---

## 検証済み 100/100 スコアカード & パフォーマンス

すべての変更は、実際の macOS（`ditto`/`unzip`）および Windows（Explorer COM / `Expand-Archive`）に対して自動評価ハーネス（[`dandi-eval`](docs/EVAL_RUBRIC.md)）で採点されます。

| カテゴリ | スコア | 主な検証項目 |
|---|---:|---|
| クロス OS ネイティブ互換性 | **30 / 30** | 実機 macOS ↔ Windows エクスプローラー往復、`.app` `+x`/シンボリックリンク、UTC `0x5455`、ZIP64、ZIP・7z AES-256 Unicode パスワード、`.7z`/`.rar`/`.tar.*`、分割 `.z01`/`.001`（Info-ZIP・libarchive で相互検証） |
| 多言語 & 文字コード精度 | **25 / 25** | 多言語 NFD → NFC、Shift_JIS（`0x5C`）、CP949、GB18030、Big5、キリル文字、`0x7075` CRC32 検証 |
| セキュリティ & ファイルシステム安全性 | **20 / 20** | Zip Slip（ZIP・RAR）、シンボリックリンク脱出、Zip Bomb `SafetyBudget`（ZIP・TAR・RAR）、Windows 予約名・長パス（`MAX_PATH`）、衝突保護 |
| パフォーマンス & 効率 | **15 / 15** | 並列 Deflate 圧縮 **454 MB/s**（`rayon` + `zlib-rs`）+ Smart Store、ストリーミング展開 **718 MB/s** |
| 信頼性 & スマート UX | **10 / 10** | スマート展開（`foo/foo/` 二重フォルダや tarbomb 防止）、即時キャンセルとロールバック、暗黙ディレクトリ補完 |
| **合計** | **100 / 100** | **スキップ 0 件・セキュリティブロッカー 0 件** |

---

## クイックスタート (CLI)

```bash
# ソースからインストール
cargo install --path crates/dandi-cli

# クロス OS 標準 UTF-8 NFC ZIP を作成（OS 不要ファイル自動除外）
dandi pack ./project -o project.zip

# ZIP / 7z / RAR / TAR（.tar/.tgz/.tar.gz/.tar.zst/.tar.bz2/.tar.xz）をスマート展開
dandi unpack archive.zip --dest ./out --mode smart

# 25 MB ごとに分割: project.z01, project.z02, ..., project.zip（--split-style numeric なら .001）
dandi pack ./project -o project.zip --split 25M

# AES-256 の高圧縮 .7z（ファイル名も暗号化）を .7z.001, .7z.002, ... に分割
dandi pack ./project -o project.7z --format 7z --password '단디-7z!2026' --split 100M

# 分割セットのどのパートからでも、または .rar / .part1.rar を展開
dandi unpack project.z01 --dest ./out
dandi unpack photos.part2.rar --dest ./out

# 形式・自動判定文字コード・フォルダツリーを確認
dandi inspect legacy_sjis.zip

# 曖昧なレガシー書庫の文字コードを手動指定
dandi list legacy.zip --encoding shift_jis
dandi unpack legacy.zip --dest ./out --encoding cp949

# 文字化けする旧 ZIP をクリーンな UTF-8 NFC ZIP に修復
dandi fix broken.zip -o clean_nfc.zip
```

全コマンドでスクリプト連携用の `--json` 出力に対応しています。

---

## デスクトップアプリ & 右クリック統合

Tauri v2 デスクトップアプリ（`apps/desktop`）は `dandi-core` 上の軽量 GUI で、ドラッグ＆ドロップによるプレビュー・圧縮、ZIP（最大互換性）/ 7z（高圧縮 + AES-256）の形式選択、分割圧縮（10 / 25 / 100 MB・カスタム）、文字コード即時切替、スマート／そのまま／フォルダ作成モード、上書き保護、展開時警告の詳細表示、キャンセル機能を備えています。

### macOS Finder クイックアクション

メインウィンドウを開かずバックグラウンドで静かに実行される 2 つのクイックアクション（`Compress with Dandi` / `Extract with Dandi`）を `~/Library/Services/` に導入します。ローカル・iCloud Drive・外付けドライブのいずれでも動作します。

```bash
./packaging/macos/install-quick-actions.sh
# オプション: --dandi-bin /path/to/dandi --dry-run

# アンインストール
./packaging/macos/uninstall-quick-actions.sh
```

### Windows エクスプローラー右クリックメニュー

管理者権限（UAC）不要でユーザー単位（`HKCU`）に登録され、Windows 10/11 のメニュー重複も起こりません。

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\windows\install-context-menu.ps1
# オプション: -DandiBin C:\path\to\dandi.exe -DesktopBin C:\path\to\Dandi.exe -DryRun

# アンインストール
powershell -ExecutionPolicy Bypass -File .\packaging\windows\uninstall-context-menu.ps1
```

ファイル・フォルダに **Compress with Dandi (Clean ZIP)**、アーカイブ拡張子（`.zip`, `.z01`, `.7z`, `.rar`, `.001`, `.tar`, `.tgz`, `.gz`, `.zst`, `.bz2`, `.xz`, `.tzst`, `.tbz2`, `.txz`）に **Extract with Dandi (Smart)** と **Open in Dandi** が追加されます。

---

## 未署名ビルドの初回起動手順

コード署名証明書の導入前のビルドでは、OS の保護警告が表示される場合があります。

- **macOS**: `Dandi.app` を `/Applications` に移動後、Gatekeeper の警告が表示された場合は隔離属性を解除してください。
  ```bash
  xattr -dr com.apple.quarantine /Applications/Dandi.app
  # CLI バイナリ単体の場合:
  xattr -d com.apple.quarantine /path/to/dandi
  ```
- **Windows**: Microsoft Defender SmartScreen が表示された場合は **詳細情報** → **実行** をクリックしてください。リリースページの `SHA256SUMS.txt` でハッシュ値を確認することを推奨します。

---

## ロードマップ

- [x] **M0 — 調査 & 設計**: 既存アーカイバの 24 件の実バグ調査（[`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md)）、ディープモジュール設計（[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)）、100 点評価基準（[`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md)）。
- [x] **M1 — コアエンジン + CLI + 自動評価ハーネス**: `dandi-core` / `dandi-cli` / `dandi-eval` で **100/100** を達成。M1.5 にて `ExtractionSink`・構造化警告・`SanitizedPath` を強化。
- [x] **M2 — Tauri v2 デスクトップ GUI**: ドラッグ＆ドロップ、ツリープレビュー、ワンクリック文字コード切替、NFC 修復、スマート展開、進捗・キャンセル。
- [x] **M3 — OS シェル統合 & 自動リリースパイプライン**: デスクトップ警告/上書き UI、macOS Finder クイックアクション、Windows HKCU エクスプローラー統合、クロス OS リリースワークフローと SHA-256 チェックサム、多言語ドキュメント。
- [x] **M4 — 分割圧縮・.7z 作成・.rar 展開**: PKWARE `.z01`/`.zip` と数字形式 `.001` の分割書き込み/読み込み（ボリューム自動検出・ストリーミング）、AES-256 + ファイル名暗号化の `.7z` 作成、純 Rust の `rars` クレートによる RAR4/RAR5 展開（RARLAB コードなし）、デスクトップの形式・分割選択。

---

## コントリビューション & セキュリティ

- 開発環境・コーディング規約・`dandi-eval` ゲートについては [`CONTRIBUTING.md`](CONTRIBUTING.md) をご覧ください。
- セキュリティ脅威モデルと脆弱性の非公開報告手順は [`SECURITY.md`](SECURITY.md) をご覧ください。

## ライセンスと商標

- **ソースコード**: [GNU General Public License v3.0](LICENSE)（`GPL-3.0-only`）© [ITP-Adieum](https://github.com/ITP-Adieum)。個人利用・商用利用ともに無料です。
- **商標**: **Dandi** の名称およびロゴは ITP-Adieum の商標であり、GPL-3.0 ライセンスには含まれません。フォーク版では別の名称とアイコンを使用してください。
- **商用 / デュアルライセンス**: プロプライエタリ製品への組み込みや商用再配布については ITP-Adieum までお問い合わせください。
- **RAR 対応**: `.rar` の展開には Apache-2.0 の [`rars`](https://crates.io/crates/rars) クレートを使用します。GPL と互換性のない RARLAB UnRAR のコードは含まれておらず、Dandi は `.rar` を作成できません。
