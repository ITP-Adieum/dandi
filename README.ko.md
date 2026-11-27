<p align="center">
  <a href="README.md">English</a> | <strong>한국어</strong> | <a href="README.ja.md">日本語</a>
</p>

# Dandi (단디)

> **파일명이 절대 깨지지 않는 빠르고 안전한 오픈소스 macOS · Windows · Linux 압축 도구**
>
> **단디** — *"빈틈없이, 확실하게, 야무지게"*라는 뜻의 한국어 방언에서 이름을 따왔습니다.

---

## 왜 단디(Dandi)인가요?

macOS, Windows, Linux 사이에서 압축 파일을 주고받을 때 여전히 매일 같은 문제가 반복됩니다.

- **macOS → Windows**: macOS는 한글(`한` → `ㅎ+ㅏ+ㄴ`), 일본어 탁점(`が` → `か+゙`), 유럽어 악센트(`é`, `ü`), 베트남어 성조를 **Unicode NFD**로 저장하고 `__MACOSX/`, `.DS_Store`, `._*` 정크 파일을 섞어 넣습니다. 단디는 기본적으로 모든 파일명을 **Unicode NFC UTF-8(ZIP Bit 11)**로 정규화하고 OS 정크를 제거합니다.
- **Windows → macOS**: 구형 Windows 도구가 만든 ZIP은 UTF-8 플래그 없이 **CP949**, **Shift_JIS (`0x5C` 바이트 포함)**, **GB18030/GBK**, **Big5**, **Windows-1251/IBM866**, **Windows-1252** 바이트를 그대로 저장해 macOS에서 파일명이 깨집니다. 단디는 OS 로케일에 의존하지 않는 **아카이브 전체 코퍼스 기반 인코딩 자동 감지**와 원클릭 미리보기 전환, NFC 복구(`dandi fix`)를 제공합니다.
- **보안 및 크로스 OS 함정 방지**: UTC `0x5455` 타임스탬프 기록, macOS `.app` 실행 권한(`+x`) 및 안전한 내부 상대 심볼릭 링크 보존, **Zip Slip · 심볼릭 링크 탈출 · Zip Bomb** 차단, Windows 금지 문자/예약어(`CON`, `NUL`, `COM1`–`9`) 자동 정제, 대소문자 충돌 안전 리네임, Windows `Zone.Identifier` ADS 전파까지 기본 내장되어 있습니다.

---

## 검증된 100/100 평가 점수 & 성능

단디의 모든 변경은 실제 macOS(`ditto`/`unzip`) 및 실제 Windows(Explorer COM / `Expand-Archive`) 도구를 사용하는 자동 평가 하네스([`dandi-eval`](docs/EVAL_RUBRIC.md))로 채점됩니다.

| 평가 항목 | 점수 | 핵심 검증 내용 |
|---|---:|---|
| 크로스 OS 네이티브 호환성 | **30 / 30** | 실제 macOS ↔ Windows 탐색기 왕복, `.app` `+x`/심볼릭 링크, UTC `0x5455`, ZIP64, AES-256 유니코드 암호, `.7z`/`.tar.*` |
| 다국어 & 인코딩 정확도 | **25 / 25** | 다국어 NFD → NFC, CP949, Shift_JIS(`0x5C`), GB18030, Big5, 키릴 문자, `0x7075` CRC32 검증 |
| 보안 & 파일시스템 안전성 | **20 / 20** | Zip Slip, 심볼릭 링크 탈출, Zip Bomb `SafetyBudget`, Windows 예약어/긴 경로(`MAX_PATH`), 대소문자 충돌 방지 |
| 성능 & 효율성 | **15 / 15** | 병렬 Deflate 압축 **454 MB/s** (`rayon` + `zlib-rs`) + Smart Store, 스트리밍 해제 **718 MB/s** |
| 안정성 & 스마트 UX | **10 / 10** | 스마트 풀기(`foo/foo/` 이중 폴더·타르밤 방지), 즉시 취소 및 임시 파일 정리, 암묵적 디렉터리 복원 |
| **합계** | **100 / 100** | **0건 스킵 · 보안 차단 항목 0건** |

---

## 빠른 시작 (CLI)

```bash
# 소스에서 CLI 설치
cargo install --path crates/dandi-cli

# 크로스 OS 표준 UTF-8 NFC ZIP 생성 (OS 정크 자동 제외)
dandi pack ./프로젝트 -o 프로젝트.zip

# ZIP, 7z, TAR(.tar/.tgz/.tar.gz/.tar.zst/.tar.bz2/.tar.xz) 스마트 풀기
dandi unpack archive.zip --dest ./out --mode smart

# 압축 포맷, 자동 감지된 인코딩, 폴더 트리 확인
dandi inspect legacy_cp949.zip

# 모호한 레거시 ZIP의 인코딩 수동 지정
dandi list legacy.zip --encoding cp949
dandi unpack legacy.zip --dest ./out --encoding shift_jis

# 한글/일본어가 깨지는 구형 ZIP을 깨끗한 UTF-8 NFC ZIP으로 변환
dandi fix broken.zip -o clean_nfc.zip
```

모든 하위 명령은 스크립트 연동을 위해 `--json` 출력을 지원합니다.

---

## 데스크톱 앱 & 우클릭 탐색기 연동

Tauri v2 데스크톱 앱(`apps/desktop`)은 `dandi-core` 위의 얇은 GUI 셸로, 드래그 앤 드롭 미리보기/압축, 실시간 인코딩 전환, 스마트/바로 풀기/폴더 생성 모드, 덮어쓰기 보호, 확장 가능한 경고 배너, 즉시 취소를 지원합니다.

### macOS Finder 빠른 동작(Quick Actions)

메인 창을 띄우지 않고 백그라운드에서 조용히 실행되는 두 가지 빠른 동작(`Compress with Dandi`, `Extract with Dandi`)을 `~/Library/Services/`에 설치합니다. 로컬 폴더는 물론 iCloud Drive와 외장 드라이브에서도 안정적으로 동작합니다.

```bash
./packaging/macos/install-quick-actions.sh
# 선택 옵션: --dandi-bin /path/to/dandi --dry-run

# 깔끔하게 제거
./packaging/macos/uninstall-quick-actions.sh
```

### Windows 탐색기 우클릭 메뉴

관리자 권한(UAC) 없이 현재 사용자(`HKCU`) 영역에 깔끔하게 등록되며 Windows 10/11 중복 등록 문제를 일으키지 않습니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\windows\install-context-menu.ps1
# 선택 옵션: -DandiBin C:\path\to\dandi.exe -DesktopBin C:\path\to\Dandi.exe -DryRun

# 깔끔하게 제거
powershell -ExecutionPolicy Bypass -File .\packaging\windows\uninstall-context-menu.ps1
```

파일·폴더에는 **Compress with Dandi (Clean ZIP)**가, 압축 확장자(`.zip`, `.7z`, `.tar`, `.tgz`, `.gz`, `.zst`, `.bz2`, `.xz`, `.tzst`, `.tbz2`, `.txz`)에는 **Extract with Dandi (Smart)** 및 **Open in Dandi**가 추가됩니다.

---

## 미서명 빌드 최초 실행 안내

코드 서명 인증서 적용 전의 릴리스 빌드는 OS 보안 경고가 표시될 수 있습니다.

- **macOS**: `Dandi.app`을 `/Applications`로 복사한 뒤, Gatekeeper 경고가 뜨면 터미널에서 검역 속성을 제거하세요.
  ```bash
  xattr -dr com.apple.quarantine /Applications/Dandi.app
  # 단독 CLI 바이너리인 경우:
  xattr -d com.apple.quarantine /path/to/dandi
  ```
- **Windows**: Microsoft Defender SmartScreen에서 *"Windows의 PC 보호"* 창이 뜨면 **추가 정보** → **실행**을 선택하세요. 다운로드 파일은 릴리스 페이지의 `SHA256SUMS.txt`로 무결성을 검증할 수 있습니다.

---

## 로드맵

- [x] **M0 — 이슈 리서치 & 아키텍처**: 24개 실전 아카이버 버그 분석([`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md)), 딥 모듈 아키텍처([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)), 100점 평가 기준([`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md)).
- [x] **M1 — 코어 엔진 + CLI + 자동 평가 하네스**: `dandi-core`, `dandi-cli`, `dandi-eval` **100/100** 달성 및 M1.5 `ExtractionSink`·구조화 경고·`SanitizedPath` 강화.
- [x] **M2 — Tauri v2 데스크톱 GUI**: 드래그 앤 드롭, 아카이브 트리 미리보기, 원클릭 인코딩 전환, NFC 복구, 스마트 풀기, 진행률·취소.
- [x] **M3 — OS 셸 통합 & 자동 릴리스 파이프라인**: 데스크톱 경고/덮어쓰기 UX, macOS Finder 빠른 동작, Windows HKCU 탐색기 메뉴, 크로스 OS 릴리스 워크플로 및 SHA-256 체크섬, 다국어 오픈소스 문서.

---

## 기여 및 보안

- 개발 환경 설정, 코딩 규칙, `dandi-eval` 머지 기준은 [`CONTRIBUTING.md`](CONTRIBUTING.md)를 참고하세요.
- 보안 위협 모델 및 취약점 비공개 제보 절차는 [`SECURITY.md`](SECURITY.md)를 참고하세요.

## 라이선스 및 상표권

- **소스 코드**: [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`) © [ITP-Adieum](https://github.com/ITP-Adieum). 개인 및 기업/상업적 사용 모두 무료입니다.
- **상표권**: **Dandi(단디)** 이름과 로고는 ITP-Adieum의 상표이며 GPL-3.0 라이선스 범위에 포함되지 않습니다. 포크 프로젝트는 별도의 이름과 아이콘을 사용해야 합니다.
- **상용 / 듀얼 라이선스**: 독점 소프트웨어 임베딩이나 상용 재배포 라이선스는 ITP-Adieum에 문의해 주세요.
