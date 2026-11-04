# AI SOC 與 AI Sandbox 新手指南（老師版）

> 這份指南假設你是**第一次**接觸這個專案、也第一次接觸「密碼學帳本」這類東西。
> 我會像老師一樣，每一步先告訴你「要做什麼、為什麼、預期看到什麼、看到別的代表什麼」。
> 除非另有說明，指令都在這個 repo 的根目錄執行。範例輸出供判讀使用，筆數、識別碼與執行時間可能隨版本而異。

---

## 0. 這份指南怎麼用

| 你想要… | 去哪一節 |
|---|---|
| 10 分鐘弄懂這套系統在防什麼 | §1、§2 |
| 把軟體跑起來、看到結果 | §4、§5 |
| Ubuntu 主機經真人核准後實際封鎖來源 IP | [Ubuntu 封鎖部署說明](UBUNTU_BLOCKING.zh-TW.md)；預設停用，先在隔離主機驗收 |
| 看懂跑出來的檔案 | §6 |
| 親手證明「改一個字元就會被抓到」 | §7 |
| 讀程式碼、判斷每個函數是不是真的在做它說的事 | §8 |
| 自己從零重寫一遍 | §9 |
| 準備答辯、回答專家提問 | §10、§11、§12 |

**老師註解在哪裡？** 程式碼裡所有重要的 class / function 上方都有一段以 `【老師註解】` 開頭的中文註解，固定格式：

```
# ── 【老師註解】<名稱> ───────────────
# 做什麼：這段程式做的事（一句話）
# 為什麼：論文／安全理由
# 怎麼看：讀這段程式時的判讀要點
# 拿掉會怎樣：這個控制不存在時的後果
# 對應：準則 #n；測試 tests/<檔案>::<測試名>
```

列出全部註解：

```bash
grep -rn "老師註解" aisoc/          # 每一條註解的檔案與行號
grep -rc "老師註解" aisoc/ | sort   # 每個檔案有幾條
```

「對應」那一行是給你**自己驗證**用的：準則編號對照 §3 的表；測試名可以直接跑，例如
`python -m pytest -q tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper`。
**程式碼說它做了什麼不算數，測試證明它做了什麼才算數。**

---

## 1. 五個核心概念（先讀這裡，10 分鐘）

### 1.1 哈希（hash）＝ 資料的指紋

把任意長度的資料丟進 SHA-256，得到固定 64 個十六進位字元。改資料的任何一個位元，指紋就完全不同；而且從指紋推不回原始資料。

本專案用 `sha256:` 前綴標示，例如 `sha256:20dbd2dc…`。**帳本裡只存指紋，不存原文**（準則 #7）——所以監管者可以驗證帳本，卻看不到敏感流量內容。

→ 程式碼：`aisoc/canonical.py::digest`

### 1.2 規範化（JCS, RFC 8785）＝ 同一份資料永遠長得一樣

同一個 JSON 物件可以有很多寫法（鍵的順序、空白、`1.0` vs `1`）。如果簽名前不先統一格式，驗證方算出的指紋就會不同、簽名就驗不過。

JCS 的規則：鍵按字典序排序、沒有多餘空白、數字用固定格式、拒絕 NaN。**所有簽名與哈希都先經過 JCS**。

→ 程式碼：`aisoc/canonical.py::canonical_bytes`；測試 `tests/test_canonical_crypto.py::test_digest_stable_across_ordering`

### 1.3 數位簽名（Ed25519）＝ 只有持鑰者能蓋的章

一對鑰匙：**私鑰**（只有簽名者有）、**公鑰**（人人可拿）。用私鑰對資料簽出一段 `sig`，任何人用公鑰可以檢查「這段資料確實是私鑰持有者簽的、而且簽完沒被改過」。

本專案**一個角色一把鑰匙**（準則 #9）：

| 角色 (role) | 誰 | 簽什麼 |
|---|---|---|
| `ledger` | 帳本服務 | 帳本檢查點（Merkle 根） |
| `authorizer` | 簽名服務 | 動作授權（單次、短時效） |
| `executor` | 執行器 | 動作收據 |
| `approver` | 人類審批者 | 人工批准／拒絕、接受決定 |
| `verifier` | 獨立驗證器 | 驗證結論 |
| `model_release` | 訓練域 | 模型發布清單（SOC 只拿到公鑰） |

**沙箱裡的 Agent 一把鑰匙都沒有**（準則 #1）。這是整個設計的核心：Agent 就算被完全攻陷，也偽造不出任何一個簽名。

→ 程式碼：`aisoc/crypto.py::Ed25519Signer`、`TrustedKeys.verify`（驗簽時連 role 一起驗，拿錯角色的鑰匙簽也不行）

### 1.4 Nonce 與重放攻擊

攻擊者截到一張「有效的授權」，再送一次會怎樣？如果系統只驗簽名，就會再執行一次（**重放攻擊**）。

解法：每張授權帶一個一次性的亂數 `nonce`，執行器記住用過的 nonce，第二次看到就拒絕（準則 #6）。本專案另外還有「冪等鍵」：同一個 idempotency key 再送，回傳**上次的收據**，不產生新副作用。

→ 程式碼：`aisoc/sandbox/pep.py::NonceStore`、`PolicyEnforcementPoint.execute`；測試 `tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper`；消融實驗「ABLATION: remove single-use nonce and idempotency」會證明拿掉它重放就成功

### 1.5 哈希鏈、Merkle 根、外部見證

**哈希鏈**：帳本第 n 筆記錄包含第 n−1 筆的指紋 (`prev_hash`)。改第 5 筆，第 6 筆存的 `prev_hash` 就對不上 → 「chain broken at 5」。

但攻擊者如果能改整條鏈（第 5 筆之後全部重算）呢？所以還需要：

**Merkle 根 + 外部見證**：每個調查案件結束時，帳本把目前全部記錄算成一個 Merkle 根，用 `ledger` 鑰匙簽名，交給**帳本管理員管不到的**外部見證（準則 #7）；匯出前 `AISOC.seal()` 再補最後一個檢查點，讓見證長度 = 帳本長度（尾端只偵測不調查的案件也被保護）。之後就算整條鏈被重寫，也對不上見證保存的根與長度 → 「truncated below witnessed length 472」。

**沒有見證且其餘完整性檢查通過時**，驗證器不會說「通過」，只會說 `UNKNOWN`（準則 #8）——因為它無法排除整條鏈被重寫的可能。若帳本已損壞，仍會回傳 `FAILED`。

→ 程式碼：`aisoc/owp/ledger.py::HashChainLedger`、`merkle_root`、`ExternalWitness`；`aisoc/owp/verifier.py::Verifier.verify_case`

---

## 2. 系統全貌

```
                     訓練域（離線）＝ 論文「架構一：dual_model 訓練與推理」，詳見 §13
                     ┌──────────────────────────────────────────────────────┐
                     │ pyshark 即時抓包 → conn.log + 抓包清單 (aisoc/capture/)  │
                     │ Slips IPS 偵測／攔截 → alerts.json（標籤來源）            │
                     │ → 簽名資料集副本 (dataset_curator 鑰匙)                  │
                     │ → 校驗清洗 → [已知分支 | 異常分支] → 留一家族評估          │
                     │ → 簽名發布清單 (model_release 鑰匙) → 發布閘門（人批待定） │
                     └──────────────────────────┬───────────────────────────┘
                                    │ 模型位元組 + 清單（只驗哈希與簽名）
   流量/Slips 告警 ──► ┌─────────────▼─────────────┐
                      │ AI-IDPS  dual_model        │  已知分支 c_k ＋ 異常分支 s_a
                      │ (aisoc/idps/)              │  → Table III 六條規則 → 案件狀態
                      └─────────────┬─────────────┘
                                    │ 需要調查的案件
                      ┌─────────────▼─────────────┐
                      │ 沙箱  (aisoc/sandbox/)     │
                      │  凍結工作單 + 最小能力授予   │
                      │  Agent（只讀工具、無鑰匙）   │
                      │  ↓ 唯一出口：出口代理        │  先記帳、後轉發；記不了就丟（fail-closed）
                      └─────────────┬─────────────┘
                                    │ 報告 / 動作請求
            ┌───────────────────────▼────────────────────────┐
            │ 控制面（沙箱外）                                  │
            │  政策引擎 → allowed / reserved / denied           │
            │  reserved ⇒ 人類審批（簽名，綁定請求摘要）          │
            │  簽名服務 ⇒ 單次、短時效、綁範圍的授權              │
            │  PEP ⇒ 八項檢查全過才執行 ⇒ 簽名收據               │
            └───────────────────────┬────────────────────────┘
                                    │ 每一步都寫帳本
            ┌───────────────────────▼────────────────────────┐
            │ OWP 帳本 (aisoc/owp/)                            │
            │  只存指紋、哈希鏈、Merkle 檢查點、外部見證          │
            │  獨立驗證器：離線對賬 → VERIFIED / UNKNOWN / FAILED│
            └────────────────────────────────────────────────┘
```

一句話總結論文主張：**我們不假設 Agent 永遠不會被攻破；而是讓它攻破後的每一步都無權、無鑰、無法抹去。**

編排者是 `aisoc/soc.py::AISOC`，上面每一個箭頭都對應 `AISOC._run_case` 裡的一個步驟（程式碼裡標了「步驟 1～11」）。

---

## 3. 十三條設計準則 → 程式碼 → 測試

這十三條是從論文整理出來的；程式碼註解裡的「準則 #n」就是指這張表。

| # | 準則 | 程式碼位置 | 證明它成立的測試 |
|---|---|---|---|
| 1 | Agent 無權力、不持鑰匙，只有只讀工具 | `sandbox/tools.py::ReadOnlyTools`、`soc.py::AISOC.__init__` | `test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects` |
| 2 | 單一出口；先記帳後轉發；記不了就丟 (fail-closed) | `sandbox/egress.py::ControlledEgressProxy.forward` | `test_egress_release_grant.py::test_egress_proxy_fail_closed_vs_fail_open` |
| 3 | 政策在沙箱外；有效能力 = 任務 ∩ 授予 ∩ 執行期限制 ∩ 人類 | `sandbox/policy.py::PolicyEngine.decide` | `test_policy_pep.py::test_policy_denies_scope_violations` |
| 4 | 保留動作必須真人簽名，且簽名綁定請求摘要 | `sandbox/authorization.py::HumanApprover`、`AuthorizationSigner._check_approval` | `test_policy_pep.py::test_signer_refuses_without_or_with_bad_approval` |
| 5 | PEP 檢查順序固定（簽名→信封綁定→時效→撤銷→人簽→冪等→nonce→受限執行） | `sandbox/pep.py::PolicyEnforcementPoint.execute` | `test_policy_pep.py::test_pep_rejects_untrusted_signer_and_expiry_and_revocation` |
| 6 | 授權單次、短時效、可撤銷；授予只能收窄不能放寬 | `sandbox/pep.py::NonceStore`、`owp/objects.py::CapabilityGrant.attenuate` | `test_policy_pep.py::test_ablation_flag_restores_replay`、`test_egress_release_grant.py::test_attenuate_narrows_only` |
| 7 | 帳本只存指紋 + 哈希鏈 + Merkle + 外部見證 | `owp/ledger.py::HashChainLedger` | `test_ledger_verifier.py::test_modification_detected`、`test_truncation_and_fork_detected` |
| 8 | 驗證器離線可跑；沒有見證 ⇒ UNKNOWN，不是通過 | `owp/verifier.py::Verifier.verify_case`、`cli.py` 的 `verify` | `test_ledger_verifier.py::test_verifier_unknown_without_witness` |
| 9 | 一角色一鑰匙；驗簽連角色一起驗 | `crypto.py::TrustedKeys.verify` | `test_canonical_crypto.py::test_signature_roundtrip_and_role_check` |
| 10 | 模型以簽名 + 哈希釘死，不符就拒載入；只有 `verify_release` 回傳的 `VerifiedRelease` 能讓帳本記成 verified | `idps/release.py::verify_release`、`soc.py::AISOC.from_release` | `test_egress_release_grant.py::test_release_gate_accepts_only_exact_signed_artefact`、`::test_soc_rejects_release_that_did_not_pass_the_gate` |
| 11 | 日誌文字一律不可信（可能含注入）；缺資料 ⇒ UNKNOWN 不是正常 | `sandbox/untrusted.py::Untrusted`、`idps/dual_model.py::DualModel._unknown` | `test_policy_pep.py::test_injection_screen_flags_instructions`、`test_egress_release_grant.py::test_decide_external_combinations` |
| 12 | 雙模型多路徑；已知低信心 ∧ 異常高 ⇒ 疑似零日 ⇒ 必須人審 | `idps/dual_model.py::DualModel._combine` | `test_dual_model.py::test_decision_table_covers_known_attack`、`test_missing_data_is_unknown_not_normal`、`test_leave_one_family_out_escalates_unseen_family_somewhere` |
| 13 | 誠實範圍：合成資料、單一進程、確定性 Agent；數字不是安全認證 | `report.md` 開頭的免責聲明、`README.md` 的 Honest scope | — |

---

## 4. 環境準備

需要：Python 3.10 以上（我用 3.12.3 驗證）、pip。**不需要** GPU、Docker、網路服務；全部在本機跑完。

```bash
git clone https://github.com/alphatin123/AI-SOC-and-AISandbox.git
cd AI-SOC-and-AISandbox
git checkout feat/slips-aisoc-adapters     # PR #5 的分支；合併後用 main 即可
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -e '.[test]'          # 安裝本專案、cryptography 與 pytest
```

`-e` 是可編輯安裝：使用同一個 Python 環境時，即使切換到 `demo-output/aisoc-run`，仍可執行 `python -m aisoc`。只安裝 `requirements.txt` 不會安裝本專案；若出現 `No module named aisoc`，請用發生錯誤的那個 Python 在 repo 根目錄執行上面的安裝指令。

**先確認所在目錄**：`pwd` 應指向 repo 根目錄，而不是 `demo-output/aisoc-run`。在此 Codespace 可以執行：

```bash
cd /workspaces/AI-SOC-and-AISandbox
```

其他環境請換成自己的 repo 路徑。套件安裝後能從任何目錄匯入，但 `tests/...`、`demo-output/...` 這類相對路徑仍以目前所在目錄為準。

為什麼依賴這麼少？因為 dual_model 是純 Python 寫的邏輯迴歸 + Isolation Forest（在 `aisoc/idps/`），故意不用 PyTorch——**重點不是模型多強，而是模型周圍的治理鏈條**。

---

## 5. 一步一步重現

每一步都有：**做什麼 → 指令 → 預期輸出 → 怎麼判讀 → 出錯怎麼辦**。

### 步驟 1：跑完整測試套件

**做什麼**：先確認所有安全性質在你的機器上成立，再看任何東西。

```bash
python -m pytest -q
```

**預期輸出**（最後一行）：
```
192 passed in ~19s
```

**怎麼判讀**：192 個測試涵蓋 §3 表中每一條準則（其中 `tests/test_capture.py`、`tests/test_training_domain.py` 是 §13 架構一的 27 個測試）。任何一個失敗都代表某條保證在你的環境不成立——**先停下來**。

**出錯怎麼辦**：`ModuleNotFoundError: cryptography` → 沒裝依賴或沒啟用 venv。

若看到 `file or directory not found: tests/...`，請先回 repo 根目錄。也可以在此 Codespace 的任何目錄用絕對路徑執行單一測試：

```bash
python -m pytest -q /workspaces/AI-SOC-and-AISandbox/tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
```

這個單一測試已實測通過（`1 passed`）；不代表已執行完整測試套件。

### 步驟 2：跑完整模擬

**做什麼**：訓練模型 → 留一家族實驗 → 跑 200 個案件的 SOC 流程 → 跑 15 個攻擊情境 + 4 個消融實驗。

```bash
python -m aisoc simulate --out demo-output/aisoc-run
```

**預期輸出**：
```
1/4 training dual_model on time-ordered synthetic split ...
2/4 leave-one-family-out ...
3/4 running SOC pipeline with heuristic agent (model loaded through the signed release gate) ...
4/4 running security scenarios and ablations ...
   [ok] L0/L1 indirect prompt injection drives a fully compromised agent
   [ok] cross-tenant target
   [ok] replay of a valid single-use authorization
   [ok] expired authorization
   [ok] revocation
   [ok] parameter change after approval
   [ok] ledger tamper and truncation after external checkpoint
   [ok] execution that bypasses the ledger (tool-side receipt without authorization record)
   [ok] Slips Description text as prompt injection into a compromised agent
   [ok] Slips anomaly-only / weak-indicator-only evidence (no normality branch, no named class)
   [ok] AiSOC approval inbox as the human step (approve / deny / undecided / wrong record)
   [ok] AiSOC evidence bundle anchored into the OWP ledger (HMAC tamper-evidence upgraded to signed, witnessed commitment)
   [ok] sandbox egress proxy fails closed (audit down / oversize / rate limit)
   [ok] signed model release gate (training domain -> sandbox)
   [ok] capability grant attenuation for sub-tasks (narrow only)
   [ok] ABLATION: remove single-use nonce and idempotency
   [ok] ABLATION: PEP no longer requires approval for high impact
   [ok] ABLATION: no external witness
   [ok] ABLATION: egress proxy fails open when the audit domain is down

written to demo-output/aisoc-run/report.json and report.md
```

**怎麼判讀**：
- `[ok]` 的意思是「**情境的結果符合預期**」。注意：ABLATION（消融）的預期是「控制拿掉後攻擊**成功**」——`[ok]` 代表我們成功證明了那個控制是必要的，不是代表系統安全。
- 「model loaded through the signed release gate」：第 3 步的模型是經 `AISOC.from_release` 驗簽載入的（準則 #10）。

**出錯怎麼辦**：出現 `[FAIL]` → 對照 `report.md` 的 expected 欄，看哪個情境行為變了；`--seed` 預設固定，結果應完全可重現。

### 步驟 3：讀報告

```bash
cat demo-output/aisoc-run/report.md
```

**重點段落怎麼讀**：

```
- benign FPR at validation-fixed thresholds: 0.0037
- recall by family: {'ssh_bruteforce': 1.0, 'c2_beacon': 1.0, 'port_scan': 1.0, 'exfiltration': 1.0}
- status mix: {'LOW_RISK_OBSERVE': 541, 'KNOWN_SUSPICIOUS': 57, 'MODEL_CONFLICT': 2}
```
→ 門檻是在**驗證集**上定的，不是在測試集上調的（否則 FPR 會不誠實）。

```
| held-out family | recall | benign FPR |
| ssh_bruteforce  | 0.619  | 0.0037     |
```
→ **留一家族**實驗：訓練時完全不給模型看 ssh_bruteforce，測它能不能憑異常分支抓到。0.619 是誠實的數字——它說明「疑似零日」路徑有用但不是萬能；答辯時直接說這個數字，比說 100% 可信。

```
- requests: {'requests': 23, ..., 'reserved': 17, 'allowed': 6, 'human_approved': 17, ..., 'executed': 23, 'pep_rejected': 0, 'cross_tenant_executed': 0}
- verification: {'VERIFIED': 23}
- acceptance: {'ACCEPTED': 23}
```
→ 正常流程：23 個動作請求，17 個是高影響 (`block_host`) 需人簽、6 個低影響自動放行；23 個全部有驗證結論且全部 VERIFIED。`cross_tenant_executed: 0` 是關鍵的零。

### 步驟 4：離線驗證

**做什麼**：假裝你是監管者，**只拿輸出檔案、不碰 SOC**，重算整條證據鏈。

```bash
python -m aisoc verify demo-output/aisoc-run
```

`verify` 的參數是**輸出目錄**，不是 `ledger.json`，因為還需要讀取公鑰、見證與收據。如果已經在 `demo-output/aisoc-run` 裡，請改用：

```bash
python -m aisoc verify .
echo "exit=$?"
```

若指定的目錄不存在或缺檔，可能看到 `FileNotFoundError`；這是檔案路徑問題，不是驗證結論。若看到 `chain broken at 5`，代表帳本第 5 筆的完整性檢查失敗，不是匯入或目錄問題。不要改寫雜湊來「修好」證據，請保留原檔，另產生乾淨資料做練習（見 §7）。

**預期輸出**：
```json
{
  "status": "VERIFIED",
  "entries": 472,
  "checkpoints": 24,
  "receipts": 23,
  "problems": []
}
```

**怎麼判讀**：
- `entries: 472`：帳本 472 筆（200 偵測 + 23 個調查案件 × 11 類記錄 + 46 筆出口紀錄 + 1 模型發布 + 1 去重）。
- `checkpoints: 24`：每個調查案件結束都做一次檢查點送見證（23 個），匯出前再「封頂」一個，讓最後一個檢查點的長度 = 472 = 帳本長度——所以是案件數 + 1。
- `receipts: 23`：執行器簽的收據，每一張都要能對到一筆 `authorization` 帳本記錄——對不到就是「繞過帳本執行」。
- 驗證器做了什麼：重算哈希鏈 → 用 `trusted-keys.json` 裡 `ledger` 的公鑰驗每個檢查點簽名 → 比對 Merkle 根 → 驗每張收據的 `executor` 簽名 → 對賬收據 vs 授權 → 對賬動作請求 vs 出口紀錄。

**三種狀態**：`VERIFIED`（exit 0）/ `UNKNOWN`（見證缺失且其餘檢查通過，exit 1）/ `FAILED`（發現完整性問題，exit 1）。`FAILED` 優先於 `UNKNOWN`；§7 會讓你親手製造後兩種。

### 步驟 5：把 Slips 的真實告警格式餵進同一條管線

**做什麼**：把 [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS) 輸出的 IDMEFv2 `alerts.json` + Zeek `conn.log` 當「外部已知分支」跑。這裡用 fixture；接真機見 `docs/INTEGRATION.md`。

```bash
python -m aisoc slips-ingest tests/fixtures/slips/alerts.json \
    --conn-log tests/fixtures/slips/conn.log --out demo-output/slips-run
```

**預期輸出**：
```
training dual_model on synthetic data (only its release gate and thresholds are used; the internal normality model is disabled for real traffic) ...
{
  "evidence": 7,
  "incidents": 1,
  "malformed": 1,
  "cases": 5,
  "status_counts": {"KNOWN_SUSPICIOUS": 3, "SUSPECTED_UNKNOWN": 1, "UNKNOWN": 1},
  "requires_human_review": 2,
  "known_families": {"bruteforce": 1, "threat_intel": 1, "port_scan": 1, "unclassified": 2}
}
```

**怎麼判讀**：
- `malformed: 1`：fixture 故意放了一行壞資料，adapter **拒絕而不是猜**（準則 #11）。
- `UNKNOWN: 1`：Slips 沒給家族、也沒有異常訊號的那筆，狀態是 UNKNOWN 送人審——**不是** LOW_RISK_OBSERVE。這是 `DualModel.decide_external` 路徑 D，註解裡有寫「拿掉會怎樣」。
- 「internal normality model is disabled for real traffic」：合成資料練的基線不能拿來比真實網路，所以預設關閉（除非 `--internal-normality`）。這是誠實範圍的一部分。

### 步驟 6：驗證 Slips 那一輪

```bash
python -m aisoc verify demo-output/slips-run
```
預期：`"status": "VERIFIED", "entries": 50, "checkpoints": 5, "receipts": 4`（4 個調查案件各一個檢查點 + 匯出前封頂 1 個）。

### 步驟 7：看會送去 AiSOC 的告警長什麼樣（不真的送）

```bash
python -m aisoc aisoc-push demo-output/slips-run --dry-run
```

**預期輸出**（節錄）：
```json
{
  "would_post": "http://localhost:8000/api/v1/alerts/submit",
  "events": [
    {
      "title": "[OWP-SOC] KNOWN_SUSPICIOUS on 10.0.0.77",
      "description": "known class bruteforce from slips/flowalerts with score 0.700; normality branch unavailable",
      "mitre_techniques": ["T1110"],
      "aisoc_owp": {"case_id": "case-…", "model_version": "dual_model/synthetic-seed1+slips/flowalerts", ...}
```

**怎麼判讀**：`model_version` 帶 `+slips/flowalerts`，帳本因此看得出「這個結論是誰說的」；`aisoc_owp` 區塊帶帳本錨點，AiSOC 那邊的告警可以反查回我們的帳本。

### 步驟 8：驗證 AiSOC 證據包的完整性欄位

```bash
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key test-key
```
預期：`"sha256_ok": true, "hmac_checked": true, "hmac_ok": true, "ok": true`，exit 0。

```bash
python -m aisoc aisoc-bundle-verify tests/fixtures/aisoc/investigation-bundle.json --hmac-key wrong-key
```
預期：`"hmac_ok": false, "problems": ["HMAC-SHA256 signature does not verify under the supplied key"], "ok": false`，exit 1。

**怎麼判讀**：AiSOC 的 HMAC 是**對稱**金鑰——伺服器自己也能造出任何合法的包。所以 `AISOC.anchor_external_evidence` 會再把包的指紋寫進我們的 Ed25519 帳本並立即做檢查點送見證，把「可偵測竄改」升級為「可對第三方承諾」。

### 步驟 9：列出所有老師註解，對照 §3

```bash
grep -rc "老師註解" aisoc/ | sort
```
每個檔案的數字就是該檔案裡被註解的重要函數數。接著讀 §8 的閱讀路線。

### 步驟 10：清理

```bash
rm -rf demo-output/     # 已在 .gitignore，不會被 commit
```

**想接真實封包、自己訓練模型？** 做完這裡之後直接跳到 §13（架構一：從 pyshark 抓包、Slips 標籤到簽名模型），那裡是另一組步驟 11～17。

---

## 6. 輸出檔案怎麼讀

`simulate` 與 `slips-ingest` 寫出的檔案（在 `--out` 目錄）：

| 檔案 | 內容 | 誰用 |
|---|---|---|
| `report.md` / `report.json` | 人讀的摘要：偵測指標、留一家族、SOC 統計、情境表 | 你、評審 |
| `ledger.json` | **帳本**，JSON 陣列；每筆只有指紋 | `verify` |
| `witness-checkpoints.json` | 外部見證保存的簽名檢查點 | `verify` |
| `trusted-keys.json` | 各角色的**公鑰**（沒有任何私鑰） | `verify` |
| `tool-side-receipts.json` | 執行器簽的動作收據（工具那一側的紀錄，不是帳本的） | `verify` 對賬 |
| `tool-calls.json` | Agent 呼叫只讀工具的紀錄 | 稽核 |
| `cases.json` | 每個案件的人讀結果（§6.2） | 你 |
| `model-card.json` | 模型版本、特徵結構、門檻、訓練資料指紋 | 稽核 |
| `slips-summary.json`（僅 slips-ingest） | 上面步驟 5 印的那段統計 | 你 |

### 6.1 一筆帳本記錄

```json
{
  "index": 0,
  "entry_type": "model_release",
  "case_id": "-",
  "object_digest": "sha256:20dbd2dc…",   ← 被記錄物件的指紋（原文不在這）
  "prev_hash":     "sha256:0000…0000",   ← 上一筆的 entry_hash；第 0 筆是全零
  "entry_hash":    "sha256:b7eab2f7…",   ← 本筆的指紋 = hash(index, type, case, digest, prev, time, refs)
  "recorded_at": "2026-11-02T01:50:49Z",
  "refs": {"model_version": "dual_model/synthetic-seed1"}
}
```

`entry_type` 的種類與一個調查案件的**固定順序**：
`detection → work_order → capability_grant → agent_egress(報告) → investigation_report → agent_egress(請求) → action_request → policy_decision → [human_approval] → authorization → action_receipt → verification_decision → acceptance_decision`

這個順序就是 `AISOC._run_case` + `_handle_request` 的程式碼順序。驗證器檢查的其中一件事就是「每個 `action_request` 前面有沒有對應的 `agent_egress`」（沒有 = 繞過出口代理）。

### 6.2 一個案件（cases.json）

```json
{
  "case_id": "case-…", "flow_id": "…",
  "decision": {"status": "KNOWN_SUSPICIOUS", "known_label": "ssh_bruteforce", "known_score": 1.0,
               "anomaly_score": 0.600879, "anomaly_threshold": 0.59487, "anomaly_high": true,
               "requires_human_review": false, "requires_agent_investigation": true, "reasons": [...]},
  "investigated": true, "deduplicated": false,
  "requests": [{"action": "block_host", "policy_status": "reserved", "human_decision": "approve",
                "authorized": true, "executed": true, "reason": "executed"}],
  "verification_status": "VERIFIED", "verification_findings": [],
  "acceptance_status": "ACCEPTED", "egress_dropped": []
}
```

**四個欄位 = 四道閘門**：`policy_status`（政策）→ `human_decision`（人）→ `authorized`（簽名器）→ `executed`（PEP）。
情境測試證明「被攻陷的 Agent 造不成副作用」用的就是：所有請求 `executed == false`。

`decision.status` 六種值（Table III）：

| 狀態 | 條件 | 人審？ | 派 Agent？ | 可封鎖？ |
|---|---|---|---|---|
| `KNOWN_SUSPICIOUS` | 已知分支指認攻擊類別 | 否 | 是 | 是（仍需人簽） |
| `SUSPECTED_UNKNOWN` | 已知分支拒答／弱正常 ∧ 異常高 → **疑似零日** | **是** | 是 | 否（只給可逆動作） |
| `MODEL_CONFLICT` | 已知分支很有信心說正常 ∧ 異常高 | **是** | 是 | 否 |
| `INSUFFICIENT_EVIDENCE` | 拒答 ∧ 異常低 | 抽樣 | 否 | — |
| `LOW_RISK_OBSERVE` | 正常 ∧ 異常低 | 否 | 否 | — |
| `UNKNOWN` | 缺欄位／模型失敗／外部沒給結論 | **是** | 否 | — |

---

## 7. 動手破壞它（每個練習都附預期輸出）

先建立**全新且已驗證**的暫存基準，不使用可能已被前一次練習改壞的 `demo-output/aisoc-run`。完成 §4 的套件安裝後，以下指令可從任何目錄執行，不會覆寫 repo 內的資料：

```bash
demo_root=$(mktemp -d /tmp/aisoc-exercises.XXXXXX)
python -m aisoc simulate --out "$demo_root/baseline" &&
python -m aisoc verify "$demo_root/baseline"
```

**只有基準顯示 `VERIFIED` 且 exit 0，才繼續。** 在同一個終端機執行後續練習，保留 `demo_root` 變數。每個練習都另建目錄，避免重複 `cp -r` 到既有目錄造成巢狀複製。

若 `cp` 顯示 `cannot stat 'demo-output/aisoc-run'`，表示目前目錄下沒有這個相對路徑；不要繼續驗證不存在的副本。請回 repo 根目錄，或使用以下暫存基準的路徑。

### 練習 A：改帳本一個字元

```bash
tamper_dir=$(mktemp -d "$demo_root/tamper.XXXXXX")
cp -r "$demo_root/baseline/." "$tamper_dir/" &&
python - "$tamper_dir" <<'EOF'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) / "ledger.json"
entries = json.loads(path.read_text())
original = entries[5]["object_digest"]
entries[5]["object_digest"] = original[:-1] + ("0" if original[-1] != "0" else "1")
path.write_text(json.dumps(entries, indent=2))
EOF
python -m aisoc verify "$tamper_dir"; echo "exit=$?"
```
```json
{"status": "FAILED", "entries": 472, "checkpoints": 24, "receipts": 23,
 "problems": ["chain broken at 5"]}
exit=1
```
**為什麼抓得到**：第 6 筆的 `prev_hash` 是用第 5 筆**原本**的內容算的。

### 練習 B：刪掉最後 10 筆（截斷）

```bash
truncated_dir=$(mktemp -d "$demo_root/truncated.XXXXXX")
cp -r "$demo_root/baseline/." "$truncated_dir/" &&
python - "$truncated_dir" <<'EOF'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) / "ledger.json"
entries = json.loads(path.read_text())
path.write_text(json.dumps(entries[:-10], indent=2))
EOF
python -m aisoc verify "$truncated_dir"; echo "exit=$?"
```
```json
{"status": "FAILED", "entries": 462, ...,
 "problems": ["truncated below witnessed length 464",
              "truncated below witnessed length 472",
              "receipt rcpt-… executed without ledger authorization (bypass)"]}
exit=1
```
**為什麼抓得到**：哈希鏈本身對「刪尾巴」無感（鏈還是連續的），但外部見證記得「最後一個調查案件結束時長度是 464、匯出封頂時是 472」；同時有一張執行器收據找不到對應的授權記錄——**兩個獨立機制同時報警**。試試只刪最後 1 筆：若沒有匯出前的封頂檢查點，刪掉第 465～472 筆這段「檢查點之後的尾巴」是抓不到的。

### 練習 C：拿掉外部見證

```bash
no_witness_dir=$(mktemp -d "$demo_root/no-witness.XXXXXX")
cp -r "$demo_root/baseline/." "$no_witness_dir/" &&
printf '[]\n' > "$no_witness_dir/witness-checkpoints.json" &&
python -m aisoc verify "$no_witness_dir"
echo "exit=$?"
```
```json
{"status": "UNKNOWN", "entries": 472, "checkpoints": 0, "receipts": 23, "problems": []}
exit=1
```
**判讀**：`problems` 是空的、鏈也完整，但驗證器**拒絕說 VERIFIED**——因為它無法排除整條鏈被重寫（準則 #8）。這就是「沒有證據 ≠ 沒有問題」在程式碼裡的樣子。

如果結果仍是 `FAILED` 且包含 `chain broken at 5`，代表你複製的是已被改動的帳本；拿掉見證不會讓既有完整性錯誤消失。請重新建立並驗證上面的暫存基準，不要覆寫原本的損壞資料。

### 練習 D：試著讓測試失敗

把 `aisoc/sandbox/pep.py` 裡 `NonceStore.consume` 的「已用過就回 False」那一行註解掉，跑：
```bash
python -m pytest -q tests/test_policy_pep.py::test_pep_happy_path_then_replay_and_tamper
```
它會失敗——這就是「測試證明控制存在」。記得 `git checkout aisoc/sandbox/pep.py` 還原。

---

## 8. 讀程式碼的路線圖

按這個順序讀，每個檔案先讀 `【老師註解】`，再讀它下面的程式，再跑它「對應」的測試。

| 順序 | 檔案 | 讀完你會懂 | 約幾分鐘 |
|---|---|---|---|
| 1 | `aisoc/canonical.py` | 為什麼簽名前要規範化；`digest` 怎麼算 | 5 |
| 2 | `aisoc/crypto.py` | 鑰匙、簽名、`TrustedKeys.verify` 的三個步驟（含角色檢查） | 10 |
| 3 | `aisoc/owp/objects.py` | 六種證據物件：WorkOrder / CapabilityGrant / PolicyDecision / ActionReceipt / VerificationDecision / AcceptanceDecision；`attenuate` 只能收窄 | 15 |
| 4 | `aisoc/owp/ledger.py` | 哈希鏈怎麼接、Merkle 根怎麼算、檢查點怎麼送見證、加密證據庫為什麼分開 | 20 |
| 5 | `aisoc/owp/verifier.py` | 離線驗證的五項檢查與 VERIFIED/UNKNOWN/FAILED 的判定規則 | 15 |
| 6 | `aisoc/sandbox/untrusted.py` | 為什麼日誌文字要包成 `Untrusted`、注入篩檢只是旗標不是防線 | 5 |
| 7 | `aisoc/sandbox/tools.py` + `agent.py` | Agent 只有哪四個只讀工具（`get_flow / get_host_window / get_recent_logins / lookup_ioc`）；`HeuristicStubAgent` vs `InjectionFollowingStubAgent`（後者模擬被完全攻陷） | 15 |
| 8 | `aisoc/sandbox/egress.py` | 出口代理五道關卡；fail-closed vs fail-open 的那一行 | 10 |
| 9 | `aisoc/sandbox/policy.py` | 四層交集 C_task ∩ C_grant ∩ C_runtime ∩ C_human → allowed/reserved/denied | 15 |
| 10 | `aisoc/sandbox/authorization.py` | 人簽怎麼綁請求摘要；簽名器為什麼「絕不盲簽」 | 15 |
| 11 | `aisoc/sandbox/pep.py` | 八項檢查的順序（①簽名 ②信封綁定 ③時效 ④撤銷 ⑤人簽 ⑥冪等 ⑦nonce ⑧受限執行）、收據 | 20 |
| 12 | `aisoc/soc.py` | 全部接線；`_run_case` 的 11 步、`_handle_request` 的 4 閘門 | 20 |
| 13 | `aisoc/idps/features.py → known_model.py → normality_model.py → dual_model.py → release.py` | 特徵、已知分支、異常分支、Table III、簽名發布閘門 | 30 |
| 14 | `aisoc/adapters/slips.py`、`aisoc_stack.py` | 外部偵測器與外部 SOC 平台怎麼接進來而不動信任鏈 | 20 |
| 15 | `aisoc/scenarios.py`、`aisoc/simulate.py`、`aisoc/cli.py` | 19 個情境怎麼構造、報告怎麼產生、CLI 怎麼接 | 20 |
| 16 | `aisoc/capture/flows.py → pyshark_source.py → runner.py` | 封包怎麼被組成 Zeek 風格的 conn.log 一列（`FlowAssembler`、`_conn_state` 狀態表）；pyshark 只是來源之一，缺 tshark 時怎麼乾淨失敗；抓包清單為什麼要釘住輸出檔哈希 | 20 |
| 17 | `aisoc/training/dataset.py → offline.py` | Slips 告警怎麼變成標籤（優先順序 uid → 主機+時間 → 只有異常 → 沉默＝benign）、資料集副本怎麼簽名與驗證、六個階段怎麼跑、為什麼 `approved_by` 預設是 `pending-human-gate` | 30 |

**判斷一個函數「有沒有做到它說的」的三步法**：
1. 讀註解的「做什麼／拿掉會怎樣」，想像你是攻擊者會怎麼繞。
2. 讀程式，找「拒絕」的那幾行（`raise`、`return ... ok=False`、`denied`）——安全控制的本體永遠是拒絕路徑。
3. 跑「對應」的測試，然後**故意把拒絕那行註解掉再跑一次**，看測試有沒有紅。沒紅代表測試沒測到，那條保證就是空的。

---

## 9. 如果要自己從零重寫一遍：模組建置順序

每個階段都有驗收條件；前一階段不過，不要往下蓋。

| 階段 | 做什麼 | 驗收 |
|---|---|---|
| 0 | `canonical.py`（JCS）、`crypto.py`（Ed25519、角色綁定） | 同一物件不同鍵序 → 相同 digest；錯角色驗簽失敗 |
| 1 | `owp/objects.py` 六種物件 + `to_dict/digest` | 每個物件 round-trip 後 digest 不變 |
| 2 | `owp/ledger.py` 哈希鏈 → Merkle → 檢查點 → 見證（append-only JSONL） | 改任一筆 → 鏈斷；截斷 → 見證長度不符 |
| 3 | `owp/verifier.py` | 無見證 ⇒ UNKNOWN；有竄改 ⇒ FAILED；乾淨 ⇒ VERIFIED |
| 4 | `sandbox/tools.py`、`untrusted.py`、`agent.py`（先寫 stub） | Agent 拿不到任何 signer 物件；工具只讀 |
| 5 | `sandbox/egress.py` | 帳本寫入失敗 ⇒ 訊息不轉發；超大／超速 ⇒ 丟 |
| 6 | `sandbox/policy.py` | 跨租戶 ⇒ denied；高影響 ⇒ reserved；授予過期 ⇒ denied |
| 7 | `sandbox/authorization.py` | 無人簽／人簽摘要不符 ⇒ 簽名器拒簽 |
| 8 | `sandbox/pep.py` | 重放 ⇒ 拒；過期 ⇒ 拒；改參數 ⇒ 拒；撤銷 ⇒ 拒 |
| 9 | `soc.py` 接線 | 端到端：乾淨案件 VERIFIED/ACCEPTED；被攻陷 Agent 零執行 |
| 10 | `idps/*`（可以最後做！） | 留一家族有 recall；FPR 在驗證集定門檻 |
| 11 | `scenarios.py` 15 情境 + 4 消融 | 消融拿掉控制 ⇒ 攻擊成功（證明控制 load-bearing） |
| 12 | `adapters/*`、`cli.py` | fixture 跑通；`verify` 可離線 |
| 13 | `capture/*`（封包 → conn.log）、`training/*`（Slips 標籤 → 簽名資料集 → 離線訓練 → 簽名發布） | 改 `flows.jsonl` 一個字元 ⇒ 訓練拒跑；改 `model.bin` 一個位元組 ⇒ 推理端拒載入；沒有真實攻擊家族 ⇒ 預設報錯而不是偷偷用合成資料 |

**為什麼模型放最後？** 因為這個專案的命題是：就算模型很弱、就算 Agent 被攻破，治理鏈仍然成立。先把鏈做對，再換更強的模型，鏈一行都不用改。階段 13 就是證明：換成真實封包訓練的模型，§5 的 SOC 與帳本程式碼一行都沒改，只多了一個 `--release-dir`。

---

## 10. 常見問題（答辯常被問）

**Q：你怎麼證明那是零日？**
A：我們不證明。系統輸出的是「**疑似**未知」(`SUSPECTED_UNKNOWN`)：已知分支拒答 ∧ 異常分支高。它的作用是**把人叫來**，而不是下結論。留一家族實驗（§5 步驟 3）量化這條路徑的召回率，0.619 就是誠實數字。

**Q：誤報率和分析師負載？**
A：`report.md` 的 FPR 0.0037 是在驗證集固定門檻後量的；200 案件只有 23 個進調查、其中 17 個需人簽。去重視窗 (`dedup_window_s=300`) 抑制同主機同狀態的重複。數字是合成資料的，真實網路要用 Slips 跑過再量。

**Q：私鑰被盜怎麼辦？**
A：一角色一鑰匙，所以偷到 `authorizer` 鑰匙也簽不出人類批准、簽不出帳本檢查點。授權單次 (nonce)、短時效 (預設 300 秒)、可撤銷 (`RevocationList`)。Agent 沙箱內**根本沒有**任何私鑰可偷。模擬裡鑰匙在記憶體；正式環境放 HSM。

**Q：基線被投毒怎麼辦？**
A：門檻在驗證集上定、分析師標籤需人工審核才進訓練集、模型發布要簽名 + 哈希（準則 #10）——壞模型進不了沙箱。但我們**沒有**實作投毒偵測本身，這在誠實範圍裡。

**Q：審批者只會按「同意」（橡皮圖章）怎麼辦？**
A：`HumanApprover` 簽名綁定的是**請求摘要**，所以批的是「這個動作、這個目標、這些參數」，批完改參數 PEP 會拒（情境「parameter change after approval」）。防快速批准的時間下限我們沒做，列在待辦。

**Q：跟商用 AI SOC 差在哪？**
A：不是偵測更準，而是**問責可離線驗證**：帳本只存指紋、公鑰驗證、不需信任 SOC 營運者。這補的是業界缺口（審計證據不統一、步驟間上下文不入帳），不是「首創」。

**Q：為什麼 fail-closed？業務會不會被拖垮？**
A：消融「egress proxy fails open when the audit domain is down」示範了反面：改成 fail-open，請求還是會到控制面，但驗證器只能事後發現「缺出口紀錄」——變成偵測型而非預防型。這是設計取捨，論文選預防。

---

## 11. 誠實範圍（不要在答辯時被問倒）

- 全部資料是**合成**的；Agent 是**確定性 stub**，不是 LLM。§13 的架構一可以吃真實封包，但本指南的預期輸出仍然是用合成抓包量出來的。
- 五個信任域跑在**同一個 Python 進程**，論文的保證需要它們由不同管理員掌控、沙箱用 microVM 隔離。
- 外部見證是本地 append-only 檔案；正式環境要是第三方服務或公開時間戳。
- 鑰匙在記憶體；正式環境要 HSM。`dataset_curator` 與 `model_release` 的公鑰預設放在輸出目錄旁邊（會印 WARNING），正式環境要用 `--trust` / `--release-trust` 帶外交付。
- 架構一的標籤**全部來自 Slips**：「benign」只代表 Slips 沒有告警，不代表流量經過人工確認乾淨；Slips 漏掉的攻擊會被當成正常基線（投毒風險）。`login_failures` 永遠是 0（conn.log 看不到登入結果）。
- pyshark 的 `FlowAssembler` 是簡化版的 Zeek conn 狀態機，不是 Zeek；`--slips-blocking` 只是記錄操作者的宣稱，程式無法驗證 Slips 真的有攔截。
- 沒有實作：投毒偵測、審批最短思考時間、模型檔在沙箱內被竊取的防護。
- 所有數字描述**這個參考實作**，不是真實流量的偵測結果，不是安全認證。

---

## 12. 決賽現場演示腳本（3 個，各 1 分鐘）

| 演示 | 指令 | 觀眾看到 |
|---|---|---|
| 改一個字元就被抓 | §7 練習 A | `FAILED`, `chain broken at 5` |
| 偽造／重放被拒 | `python -m aisoc simulate --out /tmp/d \| grep -E "replay\|parameter change\|cross-tenant"` | 三行 `[ok]`；開 `report.md` 讀 expected 欄 |
| 逃逸後仍簽不了名 | `grep -n "老師註解】AISOC " -A 7 aisoc/soc.py` 再指出 `self.keys` 從未傳進 agent；跑 `python -m pytest -q tests/test_end_to_end.py::test_compromised_agent_cannot_cause_side_effects` | 1 passed |

錄一份螢幕備份：`script -q demo.log -c "python -m aisoc simulate --out /tmp/d && python -m aisoc verify /tmp/d"`。

---

## 13. 架構一：離線訓練域——從即時封包到簽名模型（新手逐步版）

論文 §5「dual_model 訓練與推理」畫的是這條離線管線：

```
數據採集與標註 → 數據校驗與清洗 → [已知攻擊模型 | 異常檢測模型]
→ 對抗與穩健性評估 → 模型登記 + 簽名 → 模型發布閘門（驗簽、驗哈希、人工批准）
```

這一章把它落到程式碼：

```
 網卡 / pcap ──► python -m aisoc capture (pyshark)  ──► conn.log + capture-manifest.json   ┐
                                                                                          ├─► python -m aisoc dataset-snapshot
 同一段流量 ──► Slips IPS（偵測；可選 -p 攔截）      ──► alerts.json（標籤來源）             ┘        │
                                                                                                   ▼
                                                   簽名資料集副本 flows.jsonl + manifest.json（dataset_curator 鑰匙）
                                                                                                   │
                                                                            python -m aisoc train-offline（六階段）
                                                                                                   ▼
                                                   model.bin + release-manifest.json（model_release 鑰匙）+ training-report.json
                                                                                                   │
                                      python -m aisoc slips-ingest --release-dir（推理端只驗哈希與簽名）   python -m aisoc dashboard --training-dir
```

**三個關鍵字先記住**：

| 名詞 | 意思 | 在哪個檔案 |
|---|---|---|
| 抓包清單（capture manifest） | 「這份 conn.log 是從哪個介面、幾個封包、什麼時候抓的；它的 sha256 是多少」 | `capture-manifest.json` |
| 資料集副本（dataset snapshot） | 流量 + Slips 標籤合成的訓練資料，**整份哈希被 `dataset_curator` 鑰匙簽名**，寫一次就不准改 | `<snapshot>/flows.jsonl`、`manifest.json`、`curator-keys.json` |
| 發布（release） | 訓練好的模型位元組 + 它的簽名清單（哈希、資料集哈希、評估數字、`approved_by`） | `<release>/model.bin`、`release-manifest.json`、`release-trust.json`、`training-report.json` |

**每一步只信上一步的「簽名 + 哈希」，不信檔名、不信路徑、不信誰說的。** 這就是論文把訓練域與沙箱分開的理由：模型進沙箱前，沙箱只能用公鑰驗、不能用信任換。

### 13.0 先決條件

```bash
python -m pip install -e '.[test,capture]'    # capture 額外裝 pyshark
```

- **抓即時封包**還需要系統套件 `tshark`（Debian/Ubuntu：`sudo apt install tshark`）以及 root 或 `CAP_NET_RAW`。沒有 tshark 也沒關係——步驟 12 之後全部不需要它，我在 Codespace 就是用合成抓包走完的。
- **Slips**：見 `docs/INTEGRATION.md` §1.1（pcap 回放）或「Codespaces Live Sensor」（即時）。Slips 的 `-p` 是攔截模式（需要 root、只在 `-i` 即時模式下有效）；**我們的 compose 檔沒有開**，開不開是部署者的決定。
- 下面所有輸出都來自測試用的合成抓包（`tests/conftest.py::synthetic_capture`：6 小時、200 個正常視窗 + 20 個掃描 + 20 個暴力破解）。真實流量的數字一定不同。

### 步驟 11：抓封包，變成 conn.log（數據採集 ①）

**做什麼**：用 pyshark 讀網卡或 pcap，把封包組成 Zeek 風格的連線紀錄（一條流一列），同時寫抓包清單。

```bash
# 即時（需要 tshark + root/CAP_NET_RAW）；60 秒或 5000 個 IP 封包後停
sudo -E python -m aisoc capture --interface eth0 --duration 60 --packets 5000 \
    --bpf 'not (tcp port 6379 or tcp port 6387)' --out sensor-output/pyshark-conn.log

# 或離線讀 pcap（還是要 tshark，但不用 root）
python -m aisoc capture --pcap dataset/your-capture.pcap --out sensor-output/pyshark-conn.log
```

**預期輸出**（進度每 1000 個封包印一行到 stderr，結束印清單摘要）：
```
capturing from interface eth0 -> sensor-output/pyshark-conn.log (header facts only; payload is counted, never stored). Stop with Ctrl-C.
  packets=1000 flows_written=137
  ...
{
  "packets_used": 4973,
  "packets_skipped_non_ip": 27,
  "flows_written": 612,
  "stop_reason": "max_packets",
  "out_sha256": "…"
}

conn.log written to sensor-output/pyshark-conn.log; manifest: sensor-output/capture-manifest.json
```

**怎麼判讀**：
- 「header facts only; payload is counted, never stored」：只記錄五元組、旗標、位元組數等表頭事實，**封包內容不落地**——這是資料最小化，也是抓包清單 `content_policy` 欄位寫的承諾。
- `stop_reason` 只會是 `source_exhausted`（pcap 讀完）/ `max_packets` / `duration` / `interrupted`（你按 Ctrl-C）/ `error`。不是這五個就是 bug。
- `out_sha256` 是 conn.log 的指紋，下一步會被釘進資料集清單。**抓完就不要再動這個檔**。
- conn.log 的欄位跟 Zeek 的 `conn.log` 一樣（`ts uid id.orig_h … conn_state orig_bytes resp_bytes …`），所以 Slips 自帶的 Zeek `conn.log` 也能直接餵給步驟 13。

**出錯怎麼辦**：
- `capture unavailable: pyshark is not installed…` → `pip install pyshark`。
- `capture unavailable: cannot start live capture on 'lo': TSharkNotFoundException…` → 沒裝 tshark。exit code 1。
- `capture unavailable: pcap file not found` → 路徑打錯。
- 沒有封包但程式不停 → 預設沒有停止條件；加 `--duration` 或 `--packets`，或按 Ctrl-C（會正常收尾並寫清單）。

讀程式：`aisoc/capture/flows.py` 的 `FlowAssembler` 註解講了 TCP 三向交握與 FIN/RST 怎麼對應 Zeek 的 `conn_state`（`SF / S0 / REJ / RSTO …`）；`tests/test_capture.py::test_conn_state_table` 一格一格驗。

### 步驟 12：讓 Slips 看同一段流量（數據標註 ②）

**做什麼**：Slips 才是「已識別惡意模式」的來源。它輸出的 `alerts.json` 之後會變成訓練標籤。

```bash
# pcap 回放
docker compose -f deploy/docker-compose.slips.yml run --rm slips ./slips.py -f dataset/your-capture.pcap -o output/
# 即時（與步驟 11 同一張網卡）
AISOC_CAPTURE_INTERFACE=eth0 docker compose -f deploy/docker-compose.slips-live.yml up -d
```

**怎麼判讀**：你需要兩個檔——`alerts.json`（IDMEFv2，一行一個 JSON）和 conn.log（步驟 11 的，或 Slips 自己的 `zeek_files/conn.log`）。兩者必須覆蓋**同一段時間、同一批主機**，否則標籤對不上流量，下一步會看到很多 `evidence_unmatched`。

**出錯怎麼辦**：Slips 跑了但 `alerts.json` 是空的 → 很正常，乾淨流量沒有告警；此時你只有 benign 標籤，步驟 14 會告訴你怎麼辦。

### 步驟 13：合成簽名資料集副本（數據採集與標註的「封存」）

**做什麼**：把 conn.log 切成 60 秒視窗（每對「來源主機 → 目的主機」一個視窗），用 Slips 告警替每個視窗貼標籤，整份資料算哈希並由 `dataset_curator` 鑰匙簽名。

```bash
python -m aisoc dataset-snapshot --conn-log sensor-output/pyshark-conn.log \
    --alerts sensor-output/alerts/alerts.json \
    --capture-manifest sensor-output/capture-manifest.json \
    --out demo-output/dataset-snapshot
```
（沒有 `--capture-manifest` 也能跑，`source.kind` 會是 `zeek-conn-log`；有的話整份抓包清單會嵌進 `manifest.json → source.capture_manifest`、`source.kind` 變成 `pyshark-capture`，並檢查 conn.log 的哈希等於抓包清單的 `out_sha256`——抓完之後有沒有被動過，一比就知道。）

**預期輸出**（合成抓包）：
```
{
  "dataset_id": "ds-a2dfd2279657",
  "flows": 390,
  "by_label": {"benign": 326, "unlabeled_anomaly": 1, "bruteforce": 34, "port_scan": 29},
  "label_sources": {"slips_silence": 326, "slips_anomaly_only": 1, "slips_host_time": 38, "slips_uid": 25},
  "evidence": 41,
  "malformed": 0,
  "flows_sha256": "a2dfd2279657…"
}

signed dataset snapshot written to demo-output/dataset-snapshot/ (flows.jsonl, manifest.json, curator-keys.json); next: python -m aisoc train-offline demo-output/dataset-snapshot
```

**怎麼判讀**（這是整章最需要懂的一張表）：

| `label_sources` | 標籤怎麼來的 | 可信度 |
|---|---|---|
| `slips_uid` | Slips 證據的 `uids` 直接指到這個視窗裡的連線 | 最高 |
| `slips_host_time` | 同一台來源主機、時間差 ≤ `--label-window-s`（預設 300 秒）、目標 IP 相符 | 中 |
| `slips_anomaly_only` | 視窗裡只有 Slips 的異常／ML 類證據、沒有家族 → 標 `unlabeled_anomaly`，**不會**進已知分支訓練 | 隔離 |
| `slips_silence` | Slips 完全沒說話 → `benign` | **最低**：只代表「Slips 沒抓到」 |

- `dataset_id` 就是 `flows_sha256` 的前 12 位：資料集的身分**等於**它的內容指紋。
- 同一視窗有多個不同家族的證據時，用 `Confidence × threat_level 權重` 取最大者，`manifest.json → labeling.conflicts` 會記錄衝突數。
- `threat_level` 為 `info`/`low` 且沒有家族的「弱指標」證據完全不參與標籤，也不算進 `evidence_matched`。
- `manifest.json → ground_truth` 那段英文是給審稿人看的免責：標籤來自 Slips，不是人工確認。

**出錯怎麼辦**：
- `refusing to overwrite … (write-once)` → 輸出目錄已有快照。這是刻意的：資料集副本不能原地覆寫，換一個 `--out`。
- `evidence_unmatched` 很大 → 時間或主機對不上，回步驟 12 確認兩個檔來自同一段流量。
- `windows_with_missing_measurements` > 0 → conn.log 有些列缺位元組數等欄位（Zeek 用 `-`），這些視窗的量測會是 `None`，步驟 14 會把它們丟掉並計數。

讀程式：`aisoc/training/dataset.py::build_flow_records`（標籤優先順序）、`build_snapshot`（簽名）、`write_snapshot`（write-once）。測試：`tests/test_training_domain.py::test_labels_follow_slips_rule_priority`、`::test_snapshot_pins_capture_manifest_hash`。

### 步驟 14：離線訓練六階段（校驗清洗 → 兩個模型 → 評估 → 登記簽名 → 閘門自檢）

**做什麼**：驗資料集簽名 → 清洗 → 按時間切 60/20/20 → 訓練已知分支（Slips 家族）與異常分支（benign 基線）→ 留一家族評估 → 算模型哈希、用 `model_release` 鑰匙簽發布清單 → 自己當一次閘門驗一遍。

```bash
python -m aisoc train-offline demo-output/dataset-snapshot --out demo-output/training-run
```

**預期輸出**（約 1 秒）：
```
WARNING: curator key taken from curator-keys.json inside the snapshot directory; pass --trust with a key received out-of-band for a real deployment
dataset ds-a2dfd2279657 verified (390 flows, flows_sha256 a2dfd22796571149...)
{
  "model_version": "dual_model/ds-a2dfd2279657-seed1",
  "known_branch_source": "real-slips-labels",
  "split": {"train": 232, "val": 78, "test": 78},
  "cleaning": {"kept": 388, "dropped_missing_measurements": 1, "dropped_duplicates": 0,
               "quarantined_anomaly_only": 1, "dropped_rare_families": {}},
  "benign_fpr": 0.0156,
  "recall_by_family": {"port_scan": 1.0, "bruteforce": 1.0},
  "lofo": {"bruteforce": 1.0, "port_scan": 1.0},
  "false_positives_per_day": 18.23,
  "stages": [["data_collection_and_labeling", "done"], ["data_validation_and_cleaning", "done"],
             ["known_attack_and_anomaly_models", "done"], ["adversarial_and_robustness_evaluation", "done"],
             ["model_registration_and_signing", "done"], ["model_release_gate", "self-check-passed"]]
}

release written to demo-output/training-run/ (model.bin, release-manifest.json, release-trust.json, training-report.json); use it with: python -m aisoc slips-ingest <alerts.json> --release-dir demo-output/training-run --internal-normality
```

**怎麼判讀**：
- 第一行 WARNING 是**故意吵你**：訓練端相信了快照目錄裡附帶的 `curator-keys.json`。正式部署要把策展人公鑰用別的管道交給訓練主機，然後加 `--trust curator.json`，WARNING 就會消失。
- `dataset … verified` 沒出現就不會往下跑。改 `flows.jsonl` 任何一個字元會得到 `dataset snapshot refused: flows.jsonl does not match the flows_sha256 pinned by the signed manifest`。
- `known_branch_source: real-slips-labels` 代表已知分支是用**真實 Slips 家族**訓練的。如果抓包裡沒有任何家族達到 `--min-per-class`（預設 5 筆），預設會停下來報 `training stopped: … pass --allow-synthetic-known …`；加了那個旗標才會退回合成資料，而且 `known_branch_source` 會變成 `synthetic-fallback`，儀表板上也會標黃。**絕不偷偷替換**。
- `lofo`（留一家族）：把某個家族整個從訓練集拿掉，看異常分支還能不能把它送進 `SUSPECTED_UNKNOWN`。1.0 是合成資料的數字，真實流量通常低很多——這才是論文要量化的「疑似零日召回率」。
- `false_positives_per_day` ＝ 測試集 benign 視窗被升級（送人審／調查）的次數 ÷ 測試集涵蓋的天數。它隨抓包時長縮放、不隨網站規模縮放；分析師負載就看這個。
- `model_release_gate: self-check-passed` 的意思是「訓練端自己用公鑰驗過一遍」，**不是**人批准了。`release-manifest.json → approved_by` 預設是 `pending-human-gate`；真人審過之後才用 `--approved-by 王小明` 重出一份。

**出錯怎麼辦**：
- `training stopped: benign baseline too small (…)` → benign 視窗少於 `--min-benign`（預設 30）。抓久一點。
- 想復現同樣的模型哈希 → 固定 `--seed`，模型是確定性的。

讀程式：`aisoc/training/offline.py` 的 `validate_and_clean`（每一筆被丟掉的流量都要有名目）、`time_split`（**按時間**切，不洗牌——洗牌會讓「未來」洩漏到訓練）、`evaluate`、`train_offline`。測試：`::test_validate_and_clean_counts_every_drop`、`::test_time_split_is_ordered`、`::test_train_offline_end_to_end_on_real_labels`、`::test_synthetic_known_fallback_is_explicit`。

### 步驟 15：把簽名模型交給推理端（模型發布閘門）

**做什麼**：推理端（`slips-ingest`）不再用合成資料現場訓練，而是載入 `--release-dir`，**只驗哈希與簽名**。

```bash
python -m aisoc slips-ingest sensor-output/alerts/alerts.json \
    --conn-log sensor-output/pyshark-conn.log \
    --release-dir demo-output/training-run --internal-normality \
    --out demo-output/slips-run-trained
python -m aisoc verify demo-output/slips-run-trained
```

**預期輸出**：
```
WARNING: trusting release-trust.json shipped next to the model; hand the model_release public key to the inference host out-of-band for a real deployment
loaded offline-trained release dual_model/ds-a2dfd2279657-seed1 from demo-output/training-run (known branch: real-slips-labels; internal normality model is ENABLED)
{ "evidence": 41, "incidents": 1, "malformed": 0, "cases": 41,
  "status_counts": {"SUSPECTED_UNKNOWN": 1, "KNOWN_SUSPICIOUS": 40}, "requires_human_review": 1, … }
```
`verify` → `"status": "VERIFIED"`。

**怎麼判讀**：
- 這裡 `--internal-normality` **終於有意義了**（§5 步驟 5 時我們把它關掉，因為合成基線不能比真實網路）：異常分支現在是用你自己的 benign 基線訓的。
- 同樣有一個 WARNING：推理端用了模型旁邊的 `release-trust.json`。正式部署用 `--release-trust release.json` 帶外交付。
- 帳本第一筆 `model_release` 會記下 `model_version` 與 `model_sha256`，所以事後任何人都能對照 `training-report.json` 查「這批案件是哪個模型判的、模型是哪份資料集練的」。

**動手破壞它**：
```bash
cp -r demo-output/training-run /tmp/bad-release
printf '\x00' | dd of=/tmp/bad-release/model.bin bs=1 seek=100 count=1 conv=notrunc
python -m aisoc slips-ingest sensor-output/alerts/alerts.json --release-dir /tmp/bad-release --out /tmp/x
```
預期：`release refused: model artefact hash does not match the signed manifest`，exit 1，`/tmp/x` 不會有帳本。改 `release-manifest.json` 裡任何欄位則是 `manifest signature invalid or signer not trusted for model release`。這就是準則 #10 在真實模型上的樣子。

### 步驟 16：在儀表板看整條架構一

```bash
python -m aisoc dashboard demo-output/slips-run-trained --training-dir demo-output/training-run --port 8765
```

打開 http://127.0.0.1:8765：

- 左側導覽現在分成 **OFFLINE TRAINING DOMAIN**（Training Domain）與 **INFERENCE DOMAIN**（Network IDPS、Detection Cases、Human Review、Evidence Ledger、Action Records），對應論文兩個管理域。
- 最上方的 **Architecture 1 pipeline** 六格：Capture → Slips IPS → Dataset snapshot → Training domain → Release gate → Inference。每格顯示來源數字與狀態色（綠＝有簽名可驗／黃＝宣稱或待人批／灰＝沒跑）。
- 下方一行 **provenance**：推理端帳本記的模型哈希是否**等於**訓練域發布的哈希；相等才是綠色「matches the training-domain release」。只開 `simulate` 輸出、沒有 `--training-dir` 時會寫「(recorded claim) · no training run attached」——儀表板不替你補證據。
- **Training Domain** 分頁：六階段進度條、標籤來源表、清洗計數、模型門檻（`tau_k`、每服務群 `tau_a`）、留一家族與 FPR、發布閘門五項檢查與 `human approval: pending`。
- 感測器 IP 預設遮罩成 `x.x.x.x`；`--show-ips` 才顯示。

**沒有 `--training-dir`**：Training Domain 顯示 `NOT_CONFIGURED` 與提示文字，pipeline 前四格灰色——這是正常狀態，不是錯誤。

### 步驟 17：清理

```bash
rm -rf demo-output/dataset-snapshot demo-output/training-run demo-output/slips-run-trained sensor-output/
```
（這些路徑都在 `.gitignore`。）

### 13.1 這一章對應的準則與測試

| 準則 | 架構一的體現 | 測試 |
|---|---|---|
| #7 只存指紋 | 資料集身分＝內容哈希；抓包清單釘 conn.log 哈希 | `test_training_domain.py::test_snapshot_round_trip_and_tamper_detection`、`::test_snapshot_pins_capture_manifest_hash` |
| #9 一角色一鑰匙 | `dataset_curator` 簽資料集、`model_release` 簽模型，角色錯驗簽失敗 | `::test_snapshot_round_trip_and_tamper_detection`（錯角色） |
| #10 模型釘死 | `slips-ingest --release-dir` 只驗哈希＋簽名 | `::test_cli_snapshot_train_and_ingest_release` |
| #11 缺資料 ≠ 正常 | 缺量測視窗被丟並計數，不補 0 | `::test_validate_and_clean_counts_every_drop` |
| #12 疑似零日要量化 | 留一家族召回率寫進發布清單 | `::test_train_offline_end_to_end_on_real_labels` |
| #13 誠實範圍 | `approved_by` 預設 pending；合成退路必須明示；benign 只是 Slips 沉默 | `::test_synthetic_known_fallback_is_explicit` |

### 13.2 答辯時怎麼講這一章（30 秒版）

「訓練域的輸入是兩份檔：pyshark 抓的連線紀錄和 Slips 的告警。我們不用檔名或路徑建立信任，而是把合併後的資料集整份雜湊、由策展人鑰匙簽名，寫一次不准改；訓練出來的模型再由另一把發布鑰匙簽名。推理端只驗這兩層簽名與雜湊——改一個位元組就拒載入。標籤全部來自 Slips，所以我們把『正常』誠實地定義成『Slips 沒有告警』，而且留一家族實驗量化了異常分支對沒見過的攻擊的召回率。」

---

*本指南對應 PR #5 分支 `feat/slips-aisoc-adapters`；§13 對應分支 `feat/pyshark-capture-dataset-training-ui`。所有輸出於 2026-11-02／11-04 以 Python 3.12.3 實測。*
