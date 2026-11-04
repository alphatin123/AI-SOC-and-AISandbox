# Ubuntu 真人核准後自動封鎖

## 範圍與安全界線

此整合阻斷本機對外連線。被動監聽主機不能靠這些規則保護整個網段。保護 **Ubuntu 主機本身的入站流量**，使用 nftables 的 `input` hook；不會封鎖其他設備的轉送流量，也不會

流程是 Slips 證據 → SOC 調查與政策 → 外部 AiSOC 真人核准 → 簽名授權 → PEP → nftables → 簽名收據。沒有真人核准，不執行封鎖；不是無人介入的自動決策。

**預設停用，尚未通過實機封包驗收，不應直接視為完整正式環境方案。** 目前以 mock 測試防火牆呼叫，沒有在開發容器修改核心規則。現有 Agent 與內部模型仍是參考實作；不要把合成模型的結果當成真實流量偵測成效。

管理來源 IP 與保護網段在本文件中以 `x.x.x.x`、`x.x.x.x/24` 隱藏。`/24` 會保護整個網段，其中所有位址都不能封鎖；若只保護單一 IPv4 位址，使用 `/32`。這些佔位符不是有效 IP，執行前必須換成實際位址，並同步修改規則中的保護範圍。本次僅遮蔽文件範例，不變更實際設定。

## 1. 管理員準備

在真正需要保護的 Ubuntu 主機安裝 nftables 與本專案，不是在 Codespaces 上保護遠端主機。Slips 輸出與 SOC 程序須能在該主機存取。

管理員需確認 `/usr/sbin/nft` 存在，並從 repo 根目錄執行以下指令。這些操作需要管理權限，請自行在終端機執行：

```bash
sudo apt-get update
sudo apt-get install nftables
sudo nft -c -f deploy/nftables-host.nft
sudo nft -f deploy/nftables-host.nft
sudo nft list table inet aisoc_guard
```

必須先以 SSH 以外的控制台確認復原管道。規則檔只建立 `inet aisoc_guard`，不含 `flush ruleset`，不清空既有 UFW、Docker 或其他防火牆規則。若同名 table 已存在，先檢查既有設定，不要反覆載入或刪除其他管理者的規則。

保護網段的 `return` 只略過 AISOC 的封鎖，不會繞過既有防火牆。封鎖規則在此 chain 內沒有 `ct state established accept` 例外，所以也會阻擋已建立連線的後續入站封包。

nft 子程序需要在**主機網路命名空間**有 `CAP_NET_ADMIN`。沒有權限時會拒絕並記錄錯誤，不會改用模擬成功。不要對整個 Python 執行檔授予 file capability，也不要把 Agent 以 root 執行。正式上線前應把特權執行器分離為受限制的服務；本版本尚未提供該隔離服務。

## 2. 設定允許的封鎖對象

以 [deploy/nftables-host.example.json](../deploy/nftables-host.example.json) 為範本，建立管理員控管的設定檔。初始 `enabled` 是 `false`，`targets` 是空的，不會觸發真實封鎖。

`targets` 必須明確列出 `(tenant, resource)` 與 IP 對照。例如測試網段的攻擊來源可使用：

```json
{
  "enabled": false,
  "max_ttl_s": 300,
  "protected_cidrs": ["x.x.x.x/24", "127.0.0.0/8", "::1/128"],
  "targets": [
    {"tenant": "tenant-a", "resource": "host:203.0.113.8", "ip": "203.0.113.8"}
  ]
}
```

`203.0.113.8` 是文件示範位址，需換成隔離測試來源。`resource` 必須與案件的 `host:<src_host>` 完全一致；不得由不可信的告警文字直接產生管理員對照表。請確認 Slips 的來源主機確實是要封鎖的遠端攻擊者；若來源是本機受感染設備，入站封鎖不等於阻止其外連。

限制如下：只有單一 IP，不接受網域或 CIDR 作為目標；保護網段、迴圈、link-local、多播、未指定位址、有限廣播與 IPv4-mapped IPv6 會被拒絕；TTL 為正整數且最多 900 秒；每個程序每分鐘最多 10 次封鎖嘗試；每個核心集合最多 1024 個項目。不會自動擴大租戶或目標範圍。

## 3. 外部真人核准與匯入

先依 [docs/INTEGRATION.md](INTEGRATION.md) 設定 AiSOC 的審批服務與真實分析師帳號，並將 `AISOC_TOKEN` 安全注入程序環境，不要把 token 放進設定檔、命令列或 Git。非 loopback 的 API 必須使用 HTTPS；HTTPS 憑證必須受信任。

在隔離測試主機完成權限與防火牆設定、確認保護範圍及對照表後，才由管理員將設定檔的 `enabled` 改為 `true`。**這是會真的封鎖流量的開關。**

```bash
python -m aisoc slips-ingest /absolute/path/to/alerts.json \
  --conn-log /absolute/path/to/zeek_files/conn.log \
  --tenant tenant-a \
  --nftables-config /absolute/path/to/admin-firewall.json \
  --approval-base-url https://soc.example.org \
  --out /absolute/path/to/new-audit-run
```

分析師在 AiSOC 審批收件匣檢查請求與 TTL，再批准或拒絕。預設示範審批不能啟用 nftables；外部核准仍由橋接器代簽，人的身分需與 AiSOC 的驗證及稽核紀錄交叉核對。不得在正式審批服務設定自動批准。

沒有 `--nftables-config` 時維持原有模擬執行器。提供設定檔但 `enabled: false` 時，封鎖仍被拒絕，不代表可用的防火牆預覽。真實模式維持 UTC 時鐘，不使用批次練習的時間推進。原有內部模型仍為合成訓練模型；不要加 `--internal-normality`。CLI 目前仍是單次匯入，不是即時監聽服務，也不保證每個告警都會提出封鎖請求。

每次執行使用新的稽核輸出目錄；不要重跑整份歷史告警來當成持續服務。封鎖失敗可在案件與收據中看到；CLI 的成功退出本身不代表每個動作成功。若 nft 執行逾時，核心可能已套用變更，需先查集合再決定是否重試。已存在的集合項目不會自動延長到期時間。

## 4. 驗證、解除與緊急停止

```bash
sudo nft list set inet aisoc_guard blocked_v4
sudo nft list set inet aisoc_guard blocked_v6
sudo nft list chain inet aisoc_guard protect_host
python -m aisoc verify /absolute/path/to/new-audit-run
```

查看項目的 timeout 與 drop counter。核心會在 TTL 到期後停止比對該項目，即使 Python 程序停止也不會留下永久封鎖。簽名收據證明的是執行器回報結果；封包是否真的被攔截，仍需從另一台隔離測試主機驗證。

管理員可提前解除單一測試位址：

```bash
sudo nft delete element inet aisoc_guard blocked_v4 '{ 203.0.113.8 }'
```

緊急停止時先停 SOC 程序，再刪除 **AISOC 專用 table**，不影響其他 table：

```bash
sudo nft delete table inet aisoc_guard
```

僅將設定檔改成停用不會撤銷現存封鎖，也不會更新正在執行中的程序。手動解除與緊急停止需另留操作稽核；本版本沒有自動簽署管理員的手動變更。

## 5. 正式上線前的必要驗收

- 在可拋棄的 Ubuntu 測試 VM 實測 IPv4、IPv6、真人批准與拒絕、TTL 到期、管理網段永不封鎖、手動解除及與 UFW/Docker 的共存。
- 將 Agent、授權服務、特權執行器與獨立見證隔離；限制特權服務只能修改指定集合，不能執行任意命令。
- 將鑰匙、nonce、冪等、撤銷與稽核狀態改為持久化儲存，補上重啟復原、跨程序速率限制及變更對賬。目前仍有記憶體狀態，不能視為完成這些要求。
- 使用可信的偵測、資產及威脅情報來源，建立誤判處理、值班與外部核准服務失效時的拒絕流程。
- 若需要持續處理 Slips 輸出，另外實作位移保存、去重、輪替及視窗彙整；不要使用固定重跑整檔的方式。