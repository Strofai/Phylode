[English](README.md) · **繁體中文**

# Phylode

**一台 Mac，守護網路上的每台裝置。**

Phylode 為網路上的手機、電腦、電視和其他所有裝置，封鎖廣告、追蹤器和惡意網站。裝置上不必安裝
任何東西，Apple 服務和 iCloud 私密轉送也照常運作。

家裡、辦公室、工作室或學校都適用，只要有一台一直開著的 Mac。

## Phylode 會封鎖什麼

Phylode 使用 [HaGeZi](https://github.com/hagezi/dns-blocklists) 維護的兩份名單，也是 HaGeZi
推薦的組合：

- **Multi PRO**：封鎖廣告、追蹤器、數據分析、App 與家電回傳的遙測資料，以及常見的詐騙、網路釣魚
  和惡意軟體。
- **威脅情資（Threat Intelligence Feeds，Medium 版）**：封鎖資安情資來源中，已知散布惡意軟體、
  網路釣魚、詐騙和挖礦程式的網域。

兩份合併、去除重複後約涵蓋 100 萬個網域。你的 Mac 每天 04:17 會下載這兩份名單，確認新版完整之後
才換上，並保留上一版。名單不在這個 repo 裡；HaGeZi 以 GPL-3.0 授權發布。

想擋少一點或多一點，在 `/usr/local/etc/phylode.conf` 改 `protection`，再執行一次
`sudo phylode install`：

| 設定 | 第一份名單 | 適合 |
|---|---|---|
| `relaxed`（寬鬆） | Multi NORMAL | 家裡沒有人會解除誤擋的網站 |
| `standard`（標準，預設） | Multi PRO | 大多數的網路 |
| `strict`（嚴格） | Multi PRO++ | 有人會用 `phylode allow` 修正偶爾的誤擋 |

三種都搭配同一份威脅情資。HaGeZi 最嚴格的 Ultimate 不提供，因為 HaGeZi 自己說它會讓 App 無法正常
運作。

有些服務無論名單怎麼寫都不會被封鎖：Apple 裝置用來尋找 Wi-Fi 登入頁面的 `captive.apple.com`，
以及 Apple 的推播通知和私密轉送服務。

## 安裝 Phylode

開始之前，你需要：

- 一台一直開著的 Mac。Phylode 在 Apple 晶片的 macOS 26 和 27 上測試過。
- Rust 工具鏈，從 [rustup.rs](https://rustup.rs) 安裝。

接著在「終端機」中執行：

```bash
git clone https://github.com/Strofai/Phylode.git
cd Phylode
cargo build --release
sudo ./target/release/phylode install
sudo phylode on
```

`install` 會把 Phylode 設定成隨 Mac 啟動、下載名單，並在 Phylode 開始回應後才結束。`on` 讓你的
Mac 也改用 Phylode，最後顯示你的 Mac 在網路上的位址，下一步會用到。

如果 Phylode 要安裝進去的資料夾（例如 `/usr/local/bin`）一般帳號也改得動，安裝會停下來，不更動
任何東西。

程式的每一次修改，都會在 CI 的全新 Mac 上實際安裝 Phylode、開啟、關閉並解除安裝，確認都正常。

## 設定你的網路

要讓 Phylode 保護每台裝置，裝置就要改透過你的 Mac 查詢網站，而不是透過路由器或網路業者。

1. 在路由器的設定中，替你的 Mac 保留固定位址，讓它重新開機後位址不變。
2. 在路由器的 DHCP 設定中，把 DNS 伺服器設成你的 Mac 的位址，並移除其他 DNS 伺服器。裝置下次
   連線時就會套用新設定。
3. 如果你的網路使用 IPv6，檢查路由器是否也會發送它自己的 IPv6 DNS 伺服器。使用那些伺服器的裝置
   不會被過濾，因此請關閉這個選項，或指向你的 Mac——要用 Mac 的哪一個 IPv6 位址很重要，
   下面的說明會解釋。

[網路設定說明](docs/network-setup.zh-TW.md)會逐步帶你完成每個步驟、確認是否生效，以及無法變更
路由器設定時如何逐台設定裝置。

Phylode 只回應家用與辦公室網路常用的私有位址範圍（10.x、172.16–31.x、192.168.x、169.254.x，
以及 IPv6 的 `fc00::/7` 和 `fe80::/10`），不回應其他任何來源。100.64–127.x 只在這台 Mac 自己也
拿到這段位址時才回應（有些路由器會發這段位址）；Tailscale 這類 VPN 也用這段，VPN 上的其他裝置
預設不回應。如果你的網路使用公用位址，或想讓 VPN 上的裝置也使用 Phylode，在
`/usr/local/etc/phylode.conf` 加一行 `serve_network`，再執行一次 `sudo phylode install`。

## 允許或封鎖網站

需要的網站被封鎖時，允許它：

```bash
phylode allow example.com
```

要封鎖名單上沒有的網站：

```bash
phylode block example.com
```

變更會在幾秒內套用到每台裝置，兩個指令可以互相復原。變更名單需要管理者帳號。

## 查看 Phylode 的運作情形

- `phylode report` 顯示本週摘要：封鎖了什麼、哪些裝置一直連向同樣的伺服器，以及保護有沒有中斷過。
- `phylode status` 顯示目前的設定與名單狀態。

## 關閉或解除安裝 Phylode

- `sudo phylode off` 把你的 Mac 的 DNS 改回 `phylode on` 之前的設定。在你變更路由器設定之前，其他
  裝置會繼續使用 Phylode。
- `sudo phylode uninstall` 會關閉並移除 Phylode。你的設定、名單和記錄會留在 Mac 上。

## 遇到問題時

執行 `phylode diagnostics`。它會顯示版本、狀態、數量和最近的事件，並移除網路位址和家目錄名稱，
你可以直接貼到公開的[問題回報](https://github.com/Strofai/Phylode/issues/new/choose)。

請不要貼查詢記錄或 `phylode status` 的輸出。裡面有網路上每個人的瀏覽記錄，以及你的設定。

## Phylode 如何保護你的網路

- **網路保持暢通。** 名單更新無法使用時，Phylode 會繼續用上一版名單封鎖；完全沒有名單可載入時，
  才會先全部允許並在每週摘要中註明，不會讓整個網路斷線。
- **查詢加密後才送出。** Phylode 使用 DNS-over-TLS 或 DNS-over-HTTPS，絕不退回未加密的 DNS
  （RFC 8310 Strict Privacy，也是 Apple 的預設做法）。所有上游伺服器都無法連線時，改用最近的
  查詢結果回應。
- **記錄只留在你的 Mac。** 查詢記錄保留 10 天，每週摘要保留 12 週；每天的查詢記錄最多
  200 MB，不會把硬碟塞滿。這台 Mac 上的每個管理員帳號都讀得到，標準帳號讀不到。不會傳送到任何地方，
  也沒有遠端存取。
- **允許立即生效。** 裝置只會記住封鎖結果 2 秒。
- **不把裝置推向其他 DNS 伺服器。** Phylode 絕不回覆 REFUSED，因為這會讓裝置改用其他伺服器而不再
  被過濾。查詢次數過多的裝置，或不在服務範圍內的來源，完全收不到回應。
- **區域網路保持私密。** 指回你網路內部的回應會被捨棄（防 DNS rebinding），只存在於內部網路的
  名稱絕不會送出去，藏在無害別名後面的追蹤器（CNAME 偽裝，或指向別處的 HTTPS 記錄）也會被封鎖。
  「你的網路」指私人位址範圍、`serve_network` 寫的網段，以及你的 Mac 所在的 IPv6 網段，跟 Apple
  對區域網路的定義相同。如果你自己的網域名稱指向家裡的裝置（例如 NAS 的遠端連線名稱），每週摘要
  會列出它；在 `/usr/local/etc/phylode.conf` 加一行 `internal_domain` 即可。
- **自行維持運作。** Phylode 每 10 秒確認一次自己仍在回應，沒有回應就重新啟動。停止回應的上游
  伺服器會再次嘗試，恢復後自動重新使用。
- **以最少的權限執行。** Phylode 以自己專屬的帳號執行，不是 root；53 埠由 macOS 開啟後再交給它。

## 開發狀態

Phylode 已經能正常運作、每天都在使用，但還沒有正式版本：`main` 就是目前的版本。程式約 11,000 行
Rust，直接依賴 9 個套件（`Cargo.lock` 共 181 個），測試 261 則。四個入口——裝置送來的封包、上游
回來的封包、封鎖名單的解析、設定檔的解析——由 GitHub Actions 工作流程進行模糊測試。

接下來：由 Phylode 自己驗證收到的封包（目前由 DNS 函式庫負責）、macOS 沙箱設定，以及可選擇
名單的嚴格程度。

目前沒有計畫：讓所有流量都經過這台 Mac、離開這個網路時的保護、圖形介面，以及任何形式的遙測。

## 使用的技術

以 Rust 在 macOS 上開發。DNS 協定層使用 [hickory-dns](https://github.com/hickory-dns/hickory-dns)；
過濾、快取、記錄、摘要、設定和指令都是 Phylode 自己的程式。除了從 macOS 接手網路 socket 的兩個
函式之外，整個專案禁止 `unsafe` 程式碼，多出一個就會有測試讓建置失敗。

想參與開發，請先閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)；文字依照 [docs/WRITING.md](docs/WRITING.md)
撰寫。回報資安問題請見 [SECURITY.md](SECURITY.md)。

## 名字的由來

取自希臘文 *phylax*（守護者）與 *ōidē*（歌）：守護者之歌。

## 授權

Phylode 可依你的選擇，採用 [MIT](LICENSE-MIT) 或 [Apache 2.0](LICENSE-APACHE) 授權，這是 Rust
社群的慣例。除非你另外明確聲明，你為了納入本專案而提交的貢獻，也以相同方式授權，不附加其他條款。
