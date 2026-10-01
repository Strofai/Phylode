[English](README.md) · **繁體中文**

# Phylode

只要一台 Mac，Phylode 就能替整個網路上的裝置擋掉廣告、追蹤器和惡意網站——手機、筆電、電視、
遊戲主機、智慧音箱都在保護範圍內。它在 DNS 這一層運作，裝置本身什麼都不用裝。它也特別照顧
Apple 裝置：Apple 自家的服務一律暢通，iCloud 私密轉送也不受影響。

家裡、辦公室、工作室、學校都適用，只要有一台一直開著的 Mac。

## 會封鎖什麼

Phylode 使用 [HaGeZi](https://github.com/hagezi/dns-blocklists) 維護的兩份名單，這也是 HaGeZi
推薦的組合：

- **Multi PRO**：廣告、追蹤器、數據分析、App 與家電回傳的遙測資料，以及常見的詐騙、網路釣魚
  和惡意軟體。
- **威脅情資（Threat Intelligence Feeds，Medium 版）**：來自資安情資來源、已知散布惡意軟體、
  網路釣魚、詐騙和挖礦程式的網域。

兩份合併去除重複後約 100 萬個網域。Mac 每天 04:17 會下載這兩份名單，確認新版完整之後才換上，
並保留上一版。名單不在這個 repo 裡；HaGeZi 以 GPL-3.0 授權發布。

有幾個網域無論名單怎麼寫都不會封鎖：Apple 裝置用來偵測 Wi-Fi 登入頁面的 `captive.apple.com`，
以及 Apple 的推播通知和私密轉送服務。

需要的網站被擋住時，一行指令就能允許，幾秒內所有裝置都會生效：

```bash
phylode allow example.com
```

之後的版本會加入選擇名單嚴格程度的功能。

## 安裝

需要一台一直開著、執行 macOS 的 Mac，以及 Rust 工具鏈（[rustup](https://rustup.rs)）。Phylode 在
Apple 晶片的 macOS 26 和 27 上測試過；程式每次修改，CI 都會在一台全新的 Mac 上實際跑一遍安裝、
開啟、關閉和解除安裝。

```bash
git clone https://github.com/Strofai/Phylode.git
cd Phylode
cargo build --release
sudo ./target/release/phylode install
sudo phylode on
```

`install` 會設定好開機自動啟動的服務、下載名單，並等到服務開始回應才結束。`on` 讓這台 Mac 自己
改用 Phylode 查詢，最後會印出這台 Mac 在網路上的位址，下一步會用到。

如果 `/usr/local/bin` 這類需要 root 權限寫入的資料夾，一般帳號也改得動，安裝會停下來，什麼都不更動。

## 設定你的網路

要保護所有裝置，就要讓它們改向這台 Mac 查詢 DNS，而不是向路由器或網路業者查詢。

1. 在路由器的設定裡替這台 Mac 保留固定位址，讓它重新開機後位址不變。
2. 在路由器的 DHCP 設定裡，把 DNS 伺服器設成這個位址，並移除其他 DNS 伺服器。裝置下次重新連線
   時就會套用。
3. 如果網路有 IPv6，檢查路由器是否也會發送它自己的 IPv6 DNS 伺服器。裝置可能改用那些伺服器而
   略過過濾；請關閉這個選項，或同樣指向這台 Mac。詳見 [SECURITY.md](SECURITY.md)。

無法變更路由器設定時，也可以在每台裝置上分別設定 DNS 伺服器。常見路由器的逐步說明之後會補上。

Phylode 只回應家用與辦公室網路常用的私有位址範圍（10.x、172.16–31.x、192.168.x、100.64–127.x、
169.254.x，以及 IPv6 的 `fc00::/7` 和 `fe80::/10`），其他來源一律不回應。如果你的網路使用公用
位址，在 `/usr/local/etc/phylode.conf` 加一行 `serve_network`，再執行一次 `sudo phylode install`。

## 日常使用

| 指令 | 用途 |
|---|---|
| `phylode allow <網域>` | 允許一個網域，幾秒內所有裝置生效 |
| `phylode block <網域>` | 封鎖一個網域，幾秒內所有裝置生效 |
| `phylode report` | 本週摘要：封鎖了什麼、哪些裝置一直往外連、保護有沒有中斷過 |
| `phylode status` | 目前的設定與名單狀態 |
| `sudo phylode off` | 讓這台 Mac 的 DNS 改回自動取得 |
| `sudo phylode uninstall` | 關閉並移除服務；你的設定、名單和記錄會保留 |

`allow` 和 `block` 可以互相復原。變更名單需要管理者帳號。

### 遇到問題時

`phylode diagnostics` 會列出版本、狀態、數量和最近的服務事件，並移除網路位址和家目錄名稱，可以
直接貼到公開的[問題回報](https://github.com/Strofai/Phylode/issues/new/choose)。請不要貼查詢記錄或
`phylode status` 的輸出：裡面有網路上每個人的瀏覽記錄，以及你的設定。

## 運作原則

- **網路暢通優先。** 名單載入失敗時，Phylode 會先全部允許，並在每週摘要裡註明，不會讓整個網路
  斷線。
- **查詢一律加密送出。** Phylode 透過 DNS-over-TLS 或 DNS-over-HTTPS 向上游查詢，絕不退回未加密
  的 DNS（RFC 8310 Strict Privacy，也是 Apple 的預設做法）。所有上游伺服器都連不上時，改用快取
  裡最近的答案。
- **記錄只留在這台 Mac。** 查詢記錄在本機保留 10 天，每週摘要保留 12 週。不會傳到任何地方，
  也沒有遠端管理介面。
- **封鎖只短暫記住。** 裝置只會記住封鎖結果 2 秒，所以允許一個網域後馬上就能連上。
- **絕不回覆 REFUSED。** 這種回覆會讓裝置改用其他 DNS 伺服器，過濾就此失效。查詢次數過多的裝置，
  或不在服務範圍內的來源，一律收不到任何回應。
- **保護內部網路。** 指回區域網路內部的答案會整筆丟棄（防 DNS rebinding），只在內部網路存在的
  名稱不會送出去，藏在無害別名後面的追蹤器（CNAME 偽裝）也會被封鎖。
- **自己照顧自己。** 每 10 秒確認一次自己還在回應，沒有就重新啟動；連不上的上游伺服器會定期
  重試，恢復後自動排回。
- **用最小的權限執行。** 服務以自己專屬的帳號執行，不是 root；53 埠由 macOS 開好再交給它。

## 開發狀態

Phylode 已經能正常運作、每天都在用，但還沒有正式版本：`main` 就是目前的版本。程式約 11,000 行
Rust，直接依賴 9 個套件（`Cargo.lock` 共 181 個），測試 200 則。四個入口——裝置送來的封包、上游
回來的封包、封鎖名單的解析、設定檔的解析——由 GitHub Actions 工作流程做模糊測試。

接下來：由 Phylode 自己驗證收到的封包（目前由 DNS 函式庫負責）、macOS 沙箱設定、可選擇名單的
嚴格程度，以及路由器設定說明。

目前不在範圍內：讓所有流量都經過這台 Mac、離開這個網路時的保護、圖形介面，以及任何形式的
遙測。

## 使用的技術

以 Rust 在 macOS 上開發。DNS 協定層使用 [hickory-dns](https://github.com/hickory-dns/hickory-dns)；
其餘的過濾、快取、記錄、摘要、設定和指令，都是 Phylode 自己的程式。除了從 macOS 接手網路
socket 的兩個函式之外，整個專案禁止 `unsafe` 程式碼，多出一個就會有測試讓建置失敗。

想參與開發，請先讀 [CONTRIBUTING.md](CONTRIBUTING.md)，文字照 [docs/WRITING.md](docs/WRITING.md)
寫。回報資安問題請見 [SECURITY.md](SECURITY.md)。

## 名字的由來

取自希臘文 *phylax*（守護者）與 *ōidē*（歌）：守護者之歌。

## 授權

Phylode 可依你的選擇，採用 [MIT](LICENSE-MIT) 或 [Apache 2.0](LICENSE-APACHE) 授權，這是 Rust
社群的慣例。除非你另外明確聲明，你為了納入本專案而提交的貢獻，也以相同方式授權，不附加其他條款。
