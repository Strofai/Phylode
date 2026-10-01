# Writing for Phylode

How Phylode's words should read, in English and in Traditional Chinese. It covers the
READMEs, the guides, command output, error messages, the weekly summary and the issue
forms. Code comments and commit messages follow `CLAUDE.md` instead.

The model is Apple's own writing: the Human Interface Guidelines chapter
[Writing](https://developer.apple.com/design/human-interface-guidelines/writing) and the
[Apple Style Guide](https://help.apple.com/applestyleguide/). When this page is silent,
do what Apple's documentation does.

## Voice

Calm, plain and exact. Phylode sits between every device on a network and the internet,
so its words should sound like something you can trust with that: no hype, no jokes, no
alarm.

- **Say what it does for the person, then how.** "Ads stop loading on every device on the
  network" before "it answers DNS queries".
- **Be specific.** Numbers, names and times beat adjectives: "updated every day at 04:17",
  not "updated regularly"; "about 1.06 million domains", not "a huge list".
- **Say how to fix it, not what went wrong.** "Run `sudo phylode install` again" is the
  heart of an error message; the cause comes second.
- **Talk to the reader as "you".** Avoid "we": it is never clear who that is. Avoid "I".
- **Leave out what does not help.** If a sentence would not change what someone does or
  understands, delete it.
- **No exclamation marks, no emoji, no "simply", "just", "easy" or "successfully".**
  What is easy for one reader is not for the next, and a finished task speaks for itself.

## Who it is for

Phylode protects **every device on a network** — phones, laptops, TVs, consoles, smart
speakers, appliances — from one Mac. Apple devices get particular care (their services
are never blocked, Private Relay is left alone), but nothing about it is limited to them.
Describe it that way: a home, an office, a studio or a school, never "your family".

## Names and capitalization

| Write | Not | Why |
|---|---|---|
| Phylode | phylode, PHYLODE | The product name, in prose |
| `phylode allow` | Phylode allow | Commands, file names and code are lowercase, in code formatting |
| Mac, iPhone, Apple TV, macOS | mac, Iphone, MacOS | Apple's own spelling |
| iCloud Private Relay | private relay | Apple's name for the feature |
| HaGeZi | hagezi, Hagezi | The list maintainer's own spelling |
| DNS, IPv4, IPv6, DHCP | dns, Ipv6 | Protocol names are all capitals |

Headings use sentence case in English and start with a verb when they describe a task:
"Set up your network", not "Network Setup". Use American spelling, as Apple does:
license, behavior, color.

## Terms

One idea, one word, in both languages. Translate the meaning, not the words: the Chinese
should read as if it had been written first.

| English | 繁體中文 | Notes |
|---|---|---|
| blocklist | 封鎖名單 | |
| allowlist | 允許名單 | |
| block / allow (a domain) | 封鎖／允許 | Not 擋／放行 in documentation |
| device | 裝置 | Apple's Traditional Chinese term; not 設備 |
| DNS server | DNS 伺服器 | Not 查號台 |
| the Mac running Phylode | 執行 Phylode 的 Mac | |
| upstream (resolver) | 上游伺服器 | |
| encrypted DNS | 加密 DNS | |
| query | 查詢 | |
| query journal | 查詢記錄 | The word the program, `phylode status` and the `journal_dir` setting use; not "query log" or "records". 記錄 as a noun, as Apple writes it |
| weekly summary | 每週摘要 | |
| router | 路由器 | |
| network | 網路 | |
| install / uninstall | 安裝／解除安裝 | |
| settings | 設定 | |
| iCloud Private Relay | iCloud 私密轉送 | Apple's official name |
| rate limit | 查詢次數上限 | |

## Traditional Chinese

- **Write for Taiwan.** Use the vocabulary Apple uses on its Taiwan site (裝置, 設定,
  記錄, 檔案, 資料夾). Address the reader as 你, as Apple Taiwan does.
- **Spacing.** Put one half-width space between Chinese and Latin letters or numbers:
  `在 Mac 上`, `約 106 萬個網域`. No space between Chinese and full-width punctuation.
- **Punctuation.** Full-width in Chinese sentences: ，。、：；？（）. Quote with 「」, and
  『』 inside them. Use an em dash pair（——）only when the second half qualifies the first.
- **Keep code as code.** Commands, file names and settings stay in English, in code
  formatting, with the Chinese outside it: 執行 `sudo phylode install`. Never translate
  a command or put Chinese inside the code formatting.
- **Not a translation.** Reorder sentences when Chinese reads better that way. If a sentence
  only makes sense in English, rewrite the idea.

## Checking a change

Before you submit text, read it aloud once in each language. Then check:

1. Does the first sentence tell the reader what they get?
2. Is every number current, and does it match the other language?
3. Do both READMEs say the same things, in the same order?
4. Would a person who has never used a terminal know what to do next?
