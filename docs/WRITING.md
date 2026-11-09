# Writing for Phylode

How Phylode's words should read. It covers the
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

One idea, one word. Once a page calls something by a name, it keeps that name.

| Write | Notes |
|---|---|
| blocklist, allowlist | |
| block / allow (a domain) | |
| device | |
| DNS server | |
| the Mac running Phylode | |
| upstream (resolver) | |
| encrypted DNS | |
| query | |
| query journal | The word the program, `phylode status` and the `journal_dir` setting use; not "query log" or "records" |
| weekly summary | |
| install / uninstall | |
| settings | |
| iCloud Private Relay | Apple's official name |
| rate limit | |

## Checking a change

Before you submit text, read it aloud once. Then check:

1. Does the first sentence tell the reader what they get?
2. Is every number current?
3. Would a person who has never used a terminal know what to do next?
