**English** · [繁體中文](network-setup.zh-TW.md)

# Set up your network for Phylode

Phylode protects a device only when that device asks your Mac to look up websites. This
guide shows how to make every device on your network do that, by changing one setting on
your router. If you can't change your router's settings, you can
[set up each device](#set-up-a-device-by-hand) instead.

Router menus differ from brand to brand, so the steps below name the settings to look for
rather than exact menus. This guide hasn't yet been checked against every router; if a
step doesn't match yours, [open an issue](https://github.com/Strofai/Phylode/issues/new/choose).

## Before you begin

- Install Phylode and run `sudo phylode on`. The last lines it prints include your Mac's
  address on the network, such as `192.168.1.20`. You'll need it below.
- Keep the Mac on and awake while it serves the network. In System Settings, you can
  choose to prevent your Mac from sleeping automatically when the display is off.
- Plan for a power outage. On a Mac desktop computer, choose Apple menu > System
  Settings, click Energy, then turn on "Start up automatically after a power failure"
  ([Apple Support](https://support.apple.com/guide/mac-help/change-energy-settings-mchlp1168/mac)).
  If FileVault is turned on, the Mac stops at the login window after it restarts, and
  Phylode can't start until the disk is unlocked — until then, devices on the network can't
  look anything up. Log in once after an outage, or turn on Remote Login and unlock the
  disk over SSH from another device (macOS Tahoe 26 or later,
  [Apple Support](https://support.apple.com/en-us/124963)). Turning FileVault off removes
  the wait, but leaves everything on the disk unencrypted, including the query journal.
- Have your router's admin page or app ready. The address is often printed on the router,
  and is usually something like `192.168.1.1` or `192.168.0.1`.

## Step 1: Give your Mac a fixed address

If your Mac's address changes, devices can no longer reach Phylode. In your router's
settings, reserve the Mac's current address for it. Routers call this a **DHCP
reservation**, **address reservation**, **static lease** or **fixed IP**.

## Step 2: Make your router hand out your Mac's address

In your router's **DHCP** or **LAN** settings, find the **DNS server** fields. Enter your
Mac's address as the first DNS server and leave the others empty.

Don't add a public DNS server (such as your internet provider's, or 1.1.1.1) as a second
server "just in case". Devices don't treat a second server as a backup: they use either one
whenever they like, and anything looked up through the second server isn't filtered. If
your Mac becomes unreachable, Phylode can't help either way; what keeps you online is the
Mac staying on.

Devices pick up the new setting the next time they join the network. To apply it straight
away, turn Wi-Fi off and on again on a device.

## Step 3: Check IPv6

If your network uses IPv6, your router may also tell devices about its own IPv6 DNS
servers, separately from the setting in step 2. Apple devices use every DNS server they're
given, so those devices would sometimes skip Phylode. Look for **IPv6 DNS**, **RDNSS** or
**DHCPv6** settings and do one of the following:

- **Point them at your Mac.** If your Mac has an IPv6 address that starts with `fd`
  (shown in System Settings > Network > your network service > Details > TCP/IP), use
  that one. Phylode answers devices using those addresses out of the box.
- **Use your Mac's public IPv6 address** — one that starts with `2` or `3` — only after
  adding your network's IPv6 prefix to `/usr/local/etc/phylode.conf`, for example
  `serve_network = 2001:db8:1:2::/64`, and running `sudo phylode install` again. Without
  that line, Phylode doesn't answer devices that reach it at a public address, and they
  can't look anything up.
- **Turn off the IPv6 DNS servers** in the router, if it allows that.

## Step 4: Check that it's working

On another Mac on the same network, open Terminal and run:

```bash
dig iadsdk.apple.com +short
```

`0.0.0.0` means the lookup went through Phylode and was blocked. Any other address means
that Mac is still using another DNS server: turn its Wi-Fi off and on, and check step 2
and step 3.

After a day, `phylode report` on the Phylode Mac shows how many lookups it handled and
blocked across the network.

## Set up a device by hand

If you can't change your router's settings, set the DNS server on each device you want to
protect. Remove any other DNS servers listed there.

- **Mac:** Choose Apple menu > System Settings, click Network, click a network service,
  click Details, then click DNS. ([Apple Support](https://support.apple.com/guide/mac-help/change-dns-settings-on-mac-mh14127/mac))
- **iPhone or iPad:** Go to Settings > Wi-Fi, tap the info button next to your network,
  then tap Configure DNS and choose Manual. ([Apple Support](https://support.apple.com/guide/iphone/manage-wi-fi-settings-iphw5gjwl8k2/ios))
- **Other devices:** look for a DNS setting in the device's network or Wi-Fi settings.

Devices with no DNS setting, such as HomePod and many smart appliances, can only be
protected through the router.

On iPhone and iPad, the setting belongs to one Wi-Fi network. On a Mac, it belongs to the
network service, so a MacBook keeps asking Phylode on other Wi-Fi networks, where it can't
be reached — set it back to automatic before taking the Mac elsewhere.

## Different kinds of network

- **A home:** steps 1 to 4 on the router your internet provider gave you, or on your own
  router if it sits behind theirs. If the provider's router won't let you change the DNS
  server, put your own router behind it, or set devices by hand.
- **An office or a studio:** the person who manages the network makes the change once on
  the router or DHCP server, and the Mac running Phylode should be on a wired connection.
- **A school:** the same as an office. Phylode answers only private addresses unless you add
  `serve_network` lines, so a network that uses public addresses needs those first.

## If something goes wrong

- **Nothing loads on some devices:** they may be using a public IPv6 address for your Mac
  that Phylode isn't set up to answer (step 3), or your Mac may be asleep or off.
- **Nothing loads after a power outage:** if FileVault is on, the Mac is waiting at the
  login window. Log in, or unlock it over SSH ([Before you begin](#before-you-begin)).
- **Ads still appear on one device:** it may use its own encrypted DNS (some browsers and
  apps do), iCloud Private Relay, or DNS settings set by hand. Phylode can't filter those.
- **To undo everything,** clear the DNS server fields you changed in step 2 and step 3.
  Devices go back to the router's DNS the next time they join the network.

For anything else, run `phylode diagnostics` and include its output in a
[bug report](https://github.com/Strofai/Phylode/issues/new/choose).
