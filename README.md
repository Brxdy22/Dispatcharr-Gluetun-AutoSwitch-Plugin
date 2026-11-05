<img src="logo.png" alt="" width="96">

# Gluetun AutoSwitch

A plugin for [Dispatcharr](https://github.com/Dispatcharr/Dispatcharr).

Moves [Gluetun](https://github.com/qdm12/gluetun) to another VPN exit when a stream stays too slow, a provider keeps rejecting VOD, a login is refused, a live source shows Cloudflare's block page, or a scheduled speed test falls below your minimums.

Tested on Dispatcharr 0.33.0.

## Install

Copy this repository's files into `/data/plugins/gluetun_autoswitch` in your Dispatcharr data folder, then enable **Gluetun AutoSwitch** on the Plugins page.

Or download `gluetun_autoswitch-1.5.0.zip` from Releases and import it on the Plugins page. Use that zip rather than GitHub's source zip, because Dispatcharr names the plugin after the zip's top folder.

## Use

1. Dispatcharr must run through Gluetun, with Gluetun's control server reachable from Dispatcharr.
2. Set the Gluetun URL and your allowed countries and cities in the plugin settings.
3. Use **Check status** to confirm it can reach Gluetun, then turn on Auto switch.

## Notes

- Exit checks and the relay list use Mullvad's public endpoints, so it is built for Mullvad.
- VOD rejection detection reads the attempts logged by [VOD Failover](https://github.com/Brxdy22/Dispatcharr-VOD-Failover-Plugin).
- Run the tests with `python3 -m unittest test_plugin`.

## Changelog

### 1.5.0
- Added scheduled speed tests, which only run when nobody is watching. A failed test is retried, and two failures in a row move the exit once viewers have finished.
- A new exit is now tested shortly after a switch.
- VOD lengths now use file size to tell minutes from seconds.

### 1.4.1
- Fixed VOD speed checks for titles with a missing or wrong length.

### 1.4.0
- Added **Run speed test**.

### 1.3.0
- Added the checks from Gluetun Rotate: a regular login check, Cloudflare block page detection on live streams, and **Ask the provider**.
- Added **Change exit node**.

### 1.2.0
- Added allowed countries, so **Allowed cities** can be left empty.

### 1.0.0 and 1.1.0
- First versions: moves Gluetun to another exit when streams are too slow or a provider keeps rejecting VOD. The plugin was first called VPN Speed Guard.
- No detailed record of each version was kept.

Blocked countries and cities were added between 1.2.0 and 1.5.0, but the exact version wasn't recorded.

## Credits

The refusal checks are ported from [Gluetun Rotate](https://github.com/PilaScat/gluetun-rotate) by Filippo Scatigna (MIT).

## Licence

MIT
