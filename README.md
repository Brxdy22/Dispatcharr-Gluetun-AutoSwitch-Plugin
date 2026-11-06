<img src="logo.png" alt="" width="96">

# Gluetun AutoSwitch

A plugin for [Dispatcharr](https://github.com/Dispatcharr/Dispatcharr).

Moves [Gluetun](https://github.com/qdm12/gluetun) to another VPN exit when a stream stays too slow, a provider keeps rejecting VOD or refuses it on this exit, a login is refused, a live source shows Cloudflare's block page, or a scheduled speed test falls below your minimums.

Tested on Dispatcharr 0.33.0.

## Install

Copy this repository's files into `/data/plugins/gluetun_autoswitch` in your Dispatcharr data folder, then enable **Gluetun AutoSwitch** on the Plugins page.

Or download `gluetun_autoswitch-1.7.zip` from Releases and import it on the Plugins page. Use that zip rather than GitHub's source zip, because Dispatcharr names the plugin after the zip's top folder.

## Use

1. Dispatcharr must run through Gluetun, with Gluetun's control server reachable from Dispatcharr.
2. To fill the country and city lists, mount Gluetun's `servers` folder read-only at `/gluetun-servers` in Dispatcharr, and set `GLUETUN_SERVER_COUNTRIES` in Dispatcharr to the same value as Gluetun's `SERVER_COUNTRIES`.
3. Set the Gluetun URL and pick your allowed countries and cities in the plugin settings. After changing Allowed countries, save and press **Reload Plugin** to update the city lists.
4. Use **Check status** to confirm it can reach Gluetun, then turn on Auto switch.

Exits a provider refused are listed under **Blocked exits** for 30 days, with the account that refused them, and are never picked while listed. Untick one and save to allow it again.

## Notes

- Exit checks and the relay list use Mullvad's public endpoints, so it is built for Mullvad.
- VOD rejection detection reads the attempts logged by [VOD Failover](https://github.com/Brxdy22/Dispatcharr-VOD-Failover-Plugin).
- After a switch it asks [M3U Failover](https://github.com/Brxdy22/Dispatcharr-M3U-Failover) 1.1.0 or later to close dead live connections, so streams reconnect sooner. Without it, streams wait for Dispatcharr's read timeout.
- Switching at the first refused VOD and the background VOD check need [M3U Failover](https://github.com/Brxdy22/Dispatcharr-M3U-Failover) 1.2 or later in front of the account. It finds the refusal and asks this plugin to move, on `127.0.0.1:9733`.
- Run the tests with `python3 -m unittest test_plugin`.

## Release notes

See [Releases](https://github.com/Brxdy22/Dispatcharr-Gluetun-AutoSwitch-Plugin/releases/latest).

## Credits

The refusal checks are ported from [Gluetun Rotate](https://github.com/PilaScat/gluetun-rotate) by Filippo Scatigna (MIT).

## Licence

MIT
