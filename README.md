<img src="logo.png" alt="" width="96">

# Gluetun AutoSwitch

A plugin for [Dispatcharr](https://github.com/Dispatcharr/Dispatcharr).

Moves [Gluetun](https://github.com/qdm12/gluetun) to another VPN exit when a stream stays too slow, a provider keeps rejecting VOD or refuses it on this exit, a login is refused, a live source shows Cloudflare's block page, or a scheduled speed test falls below your minimums.

Tested on Dispatcharr 0.33.0.

## Install

Copy this repository's files into `/data/plugins/gluetun_autoswitch` in your Dispatcharr data folder, then enable **Gluetun AutoSwitch** on the Plugins page.

Or download `gluetun_autoswitch-1.8.2.1.zip` from Releases and import it on the Plugins page. Use that zip rather than GitHub's source zip, because Dispatcharr names the plugin after the zip's top folder.

## Use

1. Dispatcharr must run through Gluetun, with Gluetun's control server reachable from Dispatcharr.
2. Give the plugin a Gluetun API key, as shown under [Gluetun API key](#gluetun-api-key).
3. To fill the country and city lists, mount Gluetun's `servers` folder read-only at `/gluetun-servers` in Dispatcharr.
4. Set the Gluetun URL and Gluetun API key, and pick your allowed countries and cities in the plugin settings. At least one Allowed country is required. After changing Allowed countries, save and refresh the page to update the city and server lists.
5. Use **Check status** to confirm it can reach Gluetun, then turn on Auto switch.

Exits a provider refused are listed under **Blocked exits** for 30 days, with the account that refused them, and are never picked while listed. Untick one and save to allow it again.

## Gluetun API key

The plugin reads and changes Gluetun's settings, so Gluetun needs a role that allows both. Add this to Gluetun's auth file, `/gluetun/auth/config.toml`, with your own long random key, then restart Gluetun:

```toml
[[roles]]
name = "dispatcharr"
routes = ["GET /v1/vpn/settings", "PUT /v1/vpn/settings"]
auth = "apikey"
apikey = "your-long-random-key"
```

Put the same key in **Gluetun API key** in the plugin settings.

Keep this key private: `GET /v1/vpn/settings` returns your VPN private key. For the same reason, don't allow these routes with `auth = "none"` or a default role of `none` unless only trusted containers can reach Gluetun's control server.

## Notes

- Exit checks and the relay list use Mullvad's public endpoints, so it is built for Mullvad.
- VOD rejection detection reads the attempts logged by [VOD Failover](https://github.com/Brxdy22/Dispatcharr-VOD-Failover-Plugin).
- After a switch it asks [M3U Failover](https://github.com/Brxdy22/Dispatcharr-M3U-Failover) 1.1.0 or later to close dead live connections, so streams reconnect sooner. Without it, streams wait for Dispatcharr's read timeout.
- Switching at the first refused VOD and the background VOD check need [M3U Failover](https://github.com/Brxdy22/Dispatcharr-M3U-Failover) 1.2 or later in front of the account. It finds the refusal and asks this plugin to move, on `127.0.0.1:9733`.
- Closing streams just before a switch needs [M3U Failover](https://github.com/Brxdy22/Dispatcharr-M3U-Failover) 1.2.1 or later. Update it first, because older versions pass that request on to your provider.
- Drag to reorder and search in the Allowed countries and cities lists come from [Clean Titles](https://github.com/Brxdy22/Dispatcharr-Clean-Titles-Plugin). Without it the lists still work.
- Run the tests with `python3 -m unittest test_plugin`.

## Release notes

See [Releases](https://github.com/Brxdy22/Dispatcharr-Gluetun-AutoSwitch-Plugin/releases/latest).

## Credits

The refusal checks are ported from [Gluetun Rotate](https://github.com/PilaScat/gluetun-rotate) by Filippo Scatigna (MIT). Its notice is in `THIRD_PARTY_NOTICES.txt`.

## Licence

MIT
