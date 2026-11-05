# Gluetun AutoSwitch

A plugin for [Dispatcharr](https://github.com/Dispatcharr/Dispatcharr).

Moves [Gluetun](https://github.com/qdm12/gluetun) to another VPN exit when a stream stays too slow, a provider keeps rejecting VOD, a login is refused, a live source shows Cloudflare's block page, or a scheduled speed test falls below your minimums.

## Install

Copy this repository's files into `/data/plugins/gluetun_autoswitch` in your Dispatcharr data folder, then enable **Gluetun AutoSwitch** on the Plugins page.

## Use

1. Dispatcharr must run through Gluetun, with Gluetun's control server reachable from Dispatcharr.
2. Set the Gluetun URL and your list of exits in the plugin settings.
3. Use **Check status** to confirm it can reach Gluetun, then turn on Auto switch.

## Notes

- Exit checks and the relay list use Mullvad's public endpoints, so it is built for Mullvad.
- VOD rejection detection reads the attempts logged by [VOD Failover](https://github.com/Brxdy22/Dispatcharr-VOD-Failover-Plugin).
- Run the tests with `python3 -m unittest test_plugin`.

## Credits

The refusal checks are ported from [Gluetun Rotate](https://github.com/PilaScat/gluetun-rotate) by Filippo Scatigna (MIT).

## Licence

MIT
