import unittest
import json
import os
import tempfile
from plugin import (BACKLOG_BYTES, DEFAULTS, LiveTracker, LogTail, RejectionTracker, VodTracker,
                    backlog_from_proc, held_back, last_pcr, next_exit, parse_codes, parse_exits,
                    parse_rejection, plan_move)
import plugin as P

def packet(pcr_seconds=None, pid=256):
    p = bytearray(b"\xff" * 188)
    p[0], p[1], p[2], p[3] = 0x47, pid >> 8, pid & 255, 0x10
    if pcr_seconds is not None:
        ticks = int(pcr_seconds * 27_000_000)
        base, ext = ticks // 300, ticks % 300
        p[3], p[4], p[5] = 0x30, 183, 0x10
        p[6:12] = bytes([(base >> 25) & 255, (base >> 17) & 255, (base >> 9) & 255, (base >> 1) & 255,
                         ((base & 1) << 7) | 0x7E | (ext >> 8), ext & 255])
    return bytes(p)

def proc(*rows):
    head = "sl local rem st tx:rx tr retr uid timeout inode\n"
    return head + "\n".join(f"0: 0100007F:1F90 {r} {s} {tx:08X}:{rx:08X} 0 0 0 0 0" for r, s, tx, rx in rows)

PUBLIC, LAN, LOOP = "04030201:0050", "0A000A0A:C000", "0100007F:1F90"  # 1.2.3.4, 10.10.0.10

class Pcr(unittest.TestCase):
    def test_reads_the_newest(self):
        self.assertAlmostEqual(last_pcr(packet(10) + packet() + packet(20) + packet())[1], 20, 3)
    def test_stays_on_one_pid(self):
        self.assertAlmostEqual(last_pcr(packet(10, 256) + packet(99, 300), 256)[1], 10, 3)
    def test_unaligned_chunk(self):
        self.assertAlmostEqual(last_pcr(b"\0\1\2" + packet(7) + packet() + packet())[1], 7, 3)
    def test_no_pcr_or_not_ts(self):
        self.assertIsNone(last_pcr(packet() * 3))
        self.assertIsNone(last_pcr(b"\0" * 2000))
        self.assertIsNone(last_pcr(b""))

class Live(unittest.TestCase):
    def feed(self, rate, seconds=120):
        t = LiveTracker()
        for s in range(0, seconds + 1, 10):
            t.add(1000 + s, 50 + s * rate, 90)
        return t
    def test_real_time(self):
        self.assertAlmostEqual(self.feed(1.0).speed(90), 1.0)
    def test_the_measured_bad_exit(self):
        self.assertAlmostEqual(self.feed(0.79).speed(90), 0.79)
    def test_needs_a_full_window(self):
        self.assertIsNone(self.feed(0.5, 80).speed(90))
    def test_stall_reads_as_zero(self):
        t = LiveTracker()
        for s in range(0, 121, 10):
            t.add(1000 + s, 50, 90)
        self.assertEqual(t.speed(90), 0)
    def test_pcr_reset_is_not_slowness(self):
        t = self.feed(1.0)
        t.add(1130, 5, 90)
        self.assertIsNone(t.speed(90))
    def test_pcr_jump_forward_is_not_speed(self):
        t = self.feed(1.0)
        t.add(1130, 9000, 90)
        self.assertIsNone(t.speed(90))

class Vod(unittest.TestCase):
    def feed(self, rate, backlog_at=None):
        t = VodTracker()
        for s in range(0, 121, 10):
            t.add(1000 + s, s * rate, s == backlog_at, 90)
        return t
    def test_keeping_up(self):
        self.assertAlmostEqual(self.feed(1300).speed(1300, 90), 1.0)
    def test_slow(self):
        self.assertAlmostEqual(self.feed(650).speed(1300, 90), 0.5)
    def test_full_buffer_is_ignored(self):
        self.assertIsNone(self.feed(650, backlog_at=110).speed(1300, 90))
    def test_old_backlog_ages_out(self):
        self.assertIsNotNone(self.feed(650, backlog_at=0).speed(1300, 90))
    def test_unknown_bitrate(self):
        self.assertIsNone(self.feed(650).speed(0, 90))
    def test_seek_restarts(self):
        t = self.feed(1300)
        t.add(1130, 5, False, 90)
        self.assertIsNone(t.speed(1300, 90))
    def test_real_samples(self):
        t = VodTracker()
        sent = 0
        for i, rate in enumerate([320, 640, 640, 640, 1439, 5277, 800, 2079, 2559, 5277]):
            sent += rate * 5
            t.add(1000 + i * 5, sent, False, 40)
        self.assertGreater(t.speed(1301, 40), 0.9)

class Backlog(unittest.TestCase):
    def test_provider_socket_unread(self):
        self.assertEqual(backlog_from_proc(proc((PUBLIC, "01", 0, 2454996))), 2454996)
    def test_loopback_unread(self):
        self.assertEqual(backlog_from_proc(proc((LOOP, "01", 0, 6151767))), 6151767)
    def test_client_unsent(self):
        self.assertEqual(backlog_from_proc(proc((LAN, "01", 2096264, 0))), 2096264)
    def test_unsent_to_provider_does_not_count(self):
        self.assertEqual(backlog_from_proc(proc((PUBLIC, "01", 900000, 0))), 0)
    def test_closed_by_provider_with_data_left(self):
        self.assertEqual(backlog_from_proc(proc((PUBLIC, "08", 0, BACKLOG_BYTES))), BACKLOG_BYTES)
    def test_listening_ignored(self):
        self.assertEqual(backlog_from_proc(proc((PUBLIC, "0A", 0, 999999))), 0)

class Exits(unittest.TestCase):
    A = ["ashburn va", "new york ny", "chicago il"]
    def test_parse(self):
        self.assertEqual(parse_exits(" Ashburn VA, ,Chicago IL "), ["ashburn va", "chicago il"])
    def test_cycles(self):
        self.assertEqual(next_exit(["ashburn va"], self.A), "new york ny")
        self.assertEqual(next_exit(["chicago il"], self.A), "ashburn va")
    def test_todays_live_selection(self):
        self.assertEqual(next_exit(["ashburn va", " chicago il"], self.A), "new york ny")
    def test_unknown_current_starts_at_the_top(self):
        self.assertEqual(next_exit([], self.A), "ashburn va")
        self.assertEqual(next_exit(["dallas tx"], self.A), "ashburn va")
    def test_nowhere_to_go(self):
        self.assertIsNone(next_exit(["ashburn va"], ["ashburn va"]))
        self.assertIsNone(next_exit(["ashburn va"], []))

class Limits(unittest.TestCase):
    def test_clear(self):
        self.assertEqual(held_back([], 10000, 300, 3), "")
    def test_cooldown(self):
        self.assertIn("cooling", held_back([9900], 10000, 300, 3))
    def test_hourly_limit(self):
        self.assertIn("hourly", held_back([7000, 8000, 9000], 10000, 300, 3))
    def test_old_switches_age_out(self):
        self.assertEqual(held_back([1000, 2000, 3000], 10000, 300, 3), "")

LOG = ("2026-11-04 18:16:31,528 -0600 INFO _dispatcharr_plugin_vod_failover.plugin [VOD-Failover] "
       "Marked {} on account {} as bad for 300s (episode): Streaming error: {}")
CODES = parse_codes(DEFAULTS["reject_codes"])

class Rejections(unittest.TestCase):
    def line(self, error, account="ProviderB", kind="account"):
        return LOG.format(kind, account, error)
    def test_codes(self):
        self.assertEqual(parse_codes("403, 520-522, x, 53"), {403, 520, 521, 522})
    def test_forbidden_counts(self):
        self.assertEqual(parse_rejection(self.line("403 Client Error: Forbidden for url"), CODES), ("ProviderB", 403))
    def test_cloudflare_counts(self):
        self.assertEqual(parse_rejection(self.line("522 Server Error: for url", "ProviderC"), CODES), ("ProviderC", 522))
    def test_account_name_with_spaces(self):
        self.assertEqual(parse_rejection(self.line("403 Client Error", "Big Provider 2"), CODES)[0], "Big Provider 2")
    def test_things_a_new_exit_cannot_fix(self):
        for error in ("404 Client Error: Not Found for url", "458 Client Error", "460 Client Error",
                      "429 Client Error", "511 Server Error", "503 Server Error: Service Unavailable",
                      "HTTPConnectionPool(host='127.0.0.1', port=8092): Read timed out."):
            self.assertIsNone(parse_rejection(self.line(error), CODES), error)
    def test_unrelated_lines(self):
        self.assertIsNone(parse_rejection("[VOD-Failover] EN - Show: playing from account ProviderB", CODES))
        self.assertIsNone(parse_rejection("ERROR vod_proxy 403 Client Error: Forbidden", CODES))
    def test_counts_per_account_inside_the_window(self):
        t = RejectionTracker()
        for moment, account in ((100, "A"), (200, "A"), (300, "B"), (950, "A")):
            t.add(account, moment)
        self.assertEqual(t.counts(1000, 900), {"A": 2, "B": 1})
    def test_old_rejections_age_out(self):
        t = RejectionTracker()
        t.add("A", 0)
        self.assertEqual(t.counts(1000, 900), {})
    def test_new_exit_restarts_the_count(self):
        t = RejectionTracker()
        t.add("A", 990)
        t.clear()
        self.assertEqual(t.counts(1000, 900), {})

class Tail(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "log")
        self.write("old\n")
        self.tail = LogTail(self.path)
        self.tail.read()
    def tearDown(self):
        self.dir.cleanup()
    def write(self, text, mode="a"):
        with open(self.path, mode) as handle:
            handle.write(text)
    def test_history_is_skipped(self):
        self.write("new\n")
        self.assertEqual(self.tail.read(), ["new"])
        self.assertEqual(self.tail.read(), [])
    def test_half_written_line_waits(self):
        self.write("par")
        self.assertEqual(self.tail.read(), [])
        self.write("tial\n")
        self.assertEqual(self.tail.read(), ["partial"])
    def test_rotation(self):
        os.rename(self.path, self.path + ".1")
        self.write("fresh\n", "w")
        self.assertEqual(self.tail.read(), ["fresh"])
    def test_truncation(self):
        self.write("x\n", "w")
        self.assertEqual(self.tail.read(), ["x"])
    def test_missing_file(self):
        self.assertEqual(LogTail(self.path + ".none").read(), [])

class AllOfUsa(unittest.TestCase):
    CITIES = parse_exits(DEFAULTS["exits"])
    def test_every_mullvad_us_city_once(self):
        self.assertEqual(len(self.CITIES), 21)
        self.assertEqual(len(set(self.CITIES)), 21)
    def test_manifest_matches(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "plugin.json")) as handle:
            fields = {f["id"]: f.get("default") for f in json.load(handle)["fields"]}
        for key, value in DEFAULTS.items():
            self.assertEqual(fields[key], value, key)
    def test_first_move_from_todays_selection_stays_close(self):
        self.assertEqual(next_exit(["ashburn va", " chicago il"], self.CITIES), "washington dc")
    def test_walks_the_whole_list_and_wraps(self):
        current, visited = ["ashburn va"], []
        for _ in self.CITIES:
            current = [next_exit(current, self.CITIES)]
            visited.append(current[0])
        self.assertEqual(sorted(visited), sorted(self.CITIES))
        self.assertEqual(visited[-1], "ashburn va")

class Capitals(unittest.TestCase):
    A = ["ashburn va", "new york ny"]
    def test_any_capitalization_means_the_same_exit(self):
        for text in ("Ashburn VA, New York NY", "ashburn va, new york ny", "ASHBURN VA,NEW YORK NY"):
            self.assertEqual(parse_exits(text), self.A)
    def test_gluetun_capitals_still_match_the_list(self):
        self.assertEqual(next_exit(["Ashburn VA"], self.A), "new york ny")
    def test_country_in_other_capitals_still_forces_a_reconnect(self):
        for current in (["USA"], ["usa"], ["Usa"]):
            sent = plan_move(current, [], parse_exits("USA"), [])[0]
            self.assertNotEqual(sent, current)
            self.assertEqual(sent[0].lower(), "usa")

class Plans(unittest.TestCase):
    def test_cities_cycle(self):
        self.assertEqual(plan_move(["usa"], ["ashburn va"], [], ["ashburn va", "boston ma"]),
                         ([], ["boston ma"], "boston ma"))
    def test_cities_clear_the_country_filter_so_no_filter_can_match_nothing(self):
        self.assertEqual(plan_move(["sweden"], [], ["sweden"], ["toronto"])[:2], ([], ["toronto"]))
    def test_only_city_already_in_use(self):
        self.assertIsNone(plan_move(["usa"], ["boston ma"], ["usa"], ["boston ma"]))
    def test_country_only_clears_cities_with_an_empty_list(self):
        plan = plan_move(["usa"], ["ashburn va", " chicago il"], ["usa"], [])
        self.assertEqual(plan[1], [])
        self.assertIsNotNone(plan[1])
    def test_same_country_always_differs_from_what_gluetun_has(self):
        current = ["usa"]
        for _ in range(4):
            sent = plan_move(current, [], ["usa"], [])[0]
            self.assertNotEqual(sent, current)
            self.assertEqual(sent[0].lower(), "usa")
            current = sent
    def test_several_countries_cycle(self):
        self.assertEqual(plan_move(["usa"], [], ["usa", "canada"], [])[0], ["canada"])
        self.assertEqual(plan_move(["canada"], [], ["usa", "canada"], [])[0], ["usa"])
    def test_several_countries_selected_at_once(self):
        self.assertEqual(plan_move(["usa", "canada"], [], ["usa", "canada"], [])[0], ["usa"])
    def test_nothing_configured(self):
        self.assertIsNone(plan_move(["usa"], [], [], []))

RELAYS = {"canada": ["toronto", "vancouver", "montreal"], "usa": ["boston ma", "dallas tx"], "sweden": ["stockholm"]}

class Blocks(unittest.TestCase):
    def test_empty_boxes_change_nothing(self):
        self.assertEqual(plan_move(["usa"], ["ashburn va"], ["usa"], ["ashburn va", "boston ma"], [], []),
                         ([], ["boston ma"], "boston ma"))
        self.assertEqual(plan_move(["usa"], [], ["usa"], [], [], [])[0], ["USA"])
    def test_blocked_city_is_skipped_in_the_list(self):
        self.assertEqual(plan_move([], ["a"], [], ["a", "b", "c"], [], ["b"])[2], "c")
    def test_blocked_country_removes_its_cities(self):
        self.assertEqual(plan_move([], ["toronto"], [], ["toronto", "dallas tx", "stockholm"], ["usa"], [], RELAYS)[2], "stockholm")
    def test_blocked_country_is_skipped_in_country_mode(self):
        self.assertEqual(plan_move(["usa"], [], ["usa", "canada", "sweden"], [], ["canada"], [])[0], ["sweden"])
    def test_everything_blocked_never_moves(self):
        self.assertIsNone(plan_move(["canada"], [], ["usa"], [], ["usa"], []))
        self.assertIsNone(plan_move([], [], [], ["a"], [], ["a"]))
    def test_a_fully_blocked_city_list_does_not_fall_back_to_countries(self):
        self.assertIsNone(plan_move([], [], ["usa"], ["a"], [], ["a"]))
    def test_country_mode_never_picks_a_blocked_city(self):
        for _ in range(50):
            plan = plan_move(["canada"], [], ["canada"], [], [], ["toronto"], RELAYS)
            self.assertEqual(plan[0], [])
            self.assertIn(plan[2], ("vancouver", "montreal"))
    def test_country_mode_with_blocks_leaves_the_current_city(self):
        self.assertEqual(plan_move([], ["vancouver"], ["canada"], [], [], ["toronto"], RELAYS)[2], "montreal")
    def test_country_mode_with_blocks_still_cycles_countries(self):
        pick = lambda names: names[0]
        self.assertEqual(plan_move([], ["vancouver"], ["canada", "usa"], [], [], ["toronto"], RELAYS, pick)[2], "boston ma")
        self.assertEqual(plan_move([], ["boston ma"], ["canada", "usa"], [], [], ["toronto"], RELAYS, pick)[2], "montreal")
    def test_every_city_of_the_country_blocked(self):
        self.assertIsNone(plan_move(["sweden"], [], ["sweden"], [], [], ["stockholm"], RELAYS))
    def test_when_the_city_list_is_needed(self):
        self.assertFalse(P.needs_relays(["usa"], ["a"], [], []))
        self.assertFalse(P.needs_relays(["usa"], [], ["canada"], []))
        self.assertFalse(P.needs_relays(["usa"], ["a"], [], ["b"]))
        self.assertTrue(P.needs_relays([], ["a"], ["usa"], []))
        self.assertTrue(P.needs_relays(["usa"], [], [], ["dallas tx"]))
    def test_relay_names_follow_gluetun(self):
        rows = [{"country_name": "USA", "city_name": "Ashburn, VA"}, {"country_name": "USA", "city_name": "Ashburn, VA"},
                {"country_name": "USA", "city_name": "Boston, MA", "active": False}]
        self.assertEqual(P.parse_relays(rows), {"usa": ["ashburn va"]})

class Routing(unittest.TestCase):
    def test_nothing(self):
        self.assertEqual(P.route([], [], True), ("", []))
    def test_slow_and_rejected_never_wait(self):
        self.assertEqual(P.route(["slow"], [], True), ("act", ["slow"]))
    def test_refusals_wait_for_viewers(self):
        self.assertEqual(P.route([], ["refused"], True), ("hold", ["refused"]))
    def test_refusals_go_when_nobody_watches(self):
        self.assertEqual(P.route([], ["refused"], False), ("act", ["refused"]))
    def test_urgent_carries_the_rest(self):
        self.assertEqual(P.route(["slow"], ["refused"], True), ("act", ["slow", "refused"]))

class Forbidden(unittest.TestCase):
    URL = "http://127.0.0.1:8090/live/user/pass/102119.ts"
    def test_proxied_403(self):
        self.assertEqual(P.refused_urls([f"ERROR live_proxy.http_streamer HTTP 403 from {self.URL}"]), [self.URL])
    def test_repeats_collapse(self):
        self.assertEqual(len(P.refused_urls([f"HTTP 403 from {self.URL}"] * 3)), 1)
    def test_stream_process_error_uses_the_attempt_url(self):
        c = "f0680adf-3418-4d8e-82af-3fcfb28c9356"
        lines = [f"Connection attempt 1/3 for URL: {self.URL} for channel {c}",
                 f"Stream process error for channel {c}: boom HTTP Error 403 Forbidden"]
        self.assertEqual(P.refused_urls(lines), [self.URL])
    def test_feed_hides_credentials(self):
        self.assertEqual(P.feed_of(self.URL), "102119.ts")

class FakeStatus:
    def __init__(self, answers):
        self.answers, self.calls = answers, []
    def __call__(self, url, agent):
        self.calls.append(url)
        return self.answers(url)

class Watchers(unittest.TestCase):
    URL = "http://127.0.0.1:8090/live/user/pass/1.ts"
    ACC = [P.Account("ProviderA", "http://127.0.0.1:8090", "user", "pass", "ua")]
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.s.accounts, self.s.accounts_at = self.ACC, 1e12
        self.real, self.proxy = P.fetch_status, P.read_proxy_status
        P.read_proxy_status = lambda base: {"preferred": "real.example:826 (1.2.3.4)", "upstreams": ["real.example:826"]}
    def tearDown(self):
        P.fetch_status, P.read_proxy_status = self.real, self.proxy
        self.dir.cleanup()
    def use(self, answers):
        P.fetch_status = FakeStatus(answers)
        return P.fetch_status
    def journal(self):
        return "\n".join(self.s.store.recent(50))
    def rounds(self, n, start=0):
        out = []
        for i in range(n):
            out = self.s.probe_accounts(DEFAULTS, start + i * 301)
        return out
    def test_two_refused_rounds_are_a_cause(self):
        self.use(lambda u: (522, b""))
        self.assertEqual(self.rounds(1, 1000), [])
        self.assertTrue(self.rounds(1, 2000))
    def test_a_good_round_resets(self):
        self.use(lambda u: (522, b""))
        self.rounds(1, 1000)
        self.use(lambda u: (200, b""))
        self.rounds(1, 2000)
        self.assertEqual(self.s.refused_streak, 0)
        self.assertIn("accepted", self.journal())
    def test_answers_a_new_exit_cannot_fix_are_not_refusals(self):
        for code in (403, 404, 458, 503, None):
            self.use(lambda u, c=code: (c, b""))
            self.rounds(3, 1000)
            self.assertEqual(self.s.refused_streak, 0, code)
            self.s.probe_at = 0
    def test_probes_are_spaced_out(self):
        f = self.use(lambda u: (200, b""))
        self.s.probe_accounts(DEFAULTS, 1000)
        self.s.probe_accounts(DEFAULTS, 1010)
        self.assertEqual(len(f.calls), 1)
    def test_zero_minutes_turns_it_off(self):
        f = self.use(lambda u: (522, b""))
        self.s.probe_accounts({**DEFAULTS, "probe_minutes": 0}, 1000)
        self.assertEqual(f.calls, [])
    def test_a_paused_proxy_keeps_the_count(self):
        self.use(lambda u: (522, b""))
        self.rounds(1, 1000)
        for code in (503, None):
            self.use(lambda u, c=code: (c, b""))
            self.rounds(1, 2000)
            self.assertEqual(self.s.refused_streak, 1, code)
            self.s.probe_at = 0
    def test_block_page_is_a_cause_in_one_round(self):
        self.use(lambda u: (403, b"<title>Website Access Blocked</title>"))
        self.assertEqual(self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000), ["ProviderA blocked 1.ts"])
    def test_plain_403_is_only_recorded(self):
        self.use(lambda u: (403, b"Forbidden"))
        self.assertEqual(self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000), [])
        self.assertIn("forbidden", self.journal())
    def test_foreign_urls_are_never_requested(self):
        f = self.use(lambda u: (403, b"Website Access Blocked"))
        self.s.check_blocked(["HTTP 403 from http://evil.example/x.ts"], 1000)
        self.assertEqual(f.calls, [])
    def test_recheck_is_rate_limited_and_clears(self):
        f = self.use(lambda u: (403, b"Website Access Blocked"))
        self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000)
        count = len(f.calls)
        self.s.check_blocked([], 1010)
        self.assertEqual(len(f.calls), count)
        self.use(lambda u: (200, b""))
        self.assertEqual(self.s.check_blocked([], 1200), [])
        self.assertIn("unblocked", self.journal())
    def test_recheck_goes_around_the_proxy(self):
        f = self.use(lambda u: (403, b"Forbidden"))
        self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000)
        self.assertEqual(f.calls, ["http://real.example:826/live/user/pass/1.ts"])
    def test_never_through_the_proxy_when_the_upstream_is_unknown(self):
        P.read_proxy_status = lambda base: None
        f = self.use(lambda u: (403, b"Website Access Blocked"))
        self.assertEqual(self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000), [])
        self.assertEqual(f.calls, [])
    def test_one_bad_channel_is_checked_once_per_half_hour(self):
        f = self.use(lambda u: (403, b"Forbidden"))
        for t in range(1000, 2700, 100):
            self.s.check_blocked([f"HTTP 403 from {self.URL}"], t)
        self.assertEqual(len(f.calls), 1)
        self.s.check_blocked([f"HTTP 403 from {self.URL}"], 2900)
        self.assertEqual(len(f.calls), 2)
    def test_credentials_stay_out_of_the_journal(self):
        self.use(lambda u: (403, b"Website Access Blocked"))
        self.s.check_blocked([f"HTTP 403 from {self.URL}"], 1000)
        self.assertNotIn("pass", self.journal())

class Direct(unittest.TestCase):
    URL = "http://127.0.0.1:8090/live/u/p/9.ts"
    def test_uses_the_preferred_upstream_without_its_ip(self):
        self.assertEqual(P.direct_url(self.URL, {"preferred": "a.tv:826 (1.2.3.4)", "upstreams": ["b.tv"]}),
                         "http://a.tv:826/live/u/p/9.ts")
    def test_falls_back_to_the_first_upstream(self):
        self.assertEqual(P.direct_url(self.URL, {"preferred": None, "upstreams": ["b.tv"]}), "http://b.tv/live/u/p/9.ts")
    def test_nothing_known(self):
        self.assertIsNone(P.direct_url(self.URL, {"preferred": None, "upstreams": []}))
    def test_a_real_host_is_used_as_it_is(self):
        self.assertEqual(P.check_target("http://x.tv/live/u/p/9.ts"), "http://x.tv/live/u/p/9.ts")

class Clock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now

class Speed(unittest.TestCase):
    def test_warm_up_is_left_out(self):
        c = Clock()
        m = P.RateMeter(c)
        for _ in range(10):
            c.now += 0.1
            m.add(1)  # slow start
        for _ in range(10):
            c.now += 0.1
            m.add(1_250_000)
        self.assertAlmostEqual(m.mbps(), 100, 0)
    def test_too_short_to_measure(self):
        c = Clock()
        m = P.RateMeter(c)
        c.now += 0.5
        m.add(999)
        self.assertIsNone(m.mbps())
    def test_nothing_received(self):
        self.assertIsNone(P.RateMeter(Clock()).mbps())
    def test_upload_leaves_out_the_slow_first_round(self):
        self.assertAlmostEqual(P.upload_mbps([(10_000_000, 4), (10_000_000, 1), (10_000_000, 1)]), 80)
    def test_upload_with_one_round_uses_it(self):
        self.assertAlmostEqual(P.upload_mbps([(10_000_000, 4)]), 20)
    def test_cloudflare_size_limit_is_respected(self):
        self.assertLess(P.SPEED_DOWN_BYTES, 100_000_000)
    def test_proxied_account_pings_the_real_provider(self):
        status = {"preferred": "provider.example:826 (203.0.113.10)", "upstreams": ["x"]}
        self.assertEqual(P.provider_target("http://127.0.0.1:8090", status), ("provider.example", 826))
    def test_default_port(self):
        self.assertEqual(P.provider_target("http://127.0.0.1:8091", {"upstreams": ["a.tv"]}), ("a.tv", 80))
    def test_direct_account(self):
        self.assertEqual(P.provider_target("https://a.tv", None), ("a.tv", 443))
        self.assertEqual(P.provider_target("http://a.tv:8080", None), ("a.tv", 8080))
    def test_proxy_unknown(self):
        self.assertIsNone(P.provider_target("http://127.0.0.1:8090", None))
    def test_full_result(self):
        text = P.format_speed({"when": "Nov 5, 1:34 AM", "city": "Ashburn, VA", "ip": "1.2.3.4",
                               "download": 182.4, "upload": 95.1, "ping": 21.6,
                               "providers": {"ProviderC": 31.2, "ProviderA": 66.0}, "streams": 0})
        self.assertEqual(text, "Nov 5, 1:34 AM - Ashburn, VA (1.2.3.4)\nDownload 182 Mbps - Upload 95 Mbps - Ping 22 ms\nProviders: ProviderA 66 ms, ProviderC 31 ms")
    def test_failures_and_viewers_are_shown(self):
        text = P.format_speed({"when": "now", "download": None, "upload": None, "ping": None,
                               "providers": {"ProviderC": None}, "streams": 2})
        self.assertIn("unknown exit", text)
        self.assertIn("Download failed", text)
        self.assertIn("ProviderC failed", text)
        self.assertIn("2 stream(s) were playing", text)

class SpeedSync(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.real = P.publish_speed
        self.sent = []
        P.publish_speed = self.sent.append
    def tearDown(self):
        P.publish_speed = self.real
        self.dir.cleanup()
    def test_no_result_yet_writes_nothing(self):
        self.s.sync_speed({})
        self.assertEqual(self.sent, [])
    def test_matching_box_writes_nothing(self):
        self.s.store.set_speed({"text": "new"})
        self.s.sync_speed({P.SPEED_FIELD: "new"})
        self.assertEqual(self.sent, [])
    def test_stale_or_edited_box_is_corrected(self):
        self.s.store.set_speed({"text": "new"})
        self.s.sync_speed({P.SPEED_FIELD: "old"})
        self.assertEqual(self.sent, ["new"])

class MovieLength(unittest.TestCase):
    def never(self):
        raise AssertionError("asked the provider without needing to")
    def test_real_stored_length_needs_no_provider_call(self):
        self.assertEqual(P.movie_seconds(5400, self.never), (5400, "stored"))
    def test_stored_minutes_are_read_as_minutes(self):
        self.assertEqual(P.movie_seconds(198, self.never), (11880, "stored"))  # Avatar: Fire and Ash
        self.assertEqual(P.movie_seconds(140, self.never), (8400, "stored"))   # #Clout
    def test_no_stored_length_asks_the_provider(self):
        self.assertEqual(P.movie_seconds(None, lambda: 6120), (6120, "provider"))
    def test_provider_failure_assumes_the_safe_length(self):
        self.assertEqual(P.movie_seconds(None, lambda: 0), (10800, "assumed"))
    def test_placeholder_answer_assumes_the_safe_length(self):
        self.assertEqual(P.movie_seconds(None, lambda: 1200), (10800, "assumed"))  # 00:20:00
    def test_real_provider_answers(self):
        for info, seconds in (({"duration_secs": 6826, "duration": "01:53:46"}, 6826),
                              ({"duration_secs": "108", "duration": "01:48:13"}, 6493),
                              ({"duration_secs": "0", "duration": "00:20:00"}, 1200),
                              ({"duration_secs": "6180", "duration": "01:43:00"}, 6180)):
            self.assertEqual(P.provider_seconds(info), seconds)
    def test_no_hms_falls_back_to_seconds(self):
        self.assertEqual(P.provider_seconds({"duration_secs": "7680"}), 7680)
        self.assertEqual(P.provider_seconds({"duration": "unknown", "duration_secs": 90}), 5400)
        self.assertEqual(P.provider_seconds({}), 0)
    def test_junk_values(self):
        for value in (None, "", "abc", 0, -5):
            self.assertEqual(P.clean_seconds(value), 0)
    def test_healthy_long_movie_never_reads_slow(self):
        size = 8_000_000_000
        for real in (5400, 7200, 10800):
            rate = size / real
            self.assertGreaterEqual(rate / (size / P.ASSUMED_MOVIE_SECONDS), 1)

GOOD = {"download": 180.0, "upload": 200.0, "ping": 60.0, "providers": {"ProviderA": 62.0, "ProviderC": 138.0}}

class LengthBySize(unittest.TestCase):
    GB = 1_000_000_000
    def test_real_short_episode_stays_in_seconds(self):
        self.assertEqual(P.clean_seconds(561, 300_000_000), 561)
    def test_minutes_in_the_seconds_field(self):
        self.assertEqual(P.clean_seconds(198, 4 * self.GB), 11880)
        self.assertEqual(P.clean_seconds(45, self.GB), 2700)
    def test_unknown_size_reads_as_minutes(self):
        self.assertEqual(P.clean_seconds(198), 11880)
    def test_implausibly_low_bitrate_reads_as_minutes(self):
        self.assertEqual(P.clean_seconds(500, 1_000_000), 30000)
    def test_long_values_are_left_alone(self):
        self.assertEqual(P.clean_seconds(5400, 4 * self.GB), 5400)
    def test_a_short_real_looking_movie_still_goes_to_the_provider(self):
        self.assertEqual(P.movie_seconds(300, lambda: 6000, 300_000_000), (6000, "provider"))
    def test_avatar_with_its_size(self):
        self.assertEqual(P.movie_seconds(198, lambda: 1 / 0, 4 * self.GB), (11880, "stored"))

class Judge(unittest.TestCase):
    def check(self, usual=None, **result):
        return P.judge({**GOOD, **result}, DEFAULTS, usual or {"ProviderA": 62.0, "ProviderC": 138.0})
    def test_tonights_results_are_healthy(self):
        self.assertEqual(self.check(), [])
    def test_low_download(self):
        self.assertEqual(self.check(download=20.0), ["download 20 Mbps (minimum 30)"])
    def test_upload_is_off_by_default(self):
        self.assertEqual(self.check(upload=1.0), [])
    def test_upload_can_be_turned_on(self):
        self.assertTrue(P.judge({**GOOD, "upload": 1.0}, {**DEFAULTS, "min_upload": 5}, {}))
    def test_high_ping(self):
        self.assertEqual(self.check(ping=200.0), ["ping 200 ms (limit 150)"])
    def test_the_bad_dallas_exit_is_caught(self):
        self.assertEqual(self.check(providers={"ProviderA": 140.0, "ProviderC": 138.0}), ["ProviderA ping 140 ms (usually 62)"])
    def test_a_far_provider_is_not_a_problem(self):
        self.assertEqual(self.check(providers={"ProviderC": 140.0}), [])
    def test_no_history_means_no_provider_verdict(self):
        self.assertEqual(P.judge({**GOOD, "providers": {"ProviderA": 900.0}}, DEFAULTS, {}), [])
    def test_failed_measurements_are_no_verdict(self):
        self.assertEqual(self.check(download=None, ping=None, providers={"ProviderA": None}), [])
    def test_zero_turns_each_check_off(self):
        off = {**DEFAULTS, "min_download": 0, "max_ping": 0, "provider_ping_factor": 0}
        self.assertEqual(P.judge({**GOOD, "download": 1.0, "ping": 999.0, "providers": {"ProviderA": 999.0}}, off, {"ProviderA": 1.0}), [])
    def test_verdict_line(self):
        base = {"when": "now"}
        self.assertIn("Health: good", P.format_speed({**base, "problems": []}))
        self.assertIn("Below minimum: a; b", P.format_speed({**base, "problems": ["a", "b"]}))

class Usual(unittest.TestCase):
    def test_median_of_healthy_tests(self):
        rows = [{"event": "speed_test", "providers": {"ProviderA": v}} for v in (60.0, 63.0, 90.0)]
        self.assertEqual(P.usual_pings(rows), {"ProviderA": 63.0})
    def test_bad_tests_cannot_raise_the_limit(self):
        rows = [{"event": "speed_test", "providers": {"ProviderA": 60.0}}, {"event": "speed_test", "providers": {"ProviderA": 62.0}},
                {"event": "speed_test", "problems": ["x"], "providers": {"ProviderA": 400.0}}]
        self.assertEqual(P.usual_pings(rows), {"ProviderA": 62.0})
    def test_one_sample_is_not_enough(self):
        self.assertEqual(P.usual_pings([{"event": "speed_test", "providers": {"ProviderA": 60.0}}]), {})
    def test_tonights_journal_entries_count(self):
        rows = [{"event": "speed_test", "providers": {"ProviderA": 63.1}}, {"event": "speed_test", "providers": {"ProviderA": 61.3}}]
        self.assertIn("ProviderA", P.usual_pings(rows))
    def test_other_events_and_failed_pings_are_ignored(self):
        self.assertEqual(P.usual_pings([{"event": "switched"}, {"event": "speed_test", "providers": {"ProviderA": None}}]), {})

class Schedule(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.s.accounts, self.s.accounts_at = [], 1e12
        self.real = P.run_speed_test
        self.results = []
        self.runs = 0
        P.run_speed_test = self.fake
    def tearDown(self):
        P.run_speed_test = self.real
        self.dir.cleanup()
    def fake(self, store, accounts, settings):
        self.runs += 1
        return self.results.pop(0) if self.results else {"unclear": False, "problems": []}
    def bad(self):
        return {"unclear": False, "problems": ["download 5 Mbps (minimum 30)"]}
    def test_never_runs_while_someone_watches(self):
        self.s.speed_health(DEFAULTS, 1e9, True)
        self.assertEqual(self.runs, 0)
    def test_overdue_test_runs_once_viewers_leave(self):
        self.s.speed_health(DEFAULTS, 1e9, True)
        self.s.speed_health(DEFAULTS, 1e9 + 10, False)
        self.assertEqual(self.runs, 1)
    def test_runs_on_the_interval_only(self):
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.s.speed_health(DEFAULTS, 1e9 + 3000, False)
        self.assertEqual(self.runs, 1)
        self.s.speed_health(DEFAULTS, 1e9 + 3601, False)
        self.assertEqual(self.runs, 2)
    def test_a_recent_test_is_not_repeated_after_a_restart(self):
        self.s.store.set_speed({"at": 1e9 - 60, "text": "x"})
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.assertEqual(self.runs, 0)
    def test_zero_turns_it_off(self):
        self.assertEqual(self.s.speed_health({**DEFAULTS, "speedtest_minutes": 0}, 1e9, False), [])
        self.assertEqual(self.runs, 0)
    def test_one_failure_is_not_a_cause_and_retests_soon(self):
        self.results = [self.bad()]
        self.assertEqual(self.s.speed_health(DEFAULTS, 1e9, False), [])
        self.s.speed_health(DEFAULTS, 1e9 + 200, False)
        self.assertEqual(self.runs, 1)
    def test_two_failures_in_a_row_are_a_cause(self):
        self.results = [self.bad(), self.bad()]
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.assertIn("download 5 Mbps", self.s.speed_health(DEFAULTS, 1e9 + 301, False)[0])
    def test_a_good_test_clears_it(self):
        self.results = [self.bad(), self.bad()]
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.s.speed_health(DEFAULTS, 1e9 + 301, False)
        self.assertEqual(self.s.speed_health(DEFAULTS, 1e9 + 602, False), [])
        self.assertEqual(self.s.speed_streak, 0)
    def test_an_unclear_test_keeps_the_count_and_retests(self):
        self.results = [self.bad(), {"unclear": True, "problems": []}]
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.s.speed_health(DEFAULTS, 1e9 + 301, False)
        self.assertEqual(self.s.speed_streak, 1)
        self.assertEqual(self.s.speed_due, 1e9 + 601)
    def test_the_cause_survives_viewers_arriving(self):
        self.results = [self.bad(), self.bad()]
        self.s.speed_health(DEFAULTS, 1e9, False)
        self.s.speed_health(DEFAULTS, 1e9 + 301, False)
        self.assertTrue(self.s.speed_health(DEFAULTS, 1e9 + 310, True))
        self.assertEqual(P.route([], self.s.speed_cause, True)[0], "hold")

class SameServer(unittest.TestCase):
    class Stop:
        def wait(self, seconds=0):
            return False
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.exit, self.switch = P.exit_info, P.switch_exit
        self.moves = []
        P.switch_exit = lambda *a, **k: self.moves.append(k.get("cause")) or "usa"
    def tearDown(self):
        P.exit_info, P.switch_exit = self.exit, self.switch
        self.dir.cleanup()
    def act(self, addresses):
        answers = iter(addresses)
        P.exit_info = lambda: {"ip": next(answers)}
        self.s.act({**DEFAULTS, "auto_switch": True}, ["slow"], 1e9, self.Stop())
    def test_a_new_address_needs_no_retry(self):
        self.act(["1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(self.moves), 1)
    def test_same_address_retries_once(self):
        self.act(["1.1.1.1", "1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(self.moves), 2)
    def test_it_never_retries_twice(self):
        self.act(["1.1.1.1", "1.1.1.1", "1.1.1.1"])
        self.assertEqual(len(self.moves), 2)

class Repair(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.exit, self.switch = P.exit_info, P.switch_exit
        self.moves = []
        P.switch_exit = lambda *a, **k: self.moves.append(k) or "x"
    def tearDown(self):
        P.exit_info, P.switch_exit = self.exit, self.switch
        self.dir.cleanup()
    def test_idle_without_a_switch(self):
        P.exit_info = lambda: 1 / 0
        self.s.check_tunnel(DEFAULTS, 1000)
    def test_healthy_tunnel_needs_nothing(self):
        P.exit_info = lambda: {"ip": "1.1.1.1"}
        self.s.repairs = 0
        self.s.check_tunnel(DEFAULTS, 1000)
        self.assertIsNone(self.s.repairs)
        self.assertEqual(self.moves, [])
    def test_dead_tunnel_retries_spaced_then_gives_up(self):
        P.exit_info = lambda: {"error": "URLError"}
        self.s.repairs = 0
        for t in range(0, 1000, 10):
            self.s.check_tunnel(DEFAULTS, 1000 + t)
        self.assertEqual(len(self.moves), P.MAX_REPAIRS)
        self.assertIsNone(self.s.repairs)
        self.assertIn("repair_gave_up", "".join(self.s.store.recent(5)))

if __name__ == "__main__":
    unittest.main()
