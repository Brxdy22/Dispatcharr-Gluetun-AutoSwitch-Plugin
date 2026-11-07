import http.server
import io
import unittest
import json
import os
import tempfile
import threading
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

class LiveLists(unittest.TestCase):
    def fresh(self):
        return [{"id": "exits", "options": [{"value": "Toronto", "label": "Toronto"}]},
                {"id": "auto_switch"}]

    def test_only_the_lists_change(self):
        loaded = [{"id": "exits", "label": "Allowed cities", "options": []},
                  {"id": "auto_switch", "default": True}]
        P.refill_options(loaded, self.fresh())
        self.assertEqual(loaded[0]["options"][0]["value"], "Toronto")
        self.assertEqual(loaded[0]["label"], "Allowed cities")
        self.assertEqual(loaded[1], {"id": "auto_switch", "default": True})

    def test_other_requests_are_ignored(self):
        original = P.current_fields
        P.current_fields = lambda: self.fail("rebuilt the lists for an unrelated request")
        try:
            P.refresh_lists(environ={"PATH_INFO": "/api/channels/channels/"})
            P.refresh_lists(environ={"PATH_INFO": "/api/plugins/plugins/other_plugin/settings/"})
            P.refresh_lists()
        finally:
            P.current_fields = original

    def test_a_failure_never_reaches_the_request(self):
        P.refresh_lists(environ={"PATH_INFO": P.LIST_PATHS[0]})  # no Dispatcharr here

    def test_cities_follow_the_saved_countries(self):
        fields = [{"id": i} for i in ("exit_countries", "exits", "blocked_countries",
                                      "blocked_cities", "blocked_exits")]
        servers = {"Canada": ["Toronto"], "USA": ["Dallas TX"]}
        built = P.build_fields(fields, servers, {"exit_countries": ["Canada"]})
        cities = next(f for f in built if f["id"] == "exits")["options"]
        self.assertEqual([o["value"] for o in cities], ["Toronto"])


class Rules(unittest.TestCase):
    ROWS = [{"hostname": "us-aaa-wg-001", "city": "Dallas TX", "country": "USA"},
            {"hostname": "ca-aaa-wg-001", "city": "Toronto", "country": "Canada"},
            {"hostname": "se-aaa-wg-001", "city": "Malmo", "country": "Sweden"}]

    def rules(self, countries=(), cities=(), blocked_countries=(), blocked_cities=()):
        return P.exit_rules({"exit_countries": list(countries), "exits": list(cities),
                             "blocked_countries": list(blocked_countries),
                             "blocked_cities": list(blocked_cities)}, self.ROWS)

    def problem(self, index, *args, **kwargs):
        return P.rule_problem(self.ROWS[index], *self.rules(*args, **kwargs))

    def test_no_country_means_no_city_is_read(self):
        self.assertEqual(self.rules(cities=["Toronto"])[:2], ([], []))

    def test_city_of_a_removed_country_is_ignored(self):
        self.assertEqual(self.rules(["USA"], ["Toronto", "Dallas TX"])[1], ["dallas tx"])

    def test_only_leftover_cities_falls_back_to_the_countries(self):
        self.assertEqual(self.rules(["USA"], ["Toronto"])[:2], (["usa"], []))

    def test_city_not_in_the_list_is_kept(self):
        self.assertEqual(self.rules(["USA"], ["Gone City"])[1], ["gone city"])

    def test_fine_exit(self):
        self.assertEqual(self.problem(0, ["USA"]), "")
        self.assertEqual(self.problem(1, ["Canada"]), "")

    def test_country_not_allowed(self):
        self.assertIn("not in Allowed countries", self.problem(1, ["USA"]))

    def test_city_not_allowed(self):
        self.assertIn("not in Allowed cities", self.problem(0, ["USA"], ["Other City"]))
        self.assertIn("not in Allowed cities", P.rule_problem(self.ROWS[0], ["usa"], ["toronto"], [], []))

    def test_blocked_wins_over_allowed(self):
        self.assertIn("is blocked", self.problem(0, ["USA"], blocked_countries=["USA"]))
        self.assertIn("is blocked", self.problem(0, ["USA"], blocked_cities=["Dallas TX"]))
        self.assertIn("is blocked", self.problem(1, ["Canada"], blocked_countries=["Canada"]))


class SaveGuard(unittest.TestCase):
    def test_emptied_countries_are_refused(self):
        self.assertIn("at least one", P.settings_problem({"exit_countries": []}))
        self.assertIn("at least one", P.settings_problem({"exit_countries": [" "], "exits": ["Toronto"]}))

    def test_a_country_passes(self):
        self.assertEqual(P.settings_problem({"exit_countries": ["USA"]}), "")

    def test_untouched_countries_keep_their_default(self):
        self.assertEqual(P.settings_problem({"auto_switch": True}), "")


class ForkedListener(unittest.TestCase):
    def test_a_forked_child_does_not_keep_the_port(self):
        import http.server
        import socket
        import time
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        port = server.server_address[1]
        P.OPEN_LISTENERS.append(server)
        ready, told = os.pipe()
        child = os.fork()
        if child == 0:
            os.write(told, b"x")  # the fork hooks have run by now
            time.sleep(3)
            os._exit(0)
        try:
            os.read(ready, 1)
            server.server_close()
            P.OPEN_LISTENERS.remove(server)
            again = socket.socket()
            again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            again.bind(("127.0.0.1", port))  # raises while the child still holds it
            again.close()
        finally:
            os.kill(child, 9)
            os.waitpid(child, 0)
            os.close(ready)
            os.close(told)


class RuleSwitches(unittest.TestCase):
    """switch_exit with the rules applied, against a stand-in for Gluetun."""
    ROWS = Rules.ROWS

    def move(self, held=((), (), ()), **settings):
        moves = []

        class FakeGluetun:
            def __init__(self, url, api_key=""):
                pass
            def selection(self):
                return tuple(list(part) for part in held)
            def move_to(self, countries, cities, hostnames=None):
                moves.append((countries, cities, hostnames))

        class FakeStore:
            def blocked(self):
                return {}, 0
            def log(self, *args, **kwargs):
                pass
            def add_switch(self, moment):
                pass
            def relays(self):
                return {"at": 9e12, "relays": {"usa": ["dallas tx"], "canada": ["toronto"], "sweden": ["malmo"]}}

        saved = P.Gluetun, P.read_server_rows
        P.Gluetun, P.read_server_rows = FakeGluetun, lambda path=None: self.ROWS
        try:
            P.switch_exit({**DEFAULTS, "exits": [], **settings}, FakeStore(), cause="test")
        finally:
            P.Gluetun, P.read_server_rows = saved
        return moves

    def test_no_country_stays_put(self):
        self.assertEqual(self.move(exit_countries=[]), [])
        self.assertEqual(self.move(exit_countries=[], exits=["Toronto"]), [])

    def test_a_named_server_with_no_country_stays_put(self):
        self.assertEqual(self.move(held=([], [], ["us-aaa-wg-001"]), exit_countries=[]), [])

    def test_a_blocked_country_is_avoided(self):
        moves = self.move(held=([], [], ["us-aaa-wg-001"]), exit_countries=["USA", "Canada", "Sweden"],
                          blocked_countries=["Canada"])
        self.assertEqual(moves[0][2], ["se-aaa-wg-001"])

    def test_a_blocked_city_is_avoided(self):
        for _ in range(20):
            moves = self.move(exit_countries=["USA", "Canada", "Sweden"], blocked_cities=["Toronto", "Malmo"])
            self.assertEqual(moves[0][1], ["dallas tx"])

    def test_leftover_city_is_never_used(self):
        moves = self.move(exit_countries=["USA"], exits=["Toronto"])
        self.assertEqual(moves[0][:2], (["usa"], []))

    def test_everything_blocked_stays_put(self):
        self.assertEqual(self.move(exit_countries=["USA"], blocked_countries=["USA"]), [])


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
    URL = "http://127.0.0.1:8090/live/user/pass/1001.ts"
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
        self.assertEqual(P.feed_of(self.URL), "1001.ts")

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
        P.read_proxy_status = lambda base: {"preferred": "real.example:8880 (1.2.3.4)", "upstreams": ["real.example:8880"]}
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
        self.assertEqual(f.calls, ["http://real.example:8880/live/user/pass/1.ts"])
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
        self.assertEqual(P.direct_url(self.URL, {"preferred": "a.tv:8880 (1.2.3.4)", "upstreams": ["b.tv"]}),
                         "http://a.tv:8880/live/u/p/9.ts")
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
        status = {"preferred": "provider.example:8880 (203.0.113.10)", "upstreams": ["x"]}
        self.assertEqual(P.provider_target("http://127.0.0.1:8090", status), ("provider.example", 8880))
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
        self.assertEqual(P.movie_seconds(198, self.never), (11880, "stored"))  # a long film
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
    def test_long_film_with_its_size(self):
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

class SlowExit(unittest.TestCase):
    def test_far_below_usual_fails_above_the_minimum(self):
        self.assertEqual(P.judge({**GOOD, "download": 56.0}, DEFAULTS, {}, 214.0),
                         ["download 56 Mbps (usually 214)"])
    def test_near_usual_passes(self):
        self.assertEqual(P.judge({**GOOD, "download": 90.0}, DEFAULTS, {}, 214.0), [])
    def test_below_the_minimum_is_reported_once(self):
        self.assertEqual(P.judge({**GOOD, "download": 20.0}, DEFAULTS, {}, 214.0),
                         ["download 20 Mbps (minimum 30)"])
    def test_zero_turns_it_off(self):
        self.assertEqual(P.judge({**GOOD, "download": 56.0}, {**DEFAULTS, "slow_percent": 0}, {}, 214.0), [])
    def test_no_history_is_no_verdict(self):
        self.assertEqual(P.judge({**GOOD, "download": 56.0}, DEFAULTS, {}, None), [])
    def test_usual_is_the_median_and_failed_tests_count(self):
        tests = [{"event": "speed_test", "download": d, "problems": ["x"]} for d in (100.0, 200.0, 300.0)]
        self.assertEqual(P.usual_download(tests), 200.0)
    def test_usual_skips_busy_failed_and_other_entries(self):
        tests = [{"event": "speed_test", "download": 5.0, "streams": 2},
                 {"event": "speed_test", "download": None}, {"event": "exit", "download": 1.0},
                 {"event": "speed_test", "download": 200.0}]
        self.assertIsNone(P.usual_download(tests))
    def test_the_field_ships_with_the_default(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.json")) as handle:
            manifest = json.load(handle)
        field = next(f for f in manifest["fields"] if f["id"] == "slow_percent")
        self.assertEqual(field["default"], DEFAULTS["slow_percent"])
        self.assertEqual(manifest["version"], P.Plugin.version)

class CloseBeforeMove(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = P.Store(self.dir.name)
        self.saved = P.Gluetun, P.read_server_rows, P.close_streams, P.load_accounts, P.time.sleep
        P.Gluetun, P.read_server_rows = FakeGluetun, lambda: ROWS
        P.load_accounts = lambda: []
        P.time.sleep = lambda seconds: None
        self.choice, P.random.choice = P.random.choice, FIRST
        FakeGluetun.selected, FakeGluetun.moves = (["USA"], [], []), []
        self.settings = {**DEFAULTS, "exits": [], "exit_countries": ["USA"]}
        self.moves_at_close = []
        def close(accounts):
            self.moves_at_close.append(len(FakeGluetun.moves))
            return 1
        P.close_streams = close
    def tearDown(self):
        P.Gluetun, P.read_server_rows, P.close_streams, P.load_accounts, P.time.sleep = self.saved
        P.random.choice = self.choice
        self.dir.cleanup()
    def events(self):
        return [entry.get("event") for entry in self.store.entries()]
    def test_streams_close_before_a_country_move(self):
        P.switch_exit(self.settings, self.store, cause="x")
        self.assertEqual(self.moves_at_close, [0])
        self.assertEqual(len(FakeGluetun.moves), 1)
        self.assertIn("closed_streams", self.events())
    def test_streams_close_before_a_named_server_move(self):
        FakeGluetun.selected = ([], [], ["us-aaa-wg-001"])
        P.switch_exit(self.settings, self.store, cause="x", left=HERE)
        self.assertEqual(self.moves_at_close, [0])
        self.assertEqual(len(FakeGluetun.moves), 1)
    def test_a_failed_close_never_stops_the_move(self):
        def broken(accounts):
            raise OSError("no")
        P.close_streams = broken
        self.assertTrue(P.switch_exit(self.settings, self.store, cause="x"))
        self.assertEqual(len(FakeGluetun.moves), 1)
    def test_nothing_closes_when_there_is_nowhere_to_go(self):
        self.store.set_blocked({}, 1)
        saved, P.plan_move = P.plan_move, lambda *a: None
        try:
            self.assertIsNone(P.switch_exit(self.settings, self.store, cause="x"))
        finally:
            P.plan_move = saved
        self.assertEqual(self.moves_at_close, [])
    def test_only_local_proxies_are_asked(self):
        asked, saved = [], P.urllib.request.urlopen
        class Reply(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False
        def fake(url, timeout=None):
            asked.append(url)
            return Reply(b'{"dropped": 2}')
        P.urllib.request.urlopen = fake
        self.addCleanup(setattr, P.urllib.request, "urlopen", saved)
        P.close_streams = self.saved[2]
        accounts = [P.Account("a", "http://127.0.0.1:8091", "u", "p", "ua"),
                    P.Account("b", "http://provider.example", "u", "p", "ua")]
        self.assertEqual(P.close_streams(accounts), 2)
        self.assertEqual(asked, ["http://127.0.0.1:8091/__before_move?hold=6"])

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

class MovedMirror(unittest.TestCase):
    def row(self, ping, host, city="A", problems=()):
        return {"event": "speed_test", "city": city, "providers": {"M": ping},
                "provider_hosts": {"M": host}, "problems": list(problems)}

    def test_old_host_does_not_count(self):
        rows = [self.row(58, "cf:80"), self.row(58, "cf:80")]
        self.assertEqual(P.usual_pings(rows, {"M": "direct:80"}), {})

    def test_journal_without_hosts_does_not_count(self):
        rows = [{"event": "speed_test", "providers": {"M": 58}}] * 3
        self.assertEqual(P.usual_pings(rows, {"M": "direct:80"}), {})

    def test_same_host_counts(self):
        rows = [self.row(58, "x:80"), self.row(60, "x:80")]
        self.assertEqual(P.usual_pings(rows, {"M": "x:80"}), {"M": 60})

    def test_rise_on_two_exits_is_the_new_usual(self):
        flag = ["M ping 200 ms (usually 58)"]
        rows = [self.row(58, "x:80"), self.row(58, "x:80"),
                self.row(200, "x:80", "A", flag), self.row(190, "x:80", "B", flag)]
        self.assertEqual(P.usual_pings(rows, {"M": "x:80"}), {"M": 200})

    def test_rise_on_one_exit_is_that_exit(self):
        flag = ["M ping 200 ms (usually 58)"]
        rows = [self.row(58, "x:80"), self.row(58, "x:80"),
                self.row(200, "x:80", "A", flag), self.row(210, "x:80", "A", flag)]
        self.assertEqual(P.usual_pings(rows, {"M": "x:80"}), {"M": 58})


class Suspects(unittest.TestCase):
    def live(self, name, speed):
        return {"kind": "live", "name": name, "speed": speed}

    def test_one_slow_among_healthy_is_the_feed(self):
        self.assertEqual(P.exit_suspects([self.live("a", 0.85), self.live("b", 1.0)], 0.9), [])

    def test_all_slow_is_the_exit(self):
        self.assertEqual(len(P.exit_suspects([self.live("a", 0.85), self.live("b", 0.8)], 0.9)), 2)

    def test_alone_can_still_be_the_exit(self):
        self.assertEqual(len(P.exit_suspects([self.live("a", 0.85)], 0.9)), 1)

    def test_other_kind_is_no_proof(self):
        vod = {"kind": "vod", "name": "m", "speed": 1.2}
        self.assertEqual(len(P.exit_suspects([self.live("a", 0.85), vod], 0.9)), 1)

    def test_unmeasured_is_no_proof(self):
        self.assertEqual(len(P.exit_suspects([self.live("a", 0.85), self.live("b", None)], 0.9)), 1)


class OneMovePerStream(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.service = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.slow = [{"kind": "live", "name": "a", "speed": 0.8}]

    def tearDown(self):
        self.dir.cleanup()

    def events(self):
        return [e for e in self.service.store.entries() if e.get("event") == "feed_slow"]

    def test_first_time_moves(self):
        self.assertEqual(len(self.service.slow_streams(self.slow, 0.9, 1000)), 1)

    def test_still_slow_after_a_move_does_not(self):
        self.service.moved_for["a"] = 1000
        self.assertEqual(self.service.slow_streams(self.slow, 0.9, 1100), [])
        self.service.slow_streams(self.slow, 0.9, 1110)
        self.assertEqual(len(self.events()), 1)  # one journal line, not one per tick

    def test_forgotten_after_a_while(self):
        self.service.moved_for["a"] = 1000
        now = 1000 + P.FEED_MEMORY_SECONDS
        self.assertEqual(len(self.service.slow_streams(self.slow, 0.9, now)), 1)


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

class SelectionFields(unittest.TestCase):
    SERVERS = {"USA": ["Ashburn VA", "Boston MA"], "Canada": ["Toronto"], "Sweden": ["Malmo"]}

    def manifest(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.json")
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)["fields"]

    def build(self, settings=None, servers=None):
        servers = self.SERVERS if servers is None else servers
        fields = P.build_fields(self.manifest(), servers, settings or {})
        return {f["id"]: [o["value"] for o in f.get("options") or []] for f in fields}

    def test_every_country_in_the_server_list_is_offered(self):
        self.assertEqual(self.build(settings={"exit_countries": ["USA"]})["exit_countries"], sorted(self.SERVERS))

    def test_cities_follow_saved_countries(self):
        fields = self.build(settings={"exit_countries": ["Canada"], "exits": []})
        self.assertEqual(fields["exits"], ["Toronto"])
        self.assertEqual(fields["blocked_cities"], ["Toronto"])

    def test_no_countries_chosen_shows_no_cities(self):
        fields = self.build(settings={"exit_countries": [], "exits": []})
        self.assertEqual(fields["exits"], [])
        self.assertEqual(fields["blocked_cities"], [])
        self.assertEqual(fields["blocked_exits"], [])

    def test_cities_are_labelled_and_sorted_by_country(self):
        built = P.build_fields(self.manifest(), self.SERVERS, {"exit_countries": ["USA", "Canada"], "exits": ["Gone City"]})
        cities = next(f for f in built if f["id"] == "exits")["options"]
        self.assertEqual(cities, [
            {"value": "Toronto", "label": "Toronto (Canada)"},
            {"value": "Ashburn VA", "label": "Ashburn VA (USA)"},
            {"value": "Boston MA", "label": "Boston MA (USA)"},
            {"value": "Gone City", "label": "Gone City"},
        ])

    def test_saved_values_stay_offered(self):
        fields = self.build(settings={"exit_countries": ["Sweden", "USA"], "exits": ["Gone City"], "blocked_cities": "Old, Older"})
        self.assertIn("Sweden", fields["exit_countries"])
        self.assertIn("Gone City", fields["exits"])
        self.assertEqual(fields["blocked_cities"][-2:], ["Old", "Older"])

    def test_every_default_is_offered_without_the_server_list(self):
        fields = self.build({}, {})
        for field in self.manifest():
            if field["type"] == "multiselect":
                self.assertTrue(set(field["default"]) <= set(fields[field["id"]]), field["id"])

    def test_old_range_text_is_expanded(self):
        codes = self.build(settings={"reject_codes": "403, 600-601"})["reject_codes"]
        self.assertTrue({"403", "600", "601", "520"} <= set(codes))

    def test_default_codes_match_the_old_text(self):
        self.assertEqual(parse_codes(DEFAULTS["reject_codes"]), parse_codes("403, 520-527"))

    def test_lists_and_text_parse_alike(self):
        self.assertEqual(parse_exits(["Ashburn VA", " Boston MA "]), parse_exits("Ashburn VA, Boston MA"))
        self.assertEqual(parse_exits([]), [])
        self.assertEqual(parse_exits(""), [])

    def test_read_servers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "s.json")
            with open(path, "w") as handle:
                json.dump({"servers": [{"country": "USA", "city": "B"}, {"country": "USA", "city": "A"}, {"country": "USA"}]}, handle)
            self.assertEqual(P.read_servers(path), {"USA": ["A", "B"]})
            self.assertEqual(P.read_servers(path + "x"), {})
            with open(path, "w") as handle:
                handle.write("{bad")
            self.assertEqual(P.read_servers(path), {})

ROWS = [
    {"hostname": "us-aaa-wg-001", "city": "Ashburn VA", "country": "USA"},
    {"hostname": "us-aaa-wg-002", "city": "Ashburn VA", "country": "USA"},
    {"hostname": "us-bbb-wg-001", "city": "Boston MA", "country": "USA"},
    {"hostname": "ca-ttt-wg-001", "city": "Toronto", "country": "Canada"},
]
FIRST = lambda pool: pool[0]  # noqa: E731

class PlanServer(unittest.TestCase):
    def plan(self, here=None, countries=("usa",), cities=(), **kw):
        found = P.plan_server(ROWS, here or {}, list(countries), list(cities), choose=FIRST, **kw)
        return found and found["hostname"]
    def test_never_the_current_server(self):
        self.assertEqual(self.plan({"hostname": "us-aaa-wg-001", "country": "USA"}), "us-aaa-wg-002")
    def test_skips_blocked_servers(self):
        self.assertEqual(self.plan(blocked_hosts={"us-aaa-wg-001", "us-aaa-wg-002"}), "us-bbb-wg-001")
    def test_same_city_is_fine_on_another_server(self):
        self.assertEqual(self.plan({"hostname": "us-aaa-wg-001", "city": "Ashburn VA"}, cities=("ashburn va",)), "us-aaa-wg-002")
    def test_cities_go_in_order_after_the_current_one(self):
        here = {"hostname": "us-bbb-wg-001", "city": "Boston MA"}
        self.assertEqual(self.plan(here, cities=("ashburn va", "boston ma")), "us-aaa-wg-001")
        here = {"hostname": "us-aaa-wg-001", "city": "Ashburn VA"}
        self.assertEqual(self.plan(here, cities=("ashburn va", "boston ma")), "us-bbb-wg-001")
    def test_next_country_first(self):
        self.assertEqual(self.plan({"hostname": "us-aaa-wg-001", "country": "USA"}, countries=("usa", "canada")), "ca-ttt-wg-001")
    def test_blocked_cities_and_countries(self):
        self.assertEqual(self.plan(blocked_cities=("ashburn va",)), "us-bbb-wg-001")
        self.assertIsNone(self.plan(countries=("usa",), blocked_countries=("USA",)))
    def test_nothing_left(self):
        self.assertIsNone(self.plan(blocked_hosts={"us-aaa-wg-001", "us-aaa-wg-002", "us-bbb-wg-001"}))
    def test_unknown_place_starts_at_the_top(self):
        self.assertEqual(self.plan({}, cities=("boston ma", "ashburn va")), "us-bbb-wg-001")
    def test_read_server_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "s.json")
            with open(path, "w") as handle:
                json.dump({"servers": [
                    {"vpn": "wireguard", "hostname": "h1", "city": "A", "country": "USA", "wgpubkey": "k"},
                    {"vpn": "openvpn", "hostname": "h2", "city": "A", "country": "USA"},
                    {"vpn": "wireguard", "city": "A", "country": "USA"},
                ]}, handle)
            self.assertEqual(P.read_server_rows(path), [{"hostname": "h1", "city": "A", "country": "USA"}])
            self.assertEqual(P.read_server_rows(path + "x"), [])

HERE = {"ip": "198.51.100.7", "hostname": "us-aaa-wg-001", "city": "Ashburn, VA"}

class Blocks(unittest.TestCase):
    def test_add_and_repeat(self):
        entries = P.add_block({}, HERE, "Provider A", 1000)
        self.assertEqual(entries["us-aaa-wg-001"]["accounts"], ["Provider A"])
        self.assertEqual(entries["us-aaa-wg-001"]["expires"], 1000 + 30 * 86400)
        again = P.add_block(entries, HERE, "Provider B", 5000)
        self.assertEqual(again["us-aaa-wg-001"]["accounts"], ["Provider A", "Provider B"])
        self.assertEqual(again["us-aaa-wg-001"]["expires"], 5000 + 30 * 86400)
        self.assertEqual(entries["us-aaa-wg-001"]["accounts"], ["Provider A"])  # the input is untouched
        self.assertEqual(P.add_block(again, HERE, "Provider A", 6000)["us-aaa-wg-001"]["accounts"], ["Provider A", "Provider B"])
    def test_unknown_server_name_keys_by_address(self):
        self.assertIn("198.51.100.7", P.add_block({}, {"ip": "198.51.100.7"}, "Provider A", 1))
    def test_expiry(self):
        entries = P.add_block({}, HERE, "Provider A", 1000)
        self.assertTrue(P.active_blocks(entries, 1000 + 29 * 86400))
        self.assertFalse(P.active_blocks(entries, 1000 + 30 * 86400))
    def test_render(self):
        text = P.render_blocks(P.add_block({}, HERE, "Provider A", 1000), 4)
        self.assertIn("198.51.100.7 - us-aaa-wg-001, Ashburn, VA - blocked by Provider A on", text)
        self.assertTrue(text.endswith("List version 4."))
        self.assertEqual(P.render_blocks({}, 0), "List version 0. No exit is blocked.")

class Reconcile(unittest.TestCase):
    def setUp(self):
        self.entries = P.add_block({}, HERE, "Provider A", 1000)
    def test_a_current_page_can_unblock(self):
        kept, version = P.reconcile(self.entries, 3, [], "List version 3.", ROWS, 2000)
        self.assertEqual((kept, version), ({}, 4))
    def test_an_older_page_cannot(self):
        self.assertEqual(P.reconcile(self.entries, 3, [], "List version 2.", ROWS, 2000), (self.entries, 3))
        self.assertEqual(P.reconcile(self.entries, 3, [], "", ROWS, 2000), (self.entries, 3))
        self.assertEqual(P.reconcile(self.entries, 3, [], "edited", ROWS, 2000), (self.entries, 3))
    def test_nothing_changed_keeps_the_version(self):
        self.assertEqual(P.reconcile(self.entries, 3, ["us-aaa-wg-001"], "List version 3.", ROWS, 2000), (self.entries, 3))
    def test_picked_by_hand(self):
        kept, version = P.reconcile(self.entries, 3, ["us-aaa-wg-001", "us-bbb-wg-001"], "List version 3.", ROWS, 2000)
        self.assertEqual(version, 4)
        self.assertEqual(kept["us-bbb-wg-001"]["accounts"], ["you"])
        self.assertEqual(kept["us-bbb-wg-001"]["city"], "Boston MA")
        self.assertEqual(kept["us-bbb-wg-001"]["expires"], 2000 + 30 * 86400)

class ExitOptions(unittest.TestCase):
    def test_every_server_and_blocked_first(self):
        entries = P.add_block({}, HERE, "Provider A", 1000)
        options = P.exit_options(ROWS, ["USA"], entries, [])
        self.assertEqual([o["value"] for o in options], ["us-aaa-wg-001", "us-aaa-wg-002", "us-bbb-wg-001"])
        self.assertEqual(options[0]["label"], "us-aaa-wg-001 - Ashburn VA - 198.51.100.7 - blocked by Provider A")
        self.assertEqual(options[1]["label"], "us-aaa-wg-002 - Ashburn VA")
    def test_blocked_elsewhere_and_saved_values_stay(self):
        entries = P.add_block({}, {"ip": "203.0.113.9", "hostname": "ca-ttt-wg-001"}, "Provider A", 1)
        values = [o["value"] for o in P.exit_options(ROWS, ["USA"], entries, ["gone-wg-9"])]
        self.assertEqual(values[0], "ca-ttt-wg-001")
        self.assertEqual(values[-1], "gone-wg-9")
    def test_build_fields_fills_the_list(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.json")
        with open(path, encoding="utf-8") as handle:
            manifest = json.load(handle)["fields"]
        fields = P.build_fields(manifest, {"USA": ["Ashburn VA"]}, {}, ROWS, {})
        options = next(f for f in fields if f["id"] == "blocked_exits")["options"]
        self.assertEqual(len(options), 3)

class FakeGluetun:
    selected = ([], [], [])
    moves = []
    def __init__(self, url, api_key=""):
        FakeGluetun.key = api_key
    def selection(self):
        return FakeGluetun.selected
    def move_to(self, *args):
        FakeGluetun.moves.append(args)

class SwitchByServer(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = P.Store(self.dir.name)
        self.saved = P.Gluetun, P.read_server_rows
        P.Gluetun, P.read_server_rows = FakeGluetun, lambda: ROWS
        self.choice, P.random.choice = P.random.choice, FIRST
        FakeGluetun.selected, FakeGluetun.moves = (["USA"], [], []), []
        self.settings = {**DEFAULTS, "exits": [], "exit_countries": ["USA"]}
    def tearDown(self):
        P.Gluetun, P.read_server_rows = self.saved
        P.random.choice = self.choice
        self.dir.cleanup()
    def test_switch_passes_the_saved_key(self):
        P.switch_exit({**self.settings, "gluetun_api_key": "secret-key"}, self.store, cause="x")
        self.assertEqual(FakeGluetun.key, "secret-key")
    def test_without_blocks_nothing_changes(self):
        P.switch_exit(self.settings, self.store, cause="x")
        self.assertEqual(FakeGluetun.moves, [(["usa"], [])])  # the case flip forces a reconnect
    def test_blocked_exits_name_a_server(self):
        self.store.set_blocked(P.add_block({}, HERE, "Provider A", P.time.time()), 1)
        label = P.switch_exit(self.settings, self.store, cause="x", left=HERE)
        self.assertEqual(FakeGluetun.moves, [([], [], ["us-aaa-wg-002"])])
        self.assertEqual(label, "Ashburn VA (us-aaa-wg-002)")
    def test_an_expired_block_is_ignored(self):
        self.store.set_blocked(P.add_block({}, HERE, "Provider A", 1000), 1)
        P.switch_exit(self.settings, self.store, cause="x")
        self.assertEqual(FakeGluetun.moves, [(["usa"], [])])  # the case flip forces a reconnect
    def test_a_named_server_keeps_naming_one(self):
        FakeGluetun.selected = ([], [], ["us-aaa-wg-001"])
        P.switch_exit(self.settings, self.store, cause="x")
        self.assertEqual(FakeGluetun.moves, [([], [], ["us-aaa-wg-002"])])
    def test_everything_blocked_stops(self):
        now = P.time.time()
        entries = {}
        for row in ROWS:
            entries = P.add_block(entries, {"ip": "x", "hostname": row["hostname"]}, "Provider A", now)
        self.store.set_blocked(entries, 1)
        self.assertIsNone(P.switch_exit(self.settings, self.store, cause="x"))
        self.assertEqual(FakeGluetun.moves, [])
        self.assertIn("every allowed server is blocked", "".join(self.store.recent(1)))
    def test_unreadable_server_list_stops(self):
        P.read_server_rows = lambda: []
        self.store.set_blocked(P.add_block({}, HERE, "Provider A", P.time.time()), 1)
        self.assertIsNone(P.switch_exit(self.settings, self.store, cause="x"))
        self.assertEqual(FakeGluetun.moves, [])

class VodBlocked(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.settings = {"auto_switch": True}
        self.s = P.Service({"data_dir": self.dir.name, "get_settings": lambda: self.settings})
        self.s.accounts, self.s.accounts_at = [P.Account("Provider A", "http://127.0.0.1:8091", "u", "p", "")], 1e12
        self.saved = P.exit_info, P.switch_exit, P.publish_blocked, P.drop_live
        self.exits = iter([HERE, {"ip": "203.0.113.1", "city": "Boston, MA"}])
        P.exit_info = lambda timeout=10: next(self.exits)
        self.moves = []
        P.switch_exit = lambda *a, **k: self.moves.append(k) or "Boston MA (us-bbb-wg-001)"
        P.publish_blocked = lambda hosts, text: None
        P.drop_live = lambda accounts: 0
    def tearDown(self):
        P.exit_info, P.switch_exit, P.publish_blocked, P.drop_live = self.saved
        self.dir.cleanup()
    def ask(self, **extra):
        return self.s.vod_blocked({"port": 8091, "title": "movie 1.mkv", "budget": 3, **extra})
    def test_blocks_moves_and_waits_for_the_tunnel(self):
        answer = self.ask()
        self.assertEqual(answer, {"moved": True, "ready": True, "exit": "Boston, MA"})
        entries, version = self.s.store.blocked()
        self.assertEqual(entries["us-aaa-wg-001"]["accounts"], ["Provider A"])
        self.assertEqual(version, 1)
        self.assertEqual(self.moves[0]["left"], HERE)
        self.assertFalse(self.s.switch_lock.locked())
    def test_a_second_request_rides_on_the_move(self):
        self.ask()
        self.assertEqual(self.ask()["detail"], "the exit moved moments ago")
        self.assertEqual(len(self.moves), 1)
    def test_observe_only(self):
        self.settings = {"auto_switch": False}
        self.assertFalse(self.ask()["moved"])
        self.assertEqual(self.s.store.blocked(), ({}, 0))
        self.assertIn("would_switch", "".join(self.s.store.recent(1)))
    def test_turned_off(self):
        self.settings = {"auto_switch": True, "vod_block_switch": False}
        self.assertFalse(self.ask()["moved"])
        self.assertEqual(self.moves, [])
    def test_hourly_limit_holds_but_cooldown_does_not(self):
        now = P.time.time()
        self.s.store.add_switch(now - 60)
        self.assertTrue(self.ask()["moved"])
        self.dir2 = tempfile.TemporaryDirectory()
        self.s.store = P.Store(self.dir2.name)
        self.s.moved_at = 0
        for k in range(3):
            self.s.store.add_switch(now - 100 - k)
        self.assertEqual(self.ask()["detail"], "hourly limit reached: the provider may be the problem, not the exit")
        self.dir2.cleanup()
    def test_unknown_exit_does_nothing(self):
        P.exit_info = lambda timeout=10: {"error": "URLError"}
        self.assertFalse(self.ask()["moved"])
        self.assertEqual(self.moves, [])
    def test_tunnel_not_back_in_time(self):
        P.exit_info = lambda timeout=10: HERE
        answer = self.ask(budget=0.5)
        self.assertEqual((answer["moved"], answer["ready"]), (True, False))
    def test_account_name_from_the_port(self):
        self.assertEqual(self.s.account_name({"port": 8091}), "Provider A")
        self.assertEqual(self.s.account_name({"port": 9999, "account": "other"}), "other")

class VodCheck(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.settings = {"auto_switch": True}
        self.s = P.Service({"data_dir": self.dir.name, "get_settings": lambda: self.settings})
        self.s.accounts = [P.Account("Provider A", "http://127.0.0.1:8091", "u", "p", ""),
                           P.Account("Remote", "http://example.invalid", "u", "p", "")]
        self.s.accounts_at = 1e12
        self.s.vod_check_at = 0
        self.saved = P.ask_vod_check
        self.asked, self.answers = [], []
        P.ask_vod_check = lambda url, forget=False: self.asked.append((url, forget)) or self.answers.pop(0)
        self.blocked = []
        self.s.vod_blocked = lambda request: self.blocked.append(request) or {"moved": True, "ready": True}
        self.s.after_reply = lambda answer: None
    def tearDown(self):
        P.ask_vod_check = self.saved
        self.dir.cleanup()
    def test_healthy_check_is_silent(self):
        self.answers = [{"checked": True, "refused": False}]
        self.s.vod_check(self.s.settings(), 1000, False)
        self.assertEqual(self.asked, [("http://127.0.0.1:8091", False)])  # remote account not asked
        self.assertEqual(self.blocked, [])
        self.assertEqual(self.s.store.recent(5), [])
        self.assertEqual(self.s.vod_check_at, 1000 + 15 * 60)
    def test_refused_blocks_and_moves_in_the_background(self):
        self.answers = [{"checked": True, "refused": True}, {"checked": True, "refused": False}]
        self.s.vod_check(self.s.settings(), 1000, False)
        self.assertEqual(self.blocked[0]["port"], 8091)
        self.assertTrue(self.blocked[0]["background"])
        self.assertEqual(self.asked[1], ("http://127.0.0.1:8091", True))
        self.assertEqual(self.s.store.recent(5), [])
        self.assertEqual(self.s.vod_check_last["refused"], ["Provider A"])
    def test_still_refused_after_the_move_is_logged(self):
        self.answers = [{"refused": True}, {"refused": True}]
        self.s.vod_check(self.s.settings(), 1000, False)
        self.assertIn("vod_check_unclear", "".join(self.s.store.recent(1)))
    def test_not_while_watching_or_before_due_or_off(self):
        self.s.vod_check(self.s.settings(), 1000, True)
        self.s.vod_check_at = 2000
        self.s.vod_check(self.s.settings(), 1000, False)
        self.s.vod_check_at = 0
        self.settings = {"auto_switch": True, "vod_check_minutes": 0}
        self.s.vod_check(self.s.settings(), 1000, False)
        self.assertEqual(self.asked, [])
    def test_unreachable_failover_is_silent(self):
        self.answers = [{}]
        self.s.vod_check(self.s.settings(), 1000, False)
        self.assertEqual(self.blocked, [])
        self.assertEqual(self.s.store.recent(5), [])
    def test_background_ignores_the_first_404_switch_setting(self):
        self.settings = {"auto_switch": False, "vod_block_switch": False}
        s = P.Service({"data_dir": self.dir.name, "get_settings": lambda: self.settings})
        s.accounts, s.accounts_at = [], 1e12
        self.assertEqual(s.vod_blocked({"port": 1, "budget": 0.5})["detail"], "Switch at the first blocked VOD is off")
        saved = P.exit_info
        P.exit_info = lambda timeout=10: HERE
        try:
            self.assertEqual(s.vod_blocked({"port": 1, "budget": 0.5, "background": True})["detail"], "Auto switch is off")
        finally:
            P.exit_info = saved

class SyncBlocked(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.s = P.Service({"data_dir": self.dir.name, "settings": {}})
        self.saved = P.publish_blocked, P.read_server_rows, P.exit_info
        self.published = []
        P.publish_blocked = lambda hosts, text: self.published.append((hosts, text))
        P.read_server_rows = lambda: ROWS
        self.now = P.time.time()
        self.s.store.set_blocked(P.add_block({}, HERE, "Provider A", self.now), 5)
    def tearDown(self):
        P.publish_blocked, P.read_server_rows, P.exit_info = self.saved
        self.dir.cleanup()
    def test_shows_a_new_block(self):
        self.s.sync_blocked({BLOCKED: [], INFO: "List version 4."}, self.now)
        self.assertEqual(self.published[-1][0], ["us-aaa-wg-001"])
        self.assertIn("List version 5.", self.published[-1][1])
        self.assertIn("us-aaa-wg-001", self.s.store.blocked()[0])
    def test_unblock_from_a_current_page(self):
        self.s.sync_blocked({BLOCKED: [], INFO: "List version 5."}, self.now)
        self.assertEqual(self.s.store.blocked(), ({}, 6))
        self.assertEqual(self.published[-1], ([], "List version 6. No exit is blocked."))
    def test_quiet_when_in_step(self):
        text = P.render_blocks(self.s.store.blocked()[0], 5)
        self.s.sync_blocked({BLOCKED: ["us-aaa-wg-001"], INFO: text}, self.now)
        self.assertEqual(self.published, [])
    def test_expires(self):
        self.s.sync_blocked({BLOCKED: ["us-aaa-wg-001"], INFO: "List version 5."}, self.now + 31 * 86400)
        self.assertEqual(self.s.store.blocked(), ({}, 6))
    def test_watch_finds_a_blocked_exit(self):
        P.exit_info = lambda timeout=10: {"ip": "198.51.100.7", "hostname": "us-aaa-wg-001"}
        causes = self.s.watch_exit(self.s.store.blocked()[0], self.now)
        self.assertEqual(causes, ["exit 198.51.100.7 (us-aaa-wg-001) is blocked by Provider A"])
        self.assertEqual(self.s.watch_exit(self.s.store.blocked()[0], self.now + 1), [])  # once a minute
        P.exit_info = lambda timeout=10: {"ip": "203.0.113.1", "hostname": "us-bbb-wg-001"}
        self.assertEqual(self.s.watch_exit(self.s.store.blocked()[0], self.now + 61), [])
    def test_watch_matches_the_address_too(self):
        P.exit_info = lambda timeout=10: {"ip": "198.51.100.7", "hostname": None}
        self.assertTrue(self.s.watch_exit(self.s.store.blocked()[0], self.now))
    def test_no_blocks_no_lookups(self):
        P.exit_info = lambda timeout=10: 1 / 0
        self.assertEqual(self.s.watch_exit({}, self.now), [])
    def rule_watch(self, hostname, **settings):
        rows = [{"hostname": "us-bbb-wg-001", "city": "Dallas TX", "country": "USA"},
                {"hostname": "ca-aaa-wg-001", "city": "Toronto", "country": "Canada"}]
        reader, P.read_server_rows = P.read_server_rows, lambda path=None: rows
        P.exit_info = lambda timeout=10: {"ip": "203.0.113.1", "hostname": hostname}
        try:
            return self.s.watch_exit({}, self.now, {**DEFAULTS, "exits": [], **settings})
        finally:
            P.read_server_rows = reader
    def test_watch_finds_an_exit_outside_the_allowed_countries(self):
        causes = self.rule_watch("ca-aaa-wg-001", exit_countries=["USA"])
        self.assertEqual(causes, ["exit ca-aaa-wg-001: Canada is not in Allowed countries"])
    def test_watch_finds_a_blocked_city_with_no_blocked_exits(self):
        causes = self.rule_watch("us-bbb-wg-001", exit_countries=["USA"], blocked_cities=["Dallas TX"])
        self.assertEqual(causes, ["exit us-bbb-wg-001: Dallas TX is blocked"])
    def test_watch_passes_an_allowed_exit(self):
        self.assertEqual(self.rule_watch("us-bbb-wg-001", exit_countries=["USA"]), [])
    def test_watch_leaves_an_unknown_server_alone(self):
        self.assertEqual(self.rule_watch("xx-new-wg-001", exit_countries=["USA"]), [])

BLOCKED, INFO = P.BLOCKED_FIELD, P.BLOCKED_INFO_FIELD

class Listener(unittest.TestCase):
    def test_round_trip(self):
        import socket as plain, threading, urllib.request as request
        probe = plain.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        saved = P.BLOCK_PORT
        P.BLOCK_PORT = port
        with tempfile.TemporaryDirectory() as folder:
            s = P.Service({"data_dir": folder, "settings": {}})
            seen, done = [], threading.Event()
            s.vod_blocked = lambda body: seen.append(body) or {"moved": False, "detail": "test"}
            s.after_reply = lambda answer: done.set()
            try:
                s.listen()
                self.assertTrue(s.listener)
                s.listen()  # a second call keeps the same server
                data = json.dumps({"port": 8091, "title": "movie 1.mkv", "budget": 2}).encode()
                with request.urlopen(request.Request(f"http://127.0.0.1:{port}{P.BLOCK_PATH}", data=data), timeout=5) as answer:
                    self.assertEqual(json.loads(answer.read()), {"moved": False, "detail": "test"})
                self.assertTrue(done.wait(2))
                self.assertEqual(seen[0]["port"], 8091)
            finally:
                s.listener.shutdown()
                s.listener.server_close()
                P.BLOCK_PORT = saved


class GluetunKey(unittest.TestCase):
    """A real local server, so the header is checked as it goes over the wire."""
    def serve(self, code=200, body=b"{}"):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self):
                seen.append((self.command, self.path, self.headers.get("X-API-Key")))
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(code)
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_PUT = answer
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}", seen

    def test_key_goes_in_the_header(self):
        url, seen = self.serve()
        P.Gluetun(url, " secret-key ").settings()
        self.assertEqual(seen, [("GET", "/v1/vpn/settings", "secret-key")])

    def test_no_key_sends_no_header(self):
        for key in ("", "   ", None):
            url, seen = self.serve()
            P.Gluetun(url, key).settings()
            self.assertEqual(seen, [("GET", "/v1/vpn/settings", None)])

    def test_put_carries_the_key_too(self):
        body = json.dumps({"provider": {"server_selection": {}}}).encode()
        url, seen = self.serve(body=body)
        P.Gluetun(url, "secret-key").move_to(["USA"], [])
        self.assertEqual([(m, k) for m, _, k in seen], [("GET", "secret-key"), ("PUT", "secret-key")])

    def test_refusal_says_what_to_fix_and_hides_the_key(self):
        for code in (401, 403):
            url, _ = self.serve(code, b"secret-key echoed")
            with self.assertRaises(RuntimeError) as caught:
                P.Gluetun(url, "secret-key").settings()
            self.assertIn("Gluetun API key", str(caught.exception))
            self.assertNotIn("secret-key", str(caught.exception))

    def test_other_errors_keep_gluetuns_detail(self):
        url, _ = self.serve(400, b"bad city")
        with self.assertRaisesRegex(RuntimeError, "400: bad city"):
            P.Gluetun(url).settings()

    def test_field_is_masked_and_default_empty(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.json"), encoding="utf-8") as handle:
            field = next(f for f in json.load(handle)["fields"] if f["id"] == "gluetun_api_key")
        self.assertEqual(field["input_type"], "password")
        self.assertEqual(field["default"], "")
        self.assertEqual(DEFAULTS["gluetun_api_key"], "")


class VodEndGrace(unittest.TestCase):
    def setUp(self):
        self.s = P.Service.__new__(P.Service)
        self.s.vod_seen_at = 0.0
        self.vod = [{"kind": "vod", "name": "title"}]
        self.live = [{"kind": "live", "name": "channel"}]

    def test_nobody_has_watched(self):
        self.assertFalse(self.s.someone_watching([], 1000))

    def test_open_streams_count(self):
        self.assertTrue(self.s.someone_watching(self.live, 1000))
        self.assertTrue(self.s.someone_watching(self.vod, 1000))

    def test_vod_counts_for_a_while_after_it_closes(self):
        self.s.someone_watching(self.vod, 1000)
        self.assertTrue(self.s.someone_watching([], 1000 + P.VOD_END_GRACE_SECONDS - 1))
        self.assertFalse(self.s.someone_watching([], 1000 + P.VOD_END_GRACE_SECONDS))

    def test_live_gets_no_grace(self):
        self.s.someone_watching(self.live, 1000)
        self.assertFalse(self.s.someone_watching([], 1001))

    def test_polite_holds_and_urgent_still_acts_in_the_grace(self):
        self.s.someone_watching(self.vod, 1000)
        watching = self.s.someone_watching([], 1010)
        self.assertEqual(P.route([], ["speed test failed"], watching)[0], "hold")
        self.assertEqual(P.route(["title at 0.50x"], [], watching)[0], "act")


if __name__ == "__main__":
    unittest.main()
