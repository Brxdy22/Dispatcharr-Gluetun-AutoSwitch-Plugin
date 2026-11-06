"""Gluetun AutoSwitch: move Gluetun to another exit when streams stay too slow, or
when a provider keeps rejecting VOD on the current exit.

Dispatcharr only measures speed through FFmpeg, so channels on the Proxy profile
report nothing and this plugin measures for itself, without opening any extra
provider connection:

- Live: PCR timestamps in the newest buffered chunk give media seconds per wall
  second, which is the true playback speed.
- VOD: bytes sent against the title's average bitrate. Players read at their own
  pace, so a low rate alone proves nothing; unread data queued on a socket means
  the player, not the network, is holding things up, and such a window is ignored.

Refusals are ported from Gluetun Rotate (MIT, PilaScat): a login check that costs no
stream connection, and Cloudflare's block page behind a live 403. Unlike Rotate, local
proxies count as the provider, because every account here sits behind one. These two
wait for viewers to leave; slow streams and VOD rejections do not, as someone is
already affected.

Rejections come from the attempts VOD Failover already logs, so no extra logins
reach the provider. Only answers a new address can fix count: a 404 (title missing)
or 458 (connection limit) says nothing about the exit.

Switches use PUT /v1/vpn/settings, whose body holds the WireGuard private key, so
the settings are never logged or written to disk. Measured against a real Gluetun:
null leaves a field as it was, only [] clears it, and a selection equal to the
current one answers 200 "settings left unchanged" without reconnecting.
"""
import http.client
import ipaddress
import json
import logging
import os
import random
import re
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque, namedtuple

logger = logging.getLogger("plugins.gluetun_autoswitch")

PLUGIN_KEY = "gluetun_autoswitch"
# Gluetun's own server list, mounted read-only into Dispatcharr.
SERVERS_FILE = "/gluetun-servers/mullvad.json"
# Gluetun's SERVER_COUNTRIES, passed on to Dispatcharr. "USA" and "SERVER_COUNTRIES=USA"
# both work, so compose can reuse Gluetun's own line. Don't share the compose file itself:
# it holds the WireGuard key.
COUNTRIES_ENV = "GLUETUN_SERVER_COUNTRIES"
REJECT_CODE_OPTIONS = [401, 403, 451, 502, 504, *range(520, 528), 530]

DEFAULTS = {
    "auto_switch": False,
    "exits": [
        "Ashburn VA",
        "Washington DC",
        "New York NY",
        "Secaucus NJ",
        "Boston MA",
        "Raleigh NC",
        "Atlanta GA",
        "Detroit MI",
        "Chicago IL",
        "Miami FL",
        "Kansas City MO",
        "Houston TX",
        "Dallas TX",
        "McAllen TX",
        "Denver CO",
        "Salt Lake City UT",
        "Phoenix AZ",
        "Seattle WA",
        "Los Angeles CA",
        "San Jose CA",
        "San Francisco CA",
    ],
    "exit_countries": ["USA"],
    "blocked_countries": [],
    "blocked_cities": [],
    "min_speed": 0.9,
    "window_seconds": 90,
    "cooldown_minutes": 5,
    "max_switches_per_hour": 3,
    "reject_retries": 3,
    "reject_window_minutes": 15,
    "reject_codes": ["403", "520", "521", "522", "523", "524", "525", "526", "527"],
    "probe_minutes": 5,
    "probe_refusals": 2,
    "speedtest_minutes": 60,
    "speedtest_failures": 2,
    "min_download": 30,
    "min_upload": 0,
    "max_ping": 150,
    "provider_ping_factor": 2,
    "gluetun_url": "http://127.0.0.1:8000",
}
TICK_SECONDS = 10
BACKLOG_BYTES = 256 * 1024
STALE_CHUNK_SECONDS = 20
PCR_JUMP_SECONDS = 30
TS_PACKET = 188
JOURNAL_LINES = 500
HOUR = 3600
EXIT_CHECK_URL = "https://am.i.mullvad.net/json"
RELAYS_URL = "https://api.mullvad.net/www/relays/wireguard/"
RELAYS_MAX_AGE = 86400
MINUTES_BELOW = 600  # providers put minutes in the seconds field: 108, not 6493
PLAUSIBLE_MBPS = (0.3, 30)  # a real short episode implies a bitrate in this range
MIN_MOVIE_SECONDS = 2400  # shorter movie lengths are mostly placeholders like 00:20:00
ASSUMED_MOVIE_SECONDS = 10800  # too long only misses a slow stream; too short cuts healthy ones
PLUGIN_KEY = "gluetun_autoswitch"
SPEED_FIELD = "speedtest_last"
SPEED_HOST = "speed.cloudflare.com"
SPEED_DOWN_BYTES = 50_000_000  # Cloudflare answers 403 to 100 MB
SPEED_DOWN_SECONDS = 8
SPEED_UP_SECONDS = 5
SPEED_UP_BYTES = 10_000_000
SPEED_WARMUP_SECONDS = 1
SPEED_CHUNK = 65536
SPEED_RETEST_SECONDS = 300  # a failed test is confirmed soon, not an hour later
SPEED_SETTLE_SECONDS = 120  # a new exit gets its own test shortly after a switch
BASELINE_TESTS = 20
BASELINE_MINIMUM = 2
LOG_PATH = "/data/logs/dispatcharr.log"
REFUSED_STATUSES = frozenset(range(520, 528))
BLOCK_PAGE_MARKER = b"Website Access Blocked"
BLOCK_CHECK_BYTES = 16384
MAX_BLOCK_CHECKS = 3
BLOCK_RECHECK_SECONDS = 120
BLOCK_FEED_SECONDS = 1800
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
PROBE_TIMEOUT = 15
ACCOUNTS_REFRESH_SECONDS = 900
REPAIR_SECONDS = 60
MAX_REPAIRS = 5
PROXY_FORBIDDEN = re.compile(r"\bHTTP 403 from (?P<url>\S+)")
STREAM_FORBIDDEN = re.compile(
    r"Stream process error for channel (?P<channel>[0-9a-f-]{36}): .*\bHTTP Error 403\b"
)
ATTEMPT = re.compile(
    r"Connection attempt \d+/\d+ for URL: (?P<url>\S+) for channel (?P<channel>[0-9a-f-]{36})"
)
Account = namedtuple("Account", "name server_url username password user_agent")
REJECTION_LINE = re.compile(
    r"\[VOD-Failover\] Marked \w+ on account (?P<account>.+?) as bad for \d+s "
    r"\(\w+\): Streaming error: (?P<code>\d{3}) "
)


def last_pcr(data, pid=None):
    """(pid, seconds) of the newest PCR in an MPEG-TS chunk, or None."""
    size = len(data)
    if size < TS_PACKET * 2:
        return None
    start = next(
        (i for i in range(TS_PACKET) if data[i] == 0x47 and data[i + TS_PACKET] == 0x47),
        None,
    )
    if start is None:
        return None
    offset = start + ((size - start) // TS_PACKET - 1) * TS_PACKET
    while offset >= start:
        p = data[offset:offset + TS_PACKET]
        offset -= TS_PACKET
        if p[0] != 0x47 or not p[3] & 0x20 or p[4] < 7 or not p[5] & 0x10:
            continue
        packet_pid = ((p[1] & 0x1F) << 8) | p[2]
        if pid is not None and packet_pid != pid:
            continue
        base = (p[6] << 25) | (p[7] << 17) | (p[8] << 9) | (p[9] << 1) | (p[10] >> 7)
        extension = ((p[10] & 1) << 8) | p[11]
        return packet_pid, (base * 300 + extension) / 27_000_000
    return None


class LiveTracker:
    """Media seconds per wall second over the window."""

    def __init__(self):
        self.samples = deque()
        self.pid = None

    def add(self, wall, pcr, window):
        if self.samples:
            last_wall, last = self.samples[-1]
            # Ad-break resets and the 26-hour PCR wrap are not speed changes.
            if pcr < last or pcr - last > (wall - last_wall) + PCR_JUMP_SECONDS:
                self.samples.clear()
        self.samples.append((wall, pcr))
        while len(self.samples) > 2 and wall - self.samples[1][0] >= window:
            self.samples.popleft()

    def speed(self, window):
        if len(self.samples) < 2:
            return None
        first_wall, first = self.samples[0]
        last_wall, last = self.samples[-1]
        if last_wall - first_wall < window:
            return None
        return (last - first) / (last_wall - first_wall)


class VodTracker:
    """Delivered bytes against the bytes per second the title needs."""

    def __init__(self):
        self.samples = deque()

    def add(self, wall, sent, backlogged, window):
        if self.samples and sent < self.samples[-1][1]:
            self.samples.clear()  # a seek opens a new request and restarts the count
        self.samples.append((wall, sent, backlogged))
        while len(self.samples) > 2 and wall - self.samples[1][0] >= window:
            self.samples.popleft()

    def speed(self, required, window):
        if required <= 0 or len(self.samples) < 2:
            return None
        first_wall, first, _ = self.samples[0]
        last_wall, last, _ = self.samples[-1]
        if last_wall - first_wall < window:
            return None
        if any(sample[2] for sample in self.samples):
            return None
        return (last - first) / (last_wall - first_wall) / required


def _items(value):
    """The entries of a multi-select list, or of comma-separated text."""
    return value if isinstance(value, (list, tuple)) else str(value or "").split(",")


def parse_codes(text):
    """{403, 520, 521} from '403, 520-521' or ['403', '520', '521']."""
    codes = set()
    for part in _items(text):
        match = re.fullmatch(r"\s*(\d{3})(?:\s*-\s*(\d{3}))?\s*", part)
        if match:
            codes.update(range(int(match[1]), int(match[2] or match[1]) + 1))
    return codes


def parse_rejection(line, codes):
    """(account, status) when a log line is a VOD attempt refused with one of the codes."""
    match = REJECTION_LINE.search(line)
    if match and int(match["code"]) in codes:
        return match["account"], int(match["code"])
    return None


def refused_urls(lines):
    """Stream URLs answered with a 403, oldest first and without repeats."""
    attempted, refused = {}, {}
    for line in lines:
        attempt = ATTEMPT.search(line)
        if attempt:
            attempted[attempt["channel"]] = attempt["url"]
            continue
        found = STREAM_FORBIDDEN.search(line)
        if found and found["channel"] in attempted:
            refused[attempted[found["channel"]]] = None
            continue
        proxied = PROXY_FORBIDDEN.search(line)
        if proxied:
            refused[proxied["url"]] = None
    return list(refused)


def feed_of(url):
    """The last part of a stream URL: never journal the rest, it holds credentials."""
    return urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]


def fetch_status(url, agent):
    """(status, start of an error body). The stream is closed unread if it opens."""
    request = urllib.request.Request(url, headers={"User-Agent": agent} if agent else {})
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            return response.status, b""
    except urllib.error.HTTPError as error:
        return error.code, error.read(BLOCK_CHECK_BYTES) or b""
    except Exception:
        return None, b""


def direct_url(url, proxy_status):
    """The same stream on the proxy's real upstream, or None if that is unknown."""
    upstreams = proxy_status.get("upstreams") or [""]
    host = str(proxy_status.get("preferred") or upstreams[0]).split(" ")[0]
    if not host:
        return None
    return urllib.parse.urlsplit(url)._replace(scheme="http", netloc=host).geturl()


def read_proxy_status(server_url):
    try:
        with urllib.request.urlopen(f"{server_url.rstrip('/')}/__status", timeout=5) as response:
            return json.loads(response.read())
    except Exception:
        return None


def check_target(url):
    """The URL to re-check a 403 on. Through m3u-failover a repeat 403 would pause the
    whole account (measured on a real provider), so go around it to the provider; the request
    still leaves through the tunnel. None when the real address is unknown."""
    parts = urllib.parse.urlsplit(url)
    if parts.hostname not in LOCAL_HOSTS:
        return url
    status = read_proxy_status(f"{parts.scheme}://{parts.netloc}")
    return direct_url(url, status) if status else None


def probe_url(account):
    query = urllib.parse.urlencode({"username": account.username, "password": account.password})
    return f"{account.server_url.rstrip('/')}/player_api.php?{query}"


def clean_seconds(value, size=0):
    """A stored or provider length in seconds. A small number may be minutes, and the file
    size tells them apart: 198 "seconds" of a 4 GB file would be 161 Mbps. When unsure
    it reads as minutes, the safe error: too long can only hide a slow stream."""
    try:
        seconds = int(float(value or 0))
    except (TypeError, ValueError):
        return 0
    if seconds <= 0:
        return 0
    if seconds >= MINUTES_BELOW:
        return seconds
    if size > 0 and PLAUSIBLE_MBPS[0] <= size * 8 / seconds / 1_000_000 <= PLAUSIBLE_MBPS[1]:
        return seconds
    return seconds * 60


def provider_seconds(info):
    """Length from get_vod_info. HH:MM:SS is the reliable field, duration_secs often is not."""
    match = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", str(info.get("duration") or "").strip())
    if match:
        seconds = int(match[1]) * 3600 + int(match[2]) * 60 + int(match[3])
        if seconds:
            return seconds
    return clean_seconds(info.get("duration_secs"))


def movie_seconds(stored, ask_provider, size=0):
    """(seconds, where it came from). Only asks the provider when Dispatcharr can't say."""
    seconds = clean_seconds(stored, size)
    if seconds >= MIN_MOVIE_SECONDS:
        return seconds, "stored"
    seconds = ask_provider()
    if seconds >= MIN_MOVIE_SECONDS:
        return seconds, "provider"
    return ASSUMED_MOVIE_SECONDS, "assumed"


def lookup_movie_seconds(movie, profile_id):
    """One small API call for the movie being played, with no stream connection."""
    from apps.m3u.models import M3UAccountProfile
    from apps.vod.models import M3UMovieRelation
    relations = M3UMovieRelation.objects.filter(
        movie=movie, m3u_account__is_active=True, m3u_account__account_type="XC",
    ).select_related("m3u_account")
    profile = M3UAccountProfile.objects.filter(id=profile_id).first() if profile_id else None
    relation = profile and relations.filter(m3u_account_id=profile.m3u_account_id).first()
    relation = relation or relations.first()
    if relation is None:
        return 0
    account = relation.m3u_account
    query = urllib.parse.urlencode({
        "username": account.username, "password": account.password,
        "action": "get_vod_info", "vod_id": relation.stream_id,
    })
    request = urllib.request.Request(
        f"{account.server_url.rstrip('/')}/player_api.php?{query}",
        headers={"User-Agent": account.get_user_agent_string()},
    )
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            return provider_seconds(json.loads(response.read()).get("info") or {})
    except Exception:
        return 0


def load_accounts():
    from django.db import close_old_connections
    from apps.m3u.models import M3UAccount
    close_old_connections()
    try:
        return [
            Account(row.name, row.server_url, row.username, row.password, row.get_user_agent_string())
            for row in M3UAccount.objects.filter(account_type="XC", is_active=True)
            if row.server_url and row.username and row.password
        ]
    finally:
        close_old_connections()


def route(urgent, polite, watching):
    """('act' or 'hold' or '', causes). Polite causes wait until nobody is watching."""
    if urgent:
        return "act", urgent + polite
    if polite:
        return ("hold" if watching else "act"), polite
    return "", []


class RejectionTracker:
    """Refused attempts per account on the current exit."""

    def __init__(self):
        self.seen = {}

    def add(self, account, now):
        self.seen.setdefault(account, []).append(now)

    def counts(self, now, window):
        self.seen = {
            account: kept
            for account, moments in self.seen.items()
            if (kept := [moment for moment in moments if now - moment < window])
        }
        return {account: len(moments) for account, moments in self.seen.items()}

    def clear(self):
        self.seen = {}


class LogTail:
    """New lines of a log that gets rotated. Starts at the end: old lines are history."""

    def __init__(self, path):
        self.path = path
        self.inode = None
        self.offset = 0

    def read(self):
        try:
            info = os.stat(self.path)
        except OSError:
            return []
        if self.inode is None:
            self.inode, self.offset = info.st_ino, info.st_size
            return []
        if info.st_ino != self.inode or info.st_size < self.offset:
            self.inode, self.offset = info.st_ino, 0
        with open(self.path, "rb") as handle:
            handle.seek(self.offset)
            data = handle.read()
        complete = data.rfind(b"\n") + 1  # leave a half-written line for the next read
        self.offset += complete
        return data[:complete].decode("utf-8", "replace").splitlines()


def parse_exits(text):
    return [str(city).strip().lower() for city in _items(text) if str(city).strip()]


def next_exit(current, exits):
    """The allowed exit after the current one, or None when there is nowhere to go."""
    current = [city.strip().lower() for city in current or []]
    if not exits:
        return None
    position = min((exits.index(city) for city in current if city in exits), default=-1)
    ordered = exits[position + 1:] + exits[:position + 1]
    for city in ordered:
        if city not in current:
            return city
    return None


def needs_relays(countries, cities, blocked_countries, blocked_cities):
    """Whether a block can only be honoured by knowing which city is in which country."""
    return bool(blocked_countries and cities) or bool(blocked_cities and not cities and countries)


def plan_move(current_countries, current_cities, countries, cities,
              blocked_countries=(), blocked_cities=(), relays=None, choose=random.choice):
    """(countries, cities, label) to send to Gluetun, or None when there is nowhere to go.

    Listed cities win and clear the country filter: Gluetun accepts a city and country
    that match no server, then has no tunnel at all. With no cities it picks a random
    server: a new country when there are several, else the same one again, in other
    capitals because Gluetun ignores identical settings. Gluetun cannot exclude a city,
    so a blocked city makes the plugin pick the country's city itself from relays.
    """
    if cities:
        banned = set(blocked_cities)
        for country in blocked_countries:
            banned.update((relays or {}).get(country, []))
        allowed = [city for city in cities if city not in banned]
        city = next_exit(current_cities, allowed)
        return ([], [city], city) if city else None
    current = [city.strip().lower() for city in current_cities or []]
    allowed = [country for country in countries if country not in blocked_countries]
    if not allowed:
        return None
    if blocked_cities:
        here = list(current_countries or []) or [
            country for country, names in (relays or {}).items() if set(names) & set(current)
        ]
        first = next_exit(here, allowed)
        ordered = [first] * bool(first) + [c for c in allowed if c != first]
        for country in ordered:
            names = [
                city for city in (relays or {}).get(country, [])
                if city not in blocked_cities and city not in current
            ]
            if names:
                city = choose(sorted(names))
                return [], [city], city
        return None
    existing = list(current_countries or [])
    country = next_exit(existing, allowed) or allowed[0]
    return ([country.upper()] if existing == [country] else [country]), [], country


def held_back(switches, now, cooldown_seconds, per_hour):
    """Why a switch must wait, or '' when it may go ahead."""
    recent = [moment for moment in switches if now - moment < HOUR]
    if recent and now - max(recent) < cooldown_seconds:
        return "cooling down after the last switch"
    if len(recent) >= per_hour:
        return "hourly limit reached: the provider may be the problem, not the exit"
    return ""


def backlog_from_proc(text):
    """Largest unread or unsent queue on an open socket, from /proc/net/tcp."""
    largest = 0
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 5 or fields[3] not in ("01", "08"):  # ESTABLISHED, CLOSE_WAIT
            continue
        tx_queue, rx_queue = (int(value, 16) for value in fields[4].split(":"))
        address = socket.inet_ntoa(struct.pack("<I", int(fields[2].split(":")[0], 16)))
        ip = ipaddress.ip_address(address)
        client_facing = ip.is_private and not ip.is_loopback
        largest = max(largest, rx_queue, tx_queue if client_facing else 0)
    return largest


def read_backlog():
    try:
        with open("/proc/net/tcp", encoding="ascii") as handle:
            return backlog_from_proc(handle.read())
    except OSError:
        return BACKLOG_BYTES  # unknown: assume the player is fine rather than switch


def _text(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


class Gluetun:
    def __init__(self, base_url):
        self.base_url = str(base_url).rstrip("/")

    def _request(self, method, body=None):
        request = urllib.request.Request(
            f"{self.base_url}/v1/vpn/settings",
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            detail = error.read(300).decode("utf-8", "replace")
            raise RuntimeError(f"Gluetun answered {error.code}: {detail}") from None

    def settings(self):
        return json.loads(self._request("GET"))

    def selection(self):
        selection = self.settings()["provider"]["server_selection"]
        return selection.get("countries") or [], selection.get("cities") or []

    def move_to(self, countries, cities):
        settings = self.settings()
        selection = settings["provider"]["server_selection"]
        selection["countries"] = countries
        selection["cities"] = cities
        answer = self._request("PUT", settings)
        if b"unchanged" in answer:
            raise RuntimeError("Gluetun left its settings unchanged and did not reconnect")
        if answer.strip() == b"crashed":
            raise RuntimeError("Gluetun found no server for this selection")


def parse_relays(rows):
    """{country: [cities]} in Gluetun's spelling, which only drops Mullvad's comma."""
    relays = {}
    for row in rows:
        if row.get("active", True):
            cities = relays.setdefault(str(row["country_name"]).lower(), [])
            city = str(row["city_name"]).replace(",", "").lower()
            if city not in cities:
                cities.append(city)
    return relays


def load_relays(store):
    """Mullvad's cities per country, from a daily cache; a stale copy beats none."""
    cached = store.relays()
    if cached.get("relays") and time.time() - float(cached.get("at") or 0) < RELAYS_MAX_AGE:
        return cached["relays"]
    try:
        with urllib.request.urlopen(RELAYS_URL, timeout=15) as response:
            relays = parse_relays(json.loads(response.read()))
        store.set_relays({"at": time.time(), "relays": relays})
        return relays
    except Exception:
        return cached.get("relays")


class RateMeter:
    """Mbps after a warm-up, because TLS and TCP slow start would drag the average down."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.start = clock()
        self.began = None
        self.counted = 0
        self.last = self.start

    def add(self, size):
        self.last = self.clock()
        if self.began is None:
            if self.last - self.start >= SPEED_WARMUP_SECONDS:
                self.began = self.last
        else:
            self.counted += size

    def elapsed(self):
        return self.clock() - self.start

    def mbps(self):
        if self.began is None or self.last <= self.began:
            return None
        return self.counted * 8 / (self.last - self.began) / 1_000_000


def measure_download():
    """One connection on purpose: a stream gets one, so this is the speed it can reach."""
    url = f"https://{SPEED_HOST}/__down?bytes={SPEED_DOWN_BYTES}"
    request = urllib.request.Request(url, headers={"User-Agent": "gluetun-autoswitch"})
    meter = RateMeter()
    try:
        while meter.elapsed() < SPEED_DOWN_SECONDS:
            with urllib.request.urlopen(request, timeout=15) as response:
                while meter.elapsed() < SPEED_DOWN_SECONDS:
                    chunk = response.read(SPEED_CHUNK)
                    if not chunk:
                        break
                    meter.add(len(chunk))
    except Exception as error:  # a dropped connection still leaves what was measured
        logger.warning("Gluetun AutoSwitch: download test stopped: %s", error)
    return meter.mbps()


def upload_mbps(rounds):
    """Mbps from (bytes, seconds) rounds, leaving out the slow first one when there are more."""
    counted = rounds[1:] or rounds
    seconds = sum(taken for _, taken in counted)
    return sum(size for size, _ in counted) * 8 / seconds / 1_000_000 if seconds > 0 else None


def measure_upload():
    """Times each upload to the server's reply. Timing send() alone reads about twice the
    real speed (measured), because it only proves the data reached a local buffer."""
    connection = http.client.HTTPSConnection(SPEED_HOST, timeout=15)
    body = b"0" * SPEED_UP_BYTES
    headers = {"User-Agent": "gluetun-autoswitch", "Content-Type": "application/octet-stream"}
    rounds = []
    started = time.monotonic()
    try:
        while time.monotonic() - started < SPEED_UP_SECONDS:
            begun = time.monotonic()
            connection.request("POST", "/__up", body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}")
            rounds.append((SPEED_UP_BYTES, time.monotonic() - begun))
    except Exception as error:
        logger.warning("Gluetun AutoSwitch: upload test stopped: %s", error)
    finally:
        connection.close()
    return upload_mbps(rounds) if rounds else None


def connect_ms(host, port, tries=3):
    """Best TCP handshake time. No login and no stream, so it uses no provider slot."""
    best = None
    for _ in range(tries):
        started = time.monotonic()
        try:
            socket.create_connection((host, port), timeout=5).close()
        except OSError:
            continue
        taken = (time.monotonic() - started) * 1000
        best = taken if best is None else min(best, taken)
    return best


def provider_target(server_url, proxy_status):
    """(host, port) of the real provider behind an account's server URL."""
    parts = urllib.parse.urlsplit(server_url)
    if parts.hostname in LOCAL_HOSTS:
        upstreams = (proxy_status or {}).get("upstreams") or [""]
        name = str((proxy_status or {}).get("preferred") or upstreams[0]).split(" ")[0]
        if not name:
            return None
        parts = urllib.parse.urlsplit(f"//{name}")
    return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def provider_pings(accounts):
    pings = {}
    for account in accounts:
        local = urllib.parse.urlsplit(account.server_url).hostname in LOCAL_HOSTS
        target = provider_target(
            account.server_url, read_proxy_status(account.server_url) if local else None,
        )
        pings[account.name] = connect_ms(*target) if target else None
    return pings


def local_stamp():
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        from core.models import CoreSettings
        now = datetime.now(ZoneInfo(CoreSettings.get_system_time_zone()))
    except Exception:
        now = None
    return (now.strftime("%b %-d, %-I:%M %p") if now else time.strftime("%b %-d, %-I:%M %p"))


def format_speed(result):
    def mbps(value):
        return "failed" if value is None else f"{value:.0f} Mbps"

    def ms(value):
        return "failed" if value is None else f"{value:.0f} ms"

    where = result.get("city") or "unknown exit"
    if result.get("ip"):
        where = f"{where} ({result['ip']})"
    lines = [
        f"{result['when']} - {where}",
        f"Download {mbps(result.get('download'))} - Upload {mbps(result.get('upload'))}"
        f" - Ping {ms(result.get('ping'))}",
    ]
    if result.get("providers"):
        lines.append("Providers: " + ", ".join(
            f"{name} {ms(value)}" for name, value in sorted(result["providers"].items())
        ))
    if result.get("streams"):
        lines.append(f"{result['streams']} stream(s) were playing, so speeds may read low.")
    if "problems" in result:
        problems = result["problems"]
        lines.append("Below minimum: " + "; ".join(problems) if problems else "Health: good")
    return "\n".join(lines)


def judge(result, settings, usual):
    """What in a speed test falls short. A failed measurement is no verdict, and a provider
    that can't be reached is its own problem: no exit fixes that."""
    problems = []
    for key, name, limit in (("download", "download", "min_download"), ("upload", "upload", "min_upload")):
        minimum, value = float(settings[limit]), result.get(key)
        if minimum > 0 and value is not None and value < minimum:
            problems.append(f"{name} {value:.0f} Mbps (minimum {minimum:.0f})")
    most, ping = float(settings["max_ping"]), result.get("ping")
    if most > 0 and ping is not None and ping > most:
        problems.append(f"ping {ping:.0f} ms (limit {most:.0f})")
    factor = float(settings["provider_ping_factor"])
    if factor > 0:
        for name, value in sorted((result.get("providers") or {}).items()):
            limit = usual.get(name, 0) * factor
            if value is not None and limit and value > limit:
                problems.append(f"{name} ping {value:.0f} ms (usually {usual[name]:.0f})")
    return problems


def usual_pings(entries):
    """Median provider ping over recent healthy tests, from journal entries oldest first.
    A test with problems is left out, so a bad exit can't raise its own limit."""
    samples = {}
    for entry in entries:
        if entry.get("event") == "speed_test" and not entry.get("problems"):
            for name, value in (entry.get("providers") or {}).items():
                if value is not None:
                    samples.setdefault(name, []).append(value)
    usual = {}
    for name, values in samples.items():
        recent = sorted(values[-BASELINE_TESTS:])
        if len(recent) >= BASELINE_MINIMUM:
            usual[name] = recent[len(recent) // 2]
    return usual


def run_speed_test(store, accounts, settings):
    info = exit_info()
    result = {
        "when": local_stamp(),
        "city": info.get("city"),
        "ip": info.get("ip"),
        "ping": connect_ms(SPEED_HOST, 443, tries=5),
        "download": measure_download(),
        "upload": measure_upload(),
        "providers": provider_pings(accounts),
        "streams": len(store.status().get("streams", [])),
    }
    result["problems"] = judge(result, settings, usual_pings(store.entries()))
    result["unclear"] = result["download"] is None or result["ping"] is None
    result["text"] = format_speed(result)
    store.set_speed({"at": time.time(), "text": result["text"], "result": result})
    store.log("speed_test", **{k: v for k, v in result.items() if k not in ("when", "text")})
    return result


def publish_speed(text):
    """Show the result in the plugin form. update() skips the save hooks, and the row
    lock keeps a settings save from another worker from being lost."""
    from django.db import close_old_connections, transaction
    from apps.plugins.models import PluginConfig
    close_old_connections()
    try:
        with transaction.atomic():
            config = PluginConfig.objects.select_for_update().filter(key=PLUGIN_KEY).first()
            if config:
                settings = {**(config.settings or {}), SPEED_FIELD: text}
                PluginConfig.objects.filter(pk=config.pk).update(settings=settings)
    finally:
        close_old_connections()


def exit_info():
    try:
        with urllib.request.urlopen(EXIT_CHECK_URL, timeout=10) as response:
            data = json.loads(response.read())
        return {"ip": data.get("ip"), "city": data.get("city"), "mullvad": data.get("mullvad_exit_ip")}
    except Exception as error:
        return {"error": type(error).__name__}


class Store:
    """The journal and switch times, shared by the service and the action buttons."""

    def __init__(self, data_dir):
        self.journal_path = os.path.join(data_dir, "journal.jsonl")
        self.state_path = os.path.join(data_dir, "state.json")
        self.status_path = os.path.join(data_dir, "status.json")
        self.relays_path = os.path.join(data_dir, "relays.json")
        self.speed_path = os.path.join(data_dir, "speedtest.json")

    def _read_json(self, path):
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {}

    def _write_json(self, path, value):
        temporary = f"{path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(value, handle)
        os.replace(temporary, path)

    def switches(self):
        return [float(moment) for moment in self._read_json(self.state_path).get("switches", [])]

    def add_switch(self, moment):
        recent = [value for value in self.switches() if moment - value < HOUR] + [moment]
        self._write_json(self.state_path, {"switches": recent})

    def speed_text(self):
        return self._read_json(self.speed_path).get("text", "")

    def speed_at(self):
        return float(self._read_json(self.speed_path).get("at") or 0)

    def entries(self):
        found = []
        for line in self.recent(JOURNAL_LINES):
            try:
                found.append(json.loads(line))
            except ValueError:
                continue
        return found

    def set_speed(self, value):
        self._write_json(self.speed_path, value)

    def relays(self):
        return self._read_json(self.relays_path)

    def set_relays(self, value):
        self._write_json(self.relays_path, value)

    def status(self):
        return self._read_json(self.status_path)

    def set_status(self, value):
        self._write_json(self.status_path, value)

    def log(self, event, **details):
        entry = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, **details}
        logger.warning("Gluetun AutoSwitch: %s", entry)
        try:
            with open(self.journal_path, encoding="utf-8") as handle:
                lines = handle.readlines()[-(JOURNAL_LINES - 1):]
        except OSError:
            lines = []
        lines.append(json.dumps(entry) + "\n")
        temporary = f"{self.journal_path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        os.replace(temporary, self.journal_path)

    def recent(self, count=10):
        try:
            with open(self.journal_path, encoding="utf-8") as handle:
                return [line.strip() for line in handle.readlines()[-count:]]
        except OSError:
            return []


def switch_exit(settings, store, cause, left=None):
    """Move to the next allowed exit. Returns the city, or None if nothing moved."""
    gluetun = Gluetun(settings["gluetun_url"])
    countries, cities = gluetun.selection()
    allowed_countries = parse_exits(settings["exit_countries"])
    allowed_cities = parse_exits(settings["exits"])
    blocked_countries = parse_exits(settings["blocked_countries"])
    blocked_cities = parse_exits(settings["blocked_cities"])
    relays = None
    if needs_relays(allowed_countries, allowed_cities, blocked_countries, blocked_cities):
        relays = load_relays(store)
        if not relays:
            # Moving blind could land on an exit the user blocked.
            store.log("no_exit", detail="could not read Mullvad's city list to honour the blocks")
            return None
    plan = plan_move(
        countries, cities, allowed_countries, allowed_cities,
        blocked_countries, blocked_cities, relays,
    )
    if plan is None:
        store.log("no_exit", detail="no other allowed exit", countries=countries, cities=cities)
        return None
    new_countries, new_cities, label = plan
    store.add_switch(time.time())  # a failed attempt still counts towards the limits
    try:
        gluetun.move_to(new_countries, new_cities)
    except Exception as error:
        store.log("failed", target=label, detail=str(error)[:300])
        return None
    store.log(
        "switched", cause=cause, before={"countries": countries, "cities": cities},
        after=label, left=left,
    )
    return label


class Service:
    def __init__(self, context):
        self.context = context
        self.store = Store(context["data_dir"])
        self.live = {}
        self.vod = {}
        self.required = {}
        self.length_source = {}
        self.rejections = RejectionTracker()
        self.log_tail = LogTail(LOG_PATH)
        self.announced = ""
        self.accounts = []
        self.accounts_at = 0.0
        self.probe_at = 0.0
        self.refused_streak = 0
        self.blocked = {}
        self.block_check_at = 0.0
        self.block_seen = {}
        self.repairs = None
        self.repair_at = 0.0
        self.speed_due = None
        self.speed_streak = 0
        self.speed_cause = []

    def settings(self):
        getter = self.context.get("get_settings")
        stored = getter() if callable(getter) else self.context.get("settings")
        return {**DEFAULTS, **(stored or {})}

    def run(self, stop_event):
        self.store.log("started")
        while not stop_event.is_set():
            try:
                self.tick(stop_event)
            except Exception:
                logger.exception("Gluetun AutoSwitch tick failed")
            stop_event.wait(TICK_SECONDS)
        self.store.log("stopped")

    def tick(self, stop_event):
        from core.utils import RedisClient
        settings = self.settings()
        window = float(settings["window_seconds"])
        now = time.time()
        readings = self.read_live(RedisClient.get_buffer(), now, window)
        readings += self.read_vod(RedisClient.get_client(), now, window)
        minimum = float(settings["min_speed"])
        self.check_tunnel(settings, now)
        self.sync_speed(settings)
        slow = [r for r in readings if r["speed"] is not None and r["speed"] < minimum]
        urgent = [f"{r['name']} at {r['speed']:.2f}x" for r in slow]
        lines = self.log_tail.read()
        counts = self.read_rejections(settings, now, lines)
        retries = max(int(settings["reject_retries"]), 1)
        urgent += [
            f"{account} rejected {count} times"
            for account, count in counts.items() if count >= retries
        ]
        polite = self.check_blocked(lines, now) + self.probe_accounts(settings, now)
        polite += self.speed_health(settings, now, bool(readings))
        self.store.set_status({
            "at": now, "streams": readings, "rejections": counts,
            "login_refusal_rounds": self.refused_streak,
            "failed_speed_tests": self.speed_streak,
            "blocked_sources": [feed_of(url) for url in self.blocked],
            "auto_switch": bool(settings["auto_switch"]),
        })
        action, causes = route(urgent, polite, bool(readings))
        if action == "act":
            self.act(settings, causes, now, stop_event)
        elif action == "hold":
            self.announce("viewers", "held_back", reason="someone is watching", causes=causes)
        else:
            self.announced = ""

    def speed_health(self, settings, now, watching):
        """Polite causes from the scheduled test, which only runs when nobody is watching:
        it competes with streams, and the slow-stream check covers active viewing."""
        minutes = float(settings["speedtest_minutes"])
        if minutes <= 0:
            self.speed_due, self.speed_streak, self.speed_cause = None, 0, []
            return []
        if self.speed_due is None:
            self.speed_due = self.store.speed_at() + minutes * 60
        if not watching and now >= self.speed_due:
            self.scheduled_test(settings, now, minutes)
        return list(self.speed_cause)

    def scheduled_test(self, settings, now, minutes):
        result = run_speed_test(self.store, self.current_accounts(now), settings)
        if result["unclear"]:
            self.speed_due = now + SPEED_RETEST_SECONDS
        elif result["problems"]:
            self.speed_streak += 1
            self.speed_due = now + SPEED_RETEST_SECONDS
            if self.speed_streak >= max(int(settings["speedtest_failures"]), 1):
                self.speed_cause = [f"speed test failed: {'; '.join(result['problems'])}"]
        else:
            self.speed_streak, self.speed_cause = 0, []
            self.speed_due = now + minutes * 60

    def sync_speed(self, settings):
        """The box is editable and a Save from an open page can restore an old result."""
        text = self.store.speed_text()
        if text and settings.get(SPEED_FIELD) != text:
            publish_speed(text)

    def read_rejections(self, settings, now, lines):
        codes = parse_codes(settings["reject_codes"])
        window = float(settings["reject_window_minutes"]) * 60
        for line in lines:
            found = parse_rejection(line, codes)
            if found:
                self.rejections.add(found[0], now)
                self.store.log("rejected", account=found[0], status=found[1])
        return self.rejections.counts(now, window)

    def current_accounts(self, now):
        if now - self.accounts_at >= ACCOUNTS_REFRESH_SECONDS:
            self.accounts = load_accounts()
            self.accounts_at = now
        return self.accounts

    def probe_accounts(self, settings, now):
        """Polite causes from the login check, which costs no stream connection."""
        minutes = float(settings["probe_minutes"])
        needed = max(int(settings["probe_refusals"]), 1)
        if minutes <= 0:
            self.refused_streak = 0
            return []
        if now - self.probe_at >= minutes * 60:
            self.probe_at = now
            self.run_probe(self.current_accounts(now))
        if self.refused_streak >= needed:
            return [f"login refused in {self.refused_streak} checks in a row"]
        return []

    def run_probe(self, accounts):
        refused, unclear = [], False
        for account in accounts:
            status = fetch_status(probe_url(account), account.user_agent)[0]
            if status in REFUSED_STATUSES:
                refused.append(f"{account.name}: HTTP {status}")
            # m3u-failover answers 503 while an account is paused, which is no verdict.
            unclear = unclear or status is None or status == 503
        if refused:
            self.refused_streak += 1
            self.store.log("refused", streak=self.refused_streak, probes=refused)
        elif not unclear:
            if self.refused_streak:
                self.store.log("accepted", after_rounds=self.refused_streak)
            self.refused_streak = 0

    def check_blocked(self, lines, now):
        """Polite causes from 403s on our own accounts that carry Cloudflare's block page."""
        new = [url for url in refused_urls(lines) if url not in self.blocked]
        if new:
            self.store.log("forbidden", feeds=[feed_of(url) for url in new])
        self.block_seen = {u: t for u, t in self.block_seen.items() if now - t < BLOCK_FEED_SECONDS}
        new = [url for url in new if url not in self.block_seen]
        due = now - self.block_check_at >= BLOCK_RECHECK_SECONDS
        candidates = (list(self.blocked) if due else []) + new
        if candidates:
            accounts = self.current_accounts(now)
            if due:
                self.block_check_at = now
            for url in candidates[:MAX_BLOCK_CHECKS]:
                account = next((a for a in accounts if url.startswith(a.server_url.rstrip("/") + "/")), None)
                if account is None:
                    continue
                self.block_seen[url] = now
                target = check_target(url)
                if target is None:
                    continue
                status, body = fetch_status(target, account.user_agent)
                if status == 403 and BLOCK_PAGE_MARKER in body:
                    if url not in self.blocked:
                        self.store.log("blocked", account=account.name, feed=feed_of(url))
                    self.blocked[url] = account.name
                elif url in self.blocked:
                    del self.blocked[url]
                    self.store.log("unblocked", feed=feed_of(url), status=status)
        return [f"{name} blocked {feed_of(url)}" for url, name in self.blocked.items()]

    def check_tunnel(self, settings, now):
        """After a switch, bring back a tunnel that never returned. A settings change
        revives a stopped or crashed Gluetun, so no control-server key is needed."""
        if self.repairs is None or now < self.repair_at:
            return
        if exit_info().get("ip"):
            self.repairs = None
            return
        if self.repairs >= MAX_REPAIRS:
            self.store.log("repair_gave_up", attempts=self.repairs)
            self.repairs = None
            return
        self.repairs += 1
        self.repair_at = now + REPAIR_SECONDS
        switch_exit(settings, self.store, cause="the tunnel did not come back")

    def read_live(self, redis, now, window):
        from apps.proxy.live_proxy.redis_keys import RedisKeys
        readings, seen = [], set()
        for key in redis.scan_iter("live:channel:*:metadata", count=200):
            channel = _text(key).split(":")[2]
            seen.add(channel)
            if not redis.scard(RedisKeys.clients(channel)):
                self.live.pop(channel, None)
                continue
            index = redis.get(RedisKeys.buffer_index(channel))
            chunk = redis.get(RedisKeys.buffer_chunk(channel, int(index))) if index else None
            tracker = self.live.setdefault(channel, LiveTracker())
            found = last_pcr(chunk, tracker.pid) if chunk else None
            if found:
                tracker.pid = found[0]
                stamp = redis.zscore(RedisKeys.chunk_timestamps(channel), _text(index))
                # A chunk's own time keeps slow channels accurate; a stalled feed
                # has no new chunk, so real time has to keep moving instead.
                wall = stamp if stamp and now - stamp <= STALE_CHUNK_SECONDS else now
                tracker.add(wall, found[1], window)
            speed = tracker.speed(window)
            readings.append({"kind": "live", "name": f"channel {channel}", "speed": speed})
        for channel in set(self.live) - seen:
            del self.live[channel]
        return readings

    def read_vod(self, redis, now, window):
        readings, seen = [], set()
        backlogged = read_backlog() >= BACKLOG_BYTES
        for key in redis.scan_iter("vod_persistent_connection:*", count=200):
            session = _text(key).split(":", 1)[1]
            state = {_text(a): _text(b) for a, b in redis.hgetall(key).items()}
            if int(state.get("active_streams") or 0) < 1:
                continue
            seen.add(session)
            required = self.required_rate(session, state)
            tracker = self.vod.setdefault(session, VodTracker())
            tracker.add(now, int(state.get("bytes_sent") or 0), backlogged, window)
            readings.append({
                "kind": "vod",
                "name": state.get("content_name") or session,
                "speed": tracker.speed(required, window),
                "length": self.length_source.get(session),
            })
        for session in set(self.vod) - seen:
            del self.vod[session]
            self.required.pop(session, None)
            self.length_source.pop(session, None)
        return readings

    def required_rate(self, session, state):
        if session in self.required:
            return self.required[session]
        from django.db import close_old_connections
        from apps.vod.models import Episode, Movie
        size = int(state.get("total_content_size") or 0) or int(state.get("content_length") or 0)
        is_episode = state.get("content_obj_type") == "episode"
        model = Episode if is_episode else Movie
        close_old_connections()
        try:
            item = model.objects.filter(uuid=state.get("content_uuid")).first()
            stored = getattr(item, "duration_secs", None)
            if is_episode:
                duration, source = clean_seconds(stored, size), "stored"
            else:
                duration, source = movie_seconds(
                    stored,
                    lambda: lookup_movie_seconds(item, state.get("m3u_profile_id")) if item else 0,
                    size,
                )
        finally:
            close_old_connections()
        self.required[session] = size / duration if duration > 0 else 0
        self.length_source[session] = source if duration > 0 else None
        return self.required[session]

    def act(self, settings, causes, now, stop_event):
        reason = held_back(
            self.store.switches(), now,
            float(settings["cooldown_minutes"]) * 60, int(settings["max_switches_per_hour"]),
        )
        if reason:
            self.announce(f"held:{reason}", "held_back", reason=reason, causes=causes)
            return
        if not settings["auto_switch"]:
            self.announce("observe", "would_switch", causes=causes, exit=exit_info())
            return
        self.announced = ""
        left = exit_info()
        moved = switch_exit(settings, self.store, cause=causes, left=left)
        self.repairs, self.repair_at = 0, now + REPAIR_SECONDS
        if moved:
            self.live.clear()
            self.vod.clear()
            self.rejections.clear()
            self.blocked.clear()
            self.refused_streak = 0
            self.probe_at = now
            self.speed_streak, self.speed_cause = 0, []
            self.speed_due = now + SPEED_SETTLE_SECONDS
            stop_event.wait(20)
            arrived = exit_info()
            self.store.log("exit", **arrived)
            if arrived.get("ip") and arrived.get("ip") == left.get("ip"):
                # Gluetun picks at random, so it can land on the same server again.
                self.store.log("not_moved", detail="the exit address did not change")
                switch_exit(settings, self.store, cause="same address, trying once more", left=left)
                stop_event.wait(20)
                self.store.log("exit", **exit_info())

    def announce(self, key, event, **details):
        if key != self.announced:  # one journal line per episode, not one per tick
            self.announced = key
            self.store.log(event, **details)


def read_servers(path=SERVERS_FILE):
    """{country: [cities]} from Gluetun's server list, or {} when it can't be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            servers = json.load(handle)["servers"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    found = {}
    for server in servers:
        if server.get("country") and server.get("city"):
            found.setdefault(server["country"], set()).add(server["city"])
    return {country: sorted(cities) for country, cities in found.items()}


def enabled_countries(text):
    """Country names from SERVER_COUNTRIES, with or without its 'SERVER_COUNTRIES=' prefix."""
    return [c.strip() for c in str(text or "").split("=")[-1].split(",") if c.strip()]


def _options(values, saved):
    """Options for a list. Saved values stay offered even when they've left the list, as
    Dispatcharr refuses to save a multi-select holding a value it doesn't offer."""
    return [{"value": v, "label": v} for v in dict.fromkeys([*values, *saved])]


def build_fields(fields, servers, enabled, settings):
    """Fields with their lists filled. Cities follow the saved Allowed countries."""
    fields = json.loads(json.dumps(fields))
    saved = lambda field: settings.get(field["id"], field.get("default"))  # noqa: E731
    names = lambda field: [str(v).strip() for v in _items(saved(field)) if str(v).strip()]  # noqa: E731
    by_name = {country.lower(): country for country in servers}
    countries = [by_name.get(c.lower(), c) for c in enabled] or sorted(servers)
    allowed = next(f for f in fields if f["id"] == "exit_countries")
    chosen = {c.lower() for c in names(allowed)}
    shown = [c for c in countries if c.lower() in chosen] or countries
    cities = sorted({city for country in shown for city in servers.get(country, [])})
    for field in fields:
        if field["id"] in ("exit_countries", "blocked_countries"):
            field["options"] = _options(countries, names(field))
        elif field["id"] in ("exits", "blocked_cities"):
            field["options"] = _options(cities, names(field))
        elif field["id"] == "reject_codes":
            codes = sorted(parse_codes(saved(field)) | set(REJECT_CODE_OPTIONS))
            field["options"] = _options([str(code) for code in codes], [])
    return fields


def _saved_settings():
    from apps.plugins.models import PluginConfig

    config = PluginConfig.objects.filter(key=PLUGIN_KEY).first()
    return (config.settings if config else None) or {}


class Plugin:
    name = "Gluetun AutoSwitch"
    version = "1.6.0"
    description = "Moves Gluetun to another VPN exit when streams stay too slow or a provider refuses the exit."

    @property
    def fields(self):
        """Read when the plugin loads, so Reload Plugin updates the lists."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.json")
        with open(path, encoding="utf-8") as handle:
            fields = json.load(handle)["fields"]
        try:
            settings = _saved_settings()
        except Exception:
            logger.exception("Could not read the saved settings for the country and city lists")
            settings = {}
        return build_fields(fields, read_servers(), enabled_countries(os.environ.get(COUNTRIES_ENV)), settings)

    def on_leader_acquired(self, context):
        service = Service(context)
        context["start_service"](service.run, name="gluetun_autoswitch")

    def run(self, action, params=None, context=None):
        context = context or {}
        settings = {**DEFAULTS, **(context.get("settings") or {})}
        store = Store(context["data_dir"])
        if action == "status":
            status = store.status()
            countries, cities = Gluetun(settings["gluetun_url"]).selection()
            age = time.time() - float(status.get("at") or 0)
            return {
                "status": "ok",
                "message": "Monitor running." if age < 60 else "Monitor is NOT running.",
                "auto_switch": bool(settings["auto_switch"]),
                "exit": exit_info(),
                "gluetun_countries": countries,
                "gluetun_cities": cities,
                "streams": status.get("streams", []),
                "rejections": status.get("rejections", {}),
                "login_refusal_rounds": status.get("login_refusal_rounds", 0),
                "failed_speed_tests": status.get("failed_speed_tests", 0),
                "blocked_sources": status.get("blocked_sources", []),
                "recent": store.recent(),
            }
        if action == "change_exit":
            before = exit_info().get("ip")
            target = switch_exit(settings, store, cause="manual", left={"ip": before})
            if not target:
                return {"status": "error", "message": "Did not move. See Check status."}
            now_at = {}
            for _ in range(10):
                time.sleep(2)
                now_at = exit_info()
                if now_at.get("ip") and now_at["ip"] != before:
                    store.log("exit", **now_at)
                    return {"status": "ok", "message": f"Moved to {now_at.get('city')} ({now_at['ip']})."}
            if now_at.get("ip"):
                store.log("not_moved", detail="the exit address did not change")
                return {"status": "error", "message": f"Reconnected to {target}, but on the same exit address. Press again."}
            return {"status": "error", "message": f"Asked for {target}, but the tunnel is not back yet. See Check status."}
        if action == "speed_test":
            text = run_speed_test(store, load_accounts(), settings)["text"]
            publish_speed(text)
            return {"status": "ok", "message": text}
        if action == "ask_provider":
            answers = {
                account.name: fetch_status(probe_url(account), account.user_agent)[0]
                for account in load_accounts()
            }
            return {"status": "ok", "message": "Asked every account. Nothing was moved.", "answers": answers}
        return {"status": "error", "message": f"Unknown action: {action}"}
