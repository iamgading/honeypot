import argparse
import asyncio
import ctypes
import datetime
import functools
import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "ip_log.db")
PID_FILE = os.path.join(BASE_DIR, "honeypot.pid")
STOP_FLAG = os.path.join(BASE_DIR, "stop.flag")
TEST_FLAG = os.path.join(BASE_DIR, "test.flag")
LOG_FILE = os.path.join(BASE_DIR, "honeypot.log")

DEFAULT_PORTS = "2222,4444,8081"
RULE_PREFIX = "HoneypotBlock"
READ_CAP = 256
READ_TIMEOUT = 5.0
REPEAT_QUIET_SECONDS = 10.0
STALE_TEST_SECONDS = 15.0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def enable_ansi():
    global RED, GREEN, YELLOW, DIM, BOLD, RESET
    if not sys.stdout.isatty():
        RED = GREEN = YELLOW = DIM = BOLD = RESET = ""
        return
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if handle and k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle, mode.value | 0x4)
        except Exception:
            pass


def now_ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def valid_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def parse_ports(text):
    ports = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
        except ValueError:
            raise SystemExit(f"port tidak valid: {part}")
        if not 1 <= p <= 65535:
            raise SystemExit(f"port di luar rentang: {p}")
        if p in ports:
            raise SystemExit(f"port duplikat: {p}")
        ports.append(p)
    if not ports:
        raise SystemExit("minimal satu port diperlukan")
    return ports


def get_local_ips():
    ips = {"127.0.0.1"}
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return {ip for ip in ips if valid_ip(ip)}


def db_connect():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db():
    conn = db_connect()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS attacker_log ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts TEXT NOT NULL, "
        "ip TEXT NOT NULL, "
        "port INTEGER NOT NULL, "
        "data BLOB, "
        "test INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_log_ip ON attacker_log(ip)")
    conn.execute("CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY, added_at TEXT)")
    conn.commit()
    conn.close()


def seed_whitelist():
    conn = db_connect()
    row = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()
    if row[0] == 0:
        for ip in get_local_ips():
            conn.execute("INSERT OR IGNORE INTO whitelist (ip, added_at) VALUES (?, ?)", (ip, now_ts()))
        conn.commit()
    conn.close()


def write_pid(ports):
    with open(PID_FILE, "w") as f:
        json.dump({"pid": os.getpid(), "ports": ports, "started": now_ts()}, f)


def read_pid():
    try:
        with open(PID_FILE) as f:
            info = json.load(f)
        if isinstance(info.get("pid"), int):
            return info
    except (OSError, ValueError):
        pass
    return None


def is_running():
    info = read_pid()
    if not info:
        return None
    pid = info["pid"]
    alive = False
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(0x1000, False, pid)
            if handle:
                code = ctypes.c_uint32()
                ok = k32.GetExitCodeProcess(handle, ctypes.byref(code))
                k32.CloseHandle(handle)
                alive = bool(ok and code.value == 259)
        except Exception:
            alive = False
    else:
        try:
            os.kill(pid, 0)
            alive = True
        except OSError:
            alive = False
    if not alive:
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        return None
    return info


def kill_pid(pid):
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(0x0001, False, pid)
            if handle:
                k32.TerminateProcess(handle, 1)
                k32.CloseHandle(handle)
                return True
        except Exception:
            pass
    return False


def cleanup_flags():
    for path in (STOP_FLAG, PID_FILE, TEST_FLAG):
        try:
            os.remove(path)
        except OSError:
            pass


def netsh_run(args_list):
    return subprocess.run(
        ["netsh", "advfirewall", "firewall"] + args_list,
        capture_output=True,
        text=True,
    )


class Honeypot:
    def __init__(self, ports):
        self.requested_ports = ports
        self.bound_ports = []
        self.conn = None
        self.whitelist = set()
        self.stop_event = asyncio.Event()
        self.last_row = {}
        self.alert_count = {}

    def load_whitelist(self):
        return {row[0] for row in self.conn.execute("SELECT ip FROM whitelist")}

    async def run(self):
        init_db()
        seed_whitelist()
        self.conn = db_connect()
        self.whitelist = self.load_whitelist()
        servers = []
        failed = []
        for port in self.requested_ports:
            try:
                server = await asyncio.start_server(
                    functools.partial(self.handle, port), host="0.0.0.0", port=port
                )
                servers.append(server)
                self.bound_ports.append(port)
            except OSError:
                failed.append(port)
        if not servers:
            self.conn.close()
            raise SystemExit(
                f"{RED}[!] Gagal membuka port {failed}. "
                f"Port dipakai aplikasi lain atau honeypot sudah jalan.{RESET}"
            )
        write_pid(self.bound_ports)
        print(f"{BOLD}=== HONEYPOT PRIBADI ==={RESET}", flush=True)
        print(f"port umpan  : {GREEN}{self.bound_ports}{RESET}", flush=True)
        if failed:
            print(f"{YELLOW}[!] port gagal dibuka (dipakai app lain?): {failed}{RESET}", flush=True)
        print(f"whitelist   : {len(self.whitelist)} IP (loopback + IP lokalmu)", flush=True)
        print(f"database    : {DB_FILE}", flush=True)
        if os.path.exists(LOG_FILE) and not sys.stdout.isatty():
            print(f"log         : {LOG_FILE}", flush=True)
        print(
            f"{DIM}berhenti: Ctrl+C atau 'python honeypot.py stop'. "
            f"Jika Windows Firewall bertanya, pilih Private networks.{RESET}",
            flush=True,
        )
        print("", flush=True)
        watchdog = asyncio.create_task(self.watch())
        try:
            await self.stop_event.wait()
        finally:
            watchdog.cancel()
            for s in servers:
                s.close()
            await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
            self.conn.close()
            try:
                os.remove(PID_FILE)
            except OSError:
                pass
            try:
                os.remove(STOP_FLAG)
            except OSError:
                pass
            print(f"{GREEN}[i] port ditutup, semua data tersimpan di ip_log.db{RESET}", flush=True)

    async def watch(self):
        ticks = 0
        while True:
            await asyncio.sleep(1)
            if os.path.exists(STOP_FLAG):
                self.stop_event.set()
                return
            ticks += 1
            if ticks % 5 == 0:
                try:
                    self.whitelist = self.load_whitelist()
                except sqlite3.Error:
                    pass

    async def handle(self, port, reader, writer):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        data = b""
        try:
            try:
                data = await asyncio.wait_for(reader.read(READ_CAP), READ_TIMEOUT)
            except (TimeoutError, ConnectionError, OSError):
                data = b""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        ts = now_ts()
        is_test = self.consume_test_flag(ip)
        if valid_ip(ip):
            self.log_row(ip, port, data, is_test, ts)
        self.announce(ip, port, data, is_test, ts)

    def consume_test_flag(self, ip):
        try:
            if ip not in ("127.0.0.1", "::1"):
                return False
            if not os.path.exists(TEST_FLAG):
                return False
            age = time.time() - os.path.getmtime(TEST_FLAG)
            os.remove(TEST_FLAG)
            return age <= STALE_TEST_SECONDS
        except OSError:
            return False

    def log_row(self, ip, port, data, is_test, ts):
        key = (ip, is_test)
        now = time.time()
        if is_test or key not in self.last_row or now - self.last_row[key] >= REPEAT_QUIET_SECONDS:
            self.conn.execute(
                "INSERT INTO attacker_log (ts, ip, port, data, test) VALUES (?, ?, ?, ?, ?)",
                (ts, ip, port, sqlite3.Binary(data) if data else None, 1 if is_test else 0),
            )
            self.conn.commit()
            self.last_row[key] = now

    def announce(self, ip, port, data, is_test, ts):
        stamp = ts.split(" ")[1]
        payload = f"  payload={repr(data)[:80]}" if data else ""
        if is_test:
            print(f"[{stamp}] {YELLOW}[SELF-TEST]{RESET} koneksi uji dari {ip} port {port} dicatat{payload}", flush=True)
            return
        if ip in self.whitelist:
            print(f"[{stamp}] {DIM}(whitelisted) {ip}:{port}{payload}{RESET}", flush=True)
            return
        count = self.alert_count.get(ip, 0) + 1
        self.alert_count[ip] = count
        if count == 1:
            print(
                f"[{stamp}] {RED}{BOLD}[!] KONEKSI MENCURIGAKAN dari {ip} ke port umpan {port}{RESET}{payload}",
                flush=True,
            )
            print(
                f"         blokir    : python honeypot.py block {ip}",
                flush=True,
            )
            print(
                f"         whitelist : python honeypot.py whitelist add {ip}",
                flush=True,
            )
            return
        print(f"[{stamp}] {DIM}... {ip}:{port} (kali ke-{count} sesi ini){RESET}", flush=True)


def start_background(ports):
    init_db()
    seed_whitelist()
    log = open(LOG_FILE, "a", encoding="utf-8")
    cmd = [sys.executable, os.path.abspath(__file__), "start", "--bg-child",
           "--ports", ",".join(str(p) for p in ports)]
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                     cwd=BASE_DIR, creationflags=flags)
    deadline = time.time() + 8
    while time.time() < deadline:
        info = is_running()
        if info:
            print(f"{GREEN}[+] Honeypot jalan di background (PID {info['pid']}){RESET}")
            print(f"    port umpan : {info.get('ports')}")
            print(f"    log        : {LOG_FILE}")
            print(f"    berhenti   : python honeypot.py stop")
            log.close()
            return
        time.sleep(0.4)
    log.close()
    print(f"{RED}[!] Proses background tidak terdeteksi. Cek log: {LOG_FILE}{RESET}")


def cmd_start(args):
    info = is_running()
    if info:
        print(f"Honeypot sudah jalan (PID {info['pid']}) di port {info.get('ports')}")
        return
    ports = parse_ports(args.ports)
    if args.bg and not args.bg_child:
        start_background(ports)
        return
    enable_ansi()
    honeypot = Honeypot(ports)
    try:
        asyncio.run(honeypot.run())
    except KeyboardInterrupt:
        print(f"\n{GREEN}[i] Honeypot dihentikan.{RESET}")


def cmd_stop(_args):
    info = is_running()
    if not info:
        print("Honeypot tidak sedang berjalan.")
        cleanup_flags()
        return
    pid = info["pid"]
    open(STOP_FLAG, "w").close()
    print(f"menghentikan PID {pid} ...")
    deadline = time.time() + 8
    while time.time() < deadline:
        if not is_running():
            print(f"{GREEN}[+] berhenti dengan rapi.{RESET}")
            cleanup_flags()
            return
        time.sleep(0.4)
    print(f"{YELLOW}[!] tidak berhenti dalam 8 detik, hentikan paksa ...{RESET}")
    if kill_pid(pid):
        print(f"{GREEN}[+] dihentikan paksa.{RESET}")
    else:
        print(f"{RED}[!] gagal menghentikan. Tutup manual via Task Manager (PID {pid}).{RESET}")
    cleanup_flags()


def cmd_status(_args):
    info = is_running()
    if info:
        print(f"{GREEN}[+] BERJALAN{RESET}  PID {info['pid']}  port {info.get('ports')}  sejak {info.get('started')}")
    else:
        print("[-] tidak berjalan")
    init_db()
    conn = db_connect()
    total, uniq = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip) FROM attacker_log WHERE test=0"
    ).fetchone()
    last = conn.execute("SELECT ts, ip, port FROM attacker_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    print(f"    koneksi tercatat : {total} ({uniq} IP unik)")
    if last:
        print(f"    kejadian terakhir: {last[0]} dari {last[1]} port {last[2]}")


def cmd_report(_args):
    init_db()
    conn = db_connect()
    total, uniq = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip) FROM attacker_log WHERE test=0"
    ).fetchone()
    if not total:
        print("Belum ada koneksi mencurigakan tercatat.")
        print("Mulai honeypot (python honeypot.py start) lalu uji: python honeypot.py test")
        conn.close()
        return
    first = conn.execute("SELECT MIN(ts) FROM attacker_log WHERE test=0").fetchone()[0]
    last = conn.execute("SELECT MAX(ts) FROM attacker_log WHERE test=0").fetchone()[0]
    print(f"{BOLD}=== HONEYPOT REPORT ==={RESET}")
    print(f"total koneksi : {total} dari {uniq} IP unik")
    print(f"periode       : {first} s/d {last}")
    print()
    print(f"{BOLD}Top IP penyerang:{RESET}")
    for rank, (ip, c, ports, last_seen) in enumerate(
        conn.execute(
            "SELECT ip, COUNT(*) c, GROUP_CONCAT(DISTINCT port), MAX(ts) "
            "FROM attacker_log WHERE test=0 GROUP BY ip ORDER BY c DESC LIMIT 10"
        ),
        1,
    ):
        print(f"  {rank:>2}. {ip:<16} {c:>5}x  port {ports:<15} terakhir {last_seen}")
    print()
    print(f"{BOLD}Port paling diserang:{RESET}")
    max_c = 1
    port_rows = conn.execute(
        "SELECT port, COUNT(*) c FROM attacker_log WHERE test=0 GROUP BY port ORDER BY c DESC"
    ).fetchall()
    max_c = max((c for _, c in port_rows), default=1)
    for port, c in port_rows:
        bar = "#" * max(1, int(c * 30 / max_c))
        print(f"  port {port:<6} {c:>5}x  {bar}")
    print()
    print(f"{BOLD}Jam tersibuk (waktu lokal):{RESET}")
    for h, c in conn.execute(
        "SELECT substr(ts,12,2) h, COUNT(*) c FROM attacker_log WHERE test=0 "
        "GROUP BY h ORDER BY c DESC LIMIT 5"
    ):
        print(f"  jam {h}:00  {c:>5}x")
    samples = conn.execute(
        "SELECT ip, port, data FROM attacker_log "
        "WHERE test=0 AND data IS NOT NULL ORDER BY id DESC LIMIT 5"
    ).fetchall()
    if samples:
        print()
        print(f"{BOLD}Payload terakhir (sanitasi, maks 70 char):{RESET}")
        for ip, port, data in samples:
            print(f"  {ip:<16} port {port:<6} {repr(data)[:70]}")
    conn.close()


def cmd_test(_args):
    info = is_running()
    if not info:
        print(f"{RED}[!] Honeypot tidak berjalan. Mulai dulu: python honeypot.py start{RESET}")
        return
    ports = info.get("ports") or parse_ports(DEFAULT_PORTS)
    port = ports[0]
    open(TEST_FLAG, "w").close()

    async def probe():
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"HONEYPOT-SELF-TEST " + str(time.time()).encode())
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()

    try:
        asyncio.run(probe())
    except OSError as e:
        print(f"{RED}[!] Gagal konek ke port {port}: {e}{RESET}")
        return
    time.sleep(1.0)
    conn = db_connect()
    row = conn.execute(
        "SELECT ts, ip, port FROM attacker_log WHERE test=1 ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row:
        t = datetime.datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        if (datetime.datetime.now() - t).total_seconds() < 30:
            print(f"{GREEN}[+] TEST BERHASIL{RESET} koneksi uji dari {row[1]} ke port {row[2]} tercatat pada {row[0]}")
            print("    Alert tampil di console honeypot (atau honeypot.log jika mode --bg).")
            return
    print(f"{YELLOW}[?] Record test tidak ditemukan. Cek console/log honeypot.{RESET}")


def cmd_block(args):
    ip = valid_ip(args.ip)
    if not ip:
        raise SystemExit(f"IP tidak valid: {args.ip}")
    conn = db_connect()
    wl = {row[0] for row in conn.execute("SELECT ip FROM whitelist")}
    conn.close()
    if ip in wl:
        print(f"{YELLOW}[!] {ip} ada di whitelist. Hapus dulu: python honeypot.py whitelist remove {ip}{RESET}")
        return
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback:
        print(f"{YELLOW}[!] PERINGATAN: {ip} adalah IP lokal/private.")
        try:
            ans = input("Yakin mau blokir? Bisa ganggu koneksi sendiri (y/N): ")
        except EOFError:
            ans = ""
        if ans.strip().lower() not in ("y", "yes", "ya"):
            print("dibatalkan.")
            return
    name = f"{RULE_PREFIX} {ip}"
    res = netsh_run(["add", "rule", f"name={name}", "dir=in", "action=block",
                     f"remoteip={ip}", "profile=any"])
    if res.returncode == 0:
        print(f"{GREEN}[+] {ip} diblokir masuk via Windows Firewall (rule '{name}').{RESET}")
    else:
        detail = (res.stderr or res.stdout).strip().splitlines()
        print(f"{RED}[!] netsh gagal (code {res.returncode}):{RESET}")
        for line in detail[:3]:
            print(f"    {line}")
        print(f"    Kemungkinan terminal bukan Administrator. Buka cmd/PowerShell sebagai Admin lalu ulangi.")


def cmd_unblock(args):
    ip = valid_ip(args.ip)
    if not ip:
        raise SystemExit(f"IP tidak valid: {args.ip}")
    name = f"{RULE_PREFIX} {ip}"
    res = netsh_run(["delete", "rule", f"name={name}"])
    if res.returncode == 0:
        print(f"{GREEN}[+] Blokir untuk {ip} dihapus.{RESET}")
    else:
        detail = (res.stderr or res.stdout).strip().splitlines()
        print(f"{RED}[!] netsh gagal (code {res.returncode}):{RESET}")
        for line in detail[:3]:
            print(f"    {line}")


def cmd_blocked(_args):
    res = netsh_run(["show", "rule", "name=all"])
    found = []
    for line in res.stdout.splitlines():
        if RULE_PREFIX in line:
            part = line.split(":", 1)[-1].strip()
            if part.startswith(RULE_PREFIX):
                found.append(part[len(RULE_PREFIX):].strip())
    if found:
        print(f"IP yang diblokir ({len(found)}):")
        for ip in found:
            print(f"  {ip}")
    else:
        print("Belum ada IP yang diblokir via honeypot.")


def cmd_whitelist(args):
    init_db()
    if args.wl_cmd == "list":
        seed_whitelist()
    conn = db_connect()
    if args.wl_cmd == "list":
        rows = conn.execute("SELECT ip, added_at FROM whitelist ORDER BY added_at").fetchall()
        local = get_local_ips()
        print(f"{len(rows)} IP di whitelist:")
        for ip, added in rows:
            tag = "  (IP lokalmu)" if ip in local else ""
            print(f"  {ip:<18} {added}{tag}")
    elif args.wl_cmd == "add":
        ip = valid_ip(args.ip)
        if not ip:
            conn.close()
            raise SystemExit(f"IP tidak valid: {args.ip}")
        conn.execute("INSERT OR IGNORE INTO whitelist (ip, added_at) VALUES (?, ?)", (ip, now_ts()))
        conn.commit()
        print(f"{GREEN}[+] {ip} masuk whitelist (tidak memicu alarm).{RESET}")
        print("    Honeypot memuat ulang whitelist tiap ~5 detik.")
    elif args.wl_cmd == "remove":
        ip = valid_ip(args.ip)
        if not ip:
            conn.close()
            raise SystemExit(f"IP tidak valid: {args.ip}")
        cur = conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
        conn.commit()
        if cur.rowcount:
            print(f"{GREEN}[+] {ip} dihapus dari whitelist.{RESET}")
        else:
            print(f"[-] {ip} tidak ada di whitelist.")
    conn.close()


def main():
    parser = argparse.ArgumentParser(
        prog="honeypot",
        description="Honeypot port pribadi: deteksi koneksi mencurigakan ke laptopmu.",
        epilog=(
            "contoh:\n"
            "  python honeypot.py start\n"
            "  python honeypot.py start --bg --ports 2222,4444,8081\n"
            "  python honeypot.py test\n"
            "  python honeypot.py report\n"
            "  python honeypot.py block 203.0.113.7\n"
            "  python honeypot.py whitelist add 192.168.1.10\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    p_start = sub.add_parser("start", help="jalankan honeypot (Ctrl+C untuk berhenti)")
    p_start.add_argument("--ports", default=DEFAULT_PORTS, help=f"port umpan, dipisah koma (default: {DEFAULT_PORTS})")
    p_start.add_argument("--bg", action="store_true", help="jalankan di background, log ke honeypot.log")
    p_start.add_argument("--bg-child", action="store_true", help=argparse.SUPPRESS)

    sub.add_parser("stop", help="hentikan honeypot yang berjalan")
    sub.add_parser("status", help="cek honeypot jalan atau tidak")
    sub.add_parser("report", help="statistik serangan")
    sub.add_parser("test", help="uji alert dengan koneksi dari laptop sendiri")

    p_block = sub.add_parser("block", help="blokir IP via Windows Firewall (butuh Admin)")
    p_block.add_argument("ip")
    p_unblock = sub.add_parser("unblock", help="hapus blokir IP")
    p_unblock.add_argument("ip")
    sub.add_parser("blocked", help="daftar IP yang diblokir")

    p_wl = sub.add_parser("whitelist", help="kelola IP yang tidak memicu alarm")
    wl_sub = p_wl.add_subparsers(dest="wl_cmd", required=True)
    p_wl_add = wl_sub.add_parser("add", help="tambah IP ke whitelist")
    p_wl_add.add_argument("ip")
    p_wl_rm = wl_sub.add_parser("remove", help="hapus IP dari whitelist")
    p_wl_rm.add_argument("ip")
    wl_sub.add_parser("list", help="lihat isi whitelist")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    enable_ansi()
    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "report": cmd_report,
        "test": cmd_test,
        "block": cmd_block,
        "unblock": cmd_unblock,
        "blocked": cmd_blocked,
        "whitelist": cmd_whitelist,
    }
    commands[args.cmd](args)


if __name__ == "__main__":
    main()
