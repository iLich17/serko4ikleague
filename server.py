#!/usr/bin/env python3
"""F1 League server: registration/login + password-protected admin panel."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote
import os, json, threading, secrets, time, hashlib, hmac, re, shutil, mimetypes

ROOT = Path(__file__).resolve().parent
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))
# On Railway, set F1_DATA_DIR=/data and attach a Volume mounted at /data.
# Locally it defaults to the project directory so the existing JSON files keep working.
DATA_DIR = Path(os.getenv("F1_DATA_DIR", str(ROOT)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

def data_file(name):
    target = DATA_DIR / name
    bundled = ROOT / name
    if target != bundled and not target.exists() and bundled.exists():
        shutil.copy2(bundled, target)
    return target

NEWS_FILE = data_file("news.json")
USERS_FILE = data_file("users.json")
ADMINS_FILE = data_file("admins.json")
PROTESTS_FILE = data_file("protests.json")
PROTESTS_DIR = DATA_DIR / "protest_files"
PROTESTS_DIR.mkdir(parents=True, exist_ok=True)
DRIVERS_FILE = data_file("drivers.json")
DRIVER_PHOTOS_DIR = DATA_DIR / "driver_photos"
DRIVER_PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
TEAM_PHOTOS_DIR = DATA_DIR / "team_photos"
TEAM_PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
TEAMS_FILE = data_file("teams.json")
NEWS_LOCK = threading.Lock()
USERS_LOCK = threading.Lock()
ADMINS_LOCK = threading.Lock()
PROTESTS_LOCK = threading.Lock()
DRIVERS_LOCK = threading.Lock()
TEAMS_LOCK = threading.Lock()

SESSION_TTL = 12 * 60 * 60
SESSIONS = {}  # token -> {expires, nick}
SESSIONS_LOCK = threading.Lock()
NICK_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9_.-]{3,24}$")


def load_json(path, default):
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def load_news():
    data = load_json(NEWS_FILE, [])
    return data if isinstance(data, list) else []


def save_news(data):
    save_json(NEWS_FILE, data)


def load_users():
    data = load_json(USERS_FILE, [])
    return data if isinstance(data, list) else []


def save_users(data):
    save_json(USERS_FILE, data)


def load_admins():
    data = load_json(ADMINS_FILE, [])
    if isinstance(data, dict):
        data = data.get("admins", [])
    if not isinstance(data, list):
        return []
    return [str(x).strip() for x in data if str(x).strip()]


def save_admins(data):
    save_json(ADMINS_FILE, data)


def load_protests():
    data = load_json(PROTESTS_FILE, [])
    return data if isinstance(data, list) else []


def save_protests(data):
    save_json(PROTESTS_FILE, data)


def load_driver_settings():
    data = load_json(DRIVERS_FILE, {})
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        return {str(x.get("name")): x for x in data if isinstance(x, dict) and x.get("name")}
    return {}


def save_driver_settings(data):
    save_json(DRIVERS_FILE, data)


def is_driver_active(name):
    item = load_driver_settings().get(str(name), {})
    return bool(item.get("active", True))


def driver_settings_with_stats():
    settings = load_driver_settings()
    # Keep settings compatible with the current results: create missing entries lazily.
    seen = {}
    results = load_json(ROOT / "results.json", {})
    for race in results.get("races", []) if isinstance(results, dict) else []:
        for row in race.get("results", []):
            name = str(row.get("driver", "")).strip()
            if not name:
                continue
            seen[name] = row.get("team", "")
    changed = False
    for name, team in seen.items():
        if name not in settings:
            settings[name] = {"name": name, "team": team, "photo": "", "active": True}
            changed = True
        elif not settings[name].get("team") and team:
            settings[name]["team"] = team
            changed = True
        settings[name].setdefault("photo", "")
        settings[name].setdefault("active", True)
    if changed:
        save_driver_settings(settings)
    return settings


def driver_public_list(include_inactive=False):
    settings = driver_settings_with_stats()
    rows = []
    for name, item in settings.items():
        active = bool(item.get("active", True))
        if not include_inactive and not active:
            continue
        rows.append({
            "name": name,
            "team": item.get("team", ""),
            "photo": item.get("photo", ""),
            "active": active,
        })
    rows.sort(key=lambda x: x["name"].casefold())
    return rows


def load_team_settings():
    data = load_json(TEAMS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_team_settings(data):
    save_json(TEAMS_FILE, data)


def team_names_from_results():
    results = load_json(ROOT / "results.json", {})
    names = set()
    if isinstance(results, dict):
        for race in results.get("races", []):
            for row in race.get("results", []):
                team = str(row.get("team", "")).strip()
                if team:
                    names.add(team)
    names.update([
        "McLaren", "Ferrari", "Mercedes", "Red Bull Racing", "Aston Martin",
        "Williams", "Haas", "Alpine", "Visa Cash App RB", "Kick Sauber"
    ])
    return sorted(names, key=str.casefold)


def team_public_list():
    settings = load_team_settings()
    return [{"name": n, "photo": settings.get(n, {}).get("photo", "")} for n in team_names_from_results()]


def safe_team_photo_filename(name):
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name)).strip("._-") or "team"
    return base[:80]


def safe_photo_filename(name):
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name)).strip("._-") or "driver"
    return base[:80]


def parse_cookies(header):
    cookies = {}
    for part in (header or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k] = v
    return cookies


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_user_session(nick):
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS[token] = {"expires": time.time() + SESSION_TTL, "nick": nick}
    return token


def current_user(handler):
    token = parse_cookies(handler.headers.get("Cookie")).get("f1_user")
    if not token:
        return None
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        if session["expires"] < time.time():
            SESSIONS.pop(token, None)
            return None
        session["expires"] = time.time() + SESSION_TTL
        return session["nick"]


def delete_user_session(handler):
    token = parse_cookies(handler.headers.get("Cookie")).get("f1_user")
    if token:
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


def create_admin_session(nick):
    token = secrets.token_urlsafe(32)
    with SESSIONS_LOCK:
        SESSIONS["admin:" + token] = {"expires": time.time() + SESSION_TTL, "admin": True, "nick": nick}
    return token


def is_admin(handler):
    token = parse_cookies(handler.headers.get("Cookie")).get("f1_admin")
    if not token:
        return False
    key = "admin:" + token
    with SESSIONS_LOCK:
        session = SESSIONS.get(key)
        if not session:
            return False
        if session["expires"] < time.time():
            SESSIONS.pop(key, None)
            return False
        session["expires"] = time.time() + SESSION_TTL
        return True


def current_admin(handler):
    token = parse_cookies(handler.headers.get("Cookie")).get("f1_admin")
    if not token:
        return None
    key = "admin:" + token
    with SESSIONS_LOCK:
        session = SESSIONS.get(key)
        if not session:
            return None
        if session["expires"] < time.time():
            SESSIONS.pop(key, None)
            return None
        session["expires"] = time.time() + SESSION_TTL
        return session.get("nick")


def delete_admin_session(handler):
    token = parse_cookies(handler.headers.get("Cookie")).get("f1_admin")
    if token:
        with SESSIONS_LOCK:
            SESSIONS.pop("admin:" + token, None)

def cookie(name, value, max_age):
    return f"{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}"


class F1Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map,
        ".json": "application/json; charset=utf-8", ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".svg": "image/svg+xml"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        path = self.path.split("?", 1)[0]
        if path.endswith(("results.json", "news.json", "users.json")):
            self.send_header("Cache-Control", "no-store, max-age=0")
        else:
            self.send_header("Cache-Control", "public, max-age=300")
        super().end_headers()

    def _json_response(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, max-age=0")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self, max_bytes=25 * 1024 * 1024):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid content length")
        if length <= 0 or length > max_bytes:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _read_multipart(self, max_bytes=55 * 1024 * 1024):
        content_type = self.headers.get("Content-Type", "")
        match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type)
        if not match:
            raise ValueError("Ожидается multipart/form-data")
        boundary = (match.group(1) or match.group(2)).encode("utf-8")
        length_header = self.headers.get("Content-Length")
        if not length_header:
            raise ValueError("Не указан размер запроса")
        try:
            length = int(length_header)
        except ValueError:
            raise ValueError("Некорректный размер запроса")
        if length <= 0 or length > max_bytes:
            raise ValueError("Файл слишком большой. Максимум 50 МБ")
        body = self.rfile.read(length)
        delimiter = b"--" + boundary
        parts = body.split(delimiter)
        fields = {}
        file_part = None
        for part in parts[1:]:
            if part.startswith(b"--"):
                break
            if part.startswith(b"\r\n"):
                part = part[2:]
            if part.endswith(b"\r\n"):
                part = part[:-2]
            if b"\r\n\r\n" not in part:
                continue
            raw_headers, content = part.split(b"\r\n\r\n", 1)
            headers = raw_headers.decode("utf-8", "replace")
            disposition = re.search(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]*)")?', headers, re.I)
            if not disposition:
                continue
            name, filename = disposition.group(1), disposition.group(2)
            ctype = re.search(r'Content-Type:\s*([^\r\n;]+)', headers, re.I)
            mime = ctype.group(1).strip().lower() if ctype else ""
            if filename is not None:
                file_part = {"name": name, "filename": filename, "mime": mime, "data": content}
            else:
                fields[name] = content.decode("utf-8", "replace")
        return fields, file_part

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._json_response(200, {"status": "ok", "service": "f1-league"})
            return
        if path in ("/users.json", "/admins.json", "/news.json", "/drivers.json"):
            self._json_response(403, {"error": "forbidden"})
            return
        if path == "/api/auth/me":
            nick = current_user(self)
            self._json_response(200, {"authenticated": bool(nick), "nick": nick})
            return
        if path == "/api/admin/me":
            self._json_response(200, {"authenticated": bool(current_admin(self)), "nick": current_admin(self)})
            return
        if path == "/api/admins":
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            self._json_response(200, {"admins": load_admins()})
            return
        if path == "/api/admin/users":
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            admins = {a.casefold() for a in load_admins()}
            with USERS_LOCK:
                users = load_users()
            public = []
            for u in users:
                nick = str(u.get("nick", ""))
                public.append({"nick": nick, "created_at": u.get("created_at", ""), "admin": nick.casefold() in admins})
            self._json_response(200, {"users": public})
            return
        if path == "/api/teams":
            if not current_user(self) and not is_admin(self):
                self._json_response(401, {"error": "Сначала зарегистрируйтесь или войдите"})
                return
            self._json_response(200, {"teams": team_public_list()})
            return
        if path == "/api/admin/teams":
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            self._json_response(200, {"teams": team_public_list()})
            return
        if path.startswith("/team-photos/"):
            requested = path[len("/team-photos/"):].split("?", 1)[0]
            if not requested or "/" in requested or "\\" in requested or ".." in requested:
                self._json_response(404, {"error": "Файл не найден"})
                return
            file_path = (TEAM_PHOTOS_DIR / requested).resolve()
            try:
                if file_path.parent != TEAM_PHOTOS_DIR.resolve() or not file_path.is_file():
                    self._json_response(404, {"error": "Файл не найден"})
                    return
                mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=300")
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                self._json_response(404, {"error": "Файл не найден"})
            return
        if path == "/api/drivers":
            if not current_user(self) and not is_admin(self):
                self._json_response(401, {"error": "Сначала зарегистрируйтесь или войдите"})
                return
            self._json_response(200, {"drivers": driver_public_list(False)})
            return
        if path == "/api/admin/drivers":
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            self._json_response(200, {"drivers": driver_public_list(True)})
            return
        if path.startswith("/driver-photos/"):
            requested = path[len("/driver-photos/"):] .split("?",1)[0]
            if not requested or "/" in requested or "\\" in requested or ".." in requested:
                self._json_response(404, {"error":"Файл не найден"})
                return
            file_path = (DRIVER_PHOTOS_DIR / requested).resolve()
            try:
                if file_path.parent != DRIVER_PHOTOS_DIR.resolve() or not file_path.is_file():
                    self._json_response(404, {"error":"Файл не найден"})
                    return
                mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=300")
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                self._json_response(404, {"error":"Файл не найден"})
            return
        if path == "/api/news":
            if not current_user(self) and not is_admin(self):
                self._json_response(401, {"error": "Сначала зарегистрируйтесь или войдите"})
                return
            with NEWS_LOCK:
                self._json_response(200, load_news())
            return
        if path == "/api/admin/protests":
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            with PROTESTS_LOCK:
                self._json_response(200, {"protests": load_protests()})
            return
        if path.startswith("/protest-files/"):
            if not is_admin(self):
                self._json_response(403, {"error": "Доказательства доступны только администраторам"})
                return
            # Serve evidence files only after the admin check.
            requested = path[len("/protest-files/"):]
            requested = requested.split("?", 1)[0]
            if not requested or "/" in requested or "\\" in requested or ".." in requested:
                self._json_response(404, {"error": "Файл не найден"})
                return
            file_path = (PROTESTS_DIR / requested).resolve()
            try:
                if file_path.parent != PROTESTS_DIR.resolve() or not file_path.is_file():
                    self._json_response(404, {"error": "Файл не найден"})
                    return
                mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
                size = file_path.stat().st_size
                range_header = self.headers.get("Range")
                start, end = 0, size - 1
                status = 200
                if range_header and range_header.startswith("bytes="):
                    try:
                        spec = range_header[6:].split(",", 1)[0].strip()
                        if "-" in spec:
                            a, b = spec.split("-", 1)
                            if a:
                                start = int(a)
                                end = int(b) if b else size - 1
                            else:
                                length = int(b)
                                start = max(0, size - length)
                            end = min(end, size - 1)
                            if start > end or start >= size:
                                self.send_response(416)
                                self.send_header("Content-Range", f"bytes */{size}")
                                self.end_headers()
                                return
                            status = 206
                    except ValueError:
                        start, end, status = 0, size - 1, 200
                length = end - start + 1
                self.send_response(status)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(length))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Cache-Control", "private, max-age=300")
                if status == 206:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.end_headers()
                with file_path.open("rb") as fh:
                    fh.seek(start)
                    remaining = length
                    while remaining:
                        chunk = fh.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            except OSError:
                self._json_response(404, {"error": "Файл не найден"})
            return
        if path == "/admin":
            self.path = "/admin.html"
            return super().do_GET()
        if path in ("", "/"):
            if not current_user(self):
                return self._redirect("/auth")
            self.path = "/index.html"
        elif path == "/auth":
            self.path = "/auth.html"
        elif path == "/admin.html":
            self.path = "/admin.html"
        else:
            # All site pages/assets are available only to authenticated users.
            if not current_user(self) and path not in ("/auth.html",):
                return self._redirect("/auth")
        return super().do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/auth/register":
                data = self._read_json(64 * 1024)
                nick = str(data.get("nick", "")).strip() if isinstance(data, dict) else ""
                password = str(data.get("password", "")) if isinstance(data, dict) else ""
                if not NICK_RE.fullmatch(nick):
                    self._json_response(400, {"error": "Ник: 3–24 символа, только буквы, цифры, _, -, ."})
                    return
                if len(password) < 6 or len(password) > 128:
                    self._json_response(400, {"error": "Пароль должен содержать от 6 до 128 символов"})
                    return
                with USERS_LOCK:
                    users = load_users()
                    if any(u.get("nick", "").casefold() == nick.casefold() for u in users):
                        self._json_response(409, {"error": "Этот ник уже занят"})
                        return
                    users.append({"nick": nick, "password": hash_password(password), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
                    save_users(users)
                token = create_user_session(nick)
                self._json_response(201, {"ok": True, "nick": nick}, [("Set-Cookie", cookie("f1_user", token, SESSION_TTL))])
                return

            if path == "/api/auth/login":
                data = self._read_json(64 * 1024)
                nick = str(data.get("nick", "")).strip() if isinstance(data, dict) else ""
                password = str(data.get("password", "")) if isinstance(data, dict) else ""
                with USERS_LOCK:
                    user = next((u for u in load_users() if u.get("nick", "").casefold() == nick.casefold()), None)
                if not user or not verify_password(password, user.get("password", "")):
                    self._json_response(401, {"error": "Неверный ник или пароль"})
                    return
                token = create_user_session(user["nick"])
                self._json_response(200, {"ok": True, "nick": user["nick"]}, [("Set-Cookie", cookie("f1_user", token, SESSION_TTL))])
                return

            if path == "/api/auth/logout":
                delete_user_session(self)
                self._json_response(200, {"ok": True}, [("Set-Cookie", cookie("f1_user", "", 0))])
                return

            if path == "/api/admin/drivers":
                if not is_admin(self):
                    self._json_response(401, {"error": "Требуется вход в админ-панель"})
                    return
                fields, file_part = self._read_multipart(max_bytes=15 * 1024 * 1024)
                name = fields.get("name", "").strip()
                if not name:
                    self._json_response(400, {"error": "Не указан пилот"})
                    return
                with DRIVERS_LOCK:
                    settings = driver_settings_with_stats()
                    # Match case-insensitively so the name is canonical.
                    canonical = next((n for n in settings if n.casefold() == name.casefold()), None)
                    if not canonical:
                        self._json_response(404, {"error": "Пилот не найден в результатах"})
                        return
                    item = settings[canonical]
                    item["active"] = True
                    if file_part and file_part.get("data"):
                        mime = file_part.get("mime", "")
                        if not mime.startswith("image/"):
                            self._json_response(400, {"error": "Фото пилота должно быть изображением"})
                            return
                        data = file_part["data"]
                        if len(data) > 10 * 1024 * 1024:
                            self._json_response(400, {"error": "Фото не должно превышать 10 МБ"})
                            return
                        ext = Path(file_part.get("filename") or "").suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
                            ext = ".jpg"
                        base = safe_photo_filename(canonical)
                        filename = base + ext
                        # Remove an older photo for the same driver.
                        old = str(item.get("photo", ""))
                        if old.startswith("/driver-photos/"):
                            old_file = (DRIVER_PHOTOS_DIR / Path(old).name).resolve()
                            if old_file.parent == DRIVER_PHOTOS_DIR.resolve() and old_file.is_file() and old_file.name != filename:
                                try: old_file.unlink()
                                except OSError: pass
                        target = DRIVER_PHOTOS_DIR / filename
                        target.write_bytes(data)
                        item["photo"] = "/driver-photos/" + filename
                    save_driver_settings(settings)
                self._json_response(200, {"ok": True, "driver": {"name": canonical, **settings[canonical]}})
                return

            if path == "/api/protests":
                nick = current_user(self)
                if not nick:
                    self._json_response(401, {"error": "Сначала зарегистрируйтесь или войдите"})
                    return
                fields, file_part = self._read_multipart()
                pilot_name = fields.get("pilot_name", "").strip()
                violator_name = fields.get("violator_name", "").strip()
                complaint = fields.get("complaint", "").strip()
                if not pilot_name:
                    self._json_response(400, {"error": "Укажите ваше имя пилота"})
                    return
                if not complaint:
                    self._json_response(400, {"error": "Опишите жалобу"})
                    return
                if not file_part or not file_part.get("data"):
                    self._json_response(400, {"error": "Прикрепите фото или видео доказательства"})
                    return
                mime = file_part.get("mime", "")
                if not (mime.startswith("image/") or mime.startswith("video/")):
                    self._json_response(400, {"error": "Можно прикрепить только изображение или видео"})
                    return
                data = file_part["data"]
                if len(data) > 50 * 1024 * 1024:
                    self._json_response(400, {"error": "Доказательство не должно превышать 50 МБ"})
                    return
                ext = Path(file_part.get("filename") or "").suffix.lower()
                allowed_ext = {".jpg",".jpeg",".png",".gif",".webp",".mp4",".webm",".mov",".m4v",".avi"}
                if ext not in allowed_ext:
                    ext = ".mp4" if mime.startswith("video/") else ".jpg"
                protest_id = str(int(time.time() * 1000)) + secrets.token_hex(3)
                filename = protest_id + ext
                target = PROTESTS_DIR / filename
                target.write_bytes(data)
                item = {
                    "id": protest_id,
                    "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "user_nick": nick,
                    "pilot_name": pilot_name[:120],
                    "violator_name": violator_name[:120],
                    "complaint": complaint[:5000],
                    "evidence": "/protest-files/" + filename,
                    "evidence_name": str(file_part.get("filename") or filename)[:200],
                    "evidence_mime": mime,
                    "status": "Новый"
                }
                with PROTESTS_LOCK:
                    protests = load_protests()
                    protests.insert(0, item)
                    save_protests(protests[:500])
                self._json_response(201, {"ok": True, "id": protest_id})
                return

            if path.startswith("/api/admin/protests/") and path.endswith("/delete"):
                if not is_admin(self):
                    self._json_response(401, {"error": "Требуется вход в админ-панель"})
                    return
                protest_id = path[len("/api/admin/protests/"):-len("/delete")].strip("/")
                if not protest_id:
                    self._json_response(400, {"error": "Не указан протест"})
                    return
                with PROTESTS_LOCK:
                    protests = load_protests()
                    target = next((p for p in protests if str(p.get("id")) == protest_id), None)
                    if not target:
                        self._json_response(404, {"error": "Протест не найден"})
                        return
                    evidence = str(target.get("evidence", ""))
                    filename = Path(evidence[len("/protest-files/"):]).name if evidence.startswith("/protest-files/") else ""
                    if filename:
                        file_path = (PROTESTS_DIR / filename).resolve()
                        if file_path.parent == PROTESTS_DIR.resolve() and file_path.is_file():
                            try:
                                file_path.unlink()
                            except OSError:
                                pass
                    save_protests([p for p in protests if str(p.get("id")) != protest_id])
                self._json_response(200, {"ok": True})
                return

            if path == "/api/admin/login":
                data = self._read_json(64 * 1024)
                nick = str(data.get("nick", "")).strip() if isinstance(data, dict) else ""
                password = str(data.get("password", "")) if isinstance(data, dict) else ""
                admins = load_admins()
                if not any(a.casefold() == nick.casefold() for a in admins):
                    self._json_response(403, {"error": "Этот пользователь не является администратором"})
                    return
                with USERS_LOCK:
                    user = next((u for u in load_users() if u.get("nick", "").casefold() == nick.casefold()), None)
                if not user or not verify_password(password, user.get("password", "")):
                    self._json_response(401, {"error": "Неверный ник или пароль"})
                    return
                token = create_admin_session(user["nick"])
                self._json_response(200, {"ok": True, "nick": user["nick"]}, [("Set-Cookie", cookie("f1_admin", token, SESSION_TTL))])
                return

            if path == "/api/admin/logout":
                delete_admin_session(self)
                self._json_response(200, {"ok": True}, [("Set-Cookie", cookie("f1_admin", "", 0))])
                return

            if path == "/api/admins":
                if not is_admin(self):
                    self._json_response(401, {"error": "Требуется вход в админ-панель"})
                    return
                data = self._read_json(64 * 1024)
                nick = str(data.get("nick", "")).strip() if isinstance(data, dict) else ""
                if not NICK_RE.fullmatch(nick):
                    self._json_response(400, {"error": "Некорректный ник"}); return
                with USERS_LOCK:
                    users = load_users()
                    user = next((u for u in users if u.get("nick", "").casefold() == nick.casefold()), None)
                if not user:
                    self._json_response(404, {"error": "Сначала зарегистрируйте этого пользователя"}); return
                with ADMINS_LOCK:
                    admins = load_admins()
                    if not any(a.casefold() == nick.casefold() for a in admins):
                        admins.append(user["nick"])
                        save_admins(admins)
                self._json_response(201, {"ok": True, "admins": load_admins()}); return

            if path == "/api/news":
                if not is_admin(self):
                    self._json_response(401, {"error": "Требуется вход в админ-панель"})
                    return
                item = self._read_json()
                if not isinstance(item, dict): raise ValueError("invalid news")
                title = str(item.get("title", "")).strip()
                if not title:
                    self._json_response(400, {"error": "title is required"}); return
                item["title"] = title[:160]
                item["text"] = str(item.get("text", ""))[:4000]
                item["tag"] = str(item.get("tag", "F1 LEAGUE"))[:50]
                if not isinstance(item.get("images", []), list): item["images"] = []
                item["images"] = [str(x) for x in item["images"][:8] if str(x).startswith("data:image/")]
                item["id"] = int(item.get("id") or time.time() * 1000)
                item["date"] = str(item.get("date", ""))[:10]
                item["time"] = str(item.get("time", ""))[:5]
                with NEWS_LOCK:
                    news = load_news(); news.insert(0, item); save_news(news[:200])
                self._json_response(201, item); return

            self._json_response(404, {"error": "not found"})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._json_response(400, {"error": "Некорректные данные или слишком большой запрос"})
        except OSError as exc:
            print(f"[F1] save error: {exc}")
            self._json_response(500, {"error": "Не удалось сохранить данные"})

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/news/"):
            self._json_response(404, {"error": "not found"}); return
        if not is_admin(self):
            self._json_response(401, {"error": "Требуется вход в админ-панель"}); return
        try:
            news_id = int(unquote(path.rsplit("/", 1)[1]))
            item = self._read_json()
            if not isinstance(item, dict): raise ValueError()
            title = str(item.get("title", "")).strip()
            if not title:
                self._json_response(400, {"error": "Укажи заголовок"}); return
            item["title"] = title[:160]; item["text"] = str(item.get("text", ""))[:4000]; item["tag"] = str(item.get("tag", "F1 LEAGUE"))[:50]; item["id"] = news_id
            if not isinstance(item.get("images", []), list): item["images"] = []
            item["images"] = [str(x) for x in item["images"][:8] if str(x).startswith("data:image/")]
            with NEWS_LOCK:
                news = load_news()
                for i, old in enumerate(news):
                    if int(old.get("id", -1)) == news_id:
                        item.setdefault("date", old.get("date", "")); item.setdefault("time", old.get("time", ""))
                        news[i] = item; save_news(news); self._json_response(200, item); return
            self._json_response(404, {"error": "Новость не найдена"})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._json_response(400, {"error": "Некорректные данные"})

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/admins/"):
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"}); return
            nick = unquote(path.rsplit("/", 1)[1]).strip()
            with ADMINS_LOCK:
                admins = load_admins()
                target = next((a for a in admins if a.casefold() == nick.casefold()), None)
                if not target:
                    self._json_response(404, {"error": "Администратор не найден"}); return
                if len(admins) <= 1:
                    self._json_response(400, {"error": "Нельзя удалить последнего администратора"}); return
                admins = [a for a in admins if a.casefold() != nick.casefold()]
                save_admins(admins)
            self._json_response(200, {"ok": True, "admins": load_admins()}); return
        if path.startswith("/api/admin/drivers/"):
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"})
                return
            name = unquote(path.rsplit("/", 1)[1]).strip()
            with DRIVERS_LOCK:
                settings = driver_settings_with_stats()
                canonical = next((n for n in settings if n.casefold() == name.casefold()), None)
                if not canonical:
                    self._json_response(404, {"error": "Пилот не найден"})
                    return
                item = settings[canonical]
                item["active"] = False
                save_driver_settings(settings)
            self._json_response(200, {"ok": True})
            return
        if path.startswith("/api/admin/users/"):
            if not is_admin(self):
                self._json_response(401, {"error": "Требуется вход в админ-панель"}); return
            nick = unquote(path.rsplit("/", 1)[1]).strip()
            current = current_admin(self)
            if current and current.casefold() == nick.casefold():
                self._json_response(400, {"error": "Нельзя удалить самого себя"}); return
            with USERS_LOCK:
                users = load_users()
                if not any(u.get("nick", "").casefold() == nick.casefold() for u in users):
                    self._json_response(404, {"error": "Пользователь не найден"}); return
                users = [u for u in users if u.get("nick", "").casefold() != nick.casefold()]
                save_users(users)
            with ADMINS_LOCK:
                admins = [a for a in load_admins() if a.casefold() != nick.casefold()]
                save_admins(admins)
            self._json_response(200, {"ok": True}); return
        if not path.startswith("/api/news/"):
            self._json_response(404, {"error": "not found"}); return
        if not is_admin(self):
            self._json_response(401, {"error": "Требуется вход в админ-панель"}); return
        try:
            news_id = int(unquote(path.rsplit("/", 1)[1]))
            with NEWS_LOCK:
                news = load_news(); new_news = [n for n in news if int(n.get("id", -1)) != news_id]
                if len(new_news) == len(news): self._json_response(404, {"error": "Новость не найдена"}); return
                save_news(new_news)
            self._json_response(200, {"ok": True})
        except (ValueError, TypeError):
            self._json_response(400, {"error": "Некорректный ID"})

    def log_message(self, fmt, *args):
        print(f"[F1] {self.address_string()} - {fmt % args}")


def main():
    os.chdir(ROOT)
    if not USERS_FILE.exists(): save_users([])
    if not ADMINS_FILE.exists(): save_admins(["admin"])
    if not NEWS_FILE.exists(): save_news([])
    if not PROTESTS_FILE.exists(): save_protests([])
    driver_settings_with_stats()
    if not TEAMS_FILE.exists(): save_team_settings({})
    server = ThreadingHTTPServer((HOST, PORT), F1Handler)
    print(f"F1 League server: http://{HOST}:{PORT}")
    print(f"Registration/login: http://127.0.0.1:{PORT}/auth")
    print(f"Admin panel: http://127.0.0.1:{PORT}/admin")
    print("Admins list: admins.json (add registered nicknames here)")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping server...")
    finally: server.server_close()

if __name__ == "__main__": main()
