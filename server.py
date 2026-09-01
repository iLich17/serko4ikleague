#!/usr/bin/env python3
"""F1 League server: registration/login + password-protected admin panel."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote
import os, json, threading, secrets, time, hashlib, hmac, re, shutil

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
NEWS_LOCK = threading.Lock()
USERS_LOCK = threading.Lock()
ADMINS_LOCK = threading.Lock()

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
        if path in ("/users.json", "/admins.json", "/news.json"):
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
        if path == "/api/news":
            if not current_user(self) and not is_admin(self):
                self._json_response(401, {"error": "Сначала зарегистрируйтесь или войдите"})
                return
            with NEWS_LOCK:
                self._json_response(200, load_news())
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
    server = ThreadingHTTPServer((HOST, PORT), F1Handler)
    print(f"F1 League server: http://{HOST}:{PORT}")
    print(f"Registration/login: http://127.0.0.1:{PORT}/auth")
    print(f"Admin panel: http://127.0.0.1:{PORT}/admin")
    print("Admins list: admins.json (add registered nicknames here)")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nStopping server...")
    finally: server.server_close()

if __name__ == "__main__": main()
