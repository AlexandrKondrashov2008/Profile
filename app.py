from __future__ import annotations

import io
import json
import logging
import os
import secrets
import socket
import time
import zipfile
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import bcrypt
import markdown
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    Response,
    request,
    send_file,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", f"sqlite:///{BASE_DIR / 'statuses.db'}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = BASE_DIR / "static" / "uploads"
app.config["VPN_DOWNLOAD_FOLDER"] = BASE_DIR / "storage" / "vpn"
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

db = SQLAlchemy(app)
scheduler = BackgroundScheduler(daemon=True)
SERVICE_CACHE: list[dict] | None = None
APP_INITIALIZED = False


def configure_logging() -> None:
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    for name, filename in (
        ("admin", "admin.log"),
        ("auth", "auth.log"),
        ("vpn", "vpn_checks.log"),
    ):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        if logger.handlers:
            continue
        handler = RotatingFileHandler(log_dir / filename, maxBytes=512_000, backupCount=5, encoding="utf-8")
        handler.setFormatter(formatter)
        logger.addHandler(handler)


configure_logging()
admin_logger = logging.getLogger("admin")
auth_logger = logging.getLogger("auth")
vpn_logger = logging.getLogger("vpn")


class Service(db.Model):
    __tablename__ = "services"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    icon = db.Column(db.String(120), nullable=False)
    status_text = db.Column(db.String(40), nullable=False, default="Нужен обход")
    status_color = db.Column(db.String(20), nullable=False, default="danger")
    sort_order = db.Column(db.Integer, nullable=False, default=0)


class VPN(db.Model):
    __tablename__ = "vpns"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    logo_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.Boolean, nullable=False, default=False)
    check_url = db.Column(db.String(500), nullable=False)
    button_enabled = db.Column(db.Boolean, nullable=False, default=False)
    install_url = db.Column(db.String(500), nullable=True)
    extension_url = db.Column(db.String(500), nullable=True)
    chrome_extension_id = db.Column(db.String(80), nullable=True)
    is_paid = db.Column(db.Boolean, nullable=False, default=False)
    price_text = db.Column(db.String(80), nullable=True)
    purchase_url = db.Column(db.String(500), nullable=True)
    key_note = db.Column(db.String(300), nullable=True)
    failure_count = db.Column(db.Integer, nullable=False, default=0)
    last_checked = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String(500), nullable=True)


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class AdminAction(db.Model):
    __tablename__ = "admin_actions"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class StatusHistory(db.Model):
    __tablename__ = "status_history"

    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(30), nullable=False)
    item_id = db.Column(db.Integer, nullable=False)
    item_name = db.Column(db.String(120), nullable=False)
    status_text = db.Column(db.String(80), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class InstructionContent(db.Model):
    __tablename__ = "instruction_content"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body_markdown = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class InstructionStep(db.Model):
    __tablename__ = "instruction_steps"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=False)
    sort_order = db.Column(db.Integer, nullable=False, default=0)


class DownloadFile(db.Model):
    __tablename__ = "download_files"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), nullable=False, unique=True)
    title = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(30), nullable=False, default="text")
    download_count = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


DEFAULT_SERVICES = [
    {"name": "YouTube", "icon": "fa-brands fa-youtube"},
    {"name": "Telegram", "icon": "fa-brands fa-telegram"},
    {"name": "Instagram", "icon": "fa-brands fa-instagram"},
    {"name": "Twitter", "icon": "fa-brands fa-x-twitter"},
    {"name": "WhatsApp", "icon": "fa-brands fa-whatsapp"},
    {"name": "Max", "icon": "fa-solid fa-comment-dots"},
    {"name": "Snapchat", "icon": "fa-brands fa-snapchat"},
    {"name": "ChatGPT", "icon": "fa-solid fa-robot"},
    {"name": "Claude", "icon": "fa-solid fa-brain"},
]

DEFAULT_VPN_PURCHASE_URL = os.getenv("VPN_PURCHASE_URL", "https://t.me/your_vpn_shop")

DEFAULT_VPNS = [
    {
        "name": "Browsec",
        "logo_url": "https://placehold.co/72x72/1f6feb/ffffff?text=BR",
        "check_url": "https://browsec.com",
        "install_url": "",
        "extension_url": "https://chromewebstore.google.com/detail/browsec-vpn-privacy-and-s/omghfjlpggmjjaagoclmmobgdodcjboh",
        "chrome_extension_id": "omghfjlpggmjjaagoclmmobgdodcjboh",
        "is_paid": False,
    },
    {
        "name": "VeePN",
        "logo_url": "https://placehold.co/72x72/0d6efd/ffffff?text=VP",
        "check_url": "https://veepn.com",
        "install_url": "",
        "extension_url": "https://chromewebstore.google.com/detail/free-vpn-for-chrome-vpn-p/majdfhpaihoncoakbjgbdhglocklcgno",
        "chrome_extension_id": "majdfhpaihoncoakbjgbdhglocklcgno",
        "is_paid": False,
    },
    {
        "name": "Proton VPN",
        "logo_url": "https://placehold.co/72x72/6d4aff/ffffff?text=PV",
        "check_url": "https://protonvpn.com",
        "install_url": "",
        "extension_url": "https://protonvpn.com/download-chrome-extension",
        "chrome_extension_id": "jplgfhpmjnbigmhklmmbgecoobifkmpa",
        "is_paid": False,
    },
    {
        "name": "TunnelBear",
        "logo_url": "https://placehold.co/72x72/f59f00/ffffff?text=TB",
        "check_url": "https://tunnelbear.com",
        "install_url": "",
        "extension_url": "https://chromewebstore.google.com/detail/tunnelbear-vpn/omdakjcmkglenbhjadbccaookpfjihpa",
        "chrome_extension_id": "omdakjcmkglenbhjadbccaookpfjihpa",
        "is_paid": False,
    },
    {
        "name": "Free VPN Proxy",
        "logo_url": "https://placehold.co/72x72/20c997/ffffff?text=FV",
        "check_url": "https://freevpn.zone",
        "install_url": "",
        "extension_url": "https://chromewebstore.google.com/detail/free-vpn-proxy/jajilbjjinjmgcibalaakngmkilboobh",
        "chrome_extension_id": "jajilbjjinjmgcibalaakngmkilboobh",
        "is_paid": False,
    },
    {
        "name": "SetupVPN",
        "logo_url": "https://placehold.co/72x72/198754/ffffff?text=SV",
        "check_url": "https://setupvpn.com",
        "install_url": "",
        "extension_url": "https://chromewebstore.google.com/detail/setupvpn-lifetime-free-vp/oofgbpoabipfcfjapgnbbjjaenockbdp",
        "chrome_extension_id": "oofgbpoabipfcfjapgnbbjjaenockbdp",
        "is_paid": False,
    },
    {
        "name": "NordVPN",
        "logo_url": "https://placehold.co/72x72/2563eb/ffffff?text=NV",
        "check_url": "https://nordvpn.com",
        "install_url": "",
        "extension_url": "https://nordvpn.com/download/",
        "chrome_extension_id": "",
        "is_paid": True,
        "price_text": "от 299 ₽ / месяц",
        "purchase_url": DEFAULT_VPN_PURCHASE_URL,
        "key_note": "Ключ активирует премиум-доступ после бесплатной установки приложения.",
    },
    {
        "name": "Surfshark",
        "logo_url": "https://placehold.co/72x72/14b8a6/ffffff?text=SS",
        "check_url": "https://surfshark.com",
        "install_url": "",
        "extension_url": "https://surfshark.com/download",
        "chrome_extension_id": "",
        "is_paid": True,
        "price_text": "от 249 ₽ / месяц",
        "purchase_url": DEFAULT_VPN_PURCHASE_URL,
        "key_note": "Установщик бесплатный, платный ключ покупается отдельно у нас.",
    },
    {
        "name": "ExpressVPN",
        "logo_url": "https://placehold.co/72x72/ef4444/ffffff?text=EV",
        "check_url": "https://expressvpn.com",
        "install_url": "",
        "extension_url": "https://www.expressvpn.com/vpn-download",
        "chrome_extension_id": "",
        "is_paid": True,
        "price_text": "от 399 ₽ / месяц",
        "purchase_url": DEFAULT_VPN_PURCHASE_URL,
        "key_note": "После оплаты пользователь получает ключ и вводит его в установленном VPN.",
    },
    {
        "name": "CyberGhost",
        "logo_url": "https://placehold.co/72x72/facc15/182536?text=CG",
        "check_url": "https://www.cyberghostvpn.com",
        "install_url": "",
        "extension_url": "https://www.cyberghostvpn.com/en_US/download",
        "chrome_extension_id": "",
        "is_paid": True,
        "price_text": "от 199 ₽ / месяц",
        "purchase_url": DEFAULT_VPN_PURCHASE_URL,
        "key_note": "Сначала скачайте приложение, затем купите ключ доступа.",
    },
]

ZAPRET_RELEASE_API_URL = "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest"
CHROME_CRX_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3"
    "&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
)
CHROME_WEBSTORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"

DEFAULT_INSTRUCTION = """## Что скачивается

Сервис скачивает актуальный ZIP-релиз Flowseal/zapret-discord-youtube напрямую с GitHub. Это готовая Windows-сборка Zapret для обхода проблем доступа к Discord и YouTube.

## Как использовать

1. Скачайте ZIP-архив на этой странице.
2. Распакуйте архив в отдельную папку, например `C:\\zapret-discord-youtube`.
3. Откройте `service.bat` или подходящий `.bat`-профиль от имени администратора.
4. Выберите установку/запуск службы в меню проекта.
5. Перезапустите Discord, браузер и проверьте YouTube.

Используйте только официальный релиз и проверяйте содержимое архива перед запуском.
"""

DEFAULT_STEPS = [
    {
        "title": "Скачайте актуальный релиз",
        "body": "Кнопка скачивания получает последний ZIP-архив Flowseal/zapret-discord-youtube из GitHub Releases.",
        "image_url": "https://placehold.co/640x360/eef4fb/1f4f82?text=Step+1",
    },
    {
        "title": "Распакуйте архив",
        "body": "Создайте отдельную папку без кириллицы в пути и распакуйте туда все файлы архива.",
        "image_url": "https://placehold.co/640x360/e8f5e9/198754?text=Step+2",
    },
    {
        "title": "Запустите service.bat",
        "body": "Откройте файл от имени администратора и выберите подходящий пункт меню для установки или запуска службы.",
        "image_url": "https://placehold.co/640x360/fff4e5/f59f00?text=Step+3",
    },
    {
        "title": "Проверьте результат",
        "body": "Перезапустите Discord и браузер, затем откройте YouTube и проверьте загрузку видео.",
        "image_url": "https://placehold.co/640x360/f8d7da/dc3545?text=Step+4",
    },
]

ICON_OPTIONS = [
    ("fa-brands fa-youtube", "YouTube"),
    ("fa-brands fa-telegram", "Telegram"),
    ("fa-brands fa-instagram", "Instagram"),
    ("fa-brands fa-x-twitter", "Twitter / X"),
    ("fa-brands fa-whatsapp", "WhatsApp"),
    ("fa-brands fa-snapchat", "Snapchat"),
    ("fa-solid fa-comment-dots", "Мессенджер"),
    ("fa-solid fa-globe", "Сайт"),
]


def username() -> str:
    return session.get("admin_username", "system")


def is_admin() -> bool:
    return bool(session.get("admin_id"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def admin_required():
    if not is_admin():
        flash("Требуется вход администратора.", "warning")
        return redirect(url_for("admin"))
    return None


def log_action(action: str, details: str = "") -> None:
    admin_logger.info("%s: %s", username(), f"{action} {details}".strip())
    db.session.add(AdminAction(username=username(), action=action, details=details))


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not sent or sent != session.get("csrf_token"):
        abort(400, "CSRF token is invalid")


@app.before_request
def protect_forms():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        validate_csrf()


@app.context_processor
def inject_globals():
    return {
        "is_admin": is_admin(),
        "csrf_token": get_csrf_token,
        "icon_options": ICON_OPTIONS,
    }


def migrate_database() -> None:
    db.create_all()
    if db.engine.name != "sqlite":
        db.session.commit()
        return

    migrations = {
        "services": [
            ("sort_order", "ALTER TABLE services ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"),
        ],
        "vpns": [
            ("install_url", "ALTER TABLE vpns ADD COLUMN install_url VARCHAR(500)"),
            ("extension_url", "ALTER TABLE vpns ADD COLUMN extension_url VARCHAR(500)"),
            ("chrome_extension_id", "ALTER TABLE vpns ADD COLUMN chrome_extension_id VARCHAR(80)"),
            ("is_paid", "ALTER TABLE vpns ADD COLUMN is_paid BOOLEAN NOT NULL DEFAULT 0"),
            ("price_text", "ALTER TABLE vpns ADD COLUMN price_text VARCHAR(80)"),
            ("purchase_url", "ALTER TABLE vpns ADD COLUMN purchase_url VARCHAR(500)"),
            ("key_note", "ALTER TABLE vpns ADD COLUMN key_note VARCHAR(300)"),
            ("failure_count", "ALTER TABLE vpns ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0"),
            ("last_checked", "ALTER TABLE vpns ADD COLUMN last_checked DATETIME"),
            ("last_error", "ALTER TABLE vpns ADD COLUMN last_error VARCHAR(500)"),
        ],
    }

    for table_name, table_migrations in migrations.items():
        columns = {
            row[1]
            for row in db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        }
        for column_name, statement in table_migrations:
            if column_name not in columns:
                db.session.execute(text(statement))

    db.session.commit()


def invalidate_service_cache() -> None:
    global SERVICE_CACHE
    SERVICE_CACHE = None


def service_rows() -> list[Service]:
    return Service.query.order_by(Service.sort_order.asc(), Service.id.asc()).all()


def service_cache() -> list[dict]:
    global SERVICE_CACHE
    if SERVICE_CACHE is None:
        SERVICE_CACHE = [
            {
                "id": service.id,
                "name": service.name,
                "icon": service.icon,
                "status_text": service.status_text,
                "status_color": service.status_color,
            }
            for service in service_rows()
        ]
    return SERVICE_CACHE


def seed_database() -> None:
    migrate_database()

    max_order = db.session.query(db.func.max(Service.sort_order)).scalar() or 0
    for index, item in enumerate(DEFAULT_SERVICES, start=1):
        service = Service.query.filter_by(name=item["name"]).first()
        if not service:
            max_order += 10
            db.session.add(
                Service(
                    name=item["name"],
                    icon=item["icon"],
                    status_text="Нужен обход",
                    status_color="danger",
                    sort_order=max_order,
                )
            )
        elif not service.icon:
            service.icon = item["icon"]
        elif service.sort_order == 0:
            service.sort_order = index * 10

    db.session.flush()

    default_names = [item["name"] for item in DEFAULT_SERVICES]
    default_services = Service.query.filter(Service.name.in_(default_names)).all()
    for service in Service.query.all():
        if service.status_text not in {"Работает", "Нужен обход"}:
            service.status_text = "Работает" if service.status_color == "success" else "Нужен обход"

    default_orders = [service.sort_order for service in default_services]
    if len(default_orders) != len(set(default_orders)):
        order_by_name = {name: (index + 1) * 10 for index, name in enumerate(default_names)}
        for service in default_services:
            service.sort_order = order_by_name.get(service.name, service.sort_order)

    default_vpn_names = {item["name"] for item in DEFAULT_VPNS}
    VPN.query.filter(~VPN.name.in_(default_vpn_names)).delete(synchronize_session=False)

    for item in DEFAULT_VPNS:
        vpn = VPN.query.filter_by(name=item["name"]).first()
        if not vpn:
            db.session.add(
                VPN(
                    name=item["name"],
                    logo_url=item["logo_url"],
                    check_url=item["check_url"],
                    install_url=item.get("install_url") or None,
                    extension_url=item.get("extension_url") or None,
                    chrome_extension_id=item.get("chrome_extension_id") or None,
                    is_paid=item.get("is_paid", False),
                    price_text=item.get("price_text") or None,
                    purchase_url=item.get("purchase_url") or None,
                    key_note=item.get("key_note") or None,
                    status=False,
                    button_enabled=False,
                )
            )
        else:
            vpn.logo_url = item["logo_url"]
            vpn.check_url = item["check_url"]
            vpn.install_url = item.get("install_url") or None
            vpn.extension_url = item.get("extension_url") or None
            vpn.chrome_extension_id = item.get("chrome_extension_id") or None
            vpn.is_paid = item.get("is_paid", False)
            vpn.price_text = item.get("price_text") or None
            vpn.purchase_url = item.get("purchase_url") or None
            vpn.key_note = item.get("key_note") or None

    instruction = InstructionContent.query.first()
    if not instruction:
        db.session.add(
            InstructionContent(
                title="Как обойти замедления YouTube, Instagram и других сервисов",
                body_markdown=DEFAULT_INSTRUCTION,
            )
        )
    else:
        instruction.title = "Как обойти замедления Discord и YouTube"
        instruction.body_markdown = DEFAULT_INSTRUCTION

    if InstructionStep.query.count() == 0:
        for order, step in enumerate(DEFAULT_STEPS, start=10):
            db.session.add(InstructionStep(sort_order=order, **step))
    else:
        existing_steps = InstructionStep.query.order_by(InstructionStep.sort_order, InstructionStep.id).all()
        for index, step_data in enumerate(DEFAULT_STEPS):
            step = existing_steps[index] if index < len(existing_steps) else None
            if step:
                step.title = step_data["title"]
                step.body = step_data["body"]
                step.image_url = step.image_url or step_data["image_url"]
                step.sort_order = (index + 1) * 10

    default_downloads = [
        ("zapret-configs", "Скачать актуальный Zapret для Discord / YouTube", "github_release"),
    ]
    for slug, title, file_type in default_downloads:
        item = DownloadFile.query.filter_by(slug=slug).first()
        if not item:
            db.session.add(DownloadFile(slug=slug, title=title, file_type=file_type))
        else:
            item.title = title
            item.file_type = file_type
            item.is_active = True

    legacy_manager = DownloadFile.query.filter_by(slug="vpn-manager").first()
    if legacy_manager:
        legacy_manager.is_active = False

    env_admin = os.getenv("ADMIN_USERNAME")
    env_hash = os.getenv("ADMIN_PASSWORD_HASH")
    if env_admin and env_hash and not AdminUser.query.filter_by(username=env_admin).first():
        db.session.add(AdminUser(username=env_admin, password_hash=env_hash))

    db.session.commit()
    invalidate_service_cache()


def check_http_url(url: str) -> tuple[bool, str | None]:
    req = Request(
        url,
        headers={
            "User-Agent": "StatusServicesBot/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=5) as response:
            return 200 <= response.status < 500, None
    except Exception as exc:
        return False, str(exc)[:450]


def parse_tcp_target(check_url: str) -> tuple[str, int] | None:
    raw = check_url.strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"tcp://{raw}")
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        return parsed.hostname, parsed.port or (443 if scheme == "https" else 80)
    if scheme == "tcp":
        return parsed.hostname, parsed.port or 443
    if ":" in raw and "://" not in raw:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return raw, 443


def check_tcp(check_url: str) -> tuple[bool, str | None]:
    target = parse_tcp_target(check_url)
    if not target or not target[0]:
        return False, "Не указан адрес проверки"
    host, port = target
    try:
        with socket.create_connection((host, port), timeout=5):
            return True, None
    except OSError as exc:
        return False, str(exc)[:450]


def probe_vpn(check_url: str) -> tuple[bool, str | None]:
    parsed = urlparse(check_url.strip())
    if parsed.scheme in {"http", "https"}:
        ok, error = check_http_url(check_url)
        if ok:
            return True, None
        tcp_ok, tcp_error = check_tcp(check_url)
        return tcp_ok, None if tcp_ok else f"HTTP: {error}; TCP: {tcp_error}"
    return check_tcp(check_url)


def check_all_vpns() -> None:
    with app.app_context():
        for vpn in VPN.query.order_by(VPN.id).all():
            ok, error = probe_vpn(vpn.check_url)
            previous_status = vpn.status
            if ok:
                vpn.failure_count = 0
                vpn.status = True
                vpn.button_enabled = True
                vpn.last_error = None
            else:
                vpn.failure_count += 1
                vpn.last_error = error
                if vpn.failure_count >= 3 or not previous_status:
                    vpn.status = False
                    vpn.button_enabled = False

            vpn.last_checked = datetime.utcnow()
            db.session.add(
                StatusHistory(
                    item_type="vpn",
                    item_id=vpn.id,
                    item_name=vpn.name,
                    status_text="Работает" if vpn.status else "Не работает",
                    details=json.dumps(
                        {
                            "probe_success": ok,
                            "failure_count": vpn.failure_count,
                            "error": vpn.last_error,
                        },
                        ensure_ascii=False,
                    ),
                )
            )
            vpn_logger.info(
                "%s status=%s probe=%s failures=%s error=%s",
                vpn.name,
                vpn.status,
                ok,
                vpn.failure_count,
                vpn.last_error or "",
            )
        db.session.commit()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(
        check_all_vpns,
        "interval",
        hours=4,
        id="vpn_status_check",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()


def latest_vpn_check_text() -> str:
    latest = db.session.query(db.func.max(VPN.last_checked)).scalar()
    if not latest:
        return "проверка еще не выполнялась"
    delta = datetime.utcnow() - latest
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "только что"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} мин. назад"
    hours = minutes // 60
    return f"{hours} ч. назад"


def render_instruction_markdown(text_value: str) -> str:
    return markdown.markdown(text_value, extensions=["extra", "sane_lists"])


def allowed_upload(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "webp", "gif"}


def github_json(url: str) -> dict:
    req = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "StatusServicesBot/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def latest_zapret_release_asset() -> tuple[str, str, str]:
    release = github_json(ZAPRET_RELEASE_API_URL)
    assets = release.get("assets", [])
    zip_assets = [
        asset
        for asset in assets
        if asset.get("browser_download_url") and asset.get("name", "").lower().endswith(".zip")
    ]
    if not zip_assets:
        raise RuntimeError("В последнем релизе Zapret не найден ZIP-архив.")

    asset = zip_assets[0]
    tag_name = release.get("tag_name") or "latest"
    return asset["browser_download_url"], asset.get("name") or f"zapret-{tag_name}.zip", tag_name


def stream_remote_file(url: str) -> tuple[io.BytesIO, int]:
    req = Request(url, headers={"User-Agent": "StatusServicesBot/1.0"})
    with urlopen(req, timeout=60) as response:
        data = response.read()
    return io.BytesIO(data), len(data)


def safe_filename(value: str, suffix: str) -> str:
    cleaned = "".join(ch for ch in value.lower().replace(" ", "-") if ch.isalnum() or ch in {"-", "_"})
    return f"{cleaned or 'download'}{suffix}"


def vpn_cache_path(vpn: VPN, suffix: str) -> Path:
    app.config["VPN_DOWNLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)
    return app.config["VPN_DOWNLOAD_FOLDER"] / safe_filename(vpn.name, suffix)


def cache_remote_to_file(url: str, path: Path) -> int:
    if path.exists() and path.stat().st_size > 1024:
        return path.stat().st_size

    path.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=120) as response:
        data = response.read()
    if len(data) <= 1024:
        raise RuntimeError("Скачанный файл подозрительно мал или пуст.")
    path.write_bytes(data)
    return len(data)


def ensure_vpn_installer(vpn: VPN) -> tuple[Path, int]:
    if not vpn.install_url:
        raise RuntimeError("Для этого VPN нет прямого EXE-установщика.")
    path = vpn_cache_path(vpn, ".exe")
    size = cache_remote_to_file(vpn.install_url, path)
    return path, size


def ensure_vpn_crx(vpn: VPN) -> tuple[Path, int]:
    if not vpn.chrome_extension_id:
        raise RuntimeError("Для этого VPN нет Chrome extension id.")
    path = vpn_cache_path(vpn, ".crx")
    url = CHROME_CRX_URL.format(extension_id=vpn.chrome_extension_id)
    size = cache_remote_to_file(url, path)
    return path, size


def crx_manifest_version(path: Path) -> str:
    data = path.read_bytes()
    if data[:4] != b"Cr24":
        raise RuntimeError("Файл расширения не похож на CRX.")

    crx_version = int.from_bytes(data[4:8], "little")
    if crx_version == 2:
        public_key_len = int.from_bytes(data[8:12], "little")
        signature_len = int.from_bytes(data[12:16], "little")
        zip_start = 16 + public_key_len + signature_len
    elif crx_version == 3:
        header_len = int.from_bytes(data[8:12], "little")
        zip_start = 12 + header_len
    else:
        raise RuntimeError(f"Неподдерживаемая версия CRX: {crx_version}")

    with zipfile.ZipFile(io.BytesIO(data[zip_start:])) as archive:
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    return manifest.get("version", "1.0.0")


def extension_update_url(vpn: VPN) -> str:
    return url_for("extension_update_xml", vpn_id=vpn.id, _external=True)


def extension_crx_url(vpn: VPN) -> str:
    return url_for("extension_crx_file", vpn_id=vpn.id, _external=True)


def extension_policy_value(vpn: VPN) -> str:
    return f"{vpn.chrome_extension_id};{CHROME_WEBSTORE_UPDATE_URL}"


def build_extension_installer_zip(vpn: VPN) -> io.BytesIO:
    policy_value = extension_policy_value(vpn)
    filename = safe_filename(vpn.name, ".zip")

    install_bat = f"""@echo off
setlocal
set "SCRIPT=%~dp0install-chrome-edge-policy.ps1"
if not exist "%SCRIPT%" (
  echo install-chrome-edge-policy.ps1 was not found next to this BAT file.
  pause
  exit /b 1
)
fltmc >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
pause
endlocal
"""
    uninstall_bat = f"""@echo off
setlocal
set "SCRIPT=%~dp0uninstall-chrome-edge-policy.ps1"
if not exist "%SCRIPT%" (
  echo uninstall-chrome-edge-policy.ps1 was not found next to this BAT file.
  pause
  exit /b 1
)
fltmc >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
pause
endlocal
"""
    install_ps1 = f"""$ErrorActionPreference = "Stop"
$extensionName = {json.dumps(vpn.name)}
$extensionId = {json.dumps(vpn.chrome_extension_id)}
$policyValue = {json.dumps(policy_value)}

function Set-ExtensionPolicyValue {{
    param(
        [string]$Path,
        [string]$Value
    )

    New-Item -Path $Path -Force | Out-Null
    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $slot = $null

    if ($properties) {{
        foreach ($property in $properties.PSObject.Properties) {{
            if ($property.Name -match "^\\d+$" -and [string]$property.Value -like "$extensionId;*") {{
                $slot = $property.Name
                break
            }}
        }}

        if (-not $slot) {{
            $numbers = @(
                $properties.PSObject.Properties |
                    Where-Object {{ $_.Name -match "^\\d+$" }} |
                    ForEach-Object {{ [int]$_.Name }}
            )
            $slot = if ($numbers.Count) {{ (($numbers | Measure-Object -Maximum).Maximum + 1).ToString() }} else {{ "1" }}
        }}
    }} else {{
        $slot = "1"
    }}

    New-ItemProperty -Path $Path -Name $slot -Value $Value -PropertyType String -Force | Out-Null
}}

$targets = @(
    "HKLM:\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    "HKLM:\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist",
    "HKCU:\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    "HKCU:\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist"
)

Write-Host "Installing $extensionName for Chrome and Edge..."
foreach ($target in $targets) {{
    Set-ExtensionPolicyValue -Path $target -Value $policyValue
    Write-Host "OK: $target"
}}

Write-Host ""
Write-Host "Policy value:"
Write-Host $policyValue
Write-Host ""
$answer = Read-Host "Close Chrome/Edge now so the extension appears on next launch? [Y/n]"
if ($answer -notmatch "^(n|no|N|NO)$") {{
    Stop-Process -Name chrome,msedge -Force -ErrorAction SilentlyContinue
    Write-Host "Chrome and Edge were closed. Open the browser again and check chrome://extensions or edge://extensions."
}} else {{
    Write-Host "Open chrome://policy or edge://policy, click Reload policies, then restart the browser."
}}
Write-Host ""
Read-Host "Press Enter to exit"
"""
    uninstall_ps1 = f"""$ErrorActionPreference = "SilentlyContinue"
$extensionName = {json.dumps(vpn.name)}
$extensionId = {json.dumps(vpn.chrome_extension_id)}

function Remove-ExtensionPolicyValue {{
    param([string]$Path)

    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if (-not $properties) {{
        return
    }}

    foreach ($property in $properties.PSObject.Properties) {{
        if ($property.Name -match "^\\d+$" -and [string]$property.Value -like "$extensionId;*") {{
            Remove-ItemProperty -Path $Path -Name $property.Name -Force
            Write-Host "Removed: $Path\\$($property.Name)"
        }}
    }}
}}

$targets = @(
    "HKLM:\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    "HKLM:\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist",
    "HKCU:\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    "HKCU:\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist"
)

Write-Host "Removing $extensionName policy from Chrome and Edge..."
foreach ($target in $targets) {{
    Remove-ExtensionPolicyValue -Path $target
}}
Write-Host "Done. Restart Chrome and Edge."
Read-Host "Press Enter to exit"
"""
    readme = f"""Extension installer for {vpn.name}

Files:
- install-chrome-edge-policy.bat: starts the installer with administrator rights.
- install-chrome-edge-policy.ps1: installs the extension through Chrome/Edge policy.
- uninstall-chrome-edge-policy.bat: starts the remover with administrator rights.
- uninstall-chrome-edge-policy.ps1: removes that policy.

Install:
1. Extract the ZIP archive.
2. Run install-chrome-edge-policy.bat.
3. Accept the Windows administrator prompt.
4. Let the installer close Chrome/Edge, then open the browser again.

Extension ID: {vpn.chrome_extension_id}
Policy value: {policy_value}

The extension is installed from the Chrome Web Store update service.
Policy installation is the supported silent-install method for Chrome/Edge.
"""

    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("install-chrome-edge-policy.bat", install_bat.encode("ascii"))
        archive.writestr("install-chrome-edge-policy.ps1", install_ps1.encode("utf-8-sig"))
        archive.writestr("uninstall-chrome-edge-policy.bat", uninstall_bat.encode("ascii"))
        archive.writestr("uninstall-chrome-edge-policy.ps1", uninstall_ps1.encode("utf-8-sig"))
        archive.writestr("README.txt", readme.encode("utf-8"))
    memory.seek(0)
    return memory


@app.route("/")
def index():
    vpns = VPN.query.order_by(VPN.id).all()
    return render_template(
        "index.html",
        services=service_cache(),
        vpns=vpns,
        latest_vpn_check=latest_vpn_check_text(),
    )


@app.route("/obhod")
def obhod():
    instruction = InstructionContent.query.first()
    steps = InstructionStep.query.order_by(InstructionStep.sort_order, InstructionStep.id).all()
    downloads = DownloadFile.query.filter_by(is_active=True).order_by(DownloadFile.id).all()
    return render_template(
        "obhod.html",
        instruction=instruction,
        instruction_html=render_instruction_markdown(instruction.body_markdown),
        steps=steps,
        downloads=downloads,
    )


@app.route("/download/<slug>")
def download_file(slug: str):
    item = DownloadFile.query.filter_by(slug=slug, is_active=True).first_or_404()
    if item.slug == "zapret-configs" or item.file_type == "github_release":
        try:
            download_url, filename, tag_name = latest_zapret_release_asset()
            memory, size = stream_remote_file(download_url)
        except Exception as exc:
            flash(f"Не удалось скачать актуальный Zapret с GitHub: {exc}", "danger")
            return redirect(url_for("obhod"))

        item.download_count += 1
        db.session.add(
            StatusHistory(
                item_type="download",
                item_id=item.id,
                item_name=item.title,
                status_text=f"downloaded {tag_name}",
                details=json.dumps({"source": download_url, "bytes": size}, ensure_ascii=False),
            )
        )
        db.session.commit()
        return send_file(
            memory,
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename,
        )

    abort(404)


@app.route("/download/setup.exe")
def legacy_download_setup():
    return redirect(url_for("download_file", slug="zapret-configs"))


@app.route("/download/vpn/<int:vpn_id>")
def download_vpn(vpn_id: int):
    vpn = db.session.get(VPN, vpn_id) or abort(404)

    if vpn.chrome_extension_id:
        try:
            memory = build_extension_installer_zip(vpn)
        except Exception as exc:
            flash(f"Не удалось скачать расширение {vpn.name}: {exc}", "danger")
            return redirect(url_for("index"))

        db.session.add(
            StatusHistory(
                item_type="vpn_download",
                item_id=vpn.id,
                item_name=vpn.name,
                status_text="extension_installer_downloaded",
                details=json.dumps({"extension_id": vpn.chrome_extension_id}, ensure_ascii=False),
            )
        )
        db.session.commit()
        return send_file(
            memory,
            mimetype="application/zip",
            as_attachment=True,
            download_name=safe_filename(vpn.name + "-extension-installer", ".zip"),
        )

    if vpn.install_url:
        try:
            path, size = ensure_vpn_installer(vpn)
        except Exception as exc:
            flash(f"Не удалось скачать установщик {vpn.name}: {exc}", "danger")
            return redirect(url_for("index"))

        db.session.add(
            StatusHistory(
                item_type="vpn_download",
                item_id=vpn.id,
                item_name=vpn.name,
                status_text="installer_downloaded",
                details=json.dumps({"bytes": size, "source": vpn.install_url}, ensure_ascii=False),
            )
        )
        db.session.commit()
        return send_file(
            path,
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=path.name,
        )

    flash("Для этого VPN пока нет прямого файла установки.", "warning")
    return redirect(url_for("index"))


@app.route("/extensions/<int:vpn_id>/update.xml")
def extension_update_xml(vpn_id: int):
    vpn = db.session.get(VPN, vpn_id) or abort(404)
    if not vpn.chrome_extension_id:
        abort(404)
    crx_path, _ = ensure_vpn_crx(vpn)
    version = crx_manifest_version(crx_path)
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="{vpn.chrome_extension_id}">
    <updatecheck codebase="{extension_crx_url(vpn)}" version="{version}" />
  </app>
</gupdate>
"""
    return Response(xml, mimetype="application/xml")


@app.route("/extensions/<int:vpn_id>/file.crx")
def extension_crx_file(vpn_id: int):
    vpn = db.session.get(VPN, vpn_id) or abort(404)
    if not vpn.chrome_extension_id:
        abort(404)
    path, _ = ensure_vpn_crx(vpn)
    return send_file(
        path,
        mimetype="application/x-chrome-extension",
        as_attachment=False,
        download_name=path.name,
    )


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST" and request.form.get("action") == "login":
        username_value = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = AdminUser.query.filter_by(username=username_value).first()
        if user and verify_password(password, user.password_hash):
            session["admin_id"] = user.id
            session["admin_username"] = user.username
            log_action("login", "success")
            db.session.commit()
            flash("Вход выполнен.", "success")
            return redirect(url_for("admin"))

        auth_logger.warning("failed login username=%s ip=%s", username_value, request.remote_addr)
        flash("Неверный логин или пароль.", "danger")

    if not is_admin():
        return render_template("admin.html", login_only=True)

    instruction = InstructionContent.query.first()
    return render_template(
        "admin.html",
        login_only=False,
        services=service_rows(),
        vpns=VPN.query.order_by(VPN.id).all(),
        instruction=instruction,
        steps=InstructionStep.query.order_by(InstructionStep.sort_order, InstructionStep.id).all(),
        downloads=DownloadFile.query.order_by(DownloadFile.id).all(),
        admins=AdminUser.query.order_by(AdminUser.id).all(),
    )


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    if is_admin():
        log_action("logout")
        db.session.commit()
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    flash("Вы вышли из админки.", "info")
    return redirect(url_for("index"))


@app.route("/admin/services", methods=["POST"])
def save_services():
    blocked = admin_required()
    if blocked:
        return blocked

    for service in service_rows():
        active = request.form.get(f"service_{service.id}") == "on"
        new_text = "Работает" if active else "Нужен обход"
        new_color = "success" if active else "danger"
        if service.status_text != new_text:
            db.session.add(
                StatusHistory(
                    item_type="service",
                    item_id=service.id,
                    item_name=service.name,
                    status_text=new_text,
                )
            )
        service.status_text = new_text
        service.status_color = new_color

    log_action("save_services")
    db.session.commit()
    invalidate_service_cache()
    flash("Статусы сервисов сохранены.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/services/add", methods=["POST"])
def add_service():
    abort(404)


@app.route("/admin/services/order", methods=["POST"])
def save_service_order():
    blocked = admin_required()
    if blocked:
        return blocked

    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids", [])
    for order, service_id in enumerate(ids, start=1):
        service = db.session.get(Service, int(service_id))
        if service:
            service.sort_order = order * 10
    log_action("save_service_order", ",".join(map(str, ids)))
    db.session.commit()
    invalidate_service_cache()
    return jsonify({"ok": True})


@app.route("/admin/check-vpns", methods=["POST"])
def force_check_vpns():
    blocked = admin_required()
    if blocked:
        return blocked
    check_all_vpns()
    log_action("force_check_vpns")
    db.session.commit()
    flash("VPN проверены принудительно.", "success")
    return redirect(request.referrer or url_for("admin"))


@app.route("/admin/vpns/add", methods=["POST"])
def add_vpn():
    abort(404)


@app.route("/admin/instruction", methods=["POST"])
def save_instruction():
    blocked = admin_required()
    if blocked:
        return blocked

    instruction = InstructionContent.query.first()
    instruction.title = request.form.get("title", "").strip() or instruction.title
    instruction.body_markdown = request.form.get("body_markdown", "").strip() or instruction.body_markdown
    instruction.updated_at = datetime.utcnow()
    log_action("save_instruction")
    db.session.commit()
    flash("Инструкция обновлена.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/steps/upload", methods=["POST"])
def upload_step_image():
    blocked = admin_required()
    if blocked:
        return blocked

    step = db.session.get(InstructionStep, int(request.form.get("step_id", "0")))
    file = request.files.get("image")
    if not step or not file or not file.filename or not allowed_upload(file.filename):
        flash("Выберите корректную картинку для шага.", "danger")
        return redirect(url_for("admin"))

    app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)
    filename = f"step-{step.id}-{int(time.time())}-{secure_filename(file.filename)}"
    file.save(app.config["UPLOAD_FOLDER"] / filename)
    step.image_url = url_for("static", filename=f"uploads/{filename}")
    log_action("upload_step_image", step.title)
    db.session.commit()
    flash("Картинка шага обновлена.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/downloads/add", methods=["POST"])
def add_download():
    blocked = admin_required()
    if blocked:
        return blocked

    title = request.form.get("title", "").strip()
    slug = request.form.get("slug", "").strip()
    file_type = request.form.get("file_type", "text")
    if not title or not slug:
        flash("Укажите название и slug файла.", "danger")
        return redirect(url_for("admin"))
    if DownloadFile.query.filter_by(slug=slug).first():
        flash("Файл с таким slug уже есть.", "danger")
        return redirect(url_for("admin"))
    db.session.add(DownloadFile(title=title, slug=slug, file_type=file_type))
    log_action("add_download", slug)
    db.session.commit()
    flash("Файл добавлен.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/downloads/<int:file_id>/delete", methods=["POST"])
def delete_download(file_id: int):
    blocked = admin_required()
    if blocked:
        return blocked
    item = db.session.get(DownloadFile, file_id) or abort(404)
    item.is_active = False
    log_action("delete_download", item.slug)
    db.session.commit()
    flash("Файл скрыт из скачивания.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/users/add", methods=["POST"])
def add_admin_user():
    blocked = admin_required()
    if blocked:
        return blocked

    new_username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not new_username or len(password) < 6:
        flash("Укажите логин и пароль минимум 6 символов.", "danger")
        return redirect(url_for("admin"))
    if AdminUser.query.filter_by(username=new_username).first():
        flash("Администратор с таким логином уже есть.", "danger")
        return redirect(url_for("admin"))
    db.session.add(AdminUser(username=new_username, password_hash=hash_password(password)))
    log_action("add_admin_user", new_username)
    db.session.commit()
    flash("Администратор добавлен.", "success")
    return redirect(url_for("admin"))


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "services": service_cache(),
            "vpns": [
                {
                    "id": vpn.id,
                    "name": vpn.name,
                    "status": vpn.status,
                    "status_text": "Работает" if vpn.status else "Не работает",
                    "last_checked": vpn.last_checked.isoformat() if vpn.last_checked else None,
                    "failure_count": vpn.failure_count,
                    "is_paid": vpn.is_paid,
                    "price_text": vpn.price_text,
                }
                for vpn in VPN.query.order_by(VPN.id).all()
            ],
            "latest_vpn_check": latest_vpn_check_text(),
        }
    )


@app.route("/api/history")
def api_history():
    rows = StatusHistory.query.order_by(StatusHistory.created_at.desc()).limit(100).all()
    return jsonify(
        [
            {
                "id": row.id,
                "item_type": row.item_type,
                "item_id": row.item_id,
                "item_name": row.item_name,
                "status_text": row.status_text,
                "details": row.details,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    )


@app.route("/api/services/html")
def api_services_html():
    return render_template("_service_list.html", services=service_cache())


@app.route("/api/vpns/html")
def api_vpns_html():
    return render_template(
        "_vpn_cards.html",
        vpns=VPN.query.order_by(VPN.id).all(),
        latest_vpn_check=latest_vpn_check_text(),
    )


@app.route("/api/vpns/refresh", methods=["POST"])
def api_refresh_vpns():
    now = time.time()
    last = float(session.get("last_public_vpn_refresh", 0))
    if now - last < 60:
        wait = int(60 - (now - last))
        return jsonify({"ok": False, "message": f"Повторная проверка будет доступна через {wait} сек."}), 429
    session["last_public_vpn_refresh"] = now
    check_all_vpns()
    return jsonify(
        {
            "ok": True,
            "html": render_template(
                "_vpn_cards.html",
                vpns=VPN.query.order_by(VPN.id).all(),
                latest_vpn_check=latest_vpn_check_text(),
            ),
            "latest_vpn_check": latest_vpn_check_text(),
        }
    )


def initialize_app() -> None:
    global APP_INITIALIZED
    if APP_INITIALIZED:
        return
    with app.app_context():
        seed_database()
        if not any(vpn.last_checked for vpn in VPN.query.all()):
            check_all_vpns()
    start_scheduler()
    APP_INITIALIZED = True


initialize_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
