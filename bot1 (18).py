# ... (Previous code unchanged up to handlers)

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

async def check_link_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.callback_query.message.reply_text("Contact admin to access the bot.")
        await update.callback_query.answer()
        return
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("Send a URL (e.g., http://86.103.65.158:8443/login) or IP to check for admin panel:")
    context.user_data["awaiting_checklink"] = True

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
            return PORT
    # ... (rest unchanged)

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
    # ... (rest unchanged)

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized_user(update, context):
        await update.message.reply_text("Contact admin to access the bot.")
        return
    if not (context.user_data.get("awaiting_checklink", False) or (context.args and len(context.args) > 0)):
        await update.message.reply_text(
            "Send a URL (e.g., http://86.103.65.158:8443/login) or IP to check for admin panel:",
            reply_markup=main_menu_markup()
        )
        return

    input_text = update.message.text.strip() if context.user_data.get("awaiting_checklink") else context.args[0].strip()
    context.user_data["awaiting_checklink"] = False
    logger.debug(f"Check Link input: {input_text}")

    ip = None
    port = 80
    path = "/"
    protocol = "http"

    if input_text.startswith(("http://", "https://")):
        parsed_url = urlparse(input_text)
        logger.debug(f"Parsed URL: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, hostname={parsed_url.hostname}, port={parsed_url.port}, path={parsed_url.path}")
        if not parsed_url.hostname:
            netloc = parsed_url.netloc.split(":")[0]
            if is_valid_ipv4(netloc):
                ip = netloc
            else:
                await update.message.reply_text("Invalid URL: No valid IP found!", reply_markup=main_menu_markup())
                return
        else:
            ip = parsed_url.hostname
        if not is_valid_ipv4(ip):
            logger.debug(f"Invalid IP: {ip}")
            await update.message.reply_text("Invalid IP! Try a valid IPv4 (e.g., 86.103.65.158).", reply_markup=main_menu_markup())
            return
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"
        protocol = parsed_url.scheme
    elif is_valid_ipv4(input_text):
        ip = input_text
        port = 80
        path = "/"
    elif input_text.startswith("/"):
        if not context.user_data.get("ip"):
            await update.message.reply_text(
                "No IP provided. Run /hack first or provide a full URL/IP.", reply_markup=main_menu_markup()
            )
            return
        ip = context.user_data["ip"]
        path = input_text
        port = context.user_data.get("port", 80)
        protocol = context.user_data.get("protocol", "http")
    else:
        await update.message.reply_text(
            "Invalid input! Use a URL (e.g., http://86.103.65.158:8443/login) or IP (e.g., 86.103.65.158).",
            reply_markup=main_menu_markup()
        )
        return

    url = f"{protocol}://{ip}:{port}{path}"
    logger.debug(f"Constructed URL: {url}")

    try:
        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} is closed on {ip}. Try another port:", reply_markup=main_menu_markup())
            return

        geo = await get_geo(ip, context)
        geo_text = f"🌍 Location: {geo}\n" if geo != "Unknown" else ""

        is_admin, details = await check_admin_panel(url)
        panel_name = path.strip("/") or "root"

        admin_id = f"a{len(context.user_data.get('admin_urls', {})) + 1}"
        context.user_data.setdefault("admin_urls", {})[admin_id] = url
        keyboard = [
            [InlineKeyboardButton(f"Visit {panel_name}", url=url)],
            [InlineKeyboardButton(f"Start Brute-Force {panel_name}", callback_data=f"hunt_{ip}_{port}_{admin_id}")],
            [InlineKeyboardButton("Main Menu", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        if is_admin:
            context.user_data.setdefault("admin_pages", []).append(url)
            await update.message.reply_text(
                f"{geo_text}✅ **Admin Panel**: {panel_name} 🎯\nURL: {url}\nDetails: {', '.join(details)}",
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
            try:
                await context.bot.send_message(
                    chat_id=GROUP_CHAT_ID,
                    text=f"{geo_text}✅ **Admin Panel** for {ip}:{port}!\nURL: {url}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Group send error: {e}")
        else:
            await update.message.reply_text(
                f"{geo_text}❌ No admin panel found at {url}.\nDetails: {', '.join(details)}",
                reply_markup=reply_markup
            )

    except Exception as e:
        logger.error(f"Check link error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}", reply_markup=main_menu_markup())

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
    potential_links = context.user_data.get("potential_links", [])
    admin_pages = [admin_urls[admin_id]] if admin_id and admin_id in admin_urls else context.user_data.get("admin_pages", [])

    if not (potential_links or admin_pages):
        await query.message.reply_text(
            "No targets to brute-force. Run /hack or /checklink.", reply_markup=main_menu_markup()
        )
        return

    context.user_data["brute_force_running"] = True
    target = admin_urls.get(admin_id, f"{ip}:{port}")
    await query.message.reply_text(f"🔥 Trying 2000+ username-password combos on {target}...")
    # ... (rest unchanged)

# ... (Rest of the code unchanged)