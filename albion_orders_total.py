"""Albion Orders Total - Made by Shibarakiri - v1.0.1

Standalone replacement for albion_orders_total.py. No old script is needed.
Dependencies: python -m pip install scapy customtkinter pillow
Windows capture requires Npcap. Run with administrator rights if required.

Run:
    python albion_orders_total.py
    python albion_orders_total.py --demo
    python albion_orders_total.py --list
    python albion_orders_total.py --iface "INTERFACE NAME"

Save the supplied item picture as coin.png beside this script.
Optional application icon: icon.png or icon.ico.

Example Windows build (with coin.png present):
    pyinstaller --noconfirm --onefile --windowed --collect-all customtkinter --add-data "coin.png;." albion_orders_total.py

Next Market saves a snapshot of the current market, including its tax rate,
and starts an empty market. The live market is always included in All Markets.
Reset clears saved markets AND the current market, after confirmation.
Only orders observed since the last reset/market transition are counted.
Revisit every page of your own orders for each market. This is not an automatic
live inventory: orders that disappear from the game are not removed implicitly.
Saved markets are held in memory; export them before closing if needed.

The passive capture/Photon decoding approach is retained from the supplied
script. It does not send requests to the game or decrypt encrypted traffic.
Protocol operation numbers and tax presets are retained from that script,
not independently verified against a current game version.
"""

import argparse
import csv
import json
import os
import queue
import re
import struct
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageTk

TAX_PERCENT = 4
PRICE_DIVISOR = 10000
PORT = 5056
MY_CODES = {92, 93, 94}
BUY_CODES = {93}
NPCAP_URL = "https://npcap.com/#download"
OP_NAMES = {
    81: "AuctionGetOffers (public market)",
    82: "AuctionGetRequests (public market)",
    83: "AuctionBuyOffer",
    92: "AuctionGetMyOpenOffers (my sell orders)",
    93: "AuctionGetMyOpenRequests (my buy orders)",
    94: "AuctionGetMyOpenAuctions (my orders)",
}

# Photon / Protocol18 decoder, based on the decoder in the supplied script.
class Buf:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def left(self):
        return len(self.d) - self.p

    def byte(self):
        if self.p >= len(self.d):
            raise EOFError
        value = self.d[self.p]
        self.p += 1
        return value

    def read(self, size):
        if size < 0 or self.p + size > len(self.d):
            raise EOFError
        value = self.d[self.p:self.p + size]
        self.p += size
        return value


def uvarint(buf, maxshift=35):
    value = 0
    shift = 0
    while shift < maxshift:
        byte = buf.byte()
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value
        shift += 7
    raise ValueError("Invalid variable-length integer")


def zigzag(value):
    return (value >> 1) ^ -(value & 1)


def read_string(buf):
    size = uvarint(buf)
    return buf.read(size).decode("utf-8", "replace")


def custom_payload(buf, cid, slim):
    size = uvarint(buf)
    return {"type": cid, "data": buf.read(size)}


def read_custom(buf, gp):
    slim = gp >= 0x80
    cid = (gp & 0x7F) if slim else buf.byte()
    return custom_payload(buf, cid, slim)


def read_dict(buf):
    ktc, vtc = buf.byte(), buf.byte()
    count = uvarint(buf)
    if count > 100000:
        raise ValueError("Dictionary too large")
    result = {}
    for index in range(count):
        kt = buf.byte() if ktc == 0 else ktc
        vt = buf.byte() if vtc == 0 else vtc
        key, value = deserialize(buf, kt), deserialize(buf, vt)
        try:
            result[key] = value
        except TypeError:
            result[f"UNHASHABLE_{index}"] = value
    return result


def read_param_table(buf):
    count = uvarint(buf)
    if count > 256:
        raise ValueError("Parameter table too large")
    params = {}
    for _ in range(count):
        key = buf.byte()
        tc = buf.byte()
        params[key] = deserialize(buf, tc)
    return params


def read_typed_array(buf, et):
    size = uvarint(buf)
    if size > 1000000:
        raise ValueError("Array too large")
    if et == 2:
        packed = buf.read((size + 7) // 8)
        return [bool(packed[i // 8] & (1 << (i % 8))) for i in range(size)]
    if et == 3:
        return buf.read(size)
    formats = {4: ("<h", 2), 5: ("<f", 4), 6: ("<d", 8)}
    if et in formats:
        fmt_code, width = formats[et]
        return [struct.unpack(fmt_code, buf.read(width))[0] for _ in range(size)]
    if et == 7:
        return [read_string(buf) for _ in range(size)]
    if et == 19:
        cid = buf.byte()
        return [custom_payload(buf, cid, False) for _ in range(size)]
    if et in (20, 21):
        return [read_dict(buf) for _ in range(size)]
    if et in (9, 10):
        return [zigzag(uvarint(buf, 70 if et == 10 else 35)) for _ in range(size)]
    return [deserialize(buf, et) for _ in range(size)]


def deserialize(buf, tc):
    if tc >= 0x80:
        return read_custom(buf, tc)
    if tc in (0, 8):
        return None
    if tc == 2:
        return buf.byte() != 0
    if tc == 3:
        return buf.byte()
    if tc == 4:
        return struct.unpack("<h", buf.read(2))[0]
    if tc == 5:
        return struct.unpack("<f", buf.read(4))[0]
    if tc == 6:
        return struct.unpack("<d", buf.read(8))[0]
    if tc == 7:
        return read_string(buf)
    if tc in (9, 10):
        return zigzag(uvarint(buf, 70 if tc == 10 else 35))
    if tc in (11, 15):
        return buf.byte()
    if tc in (12, 16):
        return -buf.byte()
    if tc in (13, 17):
        return struct.unpack("<H", buf.read(2))[0]
    if tc in (14, 18):
        return -struct.unpack("<H", buf.read(2))[0]
    if tc == 19:
        return read_custom(buf, 0)
    if tc in (20, 21):
        return read_dict(buf)
    if tc == 23:
        size = uvarint(buf)
        if size > 1000000:
            raise ValueError("Array too large")
        return [deserialize(buf, buf.byte()) for _ in range(size)]
    if tc == 24:
        op = buf.byte()
        return {"operationCode": op, "parameters": read_param_table(buf)}
    if tc == 25:
        op = buf.byte()
        rc = struct.unpack("<h", buf.read(2))[0]
        debug = deserialize(buf, buf.byte())
        return {"operationCode": op, "returnCode": rc,
                "debugMessage": debug if isinstance(debug, str) else "",
                "parameters": read_param_table(buf)}
    if tc == 26:
        code = buf.byte()
        return {"code": code, "parameters": read_param_table(buf)}
    if tc == 27:
        return False
    if tc == 28:
        return True
    if tc in (29, 30, 31, 34):
        return 0
    if tc in (32, 33):
        return 0.0
    if tc == 0x40:
        size = uvarint(buf)
        if size > 1000000:
            raise ValueError("Array too large")
        et = buf.byte()
        return [deserialize(buf, et) for _ in range(size)]
    if tc & 0x40:
        return read_typed_array(buf, tc & ~0x40)
    raise ValueError(f"Unknown Photon type 0x{tc:02X}")


class PhotonParser:
    def __init__(self, on_request, on_response, on_encrypted):
        self.on_request = on_request
        self.on_response = on_response
        self.on_encrypted = on_encrypted
        self.pending = {}
        self.stream = None
        self.channel = 0

    def receive(self, payload, stream=None):
        self.stream = stream
        try:
            off = 0
            while off + 12 <= len(payload):
                if payload[off + 2] == 1:
                    self.on_encrypted()
                    return
                nxt = self._single(payload, off)
                if nxt is None or nxt <= off:
                    return
                off = nxt
        except (EOFError, ValueError, TypeError, struct.error, RecursionError):
            return

    def _single(self, payload, start):
        flags, count = payload[start + 2], payload[start + 3]
        off = start + 12
        if flags == 0xCC:
            off += 4
        for _ in range(count):
            off = self._command(payload, off)
            if off is None:
                return None
        return off

    def _command(self, src, off):
        if len(src) - off < 12:
            return None
        ctype = src[off]
        self.channel = src[off + 1]
        length = struct.unpack(">I", src[off + 4:off + 8])[0]
        if length < 12 or off + length > len(src):
            return None
        body = src[off + 12:off + length]
        if ctype == 6:
            self._reliable(body)
        elif ctype == 7 and len(body) >= 4:
            self._reliable(body[4:])
        elif ctype == 8:
            self._fragment(body)
        return off + length

    def _reliable(self, body):
        if len(body) < 2:
            return
        msg, data = body[1], body[2:]
        if msg & 0x80:
            self.on_encrypted()
        elif msg == 2:
            self._request(data)
        elif msg in (3, 7):
            self._response(data)

    def _request(self, data):
        if data:
            self.on_request(data[0], read_param_table(Buf(data[1:])))

    def _response(self, data):
        if len(data) < 3:
            return
        opcode = data[0]
        rc = struct.unpack("<h", data[1:3])[0]
        buf = Buf(data[3:])
        if buf.left() > 0:
            value = deserialize(buf, buf.byte())
            if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
                self.on_response(opcode, rc, {0: value})
                return
        params = read_param_table(buf)
        self.on_response(opcode, rc, params)

    def _fragment(self, body):
        if len(body) < 20:
            return
        start_seq, count, number, total, offset = struct.unpack(">IIIII", body[:20])
        chunk = body[20:]
        if not (0 < total <= (8 << 20) and 0 < count <= 65536 and number < count):
            return
        if not chunk or offset + len(chunk) > total:
            return
        now = time.monotonic()
        for old_key in list(self.pending):
            if now - self.pending[old_key]["time"] > 30:
                del self.pending[old_key]
        key = (self.stream, self.channel, start_seq)
        seg = self.pending.get(key)
        if seg is None:
            if len(self.pending) >= 64:
                self.pending.pop(next(iter(self.pending)))
            seg = {"total": total, "count": count, "parts": {}, "time": now}
            self.pending[key] = seg
        if seg["total"] != total or seg["count"] != count:
            del self.pending[key]
            return
        seg["parts"][number] = (offset, chunk)
        if len(seg["parts"]) != count:
            return
        parts = sorted(seg["parts"].values(), key=lambda part: part[0])
        del self.pending[key]
        cursor = 0
        for part_offset, part in parts:
            if part_offset != cursor:
                return
            cursor += len(part)
        if cursor == total:
            self._reliable(b"".join(part for _, part in parts))


# Utilities
BG = "#0b0d13"
CARD = "#141823"
CARD_ALT = "#1a1f2d"
BORDER = "#252b3c"
TEXT = "#eef0f6"
MUTED = "#8b92a8"
GOLD = "#f0b94a"
GREEN = "#4ade80"
BLUE = "#60a5fa"
VIOLET = "#c084fc"
RED = "#f87171"
BAR_COLORS = [GOLD, "#fb923c", "#f472b6", VIOLET, BLUE, GREEN]
SEG_TAX = ["4 % (premium)", "8 % (no premium)"]
SEG_VIEW = ["Sell orders", "Buy orders", "Console"]
HEADS = {"item": "Item", "qty": "Quantity", "unit_price": "Unit price",
         "total_price": "Total", "share": "Share"}


def normalize_op(code):
    if code in OP_NAMES:
        return code
    swapped = ((code << 8) & 0xFFFF) | (code >> 8)
    if swapped in OP_NAMES:
        return swapped
    if code > 0xFF and code & 0xFF == 0:
        return code >> 8
    return code


def fmt(value):
    return f"{int(value):,}".replace(",", " ")


def compact(value):
    for limit, suffix in ((10**9, "B"), (10**6, "M"), (10**3, "k")):
        if abs(value) >= limit:
            return f"{value / limit:.2f} {suffix}"
    return str(int(value))


def net_total(gross, tax):
    return gross * (100 - tax) // 100


def resource_path(name):
    folders = []
    if getattr(sys, "frozen", False):
        folders.append(os.path.dirname(sys.executable))
    folders.append(os.path.dirname(os.path.abspath(__file__)))
    if hasattr(sys, "_MEIPASS"):
        folders.append(sys._MEIPASS)
    for folder in folders:
        for relative in (name, os.path.join("assets", name)):
            candidate = os.path.join(folder, relative)
            if os.path.isfile(candidate):
                return candidate
    return os.path.join(folders[0], name)


def npcap_installed():
    if sys.platform != "win32":
        return True
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.exists(os.path.join(root, "System32", *parts))
               for parts in (("Npcap", "wpcap.dll"), ("wpcap.dll",)))


def is_admin():
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pretty_item(raw):
    base, _, enchantment = str(raw).partition("@")
    parts = base.split("_")
    tier = parts.pop(0) if parts and re.fullmatch(r"T\d+", parts[0]) else ""
    words = [word.upper() if word.upper() in ("2H", "1H") else word.capitalize()
             for word in parts]
    name = " ".join(words)
    if tier:
        return f"{tier}{'.' + enchantment if enchantment.isdigit() else ''}   {name}"
    return name or str(raw)


def pil_font(size):
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default()


def make_coin(size):
    scale = size * 4
    image = Image.new("RGBA", (scale, scale))
    draw = ImageDraw.Draw(image)
    draw.ellipse((0, 0, scale - 1, scale - 1), fill="#96a0b8")
    draw.ellipse((scale * .06, scale * .06, scale * .94, scale * .94), fill="#d6ddec")
    draw.ellipse((scale * .16, scale * .16, scale * .84, scale * .84),
                 outline="#96a0b8", width=max(1, int(scale * .05)))
    draw.text((scale * .5, scale * .52), "S", fill="#78829c", anchor="mm",
              font=pil_font(int(scale * .46)))
    return image.resize((size, size), Image.Resampling.LANCZOS)


def load_hero_image(size):
    path = resource_path("coin.png")
    if os.path.isfile(path):
        try:
            with Image.open(path) as source:
                image = source.convert("RGBA")
            image.thumbnail((size, size), Image.Resampling.LANCZOS)
            result = Image.new("RGBA", (size, size))
            result.alpha_composite(image, ((size - image.width) // 2, (size - image.height) // 2))
            return result
        except (OSError, ValueError):
            pass
    return make_coin(size)


class Hero(tk.Canvas):
    def __init__(self, master):
        super().__init__(master, height=220, bg=BG, highlightthickness=0, bd=0)
        self.background = None
        self.image = ImageTk.PhotoImage(load_hero_image(58))
        self.title_font = tkfont.Font(family="Segoe UI", size=12, weight="bold")
        self.big_font = tkfont.Font(family="Segoe UI", size=43, weight="bold")
        self.unit_font = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        self.sub_font = tkfont.Font(family="Segoe UI", size=10)
        self.value = 0
        self.caption = "0 silver"
        self.bind("<Configure>", self.resize)

    def resize(self, event):
        width, height = event.width, event.height
        if width < 40 or height < 40:
            return
        small = Image.new("RGB", (64, 20))
        pixels = small.load()
        first, last = (52, 36, 104), (20, 42, 92)
        for y in range(20):
            for x in range(64):
                mix = x / 63 * .75 + y / 19 * .25
                pixels[x, y] = tuple(int(first[i] + (last[i] - first[i]) * mix) for i in range(3))
        image = small.resize((width, height), Image.Resampling.BICUBIC).convert("RGBA")
        glow = Image.new("RGBA", (width, height))
        ImageDraw.Draw(glow).ellipse((width * .55, -height * .55, width * 1.15, height * .75),
                                    fill=(120, 96, 255, 70))
        image = Image.alpha_composite(image, glow.filter(ImageFilter.GaussianBlur(35)))
        mask = Image.new("L", (width * 2, height * 2))
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, width * 2 - 1, height * 2 - 1), radius=40, fill=255)
        mask = mask.resize((width, height), Image.Resampling.LANCZOS)
        image = Image.composite(image, Image.new("RGBA", (width, height), BG), mask)
        self.background = ImageTk.PhotoImage(image)
        self.draw()

    def set(self, value, caption):
        self.value, self.caption = value, caption
        self.draw()

    def draw(self):
        if self.background is None:
            return
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self.background)
        self.create_image(28, 44, anchor="w", image=self.image)
        self.create_text(100, 44, anchor="w", text="Total with taxes", fill="#d1d6ef", font=self.title_font)
        number, _, unit = compact(self.value).partition(" ")
        available = max(100, self.winfo_width() - 155)
        size = 43
        self.big_font.configure(size=size)
        while self.big_font.measure(number) > available and size > 20:
            size -= 1
            self.big_font.configure(size=size)
        self.create_text(30, 121, anchor="w", text=number, fill="white", font=self.big_font)
        x = 30 + self.big_font.measure(number) + 10
        if unit:
            self.create_text(x, 137, anchor="w", text=unit, fill=GOLD, font=self.unit_font)
            x += self.unit_font.measure(unit) + 8
        self.create_text(x, 137, anchor="w", text="silver", fill="#b8bfe0", font=self.sub_font)
        self.create_text(30, self.winfo_height() - 27, anchor="w", text=self.caption,
                         fill="#b8bfe0", font=self.sub_font)


class MarketsPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, width=320, fg_color=CARD, corner_radius=18,
                         border_width=1, border_color=BORDER)
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        ctk.CTkLabel(self, text="ALL MARKETS", text_color=MUTED,
                     font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=20, pady=(17, 0))
        self.total_label = ctk.CTkLabel(self, text="0 silver", text_color=GOLD,
                                       font=("Segoe UI", 28, "bold"))
        self.total_label.grid(row=1, column=0, sticky="w", padx=20)
        self.detail_label = ctk.CTkLabel(self, text="0 silver · with taxes", text_color=MUTED,
                                        font=("Segoe UI", 11))
        self.detail_label.grid(row=2, column=0, sticky="w", padx=20)
        self.count_label = ctk.CTkLabel(self, text="0 saved + current market", text_color=MUTED,
                                       font=("Segoe UI", 11))
        self.count_label.grid(row=3, column=0, sticky="w", padx=20, pady=(0, 7))
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self.scroll.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 8))
        self.scroll.grid_columnconfigure(0, weight=1)
        self.widgets = []
        ctk.CTkLabel(self, text="Next Market saves the current total.\nThe current market is always included.",
                     text_color=MUTED, font=("Segoe UI", 11), justify="left").grid(
                         row=5, column=0, sticky="w", padx=20, pady=(0, 16))

    def set(self, saved, current):
        values = [market["net"] for market in saved] + [current]
        total = sum(values)
        self.total_label.configure(text=f"{compact(total)} silver")
        self.detail_label.configure(text=f"{fmt(total)} silver · with taxes")
        self.count_label.configure(text=f"{len(saved)} saved + current market")
        while len(self.widgets) < len(values):
            frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
            frame.grid(row=len(self.widgets), column=0, sticky="ew", pady=(8, 10))
            frame.grid_columnconfigure(0, weight=1)
            title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12), text_color=TEXT)
            title.grid(row=0, column=0, sticky="w")
            amount = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12, "bold"))
            amount.grid(row=0, column=1, sticky="e", padx=(5, 0))
            bar = ctk.CTkProgressBar(frame, height=8, fg_color=BORDER)
            bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(7, 0))
            self.widgets.append((frame, title, amount, bar))
        while len(self.widgets) > len(values):
            self.widgets.pop()[0].destroy()
        maximum = max(values) or 1
        for index, (value, widgets) in enumerate(zip(values, self.widgets)):
            _, title, amount, bar = widgets
            color = BAR_COLORS[index % len(BAR_COLORS)]
            live = index == len(saved)
            title.configure(text=f"Market {index + 1}" + (" · current" if live else ""),
                            text_color=GREEN if live else TEXT)
            amount.configure(text=compact(value), text_color=color)
            bar.configure(progress_color=color)
            bar.set(value / maximum)


class AlbionApp(ctk.CTk):
    def __init__(self, demo=False, iface=None):
        ctk.set_appearance_mode("dark")
        super().__init__()
        self.title("Albion Orders Total")
        self.geometry("1220x850")
        self.minsize(1080, 740)
        self.configure(fg_color=BG)
        self.iface = iface
        self.demo = demo
        self.tax = TAX_PERCENT
        self.sell = {}
        self.buy = {}
        self.markets = []
        self.view = "sell"
        self.sort_states = {name: {"col": None, "phase": 0} for name in ("sell", "buy")}
        self.events = queue.Queue()
        self.capture_lock = threading.RLock()
        self.epoch = 0
        self.last_req = None
        self.last_req_time = 0.0
        self.last_enc_warn = 0.0
        self.closed = False
        self.sniffer = None
        self.poll_job = None
        self.parser = PhotonParser(self.on_request, self.on_response, self.on_encrypted)
        self._set_icon()
        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_job = self.after(200, self.poll)
        if demo:
            self.set_status("Demo mode", GOLD)
            self._demo()
        else:
            self._startup()
            threading.Thread(target=self.run_sniffer, daemon=True).start()
        self.refresh()

    def _set_icon(self):
        png = resource_path("icon.png")
        ico = resource_path("icon.ico")
        try:
            if os.path.isfile(png):
                self.window_icon = tk.PhotoImage(file=png)
                self.iconphoto(True, self.window_icon)
            elif sys.platform == "win32" and os.path.isfile(ico):
                self.iconbitmap(ico)
        except (tk.TclError, OSError):
            pass

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        rowheight=34, borderwidth=0, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=CARD_ALT, foreground=MUTED, relief="flat",
                        borderwidth=0, font=("Segoe UI", 9, "bold"), padding=(8, 9))
        style.map("Treeview", background=[("selected", "#2a3150")], foreground=[("selected", TEXT)])
        style.map("Treeview.Heading", background=[("active", CARD_ALT)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 10))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Albion Orders Total", font=("Segoe UI", 26, "bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Made by Shibarakiri - v1.0.1", font=("Segoe UI", 12),
                     text_color=MUTED).grid(row=1, column=0, sticky="w")
        self.status = ctk.CTkLabel(header, text="● Starting…", font=("Segoe UI", 12, "bold"),
                                  text_color=GOLD, fg_color=CARD, corner_radius=16, height=34, padx=16)
        self.status.grid(row=0, column=1, rowspan=2)
        self.banner = ctk.CTkFrame(self, fg_color="#3a2a14", corner_radius=14,
                                   border_width=1, border_color="#6b4a1a")
        self.banner.grid(row=1, column=0, sticky="ew", padx=28, pady=(0, 8))
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner_label = ctk.CTkLabel(self.banner, text="", text_color="#fcd9a0",
                                        font=("Segoe UI", 12), wraplength=790, justify="left")
        self.banner_label.grid(row=0, column=0, sticky="w", padx=16, pady=10)
        self.banner_button = ctk.CTkButton(self.banner, text="Download Npcap", width=150,
                                          fg_color=GOLD, text_color=BG,
                                          command=lambda: webbrowser.open(NPCAP_URL))
        self.banner_button.grid(row=0, column=1, padx=12)
        self.banner.grid_remove()

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=2, column=0, sticky="ew", padx=22, pady=(4, 6))
        top.grid_columnconfigure(0, weight=5, uniform="top")
        top.grid_columnconfigure(1, weight=4, uniform="top")
        self.hero = Hero(top)
        self.hero.grid(row=0, column=0, sticky="nsew", padx=6)
        stats = ctk.CTkFrame(top, fg_color="transparent")
        stats.grid(row=0, column=1, sticky="nsew")
        for index in range(2):
            stats.grid_columnconfigure(index, weight=1, uniform="stats")
            stats.grid_rowconfigure(index, weight=1, uniform="rows")
        self.c_gross = self._card(stats, 0, 0, "BEFORE TAX", GOLD)
        self.c_tax = self._card(stats, 0, 1, "ESTIMATED TAX", RED)
        self.c_orders = self._card(stats, 1, 0, "ORDERS", BLUE)
        self.c_items = self._card(stats, 1, 1, "ITEMS", VIOLET)

        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=3, column=0, sticky="ew", padx=28, pady=(8, 10))
        for text, command, width in (("Reset", self.reset_data, 110),
                                      ("Export", self.export_details, 110),
                                      ("Next Market", self.next_market, 145)):
            accent = text == "Next Market"
            ctk.CTkButton(controls, text=text, command=command, width=width, height=38,
                          corner_radius=12, fg_color=BLUE if accent else CARD,
                          hover_color="#4588db" if accent else CARD_ALT,
                          border_width=1, border_color=BORDER, text_color=BG if accent else TEXT,
                          font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 10))
        self.tax_seg = ctk.CTkSegmentedButton(controls, values=SEG_TAX, command=self.on_tax,
                                             height=36, corner_radius=12, fg_color=CARD,
                                             selected_color=GOLD, selected_hover_color="#d9a43b",
                                             unselected_color=CARD, unselected_hover_color=CARD_ALT,
                                             text_color=TEXT, font=("Segoe UI", 12, "bold"))
        self.tax_seg.set(SEG_TAX[0])
        self.tax_seg.pack(side="right")
        ctk.CTkLabel(controls, text="Sales tax", text_color=MUTED,
                     font=("Segoe UI", 12)).pack(side="right", padx=(0, 12))

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=4, column=0, sticky="nsew", padx=22, pady=(0, 8))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)
        box = ctk.CTkFrame(main, fg_color=CARD, corner_radius=18, border_width=1, border_color=BORDER)
        box.grid(row=0, column=0, sticky="nsew", padx=6)
        box.grid_columnconfigure(0, weight=1)
        box.grid_rowconfigure(2, weight=1)
        toolbar = ctk.CTkFrame(box, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
        toolbar.grid_columnconfigure(1, weight=1)
        self.view_seg = ctk.CTkSegmentedButton(toolbar, values=SEG_VIEW, command=self.on_view,
                                              height=34, fg_color=CARD_ALT, selected_color=BLUE,
                                              unselected_color=CARD_ALT, text_color=TEXT,
                                              font=("Segoe UI", 12, "bold"))
        self.view_seg.set(SEG_VIEW[0])
        self.view_seg.grid(row=0, column=0, sticky="w")
        self.search_entry = ctk.CTkEntry(toolbar, placeholder_text="Search items…", width=180,
                                        height=34, fg_color=CARD_ALT, border_color=BORDER)
        self.search_entry.grid(row=0, column=1, sticky="e", padx=(12, 0))
        self.search_entry.bind("<KeyRelease>", lambda event: self.refresh())
        self.view_info = ctk.CTkLabel(box, text="", font=("Segoe UI", 11), text_color=MUTED)
        self.view_info.grid(row=1, column=0, sticky="w", padx=17, pady=(0, 5))
        self.table_frame = ctk.CTkFrame(box, fg_color="transparent")
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.table_frame.grid_columnconfigure(0, weight=1)
        self.table_frame.grid_rowconfigure(0, weight=1)
        columns = tuple(HEADS)
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", selectmode="browse")
        widths = {"item": 280, "qty": 75, "unit_price": 120, "total_price": 130, "share": 70}
        for column in columns:
            anchor = "w" if column == "item" else "e"
            self.tree.heading(column, text=HEADS[column], anchor=anchor,
                              command=lambda col=column: self.sort_table(col))
            self.tree.column(column, anchor=anchor, width=widths[column],
                             minwidth=180 if column == "item" else widths[column],
                             stretch=column == "item")
        self.tree.tag_configure("odd", background=CARD)
        self.tree.tag_configure("even", background="#171b27")
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical = ctk.CTkScrollbar(self.table_frame, command=self.tree.yview,
                                    button_color=BORDER, button_hover_color=MUTED)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ctk.CTkScrollbar(self.table_frame, orientation="horizontal", command=self.tree.xview,
                                      button_color=BORDER, button_hover_color=MUTED)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.console = ctk.CTkTextbox(box, fg_color="#0a0c11", text_color=TEXT,
                                      font=("Consolas", 12), wrap="word")
        self.console.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.console.configure(state="disabled")
        self.console.grid_remove()
        self.market_panel = MarketsPanel(main)
        self.market_panel.grid(row=0, column=1, sticky="nsew", padx=6)
        self.footer = ctk.CTkLabel(self, text="Open the market in the game, then browse your own orders.",
                                   font=("Segoe UI", 11), text_color=MUTED, anchor="w")
        self.footer.grid(row=5, column=0, sticky="ew", padx=30, pady=(0, 12))

    def _card(self, master, row, column, title, color):
        frame = ctk.CTkFrame(master, fg_color=CARD, corner_radius=18, border_width=1, border_color=BORDER)
        frame.grid(row=row, column=column, padx=6, pady=(0, 6) if row == 0 else (6, 0), sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        heading = ctk.CTkLabel(frame, text=title, font=("Segoe UI", 10, "bold"), text_color=MUTED)
        heading.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 0))
        value = ctk.CTkLabel(frame, text="0", font=("Segoe UI", 24, "bold"), text_color=color)
        value.grid(row=1, column=0, sticky="w", padx=18)
        sub = ctk.CTkLabel(frame, text="", font=("Segoe UI", 11), text_color=MUTED)
        sub.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 10))
        return {"title": heading, "value": value, "sub": sub}

    def _startup(self):
        if not npcap_installed():
            self.show_banner("Npcap is required for game traffic capture. Install it, then restart the app.", True)
        elif sys.platform == "win32" and not is_admin():
            self.show_banner("Not running as administrator. If capture fails, restart with 'Run as administrator'.", False)

    def show_banner(self, text, button=False):
        self.banner_label.configure(text=text)
        if button:
            self.banner_button.grid()
        else:
            self.banner_button.grid_remove()
        self.banner.grid()

    def set_status(self, text, color):
        self.status.configure(text=f"● {text}", text_color=color)

    def log(self, message):
        self.console.configure(state="normal")
        self.console.insert("end", f"[{datetime.now():%H:%M:%S}] {message}\n")
        if int(self.console.index("end-1c").split(".")[0]) > 2000:
            self.console.delete("1.0", "201.0")
        self.console.see("end")
        self.console.configure(state="disabled")

    def say(self, message):
        self.footer.configure(text=f"[{datetime.now():%H:%M:%S}] {message}")
        self.log(message)

    # The capture thread only queues events. Tk operations stay in the UI thread.
    def run_sniffer(self):
        try:
            from scapy.all import AsyncSniffer, IP, IPv6, Raw, TCP, UDP, conf
            conf.use_pcap = True

            def handle_packet(packet):
                if self.closed or Raw not in packet or not (UDP in packet or TCP in packet):
                    return
                transport = packet[UDP] if UDP in packet else packet[TCP]
                network = packet[IP] if IP in packet else (packet[IPv6] if IPv6 in packet else None)
                stream = (str(network.src) if network else "", int(transport.sport),
                          str(network.dst) if network else "", int(transport.dport))
                with self.capture_lock:
                    self.parser.receive(bytes(packet[Raw].load), stream)

            kwargs = {"filter": f"udp port {PORT} or tcp port {PORT}", "prn": handle_packet,
                      "store": False, "started_callback": lambda: self.events.put(("status", "listening"))}
            if self.iface:
                kwargs["iface"] = self.iface
            sniffer = AsyncSniffer(**kwargs)
            with self.capture_lock:
                if self.closed:
                    return
                self.sniffer = sniffer
                sniffer.start()
            sniffer.join()
        except Exception as error:
            if not self.closed:
                self.events.put(("fatal", f"Network capture failed: {error}\nCheck Scapy, Npcap and capture permissions."))

    def on_encrypted(self):
        now = time.monotonic()
        if now - self.last_enc_warn > 30:
            self.last_enc_warn = now
            self.events.put(("encrypted", None))

    def on_request(self, opcode, params):
        code = params.get(253, opcode)
        if not isinstance(code, int):
            code = opcode
        code = normalize_op(code)
        if code in OP_NAMES:
            self.last_req = code
            self.last_req_time = time.monotonic()

    def on_response(self, opcode, rc, params):
        if rc != 0:
            return
        strings = params.get(0)
        if not isinstance(strings, list) or not strings or not all(isinstance(s, str) for s in strings):
            return
        orders = []
        for value in strings:
            try:
                order = json.loads(value)
            except (ValueError, TypeError):
                continue
            if isinstance(order, dict) and "UnitPriceSilver" in order:
                orders.append(order)
        if not orders:
            return
        # Prefer an operation ID supplied by the response. Otherwise retain the
        # original script's last-request heuristic, with an expiry limit.
        code = params.get(253)
        if isinstance(code, int) and normalize_op(code) in OP_NAMES:
            label = normalize_op(code)
        else:
            label = self.last_req if time.monotonic() - self.last_req_time < 20 else None
        self.events.put(("orders", (self.epoch, label, orders)))

    def drain_events(self, limit=1000):
        changed = False
        for _ in range(limit):
            try:
                kind, data = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "orders":
                epoch, label, orders = data
                if epoch == self.epoch:
                    self.handle_orders(label, orders)
                    changed = True
            elif kind == "status":
                self.set_status("Listening", GREEN)
                self.log("Capture started. Open your own orders in the in-game market.")
            elif kind == "encrypted":
                self.say("Encrypted traffic detected. Encrypted market data cannot be read.")
            elif kind == "fatal":
                self.set_status("Network error", RED)
                self.say(data.replace("\n", " "))
                self.show_banner(data)
        return changed

    def poll(self):
        if self.closed:
            return
        if self.drain_events():
            self.refresh()
        self.poll_job = self.after(200, self.poll)

    def handle_orders(self, label, orders):
        self.log(f"Received {len(orders)} orders: {OP_NAMES.get(label, 'unknown operation')}")
        if label not in MY_CODES:
            self.log("Public or unclassified orders ignored.")
            return
        sells, buys = [], []
        for order in orders:
            auction_type = str(order.get("AuctionType", "")).lower()
            if "request" in auction_type:
                buys.append(order)
            elif "offer" in auction_type:
                sells.append(order)
            elif label in BUY_CODES:
                buys.append(order)
            else:
                sells.append(order)
        if sells:
            self.add_orders(self.sell, sells, "SELL")
        if buys:
            self.add_orders(self.buy, buys, "BUY")

    def add_orders(self, store, orders, kind):
        added = updated = skipped = 0
        for order in orders:
            oid = order.get("Id")
            if oid is None or isinstance(oid, (list, dict)):
                skipped += 1
                continue
            try:
                quantity = int(order.get("Amount", 0))
                price = int(order.get("UnitPriceSilver", 0)) // PRICE_DIVISOR
            except (ValueError, TypeError, OverflowError):
                skipped += 1
                continue
            if quantity < 0 or price < 0:
                skipped += 1
                continue
            key = str(oid)
            value = (str(order.get("ItemTypeId", "?")), quantity, price)
            if key not in store:
                added += 1
            elif store[key] != value:
                updated += 1
            store[key] = value
        self.say(f"{kind}: {added} new, {updated} updated" + (f", {skipped} invalid orders skipped." if skipped else "."))

    def on_tax(self, value):
        self.tax = 4 if value == SEG_TAX[0] else 8
        self.refresh()

    def on_view(self, value):
        self.view = {SEG_VIEW[0]: "sell", SEG_VIEW[1]: "buy"}.get(value, "console")
        if self.view == "console":
            self.table_frame.grid_remove()
            self.search_entry.grid_remove()
            self.console.grid()
        else:
            self.console.grid_remove()
            self.table_frame.grid()
            self.search_entry.grid()
        self.refresh()

    def sort_table(self, column):
        if self.view not in self.sort_states:
            return
        state = self.sort_states[self.view]
        if state["col"] == column:
            state["phase"] = (state["phase"] + 1) % 3
            if state["phase"] == 0:
                state["col"] = None
        else:
            state["col"], state["phase"] = column, 1
        self.refresh()

    def gross(self):
        return sum(quantity * price for _, quantity, price in self.sell.values())

    def snapshot(self):
        gross = self.gross()
        return {"number": len(self.markets) + 1, "gross": gross, "tax": self.tax,
                "net": net_total(gross, self.tax), "sell": dict(self.sell), "buy": dict(self.buy),
                "time": datetime.now().isoformat(timespec="seconds")}

    def clear_current(self):
        # Called while holding capture_lock: queued data from the previous
        # capture generation will not be added to the new market.
        self.epoch += 1
        self.last_req = None
        self.last_req_time = 0.0
        self.parser.pending.clear()
        self.sell.clear()
        self.buy.clear()

    def next_market(self):
        self.drain_events()
        self.refresh()
        number = len(self.markets) + 1
        if not messagebox.askyesno("Next Market",
                                  "Save the current total after tax and clear the current sell and buy orders?",
                                  parent=self):
            return
        with self.capture_lock:
            self.drain_events()
            saved = self.snapshot()
            self.markets.append(saved)
            self.clear_current()
        self.search_entry.delete(0, "end")
        if self.demo:
            self._demo()
        self.refresh()
        self.say(f"Market {number} saved: {fmt(saved['net'])} silver with taxes. Market {number + 1} is current.")

    def reset_data(self):
        if not messagebox.askyesno("Reset all markets",
                                  "Delete ALL saved markets and ALL current orders?\n\n"
                                  "This cannot be undone. The next market will be Market 1.", parent=self):
            return
        with self.capture_lock:
            self.markets.clear()
            self.clear_current()
        self.search_entry.delete(0, "end")
        self.refresh()
        self.say("All markets cleared. Browse your own order pages to collect data again.")

    def refresh(self):
        gross = self.gross()
        net = net_total(gross, self.tax)
        self.hero.set(net, f"{fmt(net)} silver · after {self.tax}% tax · Market {len(self.markets) + 1}")
        self.c_gross["value"].configure(text=compact(gross))
        self.c_gross["sub"].configure(text=f"{fmt(gross)} silver")
        self.c_tax["title"].configure(text=f"ESTIMATED TAX ({self.tax}%)")
        self.c_tax["value"].configure(text=compact(gross - net))
        self.c_tax["sub"].configure(text=f"{fmt(gross - net)} silver")
        self.c_orders["value"].configure(text=fmt(len(self.sell)))
        self.c_orders["sub"].configure(text=f"sell orders · {len(self.buy)} buy orders")
        self.c_items["value"].configure(text=fmt(sum(quantity for _, quantity, _ in self.sell.values())))
        self.c_items["sub"].configure(text="total sell quantity")
        self.market_panel.set(self.markets, net)
        if self.view == "console":
            self.view_info.configure(text="Capture log")
            return
        store = self.sell if self.view == "sell" else self.buy
        total = sum(quantity * price for _, quantity, price in store.values())
        self.view_info.configure(text=f"Market {len(self.markets) + 1} · {fmt(len(store))} orders · {fmt(total)} silver")
        self.populate_tree(total)

    def populate_tree(self, total):
        state = self.sort_states[self.view]
        store = self.sell if self.view == "sell" else self.buy
        query = self.search_entry.get().strip().lower()
        rows = []
        for oid, (item, quantity, price) in store.items():
            pretty = pretty_item(item)
            if query and query not in item.lower() and query not in pretty.lower():
                continue
            rows.append((oid, pretty, quantity, price, quantity * price))
        indices = {"item": 1, "qty": 2, "unit_price": 3, "total_price": 4, "share": 4}
        if state["col"] and state["phase"]:
            index = indices[state["col"]]
            rows.sort(key=lambda row: row[index].lower() if index == 1 else row[index],
                      reverse=state["phase"] == 2)
        else:
            rows.sort(key=lambda row: row[4], reverse=True)
        for column, title in HEADS.items():
            arrow = ""
            if column == state["col"] and state["phase"]:
                arrow = " ▲" if state["phase"] == 1 else " ▼"
            self.tree.heading(column, text=title + arrow)
        position = self.tree.yview()
        selection = self.tree.selection()
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for index, (oid, name, quantity, price, subtotal) in enumerate(rows):
            share = f"{subtotal / total * 100:.1f}%" if total else "0.0%"
            self.tree.insert("", "end", iid=oid, tags=("even" if index % 2 else "odd",),
                             values=(name, fmt(quantity), fmt(price), fmt(subtotal), share))
        if selection and self.tree.exists(selection[0]):
            self.tree.selection_set(selection[0])
        if position:
            self.tree.yview_moveto(position[0])

    def export_details(self):
        self.drain_events()
        self.refresh()
        if not self.markets and not self.sell and not self.buy:
            messagebox.showinfo("Export", "Nothing to export yet.", parent=self)
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            initialfile=f"albion_orders_{datetime.now():%Y%m%d_%H%M%S}.csv",
                                            filetypes=[("CSV (Excel)", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        markets = self.markets + [self.snapshot()]
        total = sum(market["net"] for market in markets)
        try:
            if path.lower().endswith(".txt"):
                with open(path, "w", encoding="utf-8") as output:
                    output.write("ALBION ORDERS TOTAL\nMade by Shibarakiri - v1.0.1\n\n")
                    output.write(f"ALL MARKETS WITH TAXES: {total} silver\n\n")
                    for index, market in enumerate(markets):
                        status = "current" if index == len(self.markets) else "saved"
                        output.write(f"MARKET {market['number']} ({status})\n")
                        output.write(f"Total with taxes ({market['tax']}%): {market['net']} silver\n")
                        for kind, key in (("SELL", "sell"), ("BUY", "buy")):
                            output.write(f"{kind} ORDERS\n")
                            for item, quantity, price in sorted(market[key].values(), key=lambda row: -row[1] * row[2]):
                                output.write(f"{item} | {quantity} x {price} = {quantity * price}\n")
                        output.write("\n")
            else:
                with open(path, "w", newline="", encoding="utf-8-sig") as output:
                    writer = csv.writer(output, delimiter=";")
                    writer.writerow(["Market", "Status", "Tax (%)", "Total with taxes"])
                    for index, market in enumerate(markets):
                        writer.writerow([market["number"], "current" if index == len(self.markets) else "saved",
                                         market["tax"], market["net"]])
                    writer.writerow(["ALL MARKETS", "", "", total])
                    writer.writerow([])
                    writer.writerow(["Market", "Type", "Order ID", "Item", "Quantity", "Unit price", "Total before tax"])
                    for market in markets:
                        for kind, key in (("Sell", "sell"), ("Buy", "buy")):
                            for oid, (item, quantity, price) in sorted(market[key].items(), key=lambda entry: -entry[1][1] * entry[1][2]):
                                writer.writerow([market["number"], kind, oid, item, quantity, price, quantity * price])
            self.say(f"Export saved: {path}")
        except OSError as error:
            messagebox.showerror("Export error", str(error), parent=self)

    def _demo(self):
        import random
        rng = random.Random(7 + len(self.markets))
        items = ["T8_2H_AXE@3", "T8_2H_ARCLIGHT_BLASTERS", "T5_RELIC", "T7_MAIN_SWORD@2",
                 "T6_ARMOR_PLATE_SET3", "T4_BAG", "T8_CAPEITEM_FW_LYMHURST", "T6_2H_BOW@1",
                 "T5_HEAD_CLOTH_SET2", "T7_SHOES_LEATHER_SET1@3"]
        for index in range(1, 46):
            self.sell[str(index)] = (rng.choice(items), rng.choice([1, 1, 2, 5]), rng.randint(900, 19500000))
        for index in range(1, 7):
            self.buy[str(index)] = (rng.choice(items), rng.randint(1, 5), rng.randint(900, 1000000))
        self.say("Demo mode: fictional orders. Next Market generates another fictional market.")

    def close(self):
        self.closed = True
        if self.poll_job is not None:
            try:
                self.after_cancel(self.poll_job)
            except tk.TclError:
                pass
        sniffer = self.sniffer
        if sniffer is not None:
            def stop_capture():
                try:
                    if sniffer.running:
                        sniffer.stop(join=False)
                except Exception:
                    pass
            threading.Thread(target=stop_capture, daemon=True).start()
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description="Albion Orders Total - v1.0.1")
    parser.add_argument("--list", action="store_true", help="List network interfaces")
    parser.add_argument("--iface", help="Network interface name")
    parser.add_argument("--demo", action="store_true", help="Use fictional data without capturing traffic")
    args = parser.parse_args()
    if args.list:
        from scapy.all import conf
        conf.use_pcap = True
        print(conf.ifaces)
        return
    AlbionApp(demo=args.demo, iface=args.iface).mainloop()


if __name__ == "__main__":
    main()