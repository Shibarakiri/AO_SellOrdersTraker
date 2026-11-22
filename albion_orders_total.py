"""Albion Orders Total - Made by Shibarakiri - v1.2.0

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

When the app starts it asks which city (market) you are in. Next Market saves a
snapshot of the current market, including its tax rate, then asks for the next
city: every city can be used once, except "Other" (Other 1, Other 2, ...).
Each city has its own colour in the All Markets panel. Next Market starts an empty market. The live market is always included in All Markets.
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
import base64
import csv
import io
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
from tkinter import filedialog, ttk

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageGrab, ImageTk

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
# One theme per city. The colours you suggested were the starting point; these are tuned to look
# good on the dark UI. "accent" = bars/amounts/buttons, "tab" = selected tab, g1/g2/glow = main card.
# "Other" keeps the original look of the app.
CITY_THEMES = {
    "Lymhurst": {"colors": ["#bef264", "#4ade80", "#2dd4bf"], "tab": "#1f9d55", "on_accent": "#06210f",
                 "g1": (14, 62, 44), "g2": (9, 34, 38), "glow": (74, 222, 128), "glow2": (45, 212, 191)},
    "Fort Sterling": {"colors": ["#ffffff", "#dbeafe", "#a5b4fc"], "tab": "#5b82c0", "on_accent": "#0b1730",
                      "g1": (54, 66, 98), "g2": (26, 36, 64), "glow": (219, 234, 254), "glow2": (165, 180, 252)},
    "Thetford": {"colors": ["#9333ea", "#7c3aed", "#5b21b6"], "tab": "#6d28d9", "on_accent": "#ffffff",
                 "text": "#a78bfa", "g1": (58, 18, 102), "g2": (24, 10, 62),
                 "glow": (124, 58, 237), "glow2": (88, 28, 135)},
    "Martlock": {"colors": ["#7dd3fc", "#38bdf8", "#818cf8"], "tab": "#1d7ac8", "on_accent": "#04162a",
                 "g1": (14, 54, 112), "g2": (10, 28, 74), "glow": (56, 189, 248), "glow2": (129, 140, 248)},
    "Bridgwatch": {"colors": ["#fcd34d", "#fb923c", "#f87171"], "tab": "#d9631a", "on_accent": "#2a1204",
                   "g1": (100, 50, 14), "g2": (58, 28, 24), "glow": (251, 146, 60), "glow2": (248, 113, 113)},
    "Brecilien": {"colors": ["#f9a8d4", "#f0689f", "#c084fc"], "tab": "#b8316c", "on_accent": "#2a0618",
                  "g1": (94, 20, 60), "g2": (50, 14, 46), "glow": (240, 104, 159), "glow2": (192, 132, 252)},
    "Caerleon": {"colors": ["#dc2626", "#b91c1c", "#991b1b"], "tab": "#991b1b", "on_accent": "#ffffff",
                 "text": "#f87171", "g1": (72, 12, 16), "g2": (18, 8, 10),
                 "glow": (220, 38, 38), "glow2": (127, 29, 29)},
    "Other": {"colors": ["#d1d5db", "#9ca3af", "#6b7280"], "tab": "#6b7280", "on_accent": "#0f1115",
              "sel": "#343944", "text": "#b4bac4", "g1": (62, 64, 72), "g2": (26, 28, 34),
              "glow": (156, 163, 175), "glow2": (107, 114, 128)},
}
for _theme in CITY_THEMES.values():
    _theme["accent"] = _theme["colors"][1]          # the middle colour is the main one
    _theme.setdefault("text", _theme["accent"])      # readable tone used for amounts on dark cards
CITY_COLORS = {city: theme["accent"] for city, theme in CITY_THEMES.items()}
DANGER_COLORS = ["#fca5a5", "#ef4444", "#dc2626"]
TRACK = "#2b3143"        # background of the bars (so very dark city colours stay visible)
TRACK_EDGE = "#4a5270"
RADIUS_CARD = 18          # cards, panels, main card
RADIUS_CONTROL = 12       # buttons, tabs, search box, tax selector
CONTROL_HEIGHT = 38       # every control has the same height
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


def _rgb(color):
    return tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))


def _luminance(color):
    red, green, blue = _rgb(color)
    return (0.299 * red + 0.587 * green + 0.114 * blue) / 255


def readable_color(color, minimum=0.45):
    """Lighten very dark colours so text and dots stay readable on the dark theme."""
    luminance = _luminance(color)
    if luminance >= minimum:
        return color
    factor = (minimum - luminance) / (1 - luminance)
    return "#%02x%02x%02x" % tuple(int(c + (255 - c) * factor) for c in _rgb(color))


def text_on(color):
    """Black or white text, whichever reads better on the given background."""
    return "#0b0d13" if _luminance(color) > 0.55 else "#ffffff"


def shade(color, factor):
    """Multiply the brightness of a #rrggbb colour (factor < 1 darkens)."""
    return "#%02x%02x%02x" % tuple(min(255, int(c * factor)) for c in _rgb(color))


def hover_of(color):
    """Slightly lighter version of a colour for button hover."""
    return "#%02x%02x%02x" % tuple(int(c + (255 - c) * 0.18) for c in _rgb(color))


_ICON_PIL = {}
_ICON_CTK = {}


def icon_pil(name):
    """PIL image of an embedded icon (city name, or "Crown" for the premium tax)."""
    if name not in _ICON_PIL:
        data = ICONS_B64.get(name)
        _ICON_PIL[name] = Image.open(io.BytesIO(base64.b64decode(data))).convert("RGBA") if data else None
    return _ICON_PIL[name]


def icon_ctk(name, size, dim=False):
    """CTkImage of an embedded icon at the given size (dim=True for disabled/greyed)."""
    key = (name, size, dim)
    if key not in _ICON_CTK:
        image = icon_pil(name)
        if image is None:
            _ICON_CTK[key] = None
        else:
            image = image.resize((size * 2, size * 2), Image.Resampling.LANCZOS)
            if dim:
                alpha = image.getchannel("A").point(lambda value: int(value * 0.4))
                gray = image.convert("L")
                image = Image.merge("RGBA", (gray, gray, gray, alpha))
            _ICON_CTK[key] = ctk.CTkImage(light_image=image, dark_image=image, size=(size, size))
    return _ICON_CTK[key]


def city_icon(city, size, dim=False):
    return icon_ctk(city if city in CITY_COLORS else "Other", size, dim)


_BLANK = []


def blank_icon():
    """Transparent 1px image: configure(image=None) does not clear a CTkLabel image, this does."""
    if not _BLANK:
        _BLANK.append(ctk.CTkImage(Image.new("RGBA", (2, 2), (0, 0, 0, 0)), size=(1, 1)))
    return _BLANK[0]


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
        self.city = None
        self.city_name = ""
        self.city_photos = {}
        self.theme = CITY_THEMES["Other"]
        self.bind("<Configure>", self.resize)

    def resize(self, event):
        self.render(event.width, event.height)

    def set_theme(self, theme):
        self.theme = theme
        if self.winfo_width() > 40:
            self.render(self.winfo_width(), self.winfo_height())

    def render(self, width, height):
        if width < 40 or height < 40:
            return
        small = Image.new("RGB", (64, 20))
        pixels = small.load()
        first, last = self.theme["g1"], self.theme["g2"]
        for y in range(20):
            for x in range(64):
                mix = x / 63 * .75 + y / 19 * .25
                pixels[x, y] = tuple(int(first[i] + (last[i] - first[i]) * mix) for i in range(3))
        image = small.resize((width, height), Image.Resampling.BICUBIC).convert("RGBA")
        glow = Image.new("RGBA", (width, height))
        ImageDraw.Draw(glow).ellipse((width * .55, -height * .55, width * 1.15, height * .75),
                                    fill=tuple(self.theme["glow"]) + (70,))
        image = Image.alpha_composite(image, glow.filter(ImageFilter.GaussianBlur(35)))
        glow2 = Image.new("RGBA", (width, height))
        ImageDraw.Draw(glow2).ellipse((-width * .12, height * .35, width * .42, height * 1.5),
                                      fill=tuple(self.theme["glow2"]) + (60,))
        image = Image.alpha_composite(image, glow2.filter(ImageFilter.GaussianBlur(40)))
        mask = Image.new("L", (width * 2, height * 2))
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, width * 2 - 1, height * 2 - 1), radius=RADIUS_CARD * 2, fill=255)
        mask = mask.resize((width, height), Image.Resampling.LANCZOS)
        image = Image.composite(image, Image.new("RGBA", (width, height), BG), mask)
        self.background = ImageTk.PhotoImage(image)
        self.draw()

    def set(self, value, caption, city=None, city_name=""):
        self.value, self.caption = value, caption
        self.city, self.city_name = city, city_name
        self.draw()

    def city_photo(self, city, size=24):
        key = (city, size)
        if key not in self.city_photos:
            image = icon_pil(city if city in CITY_COLORS else "Other")
            self.city_photos[key] = (ImageTk.PhotoImage(image.resize((size, size), Image.Resampling.LANCZOS))
                                     if image is not None else None)
        return self.city_photos[key]

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
        y = self.winfo_height() - 27
        self.create_text(30, y, anchor="w", text=self.caption, fill="#b8bfe0", font=self.sub_font)
        if self.city_name:
            x = 30 + self.sub_font.measure(self.caption) + 12
            self.create_text(x, y, anchor="w", text="·", fill="#b8bfe0", font=self.sub_font)
            x += 14
            photo = self.city_photo(self.city) if self.city else None
            if photo is not None:
                self.create_image(x, y, anchor="w", image=photo)
                x += 31
            self.create_text(x, y, anchor="w", text=self.city_name, fill="white", font=self.sub_font)


_GRAD_CACHE = {}
_MASK_CACHE = {}


def _gradient(width, height, stops):
    """Horizontal gradient (RGB image) through the given #rrggbb colours."""
    key = (width, height, tuple(stops))
    if key not in _GRAD_CACHE:
        if len(_GRAD_CACHE) > 300:
            _GRAD_CACHE.clear()
        count = max(width, 2)
        colors = [_rgb(color) for color in stops]
        segments = max(len(colors) - 1, 1)
        strip = Image.new("RGB", (count, 1))
        for x in range(count):
            position = x / (count - 1) * segments
            index = min(int(position), segments - 1)
            fraction = position - index
            first, second = colors[index], colors[min(index + 1, len(colors) - 1)]
            strip.putpixel((x, 0), tuple(int(first[k] + (second[k] - first[k]) * fraction) for k in range(3)))
        _GRAD_CACHE[key] = strip.resize((width, height), Image.Resampling.NEAREST)
    return _GRAD_CACHE[key]


def _round_mask(width, height, radius):
    key = (width, height, int(radius))
    if key not in _MASK_CACHE:
        if len(_MASK_CACHE) > 300:
            _MASK_CACHE.clear()
        scale = 3
        mask = Image.new("L", (width * scale, height * scale), 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, width * scale - 1, height * scale - 1),
                                               radius=int(radius) * scale, fill=255)
        _MASK_CACHE[key] = mask.resize((width, height), Image.Resampling.LANCZOS)
    return _MASK_CACHE[key]


def _dim_image(image):
    alpha = image.getchannel("A").point(lambda value: int(value * 0.4))
    gray = image.convert("L")
    return Image.merge("RGBA", (gray, gray, gray, alpha))


class GradientBar(tk.Canvas):
    """Rounded progress bar filled with a multi-colour gradient."""

    def __init__(self, master, height=10, bg=CARD):
        self._ui = master.winfo_fpixels("1i") / 96.0
        self._h = max(int(height * self._ui), 4)
        super().__init__(master, height=self._h, bg=bg, highlightthickness=0, bd=0)
        self._bg = bg
        self.fraction, self.colors = 0.0, None
        self._photo, self._key = None, None
        self.bind("<Configure>", lambda event: self.render())

    def set(self, fraction, colors):
        self.fraction, self.colors = max(0.0, min(1.0, fraction)), list(colors)
        self.render()

    def render(self):
        width, height = self.winfo_width(), self._h
        if width < 8 or not self.colors:
            return
        key = (width, round(self.fraction, 3), tuple(self.colors))
        if key == self._key:
            return
        self._key = key
        image = Image.new("RGB", (width, height), self._bg)
        image.paste(Image.new("RGB", (width, height), TRACK), (0, 0), _round_mask(width, height, height // 2))
        if self.fraction > 0:
            fill = max(int(width * self.fraction), height)
            image.paste(_gradient(fill, height, self.colors), (0, 0), _round_mask(fill, height, height // 2))
        self._photo = ImageTk.PhotoImage(image)
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._photo)


class GradientButton(tk.Canvas):
    """Rounded button with a multi-colour gradient, optional icon and a hover glow."""

    def __init__(self, master, text="", command=None, colors=("#60a5fa", "#a78bfa"), text_color="#0b0d13",
                 icon=None, width=200, height=CONTROL_HEIGHT, radius=RADIUS_CONTROL,
                 font=("Segoe UI", 12, "bold"), disabled=False, bg=CARD):
        self._ui = master.winfo_fpixels("1i") / 96.0
        super().__init__(master, width=int(width * self._ui), height=int(height * self._ui), bg=bg,
                         highlightthickness=0, bd=0, cursor="arrow" if disabled else "hand2")
        self.text, self.command = text, command
        self.colors, self.text_color = list(colors), text_color
        self.icon, self.radius, self.disabled, self._bg = icon, radius, disabled, bg
        # negative size = pixels, like the other (customtkinter) widgets
        self.font = tkfont.Font(family=font[0], size=-max(int(font[1] * self._ui), 1), weight=font[2])
        self._hover, self._key, self._photo, self._icon_photo = False, None, None, None
        self.bind("<Configure>", lambda event: self.render())
        self.bind("<Enter>", lambda event: self._set_hover(True))
        self.bind("<Leave>", lambda event: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._release)

    def set_style(self, colors=None, text_color=None):
        if colors is not None:
            self.colors = list(colors)
        if text_color is not None:
            self.text_color = text_color
        self._key = None
        self.render()

    def _set_hover(self, value):
        if not self.disabled:
            self._hover = value
            self.render()

    def _release(self, event):
        inside = 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height()
        if inside and not self.disabled and self.command:
            self.command()

    def render(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width < 8 or height < 8:
            return
        colors = ["#1a1f2d", "#1a1f2d"] if self.disabled else self.colors
        key = (width, height, tuple(colors), self._hover, self.disabled, self.text_color, self.text)
        if key == self._key:
            return
        self._key = key
        body = _gradient(width, height, colors)
        if self._hover:
            body = Image.blend(body, Image.new("RGB", body.size, "#ffffff"), 0.18)
        image = Image.new("RGB", (width, height), self._bg)
        image.paste(body, (0, 0), _round_mask(width, height, int(self.radius * self._ui)))
        self._photo = ImageTk.PhotoImage(image)
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._photo)
        fill = MUTED if self.disabled else self.text_color
        text_width = self.font.measure(self.text)
        icon_width, gap = 0, int(10 * self._ui)
        if self.icon is not None:
            size = int(height * 0.58)
            source = _dim_image(self.icon) if self.disabled else self.icon
            self._icon_photo = ImageTk.PhotoImage(source.resize((size, size), Image.Resampling.LANCZOS))
            icon_width = size + gap
        x = (width - icon_width - text_width) / 2
        if self.icon is not None:
            self.create_image(x, height / 2, anchor="w", image=self._icon_photo)
        self.create_text(x + icon_width, height / 2, anchor="w", text=self.text, fill=fill, font=self.font)


def attach_click(widget, command, hover_frame=None, hover_color=None):
    """Make a widget and everything inside it clickable (hand cursor, optional hover border)."""

    def enter(_event=None):
        if hover_frame is not None and hover_color is not None:
            try:
                hover_frame.configure(border_color=hover_color())
            except tk.TclError:
                pass

    def leave(_event=None):
        if hover_frame is None:
            return

        def check():
            try:
                x, y = hover_frame.winfo_pointerxy()
                left, top = hover_frame.winfo_rootx(), hover_frame.winfo_rooty()
                inside = (left <= x < left + hover_frame.winfo_width()
                          and top <= y < top + hover_frame.winfo_height())
                if not inside:
                    hover_frame.configure(border_color=BORDER)
            except tk.TclError:
                pass
        hover_frame.after(40, check)

    def walk(node):
        if isinstance(node, ctk.CTkScrollbar):
            return
        try:
            node.bind("<Button-1>", lambda event: command(), add="+")
            node.bind("<Enter>", enter, add="+")
            node.bind("<Leave>", leave, add="+")
        except Exception:
            pass
        try:
            node.configure(cursor="hand2")
        except Exception:
            pass
        for child in node.winfo_children():
            walk(child)

    walk(widget)


# Expanded (click to enlarge) views: which value of each market is shown
EXPAND_VIEWS = {
    "all": {"title": "All Markets", "sub": "Total with taxes", "key": "net", "money": True},
    "gross": {"title": "Before tax", "sub": "Total before taxes", "key": "gross", "money": True},
    "tax": {"title": "Estimated tax", "sub": "Taxes over all markets", "key": "tax_amount", "money": True},
    "orders": {"title": "Orders", "sub": "Sell orders", "key": "orders", "money": False, "unit": "orders"},
    "items": {"title": "Items", "sub": "Total quantity", "key": "items", "money": False, "unit": "items"},
}


class MarketsPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, width=320, fg_color=CARD, corner_radius=RADIUS_CARD,
                         border_width=1, border_color=BORDER)
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self.on_open, self.hover_color = None, None
        ctk.CTkLabel(self, text="ALL MARKETS", text_color=MUTED,
                     font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=20, pady=(17, 0))
        self.total_label = ctk.CTkLabel(self, text="0 silver", text_color=GOLD,
                                       font=("Segoe UI", 28, "bold"))
        self.total_label.grid(row=1, column=0, sticky="w", padx=20)
        self.detail_label = ctk.CTkLabel(self, text="0 silver", text_color=MUTED,
                                        font=("Segoe UI", 11))
        self.detail_label.grid(row=2, column=0, sticky="w", padx=20)
        self.count_label = ctk.CTkLabel(self, text="0 saved + current market", text_color=MUTED,
                                       font=("Segoe UI", 11))
        self.count_label.grid(row=3, column=0, sticky="w", padx=20, pady=(0, 7))
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self.scroll.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 14))
        self.scroll.grid_columnconfigure(0, weight=1)
        self.widgets = []

    def bind_open(self, command, hover_color):
        """Click anywhere on the panel to run command (opens the enlarged view)."""
        self.on_open, self.hover_color = command, hover_color
        attach_click(self, command, self, hover_color)

    def set(self, saved, current, current_market=None):
        entries = [(market.get("name", f"Market {index + 1}"), market.get("city", "Other"),
                    market["net"], False) for index, market in enumerate(saved)]
        if current_market:
            entries.append((current_market["name"], current_market["city"], current, True))
        else:
            entries.append(("Select a market", "Other", current, True))
        values = [entry[2] for entry in entries]
        total = sum(values)
        self.total_label.configure(text=f"{compact(total)} silver")
        self.detail_label.configure(text=f"{fmt(total)} silver")
        self.count_label.configure(text=f"{len(saved)} saved + current market")
        while len(self.widgets) < len(entries):
            frame = ctk.CTkFrame(self.scroll, fg_color="transparent")
            frame.grid(row=len(self.widgets), column=0, sticky="ew", pady=(8, 10))
            frame.grid_columnconfigure(1, weight=1)
            dot = ctk.CTkLabel(frame, text="", width=26)
            dot.grid(row=0, column=0, sticky="w", padx=(0, 6))
            title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12), text_color=TEXT)
            title.grid(row=0, column=1, sticky="w")
            amount = ctk.CTkLabel(frame, text="", font=("Segoe UI", 12, "bold"))
            amount.grid(row=0, column=2, sticky="e", padx=(5, 0))
            bar = GradientBar(frame, height=10, bg=CARD)
            bar.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(7, 0))
            self.widgets.append((frame, dot, title, amount, bar))
            if self.on_open:
                attach_click(frame, self.on_open, self, self.hover_color)
        while len(self.widgets) > len(entries):
            self.widgets.pop()[0].destroy()
        maximum = max(values) or 1
        for (name, city, value, live), widgets in zip(entries, self.widgets):
            _, dot, title, amount, bar = widgets
            theme = CITY_THEMES.get(city, CITY_THEMES["Other"])
            dot.configure(image=city_icon(city, 22), text="")
            title.configure(text=name + (" · current" if live else ""),
                            text_color=GREEN if live else TEXT)
            amount.configure(text=compact(value), text_color=theme["text"])
            bar.set(value / maximum, theme["colors"])


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
        self.current_market = None   # {"city": ..., "name": ...}
        self.view = "sell"
        self.sort_states = {name: {"col": None, "phase": 0} for name in ("sell", "buy")}
        self.events = queue.Queue()
        self.capture_lock = threading.RLock()
        self.epoch = 0
        self.last_req = None
        self.last_req_time = 0.0
        self.last_enc_warn = 0.0
        self.closed = False
        self._modal_done = None      # set while an in-window dialog is open
        self.lock_canvas = None      # "no market selected" layer
        self._picking = False
        self.sniffer = None
        self.poll_job = None
        self.parser = PhotonParser(self.on_request, self.on_response, self.on_encrypted)
        self._set_icon()
        self._style()
        self._build()
        self._wire_clicks()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_job = self.after(200, self.poll)
        self.after(350, self.prompt_start_city)
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
        style.map("Treeview", background=[("selected", CITY_THEMES["Other"]["sel"])], foreground=[("selected", TEXT)])
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
        ctk.CTkLabel(header, text="Made by Shibarakiri - v1.2.0", font=("Segoe UI", 12),
                     text_color=MUTED).grid(row=1, column=0, sticky="w")
        self.status = ctk.CTkLabel(header, text="● Starting…", font=("Segoe UI", 12, "bold"),
                                  text_color=GOLD, fg_color=CARD, corner_radius=RADIUS_CONTROL, height=CONTROL_HEIGHT, padx=16)
        self.status.grid(row=0, column=1, rowspan=2)
        self.banner = ctk.CTkFrame(self, fg_color="#3a2a14", corner_radius=RADIUS_CONTROL,
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
        for text, command in (("Reset", self.reset_data), ("Export", self.export_details)):
            ctk.CTkButton(controls, text=text, command=command, width=110, height=CONTROL_HEIGHT,
                          corner_radius=RADIUS_CONTROL, fg_color=CARD, hover_color=CARD_ALT, border_width=1,
                          border_color=BORDER, text_color=TEXT,
                          font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 10))
        theme = CITY_THEMES["Other"]
        self.next_button = GradientButton(controls, text="Next Market", command=self.next_market,
                                          colors=theme["colors"], text_color=theme["on_accent"],
                                          width=145, height=CONTROL_HEIGHT, bg=BG)
        self.next_button.pack(side="left", padx=(0, 10))
        self.tax_seg = ctk.CTkSegmentedButton(controls, values=SEG_TAX, command=self.on_tax,
                                             height=CONTROL_HEIGHT, corner_radius=RADIUS_CONTROL, fg_color=CARD,
                                             selected_color=GOLD, selected_hover_color="#d9a43b",
                                             unselected_color=CARD, unselected_hover_color=CARD_ALT,
                                             text_color=TEXT, font=("Segoe UI", 12, "bold"))
        self.tax_seg.set(SEG_TAX[0])
        self.tax_seg.pack(side="right")
        self.tax_label = ctk.CTkLabel(controls, text="Sales tax", text_color=MUTED,
                                      font=("Segoe UI", 12), compound="left")
        self.tax_label.pack(side="right", padx=(0, 12))

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
                                              height=CONTROL_HEIGHT, corner_radius=RADIUS_CONTROL, fg_color=CARD_ALT, selected_color=CITY_THEMES["Other"]["tab"],
                                              unselected_color=CARD_ALT, text_color=TEXT,
                                              font=("Segoe UI", 12, "bold"))
        self.view_seg.set(SEG_VIEW[0])
        self.view_seg.grid(row=0, column=0, sticky="w")
        self.search_entry = ctk.CTkEntry(toolbar, placeholder_text="Search items…", width=180,
                                        height=CONTROL_HEIGHT, corner_radius=RADIUS_CONTROL, border_width=1,
                                        fg_color=CARD_ALT, border_color=BORDER)
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
        frame = ctk.CTkFrame(master, fg_color=CARD, corner_radius=RADIUS_CARD, border_width=1, border_color=BORDER)
        frame.grid(row=row, column=column, padx=6, pady=(0, 6) if row == 0 else (6, 0), sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        heading = ctk.CTkLabel(frame, text=title, font=("Segoe UI", 10, "bold"), text_color=MUTED)
        heading.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 0))
        value = ctk.CTkLabel(frame, text="0", font=("Segoe UI", 24, "bold"), text_color=color)
        value.grid(row=1, column=0, sticky="w", padx=18)
        sub = ctk.CTkLabel(frame, text="", font=("Segoe UI", 11), text_color=MUTED)
        sub.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 10))
        return {"title": heading, "value": value, "sub": sub, "frame": frame}

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

    def current_name(self):
        return self.current_market["name"] if self.current_market else "Select a market"

    def snapshot(self):
        gross = self.gross()
        market = self.current_market or {"city": "Other", "name": f"Market {len(self.markets) + 1}"}
        return {"number": len(self.markets) + 1, "city": market["city"], "name": market["name"],
                "gross": gross, "tax": self.tax,
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

    # --- in-window dialogs ------------------------------------------------
    def _backdrop(self):
        """Screenshot of the window, slightly greyed, used behind dialogs."""
        self.update_idletasks()
        self.update()
        width, height = max(self.winfo_width(), 2), max(self.winfo_height(), 2)
        try:
            kwargs = {"xdisplay": os.environ.get("DISPLAY")} if sys.platform.startswith("linux") else {}
            left, top = self.winfo_rootx(), self.winfo_rooty()
            image = ImageGrab.grab(bbox=(left, top, left + width, top + height), **kwargs).convert("RGB")
            if image.size != (width, height):
                image = image.resize((width, height), Image.Resampling.BILINEAR)
        except Exception:
            image = Image.new("RGB", (width, height), BG)
        return Image.blend(image, Image.new("RGB", image.size, (34, 37, 48)), 0.5)

    @staticmethod
    def _bake_card(backdrop, card_size, pad=14, radius=24):
        """Draw the rounded card (with border and soft shadow) into the dimmed backdrop picture."""
        width, height = backdrop.size
        card_w, card_h = card_size
        box_w, box_h = card_w + 2 * pad, card_h + 2 * pad
        left, top = (width - card_w) // 2 - pad, (height - card_h) // 2 - pad
        image = backdrop.convert("RGBA")
        shadow = Image.new("RGBA", image.size, (0, 0, 0, 0))
        ImageDraw.Draw(shadow).rounded_rectangle((left, top + 10, left + box_w, top + box_h + 10),
                                                 radius=radius, fill=(0, 0, 0, 150))
        image = Image.alpha_composite(image, shadow.filter(ImageFilter.GaussianBlur(18)))
        scale = 3

        def shape(w, h, r):
            mask = Image.new("L", (w * scale, h * scale), 0)
            ImageDraw.Draw(mask).rounded_rectangle((0, 0, w * scale - 1, h * scale - 1), radius=r * scale, fill=255)
            return mask.resize((w, h), Image.Resampling.LANCZOS)

        image.paste(Image.new("RGBA", (box_w, box_h), TRACK_EDGE), (left, top), shape(box_w, box_h, radius))
        image.paste(Image.new("RGBA", (box_w - 2, box_h - 2), CARD), (left + 1, top + 1),
                    shape(box_w - 2, box_h - 2, radius - 1))
        return image.convert("RGB")

    def _layer(self, build, on_outside=None):
        """Full-window dimmed layer with a centred card (built by build(card)). Returns the canvas."""
        backdrop = self._backdrop()
        width, height = backdrop.size
        canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg="#0a0c11")
        canvas.place(x=0, y=0, relwidth=1, relheight=1)
        card = ctk.CTkFrame(canvas, fg_color=CARD, corner_radius=0, border_width=0)
        build(card)
        card.update_idletasks()
        card_size = (card.winfo_reqwidth(), card.winfo_reqheight())
        canvas.photo = ImageTk.PhotoImage(self._bake_card(backdrop, card_size))
        picture = canvas.create_image(0, 0, anchor="nw", image=canvas.photo)
        window = canvas.create_window(width / 2, height / 2, window=card, anchor="center")
        state = {"size": (width, height)}

        def relayout(event):
            canvas.coords(window, event.width / 2, event.height / 2)
            if (event.width, event.height) != state["size"] and event.width > 10 and event.height > 10:
                state["size"] = (event.width, event.height)
                resized = backdrop.resize(state["size"], Image.Resampling.BILINEAR)
                canvas.photo = ImageTk.PhotoImage(self._bake_card(resized, card_size))
                canvas.itemconfigure(picture, image=canvas.photo)

        canvas.bind("<Configure>", relayout)
        canvas.bind("<Button-1>", (lambda event: on_outside() or "break") if on_outside else (lambda event: "break"))
        canvas.focus_set()
        return canvas

    def open_modal(self, build, dismiss_value=None, outside_closes=False):
        """Show a dialog inside this window and wait for build(card, close) to call close(value)."""
        if self._modal_done is not None or self.closed:
            return dismiss_value
        result = {"value": dismiss_value}
        done = tk.BooleanVar(self, False)
        self._modal_done = done

        def close(value=dismiss_value):
            result["value"] = value
            done.set(True)

        canvas = self._layer(lambda card: build(card, close),
                             (lambda: close(dismiss_value)) if outside_closes else None)
        canvas.bind("<Escape>", lambda event: close(dismiss_value))
        try:
            self.wait_variable(done)
        except tk.TclError:
            return dismiss_value
        finally:
            self._modal_done = None
        try:
            canvas.destroy()
            self.update_idletasks()
        except tk.TclError:
            pass
        return result["value"]

    def _dialog_header(self, card, title, close, value):
        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=26, pady=(22, 0))
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text=title, font=("Segoe UI", 20, "bold"), text_color=TEXT).grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(head, text="✕", width=32, height=32, corner_radius=10, fg_color="transparent",
                      hover_color=CARD_ALT, text_color=MUTED, font=("Segoe UI", 14, "bold"),
                      command=lambda: close(value)).grid(row=0, column=1, padx=(18, 0))

    def theme(self):
        return CITY_THEMES.get(self.current_market["city"] if self.current_market else "Other",
                               CITY_THEMES["Other"])

    def confirm(self, title, message, confirm_text="Confirm", danger=False):
        theme = self.theme()
        colors = DANGER_COLORS if danger else theme["colors"]
        on_accent = "#ffffff" if danger else theme["on_accent"]

        def build(card, close):
            card.grid_columnconfigure(0, weight=1)
            self._dialog_header(card, title, close, False)
            ctk.CTkLabel(card, text=message, wraplength=400, justify="left", text_color=MUTED,
                         font=("Segoe UI", 13)).grid(row=1, column=0, sticky="w", padx=26, pady=(10, 22))
            buttons = ctk.CTkFrame(card, fg_color="transparent")
            buttons.grid(row=2, column=0, sticky="e", padx=26, pady=(0, 24))
            ctk.CTkButton(buttons, text="Cancel", width=110, height=42, corner_radius=RADIUS_CONTROL, fg_color=CARD_ALT,
                          hover_color=BORDER, text_color=TEXT, font=("Segoe UI", 12, "bold"),
                          command=lambda: close(False)).pack(side="left", padx=(0, 10))
            GradientButton(buttons, text=confirm_text, command=lambda: close(True), colors=colors,
                           text_color=on_accent, width=170, height=42, bg=CARD).pack(side="left")

        return bool(self.open_modal(build, False))

    def notify(self, title, message, kind="info"):
        colors = DANGER_COLORS if kind == "error" else self.theme()["colors"]
        on_accent = "#ffffff" if kind == "error" else self.theme()["on_accent"]

        def build(card, close):
            card.grid_columnconfigure(0, weight=1)
            self._dialog_header(card, title, close, None)
            ctk.CTkLabel(card, text=message, wraplength=400, justify="left", text_color=MUTED,
                         font=("Segoe UI", 13)).grid(row=1, column=0, sticky="w", padx=26, pady=(10, 22))
            GradientButton(card, text="OK", command=lambda: close(None), colors=colors, text_color=on_accent,
                           width=120, height=42, bg=CARD).grid(row=2, column=0, sticky="e", padx=26, pady=(0, 24))

        self.open_modal(build, None)

    # --- city selection -------------------------------------------------
    def used_cities(self):
        used = {market.get("city") for market in self.markets}
        if self.current_market:
            used.add(self.current_market["city"])
        return used

    def other_count(self):
        count = sum(1 for market in self.markets if market.get("city") == "Other")
        if self.current_market and self.current_market["city"] == "Other":
            count += 1
        return count

    def new_market_ident(self, city):
        name = city if city != "Other" else f"Other {self.other_count() + 1}"
        return {"city": city, "name": name}

    def ask_city(self, title="Which market are you in?"):
        """City picker inside the window. Returns the city, or None if closed with the X / Esc."""
        used = self.used_cities()
        other_label = f"Other {self.other_count() + 1}"

        def build(card, close):
            card.grid_columnconfigure(0, weight=1)
            self._dialog_header(card, title, close, None)
            ctk.CTkLabel(card, text="Each city can be used once. Use \"Other\" for anything else.",
                         font=("Segoe UI", 12), text_color=MUTED).grid(
                             row=1, column=0, sticky="w", padx=26, pady=(2, 14))
            grid = ctk.CTkFrame(card, fg_color="transparent")
            grid.grid(row=2, column=0, padx=22, pady=(0, 24))
            for index, (city, theme) in enumerate(CITY_THEMES.items()):
                taken = city != "Other" and city in used
                label = f"Other  ({other_label})" if city == "Other" else city
                if taken:
                    label += "  ·  used"
                GradientButton(
                    grid, text=label, command=lambda value=city: close(value), colors=theme["colors"],
                    text_color=theme["on_accent"], icon=icon_pil(city), width=224, height=48,
                    font=("Segoe UI", 13, "bold"), disabled=taken, bg=CARD,
                ).grid(row=index // 2, column=index % 2, padx=5, pady=5)

        return self.open_modal(build, None)

    def show_lock(self):
        """No market selected: the app is locked behind a dimmed layer until a city is chosen."""
        if self.lock_canvas is not None or self.closed or self.current_market is not None \
                or self._modal_done is not None:
            return
        theme = CITY_THEMES["Other"]

        def build(card):
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text="No market selected", font=("Segoe UI", 22, "bold"),
                         text_color=TEXT).grid(row=0, column=0, padx=34, pady=(28, 4))
            ctk.CTkLabel(card, text="Pick the city you are in to start counting your orders.",
                         font=("Segoe UI", 13), text_color=MUTED).grid(row=1, column=0, padx=34, pady=(0, 20))
            GradientButton(card, text="Select a market", command=lambda: self.after(10, self.pick_city_flow),
                           colors=theme["colors"], text_color=theme["on_accent"], width=240, height=46,
                           font=("Segoe UI", 14, "bold"), bg=CARD).grid(
                               row=2, column=0, padx=34, pady=(0, 30))

        self.lock_canvas = self._layer(build)

    def hide_lock(self):
        if self.lock_canvas is not None:
            try:
                self.lock_canvas.destroy()
            except tk.TclError:
                pass
            self.lock_canvas = None

    def pick_city_flow(self):
        """Ask for the city; if the picker is closed without a choice, the app stays locked."""
        if self.closed or self._picking or self.current_market is not None or self._modal_done is not None:
            return
        self._picking = True
        try:
            self.hide_lock()
            city = self.ask_city("Select your market")
        finally:
            self._picking = False
        if self.closed:
            return
        if city:
            self.set_current_city(city)
        else:
            self.show_lock()

    def prompt_start_city(self):
        self.pick_city_flow()

    def set_current_city(self, city):
        self.current_market = self.new_market_ident(city)
        self.hide_lock()
        self.apply_theme(city)
        self.refresh()
        self.say(f"Counting orders for {self.current_market['name']}.")

    def apply_theme(self, city=None):
        """Colour the app (main card, Next Market, selected tab...) with the city's theme."""
        theme = CITY_THEMES.get(city, CITY_THEMES["Other"])
        self.hero.set_theme(theme)
        self.next_button.set_style(colors=theme["colors"], text_color=theme["on_accent"])
        self.view_seg.configure(selected_color=theme["tab"], selected_hover_color=theme["tab"])
        selection = theme.get("sel") or shade(theme["tab"], 0.4)
        ttk.Style(self).map("Treeview", background=[("selected", selection)], foreground=[("selected", TEXT)])

    # --- markets --------------------------------------------------------
    def next_market(self):
        if self.current_market is None:
            self.pick_city_flow()
            return
        self.drain_events()
        self.refresh()
        current = self.snapshot()
        if not self.confirm("Next Market",
                            f"Save {current['name']} ({fmt(current['net'])} silver with taxes) "
                            "and clear the current sell and buy orders?", "Save and continue"):
            return
        city = self.ask_city("Next market")
        if city is None:
            return
        with self.capture_lock:
            self.drain_events()
            saved = self.snapshot()
            self.markets.append(saved)
            self.clear_current()
            self.current_market = None
            self.current_market = self.new_market_ident(city)
        self.search_entry.delete(0, "end")
        if self.demo:
            self._demo()
        self.apply_theme(city)
        self.refresh()
        self.say(f"{saved['name']} saved: {fmt(saved['net'])} silver with taxes. "
                 f"Now counting {self.current_market['name']}.")

    def reset_data(self):
        if not self.confirm("Reset all markets",
                            "Delete ALL saved markets and ALL current orders?\n\n"
                            "This cannot be undone. You will be asked to pick your market again.",
                            "Reset", danger=True):
            return
        with self.capture_lock:
            self.markets.clear()
            self.clear_current()
            self.current_market = None
        self.search_entry.delete(0, "end")
        self.apply_theme(None)
        self.refresh()
        self.say("All markets cleared. Pick your market, then browse your own order pages.")
        self.after(100, self.pick_city_flow)

    # --- enlarged views (click a card / All Markets) -----------------------
    def _wire_clicks(self):
        accent = lambda: self.theme()["accent"]
        for key, card in (("gross", self.c_gross), ("tax", self.c_tax), ("orders", self.c_orders),
                          ("items", self.c_items)):
            attach_click(card["frame"], lambda key=key: self.open_expanded(key), card["frame"], accent)
        attach_click(self.hero, lambda: self.open_expanded("all"))
        self.market_panel.bind_open(lambda: self.open_expanded("all"), accent)

    def market_rows(self):
        """Saved markets + the current one, with every value the enlarged views need."""
        entries = [(market, False) for market in self.markets]
        if self.current_market is not None or self.sell or self.buy or not self.markets:
            entries.append((self.snapshot(), True))
        rows = []
        for market, live in entries:
            rows.append({"name": market["name"], "city": market["city"], "live": live, "tax": market["tax"],
                         "gross": market["gross"], "net": market["net"],
                         "tax_amount": market["gross"] - market["net"],
                         "orders": len(market["sell"]), "buy_orders": len(market["buy"]),
                         "items": sum(quantity for _, quantity, _ in market["sell"].values())})
        return rows

    def open_expanded(self, key):
        spec = EXPAND_VIEWS[key]
        rows = self.market_rows()
        theme = self.theme()
        values = [row[spec["key"]] for row in rows]
        total = sum(values)
        top = max(values) if values and max(values) else 1
        list_height = max(180, min(440, self.winfo_height() - (420 if key == "all" else 340)))

        def detail(row):
            if key == "all":
                return (f"{fmt(row['gross'])} before tax  ·  {row['tax']}% tax  ·  "
                        f"{fmt(row['orders'])} orders  ·  {fmt(row['items'])} items")
            if key == "gross":
                return f"{row['tax']}% tax  →  {fmt(row['net'])} silver with taxes"
            if key == "tax":
                return f"{row['tax']}% of {fmt(row['gross'])} silver before tax"
            if key == "orders":
                return f"{fmt(row['orders'])} sell  ·  {fmt(row['buy_orders'])} buy"
            return f"{fmt(row['orders'])} sell orders"

        def build(card, close):
            card.grid_columnconfigure(0, weight=1)
            self._dialog_header(card, spec["title"], close, None)
            ctk.CTkLabel(card, text=spec["sub"], font=("Segoe UI", 12), text_color=MUTED).grid(
                row=1, column=0, sticky="w", padx=26)
            big = f"{compact(total)} silver" if spec["money"] else f"{fmt(total)} {spec['unit']}"
            ctk.CTkLabel(card, text=big, font=("Segoe UI", 36, "bold"), text_color=theme["text"]).grid(
                row=2, column=0, sticky="w", padx=26)
            small = f"{fmt(total)} silver" if spec["money"] else f"{fmt(total)} {spec['unit']}"
            ctk.CTkLabel(card, text=f"{small}  ·  {len(rows)} market{'s' if len(rows) != 1 else ''}",
                         font=("Segoe UI", 12), text_color=MUTED).grid(row=3, column=0, sticky="w", padx=26)
            next_row = 4
            if key == "all":
                chips = ctk.CTkFrame(card, fg_color="transparent")
                chips.grid(row=next_row, column=0, sticky="ew", padx=20, pady=(14, 0))
                next_row += 1
                totals = (("BEFORE TAX", sum(r["gross"] for r in rows), GOLD, True),
                          ("TAX", sum(r["tax_amount"] for r in rows), RED, True),
                          ("ORDERS", sum(r["orders"] for r in rows), BLUE, False),
                          ("ITEMS", sum(r["items"] for r in rows), VIOLET, False))
                for index, (label, amount, color, money) in enumerate(totals):
                    chips.grid_columnconfigure(index, weight=1, uniform="chip")
                    chip = ctk.CTkFrame(chips, fg_color=CARD_ALT, corner_radius=RADIUS_CONTROL)
                    chip.grid(row=0, column=index, padx=6, sticky="ew")
                    ctk.CTkLabel(chip, text=label, font=("Segoe UI", 10, "bold"), text_color=MUTED).pack(
                        anchor="w", padx=14, pady=(10, 0))
                    ctk.CTkLabel(chip, text=compact(amount) if money else fmt(amount),
                                 font=("Segoe UI", 20, "bold"), text_color=color).pack(
                                     anchor="w", padx=14, pady=(0, 10))
            scroll = ctk.CTkScrollableFrame(card, fg_color="transparent", width=660, height=list_height,
                                            corner_radius=0)
            scroll.grid(row=next_row, column=0, sticky="ew", padx=18, pady=(14, 22))
            scroll.grid_columnconfigure(0, weight=1)
            if not rows:
                ctk.CTkLabel(scroll, text="No market yet.", text_color=MUTED, font=("Segoe UI", 13)).grid(
                    row=0, column=0, pady=30)
            for index, row in enumerate(rows):
                row_theme = CITY_THEMES.get(row["city"], CITY_THEMES["Other"])
                item = ctk.CTkFrame(scroll, fg_color=CARD_ALT, corner_radius=RADIUS_CONTROL)
                item.grid(row=index, column=0, sticky="ew", pady=5)
                item.grid_columnconfigure(1, weight=1)
                ctk.CTkLabel(item, text="", image=city_icon(row["city"], 30)).grid(
                    row=0, column=0, rowspan=2, padx=(14, 10), pady=(12, 0))
                ctk.CTkLabel(item, text=row["name"] + ("  ·  current" if row["live"] else ""),
                             font=("Segoe UI", 14, "bold"),
                             text_color=GREEN if row["live"] else TEXT).grid(
                                 row=0, column=1, sticky="w", pady=(12, 0))
                value = row[spec["key"]]
                ctk.CTkLabel(item, text=f"{fmt(value)} silver" if spec["money"] else fmt(value),
                             font=("Segoe UI", 14, "bold"), text_color=row_theme["text"]).grid(
                                 row=0, column=2, sticky="e", padx=16, pady=(12, 0))
                ctk.CTkLabel(item, text=detail(row), font=("Segoe UI", 11), text_color=MUTED).grid(
                    row=1, column=1, columnspan=2, sticky="w")
                bar = GradientBar(item, height=10, bg=CARD_ALT)
                bar.grid(row=2, column=0, columnspan=3, sticky="ew", padx=16, pady=(8, 14))
                bar.set(value / top, row_theme["colors"])

        self.open_modal(build, None, outside_closes=True)

    def refresh(self):
        gross = self.gross()
        net = net_total(gross, self.tax)
        self.hero.set(net, f"{fmt(net)} silver",
                      self.current_market["city"] if self.current_market else None, self.current_name())
        self.c_gross["value"].configure(text=compact(gross))
        self.c_gross["sub"].configure(text=f"{fmt(gross)} silver")
        premium = self.tax == 4          # the crown marks the premium (4%) tax
        self.c_tax["title"].configure(text=(" " if premium else "") + f"ESTIMATED TAX ({self.tax}%)",
                                      image=icon_ctk("Crown", 16) if premium else blank_icon(), compound="left")
        self.tax_label.configure(text=" Sales tax" if premium else "Sales tax",
                                 image=icon_ctk("Crown", 18) if premium else blank_icon())
        self.c_tax["value"].configure(text=compact(gross - net))
        self.c_tax["sub"].configure(text=f"{fmt(gross - net)} silver")
        self.c_orders["value"].configure(text=fmt(len(self.sell)))
        self.c_orders["sub"].configure(text=f"sell orders · {len(self.buy)} buy orders")
        self.c_items["value"].configure(text=fmt(sum(quantity for _, quantity, _ in self.sell.values())))
        self.c_items["sub"].configure(text="total sell quantity")
        self.market_panel.set(self.markets, net, self.current_market)
        if self.view == "console":
            self.view_info.configure(text="Capture log", image=blank_icon())
            return
        store = self.sell if self.view == "sell" else self.buy
        total = sum(quantity * price for _, quantity, price in store.values())
        self.view_info.configure(
            text=f"  {self.current_name()} · {fmt(len(store))} orders · {fmt(total)} silver",
            image=city_icon(self.current_market["city"], 18) if self.current_market else blank_icon(),
            compound="left")
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
            self.notify("Export", "Nothing to export yet.")
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
                    output.write("ALBION ORDERS TOTAL\nMade by Shibarakiri - v1.2.0\n\n")
                    output.write(f"ALL MARKETS WITH TAXES: {total} silver\n\n")
                    for index, market in enumerate(markets):
                        status = "current" if index == len(self.markets) else "saved"
                        output.write(f"{market['name'].upper()} ({status})\n")
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
                        writer.writerow([market["name"], "current" if index == len(self.markets) else "saved",
                                         market["tax"], market["net"]])
                    writer.writerow(["ALL MARKETS", "", "", total])
                    writer.writerow([])
                    writer.writerow(["Market", "Type", "Order ID", "Item", "Quantity", "Unit price", "Total before tax"])
                    for market in markets:
                        for kind, key in (("Sell", "sell"), ("Buy", "buy")):
                            for oid, (item, quantity, price) in sorted(market[key].items(), key=lambda entry: -entry[1][1] * entry[1][2]):
                                writer.writerow([market["name"], kind, oid, item, quantity, price, quantity * price])
            self.say(f"Export saved: {path}")
        except OSError as error:
            self.notify("Export error", str(error), kind="error")

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
        if self._modal_done is not None:
            try:
                self._modal_done.set(True)
            except tk.TclError:
                pass
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


# Embedded icons (PNG, base64): the 8 cities + the premium crown, so no extra file is needed.
ICONS_B64 = {
    "Caerleon": (
        "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"
    ),
    "Lymhurst": (
        "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"
    ),
    "Fort Sterling": (
        "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"
        "SUVORK5CYII="
    ),
    "Thetford": (
        "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"
    ),
    "Martlock": (
        "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"
        "tQAAAABJRU5ErkJggg=="
    ),
    "Bridgwatch": (
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAcFklEQVR42sWbeZBl2VHef5nn3rfV3tX7Nt09+2hBGAQ2CINxsCsQ"
        "wgybMBbCgxAO2dgWHsCGmhaEwbIRhCHAksBGCkuEZwiMRohQ2ATCDiMjiUUCaTRMM6Punt67q6qr69Vb7j0n03+c+6qqN01LlvGd"
        "uD3d7727nHMyv/zyyzzC5+lYWlrSxx4DkeO27ePeud/+sSOrayv3zs/b/fsP7rvXUjymwh5c5oFW87sKWAG/QKHPnj9/4cTyuP3M"
        "3t17Tux6xU+eAkaTG7rn5xw/ft1zPudD/m9v4I6Ai4gYwOOPPxzmrpYvuevgoW/etbDw8lm1FxUt3UUcTdMWsATm+dx+qIAqKCBC"
        "bbLuXlzsD+MnVlf7f3Ru+dz7/vb3vPtTCD6ZCJHjDvj/lwlwEHxJJiv+Sz/0t+76tld/5dftXOh97yjVXzI11ytxoD8EA7w2VG58"
        "rmzdbuu2lYigSKvTBnPcITmj5PaHl5c33vnE+37/9/7ZL/zJ+c/HRMjnuuqq4u7OO3/07y7+na/4G6/dMTv1uqmp8iEkQT0iSW2Y"
        "IIAaggZB7uBxroxVcXFXNxd3yvyaSqvEanyU0p+trq6/4wO//5F3/8N/+6F1VSElF5HPfhLksx+8a2Pu7VPv/1ffsXhg+id6Lb9H"
        "Uo2N+q4kJ7UUAoiDR1wcEJrp2PZUud6mPE9ArYIJFAiaApICMARdNyiVsguhRYr+8TNnzv/UkVf/h/cCcdu73fFRfDaT5b4kImK/"
        "+5avv/tLv/Sht/R66Vs6UulwfWRBnIJCXIKKFLgpyRJCgRYhD14CxATu11u+e/4uBFAoVXFPePTsPuLNq3YU1GNVu5VKGfQLduzZ"
        "+Z5rH3nzb/zZ//rDHxOR841L2OfVAhqgQ0R85QP/6nvndrd/SluDw9VG38U6BG2JuCIieUzSDFYEj8Z4PIZxjYwisa6JMWLumxPh"
        "zUSUZYtOr4OVQlEWhFYXJG3zbgeFpFArJMxUCu1OdRhdG/3lysrKowe+4Rff6+6CCHIHuCB3AnaTYT37G//40SPH9h/XMrZGwzUL"
        "ahJQUS/BNaO4CBCw0YjhRp+N/pDRcIRUiZ4JsY6ICKKCTyzBwd1xd0IRGEsidFp0u1NMzfQoe73GOhwkP6oOzdR5cHPzbrutZvRP"
        "nzz16NG/945fVlGSm7zQJMgLxfbjx4/bh37u4e5LXv7SX+p1itfFNMZT9CAmQkIR8ICgYIrVNRsrK6xfu8a4GqMeUIQCoWWT19l6"
        "J5FtAUHyRBhOAsyNECC0WvRmpmjPTROmOhACJkIUR0RQETyZhVCoIDx/6vRbDz/8jkfdPYHwmcBRPgPYiYj4k0uv7H3ZN73srQvd"
        "8vWxXxsukjHaCQiaFBBsPGbjyjLjwZC6rrFkiDsqRQMgIM2KSzbPxltk+zPz9+YIjkhA1KliTRSjmO7Qnp2mt2OecmqKlIEpQ4QI"
        "5mLgFL2enj176WcOfuO/+wlVTWYmtwuTn3EC3v76Ly6+73Xf+vZypnrtxkY/tVIrCIq7oCqoCTJ2xhevsLa6QoyGAopmPuNbj1AH"
        "wzMlkC3nCqKoCu5glrFLzcAdVyUUSmVG9JSvDUJ3ZprZxR20pntQ5GjjDV4md/eiRbtdyPOnPv3Ww69625uaxbQ7nQCZXHDut9/4"
        "L/cdWPjpmAYJXNVaIoCZ5AEabJy+xMbqOilFRAo0I2Z2VwcVaSYiB0ITocaIzYIE8m9UBBHNwOiGSf5NQkkBgkPpiniGzKBCe7ZH"
        "d/9etNfCPZEwUCGau5TiodXi02fPvvG+V77tl28XHW4Kg48//riKSLr0gR953eKe+aV6PHA8qAqi5GkOItSDIZdOnkWGQLL88tdZ"
        "mWMiuCioZL92qM0IZYkXgYkfpGS4GeZOUCVYQwmamVMHdQEXxAURx83YWLtGpcr8/l1IuyQ7gGcGUjvJazm4d+/PXvjfP3JG5PiT"
        "t5oEuZXfP/tb/+i+Q/vnPxhCsb+uoqsimBOSoUVJXOuzcv4C4/6QwltYSrhDEQrACeaIO6aCFQU1CZdA0Zlham6W7vwcUuTfioOb"
        "k+rI+soK62tXCXFEiBHcM4FEEGv+j0x8C1cnBaGc7rLz4D5olc1ADFGhFjdpBx3DM08//exXffHff/d5z7jpN1lAY7l8cOnh6d07"
        "p99attk/6g8tSEsxzbHQa6r+gKvnLmD9EW1XoqUMakLj4c3NGjQf2pii12bngaN05/YiZcC1WXrJYIdDidBZXGBuPGb9+VMMr5wn"
        "Vom2FxkTyDjhkq0AATfDDUbX+qycvcD83r2ETjuHY4+Uohojaapb3HfPsWM/+xA8Al43sdozv94KeiIi/rIv2f9d0x39utFwZCKq"
        "CqgJ6opE5+LJU4w3Bqg7XqXmPt7EZMO9eVkCtQm9+Xn233svvV2LSKdFcqeyRC05B64zh80AV5YUU1MsHrmL3UeOUk5NU5sgknmG"
        "4xi2SaLcsiuUoqwtr7J85myDsEoTR4nDkVbDsbXgO97/xBteKSLuvnRzViaCv+vHvmLft33913yk3aoPVqny4CqFF2AK0RmePcfy"
        "5QsIgjo4AlI0qL4ts6VNtMD07kUW7r8bCmkord4J6wRPiBu2MeL0J0/AYEwrOM6wscQbIppInng35nYuMn1wHxKyqyRJjHHvTfck"
        "xfTnJz7x8Vc89MiT65NbaJNSiju87KUPfn/Z0YN1cguUEkzzC4kwPH+ea5evUKKI+TaQsm0WkHA3RmZ05+eZP3wYpARTPENoc92t"
        "T2sWjxBAFJ2aYf8996LtHmMz0OxWjm8yx8msKUJAWLt8mWplFTSAZYcvgspoOLSg8tJ9R+777mxAS5oBdgkVOW6/8PqX3bu4OPNa"
        "k8rRDEwTQpKGA9auXqWOKSN2MxK3CYU1zPOrJYyi12Lx3qNIpwWZjDWgJXgQDDB3rAlp7lur6pvJUXbT1tw0e+87Cq1AlWqs0Qdu"
        "pjXeuJ6ytryCjyq2p9+O4Gao8wO/+J1fuF/kzeaOKI8tAfDqV33FN+1e7B4bVyOSRXXLA/U6snLhIuPxGMGxJodpuApmiWQpT4Q5"
        "QYS9dx9Dei3QmGMYjrih5mgoCSjBnNCENxVFJaAGmjK/wCdkwmjNz7CwZxc0iaSlrUnbOsHMAWU4GDJYWQazhoECglZ18qle56UP"
        "f9dXfXV+wJIUIsfNf/eN7f5c97WexoK4eYZpRIRqOGb5yhXK6IQGM71ZgrwIhpDNuxpV7L7rEOXCHGC4bpEgUOgPGQ2uMBpskBrW"
        "l+pEp9Om3ZuiPTMNZavJ+iKI4kVOsOb278PW11hbXQFxdAKEqtvWP1tPipFra2tNuC2b6KQk8LZKsWvn4ve6+7sR8QLg45evvPz+"
        "haMvqatIy1TdQQ1Iif6VFcI4UmqxOeSJuao7AYgKG6kmLMwyc+wIlAV1zKZfqCNV4uqpswxXVhgMNhiPx/keAjEZRVlQFgXTU7PM"
        "Li7S272IznWpiNTutEQoex1mDh3k0tVVCjOCZxZp5ohotoImDKsow8GYleUVdk7vJ6hOzF+tqokeXvHHv/ja+78cni4ADh/a/6pO"
        "u62jdbfC0ZyFBaqNDdYuLzOlJSQj6vU+5+4ISoqQioJ9dx1DejMknEii0IJrV1ZYPvFpxlevISqklGiVJaEIm2JorCPj8YjRcES/"
        "vwbnn2f3fcfo7t6BBGswBsodC+w8fJhLzz5LKzQA7Xl1M53IruCa84rVlVVm9+yg7HVRMwoDU7NWS7uL8zPfDDxdfPDnXzWvRfii"
        "OB43Zi0NBin9a+uYGdEAM1xkk74CuCgjlKEZew8eYW5hFyRF2kq7VbB24TLPf/IZQn9AUQZ0ZppdCzuYmp9DQ9EAoxL7fQYbfdav"
        "XWM4GOIp8dxTT3FweJTdRw7gyRAtgIId+w+wdvEio/U12iErTRmvbPPFxEDEiXXN2tWrLHRaTQQSzIygicVdM38T6BT7D+y8T4M+"
        "4C5NTMxc32NkdXWVVEdKCds0WyGmlAFWAwN3dh8+ys4jxyC08OSoBTZWlzn3qb/CNob0Ol323nOU6b17G9m7bPL/rA+0Z3cwFYSF"
        "YZ8Lnz7J6uUrlDFw+ZmTdMyYPXQAygbFuy2OvOhBTv/5x6hHY9QUjxENikwock6miTExHAyZTZEUnaAFJgbUzMyUL3n+fT9ySPvj"
        "0X2dTmcxmiEuIu6oBkaDIfW4ymKDOzp53+bvk9Rn/933sOuee3IKYgGRLr4+5Myf/gW6vkGnUPbde4Tpo4dImkgCJo5pw8NccM+a"
        "QjHVY//9d7N71y46yejUkQt/9RzjtWtQBOomhwy9Ke560YtZ3L0XMcuLIVxHyLIWIQw2NqiqmqIIpEyWJNYjROvdqyuX7y0eOnro"
        "xYXFVlVVhpRqOBZrqtEQG1ebjLn2HBalCBStDov79tHbuw+m5wFFrHm6GssnT2HX+qgGFvbvYmrvbmw8QCRk8uQNcBGaPMLxFHFP"
        "aKtkz4G9jM+eRYFRXXPu6RMcmerR6nUgAq0WurDIwvwC8wf2cfX8RfpXV6nHoxx1HILlslMcVMiwQtsdXAxXlXGM3grF7FRP7i/K"
        "aA+IJ1oE3NMmq6o2BvioQkKHKBAbbOi02izs20t7cQejeky6fAkVJVYVBKEaDlg+d5pCA7UYg2GfeHWZMDONlMUmh5ftCWkDpiJC"
        "Gg5g1EfEqFINyUnL1+j/1WmKxbmMeSFkqusJAszs30XZKbl05iyeUr5tckozJCZkOKaYF2rJrFYpvBCVg7t33VPEFO/OodRkk7KJ"
        "MBgMUFGk0eYEKFyo1zc4ffUErXaXqq4hFKgqVazBDQ1KQdYA1GF9dZWnPvpRWt0eZbfLXQ++iGJ2B6SGoXgCVUb9dc489ynGg3Va"
        "ow1sMCCEEhPDxbl09gzx+dOAkBr+Ye5ErwmaGYp6Jj6FKGr5fS0Zg40BU26YTAK5NEw23V2o6K4GQDfTZHenrqrM/MwwmiQ6JlSE"
        "toEMKzpCQ3UTpWeWSMPZEaEQQd1JVYS6T3/1GqvT8+x6YC5njgpYQly4dObTXD79HNPtkrqqUBzzRjcSI9Xe0DDZNHPEaWnAUw6H"
        "HiaLb1l9wqktMhqPNqNEI9OJ1YY7ewszn9sumk7ykZRS5uruuDgRRwKoeZ5hGiaWIk16nnN70UyTRQlAYUYHBRNKSoaXlvG7htCd"
        "xj0RSqUeXOPqpTNMF0qnrnI4bjSDyWCdGt+WvYvmNL2MmYVGgRgNC3mCrHHlicqMO1vr77iBmOwogPZN6aVvafWZmEvO1nLlKqu7"
        "DoqTGrI9SWpQw7zxz2a1xPIEFSKM+htUwzHtqRncEgShHmxgowGdVBMsYRIy52iSpq2VsW1VtJzuaiO1m+bodONQ8Ft8NiHyQrto"
        "ys2ba9gwnMYOZHM21LZkI/cMxpO/bz+s0ZyAxlcV00Yg1cwh6sGQtmdFBxOq9XVsMCYUkDDctame+/WLEm/QHB1GOKJ5cfCmkNQs"
        "VkIyTtQRmJTn7DoZoRD3SlQ67tfPzo1WsZlV3WAot5HUbzYoyTcxd1JVgTshBHBnNBwilq3K8Pxb34rnn+lhNimqbnNh3366N5rl"
        "xAXyIooI7lQFLuuCdsztpoJ9igkLTXzwOy8kby95WZOgiEtWC8xJ9TivVlEAFYONDURlE3CzvCu3GPgLv4M38Uy3T0rQ611bGoke"
        "Wy1AL4voLvcsOU7ygLIsGKVE3Fw9yeHtBQ7btvpuuTyeX12zCJKM4WCQq+RueEqMR+Ocz08mzNNtBn1n5f9GDszYpVC22yT3HLCa"
        "nFlVRBKXCkSe06APEaNPLM4VelPT9MMyIjmcuDvR4h3Um7fRiW1/eqMCa1CGgz5YDVpATFiKWExbGvV1hazPvvFDtrlyCIFut9uM"
        "3DZ1DAmCRnmuqLz1dJDwyug1YVPoMDrdFqJCTA0PuI356S0sYGIFsl26EsFTIjlUdZ3vKEasNkjDIWUICAZeNC0BfhOeiNzZZEjK"
        "gF7l0EPotjfXpoFGwQqurKw+Uzx7+sJfHD18oHbXUjAPnkl9q90mlAV1NcJDji96Cxy4KQpMQiI3gKZPFEOlris8jpFWm3o4wKox"
        "mqDCsn9uu9htq5nC73QCPJfgKnXKsk2r07nhRZLgsr62PHimmCraJwxfDcLu5t0FEdq9LlqWRAYEKXA3Yrq5vqg3vpNmzjBpitms"
        "+Dbmoi7E8SgPeqpNipGYIlKPs4lqLpgG2SqXb6ue39GRC7CCYxRFQbvb2bRIU1yLlgy9uDw7v++E/sHH/uQvY4zPFIVmZdedqqoJ"
        "Rcns/FxWfVQIobhZj78NCG6p1b7ZD5ALGhmdLNb5u1ZJXY2xFG/wl+xGZn59OLuD03GSW55UFxbmF1DJEQZ33AVpdVkejD954DVv"
        "PaWP/PwfrdZV9adlUSAesx8ixBRZ3LWT0CqpqhpLqSE+ft3JDedEJp98b2ZYo9hMYrFZRn9iZDjKAqk24qZI1vlSUyydXH+nZ4qJ"
        "osjtOaFVsLi4mBfGLOOQKEkCl9b6HwGGCvjz5z/95LgaepAkSETFqWOk3esxOz+fGxRSnFT3GyPL543/TboAJmUyk/xvc8ct5/wp"
        "JqrhCGKi3hjhVd0kK+TrZOse25/FLSb8pgXAqc2oYmTH4iLtbrupZTgmYGrqycbrq8vv3SyOph36oaD2dKuUB8fRzHB1zY0QCzt3"
        "cHXtKtVg1Mji23nWresT4jd1P070NMQVPDHuD5iOQlofQIokoUletnDGr2eud0bCFCxFynaL+R0Lm+7jEjDHWqUqVfXhr7zy0CcB"
        "Ufcl/bJvf2J47uLqu1wLDMUQRJXozuzcHLOzM1ux9QYXuNW56Y+3+U4nrbEYo8GAUBRNX8QN15rf0fOuO4GYErv37qE3NYWlrdJd"
        "wiVCWl67+i45ftzcl0R5LA/s8qXqyY1KTycJkgxzz2AS2m32HDiIqhJj2qzI3ujjL3wmLBmejKquqEYjwBiMBmAJ85TbYCa+3Jx3"
        "ev8Jgx2PKrq9KQ4cPJAToZTvmVJlRWGs9Qef+p3/9qH/DsJjjx2nkOPHvWmMeOr0b77xP88tdn88prEXzmbJe2Zulj3797F85jyp"
        "TrnI20C9+Z3E5i2XmaTSdT2GqqYaj7OS04ivN/rUnXqASo4aoSjZe2A/RbuTOQwGKbflKchwVP3a69/+1OlJt4hOtCCAvzxz4W2R"
        "4lKrLDS6exJnHGvGseLgXYeYnZsjetxEbG4IT9tD1nXV222FFCOh4qRYYcM+1mh42397y+tvjDzXdW3nj8ZVxZ49e9i9ex/1OOYu"
        "M1EQ81ZZaKrCidFK/10i0DRYsylO+9KSfs0PP3F6sLL2M4WrmZsnd6JAjeNlweGH7qU1M80o1UgIm4OdqA6bDRKbmY03Ob8jJqg5"
        "glFXQ3x0jfrqFSTFbMJmWU4za1rf8unNd35dqM0FIUtZwtfQYjAaM71jnoN33010IRHwRrcScR8PY7V8duPNL37kiRWzJb25Q+Sx"
        "7Ar/86Mn37nWr/9Hr91SczPXpkjqCcrAvQ89QG96mlE1ovaEiZNwbBtNtebf2z9jW7QSBasq+qurWFNZ5oUsYNvnW7JY3mMwrEZM"
        "Lcxyz0P3k4KSmmZrE6GK0Yqy1EE9fN/SI7/ym1mvOe435TITRfQ1P/v+1fXx8J+OqriiIprcfdLgOYqRqblZDh87Rmi3qao4kRdy"
        "s6RlPzS/Gc0nLDOTnkC/v8GFCxduOehbRg+zBoCzoeCCoAyGQ1q9Lvc8+ACh06GyGlMjaSSSbGpmJoysOP2xT/7Fm965tfPEb5nM"
        "Nf0zev93vu3jyysrbw5FYUHFDfcoIEWLUZ2Y3jHPPQ8+RNntMhxVpOjEaMRopNRMwgTNU2rOjOreSGarV1e4ePFiDq/N4G7J7Jrr"
        "8z2bHgDPAmh/Y0BvdoYHX/piZubmqN3xQqglUlG7qUslxXj12ujHv+H4h09m4HsBiWXbThAu/dYP/euZqc6jw6pKbjlbLhAkRtpB"
        "GfWHnDrxLBcvXkRdKEOYMPmt6nFTa5yIrJY32GT1drMH0F8w7Z/U+0QES9m69uzZw5EHjhHaLSJgIZDEMMU9uIdQ6vNnrjz6BY+8"
        "5y2321kit98O4/AHj7VXrqy8p9ubenW/qpJKHRSnaNheSwvUnLMnT3Pq1EnGGxsEDRRlaMw1g55s0xQnvUC+PZ+eNFLIlv64FTzz"
        "h6HMZKmqakIouP/+B9i9dw8EISlEN0yVWo2+BOt0WjoarP/qXd/69jf40pLJbTZZvWCz9O+84RULX/jVX/4r0z2+Y1z1TZvAEiy3"
        "uJaieJ24trrK+bNnuHjhAg60irJBdGPS2xia3H57md3cNnt5NtmmyFahUwoQGNVjylaL3Xv2sG/vfmZn57K2o7qpAkfBU3C3zoxe"
        "uDr85Y9+4Lf/+evedXpkdvvtNMXtlS2ZEKTV/7p78Qdf/pJDrflO8epRTG4pa2oOOSS6M71jnrvnptl/5DBnTp3m8sWLeFNG16ZI"
        "MhE0RK7bQNM0Vm5NQK0QG3U41mNEhQOHD7GwY5H5hQVanQ5VVW9uNhMg4u5BJBSljIbxV586d+5N3/fO0yN3E/kMUtILagxLS+jx"
        "49jSP7ir88jXfs1P9nrdHwWkjtHaZUtTjE0YyxZWhEBbhOHaOufOnePatatUo9z9EeuUe58kt7TRtNBP0uyJXE07UPY6dKd6LOzY"
        "yeLiTrq9LsmFuimlaQhNd7m7FOqhUK3Eq/NXriy9+Pv/y7/Z1mv2uW+Y2L5x4s3Hj5uDPP2O7/7hA3t3/7i779wYVya51z2X6Bsy"
        "1BboSlaBq2pMGlcMhiP66wMGowEbwyEk21R8JG9Do93p0ut1mZmbpTvVpSxLkIAUuUiTUlYn0WaPQjKXAuZmpmQQ45nnnj/5E1/4"
        "hvf+unsjfMvnYcvMjcAoIv7ht3zjyw4dO/JzM93uV9ejEVWK5hiqoohTRqNIuQlCJBDKAvW8fwiVplHhhnRapakoyaYWGFOdW++C"
        "ggaSh4kFmeC0221NWrK8evXJEyefe9PX/uTvnfh/smnqenDMD3j04YW5H/zGh79vptv+F2VL9lE4G9WGqQrtGi2SEAMkCUTNmyDK"
        "5Jta/fYtMxPB2hpNflKEEXFEYlNZCkQvzD3IdLcrYpGx6clLVzd++oHv/5X3AMPPdvCf88bJyV4igMcffeXhlz545Ae63fI101Mc"
        "IY6wylHDDMdUxVUJnqSYJD5yfRmBbToTrpN9Ae7B3Sw1pcqgZVFilKwPxycuX7z8nz7+iaf+4yO/9omLWUbjr2fj5PXt9VtbZ//9"
        "D3ztA1/28iPfsm9x6nsUHio8SlmUxJjzf3WzVm6nFZks+/Vprzc1QS9CiSe0xujNTVNFY31QWZDiY6vrw3d+8MN//v5/8vYPPTux"
        "SOS4y1/n1tnPtHn6ybe9sjfbb33pob37vzml9EUzven7gvuOlo/LUhIxWbPaW3qCIIiCqFKoEFBM2uP1ul65No5PJ5GPnj574b3X"
        "/kT/+NufeKL6fAz8c9k5ertKWA5mS0tK3j4/AD4IfPAwLDz+c6+5n6q+79jhXS9KxAdUOGoiu0Vkxt3bGe+8wrgmpItm+qzV46ef"
        "P3Puk7Eze+LrfvjXn1mFtRu3z3+2vn674/8Ak1MDRlkQ2CUAAAAASUVORK5CYII="
    ),
    "Brecilien": (
        "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"
        "PeD0afXixx6PHpmf18aOHpXnzpz5Q+APASZPvr188sfedWBs3+G5fDl90ErnDsShOxt7GKFvbrtucD2RyZXI9a7++w/+7CUWF32A"
        "r5w+qz4yf1U7v3AmADh58qT+vve9rw78izP/4N+80Lyx/v6bnfDegw+8Spkan0ga+VymXl/fuxWadwGY5zueg9/5kDh5UufixdCY"
        "fuNb89NT/37fseNl28koi3eW2Fxa2pSD1hPJxrP/DuaVV97yzRmXOH32rFJozykATz52MhLf5TbX6bNn1UK7rdysVuX5uyms/GvZ"
        "mXjk1BPq+fML0W9++Na+P7558cMya/7o+Fg221y9RX/12qdtMXzfV7/08TunT59Wv9MilfYdN8rS6btDU0dMmzIoNaurUWc0Umpb"
        "27cYeI+x9ewzrxj/N6Wa8pXqKwb42OMIpBTzTyCuHT0nTp8+/d9uvPr00+JavS6PXD0tF55Anru7lxh/h+xMnodofn5eed+/PHhH"
        "IH787733U4/vrK1/oFWv7VHjsJJT9TxArXbk+9+OPXnypA6w++ibH9r/wLtu7X74f5HW8R95noMPz75SSv+dbHR/7zu8dwc8P/pz"
        "f3bi8I/8wgv3vvHx7Tc88p633KXT6e9Y7/x/6dyD0wUyoYcAAAAASUVORK5CYII="
    ),
    "Other": (
        "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"
        "5co6rl9BdUpQzqHJgnyhyKXhEWbmlsjNzNDeHCXdlqCSN+loivF93/cAi5Uaw0vLLGcrZPM2iiLT3tLKYP9O8vmcKBUL3c3hxFMn"
        "T3575ZYU+G8JgKGhIWV8fNx97LEfvt+xvX8fCoeke+45LK2vr5GIJrDyZZSgTENdhJs3Z5G1AM3KYvhrHH5oEN8os1YwmbwJVTdG"
        "zRboukY8EaZWKRDSdZL1zbQ01ONaJtFICFlyCSwL1/TIFkro8QY2Kz6mKxNBRfMKyGKdAzt66G1JMHpzkvGczalLI+QLJk0NrWQL"
        "mwAsLi2Lzc1NP6TpUS2kFC5dPPvi8vKytF1csC0AiURCyWaz0t69Bz6uaaF7p25OBlM3p0W1UsW1bAxNxyqv0tSgUxdTuHHtGq1x"
        "i56MhVldQzMMLo5l6Rz6AEcefD8+CpWSxQvPnWJkZIrlpSIXz48xdmWU5flV2toHMYMY5WqYUjVMwVTQYi0UqjJdPfvo3nWIsdGL"
        "GLWbyIUFludvcGXsBs+9dJ3VZZ/GTBdy2MV0inhBQLXqIEsyVs3CD7x4U3vn09MTo4Xtvhi3A0DOZrNB1+BgT1dH369VqmZDrpAX"
        "QpaFBODW2L+nl3I2S2F1jdbGBM3pMPftSxPRaqzZdbw6VSFvpXjk0R8lWt9KMt2CZfkEgcrqSo5LF8eZvLHA9I1pSoUqzR07Wcx6"
        "5E0dT6rDSLURjjcxtOcw9fUZjHiMqZuTXLsyQiG3ilkpk6prQtKjmDWFpuYOpuamMKL1IHQURcd1HaEoilBkNeE5/tWJ8atXDx48"
        "KN1uDOXtxH99fd3bt3f/o6pufKRYLKlWrYau68KyasQjKt2ZJLOTs5w/fZp0Ch4+dojOzg4WCzKT62lyTiN7736EbL6Kr2qkGtM0"
        "ptMk43W0tnYz0LcDq1ylUszRkE5T19pFTU2QzPTS3N5Pc3sPmfYujEgUIUlcuz5MoVxlYj7H3JqDZYeoq2th19AuLMvnxKmzLK/l"
        "6R/YgVmzkTUdIUmoihKEwoYaBP7K6MjFb90i/h/FBf8EgPX1dQVQ2ru6PlzIl49Vq1aAQNi2QwB0tbdgFwv4ls17Hr2bPXtacapw"
        "YaqCn74bzdhJW9sgO/fuxwwEsyszGIZKXSqOLMsokooe0mhqTLG0ME00GaOltx8iCdp6dpBqSNPY2IimazhujfHxEWZmlunu70UK"
        "hbg5rSOFu6l5EmtzG4TDESLJejLtfTiU0SMaFdNH1zWqlWpgO7ZwHUd4rvb1XG65AE8IuP4dAKTbff9rsXM0Wqv5e13Xxfe9ACFw"
        "ahALG6gK1DfWY5keh+95hIN3v5eiE+f8lVn++n/9A927umnsTDM6cZV0Y4zmhhRXL19kamKKSMSgrT1DMpUg1dBEpncIPdVONJEh"
        "05ChIRKlJd2AEdZxbJPJ8TFmJifZO9hLLVfCyls88vARhBzwX/7b5/mHF8eQG/r5yZ//Rbp7erEtjeaGHsxqlUqljG2bolopYlZL"
        "A5lMugXwDh68Kb2RCsiA39DQ2hqJRv+tbTt1AX4gSaogUMhkGhi+dIaN2XkUT+PV85doae3g5Olh1jfLzMxNMzM3zqEjd6FpkNtc"
        "I5NpxtDCTIyPIQGJRJxEIkE4YrCeLxBICi0tbTQ1NtHd3Y0iCSqlEtdHRpibmeXuAwexKxXGr4+SaWxicvwaf/qZP8bzwfYlegd2"
        "Mzl5k89/7m9QZIma5+JLEuVKBU2V8ZxaYJrVUKlQeHFtfWk4EomoW2MCeZvQ2A1FI/2aFvrZaqUSQoCQFBHSI9Q3pliYHEUvFTB0"
        "n7XNBa6PXmdxcZON7AYdHRmmb97gyqXz7N29g1jUYH5unvr6BprSjVy/NoKiKKTTaSLxOEY4jOc4DO7YQSqVQg3puLbLhVfPk93Y"
        "ZO/uPWxsbDI5OUl9Q5ozZ87we7/7n7EdBy2kUrOKWOUKJ799Al3ywF7DwyWcaiaXzaGosnAcxyuXK5JZKp3LFTZezmazylZ3KN8W"
        "AMmAV1efHvA8PlKzbEWWZQKEiEVTJJIRzNwCx4aakFlAKCWQIVnfwP4Dd+E5Fr5vsbY2x+TkGAMDfbS1tjE9PUMqkaAlk2HsxhiK"
        "qhGPJUil6mhsbCKZqkNTdYq5POfPn6NarbJv7z4WFxaYunmTRDzOyy+f4r/+8Z/gOg6RSJTBHQMcfeAIhewmVjFHWJj0tcbo7h+g"
        "5BssL6+Qz+Wwa7YfeIFke97pQmHjhVtM9u5kAwCo2p5es0y1ZplBpVIhm80SjUZxHZ9yLotmVWiKBySjHtFImJ7ePhRJxrGr1Kwq"
        "YVWhUtzgyT/7NJdePU9XWxuzMzM4rsM99xxidHSUG+Pj1CwLVVFQVJVcLsfLr7xMpVLhwIEDjFwbYWVlhdaWDE8//QzHv/BFNElB"
        "VRUIfHQ9hKyEyGSSJOI2HRmZ9noVK7+BZZrIsoxpmlQrVapmFc9xte3o3RYAXFfUajWBEASBj+u4BIFAkmRcX2FyMY+sJwgrYVRf"
        "MDE2zsryEt0dnWQam3FrLqofkNQUvvb3f8eVSxfoamtjc2ODSrnM/v37kRUFIQSarrOytMTLL79MKBRi3137uHjpIoVCnobGNF/6"
        "hy/zzeeeJ5VIouKSMkLsHNyBHo4yMjLK+soScUMQT4Qo2zIjN+ZxHYfAD/Bcj8D38b2AIPCl7fICyhslA2ynhiRLgEooFMYIxTDl"
        "KKdXN7BCPnu7e9i4PokVWERjISzTpKW5FXyP8vocXfE6looW3/jKl3Ecn3uO3E+pXKahKUNzSyuKJDN89Sqjo6N0dHTS2dnOmbOn"
        "sW2bpqZm/vtnP8vFS5fYsXOI4voKIQ36urpoTLeSLVXxbJv85iYJTYFQEycncuScJN1CplwpEQQ+AaBrGp5nva18QAAEQggBgiAI"
        "kCSJWCxB1fGIGPWMzSziFE0UWSNQNKqVCqoio4QTqEoIXTXwfUFXVztFR3DpwgXau3u5710PImQZ13G4OnKZiRsT9PX10drSxomT"
        "L2AYYUKhMJ/+oz9ifHycu/bfRaaxgdWgTHk9ghGOUbPAKjqIioUwq5RrDis3llgqCxpaM4SMMIEfoKgq8i0VE8LbNkm6LQCSFNhu"
        "gEuA+p3gOYBIxAABruvg2BLTN/N0dTTiSRI1s4KrgKQZHLr3PpqTBjeuXkBVQzQkIgztOci77r+PSMygUDY5depF5ufmOXb0KJIk"
        "+Oazz5BMJYlF41y5coWGhnpkZYhKqUQ1LNHd3c2xex9kanKe6elVsE2omODalNwaE+slKvEIDZKLKiv4no8iq6iygiLJ+JJw3gyA"
        "74SIfhBYQhI1hNAIRCAkiWKpTDweJ6Jp+NVN4rJCRNWxC1XCYQ3XrKLFdHYN9BGOJ5mYmcaRdFKxFPsP38O7Hn6EaEMd5bLJqZdO"
        "Mr+4xMMPPQQBnD79CpFIBN8LOHnyFIODg3zgAx9gfHyUp772VXZ097Iwu8zY1CJ9/QN4gc/Iq1NIdhFklY1clZov8GsmhizjewGu"
        "46EioeoqkgAZYb0VCXht717yC74rZSWIBQSBpigin88Ti8VJxgycyhKGU6M1GsWsFQkHFkZdFENVmZkYx5bnqW9sJN3axeF793P0"
        "4WMILcT68jIvnz5PLl/kPY8+QqVS5fQrZ0km4iiywsSNUTbWVhncMUBLpoX29jYG+gZYGp1jbfYkebvAC6deIqZXqa/3cPUwSysW"
        "pZqPqoLiCZpidZhmBVkWKIqEjychJBDB0nZfg9t5AVkNgnVdlec0VUUWPkgexWoB0wno6d5FTDGIBS4RzyQmfLRygfZEHCkAs1Qm"
        "kUySrE/z8Pu+n4ce+36UWJJcscTJUy9TLOQ59sAD5DeznDtzgdaWDjxf8NWvfJXGdCM/+ZMfIZvNcvbsGUyzSs/OIVr6ujHSMcJh"
        "hVRYo7S8QkTSiIRjrG6WIRDIHkQkg4gaIZvNEgrpGEY4UBRFIgiqBGJ6u2qT2wHwAWltba2oqfIVVVOQBEKSfBzf5Mr1UfYdeACC"
        "KJoPfq2KFvjoNYfqZhnXE4SNCJqmcvShB9l78G4CVeXm1DTPP/8ituvx8MMPszA7x5WLV+noGqBY9Tlx6jzRaAqzYhEzohy9/12M"
        "jY/x9NPfZGVxkY5dPXzo33yI9o56/GoRI9Axsz6r83k820MRAToS8UgK3w+oVquoqookSUEopCNJ0lTgOLO36PXeSAJeR8aq1cwr"
        "vufbIAS+D06NK+fPkGlKI4cimK6PpGrIIQNZj5Cv2WBEiaTqeOJf/Aj3H30AVQ8xMT3LM889hxASDz30IFNTU1y9NkJrWx83Jhb5"
        "w09/lumZDXbs2E99fYZnvvkchWKBRx99lFK5zPPPP8/SwiIdXQP82L/6MIO7hnAUgS1LrG2sI6sCCUFckalL11Myq1QrJSLhEPge"
        "QeAjpOBSzsytb5f/uFNSVFIVxVVU4zFJSHWB5wS6oopKoUhbczNhWWZ98hrpaIxAVlHCGhVdp663j4/89M+w58DdOEHA5ctXOXHi"
        "BD09PRw8eDfnz11gfnaGTEsrYzfm+exffx5P0VF1jeXFOXbu6COaMJicmiAWi3H4yGHmZucYHr5GXSpGW2cHe/bsIVfM88rZ0/gu"
        "OLZDWFWIhA3ad+xmIbuJ6/tEjUigyrLw8W3Xc/98Zvbmue0k4E4AKLVaLRdPpPdLstgrBW6gEAglCPDtgD07d7M6PoJOQCgWRwmr"
        "NO3ayQd/+qMcvP8BkGUuvHqREydeYt++fRw+dJjTp19hYX6R/r5+Lly6xF9+7vOIcIT61gyHjhxk7PpFLl58hSOHDhKJRbh27RoC"
        "OHr0GAuLi1y6eJG6ZJyWvj76d/SxsLbK2PUxQg6EBSSam6lr6+L65BSapqJIAlmRReD701bV/b2N3OrGFjV/86ww4ETj9SiCDyqS"
        "L4UVWehCZnMty67BXUS8GqXcJnI4RF1zHT/1y/+OfQ+/m1wuz6mTrzA6OsaRI/fS1dnJM9/4Bpsb63R3dnL10mX+6q//EiewkUIK"
        "d919Fy0t9dwYvUBDMsq5M6cZGBikva2N8fEbVCpVjhw+jOt4XB2+jAg8WrraufvwPYxcvUZ2YoZEKErz7p3MrGYplUw6OzqIx+NB"
        "rVYTPnzhyuiFv71Fl/tW0+IBIBPR1qKyfESR6PZdxw9cRwSeR24jz8MPP8rs6hqm5vPDP/EjHPrg45RNmxMvnWJ6epZ3P/xuGurT"
        "nHjh25TyBQb7Bzl96hX+7DN/hib71MUCGqNRBtpaWZm6zmBPHXftHqJaMnn1/Hm6O7vp7e3lytUrmJUq9913HzXL4tz5c4R1nb7B"
        "IXYPDvKtF19AiieJNHczMbWCpoTQZAJZloTnByWzZv768tryzJ1KaN5oZ0i2y2UrnoxKjmk9JoEiCAjpuijkizS2ddF/1268UMC/"
        "/OiHkBSFs+cvMzI8wrvf/QgRI8LXvvI1hO/R09vLiy+e4It/+wVkWSZpaMQNi/Z0itL6KpJT4uj9e1GEQlfHDkZHRnj22edobWll"
        "x0A/0zMzrCwt88C73vVasmT4Og1GlN6eLtB1bi5vcGNqBUWJgOeRSkaCUqkkVUzzeHG5+BdZM+vdaZf4zXaHpXTamHFr/pARCu9o"
        "72wPstlNoegas8sL3HPfYR7/4PuQoxIzc4tcvHCVA/sPYoQMvvnU0xihMKm6FMe/8AW+/vWvIwuBVbFoqI/TWK+jKD6KCgfv2UM0"
        "GiIcijMztczpV05j12zOnz1HLBZj167dLC8tMTM7w4H9B7GqNebm5jDCESYnZnnp1Fl8z0eVZBJRIxgY6JUWFucXCrnyr06sT0zf"
        "kmr/7UqAAEQ2WzbTyeSq5/GDnuOHbbsWqJoiAgJmZmd54Oj9xBIGw8MjdHcOUC1XOf3KGRrqG3Bsm7/6H3/FpQuX8V2farWKW3NJ"
        "18dpaDAoFjeJx8Ps27cb4UsYoTq+8vdPM3b9BrIQhBSNkWvXMK0ad+0/QLFYYnTkOg0NaWRV48LFy3z1a0+Ry+UJaTrRkE61UgpW"
        "lpeEosh/mJ0qHi9QEG9UNyS/ye5wAKi5Umk2EY3KvuM8oMtCyPgYekjUylVePXOWwd5e6lINXL06QjabxQiHefXcOb70pS8xNTWJ"
        "bTtYponn+/i+R+AFJKIRZOFhmhVaM220Zfo4eeJVvvHMt/E8n8D3qFYqyIrKxOQkV68Ok4jFaUw3sbmZJV8s8ezzLzA9M4dhRNAk"
        "GVXCj0cjkhEJf3s1W/zVG7kb1Vuc9/85ZXICkGRPG4vHtH5VknaqCF9FkeJ6BKdcZfjVi7S2tdPc2sLa6jpf/tKXefbZ5ygVi+AF"
        "eI6DIknoQiEkqXiWSSJsEDPC6JrGffc/RDbv8OdPfg7LtNAUCVkIFD/AsWp4fsDS+gbDly8T0nTisSQvnTjJjRsTJGJxNFkhrOu+"
        "LEuSHlKnS9nyL5+5cfHGEIj1NymTeSsABIAwXbMab4ifwxdHFElulwLhq5IkouEwnutw+swZItEYqqJybXiYjY0NfM9DCSR0JPRA"
        "IiYUknKImBAodon+nh46e3fQuWMnn/3iF7l67SYRCaKyTF3IIOxARKg4AWihEF0d3UTCYa5eusTM5E3qIzHieggR+IEiy5KLly86"
        "9i+8eOXs84C0/prbC96pQkk5lyvmU6nYqCTkQwKaRBB4Ab4U+AGqqjJ8fYRStcKjjzxKa6aF9aUVhP1aekxDEAkUDEVHFRKmZVGw"
        "HJo7+tgs1vjGM89jmzYqIFxQhYomqQgk0u2tDO7aiS6rLC4tYds2uqKgyDK6pvm+hFQyrXKlZn7q7PCVv9ni8/23It5vqd5/S7FU"
        "0N/WfVdYFX8aEvIBhcCTA0lSVFU4UoBZq+H5Hv19fezdtYdqrkBIksELMEsVAsAXASWrii0JtHiEmwtzzC4uIAnoaWtjT98gYVSs"
        "UpVqscSmWWJhdZFcLoceNiAACYEv4RvRqORJQc4OxK+cHb7yuVscv72GOHi7EiBuI37rrGaL+ZWoEbscMkI9siT32LYjTLsWiNcO"
        "FFlmcXGJ8fFxbNchXp+ioa2FWEszTlihIPmUZB8vrLFSKrKUzaLFYqRbWugfGqKlowvT9ZhemGdmeZHl1TVsq4am66iygqqqqCEN"
        "NRwSDt5CuWZ+8sLo6OdvrW87ny/ejgSIO4Dweogs4LVUWW9bW1NjPP5LvuN+aOfOoZRhhLly+QrpxjRSIBB+gHB9qtUKluOQak6T"
        "bs0QSALLsojFYshCYmMji6Zq6KpGKV/CMS2oefi2S800cXwHRZeoOTb19fUk61PB2Pi4Z7q1l1zf/60LU1MXbq1za6lssE0jxlva"
        "Hhe3ESzdum/rDKDlisXq5vr6mfccva99cHBg35lXLwRLK8uitb0Ny7ZuucQQrueCJLAch5XVZZyaRa1SpZjLUdzMIbseK/OLVHI5"
        "lmfnWVlYItPYQDwSxXFqhKIq+XIOOaSSLeWD9u5uoYWN1VKp9okz4yNnY7GYZtu2t+UTX2xZ5xuqubJd48MWAOTbOC9tfbABWhWs"
        "nb0dS5ubq0xNjQemZdHSnvH1UIjpmWmRTjXgOo6QJIERioliIU+pXETXQnh+gOe6DA3uYGVlhWQ8zvnzr7K2uRYoERXVUAK/GnDv"
        "sSPBhYuvkmlr58WXTomxiTF6e/tS6XQyBUiRIJBe26N6bW9zi/6LLergb5f7kO8g+tJt3L9tRGWwZSUcVlzXFfVRfaO/s/ux1rpU"
        "Yn76pogZmmRaZcn1LBENR4RddYRTs8X6yiqVcjnIZ/OUigU820ERgvxmjtxmFiNsIPmBcGq2UBVJ5LNZYVm2sB1XKls1KRqOSK5l"
        "it19PcK1rGsTs4ufnV9frZVtW7qNUdv1JPFmKiC20XV5+2FLgOq6rhLTtOiFienc/b3txkBT44GgWl1uTCeHEzFjQcJfUdRQDoRl"
        "WpZi11wlbBhSQ0ODSCZTIpFICk3TRQDCcT1hO7aQNCWIp5K2Fg6tNzQ1zMuKNruR35iVZOYrxc3ZeEityIFtrSwt/MU3L199VQfd"
        "+8cteHdqyHpTI3gn4pXb9F9sua4Ahgpyu0Lsvv6+wbLrVFdKlaVkKq5smE6k7LjNruc1e57fKoSaCWtaUlHViKLImu/5Ur5QQJMV"
        "X1YkOxBS1Q+cYs1xVzzfX6pa1kpI11c1hbyoeb6sCrcurkQiqqxcn1pdXnExAfvW2GoA/S3e4PVuta2/fccoijtIgLyNCki32QKF"
        "EAoWugoaIDuvvUQFQlu8hXZrvn0oW+zJ691lzm3DuzXbW3T7NWJVVeA4DlC7dY+7hejXifRuu+bd7hXEGxhBaUvwc7sRFNvYB0nX"
        "dblWq/0fPdQQGhqAFASBhOPgqCoqCGfrOx2C12i4tRGlgiaEb2O/Zrjsf2TItuPw7cRt5bZ7G+f9rWoh3sD/S3eY3+p4s4Bqa1Z6"
        "u5DV3+Z8qy/fDpStft+/wxzcCYA7eQNu86liGyKCOxC4nSUOtgFg68LEGwDBNvcHd+g+ZRuQ/olBFG/BMN6Jk290/k53pgZvcm27"
        "8zcC6U0XKN4iIeK7JFi8DULfyn3Bd3vfd9M2971q0gzeYYnZ9vjfqqWFKFLiK8EAAAAASUVORK5CYII="
    ),
    "Crown": (
        "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"
        "TkSuQmCC"
    ),
}


def main():
    parser = argparse.ArgumentParser(description="Albion Orders Total - v1.2.0")
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