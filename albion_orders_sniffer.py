import argparse
import json
import struct
import sys
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ---------------- Reglages ----------------
TAX_PERCENT = 4            # 4 % avec premium, 8 % sans
PRICE_DIVISOR = 10000      # le jeu stocke les prix x10000
PORT = 5056                # port du serveur de jeu Albion
CAPTURE_FILE = "albion_capture.jsonl"
MY_CODES = {92, 93, 94}    
BUY_CODES = {93}           
# ------------------------------------------

OP_NAMES = {
    81: "AuctionGetOffers (marché public)", 
    82: "AuctionGetRequests (marché public)",
    83: "AuctionBuyOffer", 
    92: "AuctionGetMyOpenOffers (MES ordres de vente)",
    93: "AuctionGetMyOpenRequests (MES ordres d'achat)", 
    94: "AuctionGetMyOpenAuctions"
}


# ======================= Decodeur Photon / Protocol18 =======================
class Buf:
    def __init__(self, data):
        self.d, self.p = data, 0

    def left(self):
        return len(self.d) - self.p

    def byte(self):
        if self.p >= len(self.d):
            raise EOFError
        b = self.d[self.p]
        self.p += 1
        return b

    def read(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise EOFError
        b = self.d[self.p:self.p + n]
        self.p += n
        return b


def uvarint(b, maxshift=35):
    value, shift = 0, 0
    while True:
        x = b.byte()
        value |= (x & 0x7F) << shift
        if not x & 0x80:
            return value
        shift += 7
        if shift >= maxshift:
            return 0


def zigzag(v):
    return (v >> 1) ^ -(v & 1)


def read_string(b):
    n = uvarint(b)
    if n <= 0 or n > b.left():
        return ""
    return b.read(n).decode("utf-8", "replace")


def read_custom(b, gp):
    slim = gp >= 0x80
    cid = (gp & 0x7F) if slim else b.byte()
    return custom_payload(b, cid, slim)


def custom_payload(b, cid, slim):
    size = uvarint(b)
    if size < 0 or size > b.left():
        if slim:
            return {"type": cid, "data": b.read(b.left())}
        return None
    return {"type": cid, "data": b.read(size)}


def read_dict(b):
    ktc, vtc = b.byte(), b.byte()
    count = uvarint(b)
    out = {}
    i = 0
    while i < count and b.left() > 0:
        kt = b.byte() if ktc == 0 else ktc
        vt = b.byte() if vtc == 0 else vtc
        k, v = deserialize(b, kt), deserialize(b, vt)
        try:
            out[k] = v
        except TypeError:
            out[f"UNHASHABLE_{i}"] = v
        i += 1
    return out


def read_param_table(b):
    count = uvarint(b)
    params = {}
    i = 0
    while i < count and b.left() > 0:
        key = b.byte()
        tc = b.byte()
        params[key] = deserialize(b, tc)
        i += 1
    return params


def read_typed_array(b, et):
    size = uvarint(b)
    if et == 2:
        packed = b.read((size + 7) // 8)
        return [bool(packed[i // 8] & (1 << (i % 8))) for i in range(size)]
    if et == 3:
        return b.read(size)
    if et == 4:
        return [struct.unpack("<h", b.read(2))[0] for _ in range(size)]
    if et == 5:
        return [struct.unpack("<f", b.read(4))[0] for _ in range(size)]
    if et == 6:
        return [struct.unpack("<d", b.read(8))[0] for _ in range(size)]
    if et == 7:
        return [read_string(b) for _ in range(size)]
    if et == 19:
        cid = b.byte()
        return [custom_payload(b, cid, False) for _ in range(size)]
    if et in (20, 21):
        return [read_dict(b) for _ in range(size)]
    if et == 9:
        return [zigzag(uvarint(b)) for _ in range(size)]
    if et == 10:
        return [zigzag(uvarint(b, 70)) for _ in range(size)]
    return [deserialize(b, et) for _ in range(size)]


def deserialize(b, tc):
    if tc >= 0x80:
        return read_custom(b, tc)
    if tc in (0, 8):
        return None
    if tc == 2:
        return b.byte() != 0
    if tc == 3:
        return b.byte()
    if tc == 4:
        return struct.unpack("<h", b.read(2))[0]
    if tc == 5:
        return struct.unpack("<f", b.read(4))[0]
    if tc == 6:
        return struct.unpack("<d", b.read(8))[0]
    if tc == 7:
        return read_string(b)
    if tc == 9:
        return zigzag(uvarint(b))
    if tc == 10:
        return zigzag(uvarint(b, 70))
    if tc == 11:
        return b.byte()
    if tc == 12:
        return -b.byte()
    if tc == 13:
        return struct.unpack("<H", b.read(2))[0]
    if tc == 14:
        return -struct.unpack("<H", b.read(2))[0]
    if tc == 15:
        return b.byte()
    if tc == 16:
        return -b.byte()
    if tc == 17:
        return struct.unpack("<H", b.read(2))[0]
    if tc == 18:
        return -struct.unpack("<H", b.read(2))[0]
    if tc == 19:
        return read_custom(b, 0)
    if tc in (20, 21):
        return read_dict(b)
    if tc == 23:
        n = uvarint(b)
        return [deserialize(b, b.byte()) for _ in range(n)]
    if tc == 24:
        op = b.byte()
        return {"operationCode": op, "parameters": read_param_table(b)}
    if tc == 25:
        if b.left() < 3:
            return None
        op = b.byte()
        rc = struct.unpack("<h", b.read(2))[0]
        dbg = ""
        if b.left() > 0:
            v = deserialize(b, b.byte())
            dbg = v if isinstance(v, str) else ""
        return {"operationCode": op, "returnCode": rc, "debugMessage": dbg, "parameters": read_param_table(b)}
    if tc == 26:
        code = b.byte()
        return {"code": code, "parameters": read_param_table(b)}
    if tc == 27:
        return False
    if tc == 28:
        return True
    if tc in (29, 30, 31):
        return 0
    if tc in (32, 33):
        return 0.0
    if tc == 34:
        return 0
    if tc == 0x40:
        n = uvarint(b)
        et = b.byte()
        return [deserialize(b, et) for _ in range(n)]
    if tc & 0x40:
        return read_typed_array(b, tc & ~0x40)
    return f"ERROR - unknown type 0x{tc:02X}"


class PhotonParser:
    def __init__(self, on_request, on_response, on_encrypted):
        self.on_request, self.on_response, self.on_encrypted = on_request, on_response, on_encrypted
        self.pending = {}

    def receive(self, payload):
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
        except Exception:
            return

    def _single(self, p, start):
        flags, count = p[start + 2], p[start + 3]
        off = start + 12
        if flags == 0xCC:
            off += 4
        for _ in range(count):
            off = self._command(p, off)
            if off is None:
                return None
        return off

    def _command(self, src, off):
        if len(src) - off < 12:
            return None
        ctype = src[off]
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
        if msg == 131:
            self.on_encrypted()
        elif msg == 2:
            self._request(data)
        elif msg in (3, 7):
            self._response(data)

    def _request(self, data):
        if not data:
            return
        try:
            params = read_param_table(Buf(data[1:]))
        except Exception:
            return
        self.on_request(data[0], params)

    def _response(self, data):
        if len(data) < 3:
            return
        opcode = data[0]
        rc = struct.unpack("<h", data[1:3])[0]
        b = Buf(data[3:])
        try:
            if b.left() > 0:
                v = deserialize(b, b.byte())
                if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                    self.on_response(opcode, rc, {0: v})   
                    return
            params = read_param_table(b)
        except Exception:
            return
        self.on_response(opcode, rc, params)

    def _fragment(self, body):
        if len(body) < 20:
            return
        start_seq, _cnt, _num, total, frag_off = struct.unpack(">IIIII", body[:20])
        chunk = body[20:]
        if total <= 0 or total > 8 << 20:
            return
        seg = self.pending.get(start_seq)
        if seg is None:
            if len(self.pending) >= 64:
                self.pending.pop(next(iter(self.pending)))
            seg = self.pending[start_seq] = {"total": total, "written": 0, "buf": bytearray(total)}
        if frag_off + len(chunk) <= len(seg["buf"]):
            seg["buf"][frag_off:frag_off + len(chunk)] = chunk
        seg["written"] += len(chunk)
        if seg["written"] >= seg["total"]:
            del self.pending[start_seq]
            self._reliable(bytes(seg["buf"]))


def normalize_op(code):
    if code in OP_NAMES:
        return code
    swapped = ((code << 8) & 0xFFFF) | (code >> 8)
    if swapped in OP_NAMES:
        return swapped
    if code > 0xFF and code & 0xFF == 0:
        return code >> 8
    return code


def fmt(n):
    return f"{int(n):,}".replace(",", " ")


# ======================= Application Graphique (Tkinter) =======================
class AlbionSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Albion Online - Sniffer d'Ordres")
        self.root.geometry("980x700")

        self.last_req = None
        self.sell = {}     
        self.buy = {}
        self.last_enc_warn = 0
        self.parser = PhotonParser(self.on_request, self.on_response, self.on_encrypted)

        # États de tri : col (None, "qty", "unit_price", "total_price"), phase (0: désactivé, 1: croissant, 2: décroissant)
        self.sort_states = {
            "sell": {"col": None, "phase": 0},
            "buy": {"col": None, "phase": 0}
        }

        self.create_widgets()
        threading.Thread(target=self.run_sniffer, daemon=True).start()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use("clam")

        top_frame = ttk.LabelFrame(self.root, text=" Synthèse Financière & Filtres ", padding=10)
        top_frame.pack(fill="x", padx=10, pady=10)

        self.lbl_sell_raw = ttk.Label(top_frame, text="Vente Brut : 0 silver", font=("Segoe UI", 10, "bold"))
        self.lbl_sell_raw.grid(row=0, column=0, sticky="w", padx=5, pady=2)

        self.lbl_sell_net = ttk.Label(top_frame, text=f"Vente Net (-{TAX_PERCENT}%) : 0 silver", font=("Segoe UI", 10, "bold"), foreground="green")
        self.lbl_sell_net.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        self.lbl_buy_total = ttk.Label(top_frame, text="Achats Total : 0 silver", font=("Segoe UI", 10, "bold"), foreground="blue")
        self.lbl_buy_total.grid(row=1, column=0, sticky="w", padx=5, pady=2)

        self.lbl_items_count = ttk.Label(top_frame, text="Articles comptés : 0", font=("Segoe UI", 10))
        self.lbl_items_count.grid(row=1, column=1, sticky="w", padx=5, pady=2)

        search_frame = ttk.Frame(top_frame)
        search_frame.grid(row=0, column=2, rowspan=2, padx=15, sticky="ew")
        
        ttk.Label(search_frame, text="🔍 Rechercher un item :", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=1)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.update_ui_displays())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=28)
        search_entry.pack(anchor="w", pady=2)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.grid(row=0, column=3, rowspan=2, padx=10, sticky="e")

        ttk.Button(btn_frame, text="🔄 Remettre à zéro", command=self.reset_data).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="💾 Exporter", command=self.export_details).pack(fill="x", pady=2)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree_sell = self.create_table(notebook, "Ordres de Vente", "sell")
        self.tree_buy = self.create_table(notebook, "Ordres d'Achat", "buy")

        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text=" 📜 Console / Logs ")
        self.log_txt = scrolledtext.ScrolledText(log_frame, wrap="word", font=("Consolas", 9), background="#1e1e1e", foreground="#dcdcdc")
        self.log_txt.pack(fill="both", expand=True, padx=5, pady=5)

        self.status_var = tk.StringVar(value="Statut : En attente du trafic réseau... Ouvre 'Mes ordres' en jeu.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status_bar.pack(fill="x", side="bottom")

    def create_table(self, notebook, title, table_type):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=f" {title} ")

        columns = ("item", "qty", "unit_price", "total_price")
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        
        # Nom de l'objet / ID : aucune flèche, non cliquable
        tree.heading("item", text="Nom de l'objet / ID")
        # Colonnes quantifères cliquables avec cycle de tri
        tree.heading("qty", text="Quantité", command=lambda: self.sort_table(table_type, "qty"))
        tree.heading("unit_price", text="Prix Unitaire (Silver)", command=lambda: self.sort_table(table_type, "unit_price"))
        tree.heading("total_price", text="Total (Silver)", command=lambda: self.sort_table(table_type, "total_price"))

        tree.column("item", width=360, anchor="w")
        tree.column("qty", width=110, anchor="center")
        tree.column("unit_price", width=170, anchor="e")
        tree.column("total_price", width=190, anchor="e")

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    def sort_table(self, table_type, col):
        state = self.sort_states[table_type]
        if state["col"] == col:
            state["phase"] = (state["phase"] + 1) % 3  # Passe de 0 -> 1 -> 2 -> 0
            if state["phase"] == 0:
                state["col"] = None
        else:
            state["col"] = col
            state["phase"] = 1  # Premier clic : Tri croissant (▲)

        tree = self.tree_sell if table_type == "sell" else self.tree_buy
        titles = {
            "qty": "Quantité",
            "unit_price": "Prix Unitaire (Silver)",
            "total_price": "Total (Silver)"
        }

        # Réinitialiser les en-têtes propres sans flèches superflues
        for c in titles:
            if c == state["col"] and state["phase"] > 0:
                arrow = " ▲" if state["phase"] == 1 else " ▼"
                tree.heading(c, text=titles[c] + arrow)
            else:
                tree.heading(c, text=titles[c])

        self.update_ui_displays()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"
        self.log_txt.insert(tk.END, formatted)
        self.log_txt.see(tk.END)

    def on_encrypted(self):
        if time.time() - self.last_enc_warn > 30:
            self.last_enc_warn = time.time()
            self.log("[!] Données chiffrées détectées : les ordres du marché ne sont pas lisibles.")

    def on_request(self, opcode, params):
        code = params.get(253, opcode)
        if not isinstance(code, int):
            code = opcode
        code = normalize_op(code)
        if code in OP_NAMES:
            self.last_req = code

    def on_response(self, opcode, rc, params):
        strings = params.get(0)
        if not (isinstance(strings, list) and strings and all(isinstance(s, str) for s in strings)):
            return
        orders = []
        for s in strings:
            try:
                orders.append(json.loads(s))
            except Exception:
                pass
        if not orders or "UnitPriceSilver" not in orders[0]:
            return
        label = self.last_req
        
        try:
            with open(CAPTURE_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": datetime.now().isoformat(), "last_request": label,
                                    "returnCode": rc, "orders": orders}, ensure_ascii=False) + "\n")
        except Exception:
            pass

        self.root.after(0, lambda: self.handle_orders(label, orders))

    def handle_orders(self, label, orders):
        name = OP_NAMES.get(label, f"requête inconnue ({label})")
        self.log(f"Réponse de {len(orders)} ordres reçue <- {name}")
        
        if label not in MY_CODES:
            self.log("      (ordres du marché public, ignorés)")
            return
            
        sells, buys = [], []
        for o in orders:
            t = str(o.get("AuctionType", "")).lower()
            if "request" in t:
                buys.append(o)
            elif "offer" in t:
                sells.append(o)
            elif label in BUY_CODES:
                buys.append(o)
            else:
                sells.append(o)

        if sells:
            self.add_orders_to_store(self.sell, sells, "VENTE")
        if buys:
            self.add_orders_to_store(self.buy, buys, "ACHAT")
            
        self.update_ui_displays()

    def add_orders_to_store(self, store, orders, kind):
        new = 0
        page_total = 0
        for o in orders:
            oid = o.get("Id")
            qty = int(o.get("Amount", 0))
            price = int(o.get("UnitPriceSilver", 0)) // PRICE_DIVISOR
            if oid not in store:
                new += 1
            store[oid] = (o.get("ItemTypeId", "?"), qty, price)
            page_total += qty * price

        if new == 0:
            self.log(f"      {kind} : page déjà comptée, ignorée.")
            return
            
        self.log(f"      {kind} : {len(orders)} ordres dans cette page ({new} nouveaux) = {fmt(page_total)} silver")

    def populate_tree(self, tree, store_values, table_type):
        for row in tree.get_children():
            tree.delete(row)

        query = self.search_var.get().strip().lower()

        filtered = []
        for item, qty, price in store_values:
            subtotal = qty * price
            if query in item.lower():
                filtered.append((item, qty, price, subtotal))

        state = self.sort_states[table_type]
        col = state["col"]
        phase = state["phase"]

        if col and phase > 0:
            # phase == 1 : croissant (False), phase == 2 : décroissant (True)
            reverse = (phase == 2)
            if col == "qty":
                filtered.sort(key=lambda x: x[1], reverse=reverse)
            elif col == "unit_price":
                filtered.sort(key=lambda x: x[2], reverse=reverse)
            elif col == "total_price":
                filtered.sort(key=lambda x: x[3], reverse=reverse)
        else:
            # Tri par défaut (du plus gros total au plus petit) sans aucun tri actif
            filtered.sort(key=lambda x: x[3], reverse=True)

        for item, qty, price, subtotal in filtered:
            tree.insert("", tk.END, values=(item, fmt(qty), fmt(price), fmt(subtotal)))

    def update_ui_displays(self):
        self.populate_tree(self.tree_sell, self.sell.values(), "sell")
        self.populate_tree(self.tree_buy, self.buy.values(), "buy")

        total_sell = sum(q * p for _, q, p in self.sell.values())
        total_sell_items = sum(q for _, q, _ in self.sell.values())
        
        total_buy = sum(q * p for _, q, p in self.buy.values())
        total_buy_items = sum(q for _, q, _ in self.buy.values())

        net_sell = total_sell * (1 - TAX_PERCENT / 100)
        total_items = total_sell_items + total_buy_items

        self.lbl_sell_raw.config(text=f"Vente Brut : {fmt(total_sell)} silver")
        self.lbl_sell_net.config(text=f"Vente Net (-{TAX_PERCENT}%) : {fmt(net_sell)} silver")
        self.lbl_buy_total.config(text=f"Achats Total : {fmt(total_buy)} silver")
        self.lbl_items_count.config(text=f"Articles comptés : {fmt(total_items)}")
        
        self.status_var.set(f"Statut : Actif | {len(self.sell)} ordres de vente, {len(self.buy)} ordres d'achat.")

    def reset_data(self):
        if messagebox.askyesno("Remise à zéro", "Es-tu sûr de vouloir effacer tous les totaux ?"):
            self.sell.clear()
            self.buy.clear()
            self.update_ui_displays()
            self.log("Totaux remis à zéro.")

    def export_details(self):
        try:
            filename = f"albion_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=== RAPPORT DES ORDRES ALBION ONLINE ===\n\n")
                f.write("--- VENTES ---\n")
                for item, qty, price in self.sell.values():
                    f.write(f"{item} | {qty} x {price} = {qty*price}\n")
                f.write("\n--- ACHATS ---\n")
                for item, qty, price in self.buy.values():
                    f.write(f"{item} | {qty} x {price} = {qty*price}\n")
            messagebox.showinfo("Export réussi", f"Données exportées avec succès dans :\n{filename}")
            self.log(f"Export réussi : {filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export : {e}")

    def handle_packet(self, pkt):
        from scapy.all import UDP, TCP, Raw
        layer = pkt[UDP] if UDP in pkt else (pkt[TCP] if TCP in pkt else None)
        if layer is None or Raw not in pkt:
            return
        self.parser.receive(bytes(pkt[Raw].load))

    def run_sniffer(self):
        try:
            from scapy.all import sniff, conf
        except ImportError:
            self.root.after(0, lambda: messagebox.showerror("Erreur", "Scapy n'est pas installé : pip install scapy"))
            return

        conf.use_pcap = True
        try:
            open(CAPTURE_FILE, "w", encoding="utf-8").close()
        except Exception:
            pass

        self.log("Écoute réseau automatique démarrée... Ouvre le marché en jeu > 'Mes ordres'.")
        kwargs = {"filter": f"udp port {PORT} or tcp port {PORT}", "prn": self.handle_packet, "store": False}

        try:
            sniff(**kwargs)
        except Exception as e:
            err_msg = f"Impossible d'écouter le réseau : {e}\nVérifie que Npcap est bien installé et que l'app est lancée en Administrateur."
            self.root.after(0, lambda: messagebox.showerror("Erreur Réseau", err_msg))
            self.log(f"[ERREUR] {err_msg}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="liste les interfaces réseau")
    args = ap.parse_args()

    if args.list:
        from scapy.all import conf
        conf.use_pcap = True
        print(conf.ifaces)
        sys.exit(0)

    root = tk.Tk()
    app = AlbionSnifferGUI(root)
    root.mainloop()