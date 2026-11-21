# AO_SellOrdersTraker

`AO_SellOrdersTraker` is a Windows desktop utility for tracking Albion Online
market orders. It passively captures the game's market traffic, decodes the
Photon payloads used for open orders, and displays sell orders, buy orders,
gross value, estimated tax, and net value in a graphical interface.

The application does not send requests to the game and does not modify game
files or memory.

## Running the application

### Windows executable

The easiest way to use the application is to run `AO_SellOrderTracker.exe`.
If capture does not start, right-click it and select **Run as administrator**.
The executable includes the Python runtime and application dependencies; Npcap
is still required for live capture.

## Requirements

- Windows
- [Npcap](https://npcap.com/#download), installed with WinPcap API-compatible
  mode enabled
- Administrator privileges when packet capture requires them

### Python source

To run the source code instead, first install the dependencies:

```powershell
python -m pip install scapy customtkinter pillow
```

Available options:

```text
--demo             Show fictional orders without capturing traffic
--list             List available Scapy network interfaces and exit
--iface NAME       Capture from a specific network interface
```

Examples:

```powershell
python albion_orders_total.py
python albion_orders_total.py --demo
python albion_orders_total.py --list
python albion_orders_total.py --iface "INTERFACE NAME"
```

## Using the application

1. Start the application and **pick the city (market) you are in**.
2. Start or switch to the Albion Online marketplace.
3. Open **My Orders** and browse every page of your sell and buy orders.
4. The captured orders appear in the **Sell Orders** and **Buy Orders** views.

The interface supports:

- Search by item name.
- Sorting by item, quantity, unit price, total price, or share.
- Configurable sales-tax presets.
- An **All Markets** summary.
- CSV (Excel-compatible) and text exports.

### Tracking multiple markets

**Reset** deletes all saved markets and the current market after confirmation,
then asks for your city again. Saved markets exist only in memory, so export
them before closing the application if you need to keep the data.

Only orders observed since the last reset or market transition are counted.
This is not an automatic inventory: orders that disappear from the game are
not removed unless the current market is cleared.

## Building an executable

Install PyInstaller and run:

```powershell
python -m PyInstaller --noconfirm --noconsole --onefile --windowed --collect-all customtkinter albion_orders_total.py
```

The generated executable is placed in `dist\`.

## Technical notes

- Live capture filters UDP and TCP traffic on port `5056`.
- Open-order operation codes `92`, `93`, and `94` are used for personal
  orders.
- Duplicate observations are consolidated by order ID.
- The Photon/protocol operation numbers and tax presets are retained from the
  supplied implementation and are not independently verified against every
  current Albion Online version.
- Encrypted market responses cannot be decoded by the application.

## Project files

| File | Purpose |
| --- | --- |
| `albion_orders_total.py` | Photon decoder, packet capture, GUI, market state, and export logic |
| `AO_SellOrderTracker.exe` | Packaged Windows executable |
| `README.md` | Project documentation |
