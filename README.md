# AO_SellOrdersTraker

## Description

`AO_SellOrdersTraker` is a network analysis tool designed for **Albion Online**. It intercepts and decodes network traffic in real-time to capture, aggregate, and display personal market orders (sell offers and buy requests) directly through a graphical interface.

The application captures UDP and TCP packets on the game's server port, parses the Photon protocol payload structure, extracts order metadata (such as item IDs, quantities, and unit prices), and calculates financial metrics including net values after market taxes.

## Instructions

### Prerequisites

The tool relies on raw packet capture via Scapy. To run successfully, ensure the following environment requirements are met:

1. **Npcap Installation**: Windows users must install **[Npcap](https://npcap.com/)** and ensure the option *"Support WinPcap API-compatible mode"* is checked during installation.
2. **Administrator Privileges**: Packet sniffing requires elevated privileges. Both the Python script and the executable must be run as Administrator.

### Compilation / Execution

You can run the project either via its Python source code or the standalone Windows executable.

#### Option A: Running the Python Script

Ensure Python is installed along with the required dependency (`scapy`):

```sh
pip install scapy

```

Run the script with administrator privileges:

```sh
python albion_orders_sniffer.py

```

To list available network interfaces for debugging or advanced configuration:

```sh
python albion_orders_sniffer.py --list

```

#### Option B: Running the Executable

1. Locate `albion_orders_sniffer.exe`.
2. Right-click and select **Run as administrator**.

## Usage

Once launched, the application initiates a background sniffing thread listening on port `5056` (Albion Online server port).

1. Launch **Albion Online**.
2. Open the in-game marketplace and navigate to the **"My Orders"** tab.
3. The captured packets will automatically populate the respective tables for **Sell Orders** and **Buy Orders** in the graphical interface.

### Interface Features

* **Financial Synthesis**: Real-time tracking of raw sales, net sales (factoring in customizable tax rates, default 4%), total purchase value, and total tracked item counts.
* **Dynamic Search**: Instant filtering of items by name using the search input field.
* **Column Sorting**: Clickable table headers (`Quantity`, `Unit Price`, `Total`) supporting multi-phase sorting cycles (ascending, descending, and default).
* **Data Export & Reset**: Export current order data into a structured timestamped text report or reset stored states on demand.

## Algorithm & Implementation Details

The core architecture consists of three main modules:

1. **Packet Capture & Filtering (`Scapy`)**:
Listens to network traffic matching the game port (`udp port 5056 or tcp port 5056`), extracting raw payload buffers from packets.
2. **Photon Protocol Parser (`PhotonParser`)**:
* Iterates through command blocks, handles reliable messaging, and reconstructs fragmented packets via a sequence-tracking buffer dictionary (`pending`).
* Recursively deserializes parameter tables, custom payloads, and custom types using variable-length integers (`uvarint`) and zigzag decoding.


3. **GUI & State Management (`Tkinter`)**:
* Filters incoming responses against target operation codes (`MY_CODES = {92, 93, 94}`) corresponding to user open orders.
* Maintains an in-memory dictionary store (`sell`, `buy`) keyed by unique order IDs (`Id`) to prevent duplicate counting across page refreshes.



## Project structure

| File | Purpose |
| --- | --- |
| `albion_orders_sniffer.py` | Core implementation including Photon protocol decoder, Scapy sniffer thread, and Tkinter GUI. |
| `albion_orders_sniffer.exe` | Compiled standalone Windows executable. |
| `README.md` | Project documentation and instructions. |

## Constraints

* Written in Python and designed to operate on Windows environments with Npcap support.
* Requires administrator permissions for raw socket packet capturing.
* Operates passively by listening to local network traffic without modifying game memory or files.

## Resources

* Official **Scapy** documentation for packet manipulation and sniffing.
* **Npcap** packet capture library for Windows.
* Albion Online network protocol and Photon server architecture specs.
