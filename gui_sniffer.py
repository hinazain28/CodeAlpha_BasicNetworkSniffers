import tkinter as tk
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import threading

# Global flag to stop sniffing
stop_sniffing = False

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        log.insert(tk.END, f"Source: {ip_layer.src} → Dest: {ip_layer.dst}\n")
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            log.insert(tk.END, f"  TCP Port: {tcp.sport} → {tcp.dport}\n")
        log.insert(tk.END, "-" * 40 + "\n")
        log.see(tk.END)

def sniff_packets():
    sniff(prn=process_packet, store=False, filter="ip", stop_filter=should_stop)

def should_stop(packet):
    return stop_sniffing  # Stop sniffing if flag is set

def start_sniffing():
    global stop_sniffing
    stop_sniffing = False
    log.insert(tk.END, "Sniffing started...\n\n")
    t = threading.Thread(target=sniff_packets)
    t.daemon = True
    t.start()

def stop_sniffing_action():
    global stop_sniffing
    stop_sniffing = True
    log.insert(tk.END, "\nSniffing stopped by user.\n")
    log.insert(tk.END, "=" * 40 + "\n\n")

# GUI setup
root = tk.Tk()
root.title("Basic Network Sniffer")
root.geometry("700x450")

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=20)
start_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing_action, bg="red", fg="white", width=20)
stop_button.pack(pady=5)

log = tk.Text(root, height=20, width=85, bg="black", fg="lime")
log.pack()

root.mainloop()
