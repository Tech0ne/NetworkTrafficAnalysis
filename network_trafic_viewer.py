import matplotlib.pyplot as plt
import pyshark
import netifaces
import sys

import matplotlib as mpl
mpl.rcParams['toolbar'] = 'None'


if len(sys.argv) != 2:
    print("Please provide a network interface !")
    sys.exit(1)
if not sys.argv[1] in netifaces.interfaces():
    print(f"Could not find interface {sys.argv[1]} !")
    sys.exit(1)

def is_in_local_network(ip: str):
    netmask = netifaces.ifaddresses(sys.argv[1])[netifaces.AF_INET][0]['netmask'].split('.')
    base_ip = netifaces.ifaddresses(sys.argv[1])[netifaces.AF_INET][0]['addr'].split('.')
    for i in range(len(ip.split('.'))):
        if (int(netmask[i]) != 0) and (ip.split('.')[i] != base_ip[i]):
            return False
    return True


ips_in  = {}
ips_out = {}

def add_one(ip: str, is_in: bool):
    global ips_in, ips_out
    ip = str(ip)
    if is_in:
        if not ip in ips_in.keys():
            ips_in[ip] = 0
        ips_in[ip] += 1
    else:
        if not ip in ips_out.keys():
            ips_out[ip] = 0
        ips_out[ip] += 1

fig, axs = plt.subplots(2, 3)
fig.canvas.toolbar_visible = False

try:
    capture = pyshark.LiveCapture(interface=sys.argv[1])
    capture.sniff(timeout=2)
except PermissionError:
    print("I dont have the rights !")
    print("Make sure to run as root !")
    sys.exit(1)

for pkt in capture:
    if not "IP" in pkt:
        continue
    ip_out = pkt.ip.dst
    ip_in  = pkt.ip.src
    if is_in_local_network(ip_out):
        add_one(ip_out, False)
    if is_in_local_network(ip_in):
        add_one(ip_in, True)

    labels = [str(x) for x in ips_in.keys()]
    sizes = [int(x) for x in ips_in.values()]
    explode = []
    for _ in range(len(sizes)):
        explode.append(0.05)

    axs[0, 0].clear()
    axs[0, 0].set_title("Output traffic")
    axs[0, 0].pie(sizes, explode=explode, labels=labels, autopct='%1.1f %%', shadow=True)

    axs[1, 0].clear()
    axs[1, 0].bar(labels, sizes)

    labels = [str(x) for x in ips_out.keys()]
    sizes = [int(x) for x in ips_out.values()]
    explode = []
    for _ in range(len(sizes)):
        explode.append(0.05)

    axs[0, 1].clear()
    axs[0, 1].set_title("Input traffic")
    axs[0, 1].pie(sizes, explode=explode, labels=labels, autopct='%1.1f %%', shadow=True)

    axs[1, 1].clear()
    axs[1, 1].bar(labels, sizes)

    joined = {}
    for k, v in ips_in.items():
        joined[k] = v
    for k, v in ips_out.items():
        if not k in joined.keys():
            joined[k] = 0
        joined[k] += v
        
    labels = [str(x) for x in joined.keys()]
    sizes = [int(x) for x in joined.values()]
    explode = []
    for _ in range(len(sizes)):
        explode.append(0.05)
        
    axs[0, 2].clear()
    axs[0, 2].set_title("Total traffic")
    axs[0, 2].pie(sizes, explode=explode, labels=labels, autopct='%1.1f %%', shadow=True)

    axs[1, 2].clear()
    axs[1, 2].bar(labels, sizes)
    plt.pause(0.05)
    if not len(plt.get_fignums()):
        break
