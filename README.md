# Network Trafic Viewer

---

This Python script let you visualise your network trafic usage, seeing which IP uses the most data.

Knowing that, you can (if you are evil ;-) ) kick peoples that uses too much data !

---

## Usage

Install requirements :

    tshark

using your package manager (for example `apt-get`)

Then, use pip3 to install the requirements :

    pip3 install -r requirements.txt

When you installed everything, you are ready to run the script :

    sudo python3 network_trafic_viewer.py iface

by replacing iface by your network interface. (using sudo because network capture require root rights)

---

Enjoy and stay legal ;-)