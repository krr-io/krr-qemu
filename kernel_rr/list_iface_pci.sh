for iface in $(ls /sys/class/net/); do     echo "$iface: $(readlink /sys/class/net/$iface/device)"; done
