from bcc import BPF
import pyroute2
import time
import sys




b = BPF("xdp_drop_count.c")

device = sys.argv[1]
b.attach_xdp(device, fn = b.load_func("xdp_drop_icmp", BPF.XDP))
dropcnt = b.get_table("dropcnt")
while True:
  try:
    dropcnt.clear()
    time.sleep(5)
    for k, v in dropcnt.items():
      print("{} {}: {} pkt/s".format(time.strftime("%H:%M:%S"), k.value, v.value))
  except KeyboardInterrupt:
    break

b.remove_xdp(device)