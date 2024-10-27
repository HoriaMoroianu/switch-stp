#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

def read_config(switch_id):
    port_table = {}
    try:
        with open(f'configs/switch{switch_id}.cfg', 'rt') as config:
            switch_bid = int(config.readline())
            for line in config:
                key, value = line.split()
                port_table[key] = value if value == 'T' else int(value)
            
            return switch_bid, port_table
    except ValueError:
        sys.exit('Invalid port configuration values!')
    except:
        sys.exit('Port configuration failed!')

def send_with_vlan(port_table, src_interface, dest_interface, frame_info):
    # Extract frame data
    data, length, vlan_id = frame_info
    has_vlan_tag = vlan_id != -1

    # Get VLAN ids
    dest_vlan = port_table.get(get_interface_name(dest_interface))
    src_vlan = port_table.get(get_interface_name(src_interface))
    vlan_id = src_vlan if not has_vlan_tag else vlan_id

    # Exit if VLAN ids are not found
    if dest_vlan is None or src_vlan is None:
        return

    if dest_vlan == 'T':
        # Send to trunk port
        if not has_vlan_tag:
            data = data[0:12] + create_vlan_tag(src_vlan) + data[12:]
            length += 4
        send_to_link(dest_interface, length, data)

    elif dest_vlan == vlan_id:
        # Send to access port
        if has_vlan_tag:
            data = data[0:12] + data[16:]
            length -= 4
        send_to_link(dest_interface, length, data)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_bid, port_table = read_config(switch_id)
    mac_table = {}

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()    

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        mac_table[src_mac] = interface
        frame_info = data, length, vlan_id

        if (dest_mac[0] & 1) == 0 and dest_mac in mac_table:
            send_with_vlan(port_table, interface, mac_table[dest_mac], frame_info)
        else:
            for i in interfaces:
                if i != interface:
                    send_with_vlan(port_table, interface, i, frame_info)

        # TODO: Implement STP support

if __name__ == "__main__":
    main()
