# Copyright (c) 2024 Horia-Valentin MOROIANU

#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, \
    get_interface_name

BPDU_DEST_MAC = b'\x01\x80\xC2\x00\x00\x00'

# DST_MAC|SRC_MAC|LLC_LENGTH|LLC_HEADER|BPDU_HEADER|BPDU_CONFIG
BPDU_FORMAT = '!6s 6s H 3s I B 8s I 8s H H H H H'

# DSAP|SSAP|Control
LLC_HEADER = b'\x42\x42\x03'

# Port states
BLOCKED_PORT = 0
DESIGNATED_PORT = 1

# Global var
own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
port_states = {}
lock = threading.Lock()

def create_bpdu(port_id):
    return struct.pack(
        BPDU_FORMAT,
        BPDU_DEST_MAC,
        get_switch_mac(),
        38,                 # 38 bytes long fixed payload
        LLC_HEADER,
        0,                  # Protocol ID|Protocol version ID|BPDU type
        0,                  # Flags
        root_bridge_id.to_bytes(8, byteorder='big'),
        root_path_cost,
        own_bridge_id.to_bytes(8, byteorder='big'),
        port_id,
        1,                  # Message age
        20,                 # Max age
        2,                  # Hello time
        15                  # Forward delay                 
    )

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

def send_bdpu_every_sec(trunk_ports):
    while True:
        lock.acquire()
        if root_bridge_id == own_bridge_id:
            for p in trunk_ports:
                if port_states[p] == DESIGNATED_PORT:
                    data = create_bpdu(p)
                    send_to_link(p, len(data), data)
        lock.release()
        time.sleep(1)

def handle_bpdu(data, interface, trunk_ports, root_port):
    bpdu = struct.unpack(BPDU_FORMAT, data)
    bpdu_root_id = int.from_bytes(bpdu[6], byteorder='big')
    sender_path_cost = bpdu[7]
    sender_bridge_id = int.from_bytes(bpdu[8], byteorder='big')

    global root_bridge_id
    global root_path_cost
    were_root_bridge = (root_bridge_id == own_bridge_id)

    if bpdu_root_id < root_bridge_id:
        # Update the root bridge
        lock.acquire()

        root_bridge_id = bpdu_root_id
        root_path_cost = sender_path_cost + 10
        root_port = interface

        if were_root_bridge:
            port_states.update({p: BLOCKED_PORT for p in trunk_ports if p != root_port})
        
        if port_states[root_port] == BLOCKED_PORT:
            port_states[root_port] = DESIGNATED_PORT
        
        lock.release()
    elif bpdu_root_id == root_bridge_id:
        if interface == root_port and sender_path_cost + 10 < root_path_cost:
            lock.acquire()
            root_path_cost = sender_path_cost + 10
            lock.release()
        
        elif interface != root_port:
            if sender_path_cost > root_path_cost:
                lock.acquire()
                port_states[interface] = DESIGNATED_PORT
                lock.release()
    elif sender_bridge_id == own_bridge_id:
        lock.acquire()
        port_states[interface] = BLOCKED_PORT
        lock.release()
    
    if root_bridge_id == own_bridge_id:
        lock.acquire()
        for p in trunk_ports:
            port_states[p] = DESIGNATED_PORT
        lock.release()

    return root_port
        

def read_config(switch_id):
    port_table = {}
    try:
        with open(f'configs/switch{switch_id}.cfg', 'rt') as config:
            switch_priority = int(config.readline())
            for line in config:
                key, value = line.split()
                port_table[key] = value if value == 'T' else int(value)
            
            return switch_priority, port_table
    except ValueError:
        sys.exit('Invalid port configuration values!')
    except:
        sys.exit('Port configuration failed!')

def send_with_vlan(port_table, src_interface, dest_interface, frame_info):
    # Exit if the port is blocked
    if port_states[dest_interface] == BLOCKED_PORT:
        return

    # Extract frame data
    data, length, vlan_id = frame_info
    has_vlan_tag = (vlan_id != -1)

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
    # Switch initialization
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    switch_priority, port_table = read_config(switch_id)

    # Consider this device as root bridge
    global own_bridge_id
    global root_bridge_id

    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_port = -1

    trunk_ports = []
    # Set all ports as designated and store trunk ports
    for i in interfaces:
        port_states[i] = DESIGNATED_PORT
        if port_table[get_interface_name(i)] == 'T':
            trunk_ports.append(i)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(trunk_ports, ))
    t.start()

    mac_table = {}

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, _, vlan_id = parse_ethernet_header(data)
        
        # Remember port-mac link
        mac_table[src_mac] = interface

        # Check for BPDU
        if dest_mac == BPDU_DEST_MAC:
            root_port = handle_bpdu(data, interface, trunk_ports, root_port)
            continue

        # Drop if received on a blocked port
        if port_states[interface] == BLOCKED_PORT:
            continue

        frame_info = data, length, vlan_id
        dest_interface = mac_table.get(dest_mac)

        # Check if unicast and found in mac address table
        if (dest_mac[0] & 1) == 0 and dest_interface is not None:
            send_with_vlan(port_table, interface, dest_interface, frame_info)
        else:
            # Broadcast
            for i in interfaces:
                if i != interface:
                    send_with_vlan(port_table, interface, i, frame_info)

if __name__ == "__main__":
    main()
