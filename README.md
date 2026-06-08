# Mini ip Command Clone for Termux (Android 13+)

A lightweight, read-only implementation of the standard Linux ip utility (from the iproute2 suite), designed specifically for Termux on Android 13 and above.

Starting with Android 13, Google heavily restricted userland access to network information files (such as /proc/net/arp and /proc/net/route). This tool circumvents those user-space file restrictions by interacting directly with the Linux kernel via Netlink sockets to retrieve network interface information, IP addresses, routing tables, and neighbor (ARP/NDP) caches—all without requiring root access.

## Features

- **link**: View network interfaces and their operational states (UP, BROADCAST, LOOPBACK, etc.).
- **addr**: View IPv4 and IPv6 addresses assigned to interfaces.
- **route**: View the system's routing table (destinations, gateways, and output interfaces). Supports route lookup and filtering by table/protocol.
- **neigh**: View the neighbor table (ARP cache for IPv4, NDP for IPv6) and MAC addresses.
- **Color output**: Syntax-highlighted output with cyan (interface names), magenta (IP addresses), and green (MAC addresses). Enabled by default.
- **Address family filtering**: Global filtering for IPv4 (-4) and IPv6 (-6), as well as filtering output by a specific network device.
- **Route filtering**: Filter routes by table (e.g., local, main) and protocol (e.g., kernel, static).
- **Neighbor filtering**: Filter neighbors by address/prefix (e.g., 192.168.1.0/24) and NUD (Neighbor Unreachability Detection) states such as reachable, stale, etc.

## Building in Termux

This program relies entirely on standard C libraries and Linux kernel headers available in the Termux environment. No external libraries are required.

To compile the program inside Termux, first ensure you have a C compiler installed, then build it:

```
# Install clang if you haven't already
pkg update
pkg install clang

# Compile the source code
clang -O2 -Wall ip.c -o mini_ip
```

(Note: It is recommended to name the output binary something like mini_ip rather than ip to avoid conflicting with any existing packages.)

## Command-line Options

```
./mini_ip [-c | -nc] [-4 | -6] <object> show [dev]
```

- `-4`: Show only IPv4 addresses, routes, or neighbors.
- `-6`: Show only IPv6 addresses, routes, or neighbors.
- `-c, -color, --color`: Enable colored output (default).
- `-nc, --no-color`: Disable colored output.

### Objects and Examples

#### Link (Network Interfaces)

View all network interfaces visible to the Termux app sandbox.

```
./mini_ip link show
./mini_ip link show wlan0
./mini_ip -nc link show         # Disable colored output
```

#### Addr (IP Addresses)

View IP addresses configured on the device.

```
./mini_ip addr show
./mini_ip -4 addr show          # Show only IPv4 addresses
./mini_ip -6 addr show wlan0    # Show only IPv6 addresses on wlan0
```

#### Route (Routing Table)

View the Android routing table.

```
./mini_ip route show
./mini_ip -4 route show         # Show only IPv4 routes
./mini_ip -6 route show eth0    # Show only IPv6 routes on eth0
./mini_ip route show table local # Show local table
./mini_ip route get 8.8.8.8      # Look up route to 8.8.8.8
./mini_ip route get 8.8.8.8 from 192.168.1.10 # Look up route with source IP
```

#### Neigh (Neighbor / ARP Table)

View known network neighbors and their MAC addresses.

```
./mini_ip neigh show
./mini_ip neighbor show wlan0
./mini_ip -4 neigh show         # Show only IPv4 neighbors (ARP)
./mini_ip -6 -nc neigh show     # Show IPv6 neighbors without color
./mini_ip neigh show nud reachable  # Show only reachable neighbors
./mini_ip neigh show nud stale nud delay # Show stale or delay neighbors
./mini_ip neigh show 192.168.1.0/24     # Show neighbors in a specific subnet
./mini_ip neigh show to 10.0.0.1        # Show a specific neighbor
```

## Limitations

As a lightweight clone tailored for non-rooted Android environments, this tool has several limitations:

1. **Read-Only Operations**: This tool only implements show commands. It cannot be used to modify network state (add, del, set, flush, etc. are not supported and would be blocked by Android's permission model anyway).
2. **Android Sandbox Visibility**: While Netlink works around /proc/net/ restrictions, Android's SELinux policies and network namespaces mean you may only see interfaces, routes, and neighbors relevant to the Termux application's current network context.
3. **Hardcoded Limits**: 
   - Maximum number of network interfaces is capped at 256 (MAX_INTERFACES).
   - The Netlink receive buffer size is fixed at 32,768 bytes (BUF_SIZE).
4. **Simplified Output Format**: The output formatting is basic compared to the full ip command; lacks advanced features like JSON output (-j), statistics, and complex interface configurations.
5. **Limited Attributes**: It parses basic Netlink Routing Attributes (RTA) like RTA_DST, RTA_GATEWAY, and RTA_OIF, but ignores advanced routing metrics, interface statistics, and other complex attributes.
