import socket
import struct
import time
import sys
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_PORT = 33434
MAX_HOPS = 30
TIMEOUT = 2.0
PROBES_PER_HOP = 3
PACKET_SIZE = 52

# ============================================================================
# ICMP CONSTANTS
# ============================================================================
IP_RECVERR = 11
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REPLY = 0

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def resolve_hostname(ip_address):
    """Resolve IP to hostname."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return ip_address

# ============================================================================
# TRACEROUTE USING IP_RECVERR (NO ROOT REQUIRED - LINUX ONLY)
# ============================================================================

class TracerouteNoRoot:
    """
    Traceroute implementation using UDP with IP_RECVERR socket option.
    
    Advantages:
    - No root privileges required
    - Receives ICMP errors via socket error queue
    - Works on Linux (IP_RECVERR is Linux-specific)
    
    How it works:
    1. Create UDP socket
    2. Set IP_RECVERR socket option
    3. Send UDP packets with incrementing TTL
    4. Receive ICMP errors via recvmsg() with MSG_ERRQUEUE
    """
    
    def __init__(self, destination, max_hops=MAX_HOPS, timeout=TIMEOUT,
                 probes_per_hop=PROBES_PER_HOP, start_port=DEFAULT_PORT,
                 resolve_hostnames=True):
        self.destination = destination
        self.max_hops = max_hops
        self.timeout = timeout
        self.probes_per_hop = probes_per_hop
        self.start_port = start_port
        self.current_port = start_port
        self.resolve_hostnames = resolve_hostnames
        
        # Resolve destination
        try:
            self.dest_ip = socket.gethostbyname(destination)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {destination}")
        
        # Check if running on Linux
        if sys.platform != 'linux':
            print("Warning: IP_RECVERR is Linux-specific. This may not work on other platforms.")
        
        print(f"Traceroute to {destination} ({self.dest_ip}), {max_hops} hops max")
        print("Using UDP with IP_RECVERR (no root required)")
        print()
    
    def send_probe(self, ttl):
        """
        Send a single UDP probe and receive ICMP error via IP_RECVERR.
        
        Args:
            ttl: Time To Live value
        
        Returns:
            tuple: (rtt, src_ip, icmp_type, icmp_code) or (None, None, None, None)
        """
        # Create UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        try:
            #################################################################################################
            # Set necessary socket options:
            # 1) Limit the number of hops this packet traverses using the passed ttl
            # 2) Enable extended reliable error message passing using IP_RECVERR to receive ICMP errors
            #################################################################################################
            try:
                # Set the TTL for outgoing packets
                udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            except Exception:
                # Fallback to SOL_IP if IPPROTO_IP constant differs
                udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            try:
                # Enable receiving extended error information (IP_RECVERR)
                udp_socket.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            except Exception:
                udp_socket.setsockopt(socket.SOL_IP, IP_RECVERR, 1)

            # Set timeout
            udp_socket.settimeout(self.timeout)
            
            # Bind to a local port (optional but helps with identification)
            udp_socket.bind(('', 0))
            local_port = udp_socket.getsockname()[1]
            
            # Create payload with timestamp
            payload = struct.pack('!d', time.time()) + b'TRACE' * 10
            
            # Send UDP packet to high port (unlikely to be open)
            self.current_port += 1
            dest_port = self.current_port
            
            send_time = time.time()
            udp_socket.sendto(payload, (self.dest_ip, dest_port))
            
            # Try to receive ICMP error from error queue
            try:
                # Use recvmsg to access ancillary data (error queue)
                # MSG_ERRQUEUE = 0x2000
                MSG_ERRQUEUE = 0x2000
                
                # Receive from error queue
                data, ancdata, msg_flags, addr = udp_socket.recvmsg(1024, 1024, MSG_ERRQUEUE)
                recv_time = time.time()
                rtt = (recv_time - send_time) * 1000
                
                # Parse ancillary data to extract ICMP error info
                icmp_type = None
                icmp_code = None
                error_addr = None
                
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    # IP_RECVERR provides sock_extended_err structure and optional sockaddr
                    if (cmsg_level == socket.IPPROTO_IP or cmsg_level == socket.SOL_IP) and cmsg_type == IP_RECVERR:
                        # Parse sock_extended_err (16 bytes):
                        # __u32 ee_errno; __u8 ee_origin; __u8 ee_type; __u8 ee_code; __u8 ee_pad; __u32 ee_info; __u32 ee_data;
                        try:
                            ee_errno, ee_origin, ee_type, ee_code, ee_pad, ee_info, ee_data = struct.unpack('=I4BII', cmsg_data[:16])
                            icmp_type = ee_type
                            icmp_code = ee_code

                            # If sockaddr_in follows the extended error struct, extract IPv4
                            if len(cmsg_data) >= 16 + 16:
                                sockaddr = cmsg_data[16:16+16]
                                try:
                                    fam, port, raw_addr = struct.unpack('!HH4s8x', sockaddr)
                                    error_addr = socket.inet_ntoa(raw_addr)
                                except Exception:
                                    # best-effort: try to take 4 bytes from common offset
                                    try:
                                        raw_addr = cmsg_data[20:24]
                                        error_addr = socket.inet_ntoa(raw_addr)
                                    except Exception:
                                        error_addr = None
                        except Exception:
                            # ignore parse errors
                            pass

                # If we didn't get address from ancdata, try from addr parameter
                if error_addr is None and addr:
                    error_addr = addr[0] if addr else None
                
                udp_socket.close()
                return (rtt, error_addr, icmp_type, icmp_code)
            
            except socket.timeout:
                # No response within timeout
                udp_socket.close()
                return (None, None, None, None)
            
        except Exception as e:
            print(f"Error in send_probe: {e}")
            import traceback
            traceback.print_exc()
            udp_socket.close()
            return (None, None, None, None)
    
    def probe_hop(self, ttl):
        """
        Probe a single hop with multiple probes.
        
        Args:
            ttl: Time To Live value
        
        Returns:
            dict: Hop information
        """
        results = []
        ip_addresses = set()
        
        for i in range(self.probes_per_hop):
            rtt, src_ip, icmp_type, icmp_code = self.send_probe(ttl)
            
            if src_ip:
                ip_addresses.add(src_ip)
                results.append({
                    'rtt': rtt,
                    'ip': src_ip,
                    'type': icmp_type,
                    'code': icmp_code
                })
            else:
                results.append({
                    'rtt': None,
                    'ip': None,
                    'type': None,
                    'code': None
                })
        
        return {
            'ttl': ttl,
            'probes': results,
            'ips': list(ip_addresses)
        }
    
    def format_hop_output(self, hop_info):
        """Format hop information for display."""
        ttl = hop_info['ttl']
        ips = hop_info['ips']
        probes = hop_info['probes']
        
        output = f"{ttl:2d}  "
        
        if not ips:
            output += "* * *"
            return output
        
        # Display IP addresses and hostnames
        for ip in ips:
            if self.resolve_hostnames:
                hostname = resolve_hostname(ip)
                if hostname != ip:
                    output += f"{hostname} ({ip})  "
                else:
                    output += f"{ip}  "
            else:
                output += f"{ip}  "
        
        # Display RTT for each probe
        for probe in probes:
            if probe['rtt'] is not None:
                output += f"{probe['rtt']:.3f} ms  "
            else:
                output += "*  "
        
        return output.rstrip()
    
    def run(self):
        """Run the complete traceroute."""
        reached_destination = False
        
        #########################################################################################################
        # Probe hops from 1..max_hops and print formatted output. Stop when destination is reached (port unreachable)
        #########################################################################################################
        for ttl in range(1, self.max_hops + 1):
            hop_info = self.probe_hop(ttl)
            print(self.format_hop_output(hop_info))

            # Inspect probes for destination unreachable (ICMP_DEST_UNREACHABLE) with code 3 (port unreachable)
            for probe in hop_info['probes']:
                if probe['ip'] is None:
                    continue
                if probe['type'] == ICMP_DEST_UNREACHABLE and probe['code'] == 3:
                    # If the IP that sent the ICMP message matches the destination, we've reached it
                    if probe['ip'] == self.dest_ip or probe['ip'] == self.destination:
                        reached_destination = True
                        break

            if reached_destination:
                print("\nReached destination.")
                break

        if not reached_destination:
            print(f"\nDestination not reached within {self.max_hops} hops")


def main():
    trace = TracerouteNoRoot('www.princeton.edu')
    trace.run()

if __name__ == "__main__":
    main()
