import socket
import struct
import random
import json

# Load root servers from file
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
]

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 0,      # recursion NOT desired (important for iterative!)
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # A record (not NS)
            "qclass": 1   # IN
        }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

#your parse_rr from part2
def parse_rr(data, offset):
    """Parse a single resource record and return record + new offset."""
    name, offset = parse_name(data, offset)
    atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata = data[offset:offset+rdlength]
    offset += rdlength
    
    record = {
        "hostname": name,
        "ttl": ttl,
        "atype": atype,
        "rtype": "",
        "ip": "",
        "nsname": ""
    }
    
    if atype == 1 and rdlength == 4:  # A record (IPv4)
        ip_bytes = struct.unpack("!BBBB", rdata)
        record["rtype"] = "A"
        record["ip"] = ".".join(str(byte) for byte in ip_bytes)
        
    elif atype == 28 and rdlength == 16:  # AAAA record (IPv6)
        ip_parts = struct.unpack("!HHHHHHHH", rdata)
        record["rtype"] = "AAAA"
        record["ip"] = ":".join(f"{part:x}" for part in ip_parts)
        
    elif atype == 2:  # NS record
        # For NS records, rdata contains a domain name
        ns_name, _ = parse_name(data, offset - rdlength)
        record["rtype"] = "NS"
        record["nsname"] = ns_name

    return record, offset

def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse Answer RRs
    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)
        
    # Parse Authority RRs (NS)
    authorities = []
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)
        
    # Parse Additional RRs (A, AAAA, etc.)
    additionals = []
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)
    
    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response



def dns_query(query_spec, server=("1.1.1.1", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    return parse_response(data)



def iterative_resolve(query_spec):
    servers = ROOT_SERVERS  # Initialize with IP address of root server
    print("Root servers:", servers)
    query_count = 0
    visited_servers = []

    while servers:
        server_ip = servers.pop(0)
        visited_servers.append(server_ip)
        query_count += 1
        
        print(f"\nQuery #{query_count}: Asking {server_ip}")
        
        try:
            # 1. DNS query to server_ip
            response = dns_query(query_spec, (server_ip, 53))
            
            print(f"Response from {server_ip}:")
            print(f"  Answers: {len(response.get('answers', []))}")
            print(f"  Authorities: {len(response.get('authorities', []))}")
            print(f"  Additionals: {len(response.get('additionals', []))}")
            
            # 2. Check if response has answer with IP address
            answers = response.get('answers', [])
            for answer in answers:
                if answer.get('rtype') in ['A', 'AAAA'] and answer.get('ip'):
                    print(f"Found answer: {answer['ip']}")
                    return {
                        "ip": answer['ip'],
                        "queries_sent": query_count,
                        "servers_contacted": visited_servers,
                        "final_server": server_ip
                    }
            
            # 3. Look for NS records in authorities and corresponding glue in additionals
            authorities = response.get('authorities', [])
            additionals = response.get('additionals', [])
            
            # Find NS records
            ns_records = [auth for auth in authorities if auth.get('rtype') == 'NS']
            if not ns_records:
                print("No NS records found in authorities")
                continue
                
            # Find glue records (A records for the NS names)
            new_servers = []
            for ns in ns_records:
                ns_name = ns.get('nsname', '')
                print(f"  Looking for glue for NS: {ns_name}")
                
                # Look for A record in additionals
                for additional in additionals:
                    if (additional.get('hostname', '').lower() == ns_name.lower() and 
                        additional.get('rtype') == 'A' and 
                        additional.get('ip')):
                        print(f"Found glue: {ns_name} -> {additional['ip']}")
                        new_servers.append(additional['ip'])
                        break
                else:
                    print(f"No glue found for {ns_name}")
            
            if new_servers:
                servers = new_servers
                print(f"Next servers to try: {servers}")
            else:
                return {"error": "No glue records found", 
                       "queries_sent": query_count,
                       "servers_contacted": visited_servers}
                       
        except Exception as e:
            print(f"Error querying {server_ip}: {e}")
            continue
    
    return {"error": "Resolution failed - no more servers", 
           "queries_sent": query_count,
           "servers_contacted": visited_servers}




if __name__ == "__main__":
    response = iterative_resolve(dns_query_spec)
    
    print(json.dumps(response,indent=2))
    
