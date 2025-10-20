import socket
import struct
import random
import json

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 1,      # recursion desired
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   # Arecord
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

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse answers
    answers = []
    for _ in range(ANCOUNT):
        # name (compression: first two bits 11)
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        print("atype and rdlength",atype,rdlength,type(rdata))
        
        # Extract IPv4 address or IPv6 address based on atype and rdlength
        answer = {}
        if atype == 1 and rdlength == 4:  # A record (IPv4)
            # Convert 4 bytes to IPv4 address string
            ip_bytes = struct.unpack("!BBBB", rdata)
            ip_address = ".".join(str(byte) for byte in ip_bytes)
            answer = {
                "type": "A",
                "ip": ip_address,
                "ttl": ttl
            }
        elif atype == 28 and rdlength == 16:  # AAAA record (IPv6)
            # Convert 16 bytes to IPv6 address string
            ip_parts = struct.unpack("!HHHHHHHH", rdata)
            ip_address = ":".join(f"{part:x}" for part in ip_parts)
            answer = {
                "type": "AAAA", 
                "ip": ip_address,
                "ttl": ttl
            }
        
        if answer:  # Only add if we successfully parsed an IP
            answers.append(answer)
    response["answers"] = answers
    return response


def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    result=parse_response(data)
    return result

if __name__ == "__main__":
    # Read questions from Input.json
    with open("Input.json", "r") as f:
        questions = json.load(f)
    
    # Open output file
    with open("output.txt", "w") as output_file:
        # Main loop - process each question
        for q in questions:
            # Create dns_query_spec with fields from q
            current_query_spec = {
                "id": random.randint(0, 65535),
                "qr": 0,      # query
                "opcode": 0,  # standard query
                "rd": 1,      # recursion desired
                "questions": [
                    {
                        "qname": q["qname"],
                        "qtype": q["qtype"],
                        "qclass": 1   # IN
                    }
                ]
            }
            
            print(f"Querying {q['qname']} (type {q['qtype']})")
            
            # Send DNS query
            response = dns_query(current_query_spec)
            
            # Print response
            print(json.dumps(response, indent=2))
            print("-" * 50)
            
            # Append response to output.txt
            output_file.write(json.dumps(response, indent=2) + "\n")
            output_file.write("-" * 50 + "\n")
    
