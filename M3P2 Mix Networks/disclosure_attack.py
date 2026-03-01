from pcapfile import savefile
from pcapfile.protocols.network import ip
from pcapfile.protocols.linklayer import ethernet
import sys
import struct

# Input parameters
if len(sys.argv) >= 5:
    targetIp = sys.argv[1]
    mixIp = sys.argv[2]
    nbrOfPartners = int(sys.argv[3])
    pcap_file = sys.argv[4]
else:
    targetIp = "160.66.13.37"  # Abu Nazir
    mixIp = "204.177.242.216"  # The Mix
    nbrOfPartners = 15
    pcap_file = "cia.log.5.pcap"

print(f"Analyzing {pcap_file}...")
print(f"Target: {targetIp} | Mix: {mixIp}")

# Open and load the pcap file
with open(pcap_file, "rb") as testcap:
    capfile = savefile.load_savefile(testcap, verbose=False)


# Helper to get IP string from packet object
def get_ip_str(packet):
    try:
        raw = packet.raw()
        # Skip 14-byte Ethernet header, parse IP directly
        ip_packet = ip.IP(raw[14:])
        src = (
            ip_packet.src if isinstance(ip_packet.src, str) else ip_packet.src.decode()
        )
        dst = (
            ip_packet.dst if isinstance(ip_packet.dst, str) else ip_packet.dst.decode()
        )
        return src, dst
    except (AssertionError, Exception):
        # Skip non-IPv4 packets (ARP, IPv6, etc.)
        return None, None


def extractBatches(capfile, mixIp):
    batches = []

    current_senders = set()
    current_receivers = set()

    # We iterate through all packets
    # State 0: Collecting Senders (Inputs)
    # State 1: Collecting Receivers (Outputs - The Burst)

    # Determine the "State" by looking at the first packet of a sequence
    # If Src == Mix, we are in a burst (output)
    # If Dst == Mix, we are collecting inputs

    i = 0
    packets = capfile.packets
    total_pkts = len(packets)

    while i < total_pkts:
        src, dst = get_ip_str(packets[i])

        # Skip non-IPv4 packets
        if src is None or dst is None:
            i += 1
            continue

        if dst == mixIp:
            # This is an INPUT packet (Sender -> Mix)
            current_senders.add(src)
            i += 1

        elif src == mixIp:
            # This is an OUTPUT packet (Mix -> Partner)
            # This marks the end of the collection phase and start of the burst

            # 1. Collect all packets in this immediate burst (same second/timestamp)
            timestamp = packets[i].timestamp
            while i < total_pkts:
                s_check, d_check = get_ip_str(packets[i])

                # Skip non-IPv4 packets
                if s_check is None or d_check is None:
                    i += 1
                    continue

                # Check if this packet is still part of the outgoing burst
                # (Must be from Mix AND usually same timestamp)
                if s_check == mixIp and packets[i].timestamp == timestamp:
                    current_receivers.add(d_check)
                    i += 1
                else:
                    break

            # 2. The batch is complete. Store it.
            if len(current_senders) > 0 and len(current_receivers) > 0:
                batches.append(
                    {"senders": current_senders, "receivers": current_receivers}
                )

            # 3. Reset for the next batch
            current_senders = set()
            current_receivers = set()

        else:
            # Packet unrelated to the Mix (Background noise?)
            i += 1

    return batches


def getIntersection(set1, set2):
    return set1.intersection(set2)


def findPartners(batches, targetIp, nbrOfPartners):
    # Step 1: Filter - Keep only batches where Abu Nazir is a SENDER
    target_batches = []
    for b in batches:
        if targetIp in b["senders"]:
            target_batches.append(b["receivers"])  # We only care about receivers now

    print(f"Target sent messages in {len(target_batches)} batches.")

    # Step 2: Find 'm' Disjoint Sets (The Seeds)
    # We need to find 'nbrOfPartners' batches that have ZERO overlap with each other
    disjoint_groups = []  # Will store sets of IPs

    # Simple greedy search for disjoint sets
    # (Note: In complex scenarios, this might require backtracking,
    # but for this assignment, the first matches usually work)

    # Try to find the first seed
    if len(target_batches) > 0:
        disjoint_groups.append(target_batches[0])

    # Find the rest of the disjoint seeds
    for batch_receivers in target_batches[1:]:
        if len(disjoint_groups) == nbrOfPartners:
            break

        # Check if this batch is disjoint from ALL currently found groups
        is_disjoint = True
        for group in disjoint_groups:
            if len(getIntersection(batch_receivers, group)) > 0:
                is_disjoint = False
                break

        if is_disjoint:
            disjoint_groups.append(batch_receivers)

    if len(disjoint_groups) < nbrOfPartners:
        print("Error: Could not find enough disjoint starting batches.")
        return []

    print(f"Found {len(disjoint_groups)} disjoint groups. Refining...")

    # Step 3: Intersect the remaining batches to remove Noise
    # Loop through ALL target batches to refine the groups
    for batch_receivers in target_batches:

        # Check overlaps
        matches = 0
        matched_group_index = -1

        for idx, group in enumerate(disjoint_groups):
            if len(getIntersection(batch_receivers, group)) > 0:
                matches += 1
                matched_group_index = idx

        # LOGIC:
        # If matches == 0: It's a different unknown partner (shouldn't happen if n is correct)
        # If matches > 1: It's ambiguous (Noise overlap + Partner overlap). DISCARD.
        # If matches == 1: It belongs to this group. INTERSECT to remove noise.

        if matches == 1:
            # Perform intersection to narrow down the partner IP
            disjoint_groups[matched_group_index] = getIntersection(
                disjoint_groups[matched_group_index], batch_receivers
            )

    # Step 4: Extract the final single IPs
    final_partners = []
    for group in disjoint_groups:
        if len(group) == 1:
            final_partners.append(list(group)[0])
        else:
            print(
                f"Warning: A group could not be narrowed down to 1 IP. Remaining: {group}"
            )

    return final_partners


# --- Main Execution ---

all_batches = extractBatches(capfile, mixIp)
print(f"Total batches extracted: {len(all_batches)}")

partners = findPartners(all_batches, targetIp, nbrOfPartners)
print(f"\nPartner IPs found: {partners}")

# Calculate Sum
total = 0
for partner_ip in partners:
    octets = partner_ip.split(".")
    # Convert IP to Integer (Big Endian / Network Byte Order)
    ip_int = (
        (int(octets[0]) << 24)
        + (int(octets[1]) << 16)
        + (int(octets[2]) << 8)
        + int(octets[3])
    )
    print(f"{partner_ip} -> {ip_int}")
    total += ip_int

print(f"\nSum of partner IPs: {total}")
