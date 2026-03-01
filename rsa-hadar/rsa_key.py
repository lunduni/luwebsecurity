import base64

# These values are extracted from the RSA key with rsa parser website after the censoredcensored... was removed
n_hex = "00B3742621E6940AB431DFA61CDF0EC0BB99E32CADFE0567526E6DC58FEC6B6C3BE047858E0D45152C9242489A706F9FBB723D2C33588178E994BAAB9BC347079680148E3562B820E37997B9A30C2BC31158DD51B38C9BA7BA6E08E2EBE2DCB7CC8B4C124CB77D3C6E634B41318101F6F212B48294ED232D8EA8D90983794FCF35"
d_hex = "30B5BD48046B78C052AD4F4C94EB4F3B5CD9021EB44DC92EE1D4A004A1FAC2A53A0A8FE0F00F296130CE1720FC95FFF88458C06FAB850AF5F42DFB38CB77B3421D52779ACAE522BB3FA53A27862823272C8F4DE3B0C8179E065C8C21C051C27CAEABFD1A88277005BE7132342A1AD276EEEE9B89F837C88951F770BEB2A20021"
p_hex = "00DDDCFD3727A4144C002998AF1A8BD517D3097E5EA7C5FA72D18EF0DD16B529D4974B340FAE3AD5750DFC98650515C79F5A23171BCB800DD446ADB6659370F6BD"
q_hex = "00CF10AEE4C7CB317FB5A28B16E8C778AB7C265D87146A06EEF6A7EE8AC87A3BB0789ED3776E48B7A1E6D7ECCE1766F96EC35E2ABFB8EB0644DFD93A88FD5C5DD9"

n = int(n_hex, 16)
d = int(d_hex, 16)
p = int(p_hex, 16)
q = int(q_hex, 16)

print("Checking RSA mathematical integrity")
if n == p * q:
    print("n, p, and q match perfectly. (No corruption found)")
elif n % p == 0:
    print("q is corrupted. Recalculating the correct q")
    q = n // p
elif n % q == 0:
    print("p is corrupted. Recalculating the correct p")
    p = n // q
else:
    print("n is corrupted. Recalculating the correct n")
    n = p * q
print("Math fixed!\n")


encrypted_message = "aVE+4RJi/TXRBXFSYlYWsfI1y4TfVshOZxY7yKrnZ2BdQWOFPQZddcpf6zb8ymQ2gr5wGIMlcxF4hX9AF1mQ/yQ7EgVK2fhaPpwswMJpdErgkPzNmHbAvxOvPRjpQjPOrjaS/8KbFbOq83ZAh9jeqcE7J2JRiXYL2EXVoL6qS2E="

if encrypted_message != "":
    # Convert text to raw bytes automatically

    c_bytes = base64.b64decode(encrypted_message)

    c = int.from_bytes(c_bytes, "big")

    m = pow(c, d, n)

    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")

    # Strip the PKCS#1 v1.5 padding

    separator_idx = m_bytes.index(b"\x00", 1)
    message = m_bytes[separator_idx + 1 :]
    print("MESSAGE:")
    print(message.decode("utf-8"))
else:
    print("Please paste your encrypted message into the script and run it again!")
