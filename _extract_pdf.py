from pypdf import PdfReader
from pathlib import Path

pdf_path = Path(r"C:\Users\branana\Downloads\AWS_L5_electronic_voting_part2a.pdf")
reader = PdfReader(str(pdf_path))
print("pages", len(reader.pages))

out = Path(r"C:\Users\branana\Desktop\Github Repos\luwebsecurity\_pdf_extract_electronic_voting_part2a.txt")
texts = []
for i, p in enumerate(reader.pages):
    t = p.extract_text() or ""
    texts.append(f"\n\n===== PAGE {i+1} =====\n" + t)
out.write_text("".join(texts), encoding="utf-8", errors="replace")
print("wrote", out)

text = out.read_text(encoding="utf-8", errors="replace").lower()
keywords = ["mix", "mixnet", "blind", "homomorphic", "elgamal", "bulletin", "registration", "write-in", "kdf", "otr", "mac", "signature", "fiat", "challenge", "zero-knowledge", "smp"]
for k in keywords:
    if k in text:
        print("has", k)
