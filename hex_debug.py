from config import BOT_TOKEN
import binascii

print(f"Token Length: {len(BOT_TOKEN)}")
print(f"Token Bytes (Hex): {binascii.hexlify(BOT_TOKEN.encode()).decode()}")
for i, char in enumerate(BOT_TOKEN):
    print(f"Char {i}: '{char}' (Hex: {hex(ord(char))})")
