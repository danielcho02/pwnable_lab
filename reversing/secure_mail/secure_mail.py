from pathlib import Path
from datetime import date, timedelta
from hashlib import md5
from base64 import b64decode
import re

from Crypto.Cipher import AES


html = Path("secure-mail.html").read_text(
    encoding="utf-8",
    errors="ignore"
)

array = re.search(
    r"file\s*=\s*\[(.*?)\]\s*,\s*dfbora",
    html,
    re.S
).group(1)

ciphertext = bytes(
    int(x, 0)
    for x in re.findall(
        r"0x[0-9a-fA-F]+|\d+",
        array
    )
)


def find_password():
    current = date(2000, 1, 1)
    end = date(2100, 1, 1)

    while current < end:
        password = current.strftime("%y%m%d")
        key = md5(password.encode()).digest()

        first = AES.new(
            key,
            AES.MODE_CBC,
            iv=key
        ).decrypt(ciphertext[:16])

        if first == b"data:image/png;b":
            return password, key

        current += timedelta(days=1)


password, key = find_password()

plaintext = AES.new(
    key,
    AES.MODE_CBC,
    iv=key
).decrypt(ciphertext)

base64_data = plaintext.split(
    b",",
    1
)[1]

png = b64decode(base64_data)

Path("decrypted.png").write_bytes(png)

print(password)