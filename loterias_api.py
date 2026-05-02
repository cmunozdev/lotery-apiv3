import urllib.request
import urllib.error
import gzip
import json
import ssl
from typing import Any

BASE = "https://loteriasdominicanas.com/mobile-api/v3"


def fetch(
    url: str,
    *,
    verify_ssl: bool = True,
    timeout: float = 15.0,
) -> Any:
    """
    GET request con manejo de gzip, descifrado XOR por byte, y errores claros.

    Args:
        url: Endpoint completo.
        verify_ssl: False solo para debugging en entornos controlados (ej: MITM proxy).
        timeout: Segundos antes de abortar la conexión.
    """
    # ── SSL ───────────────────────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # ── Request ────────────────────────────────────────────────────────────────
    req = urllib.request.Request(url, headers={"User-Agent": "okhttp/4.9.2"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            data: bytes = r.read()
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"HTTP {e.code}: {e.reason} — {e.url}") from e
    except urllib.error.URLError as e:
        raise ConnectionError(f"Falló la conexión a {url}: {e.reason}") from e

    # ── Gzip ────────────────────────────────────────────────────────────────────
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except Exception as e:
            raise ValueError(f"Gzip corrupto: {e}") from e

    # ── Descifrado ─────────────────────────────────────────────────────────────
    # La API devuelve un string de bytes (UTF-8) donde cada caracter = plaintext XOR key
    # Se prueba con clave = encrypted[0] ^ '[' y encrypted[0] ^ '{' — una de las dos debe coincidir
    encrypted: str = data.decode("utf-8")

    for expected in ("[", "{"):
        key: int = ord(encrypted[0]) ^ ord(expected)
        decrypted_chars = [chr(ord(c) ^ key) for c in encrypted]
        decrypted: str = "".join(decrypted_chars)
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            continue

    # Si ninguna clave funciona, guardar el raw para inspeccionar
    raw_path = "debug_encrypted.json"
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(encrypted[:500])  # primeros 500 bytes
    raise ValueError(
        f"No se pudo descifrar. Raw guardado en {raw_path}. "
        "Revisa si la API cambió su esquema de cifrado."
    )