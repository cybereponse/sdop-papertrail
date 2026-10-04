"""
QR code en SVG inline — pour l'enrôlement TOTP d'un correspondant.

Encodeur de reportlab, déjà dépendance du service (render.py) : aucun paquet
de plus dans la chaîne d'approvisionnement (SEC-012). Rendu en SVG inline,
sans script ni ressource externe : la CSP du service (`default-src 'none'`)
n'a rien à autoriser de plus.
"""
from markupsafe import Markup
from reportlab.graphics.barcode.qrencoder import QRCode, QRErrorCorrectLevel


def svg(donnees: str, module: int = 6, marge: int = 4) -> Markup:
    qr = QRCode(None, QRErrorCorrectLevel.M)
    qr.addData(donnees)
    qr.make()
    n = qr.getModuleCount()
    taille = (n + 2 * marge) * module
    traits = "".join(
        f"M{(c + marge) * module},{(l + marge) * module}h{module}v{module}h-{module}z"
        for l in range(n) for c in range(n) if qr.isDark(l, c))
    # Fond blanc imposé : un QR sur fond sombre (thème sombre) ne se lit pas.
    return Markup(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {taille} {taille}" '
        f'width="{taille}" height="{taille}" role="img" aria-label="QR code '
        f'd\'enrôlement"><rect width="100%" height="100%" fill="#fff"/>'
        f'<path d="{traits}" fill="#000"/></svg>')
