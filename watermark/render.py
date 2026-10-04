"""
Rendu filigrané SDOP (ARCHITECTURE.md).

Pipeline, par page, **entièrement en mémoire** (jamais de fichier temporaire —
§6.1 : « pas de fichier temporaire supprimé trop tôt ») :

  1. la page source est **rasterisée** (PyMuPDF, SDOP_RENDER_DPI) ;
  2. l'image obtenue est posée sur une page de même géométrie et le marquage
     d'attribution est dessiné par-dessus (ReportLab, police Helvetica
     intégrée — aucun fichier de police à installer dans l'image) ;
  3. cette page est **rasterisée une seconde fois** : le filigrane devient des
     pixels, plus du texte.

Le second passage est ce qui rend la sortie conforme à la décision verrouillée
du §6.2 : aucune couche texte n'est servie au client — ni le texte du document,
ni même celui du filigrane (qui serait sinon supprimable d'un `qpdf`/éditeur).
Le coût (deux rasterisations) est assumé au volume visé (~10 documents/jour).

Le client ne reçoit donc jamais que des pixels : soit une tuile PNG par page
(visionneuse), soit un PDF composé uniquement de ces images (export).
"""
import io
import os
from datetime import datetime, timezone

import pymupdf  # rendu MuPDF
from reportlab.lib.colors import Color
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

DPI = int(os.environ.get("SDOP_RENDER_DPI", "150"))

# Échelle points PDF -> pixels de rendu (72 pt = 1 pouce).
_SCALE = DPI / 72.0


# Budgets de rendu (SEC-017). La taille du fichier déposé ne borne pas le coût
# de sa rasterisation : un PDF compressé de quelques mégaoctets peut contenir des
# milliers de pages, ou des pages de plusieurs mètres de côté. Le plafond mémoire
# du conteneur protège l'hôte, pas le service — il le fait tuer, ce qui est
# exactement l'indisponibilité qu'on cherche à éviter.
#
# Les bornes ci-dessous sont évaluées AVANT toute allocation, à partir de la
# seule géométrie déclarée des pages.
MAX_PAGES = int(os.environ.get("SDOP_MAX_PAGES", "500"))
# Pixels d'une page au DPI de rendu. 40 Mpx ≈ une page A0 à 150 dpi.
MAX_PAGE_PIXELS = int(os.environ.get("SDOP_MAX_PAGE_PIXELS", str(40_000_000)))
# Pixels cumulés d'un export — c'est lui qui accumule en mémoire.
MAX_TOTAL_PIXELS = int(os.environ.get("SDOP_MAX_TOTAL_PIXELS", str(600_000_000)))


class RenderError(Exception):
    """PDF source illisible."""


class DocumentTooCostly(RenderError):
    """Le document dépasse un budget de rendu — refusé avant rasterisation."""


def _open(pdf_bytes: bytes) -> pymupdf.Document:
    try:
        return pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:  # pragma: no cover - dépend de MuPDF
        raise RenderError(str(exc)) from exc


def page_count(pdf_bytes: bytes) -> int:
    with _open(pdf_bytes) as doc:
        return doc.page_count


def page_sizes(pdf_bytes: bytes) -> list[tuple[float, float]]:
    """Géométrie de chaque page, en points, rotation appliquée."""
    with _open(pdf_bytes) as doc:
        return [(p.rect.width, p.rect.height) for p in doc]


def check_budget(pdf_bytes: bytes, *, full_document: bool = True) -> dict:
    """Refuse un document trop coûteux à rasteriser, AVANT d'allouer quoi que ce soit.

    Lève DocumentTooCostly avec un message destiné à l'émetteur. `full_document`
    à False n'évalue pas le cumul : une tuile isolée ne charge qu'une page.
    """
    with _open(pdf_bytes) as doc:
        return _controler_budget(doc, full_document=full_document)


def _controler_budget(doc: pymupdf.Document, *, full_document: bool = True,
                      page_index: int | None = None) -> dict:
    """Budgets évalués sur un document déjà ouvert, à partir de sa géométrie.

    Appelé au dépôt (refus à l'émetteur) ET au point de rendu (SEC-017) : un
    document qui aurait échappé au contrôle du dépôt — antérieur aux budgets,
    budgets abaissés depuis, base restaurée — ne déclenche pas pour autant
    l'allocation qu'ils existent pour empêcher.
    """
    if page_index is not None:
        # Une tuile : le nombre de pages et LA page demandée suffisent — ne pas
        # parcourir tout le document à chaque tuile.
        if doc.page_count > MAX_PAGES:
            raise DocumentTooCostly(f"{doc.page_count} pages (maximum {MAX_PAGES})")
        r = doc[page_index].rect
        px = int(r.width * _SCALE) * int(r.height * _SCALE)
        if px > MAX_PAGE_PIXELS:
            raise DocumentTooCostly(
                f"page {page_index + 1} trop grande : {px // 1_000_000} Mpx à {DPI} dpi "
                f"(maximum {MAX_PAGE_PIXELS // 1_000_000} Mpx)")
        return {"pages": doc.page_count, "pixels": px}

    tailles = [(p.rect.width, p.rect.height) for p in doc]
    if len(tailles) > MAX_PAGES:
        raise DocumentTooCostly(
            f"{len(tailles)} pages (maximum {MAX_PAGES})")

    total = 0
    for i, (w, h) in enumerate(tailles, start=1):
        px = int(w * _SCALE) * int(h * _SCALE)
        if px > MAX_PAGE_PIXELS:
            raise DocumentTooCostly(
                f"page {i} trop grande : {px // 1_000_000} Mpx à {DPI} dpi "
                f"(maximum {MAX_PAGE_PIXELS // 1_000_000} Mpx)")
        total += px

    if full_document and total > MAX_TOTAL_PIXELS:
        raise DocumentTooCostly(
            f"document trop coûteux : {total // 1_000_000} Mpx cumulés à {DPI} dpi "
            f"(maximum {MAX_TOTAL_PIXELS // 1_000_000} Mpx)")
    return {"pages": len(tailles), "pixels": total}


# Couleurs TLP officielles (FIRST, standard TLP 2.0). Elles sont définies pour
# un fond SOMBRE : TLP:AMBER est un jaune #FFC000 qui disparaît sur du blanc.
# L'étiquette est donc rendue comme le standard la prévoit — texte en couleur
# officielle sur pastille noire — ce qui la rend à la fois conforme et lisible,
# y compris en photocopie.
_TLP_OFFICIAL = {
    "TLP:RED": Color(1.0, 0.169, 0.169),          # #FF2B2B
    "TLP:AMBER+STRICT": Color(1.0, 0.753, 0.0),   # #FFC000
    "TLP:AMBER": Color(1.0, 0.753, 0.0),          # #FFC000
}

# Variante assombrie, pour les marquages posés SANS pastille (marges, diagonale
# centrale) : sur blanc, le jaune officiel serait invisible.
_TLP_INK = {
    "TLP:RED": Color(0.62, 0.02, 0.02),
    "TLP:AMBER+STRICT": Color(0.52, 0.34, 0.0),
    "TLP:AMBER": Color(0.52, 0.34, 0.0),
}

_BADGE_BG = Color(0.08, 0.08, 0.08)

# Densité du marquage. `discret` (défaut) : marquage d'en-tête et de pied de
# page, comme un rapport officiel classifié. `dense` : ajoute en plus la
# diagonale TLP répétée sur toute la page.
#
# Le défaut est `discret` parce que ces documents sont des rapports destinés à
# des directions : une tapisserie de filigranes les fait passer pour des
# brouillons et décrédibilise le fond. Le prix de ce choix est réel et assumé :
# une capture d'écran RECADRÉE sur le seul corps de page perd l'attribution.
# `dense` la rend inévitable, au prix de la lisibilité — à réserver aux cas où
# la fuite par capture partielle est le risque dominant.
DENSITY = os.environ.get("SDOP_WATERMARK_DENSITY", "discret")


def _tlp_color(tlp: str) -> Color:
    """Teinte d'encre pour un marquage sans fond (marges, diagonale)."""
    return _TLP_INK.get(tlp, Color(0.35, 0.35, 0.35))


def _draw_tlp_badge(c: canvas.Canvas, x: float, y: float, tlp: str,
                    size: float, anchor: str = "left") -> float:
    """Étiquette TLP : texte en couleur officielle sur pastille noire.

    `x` est le bord gauche ou droit de la pastille selon `anchor`, `y` sa base.
    Renvoie la largeur de la pastille.
    """
    c.setFont("Helvetica-Bold", size)
    pad_x, pad_y = 4.5 * _SCALE, 2.6 * _SCALE
    text_w = c.stringWidth(tlp, "Helvetica-Bold", size)
    box_w = text_w + 2 * pad_x
    box_h = size + 2 * pad_y
    left = x - box_w if anchor == "right" else x

    c.setFillColor(_BADGE_BG)
    c.rect(left, y, box_w, box_h, stroke=0, fill=1)
    c.setFillColor(_TLP_OFFICIAL.get(tlp, Color(1, 1, 1)))
    c.drawString(left + pad_x, y + pad_y + 0.5 * _SCALE, tlp)
    return box_w


def _draw_watermark(c: canvas.Canvas, w: float, h: float, *, username: str,
                    tlp: str, view_id: str, timestamp: str) -> None:
    """Marquage d'attribution sur quatre ancrages indépendants.

    Quatre informations, et seulement elles : le niveau TLP, le compte qui a
    obtenu le rendu, l'horodatage, et l'identifiant unique de cette
    consultation. L'adresse IP reste au journal — elle n'ajoute rien sur la
    page et l'encombre.

    Elles sont posées à quatre endroits que l'on ne peut pas tous perdre d'un
    même recadrage :

        en-tête   TLP seul, en haut à droite
        pied      TLP + attribution complète
        marges    attribution verticale dans les gouttières gauche ET droite
        centre    une mention diagonale pâle, lisible au travers

    Couper le bas d'une capture laisse les trois autres. Recadrer sur la seule
    colonne de texte laisse la diagonale centrale. Il faut découper un fragment
    à la fois sans bords, sans haut, sans bas et sans centre pour sortir une
    image non attribuée — à ce stade il ne reste plus grand-chose à exfiltrer.

    Coordonnées en pixels de rendu (la page ReportLab fait w x h pixels) : les
    tailles sont mises à l'échelle du DPI, pour un marquage identique quel que
    soit SDOP_RENDER_DPI.
    """
    tlp_color = _tlp_color(tlp)
    attribution = f"{username} · {timestamp} · {view_id}"

    if DENSITY == "dense":
        # Le niveau TLP seul ne désigne personne : une capture recadrée portant
        # « TLP:RED » répété n'attribue rien. La répétition porte donc le compte,
        # sinon ce mode ne tient pas la promesse qui le justifie (SEC-016).
        dense_label = f"{tlp} · {username}"
        c.setFillColor(Color(tlp_color.red, tlp_color.green, tlp_color.blue,
                             alpha=0.14))
        c.setFont("Helvetica-Bold", 11 * _SCALE)
        step_x, step_y, margin = 260 * _SCALE, 140 * _SCALE, 260 * _SCALE
        x = -margin
        while x < w + margin:
            y = -margin
            while y < h + margin:
                c.saveState()
                c.translate(x, y)
                c.rotate(45)
                c.drawString(0, 0, dense_label)
                c.restoreState()
                y += step_y
            x += step_x

    # ── En-tête : étiquette TLP à droite, attribution courte à gauche ────
    # Convention des documents classifiés : le niveau se lit sans chercher, y
    # compris sur une page isolée ou photocopiée. L'attribution courte est là
    # pour que le HAUT d'une page recadrée reste nominatif — l'en-tête ne
    # portait que le niveau, ce qui rendait fausse la promesse affichée au
    # lecteur (SEC-016).
    hdr_h = 16 * _SCALE
    c.setFillColor(Color(1, 1, 1, alpha=0.86))
    c.rect(0, h - hdr_h, w, hdr_h, stroke=0, fill=1)
    _draw_tlp_badge(c, w - 10 * _SCALE, h - 13.5 * _SCALE, tlp,
                    7.5 * _SCALE, anchor="right")
    c.setFillColor(Color(0.42, 0.42, 0.42))
    c.setFont("Helvetica", 6 * _SCALE)
    c.drawString(10 * _SCALE, h - 11 * _SCALE,
                 f"{username} · {view_id.split('-')[0]}")

    # ── Pied de page : TLP + attribution nominative ──────────────────────
    band_h = 17 * _SCALE
    c.setFillColor(Color(1, 1, 1, alpha=0.86))
    c.rect(0, 0, w, band_h, stroke=0, fill=1)
    c.setStrokeColor(Color(0.6, 0.6, 0.6, alpha=0.5))
    c.setLineWidth(0.4 * _SCALE)
    c.line(10 * _SCALE, band_h, w - 10 * _SCALE, band_h)

    _draw_tlp_badge(c, 10 * _SCALE, 3.5 * _SCALE, tlp, 7 * _SCALE)

    c.setFillColor(Color(0.25, 0.25, 0.25))
    c.setFont("Helvetica", 6.5 * _SCALE)
    c.drawRightString(w - 10 * _SCALE, 5.5 * _SCALE, attribution)

    # ── Marges latérales : attribution verticale, dans la gouttière ──────
    # Un recadrage qui supprime le pied de page laisse les bords. Le texte
    # vit dans la marge, pas dans la colonne de texte : il n'entre pas en
    # concurrence avec le contenu.
    c.setFillColor(Color(0.42, 0.42, 0.42, alpha=0.55))
    c.setFont("Helvetica", 5.5 * _SCALE)
    lateral = f"{tlp} · {attribution}"
    for x, rotation in ((9.5 * _SCALE, 90), (w - 9.5 * _SCALE, -90)):
        c.saveState()
        c.translate(x, h / 2)
        c.rotate(rotation)
        c.drawCentredString(0, 0, lateral)
        c.restoreState()

    # ── Centre : une mention diagonale, assez pâle pour lire au travers ──
    # Dernier filet de sécurité : un recadrage sur le seul corps de page
    # emporte l'en-tête, le pied ET les deux marges — il reste celle-ci.
    # Une seule, pas une tapisserie.
    c.saveState()
    c.translate(w / 2, h / 2)
    c.rotate(30)
    c.setFillColor(Color(tlp_color.red, tlp_color.green, tlp_color.blue,
                         alpha=0.11))
    c.setFont("Helvetica-Bold", 15 * _SCALE)
    c.drawCentredString(0, 4 * _SCALE, f"{tlp} · {username}")
    c.setFillColor(Color(0.3, 0.3, 0.3, alpha=0.13))
    c.setFont("Helvetica", 7.5 * _SCALE)
    c.drawCentredString(0, -10 * _SCALE, f"{timestamp} · {view_id}")
    c.restoreState()


def _flatten(page_png: bytes, px_w: int, px_h: int, **ident) -> bytes:
    """Image de page + filigrane -> PNG unique (filigrane devenu pixels)."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(px_w, px_h))
    c.drawImage(ImageReader(io.BytesIO(page_png)), 0, 0, px_w, px_h)
    _draw_watermark(c, px_w, px_h, **ident)
    c.showPage()
    c.save()
    buf.seek(0)

    # Second passage : 1 pt de cette page = 1 px, donc zoom 1 -> dimensions
    # identiques, sans ré-échantillonnage.
    with _open(buf.read()) as doc:
        pix = doc[0].get_pixmap(matrix=pymupdf.Matrix(1, 1), alpha=False)
        return pix.tobytes("png")


def _identity_fields(username, tlp, view_id, timestamp=None) -> dict:
    return {
        "username": username,
        "tlp": tlp,
        "view_id": view_id,
        "timestamp": timestamp or datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"),
    }


def render_page_png(pdf_bytes: bytes, page_index: int, *, username: str,
                    tlp: str, view_id: str,
                    timestamp: str | None = None) -> bytes:
    """Une page -> PNG filigrané aplati. Lève IndexError hors bornes."""
    ident = _identity_fields(username, tlp, view_id, timestamp)
    with _open(pdf_bytes) as doc:
        if page_index < 0 or page_index >= doc.page_count:
            raise IndexError(page_index)
        _controler_budget(doc, full_document=False, page_index=page_index)
        page = doc[page_index]
        pix = page.get_pixmap(dpi=DPI, alpha=False)
        return _flatten(pix.tobytes("png"), pix.width, pix.height, **ident)


def render_pdf(pdf_bytes: bytes, *, username: str, tlp: str,
               view_id: str, timestamp: str | None = None) -> bytes:
    """Document complet -> PDF filigrané **sans aucune couche texte**.

    Chaque page du résultat ne contient qu'une image : le PDF exporté n'est pas
    un PDF source filigrané (dont le filigrane serait détachable et le texte
    extractible), c'est un rendu.
    """
    ident = _identity_fields(username, tlp, view_id, timestamp)
    out = pymupdf.open()
    try:
        with _open(pdf_bytes) as src:
            _controler_budget(src)
            for page in src:
                pix = page.get_pixmap(dpi=DPI, alpha=False)
                flat = _flatten(pix.tobytes("png"), pix.width, pix.height, **ident)
                # Page de sortie à la géométrie de la source (en points) :
                # l'export s'imprime comme l'original.
                new_page = out.new_page(width=page.rect.width,
                                        height=page.rect.height)
                new_page.insert_image(new_page.rect, stream=flat)
        return out.tobytes(garbage=4, deflate=True)
    finally:
        out.close()
