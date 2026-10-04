#!/usr/bin/env python3
"""
Génère un PDF de test représentatif (note CSIRT fictive, 2 pages) pour
exercer le service watermark de bout en bout.

Aucune donnée réelle : contenu entièrement inventé. Sortie par défaut dans
var/ (ignoré par git).

Usage : watermark/.venv/bin/python scripts/make-test-doc.py [sortie.pdf]
"""
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

TITRE = "Note technique — campagne d'hameçonnage ciblée (FICTIF)"

PAGE_1 = [
    ("Objet", [
        "Document de TEST destiné à valider la chaîne de rendu filigrané SDOP.",
        "Contenu entièrement fictif : aucun IOC, aucune donnée réelle.",
    ]),
    ("Synthèse", [
        "Une campagne d'hameçonnage fictive viserait les services financiers",
        "de trois collectivités. Vecteur supposé : pièce jointe XLSM avec macro.",
        "Aucune compromission confirmée à la date de rédaction.",
    ]),
    ("Indicateurs (exemples non opérationnels)", [
        "domaine        exemple-facture-collectivite.invalid",
        "empreinte      d41d8cd98f00b204e9800998ecf8427e (vide, illustrative)",
        "adresse IP     203.0.113.42 (plage de documentation RFC 5737)",
    ]),
]

PAGE_2 = [
    ("Recommandations", [
        "1. Bloquer le domaine cité en résolution DNS sortante.",
        "2. Rappeler la procédure de validation des changements de RIB.",
        "3. Vérifier la journalisation des accès à la messagerie.",
    ]),
    ("Diffusion", [
        "Ce document est diffusé via SDOP. Chaque consultation est nominative,",
        "filigranée au nom du lecteur et inscrite au journal à chaîne de hachage.",
        "La copie n'est pas empêchée : elle est attribuée.",
    ]),
]


def page(c, sections, numero, total):
    w, h = A4
    y = h - 28 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(22 * mm, y, TITRE if numero == 1 else TITRE + " (suite)")
    y -= 6 * mm
    c.setStrokeColorRGB(0.6, 0.6, 0.6)
    c.line(22 * mm, y, w - 22 * mm, y)
    y -= 12 * mm

    for titre, lignes in sections:
        c.setFont("Helvetica-Bold", 10.5)
        c.drawString(22 * mm, y, titre)
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for ligne in lignes:
            c.drawString(26 * mm, y, ligne)
            y -= 5.4 * mm
        y -= 6 * mm

    c.setFont("Helvetica-Oblique", 8)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(22 * mm, 15 * mm, "Document de test SDOP — contenu fictif")
    c.drawRightString(w - 22 * mm, 15 * mm, f"page {numero}/{total}")
    c.setFillColorRGB(0, 0, 0)
    c.showPage()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "var/note-test-sdop.pdf"
    c = canvas.Canvas(out, pagesize=A4)
    c.setTitle(TITRE)
    page(c, PAGE_1, 1, 2)
    page(c, PAGE_2, 2, 2)
    c.save()
    print(f"✔ PDF de test écrit : {out}")


if __name__ == "__main__":
    main()
