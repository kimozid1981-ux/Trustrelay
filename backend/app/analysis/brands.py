"""Registry of organisations frequently impersonated in France / EU, with their official registrable domains.

This list is curated by hand from the organisations' own public websites. It is NOT exhaustive and must be
reviewed regularly (owner: threat-intel lead; see docs/STATUS.md risk R-07). A domain missing from this list is
not suspicious by itself; a domain that *imitates* an entry is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    id: str
    name: str
    official_domains: tuple[str, ...]
    keywords: tuple[str, ...]  # lowercase tokens that identify a claim to be this organisation
    country: str = "FR"
    category: str = "other"


BRANDS: tuple[Brand, ...] = (
    Brand("laposte", "La Poste", ("laposte.fr", "laposte.net", "labanquepostale.fr"), ("la poste", "laposte"), category="parcel"),
    Brand("colissimo", "Colissimo", ("colissimo.fr", "laposte.fr"), ("colissimo",), category="parcel"),
    Brand("chronopost", "Chronopost", ("chronopost.fr",), ("chronopost",), category="parcel"),
    Brand("dhl", "DHL", ("dhl.com", "dhl.fr", "dhl.de"), ("dhl",), "DE", "parcel"),
    Brand("ups", "UPS", ("ups.com",), ("ups",), "US", "parcel"),
    Brand("fedex", "FedEx", ("fedex.com",), ("fedex",), "US", "parcel"),
    Brand(
        "mondialrelay",
        "Mondial Relay",
        ("mondialrelay.fr", "mondialrelay.com"),
        ("mondial relay", "mondialrelay"),
        category="parcel",
    ),
    Brand("ameli", "Assurance Maladie (ameli)", ("ameli.fr",), ("ameli", "assurance maladie", "carte vitale"), category="public"),
    Brand(
        "impots",
        "Impots.gouv (DGFiP)",
        ("impots.gouv.fr",),
        ("impots.gouv", "impôts", "impots", "dgfip", "finances publiques"),
        category="public",
    ),
    Brand("antai", "ANTAI (amendes)", ("antai.gouv.fr",), ("antai", "amende", "avis de contravention"), category="public"),
    Brand("caf", "CAF", ("caf.fr",), ("caf", "allocations familiales"), category="public"),
    Brand(
        "francetravail",
        "France Travail",
        ("francetravail.fr", "pole-emploi.fr"),
        ("france travail", "pôle emploi", "pole emploi"),
        category="public",
    ),
    Brand("cpf", "Mon Compte Formation", ("moncompteformation.gouv.fr",), ("compte formation", "cpf"), category="public"),
    Brand(
        "servicepublic",
        "Service-Public.fr",
        ("service-public.fr", "gouv.fr"),
        ("service public", "service-public"),
        category="public",
    ),
    Brand("ants", "ANTS", ("ants.gouv.fr",), ("ants", "carte grise", "crit'air", "critair"), category="public"),
    Brand(
        "bnp",
        "BNP Paribas",
        ("mabanque.bnpparibas", "bnpparibas.com", "bnpparibas.net", "bnpparibas.fr"),
        ("bnp", "bnp paribas"),
        category="bank",
    ),
    Brand(
        "creditagricole",
        "Crédit Agricole",
        ("credit-agricole.fr", "credit-agricole.com"),
        ("crédit agricole", "credit agricole"),
        category="bank",
    ),
    Brand(
        "societegenerale",
        "Société Générale",
        ("societegenerale.fr", "societegenerale.com"),
        ("société générale", "societe generale"),
        category="bank",
    ),
    Brand("lcl", "LCL", ("lcl.fr",), ("lcl",), category="bank"),
    Brand("banquepostale", "La Banque Postale", ("labanquepostale.fr",), ("banque postale",), category="bank"),
    Brand("creditmutuel", "Crédit Mutuel", ("creditmutuel.fr",), ("crédit mutuel", "credit mutuel"), category="bank"),
    Brand(
        "caisseepargne",
        "Caisse d'Épargne",
        ("caisse-epargne.fr",),
        ("caisse d'épargne", "caisse d'epargne", "caisse epargne"),
        category="bank",
    ),
    Brand("boursorama", "BoursoBank", ("boursorama.com", "boursobank.com"), ("boursorama", "boursobank"), category="bank"),
    Brand("revolut", "Revolut", ("revolut.com",), ("revolut",), "LT", "bank"),
    Brand("paypal", "PayPal", ("paypal.com", "paypal.fr", "paypal.me"), ("paypal",), "LU", "payment"),
    Brand(
        "amazon",
        "Amazon",
        ("amazon.fr", "amazon.com", "amazon.de", "amazon.co.uk", "amazon.es", "amazon.it"),
        ("amazon",),
        "LU",
        "retail",
    ),
    Brand("leboncoin", "leboncoin", ("leboncoin.fr",), ("leboncoin", "le bon coin"), category="marketplace"),
    Brand("vinted", "Vinted", ("vinted.fr", "vinted.com"), ("vinted",), "LT", "marketplace"),
    Brand("booking", "Booking.com", ("booking.com",), ("booking",), "NL", "travel"),
    Brand("airbnb", "Airbnb", ("airbnb.fr", "airbnb.com"), ("airbnb",), "IE", "travel"),
    Brand("sncf", "SNCF Connect", ("sncf-connect.com", "sncf.com"), ("sncf",), category="travel"),
    Brand("netflix", "Netflix", ("netflix.com",), ("netflix",), "NL", "subscription"),
    Brand("apple", "Apple", ("apple.com", "icloud.com"), ("apple", "icloud", "itunes"), "IE", "tech"),
    Brand(
        "microsoft",
        "Microsoft",
        ("microsoft.com", "live.com", "outlook.com", "office.com"),
        ("microsoft", "outlook", "office 365"),
        "IE",
        "tech",
    ),
    Brand("google", "Google", ("google.com", "google.fr", "gmail.com"), ("google", "gmail"), "IE", "tech"),
    Brand("orange", "Orange", ("orange.fr", "orange.com", "sosh.fr"), ("orange",), category="telecom"),
    Brand("sfr", "SFR", ("sfr.fr",), ("sfr",), category="telecom"),
    Brand("free", "Free", ("free.fr",), ("free mobile", "freebox"), category="telecom"),
    Brand("bouygues", "Bouygues Telecom", ("bouyguestelecom.fr",), ("bouygues",), category="telecom"),
    Brand("edf", "EDF", ("edf.fr",), ("edf",), category="energy"),
    Brand("engie", "Engie", ("engie.fr", "engie.com"), ("engie",), category="energy"),
    Brand("totalenergies", "TotalEnergies", ("totalenergies.fr", "totalenergies.com"), ("totalenergies",), category="energy"),
)

BRANDS_BY_ID = {b.id: b for b in BRANDS}

# Words commonly appended to brand names in phishing domains.
PHISHING_DOMAIN_WORDS = (
    "secure",
    "securite",
    "security",
    "login",
    "connexion",
    "verify",
    "verification",
    "update",
    "account",
    "compte",
    "suivi",
    "tracking",
    "colis",
    "parcel",
    "livraison",
    "delivery",
    "support",
    "service",
    "client",
    "remboursement",
    "refund",
    "paiement",
    "payment",
    "facture",
    "billing",
    "amende",
    "renew",
    "unlock",
)

_KEYWORD_PATTERNS: list[tuple[re.Pattern[str], Brand]] = [
    (re.compile(r"(?<![\w])" + re.escape(k) + r"(?![\w])", re.IGNORECASE), b) for b in BRANDS for k in b.keywords
]


def official_labels() -> dict[str, Brand]:
    """Map of second-level label (e.g. 'laposte') -> brand, used for lookalike detection."""
    out: dict[str, Brand] = {}
    for b in BRANDS:
        for d in b.official_domains:
            if d.count(".") != 1:
                continue  # sub-labels such as "mabanque.bnpparibas" are too generic to compare
            label = d.split(".")[0]
            if len(label) >= 4:
                out.setdefault(label, b)
    return out


def brands_mentioned(text: str) -> list[Brand]:
    seen: dict[str, Brand] = {}
    for pattern, brand in _KEYWORD_PATTERNS:
        if brand.id not in seen and pattern.search(text):
            seen[brand.id] = brand
    return list(seen.values())


def brand_for_registrable_domain(registrable: str) -> Brand | None:
    registrable = registrable.lower()
    for b in BRANDS:
        for d in b.official_domains:
            if registrable == d or registrable.endswith("." + d):
                return b
    return None
