"""French and English rule patterns for message, advertisement and payment analysis.

Each rule is explainable: it reports the exact excerpt that matched. Patterns are deliberately conservative;
coverage and precision are measured in Phase 2 against a labelled benchmark (not yet built — see STATUS.md).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.analysis.types import Confidence, Severity


@dataclass(frozen=True)
class Rule:
    code: str
    severity: Severity
    confidence: Confidence
    patterns: tuple[re.Pattern[str], ...]


def _p(*exprs: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(e, re.IGNORECASE) for e in exprs)


S, M = Severity.STRONG, Severity.MODERATE
H, MED, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

MESSAGE_RULES: tuple[Rule, ...] = (
    Rule("msg_requests_auth_code", S, H, _p(
        r"\b(?:code|cod[ée]) (?:de )?(?:v[ée]rification|validation|confirmation|s[ée]curit[ée]|sms|re[çc]u)\b.{0,40}\b(?:communiqu|transmet|donn|envoy|indiqu|dict|partag|lire)",
        r"\b(?:communiqu|transmet|donn|envoy|indiqu|dict|partag|lis)\w*\b.{0,40}\bcode\b.{0,25}\b(?:re[çc]u|sms|s[ée]curit[ée]|validation|confirmation)",
        r"\b(?:share|send|give|read|tell)\b.{0,30}\b(?:verification|security|one[- ]time|otp|2fa|sms) code\b",
        r"\bvalider? (?:l'|la )?op[ée]ration (?:sur|dans) (?:votre|ton) application\b.{0,60}\b(?:annul|bloqu|s[ée]curis)",
    )),
    Rule("msg_requests_password", S, H, _p(
        r"\b(?:confirm|saisi|indiqu|communiqu|v[ée]rifi|entr|renseign)\w*\b.{0,40}\b(?:mot de passe|identifiants?|code (?:secret|confidentiel|d'acc[eè]s))\b",
        r"\b(?:confirm|enter|verify|provide|update|send)\b.{0,30}\b(?:password|passcode|login details|credentials|pin)\b",
    )),
    Rule("msg_requests_card_details", S, H, _p(
        r"\b(?:num[ée]ro|coordonn[ée]es|donn[ée]es) (?:de |de votre |de ta )?carte (?:bancaire|bleue|de cr[ée]dit)?\b",
        r"\b(?:cryptogramme|cvv|cvc|date d'expiration)\b",
        r"\b(?:card number|card details|security code|cvv|cvc|expiry date)\b",
    )),
    Rule("msg_safe_account_scam", S, H, _p(
        r"\bcompte (?:s[ée]curis[ée]|de s[ée]curit[ée]|refuge|temporaire)\b",
        r"\b(?:safe|secure|holding) account\b",
        r"\bne (?:raccrochez|raccroche) pas\b",
        r"\b(?:conseiller|service) (?:anti-?fraude|fraude|s[ée]curit[ée])\b.{0,80}\b(?:virement|transf[ée]r|d[ée]placer)",
    )),
    Rule("msg_artificial_urgency", M, MED, _p(
        r"\b(?:sous|dans les|d'ici|avant) (?:\d{1,2}|vingt-quatre|quarante-huit) ?(?:h|heures?|minutes?|jours?)\b",
        r"\b(?:imm[ée]diatement|sans d[ée]lai|au plus vite|dernier (?:avis|rappel)|derni[eè]re relance|urgent|action requise|aujourd'hui seulement)\b",
        r"\b(?:within \d{1,2} ?(?:hours?|minutes?|days?)|immediately|urgent|final notice|last reminder|act now|action required|expires today)\b",
    )),
    Rule("msg_threat_or_penalty", M, MED, _p(
        r"\b(?:suspendu|bloqu[ée]|ferm[ée]|supprim[ée]|r[ée]sili[ée]|d[ée]sactiv[ée])\w*\b.{0,30}\b(?:compte|carte|abonnement|ligne|acc[eè]s)\b",
        r"\b(?:compte|carte|abonnement|ligne|acc[eè]s)\b.{0,30}\b(?:sera|va [êe]tre|a [ée]t[ée]) (?:suspendu|bloqu[ée]|ferm[ée]|supprim[ée]|r[ée]sili[ée]|d[ée]sactiv[ée])",
        r"\b(?:poursuites?|huissier|majoration|amende major[ée]e|plainte|gendarmerie|police|mandat d'arr[eê]t|saisie)\b",
        r"\b(?:account|card|subscription)\b.{0,30}\b(?:will be|has been) (?:suspended|locked|closed|terminated|deleted)\b",
        r"\b(?:legal action|arrest warrant|bailiff|penalty|lawsuit)\b",
    )),
    Rule("msg_payment_gift_card_or_voucher", S, H, _p(
        r"\b(?:carte|coupon|recharge|ticket)s? (?:pcs|transcash|neosurf|paysafecard|toneo|google play|itunes|apple|steam|amazon)\b",
        r"\b(?:pcs mastercard|transcash|neosurf|paysafecard|toneo first)\b",
        r"\b(?:gift ?cards?|steam card|itunes card|google play card)\b",
    )),
    Rule("msg_payment_crypto", S, MED, _p(
        r"\b(?:bitcoin|btc|usdt|tether|ethereum|crypto-?monnaies?|cryptos?|portefeuille crypto|wallet)\b.{0,60}\b(?:envoy|vers|pay|transf|d[ée]pos|send|deposit)",
        r"\b(?:envoy|pay|transf|d[ée]pos|send|deposit)\w*\b.{0,60}\b(?:bitcoin|btc|usdt|tether|ethereum|crypto)",
    )),
    Rule("msg_payment_money_transfer_service", M, MED, _p(
        r"\b(?:western union|moneygram|ria money|worldremit|mandat cash)\b",
    )),
    Rule("msg_small_fee_to_release", M, MED, _p(
        r"\b(?:frais|droits?) (?:de (?:livraison|douane|r[ée]exp[ée]dition|traitement|port)|suppl[ée]mentaires?)\b.{0,60}\d+[,.]\d{2} ?(?:€|eur)",
        r"\b(?:pay\w*|r[ée]gl\w*)\b.{0,40}\b[0-4][,.]\d{2} ?(?:€|eur)",
        r"\b(?:customs|delivery|shipping|redelivery) fee\b",
    )),
    Rule("msg_prize_or_refund_bait", M, MED, _p(
        r"\b(?:vous avez (?:gagn[ée]|[ée]t[ée] s[ée]lectionn[ée])|f[ée]licitations|remboursement en attente|trop[- ]per[çc]u|gagnant)\b",
        r"\b(?:you (?:have )?won|congratulations|you've been selected|refund (?:is )?pending|claim your (?:prize|reward|refund))\b",
    )),
    Rule("msg_impersonates_authority", M, MED, _p(
        r"\b(?:conseiller bancaire|service (?:client|des fraudes)|banque de france|tr[ée]sor public|minist[eè]re|gendarmerie|police nationale|douane)\b",
        r"\b(?:bank advisor|fraud department|tax office|hmrc|irs|customs office)\b",
    )),
    Rule("msg_off_channel_contact", M, L, _p(
        r"\b(?:contact(?:ez|e)[- ]moi|[ée]cri(?:vez|s)[- ]moi|r[ée]pond(?:ez|s))\b.{0,30}\b(?:whatsapp|telegram|signal)\b",
        r"\b(?:contact|text|message) me (?:on|via) (?:whatsapp|telegram|signal)\b",
    )),
)

ADVERT_RULES: tuple[Rule, ...] = (
    Rule("ad_guaranteed_returns", S, H, _p(
        r"\b(?:rendements?|gains?|profits?|revenus?) (?:garanti|assur[ée]|sans risque|fixes?)\w*\b",
        r"\b(?:guaranteed|risk[- ]free) (?:returns?|profits?|income|gains?)\b",
        r"\bsans (?:aucun )?risque\b.{0,40}\b(?:investi|placement|gain)",
    )),
    Rule("ad_unrealistic_returns", S, MED, _p(
        r"\b\d{1,3} ?% (?:par|chaque|/) ?(?:jour|semaine|mois)\b",
        r"\b\d{1,3} ?% (?:per|a|every) (?:day|week|month)\b",
        r"\b(?:doubl|tripl)\w* (?:votre|ton|your) (?:argent|capital|mise|money|investment)\b",
        r"\b(?:\d{3,6} ?€|€ ?\d{3,6}) (?:par|chaque) (?:jour|semaine)\b",
    )),
    Rule("ad_passive_income_pitch", M, MED, _p(
        r"\b(?:revenus? passifs?|devenir riche|libert[ée] financi[eè]re|argent facile|sans rien faire)\b",
        r"\b(?:passive income|get rich|financial freedom|easy money|work from home and earn)\b",
    )),
    Rule("ad_fake_endorsement", M, MED, _p(
        r"\b(?:vu (?:sur|à la) (?:tf1|m6|bfm|france ?2|la t[ée]l[ée]|tv)|approuv[ée] par|recommand[ée] par (?:le gouvernement|l'[ée]tat|la banque de france))\b",
        r"\b(?:as seen on (?:tv|bbc|cnn)|endorsed by|approved by the government)\b",
        r"\b(?:a investi|a r[ée]v[ée]l[ée] (?:son|sa) (?:secret|m[ée]thode)|r[ée]v[ée]lation choc|interview (?:choc|censur[ée]e))\b",
        r"\b(?:revealed (?:his|her) secret|shocking interview|banned interview)\b",
    )),
    Rule("ad_scarcity_pressure", M, L, _p(
        r"\b(?:places? limit[ée]es?|plus que \d+ (?:places?|articles?)|stock limit[ée]|offre expire|derni[eè]res? (?:heures?|pi[eè]ces?))\b",
        r"\b(?:only \d+ (?:left|spots?)|limited (?:spots|places|stock)|offer ends (?:today|tonight|soon))\b",
    )),
    Rule("ad_crypto_investment", M, MED, _p(
        r"\b(?:plateforme|robot|algorithme|ia) (?:de )?(?:trading|investissement)\b",
        r"\b(?:trading (?:bot|platform|robot)|ai trading|crypto investment platform)\b",
    )),
)

PAYMENT_RULES: tuple[Rule, ...] = (
    Rule("pay_off_platform", S, H, _p(
        r"\b(?:payer|paiement|r[ée]gler|virement)\b.{0,40}\b(?:hors (?:de )?(?:la )?plateforme|en dehors (?:de |d')?(?:la )?(?:plateforme|airbnb|booking|leboncoin|vinted|abritel))\b",
        r"\b(?:en dehors|hors) (?:de |d')?(?:la )?(?:airbnb|booking|leboncoin|vinted|abritel)\b",
        r"\b(?:pay|payment)\b.{0,30}\b(?:outside (?:of )?(?:the )?(?:platform|airbnb|booking|app))\b",
        r"\b(?:directement (?:au|chez le) propri[ée]taire|pay the (?:owner|landlord) directly)\b",
    )),
    Rule("pay_changed_bank_details", S, H, _p(
        r"\b(?:changement|modification|nouvelles?|mise à jour) (?:de |des |du )?(?:rib|iban|coordonn[ée]es bancaires|compte bancaire)\b",
        r"\b(?:new|updated|changed) (?:bank details|iban|account details|bank account)\b",
    )),
    Rule("pay_friends_and_family", S, MED, _p(
        r"\b(?:entre proches|amis (?:et|&) famille|friends (?:and|&) family)\b",
    )),
    Rule("pay_deposit_before_viewing", M, MED, _p(
        r"\b(?:acompte|caution|d[ée]p[oô]t de garantie|r[ée]servation)\b.{0,60}\b(?:avant (?:la )?visite|sans visite|pour (?:bloquer|r[ée]server))",
        r"\b(?:deposit|advance payment)\b.{0,40}\b(?:before (?:viewing|visit)|to (?:hold|secure|reserve))\b",
    )),
    Rule("pay_bank_transfer_requested", M, L, _p(
        r"\b(?:virement (?:bancaire|instantan[ée]|imm[ée]diat)|faire un virement|wire transfer|bank transfer)\b",
    )),
)

ALL_RULE_CODES = {r.code for r in MESSAGE_RULES + ADVERT_RULES + PAYMENT_RULES}


def match_rules(rules: tuple[Rule, ...], text: str, max_excerpt: int = 120) -> list[tuple[Rule, list[str]]]:
    hits: list[tuple[Rule, list[str]]] = []
    for rule in rules:
        excerpts: list[str] = []
        for pattern in rule.patterns:
            for m in pattern.finditer(text):
                excerpt = m.group(0).strip()[:max_excerpt]
                if excerpt and excerpt not in excerpts:
                    excerpts.append(excerpt)
                if len(excerpts) >= 3:
                    break
        if excerpts:
            hits.append((rule, excerpts))
    return hits


DISCOUNT_RE = re.compile(r"(?:-\s?|jusqu'à\s|up to\s|r[ée]duction de\s)?(\d{2})\s?%\s?(?:de r[ée]duction|off|de remise|r[ée]duction)?", re.IGNORECASE)
