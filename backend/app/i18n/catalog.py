"""Localized texts for findings, verdicts, actions and missing information (French and English).

To add a language: add a column to each table below (or load from a JSON file per locale) — no engine change.
Wording rules: never say "safe", "sûr", "fiable à 100 %", "guaranteed"; always state limitations.
Legal/consumer-protection wording must be reviewed before launch (docs/STATUS.md, risk R-03).
"""

from __future__ import annotations

from typing import Any

SUPPORTED = ("fr", "en")

# code: (en_title, en_detail, fr_title, fr_detail)
FINDINGS: dict[str, tuple[str, str, str, str]] = {
    "url_listed_malicious": (
        "Listed as dangerous by a threat-intelligence source",
        "{source_name} lists this address as dangerous ({threat_type}).",
        "Signalé comme dangereux par une source de cybersécurité",
        "{source_name} répertorie cette adresse comme dangereuse ({threat_type}).",
    ),
    "url_userinfo_trick": (
        "The link hides its real destination",
        "The link uses the 'name@site' trick: everything before '@' is ignored and the real site is after it.",
        "Le lien cache sa vraie destination",
        "Le lien utilise l'astuce « nom@site » : tout ce qui précède « @ » est ignoré, le vrai site est après.",
    ),
    "url_ip_address_host": (
        "The link uses a raw IP address",
        "Legitimate organisations almost always use a domain name, not a numeric address.",
        "Le lien utilise une adresse IP brute",
        "Les organisations légitimes utilisent presque toujours un nom de domaine, pas une adresse numérique.",
    ),
    "url_no_https": (
        "The link is not encrypted (no HTTPS)",
        "Information you type on this page could be read by others. Never enter passwords or payment details there.",
        "Le lien n'est pas chiffré (pas de HTTPS)",
        "Les informations saisies sur cette page peuvent être interceptées. N'y saisissez jamais de mot de passe ni de données de paiement.",
    ),
    "url_unusual_port": (
        "The link uses an unusual technical port",
        "Ordinary websites rarely need this.",
        "Le lien utilise un port technique inhabituel",
        "Les sites ordinaires en ont rarement besoin.",
    ),
    "url_shortener": (
        "This is a shortened link",
        "Shortened links hide the final destination. We could only check the shortener itself unless the redirect was resolved.",
        "C'est un lien raccourci",
        "Un lien raccourci masque la destination finale. Seul le raccourcisseur a pu être vérifié si la redirection n'a pas été suivie.",
    ),
    "url_unrecognised_tld": (
        "The domain ending ({tld}) is not a recognised Internet extension",
        "It may be very new, or the address may not work at all; our offline list of extensions can lag behind.",
        "L'extension du domaine ({tld}) n'est pas une extension Internet reconnue",
        "Elle est peut-être très récente, ou l'adresse ne fonctionne pas ; notre liste hors ligne peut être en retard.",
    ),
    "url_high_abuse_tld": (
        "The domain ending ({tld}) is often used in scams",
        "Many legitimate sites use it too; on its own this is a weak signal.",
        "L'extension du domaine ({tld}) est souvent utilisée dans des arnaques",
        "Beaucoup de sites légitimes l'utilisent aussi ; seul, ce signal est faible.",
    ),
    "url_punycode_domain": (
        "The domain uses special characters that can imitate other letters",
        "Internationalised domains can look identical to a well-known name while being a different site.",
        "Le domaine utilise des caractères spéciaux pouvant imiter d'autres lettres",
        "Un domaine internationalisé peut ressembler exactement à un nom connu tout en étant un autre site.",
    ),
    "url_many_subdomains": (
        "The address is unusually long and layered",
        "Long chains of sub-domains are sometimes used to push the real domain out of view on phones.",
        "L'adresse est anormalement longue",
        "De longues chaînes de sous-domaines servent parfois à cacher le vrai domaine sur un écran de téléphone.",
    ),
    "url_official_domain": (
        "This is an official domain of {brand}",
        "The domain matches our list of {brand}'s official websites. This does not guarantee that the content of this specific page is genuine.",
        "C'est un domaine officiel de {brand}",
        "Le domaine figure dans notre liste des sites officiels de {brand}. Cela ne garantit pas que le contenu de cette page précise soit authentique.",
    ),
    "url_brand_in_subdomain": (
        "The link imitates {brand} but belongs to another site",
        "'{brand}' appears at the start of the address, but the site actually belongs to {registrable}.",
        "Le lien imite {brand} mais appartient à un autre site",
        "« {brand} » apparaît au début de l'adresse, mais le site appartient en réalité à {registrable}.",
    ),
    "url_lookalike_domain": (
        "The domain imitates {brand}",
        "The domain closely resembles {official} but is different — a common phishing technique.",
        "Le domaine imite {brand}",
        "Le domaine ressemble fortement à {official} mais il est différent : une technique d'hameçonnage courante.",
    ),
    "url_brand_keyword_domain": (
        "The domain uses the name {brand} without belonging to it",
        "{brand}'s official site is {official}. This domain combines the name with other words.",
        "Le domaine utilise le nom {brand} sans lui appartenir",
        "Le site officiel de {brand} est {official}. Ce domaine associe ce nom à d'autres mots.",
    ),
    "domain_recently_registered": (
        "The domain was registered very recently ({days} days ago)",
        "Scam sites are often created just before a campaign. Many new sites are legitimate, so this is one signal among others.",
        "Le domaine a été créé très récemment (il y a {days} jours)",
        "Les sites frauduleux sont souvent créés juste avant une campagne. Beaucoup de sites récents sont légitimes : c'est un signal parmi d'autres.",
    ),
    "domain_age_known": (
        "The domain has existed for {days} days",
        "Age alone says nothing about trustworthiness, but a long history makes a throw-away scam site less likely.",
        "Le domaine existe depuis {days} jours",
        "L'ancienneté ne prouve rien à elle seule, mais elle rend moins probable un site jetable.",
    ),
    "url_points_to_private_network": (
        "The link points to a private or internal network address",
        "Public websites do not resolve to private addresses. We did not connect to it.",
        "Le lien pointe vers une adresse de réseau privé",
        "Un site public ne pointe pas vers une adresse privée. Nous ne nous y sommes pas connectés.",
    ),
    "url_probe_refused": (
        "We did not open this link",
        "For safety reasons our checker refused to connect ({reason}).",
        "Nous n'avons pas ouvert ce lien",
        "Pour des raisons de sécurité, notre vérificateur a refusé de s'y connecter ({reason}).",
    ),
    "url_redirect_loop": (
        "The link redirects too many times",
        "Long redirect chains are used to evade filters.",
        "Le lien redirige trop de fois",
        "Les longues chaînes de redirection servent à échapper aux filtres.",
    ),
    "url_redirects_elsewhere": (
        "The link sends you to a different site: {final_domain}",
        "After {hops} redirect(s), the link ends on another domain. Check that this is the site you expect.",
        "Le lien vous envoie vers un autre site : {final_domain}",
        "Après {hops} redirection(s), le lien aboutit sur un autre domaine. Vérifiez que c'est bien le site attendu.",
    ),
    "tls_certificate_invalid": (
        "The site's security certificate is not valid",
        "Your browser would show a security warning. Do not continue.",
        "Le certificat de sécurité du site n'est pas valide",
        "Votre navigateur afficherait un avertissement de sécurité. Ne continuez pas.",
    ),
    "tls_certificate_very_new": (
        "The security certificate was issued {days} days ago",
        "New certificates are normal, but very new ones are common on short-lived scam sites.",
        "Le certificat de sécurité a été émis il y a {days} jours",
        "C'est courant, mais les certificats très récents sont fréquents sur les sites frauduleux éphémères.",
    ),
    "msg_requests_auth_code": (
        "It asks for a security code",
        "No bank, administration or delivery company will ever ask you to share a code received by SMS or in your app.",
        "Le message demande un code de sécurité",
        "Aucune banque, administration ou société de livraison ne vous demandera de communiquer un code reçu par SMS ou dans votre application.",
    ),
    "msg_requests_password": (
        "It asks for your password or login details",
        "Legitimate organisations never ask for your password by message or phone.",
        "Le message demande votre mot de passe ou vos identifiants",
        "Les organisations légitimes ne demandent jamais votre mot de passe par message ou par téléphone.",
    ),
    "msg_requests_card_details": (
        "It asks for bank-card details",
        "Never send your card number, expiry date or security code in reply to a message.",
        "Le message demande des données de carte bancaire",
        "N'envoyez jamais votre numéro de carte, sa date d'expiration ou son cryptogramme en réponse à un message.",
    ),
    "msg_safe_account_scam": (
        "It mentions a 'safe account' or asks you to stay on the line",
        "This is a typical fake bank-advisor scam: your bank will never ask you to move money to protect it.",
        "Il est question d'un « compte sécurisé » ou de ne pas raccrocher",
        "C'est typique de l'arnaque au faux conseiller : votre banque ne vous demandera jamais de déplacer votre argent pour le protéger.",
    ),
    "msg_artificial_urgency": (
        "It pressures you to act quickly",
        "Urgency is used to stop you from thinking or checking.",
        "Le message vous pousse à agir vite",
        "L'urgence sert à vous empêcher de réfléchir ou de vérifier.",
    ),
    "msg_threat_or_penalty": (
        "It threatens a penalty, blocking or legal action",
        "Intimidation is a common manipulation technique.",
        "Le message menace d'une sanction, d'un blocage ou de poursuites",
        "L'intimidation est une technique de manipulation courante.",
    ),
    "msg_payment_gift_card_or_voucher": (
        "It asks for payment with gift cards or prepaid vouchers",
        "Prepaid coupons (PCS, Transcash, Neosurf, gift cards) are untraceable and are never used by real organisations to collect payments.",
        "Le message demande un paiement en cartes cadeaux ou coupons prépayés",
        "Les coupons prépayés (PCS, Transcash, Neosurf, cartes cadeaux) sont intraçables et ne sont jamais utilisés par de vraies organisations pour encaisser un paiement.",
    ),
    "msg_payment_crypto": (
        "It asks you to pay or deposit in cryptocurrency",
        "Crypto transfers are practically impossible to reverse.",
        "Le message demande de payer ou déposer en cryptomonnaie",
        "Un transfert en cryptomonnaie est pratiquement impossible à annuler.",
    ),
    "msg_payment_money_transfer_service": (
        "It asks you to use a cash-transfer service",
        "Cash transfers to strangers are hard to recover.",
        "Le message demande d'utiliser un service de transfert d'argent",
        "Un transfert d'espèces à un inconnu est difficile à récupérer.",
    ),
    "msg_small_fee_to_release": (
        "It asks for a small fee to release a parcel or service",
        "Small 'customs' or 'delivery' fees are a classic way to collect card details.",
        "Le message réclame de petits frais pour débloquer un colis ou un service",
        "Les petits frais « de douane » ou « de livraison » sont une méthode classique pour récupérer des données de carte.",
    ),
    "msg_prize_or_refund_bait": (
        "It promises a prize or a refund",
        "Unexpected winnings or refunds are common bait.",
        "Le message promet un gain ou un remboursement",
        "Les gains ou remboursements inattendus sont un appât courant.",
    ),
    "msg_impersonates_authority": (
        "It claims to come from a bank, an authority or a support service",
        "Anyone can claim to be an advisor or official. Contact the organisation yourself using its official number.",
        "Le message se présente comme une banque, une autorité ou un service client",
        "N'importe qui peut se faire passer pour un conseiller. Contactez vous-même l'organisme via son numéro officiel.",
    ),
    "msg_off_channel_contact": (
        "It moves the conversation to a messaging app",
        "Moving to WhatsApp or Telegram removes the platform's protections.",
        "Le message vous fait passer sur une messagerie privée",
        "Passer sur WhatsApp ou Telegram fait perdre les protections de la plateforme.",
    ),
    "ad_guaranteed_returns": (
        "It promises guaranteed or risk-free returns",
        "No real investment can guarantee returns. This wording is a hallmark of investment fraud.",
        "L'annonce promet des gains garantis ou sans risque",
        "Aucun investissement réel ne peut garantir un rendement. Cette formulation est typique de la fraude à l'investissement.",
    ),
    "ad_unrealistic_returns": (
        "It promises unrealistic gains",
        "Promises like several percent per day or month, or doubling your money, are not realistic.",
        "L'annonce promet des gains irréalistes",
        "Plusieurs pour cent par jour ou par mois, ou doubler votre argent : ces promesses ne sont pas réalistes.",
    ),
    "ad_passive_income_pitch": (
        "It sells easy money or 'financial freedom'",
        "This pitch is common in fraudulent schemes.",
        "L'annonce vend de l'argent facile ou la « liberté financière »",
        "Cet argument est fréquent dans les montages frauduleux.",
    ),
    "ad_fake_endorsement": (
        "It claims an endorsement by a celebrity, media or authority",
        "Scam ads often misuse famous names and TV logos without permission.",
        "L'annonce revendique le soutien d'une célébrité, d'un média ou d'une autorité",
        "Les publicités frauduleuses utilisent souvent des noms célèbres et des logos de chaînes sans autorisation.",
    ),
    "ad_scarcity_pressure": (
        "It says places or stock are very limited",
        "Artificial scarcity is used to rush decisions.",
        "L'annonce affirme que les places ou le stock sont très limités",
        "La rareté artificielle sert à précipiter la décision.",
    ),
    "ad_crypto_investment": (
        "It promotes a trading robot or crypto-investment platform",
        "Check the platform on the AMF warning lists before sending any money.",
        "L'annonce promeut un robot de trading ou une plateforme crypto",
        "Vérifiez la plateforme sur les listes noires de l'AMF avant tout versement.",
    ),
    "ad_extreme_discount": (
        "It shows an extreme discount ({percent} %)",
        "Discounts this large on popular products are common on fake shops.",
        "L'annonce affiche une réduction extrême ({percent} %)",
        "Des réductions aussi fortes sur des produits populaires sont fréquentes sur les faux sites marchands.",
    ),
    "pay_off_platform": (
        "It asks you to pay outside the platform",
        "Paying outside Airbnb, Booking, leboncoin or Vinted removes their payment protection. This is the most common accommodation scam.",
        "Le message demande de payer en dehors de la plateforme",
        "Payer en dehors d'Airbnb, Booking, leboncoin ou Vinted supprime la protection de paiement. C'est l'arnaque à la location la plus courante.",
    ),
    "pay_changed_bank_details": (
        "It announces new bank details",
        "Changing an IBAN by message is the classic invoice / supplier fraud. Confirm by phone using a number you already know.",
        "Le message annonce un changement de coordonnées bancaires",
        "Changer de RIB par message est la fraude classique au faux fournisseur. Confirmez par téléphone avec un numéro que vous connaissez déjà.",
    ),
    "pay_friends_and_family": (
        "It asks for a 'friends and family' payment",
        "This PayPal mode has no buyer protection; scammers request it on purpose.",
        "Le message demande un paiement « entre proches »",
        "Ce mode PayPal n'offre aucune protection acheteur ; les escrocs le demandent exprès.",
    ),
    "pay_deposit_before_viewing": (
        "It asks for a deposit before any viewing",
        "Never pay to reserve accommodation you have not been able to verify.",
        "Le message réclame un acompte avant toute visite",
        "Ne payez jamais pour réserver un logement que vous n'avez pas pu vérifier.",
    ),
    "pay_bank_transfer_requested": (
        "It requests a bank transfer",
        "A transfer is hard to reverse; make sure the beneficiary is who they claim to be.",
        "Le message demande un virement",
        "Un virement est difficile à annuler ; assurez-vous que le bénéficiaire est bien celui qu'il prétend être.",
    ),
    "iban_invalid_checksum": (
        "The IBAN is not valid",
        "The account number fails the standard check digit test. It is mistyped or invented.",
        "L'IBAN n'est pas valide",
        "Le numéro de compte ne passe pas le contrôle standard : il est mal saisi ou inventé.",
    ),
    "beneficiary_not_verifiable": (
        "We cannot verify who owns this account ({country})",
        "TrustRelay cannot see who holds a bank account. Your bank may offer a beneficiary-name check (Verification of Payee) when you set up the transfer.",
        "Nous ne pouvons pas vérifier le titulaire de ce compte ({country})",
        "TrustRelay ne peut pas voir qui détient un compte. Votre banque peut vérifier le nom du bénéficiaire lors de la saisie du virement.",
    ),
    "iban_country_mismatch": (
        "The account is abroad ({country}) although the message claims to be {brand}",
        "A French organisation collecting payment on a foreign account is unusual.",
        "Le compte est à l'étranger ({country}) alors que le message se réclame de {brand}",
        "Il est inhabituel qu'un organisme français encaisse un paiement sur un compte étranger.",
    ),
    "impersonation_link_mismatch": (
        "It claims to be {brand} but links to {domain}",
        "{brand}'s official websites are: {official}.",
        "Il se réclame de {brand} mais renvoie vers {domain}",
        "Les sites officiels de {brand} sont : {official}.",
    ),
    "qr_contains_link": (
        "The QR code opens a website",
        "The destination was analysed as a link below.",
        "Le QR code ouvre un site web",
        "La destination est analysée comme un lien ci-dessous.",
    ),
    "qr_payment_request": (
        "The QR code is a bank-transfer request",
        "Scanning it pre-fills a transfer. Check the beneficiary and amount carefully.",
        "Le QR code est une demande de virement",
        "Le scanner pré-remplit un virement. Vérifiez soigneusement le bénéficiaire et le montant.",
    ),
    "qr_triggers_sms_or_call": (
        "The QR code starts an SMS or a phone call",
        "This can lead to premium-rate numbers.",
        "Le QR code déclenche un SMS ou un appel",
        "Cela peut mener à des numéros surtaxés.",
    ),
    "qr_wifi_network": (
        "The QR code connects you to a Wi-Fi network",
        "Only join networks you trust.",
        "Le QR code vous connecte à un réseau Wi-Fi",
        "Ne rejoignez que des réseaux de confiance.",
    ),
    "qr_crypto_payment": (
        "The QR code requests a cryptocurrency payment",
        "Crypto payments cannot be reversed.",
        "Le QR code demande un paiement en cryptomonnaie",
        "Un paiement en cryptomonnaie est irréversible.",
    ),
    "qr_authenticator_setup": (
        "The QR code adds an account to an authenticator app",
        "Someone asking you to scan this may be trying to take over an account.",
        "Le QR code ajoute un compte à une application d'authentification",
        "Quelqu'un qui vous demande de le scanner cherche peut-être à prendre le contrôle d'un compte.",
    ),
    "qr_contains_text": (
        "The QR code contains text",
        "The text was analysed like a message.",
        "Le QR code contient du texte",
        "Le texte a été analysé comme un message.",
    ),
    "ai_phishing_language": (
        "AI-assessed: phishing-style wording",
        "An AI model flagged this wording. AI signals can be wrong.",
        "Évaluation IA : formulation de type hameçonnage",
        "Un modèle d'IA a relevé cette formulation. Les signaux IA peuvent se tromper.",
    ),
    "ai_impersonation": (
        "AI-assessed: possible impersonation",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : possible usurpation d'identité",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
    "ai_urgency_pressure": (
        "AI-assessed: pressure to act",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : pression pour agir",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
    "ai_sensitive_data_request": (
        "AI-assessed: request for sensitive information",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : demande d'informations sensibles",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
    "ai_unusual_payment_request": (
        "AI-assessed: unusual payment request",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : demande de paiement inhabituelle",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
    "ai_too_good_to_be_true": (
        "AI-assessed: offer too good to be true",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : offre trop belle pour être vraie",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
    "ai_fake_endorsement": (
        "AI-assessed: possibly fake endorsement",
        "An AI model flagged this. AI signals can be wrong.",
        "Évaluation IA : soutien possiblement faux",
        "Un modèle d'IA l'a relevé. Les signaux IA peuvent se tromper.",
    ),
}

# Limitations by source family: (en, fr)
LIMITATIONS: dict[str, tuple[str, str]] = {
    "rules": (
        "Pattern-based check: it can miss new wording and can flag legitimate messages that use similar words.",
        "Vérification par motifs : elle peut manquer de nouvelles formulations et signaler des messages légitimes au vocabulaire proche.",
    ),
    "url_rules": (
        "Based only on how the address is written; it does not tell us who runs the site.",
        "Basé uniquement sur l'écriture de l'adresse ; cela ne dit pas qui exploite le site.",
    ),
    "brand_registry": (
        "Based on our hand-maintained list of official domains, which is not exhaustive.",
        "Basé sur notre liste, tenue à la main, des domaines officiels ; elle n'est pas exhaustive.",
    ),
    "reputation": (
        "Threat lists only contain threats already reported; a new scam may not be listed yet.",
        "Les listes de menaces ne contiennent que des menaces déjà signalées ; une arnaque récente peut ne pas y figurer.",
    ),
    "rdap": (
        "Registration data comes from the domain registry and can be incomplete for some extensions.",
        "Les données d'enregistrement proviennent du registre et peuvent être incomplètes pour certaines extensions.",
    ),
    "probe": (
        "Checked from our servers at one point in time; the site may behave differently for you or later.",
        "Vérifié depuis nos serveurs à un instant donné ; le site peut se comporter autrement pour vous ou plus tard.",
    ),
    "iban": (
        "Only the format and check digits are verified, not who owns the account.",
        "Seuls le format et la clé de contrôle sont vérifiés, pas le titulaire du compte.",
    ),
    "qr": ("We read what the QR code contains; we did not act on it.", "Nous lisons le contenu du QR code sans l'exécuter."),
    "ai": (
        "Generated by an AI model and only kept when it quotes the content exactly. AI can misjudge context.",
        "Produit par un modèle d'IA et conservé uniquement s'il cite exactement le contenu. L'IA peut mal interpréter le contexte.",
    ),
}

VERDICTS: dict[str, tuple[str, str, str, str, str, str]] = {
    # code: (en_title, en_summary, en_simple, fr_title, fr_summary, fr_simple)
    "known_malicious": (
        "Known dangerous",
        "At least one independent security source already lists this as dangerous.",
        "This is known to be a trap. Don't click, don't reply, and tell an adult you trust.",
        "Dangereux connu",
        "Au moins une source de sécurité indépendante le répertorie déjà comme dangereux.",
        "C'est un piège connu. Ne clique pas, ne réponds pas et parles-en à un adulte de confiance.",
    ),
    "strong_suspicious": (
        "Strong warning signs",
        "We found strong signs commonly seen in scams. It is not listed as a known threat, but treat it as a probable scam.",
        "This looks a lot like a trick to get money or passwords. Don't click or reply; ask an adult.",
        "Signaux d'alerte forts",
        "Nous avons trouvé des signaux forts, typiques des arnaques. Ce n'est pas répertorié comme menace connue, mais considérez-le comme une arnaque probable.",
        "Cela ressemble beaucoup à une ruse pour obtenir de l'argent ou des mots de passe. Ne clique pas, ne réponds pas, demande à un adulte.",
    ),
    "moderate_warning": (
        "Some warning signs",
        "Some elements call for caution. Verify through an official channel before acting.",
        "Some things here look odd. Check with an adult before doing anything.",
        "Quelques signaux d'alerte",
        "Certains éléments appellent à la prudence. Vérifiez par un canal officiel avant d'agir.",
        "Certaines choses semblent bizarres. Vérifie avec un adulte avant de faire quoi que ce soit.",
    ),
    "insufficient_information": (
        "Not enough information",
        "We could not check enough to give an opinion. That does not mean it is safe.",
        "We couldn't check this properly. Ask an adult before trusting it.",
        "Informations insuffisantes",
        "Nous n'avons pas pu vérifier suffisamment pour nous prononcer. Cela ne signifie pas que c'est sans danger.",
        "Nous n'avons pas pu bien vérifier. Demande à un adulte avant de lui faire confiance.",
    ),
    "no_known_warning_signals": (
        "No known warning signs",
        "Our checks found no known warning signs. This is not a guarantee: new scams may not be detected yet.",
        "We didn't spot anything wrong, but stay careful and ask if something feels strange.",
        "Aucun signal d'alerte connu",
        "Nos vérifications n'ont relevé aucun signal d'alerte connu. Ce n'est pas une garantie : une arnaque récente peut ne pas encore être détectée.",
        "Nous n'avons rien vu d'anormal, mais reste prudent et demande si quelque chose te paraît étrange.",
    ),
}

ACTIONS: dict[str, tuple[str, str]] = {
    "action_do_not_interact": (
        "Do not click, reply or call back. Delete the message. If you already clicked or entered information, open 'I already acted' for next steps.",
        "Ne cliquez pas, ne répondez pas, ne rappelez pas. Supprimez le message. Si vous avez déjà cliqué ou saisi des informations, ouvrez « J'ai déjà agi » pour la marche à suivre.",
    ),
    "action_never_share_codes": (
        "Never share a code, password or card details. Hang up or stop replying, then contact your bank using the number on your card.",
        "Ne communiquez jamais de code, mot de passe ou données de carte. Raccrochez ou cessez de répondre, puis contactez votre banque au numéro inscrit sur votre carte.",
    ),
    "action_do_not_pay_verify_official": (
        "Do not pay. Contact the organisation yourself through its official website or app — not using links or numbers from this message.",
        "Ne payez pas. Contactez vous-même l'organisme via son site ou son application officiels — pas avec les liens ou numéros de ce message.",
    ),
    "action_verify_independently": (
        "Check independently before acting: open the official app or type the official address yourself.",
        "Vérifiez de manière indépendante avant d'agir : ouvrez l'application officielle ou tapez vous-même l'adresse officielle.",
    ),
    "action_stay_cautious": (
        "Stay cautious: only proceed if you expected this, and never share codes or passwords.",
        "Restez prudent : ne poursuivez que si vous l'attendiez, et ne communiquez jamais de code ni de mot de passe.",
    ),
}

MISSING: dict[str, tuple[str, str]] = {
    "no_reputation_source": (
        "No independent threat-intelligence source could check the link.",
        "Aucune source indépendante de cybersécurité n'a pu vérifier le lien.",
    ),
    "links_not_checked_by_reputation_source": (
        "Links could not be checked against threat lists.",
        "Les liens n'ont pas pu être comparés aux listes de menaces.",
    ),
    "domain_age_unavailable": ("Domain registration date unavailable.", "Date de création du domaine indisponible."),
    "redirects_not_resolved": (
        "We did not follow the link to its final destination.",
        "Nous n'avons pas suivi le lien jusqu'à sa destination finale.",
    ),
    "shortened_link_not_resolved": (
        "The real destination of the shortened link is unknown.",
        "La vraie destination du lien raccourci est inconnue.",
    ),
    "certificate_not_checked": (
        "The site's security certificate was not checked.",
        "Le certificat de sécurité du site n'a pas été vérifié.",
    ),
    "image_text_not_extracted": ("We could not read text from the image.", "Nous n'avons pas pu lire le texte de l'image."),
    "ai_disabled": (
        "AI reading is turned off, so the image could not be read.",
        "La lecture par IA est désactivée ; l'image n'a pas pu être lue.",
    ),
    "qr_not_decoded": ("No QR code could be read.", "Aucun QR code n'a pu être lu."),
    "url_not_parseable": (
        "The address could not be understood as a web link.",
        "L'adresse n'a pas pu être interprétée comme un lien web.",
    ),
    "nothing_analysable": ("There was not enough content to analyse.", "Le contenu était insuffisant pour être analysé."),
    "beneficiary_identity_unverified": (
        "The identity of the account holder is unknown to us.",
        "L'identité du titulaire du compte nous est inconnue.",
    ),
}

CONFIDENCE: dict[str, tuple[str, str]] = {
    "low": ("Low confidence", "Confiance faible"),
    "medium": ("Medium confidence", "Confiance moyenne"),
    "high": ("High confidence", "Confiance élevée"),
}

SOURCE_NAMES = {
    "google_safe_browsing": "Google Safe Browsing",
    "urlhaus": "abuse.ch URLhaus",
    "trustrelay_blocklist": "TrustRelay blocklist",
    "mock_reputation": "Test source (development)",
    "rdap": "RDAP domain registry",
    "mock_rdap": "Test registry (development)",
    "link_probe": "TrustRelay link check",
    "tls_check": "TrustRelay certificate check",
    "qr_decoder": "QR decoder",
}


class _Safe(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "…"


def lang(code: str | None) -> str:
    return code if code in SUPPORTED else "fr"


def _i(language: str) -> int:
    return 0 if lang(language) == "en" else 1


def source_family(source: str) -> str:
    if source.startswith("rules:brand"):
        return "brand_registry"
    if source.startswith("rules:iban"):
        return "iban"
    if source == "rules:website":
        return "url_rules"
    if source.startswith("rules"):
        return "rules"
    if source.startswith("ai:"):
        return "ai"
    if source in ("rdap", "mock_rdap"):
        return "rdap"
    if source in ("link_probe", "tls_check"):
        return "probe"
    if source == "qr_decoder":
        return "qr"
    return "reputation"


def render_finding(code: str, source: str, params: dict[str, Any], language: str) -> dict[str, str]:
    i = _i(language)
    texts = FINDINGS.get(code, (code, "", code, ""))
    p = _Safe({**params, "source_name": SOURCE_NAMES.get(source, source)})
    return {
        "title": texts[i * 2].format_map(p),
        "detail": texts[i * 2 + 1].format_map(p),
        "limitation": LIMITATIONS[source_family(source)][i],
        "source_name": SOURCE_NAMES.get(source, "AI" if source.startswith("ai:") else source),
    }


def render_verdict(verdict: str, language: str, simple: bool = False) -> dict[str, str]:
    v = VERDICTS[verdict]
    off = 0 if lang(language) == "en" else 3
    return {"title": v[off], "summary": v[off + 2] if simple else v[off + 1]}


def render_action(code: str, language: str) -> str:
    return ACTIONS[code][_i(language)]


def render_missing(code: str, language: str) -> str:
    return MISSING.get(code, (code, code))[_i(language)]


def render_confidence(code: str, language: str) -> str:
    return CONFIDENCE[code][_i(language)]
