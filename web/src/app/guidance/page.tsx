"use client";

import { Shell } from "@/components/Shell";
import { useSession } from "@/lib/session";

// Official French resources. Every link and phone number must be re-verified before launch and on each
// knowledge-base review (owner: customer-success lead, Phase 4). Do not add unofficial "recovery" services.
const CONTENT = {
  fr: {
    title: "Conseils de sécurité",
    habits: ["Ne communiquez jamais un code reçu par SMS, même à quelqu'un qui se dit de votre banque.", "Votre banque ne vous demandera jamais de virer votre argent vers un « compte sécurisé ».", "Tapez vous-même l'adresse du site officiel ou utilisez l'application officielle plutôt que de cliquer sur un lien.", "Méfiez-vous de l'urgence, des menaces et des offres trop belles.", "Pour une location, ne payez jamais en dehors de la plateforme de réservation."],
    acted: "Si vous avez déjà agi",
    steps: [
      ["Vous avez donné des coordonnées bancaires ou fait un paiement", "Appelez immédiatement votre banque au numéro inscrit au dos de votre carte ou dans son application officielle, faites opposition si nécessaire. Aucun remboursement n'est garanti, mais plus vous agissez tôt, plus les chances sont grandes."],
      ["Vous avez saisi un mot de passe", "Changez-le tout de suite sur le site officiel, ainsi que partout où vous l'avez réutilisé, et activez la double authentification."],
      ["Vous avez communiqué un code reçu par SMS", "Contactez votre banque ou le service concerné sans attendre : ce code a peut-être servi à valider une opération."],
      ["Vous avez installé une application suspecte", "Déconnectez l'appareil d'Internet, désinstallez l'application et demandez de l'aide via Cybermalveillance.gouv.fr."],
    ],
    report: "Signaler et se faire aider",
    links: [
      ["Cybermalveillance.gouv.fr — assistance et conseils", "https://www.cybermalveillance.gouv.fr/"],
      ["17Cyber — aide aux victimes de cybermalveillance", "https://17cyber.gouv.fr/"],
      ["Perceval — signaler une fraude à la carte bancaire", "https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/signaler-fraude-carte-bancaire-perceval"],
      ["Pharos — signaler un contenu illicite en ligne", "https://www.internet-signalement.gouv.fr/"],
      ["SignalConso — signaler un problème avec une entreprise", "https://signal.conso.gouv.fr/"],
      ["AMF — listes noires des sites d'investissement non autorisés", "https://www.amf-france.org/fr/espace-epargnants/proteger-son-epargne/listes-noires-et-mises-en-garde"],
    ],
    sms: "SMS ou appel frauduleux : transférez le SMS au 33700 (service gratuit de signalement des spams).",
    limits: "TrustRelay n'est ni une banque, ni la police, ni un avocat. Nous ne pouvons pas récupérer de fonds ni intervenir à votre place.",
  },
  en: {
    title: "Safety guidance",
    habits: ["Never share a code you received by SMS, even with someone who says they are your bank.", "Your bank will never ask you to transfer your money to a “safe account”.", "Type the official address yourself or use the official app instead of clicking a link.", "Be wary of urgency, threats and offers that are too good to be true.", "For rentals, never pay outside the booking platform."],
    acted: "If you already acted",
    steps: [
      ["You gave bank details or made a payment", "Call your bank immediately using the number on the back of your card or in its official app, and block the card if needed. No refund is guaranteed, but acting early improves the chances."],
      ["You entered a password", "Change it now on the official site, and anywhere you reused it, then turn on two-factor authentication."],
      ["You shared a code received by SMS", "Contact your bank or the service concerned right away: the code may have been used to approve a transaction."],
      ["You installed a suspicious app", "Disconnect the device from the Internet, uninstall the app and get help via Cybermalveillance.gouv.fr."],
    ],
    report: "Report and get help (France)",
    links: [
      ["Cybermalveillance.gouv.fr — assistance and advice", "https://www.cybermalveillance.gouv.fr/"],
      ["17Cyber — help for cybercrime victims", "https://17cyber.gouv.fr/"],
      ["Perceval — report bank-card fraud", "https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/signaler-fraude-carte-bancaire-perceval"],
      ["Pharos — report illegal online content", "https://www.internet-signalement.gouv.fr/"],
      ["SignalConso — report a problem with a company", "https://signal.conso.gouv.fr/"],
      ["AMF — blacklists of unauthorised investment websites", "https://www.amf-france.org/fr/espace-epargnants/proteger-son-epargne/listes-noires-et-mises-en-garde"],
    ],
    sms: "Fraudulent SMS or call: forward the SMS to 33700 (free spam reporting service in France).",
    limits: "TrustRelay is not a bank, the police or a lawyer. We cannot recover funds or act on your behalf.",
  },
};

export default function GuidancePage() {
  return <Shell><Guidance /></Shell>;
}

function Guidance() {
  const { locale } = useSession();
  const c = CONTENT[locale];
  return (
    <div className="stack">
      <h1>{c.title}</h1>
      <section className="card"><ul>{c.habits.map((h) => <li key={h}>{h}</li>)}</ul></section>
      <h2 id="already-acted">{c.acted}</h2>
      <div className="stack">{c.steps.map(([title, body]) => (
        <section key={title} className="card"><h3 style={{ marginTop: 0 }}>{title}</h3><p style={{ margin: 0 }}>{body}</p></section>
      ))}</div>
      <h2>{c.report}</h2>
      <section className="card stack">
        <ul>{c.links.map(([label, href]) => <li key={href}><a href={href} target="_blank" rel="noopener noreferrer">{label}</a></li>)}</ul>
        <p>{c.sms}</p>
      </section>
      <p className="small muted">{c.limits}</p>
    </div>
  );
}
