import type { Metadata, Viewport } from "next";
import "./globals.css";
import { SessionProvider } from "@/lib/session";

export const metadata: Metadata = {
  title: "TrustRelay",
  description: "Avant de faire confiance, vérifiez. — Before you trust it, check it.",
  robots: { index: false, follow: false }, // the authenticated app is not for search engines (public site: Phase 5)
};

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
