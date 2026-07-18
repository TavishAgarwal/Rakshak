import type { Metadata } from "next";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "RAKSHAK — Cyber Resilience Intelligence",
  description:
    "AI-Driven Cyber Resilience Intelligence Platform for Indian Critical National Infrastructure",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-bg-void text-text-primary font-body antialiased">
        {children}
      </body>
    </html>
  );
}
