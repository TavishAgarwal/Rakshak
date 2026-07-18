import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // ── Security headers (Must-Fix #7 from security audit) ──────────
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          // Prevent MIME-type sniffing
          { key: "X-Content-Type-Options", value: "nosniff" },
          // Prevent clickjacking
          { key: "X-Frame-Options", value: "DENY" },
          // HSTS for secure transport
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
          // Enable browser XSS filter
          { key: "X-XSS-Protection", value: "1; mode=block" },
          // Restrict referrer information
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          // CSP: restrict sources for scripts, styles, connections
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "connect-src 'self' ws://localhost:* http://localhost:* ws://127.0.0.1:* http://127.0.0.1:*",
              "img-src 'self' data:",
              "font-src 'self'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
            ].join("; "),
          },
          // Block embedding in other origins
          { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
          // Restrict resource sharing
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      { source: "/api/:path*", destination: "http://127.0.0.1:8000/api/:path*" },
      { source: "/graph/:path*", destination: "http://127.0.0.1:8000/graph/:path*" },
      { source: "/graph", destination: "http://127.0.0.1:8000/graph" },
      { source: "/entity/:path*", destination: "http://127.0.0.1:8000/entity/:path*" },
      { source: "/query", destination: "http://127.0.0.1:8000/query" },
      { source: "/redteam/:path*", destination: "http://127.0.0.1:8000/redteam/:path*" },
      { source: "/simulation/:path*", destination: "http://127.0.0.1:8000/simulation/:path*" },
      { source: "/health", destination: "http://127.0.0.1:8000/health" }
    ];
  },
};

export default nextConfig;