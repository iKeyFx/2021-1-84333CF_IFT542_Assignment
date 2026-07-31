/** @type {import('next').NextConfig} */
// NOTE: Localhost-only TEACHING artefact for IFT542. Do not deploy.
const isDev = process.env.NODE_ENV !== "production";

// Mirrors staticSecurityHeaders() in src/lib/security-headers.ts. Duplicated as
// plain data because next.config.js is CommonJS and cannot import the .ts
// module; tests/security-headers.test.ts asserts both surfaces agree.
const staticHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  // MUST match staticSecurityHeaders() in src/lib/security-headers.ts, and MUST
  // NOT be "no-referrer" — under that policy browsers send `Origin: null` on
  // every plain <form> POST, which checkOrigin() rejects as a CSRF attempt. See
  // the long comment in that file.
  { key: "Referrer-Policy", value: "same-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
];

if (!isDev) {
  staticHeaders.push({
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains",
  });
}

const nextConfig = {
  reactStrictMode: true,

  // [FIXED — Task 3: debug mode on]
  // Browser source maps are no longer shipped in a production build, so the
  // server's original source cannot be reconstructed from a deployed bundle.
  productionBrowserSourceMaps: false,

  // Uploads are written to ./uploads on local disk by the upload route handler.
  experimental: {
    // Allow large-ish multipart bodies for the document-upload demo.
    serverActions: { bodySizeLimit: "10mb" },
  },

  // src/middleware.ts deliberately does NOT match /api/* — its Set-Cookie
  // handling would clobber the session cookie /api/login sets, and JSON
  // responses need no nonce-based CSP. Those routes get their headers here.
  async headers() {
    return [
      {
        source: "/api/:path*",
        headers: [
          ...staticHeaders,
          // API responses carry no markup, so the policy can be maximally tight.
          {
            key: "Content-Security-Policy",
            value: "default-src 'none'; frame-ancestors 'none'",
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
