/** @type {import('next').NextConfig} */
// NOTE: This is a deliberately-vulnerable TEACHING artefact for IFT542. Localhost only.
const nextConfig = {
  reactStrictMode: true,
  // [VULN: Debug mode on — Task 3] Framework build errors / source are exposed in this build.
  // productionBrowserSourceMaps kept on so stack traces map to source during the demo.
  productionBrowserSourceMaps: true,
  // Uploads are written to ./uploads on local disk by the upload route handler.
  experimental: {
    // Allow large-ish multipart bodies for the document-upload demo.
    serverActions: { bodySizeLimit: "10mb" },
  },
};

module.exports = nextConfig;
