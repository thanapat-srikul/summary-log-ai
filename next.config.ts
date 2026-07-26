import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: process.env.SELF_HOSTED_BUILD === "1" ? "standalone" : undefined,
};

export default nextConfig;
