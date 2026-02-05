export const getFrontendBaseUrl = (req) => {
  if (process.env.FRONTEND_BASE_URL) return process.env.FRONTEND_BASE_URL;
  if (process.env.CORS_ORIGIN) return process.env.CORS_ORIGIN.split(",")[0];
  if (req) return `${req.protocol}://${req.get("host")}`;
  return "http://localhost:5173";
};

export const buildFrontendUrl = (path, req) => {
  const baseUrl = getFrontendBaseUrl(req).replace(/\/$/, "");
  return `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
};
