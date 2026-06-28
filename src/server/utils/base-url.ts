/**
 * Base URL for internal server-to-server calls (pg-executer, domain-info)
 * Because these need the local loopback and shouldn't go thru reverse proxy
 * Override with DL_INTERNAL_BASE_URL for non-standard local setups
 *
 * @returns The internal base URL (e.g. "http://localhost:3000")
 */
export function getInternalBaseUrl(): string {
  const override = process.env['DL_INTERNAL_BASE_URL'];
  if (override) {
    return override;
  }

  const port = process.env['NITRO_PORT'] || process.env['PORT'] || '3000';
  return `http://localhost:${port}`;
}
