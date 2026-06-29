import whois from 'whois-json';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { Dates, Registrar, Contact, Abuse } from '../../types/common';
import Logger from './logger';

const execFileAsync = promisify(execFile);

const log = new Logger('whois');
const WHOISXML_API_KEY = process.env['WHOISXML_API_KEY'];
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const WHO_DAT_URL = (process.env['DL_WHO_DAT_URL'] || 'https://who-dat.as93.net').replace(
  /\/+$/,
  '',
);
const FETCH_TIMEOUT_MS = 8000;

interface WhoisResult {
  domainName: string | null;
  status: string[];
  dnssec: string | null;
  dates: Partial<Dates>;
  registrar: Partial<Registrar>;
  whois: Partial<Contact>;
  abuse: Partial<Abuse>;
}

type RawWhois = Record<string, unknown> & {
  error?: unknown;
  registrar?: string | { name?: string } | null;
  registrarName?: string;
  dates?: Record<string, string | undefined>;
};

let rdapBootstrapCache: Record<string, string> | null = null;

const pad = (value: number): string => String(value).padStart(2, '0');

// Format y/m/d as YYYY-MM-DD, only if it is a real calendar date (rejects e.g. Feb 31)
const toIsoDate = (year: number, month: number, day: number): string | undefined => {
  const date = new Date(Date.UTC(year, month - 1, day));
  const isReal =
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day;
  return isReal ? `${year}-${pad(month)}-${pad(day)}` : undefined;
};

// Fetch JSON identifying as domain-locker, with a timeout, throwing on non-2xx
const fetchJson = async <T>(url: string, timeoutMs = FETCH_TIMEOUT_MS): Promise<T> => {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'domain-locker', Accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
};

// Parse a whois/rdap/cert date to YYYY-MM-DD, with no timezone round-trip to shift the day
export const parseDate = (date: string | null | undefined): string | undefined => {
  if (!date) return undefined;
  const cleaned = date
    .trim()
    .replace(/\s+[A-Z]+$/, '')
    .trim();

  // ISO-ish (YYYY-MM-DD...) - keep the date part verbatim
  const iso = cleaned.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (iso) return toIsoDate(Number(iso[1]), Number(iso[2]), Number(iso[3]));

  // DD/MM/YYYY or DD.MM.YYYY - day-first unless a value can only be a day (ambiguous when both <= 12)
  const dmy = cleaned.match(/^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})/);
  if (dmy) {
    const first = Number(dmy[1]);
    const second = Number(dmy[2]);
    const [day, month] =
      first > 12 ? [first, second] : second > 12 ? [second, first] : [first, second];
    return toIsoDate(Number(dmy[3]), month, day);
  }

  // Other formats (e.g. "15 Jan 2025") - require a year so a bare time never becomes today
  if (!/\d{4}/.test(cleaned)) return undefined;
  const parsed = new Date(cleaned);
  return isNaN(parsed.getTime())
    ? undefined
    : toIsoDate(parsed.getFullYear(), parsed.getMonth() + 1, parsed.getDate());
};

const hasUsefulWhoisData = (result: WhoisResult | null): result is WhoisResult =>
  Boolean(
    result &&
    (result.dates.expiry_date ||
      result.registrar.name ||
      result.registrar.id ||
      result.registrar.registryDomainId),
  );

export const getWhoisInfo = async (domain: string): Promise<WhoisResult | null> => {
  const trimmed = domain
    .replace(/^(?:https?:\/\/)?(?:www\.)?/i, '')
    .trim()
    .toLowerCase();

  // Each fallback source returns useful data or null, tried in order until one sticks
  const fallback = async (): Promise<WhoisResult | null> => {
    for (const provider of [tryWhoDat, tryNativeWhois, tryRdapLookup]) {
      const result = await provider(trimmed);
      if (hasUsefulWhoisData(result)) return result;
    }
    if (WHOISXML_API_KEY) {
      const xml = await tryWhoisXml(trimmed);
      if (hasUsefulWhoisData(xml)) return xml;
    }
    return null;
  };

  try {
    const raw = await Promise.race([
      whois(trimmed) as Promise<RawWhois>,
      new Promise<RawWhois>((_, reject) =>
        setTimeout(
          () =>
            reject(new Error(`WHOIS timeout after ${FETCH_TIMEOUT_MS}ms for ${domain}`)),
          FETCH_TIMEOUT_MS,
        ),
      ),
    ]);
    if (raw && typeof raw === 'object' && Object.keys(raw).length > 0 && !raw.error) {
      const normalized = normalizeWhoisJson(raw);
      if (hasUsefulWhoisData(normalized)) {
        log.success(`Got WHOIS data via whois-json for ${domain}`);
        return normalized;
      }
      log.warn(`whois-json returned incomplete data for ${domain}, falling back`);
      return await fallback();
    }
    log.warn(`whois-json returned empty or error for ${domain}, falling back`);
    return await fallback();
  } catch (err) {
    log.error(`whois-json failed for ${domain}: ${(err as Error).message}`);
    return await fallback();
  }
};

/* Converts the mystery whois-json structure into a WhoisResult */
const normalizeWhoisJson = (raw: RawWhois): WhoisResult => {
  const str = (key: string): string | undefined => {
    const v = raw[key];
    return typeof v === 'string' ? v : undefined;
  };
  const registrarObj =
    typeof raw.registrar === 'object' && raw.registrar ? raw.registrar : undefined;
  return {
    domainName: str('domainName') || null,
    registrar: {
      name:
        str('registrarName') ||
        (typeof raw.registrar === 'string' ? raw.registrar : registrarObj?.name) ||
        undefined,
      id: str('registrarIanaId'),
      url: str('registrarUrl'),
      registryDomainId: str('registryDomainId'),
    },
    dates: {
      creation_date: parseDate(
        str('creationDate') ||
          str('createdDate') ||
          str('created') ||
          str('domainRegistrationDate') ||
          str('registered') ||
          str('registrationDate') ||
          (raw.dates && (raw.dates['creation_date'] || raw.dates['created'])),
      ),
      updated_date: parseDate(
        str('updatedDate') ||
          str('lastUpdated') ||
          str('updated') ||
          str('domainLastUpdated') ||
          str('lastModified') ||
          str('modified') ||
          (raw.dates && (raw.dates['updated_date'] || raw.dates['updated'])),
      ),
      expiry_date: parseDate(
        str('expiryDate') ||
          str('registrarRegistrationExpirationDate') ||
          str('expiresDate') ||
          str('expirationDate') ||
          str('domainExpirationDate') ||
          str('expiry') ||
          str('expires') ||
          str('expire') ||
          str('paidUntil') ||
          str('paid_until') ||
          (raw.dates && (raw.dates['expiry_date'] || raw.dates['expires'])),
      ),
    },
    whois: {
      name: str('registrantName'),
      organization: str('registrantOrganization'),
      street: str('registrantStreet'),
      city: str('registrantCity'),
      country: str('registrantCountry'),
      state: str('registrantStateProvince'),
      postal_code: str('registrantPostalCode'),
    },
    abuse: {
      email: str('abuseContactEmail') || str('registrarAbuseContactEmail'),
      phone: str('abuseContactPhone') || str('registrarAbuseContactPhone'),
    },
    status: parseStatusArray(str('domainStatus') || str('status')),
    dnssec: str('dnssec') || null,
  };
};

const KNOWN_STATUSES = [
  'clientDeleteProhibited',
  'clientHold',
  'clientRenewProhibited',
  'clientTransferProhibited',
  'clientUpdateProhibited',
  'serverDeleteProhibited',
  'serverHold',
  'serverRenewProhibited',
  'serverTransferProhibited',
  'serverUpdateProhibited',
  'inactive',
  'ok',
  'pendingCreate',
  'pendingDelete',
  'pendingRenew',
  'pendingRestore',
  'pendingTransfer',
  'pendingUpdate',
  'addPeriod',
  'autoRenewPeriod',
  'renewPeriod',
  'transferPeriod',
];
const STATUS_BY_TOKEN = new Map(KNOWN_STATUSES.map((s) => [s.toLowerCase(), s]));

/* Statuses arrive as free text with urls, extract the known ICANN codes as whole tokens */
const parseStatusArray = (status?: string): string[] => {
  if (!status) return [];
  const found = new Set<string>();
  for (const token of status.toLowerCase().split(/[^a-z]+/)) {
    const canonical = STATUS_BY_TOKEN.get(token);
    if (canonical) found.add(canonical);
  }
  return [...found];
};

/* Determine the url for an rdap lookup, based on the domains TLD */
const getRdapUrlForTld = async (tld: string): Promise<string | null> => {
  try {
    if (!rdapBootstrapCache) {
      const json = await fetchJson<{ services: [string[], string[]][] }>(
        RDAP_BOOTSTRAP_URL,
      );
      rdapBootstrapCache = {};
      for (const [tlds, urls] of json.services) {
        for (const name of tlds) {
          rdapBootstrapCache[name] = urls[0].replace(/\/$/, '');
        }
      }
    }
    return rdapBootstrapCache[tld] ?? null;
  } catch (err) {
    log.warn(`Failed to fetch RDAP bootstrap: ${(err as Error).message}`);
    return null;
  }
};

interface WhoDatResponse {
  domain?: string | null;
  id?: string | null;
  isRegistered?: boolean;
  registrar?: {
    name?: string | null;
    ianaId?: string | null;
    url?: string | null;
    abuseEmail?: string | null;
    abusePhone?: string | null;
  };
  status?: string[];
  dnssec?: { signed?: boolean };
  dates?: { created?: string | null; updated?: string | null; expires?: string | null };
  contacts?: {
    registrant?: {
      name?: string | null;
      organization?: string | null;
      address?: {
        street?: string | null;
        city?: string | null;
        state?: string | null;
        postalCode?: string | null;
        country?: string | null;
      };
    };
  };
  error?: unknown;
}

/* Drop who-dat's literal REDACTED placeholders, keeping only real values */
const cleanWhoDat = (value: string | null | undefined): string | undefined => {
  const trimmed = value?.trim();
  return !trimmed || /^redacted/i.test(trimmed) ? undefined : trimmed;
};

/* Try who-dat as the first fallback when local whois fails */
const tryWhoDat = async (domain: string): Promise<WhoisResult | null> => {
  try {
    const data = await fetchJson<WhoDatResponse>(
      `${WHO_DAT_URL}/${encodeURIComponent(domain)}`,
    );
    if (data.error || !data.isRegistered) return null;

    const registrant = data.contacts?.registrant;
    const address = registrant?.address;
    const result: WhoisResult = {
      domainName: data.domain || null,
      registrar: {
        name: cleanWhoDat(data.registrar?.name),
        id: cleanWhoDat(data.registrar?.ianaId),
        url: cleanWhoDat(data.registrar?.url),
        registryDomainId: cleanWhoDat(data.id),
      },
      dates: {
        creation_date: parseDate(data.dates?.created),
        updated_date: parseDate(data.dates?.updated),
        expiry_date: parseDate(data.dates?.expires),
      },
      whois: {
        name: cleanWhoDat(registrant?.name),
        organization: cleanWhoDat(registrant?.organization),
        street: cleanWhoDat(address?.street),
        city: cleanWhoDat(address?.city),
        country: cleanWhoDat(address?.country),
        state: cleanWhoDat(address?.state),
        postal_code: cleanWhoDat(address?.postalCode),
      },
      abuse: {
        email: cleanWhoDat(data.registrar?.abuseEmail),
        phone: cleanWhoDat(data.registrar?.abusePhone)?.replace(/^tel:/, ''),
      },
      status: data.status || [],
      dnssec: data.dnssec?.signed ? 'signed' : null,
    };

    if (!hasUsefulWhoisData(result)) return null;
    log.success(`Got WHOIS data via who-dat for ${domain}`);
    return result;
  } catch (err) {
    log.warn(`who-dat failed for ${domain}: ${(err as Error).message}`);
    return null;
  }
};

/* Try the native whois command as a fallback when libraries fail */
const tryNativeWhois = async (domain: string): Promise<WhoisResult | null> => {
  // Skip native whois on serverless environments where system packages aren't available
  if (
    process.env['VERCEL'] ||
    process.env['AWS_LAMBDA_FUNCTION_NAME'] ||
    process.env['NETLIFY']
  ) {
    return null;
  }

  try {
    // Sanitize domain input to prevent command injection
    const sanitizedDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '');
    if (!sanitizedDomain || sanitizedDomain !== domain) {
      log.warn(`Invalid domain format for native whois: ${domain}`);
      return null;
    }

    const { stdout } = await execFileAsync('whois', [sanitizedDomain], {
      timeout: 10000,
    });

    if (!stdout || stdout.length < 50) {
      log.warn(
        `Native whois returned insufficient data for ${domain}: ${stdout?.length || 0} bytes`,
      );
      return null;
    }

    // Parse key-value pairs, collecting every status line (not just the last)
    const data: Record<string, string> = {};
    const statuses: string[] = [];

    for (const line of stdout.split(/\r?\n/)) {
      const match = line.trim().match(/^([^:]+):\s*(.+)$/);
      if (!match) continue;
      const key = match[1]
        .trim()
        .toLowerCase()
        .replace(/[\s/]+/g, '_');
      const value = match[2].trim();
      if (!value || value.startsWith('REDACTED')) continue;
      data[key] = value;
      if (key === 'domain_status' || key === 'status') statuses.push(value);
    }

    log.success(`Got WHOIS data via native whois command for ${domain}`);
    return {
      domainName: data['domain_name'] || null,
      registrar: {
        name: data['registrar'] || undefined,
        id: data['registrar_iana_id'] || undefined,
        url: data['registrar_url'] || data['registrar_whois_server'] || undefined,
        registryDomainId: data['registry_domain_id'] || undefined,
      },
      dates: {
        creation_date: parseDate(
          data['creation_date'] || data['created_date'] || data['registration_time'],
        ),
        updated_date: parseDate(data['updated_date'] || data['last_updated']),
        expiry_date: parseDate(
          data['registry_expiry_date'] ||
            data['registrar_registration_expiration_date'] ||
            data['expiry_date'] ||
            data['expiration_time'] ||
            data['expire'] ||
            data['paid_until'],
        ),
      },
      whois: {
        name: data['registrant_name'] || undefined,
        organization: data['registrant_organization'] || undefined,
        street: data['registrant_street'] || undefined,
        city: data['registrant_city'] || undefined,
        country: data['registrant_country'] || undefined,
        state: data['registrant_state_province'] || data['registrant_state'] || undefined,
        postal_code: data['registrant_postal_code'] || undefined,
      },
      abuse: {
        email: data['registrar_abuse_contact_email'] || undefined,
        phone: data['registrar_abuse_contact_phone'] || undefined,
      },
      status: parseStatusArray(statuses.join(' ')),
      dnssec: data['dnssec'] || null,
    };
  } catch (err) {
    log.warn(`Native whois failed for ${domain}: ${(err as Error).message}`);
    return null;
  }
};

type VCardEntry = [string, Record<string, unknown>, string, string];

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, VCardEntry[]];
  publicIds?: { type: string; identifier: string }[];
  entities?: RdapEntity[];
}

interface RdapResponse {
  ldhName?: string;
  handle?: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  entities?: RdapEntity[];
  secureDNS?: { zoneSigned?: boolean };
}

const tryRdapLookup = async (domain: string): Promise<WhoisResult | null> => {
  try {
    const tld = domain.split('.').pop();
    if (!tld) return null;

    const rdapBase = await getRdapUrlForTld(tld);
    if (!rdapBase) {
      log.warn(`No RDAP base found for TLD .${tld}`);
      return null;
    }

    const json = await fetchJson<RdapResponse>(`${rdapBase}/domain/${domain}`);

    const events = json.events || [];
    const getEvent = (action: string) =>
      events.find((e) => e.eventAction === action)?.eventDate || null;

    // Find registrar entity
    const registrarEntity = json.entities?.find((e) => e.roles?.includes('registrar'));
    const registrarName =
      registrarEntity?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || undefined;
    const registrarIanaId =
      registrarEntity?.publicIds?.find((p) => p.type === 'IANA Registrar ID')
        ?.identifier || undefined;

    // Find abuse contact entity
    const abuseEntity = json.entities?.flatMap(
      (e) => e.entities?.filter((sub) => sub.roles?.includes('abuse')) || [],
    )?.[0];
    const abuseEmail =
      abuseEntity?.vcardArray?.[1]?.find((v) => v[0] === 'email')?.[3] || undefined;
    const abusePhone =
      abuseEntity?.vcardArray?.[1]
        ?.find((v) => v[0] === 'tel')?.[3]
        ?.replace('tel:', '') || undefined;

    log.success(`Got WHOIS data via RDAP for ${domain}`);
    return {
      domainName: json.ldhName || null,
      registrar: {
        name: registrarName,
        id: registrarIanaId,
        url: undefined,
        registryDomainId: json.handle || undefined,
      },
      dates: {
        creation_date: parseDate(getEvent('registration')),
        updated_date: parseDate(getEvent('last changed')),
        expiry_date: parseDate(getEvent('expiration')),
      },
      whois: {},
      abuse: {
        email: abuseEmail,
        phone: abusePhone,
      },
      status: json.status || [],
      dnssec: json.secureDNS?.zoneSigned ? 'signed' : null,
    };
  } catch (err) {
    log.warn(`RDAP failed for ${domain}: ${(err as Error).message}`);
    return null;
  }
};

interface WhoisXmlResponse {
  WhoisRecord?: {
    domainName?: string;
    registrarName?: string;
    registrarIANAID?: string;
    status?: string;
    customField1Value?: string;
    customField2Value?: string;
    registryData?: {
      registrarName?: string;
      whoisServer?: string;
      registryDomainId?: string;
      createdDateNormalized?: string;
      expiresDateNormalized?: string;
      updatedDateNormalized?: string;
      status?: string;
      registrant?: {
        name?: string;
        organization?: string;
        street1?: string;
        city?: string;
        state?: string;
        countryCode?: string;
        postalCode?: string;
      };
    };
  };
}

/* Last resort, a paid third-party API (only when an api key is configured) */
const tryWhoisXml = async (domain: string): Promise<WhoisResult | null> => {
  try {
    const url = new URL('https://www.whoisxmlapi.com/whoisserver/WhoisService');
    url.searchParams.set('apiKey', WHOISXML_API_KEY || '');
    url.searchParams.set('outputFormat', 'json');
    url.searchParams.set('domainName', domain);

    const data = await fetchJson<WhoisXmlResponse>(url.toString());
    const whoisRecord = data.WhoisRecord;
    const record = whoisRecord?.registryData;
    const registrant = record?.registrant;

    return {
      domainName: whoisRecord?.domainName || null,
      registrar: {
        name: whoisRecord?.registrarName || record?.registrarName || undefined,
        id: whoisRecord?.registrarIANAID || undefined,
        url: record?.whoisServer ? `https://${record.whoisServer}` : undefined,
        registryDomainId: record?.registryDomainId || undefined,
      },
      dates: {
        creation_date: parseDate(record?.createdDateNormalized),
        expiry_date: parseDate(record?.expiresDateNormalized),
        updated_date: parseDate(record?.updatedDateNormalized),
      },
      whois: {
        name: registrant?.name || undefined,
        organization: registrant?.organization || undefined,
        street: registrant?.street1 || undefined,
        city: registrant?.city || undefined,
        country: registrant?.countryCode || undefined,
        postal_code: registrant?.postalCode || undefined,
        state: registrant?.state || undefined,
      },
      abuse: {
        email: whoisRecord?.customField1Value || undefined,
        phone: whoisRecord?.customField2Value || undefined,
      },
      status: parseStatusArray(record?.status || whoisRecord?.status),
      dnssec: null,
    };
  } catch (err) {
    log.warn(`WhoisXML failed for ${domain}: ${(err as Error).message}`);
    return null;
  }
};
