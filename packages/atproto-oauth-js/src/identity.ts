import { z } from "zod";

// Add these type definitions and functions:
type Brand<K, T> = K & { __brand: T };
export type DID = Brand<string, "DID">;

export function isDid(s: string): s is DID {
  return s.startsWith("did:");
}

export function parseDid(s: string): DID | null {
  if (!isDid(s)) {
    return null;
  }
  return s;
}

export async function getDidDoc(did: DID) {
  const url = "https://plc.directory";
  const response = await fetch(`${url}/${did}`);
  return PlcDocument.parse(await response.json());
}

export async function getVerifiedDid(handle: string) {
  const [dnsDid, httpDid] = await Promise.all([
    getAtprotoDidFromDns(handle).catch((_) => {
      return null;
    }),
    getAtprotoFromHttps(handle).catch((_) => {
      return null;
    }),
  ]);

  if (dnsDid && httpDid && dnsDid !== httpDid) {
    return null;
  }

  const did = dnsDid ?? (httpDid ? parseDid(httpDid) : null);
  if (!did) {
    return null;
  }

  const plcDoc = await getDidDoc(did);
  const plcHandle = plcDoc.alsoKnownAs
    .find((handle) => handle.startsWith("at://"))
    ?.replace("at://", "");

  if (!plcHandle) return null;

  return plcHandle.toLowerCase() === handle.toLowerCase() ? did : null;
}

async function getAtprotoDidFromDns(handle: string) {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("type", "TXT");
  url.searchParams.set("name", `_atproto.${handle}`);

  const response = await fetch(url, {
    headers: {
      Accept: "application/dns-json",
    },
  });

  const { Answer } = DnsQueryResponse.parse(await response.json());
  const val = Answer[0]?.data
    ? JSON.parse(Answer[0]?.data).split("did=")[1]
    : null;

  return val ? parseDid(val) : null;
}

async function getAtprotoFromHttps(handle: string) {
  let res;
  const timeoutSignal = AbortSignal.timeout(1500);
  try {
    res = await fetch(`https://${handle}/.well-known/atproto-did`, {
      signal: timeoutSignal,
    });
  } catch (_e) {
    return null;
  }

  if (!res.ok) {
    return null;
  }
  return parseDid((await res.text()).trim());
}

export async function getDidFromHandleOrDid(handleOrDid: string) {
  const decodedHandleOrDid = decodeURIComponent(handleOrDid);
  if (isDid(decodedHandleOrDid)) {
    return decodedHandleOrDid;
  }

  return getVerifiedDid(decodedHandleOrDid);
}

// Add necessary schema definitions
const DnsQueryResponse = z.object({
  Answer: z.array(
    z.object({
      name: z.string(),
      type: z.number(),
      TTL: z.number(),
      data: z.string(),
    }),
  ),
});

const PlcDocument = z.object({
  id: z.string(),
  alsoKnownAs: z.array(z.string()),
  service: z.array(
    z.object({
      id: z.string(),
      type: z.string(),
      serviceEndpoint: z.string(),
    }),
  ),
});