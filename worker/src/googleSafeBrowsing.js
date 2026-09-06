const googleSafeBrowsingEndpoint =
  "https://safebrowsing.googleapis.com/v4/threatMatches:find";

// Version matches the existing Worker's health response. No user metadata.
const client = { clientId: "linkguardian", clientVersion: "0.6.2" };
// Valid URL list combinations verified with Google's v4 threatLists.list.
// PHA is platform-specific, so keep it separate from ANY_PLATFORM lists.
const threatGroups = [
  {
    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
    platformTypes: ["ANY_PLATFORM"]
  },
  {
    threatTypes: ["POTENTIALLY_HARMFUL_APPLICATION"],
    platformTypes: ["ANDROID", "IOS"]
  }
];

const defaultTimeoutMs = 2000;
const maximumCacheSeconds = 86400;

function providerResult(
  status,
  matched = false,
  threatTypes = []
) {
  return {
    status,
    matched,
    threatTypes
  };
}

function parseCacheDuration(value) {
  if (
    typeof value !== "string" ||
    !/^\d+(?:\.\d+)?s$/.test(value)
  ) {
    return 0;
  }

  const seconds =
    Math.floor(Number(value.slice(0, -1)));

  if (
    !Number.isFinite(seconds) ||
    seconds <= 0
  ) {
    return 0;
  }

  return Math.min(
    seconds,
    maximumCacheSeconds
  );
}

function formatGoogleResponse(payload) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return null;
  }

  // Lookup returns {} for no match. Do not accept an unrelated error/v5 object.
  if (!Object.hasOwn(payload, "matches")) {
    return Object.keys(payload).length === 0 ? [] : null;
  }

  const matches = payload.matches;
  if (!Array.isArray(matches) || matches.some((match) => (
    !match || typeof match !== "object" ||
    typeof match.threatType !== "string" ||
    !/^[A-Z][A-Z0-9_]*$/.test(match.threatType) ||
    match.threatEntryType !== "URL" ||
    typeof match.threat?.url !== "string" || !match.threat.url
  ))) {
    return null;
  }

  return matches;
}

async function createCacheKey(
  url,
  cryptoImplementation
) {
  if (
    !cryptoImplementation?.subtle
  ) {
    return null;
  }

  const digest =
    await cryptoImplementation.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(url)
    );

  const digestHex =
    [...new Uint8Array(digest)]
      .map((byte) => {
        return byte
          .toString(16)
          .padStart(2, "0");
      })
      .join("");

  return new Request(
    `https://google-safe-browsing-cache.link-guardian/v4-lookup/${digestHex}`
  );
}

async function readCachedResult(
  cache,
  cacheKey
) {
  if (
    !cache ||
    !cacheKey
  ) {
    return null;
  }

  try {
    const response =
      await cache.match(cacheKey);

    if (!response) {
      return null;
    }

    const result =
      await response.json();

    if (
      result?.status === "ok" &&
      result.matched === true &&
      Array.isArray(
        result.threatTypes
      ) && result.threatTypes.every((type) => typeof type === "string")
    ) {
      return providerResult("ok", true, result.threatTypes);
    }
  } catch {
    // Cache access is best-effort and must not affect provider availability.
  }

  return null;
}

async function cacheResult(
  cache,
  cacheKey,
  result,
  cacheSeconds
) {
  if (
    !cache ||
    !cacheKey ||
    cacheSeconds <= 0
  ) {
    return;
  }

  try {
    await cache.put(
      cacheKey,
      new Response(
        JSON.stringify(result),
        {
          headers: {
            "Cache-Control":
              `max-age=${cacheSeconds}`,
            "Content-Type":
              "application/json"
          }
        }
      )
    );
  } catch {
    // A cache write failure must not change the provider result.
  }
}

export async function checkGoogleSafeBrowsing(
  url,
  apiKey,
  options = {}
) {
  if (!apiKey) {
    return providerResult(
      "not_configured"
    );
  }

  const fetchImplementation =
    options.fetchImplementation ??
    globalThis.fetch;

  const timeoutMs =
    options.timeoutMs ??
    defaultTimeoutMs;

  const cache =
    options.cache ??
    globalThis.caches?.default ??
    null;

  const cryptoImplementation =
    options.cryptoImplementation ??
    globalThis.crypto;

  let cacheKey = null;

  try {
    cacheKey =
      await createCacheKey(
        url,
        cryptoImplementation
      );

    const cachedResult =
      await readCachedResult(
        cache,
        cacheKey
      );

    if (cachedResult) {
      return cachedResult;
    }
  } catch {
    cacheKey = null;
  }

  const controller =
    new AbortController();

  const timeoutId =
    setTimeout(() => {
      controller.abort();
    }, timeoutMs);

  try {
    const requestUrl =
      new URL(
        googleSafeBrowsingEndpoint
      );

    requestUrl.searchParams.set(
      "key",
      apiKey
    );

    // Both groups must finish successfully before this is a verified result.
    const groups = await Promise.all(threatGroups.map(async (group) => {
      const response = await fetchImplementation(requestUrl.href, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          client,
          threatInfo: { ...group, threatEntryTypes: ["URL"], threatEntries: [{ url }] }
        }),
        signal: controller.signal
      });
      if (response.status === 429) return { status: "rate_limited" };
      if (!response.ok) return { status: "error" };
      try {
        const matches = formatGoogleResponse(await response.json());
        return matches === null ? { status: "error" } : { status: "ok", matches };
      } catch {
        return { status: controller.signal.aborted ? "unavailable" : "error" };
      }
    }));

    const failure = groups.find((group) => group.status !== "ok");
    if (failure) return providerResult(failure.status);

    const matches = groups.flatMap((group) => group.matches);
    const result = providerResult(
      "ok", matches.length > 0,
      [...new Set(matches.map((match) => match.threatType))]
    );
    // No-match Lookup responses have no TTL. Cache only matches, and never
    // retain an aggregate result past any individual match's expiry.
    const cacheSeconds = matches.length > 0
      ? Math.min(...matches.map((match) => parseCacheDuration(match.cacheDuration)))
      : 0;

    await cacheResult(
      cache,
      cacheKey,
      result,
      cacheSeconds
    );

    return result;
  } catch {
    return providerResult(
      "unavailable"
    );
  } finally {
    clearTimeout(timeoutId);
    controller.abort();
  }
}
