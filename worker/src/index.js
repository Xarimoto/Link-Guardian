const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

const urlShortenerDomains = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "is.gd",
  "rebrand.ly",
  "rb.gy",
  "cutt.ly",
  "tiny.cc",
  "lnkd.in"
];

const redirectStatusCodes = new Set([
  301,
  302,
  303,
  307,
  308
]);

const maxRedirectHops = 5;
const redirectTimeoutMs = 5000;

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}

function createVirusTotalUrlId(url) {
  const bytes = new TextEncoder().encode(url);
  let binaryValue = "";

  for (const byte of bytes) {
    binaryValue += String.fromCharCode(byte);
  }

  return btoa(binaryValue)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function isUrlShortener(hostname) {
  const normalizedHostname = hostname.toLowerCase();

  return urlShortenerDomains.some((domain) => {
    return (
      normalizedHostname === domain ||
      normalizedHostname.endsWith(`.${domain}`)
    );
  });
}

function isPrivateOrReservedIpv4(hostname) {
  const octets = hostname.split(".").map(Number);

  if (
    octets.length !== 4 ||
    octets.some((octet) => {
      return (
        !Number.isInteger(octet) ||
        octet < 0 ||
        octet > 255
      );
    })
  ) {
    return false;
  }

  const [a, b] = octets;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateOrReservedIpv6(hostname) {
  const normalizedHostname = hostname
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .toLowerCase();

  if (!normalizedHostname.includes(":")) {
    return false;
  }

  return (
    normalizedHostname === "::" ||
    normalizedHostname === "::1" ||
    normalizedHostname.startsWith("fc") ||
    normalizedHostname.startsWith("fd") ||
    normalizedHostname.startsWith("fe8") ||
    normalizedHostname.startsWith("fe9") ||
    normalizedHostname.startsWith("fea") ||
    normalizedHostname.startsWith("feb")
  );
}

function isUnsafeRedirectTarget(url) {
  const hostname = url.hostname.toLowerCase();

  if (
    url.protocol !== "http:" &&
    url.protocol !== "https:"
  ) {
    return true;
  }

  if (url.username || url.password) {
    return true;
  }

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return true;
  }

  return (
    isPrivateOrReservedIpv4(hostname) ||
    isPrivateOrReservedIpv6(hostname)
  );
}

function analyzeUrlHeuristics(url) {
  const warnings = [];
  const hostname = url.hostname.toLowerCase();
  const usesUrlShortener = isUrlShortener(hostname);

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    warnings.push(
      "The link uses an IP address instead of a domain name."
    );
  }

  if (hostname.includes("xn--")) {
    warnings.push(
      "The domain contains internationalized or punycode characters."
    );
  }

  if (url.username || url.password) {
    warnings.push(
      "The link contains embedded login information."
    );
  }

  if (
    url.port &&
    url.port !== "80" &&
    url.port !== "443"
  ) {
    warnings.push(
      `The link uses the unusual port ${url.port}.`
    );
  }

  const hostnameParts = hostname.split(".");
  const subdomainCount =
    hostnameParts.length > 2
      ? hostnameParts.length - 2
      : 0;

  if (subdomainCount >= 4) {
    warnings.push(
      "The link contains an unusually large number of subdomains."
    );
  }

  if (usesUrlShortener) {
    warnings.push(
      "The link uses a URL-shortening service that hides the final destination."
    );
  }

  return {
    status: warnings.length > 0 ? "warning" : "clear",
    warningCount: warnings.length,
    warnings,
    usesUrlShortener
  };
}

function mergeHeuristicResults(...results) {
  const warnings = [
    ...new Set(
      results.flatMap((result) => {
        return result?.warnings ?? [];
      })
    )
  ];

  return {
    status: warnings.length > 0 ? "warning" : "clear",
    warningCount: warnings.length,
    warnings,
    usesUrlShortener: results.some((result) => {
      return result?.usesUrlShortener === true;
    })
  };
}

function analyzeRedirectHeuristics(redirectResolution) {
  const warnings = [];

  const redirectChain =
    redirectResolution?.redirectChain ?? [];

  const hasHttpsDowngrade =
    redirectChain.some((redirect) => {
      try {
        const fromUrl = new URL(redirect.from);
        const toUrl = new URL(redirect.to);

        return (
          fromUrl.protocol === "https:" &&
          toUrl.protocol === "http:"
        );
      } catch {
        return false;
      }
    });

  if (hasHttpsDowngrade) {
    warnings.push(
      "The link redirects from secure HTTPS to insecure HTTP."
    );
  }

  return {
    status: warnings.length > 0 ? "warning" : "clear",
    warningCount: warnings.length,
    warnings,
    usesUrlShortener: false,
    hasHttpsDowngrade
  };
}

async function fetchWithTimeout(url, method) {
  const controller = new AbortController();

  const timeoutId = setTimeout(() => {
    controller.abort();
  }, redirectTimeoutMs);

  try {
    return await fetch(url, {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        "User-Agent": "QR-Guardian-Link-Resolver/0.6"
      }
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

async function requestRedirectStep(url) {
  let response = await fetchWithTimeout(url, "HEAD");

  if (
    response.status === 405 ||
    response.status === 501
  ) {
    response.body?.cancel();
    response = await fetchWithTimeout(url, "GET");
  }

  return response;
}

async function resolveShortenedUrl(startUrl) {
  let currentUrl = new URL(startUrl.href);
  const redirectChain = [];

  for (
    let hop = 0;
    hop < maxRedirectHops;
    hop += 1
  ) {
    if (isUnsafeRedirectTarget(currentUrl)) {
      return {
        status: "blocked",
        message:
          "QR Guardian blocked a redirect toward a private or unsupported destination.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain
      };
    }

    let response;

    try {
      response = await requestRedirectStep(
        currentUrl.href
      );
    } catch {
      return {
        status: "unresolved",
        message:
          "QR Guardian could not resolve the shortened link safely.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain
      };
    }

    const location =
      response.headers.get("Location");

    const isRedirect =
      redirectStatusCodes.has(response.status);

    response.body?.cancel();

    if (!isRedirect || !location) {
      const resolved =
        currentUrl.href !== startUrl.href;

      return {
        status: resolved
          ? "resolved"
          : "unresolved",
        message: resolved
          ? "QR Guardian resolved the shortened link destination."
          : "The shortened link did not expose a redirect destination.",
        resolved,
        finalUrl: resolved
          ? currentUrl.href
          : null,
        finalHostname: resolved
          ? currentUrl.hostname
          : null,
        redirectChain
      };
    }

    let nextUrl;

    try {
      nextUrl = new URL(location, currentUrl);
    } catch {
      return {
        status: "unresolved",
        message:
          "The shortened link returned an invalid redirect destination.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain
      };
    }

    if (isUnsafeRedirectTarget(nextUrl)) {
      return {
        status: "blocked",
        message:
          "QR Guardian blocked a redirect toward a private or unsupported destination.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain
      };
    }

    redirectChain.push({
      statusCode: response.status,
      from: currentUrl.href,
      to: nextUrl.href
    });

    if (nextUrl.href === currentUrl.href) {
      return {
        status: "unresolved",
        message:
          "The shortened link returned a redirect loop.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain
      };
    }

    currentUrl = nextUrl;
  }

  return {
    status: "unresolved",
    message:
      `The shortened link exceeded the ${maxRedirectHops}-redirect safety limit.`,
    resolved: false,
    finalUrl: null,
    finalHostname: null,
    redirectChain
  };
}

async function getVirusTotalReport(url, apiKey) {
  const urlId = createVirusTotalUrlId(url);

  const response = await fetch(
    `https://www.virustotal.com/api/v3/urls/${urlId}`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        "X-Apikey": apiKey
      }
    }
  );

  if (response.status === 404) {
    return {
      type: "not_found"
    };
  }

  if (response.status === 429) {
    return {
      type: "unavailable",
      message:
        "The VirusTotal request limit has been reached."
    };
  }

  if (!response.ok) {
    return {
      type: "unavailable",
      message:
        `VirusTotal returned error ${response.status}.`
    };
  }

  return {
    type: "found",
    report: await response.json()
  };
}

function formatVirusTotalReport(
  report,
  reportUrl,
  usedHomepageFallback
) {
  const attributes =
    report.data?.attributes ?? {};

  const statistics =
    attributes.last_analysis_stats ?? {};

  const malicious =
    statistics.malicious ?? 0;

  const suspicious =
    statistics.suspicious ?? 0;

  const harmless =
    statistics.harmless ?? 0;

  const undetected =
    statistics.undetected ?? 0;

  let status;
  let message;

  if (malicious > 0) {
    status = "dangerous";
    message =
      `VirusTotal detected ${malicious} malicious result(s).`;
  } else if (suspicious > 0) {
    status = "suspicious";
    message =
      `VirusTotal reported ${suspicious} suspicious result(s).`;
  } else {
    status = "no_known_threats";

    if (usedHomepageFallback) {
      message =
        "No exact URL report was found. " +
        "The website homepage report has no known threats.";
    } else {
      message =
        "No known threats were found in the latest VirusTotal report.";
    }
  }

  return {
    status,
    message,
    found: true,
    usedHomepageFallback,
    reportUrl,
    malicious,
    suspicious,
    harmless,
    undetected,
    lastAnalysisDate:
      attributes.last_analysis_date ?? null,
    finalUrl:
      attributes.last_final_url ?? reportUrl
  };
}

async function checkVirusTotal(
  url,
  apiKey,
  skipHomepageFallback
) {
  const exactResult =
    await getVirusTotalReport(url, apiKey);

  if (exactResult.type === "found") {
    return formatVirusTotalReport(
      exactResult.report,
      url,
      false
    );
  }

  if (exactResult.type === "unavailable") {
    return {
      status: "unavailable",
      message: exactResult.message,
      found: false
    };
  }

  if (skipHomepageFallback) {
    return {
      status: "unknown",
      message:
        "VirusTotal has no exact report for this shortened URL.",
      found: false,
      usedHomepageFallback: false
    };
  }

  const parsedUrl = new URL(url);
  const homepageUrl = `${parsedUrl.origin}/`;

  if (homepageUrl !== url) {
    const homepageResult =
      await getVirusTotalReport(
        homepageUrl,
        apiKey
      );

    if (homepageResult.type === "found") {
      return formatVirusTotalReport(
        homepageResult.report,
        homepageUrl,
        true
      );
    }

    if (
      homepageResult.type === "unavailable"
    ) {
      return {
        status: "unavailable",
        message: homepageResult.message,
        found: false
      };
    }
  }

  return {
    status: "unknown",
    message:
      "VirusTotal has no existing report for this URL or its homepage.",
    found: false,
    usedHomepageFallback: false
  };
}

function getVirusTotalSeverity(status) {
  const severity = {
    unavailable: 0,
    unknown: 1,
    no_known_threats: 2,
    suspicious: 3,
    dangerous: 4
  };

  return severity[status] ?? 0;
}

function chooseVirusTotalResult(
  originalResult,
  destinationResult
) {
  if (!destinationResult) {
    return originalResult;
  }

  if (
    getVirusTotalSeverity(
      destinationResult.status
    ) >
    getVirusTotalSeverity(
      originalResult.status
    )
  ) {
    return destinationResult;
  }

  if (
    originalResult.status === "unknown" ||
    originalResult.status === "unavailable"
  ) {
    return destinationResult;
  }

  return originalResult;
}

function createOverallResult(
  virusTotalResult,
  heuristicResult,
  redirectResolution
) {
  if (
    redirectResolution?.status === "blocked"
  ) {
    return {
      status: "dangerous",
      message: redirectResolution.message
    };
  }

  if (
    virusTotalResult.status === "dangerous"
  ) {
    return {
      status: "dangerous",
      message: virusTotalResult.message
    };
  }

  if (
    virusTotalResult.status === "suspicious"
  ) {
    return {
      status: "suspicious",
      message: virusTotalResult.message
    };
  }

  if (
    heuristicResult.status === "warning"
  ) {
    return {
      status: "suspicious",
      message:
        `${virusTotalResult.message} ` +
        `QR Guardian found ${heuristicResult.warningCount} ` +
        `additional URL warning(s).`
    };
  }

  return {
    status: virusTotalResult.status,
    message: virusTotalResult.message
  };
}

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (
      request.method === "GET" &&
      requestUrl.pathname === "/"
    ) {
      return jsonResponse({
        service: "QR Guardian API",
        status: "online",
        version: "0.6.1"
      });
    }

    if (
      request.method === "POST" &&
      requestUrl.pathname === "/v1/check"
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          {
            error:
              "The request body must contain valid JSON."
          },
          400
        );
      }

      if (
        !body.url ||
        typeof body.url !== "string"
      ) {
        return jsonResponse(
          {
            error: "A URL is required."
          },
          400
        );
      }

      if (body.url.length > 4096) {
        return jsonResponse(
          {
            error:
              "The supplied URL is too long."
          },
          400
        );
      }

      let checkedUrl;

      try {
        checkedUrl =
          new URL(body.url.trim());
      } catch {
        return jsonResponse(
          {
            error:
              "The supplied URL is invalid."
          },
          400
        );
      }

      if (
        checkedUrl.protocol !== "http:" &&
        checkedUrl.protocol !== "https:"
      ) {
        return jsonResponse(
          {
            error:
              "Only HTTP and HTTPS links are supported."
          },
          400
        );
      }

      if (!env.VIRUSTOTAL_API_KEY) {
        return jsonResponse(
          {
            error:
              "VirusTotal is not configured."
          },
          500
        );
      }

      const originalHeuristics =
        analyzeUrlHeuristics(checkedUrl);

      let redirectResolution = {
        status: "not_needed",
        message:
          "Redirect resolution was not needed.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain: []
      };

      let destinationUrl = checkedUrl;
      let destinationHeuristics = null;
      let destinationVirusTotalResult = null;

      const originalVirusTotalResult =
        await checkVirusTotal(
          checkedUrl.href,
          env.VIRUSTOTAL_API_KEY,
          originalHeuristics.usesUrlShortener
        );

      if (
        originalHeuristics.usesUrlShortener
      ) {
        redirectResolution =
          await resolveShortenedUrl(
            checkedUrl
          );

        if (
          redirectResolution.status ===
            "resolved" &&
          redirectResolution.finalUrl
        ) {
          destinationUrl =
            new URL(
              redirectResolution.finalUrl
            );

          destinationHeuristics =
            analyzeUrlHeuristics(
              destinationUrl
            );

          destinationVirusTotalResult =
            await checkVirusTotal(
              destinationUrl.href,
              env.VIRUSTOTAL_API_KEY,
              isUrlShortener(
                destinationUrl.hostname
              )
            );
        }
      }

      const redirectHeuristics =
        analyzeRedirectHeuristics(
          redirectResolution
        );

      const heuristicResult =
        mergeHeuristicResults(
          originalHeuristics,
          destinationHeuristics,
          redirectHeuristics
        );

      const virusTotalResult =
        chooseVirusTotalResult(
          originalVirusTotalResult,
          destinationVirusTotalResult
        );

      const overallResult =
        createOverallResult(
          virusTotalResult,
          heuristicResult,
          redirectResolution
        );

      return jsonResponse({
        status: overallResult.status,
        message: overallResult.message,
        url: checkedUrl.href,
        hostname: checkedUrl.hostname,
        protocol: checkedUrl.protocol,
        destinationUrl:
          destinationUrl.href !==
          checkedUrl.href
            ? destinationUrl.href
            : null,
        destinationHostname:
          destinationUrl.href !==
          checkedUrl.href
            ? destinationUrl.hostname
            : null,
        checks: {
          redirectResolution,
          redirectHeuristics,
          heuristics: heuristicResult,
          virusTotal: virusTotalResult,
          virusTotalOriginal:
            originalVirusTotalResult,
          virusTotalDestination:
            destinationVirusTotalResult
        }
      });
    }

    return jsonResponse(
      {
        error: "Endpoint not found."
      },
      404
    );
  }
};