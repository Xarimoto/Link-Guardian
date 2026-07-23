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
  return urlShortenerDomains.some((domain) => {
    return (
      hostname === domain ||
      hostname.endsWith(`.${domain}`)
    );
  });
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
      message: "The VirusTotal request limit has been reached."
    };
  }

  if (!response.ok) {
    return {
      type: "unavailable",
      message: `VirusTotal returned error ${response.status}.`
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
  const attributes = report.data?.attributes ?? {};
  const statistics = attributes.last_analysis_stats ?? {};

  const malicious = statistics.malicious ?? 0;
  const suspicious = statistics.suspicious ?? 0;
  const harmless = statistics.harmless ?? 0;
  const undetected = statistics.undetected ?? 0;

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
  const exactResult = await getVirusTotalReport(
    url,
    apiKey
  );

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
    const homepageResult = await getVirusTotalReport(
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

    if (homepageResult.type === "unavailable") {
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

function createOverallResult(
  virusTotalResult,
  heuristicResult
) {
  if (virusTotalResult.status === "dangerous") {
    return {
      status: "dangerous",
      message: virusTotalResult.message
    };
  }

  if (virusTotalResult.status === "suspicious") {
    return {
      status: "suspicious",
      message: virusTotalResult.message
    };
  }

  if (heuristicResult.status === "warning") {
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
        version: "0.5.1"
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
            error: "The supplied URL is too long."
          },
          400
        );
      }

      let checkedUrl;

      try {
        checkedUrl = new URL(body.url.trim());
      } catch {
        return jsonResponse(
          {
            error: "The supplied URL is invalid."
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
            error: "VirusTotal is not configured."
          },
          500
        );
      }

      const heuristicResult =
        analyzeUrlHeuristics(checkedUrl);

      const virusTotalResult =
        await checkVirusTotal(
          checkedUrl.href,
          env.VIRUSTOTAL_API_KEY,
          heuristicResult.usesUrlShortener
        );

      const overallResult = createOverallResult(
        virusTotalResult,
        heuristicResult
      );

      return jsonResponse({
        status: overallResult.status,
        message: overallResult.message,
        url: checkedUrl.href,
        hostname: checkedUrl.hostname,
        protocol: checkedUrl.protocol,
        checks: {
          heuristics: heuristicResult,
          virusTotal: virusTotalResult
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