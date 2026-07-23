const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

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

async function checkVirusTotal(url, apiKey) {
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
      status: "unknown",
      message: "VirusTotal has no existing report for this URL.",
      found: false
    };
  }

  if (response.status === 429) {
    return {
      status: "unavailable",
      message: "The VirusTotal request limit has been reached.",
      found: false
    };
  }

  if (!response.ok) {
    return {
      status: "unavailable",
      message: `VirusTotal returned error ${response.status}.`,
      found: false
    };
  }

  const report = await response.json();
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
      `VirusTotal detected this URL as malicious ` +
      `with ${malicious} detection(s).`;
  } else if (suspicious > 0) {
    status = "suspicious";
    message =
      `VirusTotal reported ${suspicious} suspicious detection(s).`;
  } else {
    status = "no_known_threats";
    message =
      "No known threats were found in the latest VirusTotal report.";
  }

  return {
    status,
    message,
    found: true,
    malicious,
    suspicious,
    harmless,
    undetected,
    lastAnalysisDate: attributes.last_analysis_date ?? null,
    finalUrl: attributes.last_final_url ?? url
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

    if (request.method === "GET" && requestUrl.pathname === "/") {
      return jsonResponse({
        service: "QR Guardian API",
        status: "online",
        version: "0.2.0"
      });
    }

    if (request.method === "POST" && requestUrl.pathname === "/v1/check") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          {
            error: "The request body must contain valid JSON."
          },
          400
        );
      }

      if (!body.url || typeof body.url !== "string") {
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
            error: "Only HTTP and HTTPS links are supported."
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

      const virusTotalResult = await checkVirusTotal(
        checkedUrl.href,
        env.VIRUSTOTAL_API_KEY
      );

      return jsonResponse({
        status: virusTotalResult.status,
        message: virusTotalResult.message,
        url: checkedUrl.href,
        hostname: checkedUrl.hostname,
        protocol: checkedUrl.protocol,
        checks: {
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