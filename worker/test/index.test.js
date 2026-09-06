import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";

import worker from "../src/index.js";
import { checkGoogleSafeBrowsing } from "../src/googleSafeBrowsing.js";

const checkedUrl = "https://example.com/";
const analysisDate = 1787371783;

function virusTotalPayload(malicious = 0, suspicious = 0) {
  return {
    data: {
      attributes: {
        last_analysis_stats: {
          malicious,
          suspicious,
          harmless: 65,
          undetected: 27
        },
        last_analysis_date: analysisDate,
        last_final_url: checkedUrl
      }
    }
  };
}

function formattedVirusTotal(malicious = 0, suspicious = 0) {
  const status = malicious > 0
    ? "dangerous"
    : suspicious > 0
      ? "suspicious"
      : "no_known_threats";
  const message = malicious > 0
    ? `VirusTotal detected ${malicious} malicious result(s).`
    : suspicious > 0
      ? `VirusTotal reported ${suspicious} suspicious result(s).`
      : "No known threats were found in the latest VirusTotal report.";

  return {
    status,
    message,
    found: true,
    usedHomepageFallback: false,
    reportUrl: checkedUrl,
    malicious,
    suspicious,
    harmless: 65,
    undetected: 27,
    lastAnalysisDate: analysisDate,
    finalUrl: checkedUrl
  };
}

function expectedLegacyResponse(malicious = 0, suspicious = 0) {
  const virusTotal = formattedVirusTotal(malicious, suspicious);
  return {
    status: virusTotal.status,
    message: virusTotal.message,
    url: checkedUrl,
    hostname: "example.com",
    protocol: "https:",
    destinationUrl: null,
    destinationHostname: null,
    checks: {
      redirectResolution: {
        status: "not_needed",
        message: "Redirect resolution was not needed.",
        resolved: false,
        finalUrl: null,
        finalHostname: null,
        redirectChain: []
      },
      redirectHeuristics: {
        status: "clear",
        warningCount: 0,
        warnings: [],
        usesUrlShortener: false,
        hasHttpsDowngrade: false,
        redirectHostnames: [],
        redirectsToAnotherShortener: false
      },
      heuristics: {
        status: "clear",
        warningCount: 0,
        warnings: [],
        usesUrlShortener: false
      },
      virusTotal,
      virusTotalOriginal: virusTotal,
      virusTotalDestination: null
    }
  };
}

function createEnvironment(includeGoogleKey = true) {
  return {
    URL_CHECK_RATE_LIMITER: {
      limit: async () => ({ success: true })
    },
    VIRUSTOTAL_API_KEY: "test-virus-total-key",
    ...(includeGoogleKey
      ? { GOOGLE_SAFE_BROWSING_KEY: "test-google-key" }
      : {})
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function googleMatch(threatType = "MALWARE", cacheDuration = "300s") {
  return {
    threatType, platformType: "ANY_PLATFORM", threatEntryType: "URL",
    threat: { url: checkedUrl }, cacheDuration
  };
}

function createFetchMock({
  malicious = 0,
  suspicious = 0,
  virusTotalHandler = null,
  googleHandler = async () => jsonResponse({}),
  redirectHandler = null
} = {}) {
  return async (input, options = {}) => {
    const url = typeof input === "string" ? input : input.url;

    if (url.startsWith("https://www.virustotal.com/")) {
      if (virusTotalHandler) {
        return virusTotalHandler(url, options);
      }

      return jsonResponse(virusTotalPayload(malicious, suspicious));
    }

    if (url.startsWith("https://safebrowsing.googleapis.com/")) {
      return googleHandler(url, options);
    }

    if (redirectHandler) {
      return redirectHandler(url, options);
    }

    throw new Error(`Unexpected request to ${url}`);
  };
}

async function invokeWorker({
  fetchImplementation,
  environment = createEnvironment(),
  url = checkedUrl
}) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImplementation;

  try {
    const response = await worker.fetch(
      new Request("https://worker.test/v1/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "203.0.113.10"
        },
        body: JSON.stringify({ url })
      }),
      environment
    );
    return {
      status: response.status,
      body: await response.json()
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function separateGoogleResult(body) {
  const { googleSafeBrowsing, ...legacyChecks } = body.checks;
  return {
    googleSafeBrowsing,
    legacyResponse: {
      ...body,
      checks: legacyChecks
    }
  };
}

test("clean response preserves the complete legacy contract", async () => {
  const { status, body } = await invokeWorker({
    fetchImplementation: createFetchMock()
  });
  const separated = separateGoogleResult(body);

  assert.equal(status, 200);
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
  assert.deepEqual(separated.googleSafeBrowsing, {
    status: "ok",
    matched: false,
    threatTypes: []
  });
});

test("malicious VirusTotal response remains unchanged", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({ malicious: 2 })
  });

  assert.deepEqual(
    separateGoogleResult(body).legacyResponse,
    expectedLegacyResponse(2)
  );
});

test("Google threat matches remain provider-specific", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      googleHandler: async () => jsonResponse({
        matches: [
          googleMatch("SOCIAL_ENGINEERING", "60s"),
          googleMatch("MALWARE", "60s"),
          googleMatch("MALWARE", "60s")
        ]
      })
    })
  });
  const separated = separateGoogleResult(body);

  assert.deepEqual(separated.googleSafeBrowsing, {
    status: "ok",
    matched: true,
    threatTypes: ["SOCIAL_ENGINEERING", "MALWARE"]
  });
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("missing Google key returns not_configured without a request", async () => {
  let googleRequests = 0;
  const { body } = await invokeWorker({
    environment: createEnvironment(false),
    fetchImplementation: createFetchMock({
      googleHandler: async () => {
        googleRequests += 1;
        throw new Error("Google should not be called");
      }
    })
  });
  const separated = separateGoogleResult(body);

  assert.equal(googleRequests, 0);
  assert.deepEqual(separated.googleSafeBrowsing, {
    status: "not_configured",
    matched: false,
    threatTypes: []
  });
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("Google timeout maps to unavailable without a real network call", async () => {
  const result = await checkGoogleSafeBrowsing(checkedUrl, "test-key", {
    timeoutMs: 5,
    cache: null,
    cryptoImplementation: {},
    fetchImplementation: async (_url, options) => new Promise(
      (_resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        }, { once: true });
      }
    )
  });

  assert.deepEqual(result, {
    status: "unavailable",
    matched: false,
    threatTypes: []
  });
});

test("Google rate limit preserves successful VirusTotal output", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      googleHandler: async () => new Response(null, { status: 429 })
    })
  });
  const separated = separateGoogleResult(body);

  assert.equal(separated.googleSafeBrowsing.status, "rate_limited");
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("Google success remains available when VirusTotal is rate limited", async () => {
  const { status, body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      virusTotalHandler: async () => new Response(null, { status: 429 })
    })
  });

  assert.equal(status, 200);
  assert.deepEqual(body.checks.googleSafeBrowsing, {
    status: "ok",
    matched: false,
    threatTypes: []
  });
  assert.deepEqual(body.checks.virusTotal, {
    status: "unavailable",
    message: "The VirusTotal request limit has been reached.",
    found: false
  });
  assert.equal(body.status, "unavailable");
  assert.equal(
    body.message,
    "The VirusTotal request limit has been reached."
  );
});

test("malformed Google response maps to error", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      googleHandler: async () => jsonResponse({ matches: "invalid" })
    })
  });
  const separated = separateGoogleResult(body);

  assert.equal(separated.googleSafeBrowsing.status, "error");
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("Google network failure preserves successful VirusTotal output", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      googleHandler: async () => {
        throw new TypeError("network unavailable");
      }
    })
  });
  const separated = separateGoogleResult(body);

  assert.equal(separated.googleSafeBrowsing.status, "unavailable");
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("unknown new Google fields are ignored", async () => {
  const { body } = await invokeWorker({
    fetchImplementation: createFetchMock({
      googleHandler: async () => jsonResponse({
        matches: [],
        futureProviderField: { enabled: true }
      })
    })
  });
  const separated = separateGoogleResult(body);

  assert.deepEqual(separated.googleSafeBrowsing, {
    status: "ok",
    matched: false,
    threatTypes: []
  });
  assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
});

test("resolved shortener checks Google against the final destination", async () => {
  let googleCheckedUrl = null;
  const { body } = await invokeWorker({
    url: "https://bit.ly/guardian-demo",
    fetchImplementation: createFetchMock({
      googleHandler: async (_url, options) => {
        googleCheckedUrl = JSON.parse(options.body).threatInfo.threatEntries[0].url;
        return jsonResponse({});
      },
      redirectHandler: async (url) => {
        if (url === "https://bit.ly/guardian-demo") {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://example.com/final" }
          });
        }
        if (url === "https://example.com/final") {
          return new Response(null, { status: 200 });
        }
        throw new Error(`Unexpected redirect request to ${url}`);
      }
    })
  });

  assert.equal(googleCheckedUrl, "https://example.com/final");
  assert.equal(body.destinationUrl, "https://example.com/final");
  assert.equal(body.checks.googleSafeBrowsing.status, "ok");
});

test("Google cacheDuration prevents a duplicate provider request", async () => {
  const responses = new Map();
  const cache = {
    match: async (request) => responses.get(request.url)?.clone() ?? null,
    put: async (request, response) => {
      responses.set(request.url, response.clone());
    }
  };
  let networkCalls = 0;
  const options = {
    cache,
    cryptoImplementation: {
      subtle: {
        digest: async () => new Uint8Array(32).buffer
      }
    },
    fetchImplementation: async () => {
      networkCalls += 1;
      return jsonResponse({ matches: [googleMatch()] });
    }
  };

  const first = await checkGoogleSafeBrowsing(checkedUrl, "test-key", options);
  const second = await checkGoogleSafeBrowsing(checkedUrl, "test-key", options);

  assert.equal(networkCalls, 2); // Two list groups on the first lookup only.
  assert.deepEqual(second, first);
  assert.deepEqual(first, {
    status: "ok",
    matched: true,
    threatTypes: ["MALWARE"]
  });
});

test("v4 POST requests use supported list groups and implementation-only metadata", async () => {
  const requests = [];
  await invokeWorker({ fetchImplementation: createFetchMock({
    googleHandler: async (url, options) => {
      const parsed = new URL(url);
      assert.equal(parsed.origin + parsed.pathname, "https://safebrowsing.googleapis.com/v4/threatMatches:find");
      assert.equal(parsed.searchParams.get("key"), "test-google-key");
      assert.deepEqual([...parsed.searchParams.keys()], ["key"]);
      assert.equal(options.method, "POST");
      assert.equal(options.headers["Content-Type"], "application/json");
      requests.push(JSON.parse(options.body));
      return jsonResponse({});
    }
  }) });
  assert.deepEqual(requests, [
    { client: { clientId: "linkguardian", clientVersion: "0.6.2" }, threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url: checkedUrl }]
    } },
    { client: { clientId: "linkguardian", clientVersion: "0.6.2" }, threatInfo: {
      threatTypes: ["POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANDROID", "IOS"],
      threatEntryTypes: ["URL"], threatEntries: [{ url: checkedUrl }]
    } }
  ]);
});

for (const type of ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]) {
  test(`v4 ${type} match remains additive`, async () => {
    const { body } = await invokeWorker({ fetchImplementation: createFetchMock({
      googleHandler: async (_url, options) => jsonResponse(
        JSON.parse(options.body).threatInfo.threatTypes.includes(type)
          ? { matches: [googleMatch(type)] } : {}
      )
    }) });
    const separated = separateGoogleResult(body);
    assert.deepEqual(separated.googleSafeBrowsing, { status: "ok", matched: true, threatTypes: [type] });
    assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
  });
}

for (const payload of [null, [], { matches: null }, { matches: [{}] }, { error: "upstream diagnostic" }, { threats: [] }]) {
  test(`invalid v4 shape is isolated: ${JSON.stringify(payload)}`, async () => {
    const { body } = await invokeWorker({ fetchImplementation: createFetchMock({ googleHandler: async () => jsonResponse(payload) }) });
    const separated = separateGoogleResult(body);
    assert.equal(separated.googleSafeBrowsing.status, "error");
    assert.deepEqual(Object.keys(separated.googleSafeBrowsing), ["status", "matched", "threatTypes"]);
    assert.deepEqual(separated.legacyResponse, expectedLegacyResponse());
  });
}

test("invalid JSON is an error, not a verified no-match", async () => {
  const { body } = await invokeWorker({ fetchImplementation: createFetchMock({
    googleHandler: async () => new Response('{"matches":', { headers: { "Content-Type": "application/json" } })
  }) });
  assert.equal(body.checks.googleSafeBrowsing.status, "error");
  assert.deepEqual(separateGoogleResult(body).legacyResponse, expectedLegacyResponse());
});

test("one group failure prevents a partial lookup being reported as ok", async () => {
  const { body } = await invokeWorker({ fetchImplementation: createFetchMock({
    googleHandler: async (_url, options) => JSON.parse(options.body).threatInfo.platformTypes.includes("ANDROID")
      ? new Response(null, { status: 429 }) : jsonResponse({ matches: [googleMatch()] })
  }) });
  assert.equal(body.checks.googleSafeBrowsing.status, "rate_limited");
  assert.deepEqual(separateGoogleResult(body).legacyResponse, expectedLegacyResponse());
});

for (const [durations, ttl] of [[['300.900s','60s'],60], [['100000s'],86400], [['bogus'],0], [[undefined],0], [['0s'],0]]) {
  test(`match cache uses minimum capped TTL: ${JSON.stringify(durations)}`, async () => {
    const writes = [];
    const result = await checkGoogleSafeBrowsing(checkedUrl, "test-key", {
      cache: { match: async () => null, put: async (key, value) => writes.push({ key, value }) },
      cryptoImplementation: webcrypto,
      fetchImplementation: async () => jsonResponse({ matches: durations.map(duration => ({ ...googleMatch(), cacheDuration: duration })) })
    });
    assert.equal(result.status, "ok");
    assert.equal(writes.length, ttl ? 1 : 0);
    if (ttl) {
      assert.equal(writes[0].value.headers.get("Cache-Control"), `max-age=${ttl}`);
      const expected = Buffer.from(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(checkedUrl))).toString("hex");
      assert.equal(new URL(writes[0].key.url).pathname, `/v4-lookup/${expected}`);
      assert.equal(writes[0].key.url.includes("example.com"), false);
    }
  });
}

test("empty no-match responses and errors are never cached", async () => {
  for (const status of [200,429,500]) {
    let writes = 0;
    await checkGoogleSafeBrowsing(checkedUrl, "test-key", {
      cache: { match: async () => null, put: async () => { writes++; } }, cryptoImplementation: webcrypto,
      fetchImplementation: async () => jsonResponse({}, status)
    });
    assert.equal(writes, 0);
  }
});

test("cache read/write failures preserve a successful provider result", async () => {
  const result = await checkGoogleSafeBrowsing(checkedUrl, "test-key", {
    cache: { match: async () => { throw new Error("cache"); }, put: async () => { throw new Error("cache"); } },
    cryptoImplementation: webcrypto,
    fetchImplementation: async () => jsonResponse({ matches: [googleMatch()] })
  });
  assert.deepEqual(result, { status: "ok", matched: true, threatTypes: ["MALWARE"] });
});
