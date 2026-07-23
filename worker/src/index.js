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

export default {
  async fetch(request) {
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
        version: "0.1.0"
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

      return jsonResponse({
        status: "unscanned",
        message: "The URL is valid and ready for security checks.",
        url: checkedUrl.href,
        hostname: checkedUrl.hostname,
        protocol: checkedUrl.protocol
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