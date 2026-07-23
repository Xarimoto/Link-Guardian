const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const result = document.getElementById("result");

const apiEndpoint =
  "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check";

function showResult(message, status = "") {
  result.textContent = message;
  result.className = status;
}

async function checkUrl(url) {
  if (!url) {
    showResult("Please enter a URL.", "error");
    return;
  }

  showResult("Checking URL...", "checking");
  checkButton.disabled = true;

  try {
    const response = await fetch(apiEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: url
      })
    });

    const data = await response.json();

    if (!response.ok) {
      showResult(
        data.error || "Unable to check the URL.",
        "error"
      );
      return;
    }

    const warnings =
      data.checks?.heuristics?.warnings ?? [];

    let message = data.message;

    if (warnings.length > 0) {
      message += ` Warning: ${warnings.join(" ")}`;
    }

    message += ` Hostname: ${data.hostname}`;

    switch (data.status) {
      case "dangerous":
        showResult(message, "dangerous");
        break;

      case "suspicious":
        showResult(message, "suspicious");
        break;

      case "no_known_threats":
        showResult(message, "safe");
        break;

      case "unknown":
        showResult(message, "unknown");
        break;

      default:
        showResult(message, "unavailable");
        break;
    }
  } catch {
    showResult(
      "Unable to connect to the QR Guardian API.",
      "error"
    );
  } finally {
    checkButton.disabled = false;
  }
}

checkButton.addEventListener("click", () => {
  checkUrl(urlInput.value.trim());
});
urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    checkUrl(urlInput.value.trim());
  }
});

const pageParameters =
  new URLSearchParams(window.location.search);

const rightClickedUrl =
  pageParameters.get("url");

if (rightClickedUrl) {
  urlInput.value = rightClickedUrl;
  checkUrl(rightClickedUrl);
}