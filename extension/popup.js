const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const openButton = document.getElementById("openButton");
const result = document.getElementById("result");

const apiEndpoint =
  "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check";

let approvedUrl = "";

function showResult(message, status = "") {
  result.textContent = message;
  result.className = status;
}

function normalizeUrlInput(value) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return "";
  }

  const hasProtocol =
    /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmedValue);

  if (!hasProtocol) {
    return `https://${trimmedValue}`;
  }

  return trimmedValue;
}

async function checkUrl(rawUrl) {
  const url = normalizeUrlInput(rawUrl);

  if (!url) {
    showResult("Please enter a URL.", "error");
    return;
  }

  urlInput.value = url;

  approvedUrl = "";
  openButton.hidden = true;
  openButton.textContent = "Open Website";
  openButton.className = "";

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
        approvedUrl = data.url;
        openButton.textContent = "Proceed Anyway";
        openButton.className = "proceed";
        openButton.hidden = false;
        break;

      case "no_known_threats":
        showResult(message, "safe");
        approvedUrl = data.url;
        openButton.textContent = "Open Website";
        openButton.className = "safe-open";
        openButton.hidden = false;
        break;

      case "unknown":
        showResult(message, "unknown");
        approvedUrl = data.url;
        openButton.textContent = "Proceed Anyway";
        openButton.className = "proceed";
        openButton.hidden = false;
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
  checkUrl(urlInput.value);
});

openButton.addEventListener("click", () => {
  if (!approvedUrl) {
    return;
  }

  chrome.tabs.create({
    url: approvedUrl
  });
});

urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    checkUrl(urlInput.value);
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