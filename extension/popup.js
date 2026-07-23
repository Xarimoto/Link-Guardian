const urlInput =
  document.getElementById("urlInput");

const checkButton =
  document.getElementById("checkButton");

const openButton =
  document.getElementById("openButton");

const resultCard =
  document.getElementById("resultCard");

const verdictBadge =
  document.getElementById("verdictBadge");

const hostnameValue =
  document.getElementById("hostnameValue");

const resultTitle =
  document.getElementById("resultTitle");

const resultMessage =
  document.getElementById("resultMessage");

const destinationSection =
  document.getElementById("destinationSection");

const destinationValue =
  document.getElementById("destinationValue");

const warningsSection =
  document.getElementById("warningsSection");

const warningsList =
  document.getElementById("warningsList");

const apiEndpoint =
  "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check";

let approvedUrl = "";

function normalizeUrlInput(value) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return "";
  }

  const hasProtocol =
    /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(
      trimmedValue
    );

  if (!hasProtocol) {
    return `https://${trimmedValue}`;
  }

  return trimmedValue;
}

function clearWarnings() {
  warningsList.replaceChildren();
  warningsSection.hidden = true;
}

function showWarnings(warnings) {
  clearWarnings();

  if (!warnings.length) {
    return;
  }

  for (const warning of warnings) {
    const listItem =
      document.createElement("li");

    listItem.textContent = warning;
    warningsList.appendChild(listItem);
  }

  warningsSection.hidden = false;
}

function showDestination(
  destinationUrl,
  destinationHostname
) {
  if (!destinationUrl) {
    destinationSection.hidden = true;
    destinationValue.textContent = "";
    return;
  }

  destinationValue.textContent =
    destinationHostname || destinationUrl;

  destinationValue.title =
    destinationUrl;

  destinationSection.hidden = false;
}

function resetOpenButton() {
  approvedUrl = "";
  openButton.hidden = true;
  openButton.textContent = "Open Website";
  openButton.className = "";
}

function showCheckingState(url) {
  resultCard.hidden = false;
  resultCard.className =
    "result-card checking";

  verdictBadge.textContent = "Checking";
  hostnameValue.textContent = "";

  resultTitle.textContent =
    "Inspecting link";

  resultMessage.textContent =
    `Checking ${url}`;

  showDestination(null, null);
  clearWarnings();
  resetOpenButton();
}

function showError(message) {
  resultCard.hidden = false;
  resultCard.className =
    "result-card error";

  verdictBadge.textContent = "Error";
  hostnameValue.textContent = "";

  resultTitle.textContent =
    "Unable to check link";

  resultMessage.textContent = message;

  showDestination(null, null);
  clearWarnings();
  resetOpenButton();
}

function configureOpenButton(
  status,
  websiteToOpen,
  hasDestination
) {
  resetOpenButton();

  if (
    status === "dangerous" ||
    status === "unavailable"
  ) {
    return;
  }

  approvedUrl = websiteToOpen;

  if (status === "no_known_threats") {
    openButton.textContent =
      hasDestination
        ? "Open Destination"
        : "Open Website";

    openButton.className = "safe-open";
  } else {
    openButton.textContent =
      hasDestination
        ? "Proceed to Destination"
        : "Proceed Anyway";

    openButton.className = "proceed";
  }

  openButton.hidden = false;
}

function showResult(data) {
  const warnings =
    data.checks?.heuristics?.warnings ?? [];

  const destinationUrl =
    data.destinationUrl || null;

  const destinationHostname =
    data.destinationHostname || null;

  const websiteToOpen =
    destinationUrl || data.url;

  resultCard.hidden = false;
  resultCard.className =
    `result-card ${data.status}`;

  hostnameValue.textContent =
    data.hostname || "";

  resultMessage.textContent =
    data.message || "URL check completed.";

  showDestination(
    destinationUrl,
    destinationHostname
  );

  showWarnings(warnings);

  switch (data.status) {
    case "dangerous":
      verdictBadge.textContent =
        "Dangerous";

      resultTitle.textContent =
        "Do not open this link";
      break;

    case "suspicious":
      verdictBadge.textContent =
        "Suspicious";

      resultTitle.textContent =
        "Proceed with caution";
      break;

    case "no_known_threats":
      verdictBadge.textContent =
        "No Known Threats";

      resultTitle.textContent =
        "No known threats detected";
      break;

    case "unknown":
      verdictBadge.textContent =
        "Unknown";

      resultTitle.textContent =
        "Reputation is unknown";
      break;

    default:
      verdictBadge.textContent =
        "Unavailable";

      resultTitle.textContent =
        "Security check unavailable";
      break;
  }

  configureOpenButton(
    data.status,
    websiteToOpen,
    Boolean(destinationUrl)
  );
}

async function checkUrl(rawUrl) {
  const url =
    normalizeUrlInput(rawUrl);

  if (!url) {
    showError("Please enter a URL.");
    return;
  }

  urlInput.value = url;

  showCheckingState(url);
  checkButton.disabled = true;

  try {
    const response = await fetch(
      apiEndpoint,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify({
          url
        })
      }
    );

    const data =
      await response.json();

    if (!response.ok) {
      showError(
        data.error ||
          "Unable to check the URL."
      );
      return;
    }

    showResult(data);
  } catch {
    showError(
      "Unable to connect to the QR Guardian API."
    );
  } finally {
    checkButton.disabled = false;
  }
}

checkButton.addEventListener(
  "click",
  () => {
    checkUrl(urlInput.value);
  }
);

openButton.addEventListener(
  "click",
  () => {
    if (!approvedUrl) {
      return;
    }

    chrome.tabs.create({
      url: approvedUrl
    });
  }
);

urlInput.addEventListener(
  "keydown",
  (event) => {
    if (event.key === "Enter") {
      checkUrl(urlInput.value);
    }
  }
);

const pageParameters =
  new URLSearchParams(
    window.location.search
  );

const rightClickedUrl =
  pageParameters.get("url");

if (rightClickedUrl) {
  urlInput.value = rightClickedUrl;
  checkUrl(rightClickedUrl);
}