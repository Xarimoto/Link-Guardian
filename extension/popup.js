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

const virusTotalSection =
  document.getElementById("virusTotalSection");

const analysisDateValue =
  document.getElementById("analysisDateValue");

const maliciousValue =
  document.getElementById("maliciousValue");

const suspiciousValue =
  document.getElementById("suspiciousValue");

const harmlessValue =
  document.getElementById("harmlessValue");

const undetectedValue =
  document.getElementById("undetectedValue");

const warningsSection =
  document.getElementById("warningsSection");

const warningsList =
  document.getElementById("warningsList");

const apiEndpoint =
  "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check";

let approvedUrl = "";
function placeOpenButtonNearResult() {
  resultMessage.insertAdjacentElement(
    "afterend",
    openButton
  );
}

placeOpenButtonNearResult();

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

  if (
    !Array.isArray(warnings) ||
    warnings.length === 0
  ) {
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
    destinationValue.removeAttribute("title");
    return;
  }

  destinationValue.textContent =
    destinationHostname || destinationUrl;

  destinationValue.title =
    destinationUrl;

  destinationSection.hidden = false;
}

function resetVirusTotalDetails() {
  virusTotalSection.hidden = true;

  maliciousValue.textContent = "0";
  suspiciousValue.textContent = "0";
  harmlessValue.textContent = "0";
  undetectedValue.textContent = "0";

  analysisDateValue.textContent = "";
}

function getVirusTotalData(data) {
  return (
    data.checks?.virusTotal ||
    data.checks?.virustotal ||
    data.virusTotal ||
    data.virustotal ||
    null
  );
}

function getVirusTotalStats(
  virusTotalData
) {
  if (!virusTotalData) {
    return null;
  }

  const nestedStats =
    virusTotalData.stats ||
    virusTotalData.analysisStats ||
    virusTotalData.lastAnalysisStats ||
    virusTotalData.data?.attributes
      ?.last_analysis_stats;

  if (nestedStats) {
    return nestedStats;
  }

  const hasDirectStats =
    virusTotalData.malicious !== undefined ||
    virusTotalData.suspicious !== undefined ||
    virusTotalData.harmless !== undefined ||
    virusTotalData.undetected !== undefined;

  return hasDirectStats
    ? virusTotalData
    : null;
}

function getAnalysisDate(
  virusTotalData
) {
  if (!virusTotalData) {
    return null;
  }

  return (
    virusTotalData.analysisDate ||
    virusTotalData.lastAnalysisDate ||
    virusTotalData.lastAnalysisTimestamp ||
    virusTotalData.data?.attributes
      ?.last_analysis_date ||
    null
  );
}

function formatAnalysisDate(value) {
  if (!value) {
    return "";
  }

  let date;

  if (
    typeof value === "number" &&
    value < 1000000000000
  ) {
    date = new Date(value * 1000);
  } else {
    date = new Date(value);
  }

  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return date.toLocaleDateString(
    undefined,
    {
      year: "numeric",
      month: "short",
      day: "numeric"
    }
  );
}

function showVirusTotalDetails(data) {
  resetVirusTotalDetails();

  const virusTotalData =
    getVirusTotalData(data);

  const stats =
    getVirusTotalStats(
      virusTotalData
    );

  if (!stats) {
    return;
  }

  maliciousValue.textContent =
    String(stats.malicious ?? 0);

  suspiciousValue.textContent =
    String(stats.suspicious ?? 0);

  harmlessValue.textContent =
    String(stats.harmless ?? 0);

  undetectedValue.textContent =
    String(stats.undetected ?? 0);

  const formattedDate =
    formatAnalysisDate(
      getAnalysisDate(
        virusTotalData
      )
    );

  analysisDateValue.textContent =
    formattedDate
      ? `Analyzed ${formattedDate}`
      : "";

  virusTotalSection.hidden = false;
}

function resetOpenButton() {
  approvedUrl = "";

  openButton.hidden = true;
  openButton.textContent =
    "Open Website";

  openButton.className = "";
}

function showCheckingState(url) {
  resultCard.hidden = false;
  resultCard.className =
    "result-card checking";

  verdictBadge.textContent =
    "Checking";

  hostnameValue.textContent = "";

  resultTitle.textContent =
    "Inspecting link";

  resultMessage.textContent =
    `Checking ${url}`;

  showDestination(null, null);
  resetVirusTotalDetails();
  clearWarnings();
  resetOpenButton();
}

function showError(message) {
  resultCard.hidden = false;
  resultCard.className =
    "result-card error";

  verdictBadge.textContent =
    "Error";

  hostnameValue.textContent = "";

  resultTitle.textContent =
    "Unable to check link";

  resultMessage.textContent =
    message;

  showDestination(null, null);
  resetVirusTotalDetails();
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
    status === "unavailable" ||
    !websiteToOpen
  ) {
    return;
  }

  approvedUrl = websiteToOpen;

  if (
    status === "no_known_threats"
  ) {
    openButton.textContent =
      hasDestination
        ? "Open Destination"
        : "Open Website";

    openButton.className =
      "safe-open";
  } else {
    openButton.textContent =
      hasDestination
        ? "Proceed to Destination"
        : "Proceed Anyway";

    openButton.className =
      "proceed";
  }

  openButton.hidden = false;
}

function showResult(data) {
  const warnings =
    data.checks?.heuristics
      ?.warnings ?? [];

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
    data.message ||
    "URL check completed.";

  showDestination(
    destinationUrl,
    destinationHostname
  );

  showVirusTotalDetails(data);
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
    showError(
      "Please enter a URL."
    );

    return;
  }

  urlInput.value = url;

  showCheckingState(url);
  checkButton.disabled = true;

  try {
    const response =
      await fetch(
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
      "Unable to connect to the Link Guardian API."
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
  urlInput.value =
    normalizeUrlInput(
      rightClickedUrl
    );

  urlInput.focus();
}