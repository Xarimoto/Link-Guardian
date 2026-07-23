const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const result = document.getElementById("result");

const apiEndpoint = "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check";

async function checkUrl(url) {
  result.textContent = "Checking URL...";
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
      result.textContent = data.error || "Unable to check the URL.";
      return;
    }

    result.textContent =
      `${data.message} Hostname: ${data.hostname}`;
  } catch {
    result.textContent =
      "Unable to connect to the QR Guardian API.";
  } finally {
    checkButton.disabled = false;
  }
}

checkButton.addEventListener("click", () => {
  checkUrl(urlInput.value.trim());
});

const pageParameters = new URLSearchParams(window.location.search);
const rightClickedUrl = pageParameters.get("url");

if (rightClickedUrl) {
  urlInput.value = rightClickedUrl;
  checkUrl(rightClickedUrl);
}