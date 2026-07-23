const urlInput = document.getElementById("urlInput");
const checkButton = document.getElementById("checkButton");
const result = document.getElementById("result");

function checkUrl(url) {
  try {
    const checkedUrl = new URL(url);

    if (
      checkedUrl.protocol !== "http:" &&
      checkedUrl.protocol !== "https:"
    ) {
      result.textContent = "Only HTTP and HTTPS links are supported.";
      return;
    }

    result.textContent = `Valid URL: ${checkedUrl.hostname}`;
  } catch {
    result.textContent = "Please enter a valid URL.";
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