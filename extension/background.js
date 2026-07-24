chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "check-link",
      title: "Check link with Link Guardian",
      contexts: ["link"]
    });
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== "check-link" || !info.linkUrl) {
    return;
  }

  const guardianPage =
    chrome.runtime.getURL("popup.html") +
    "?url=" +
    encodeURIComponent(info.linkUrl);

  chrome.tabs.create({
    url: guardianPage
  });
});