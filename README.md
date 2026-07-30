# Link Guardian

Link Guardian is a Chrome extension that inspects links before opening them.

It combines:

- VirusTotal reputation checks
- Shortened-link destination resolution
- Redirect-chain analysis
- Local URL security heuristics
- Clear Safe, Suspicious, Unknown, and Dangerous verdicts

## Current Version

- Chrome extension: `0.3.0`
- Cloudflare Worker API: `0.6.2`

## Current Features

### URL Inspection

Users can:

- Paste a URL into the extension
- Enter a domain without a protocol, such as `cnn.com`
- Press Enter or click **Check URL**
- Right-click a webpage link and select **Check link with Link Guardian**

### VirusTotal Integration

Link Guardian checks for existing VirusTotal reports.

It does not automatically submit unknown URLs for a new VirusTotal scan.

If VirusTotal has no report for an exact normal URL, Link Guardian checks the website homepage report.

Homepage fallback is disabled for URL-shortening services to prevent misleading results.

When a VirusTotal report is available, Link Guardian displays:

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results
- Last analysis date

### URL Shortener Analysis

Link Guardian recognizes common shortening services, including:

- `bit.ly`
- `tinyurl.com`
- `t.co`
- `goo.gl`
- `ow.ly`
- `buff.ly`
- `is.gd`
- `rebrand.ly`
- `rb.gy`
- `cutt.ly`
- `tiny.cc`
- `lnkd.in`

For shortened links, Link Guardian:

- Resolves up to five redirects
- Displays the final destination
- Checks the resolved destination with VirusTotal
- Opens the resolved destination instead of the shortened URL
- Blocks private, local, unsupported, or credential-containing redirect targets
- Warns about HTTPS-to-HTTP downgrades
- Warns about redirect chains crossing multiple domains
- Warns when one shortener redirects to another shortener

### Local URL Heuristics

Link Guardian warns when a URL:

- Uses an IP address instead of a domain
- Contains punycode characters
- Contains embedded username or password information
- Uses an unusual port
- Contains an unusually large number of subdomains
- Uses a URL-shortening service
- Redirects from HTTPS to HTTP
- Passes through multiple unrelated domains
- Redirects to another URL shortener

### Extension Branding

Link Guardian includes dedicated Chrome extension icons in the following sizes:

- 16 Ã— 16
- 32 Ã— 32
- 48 Ã— 48
- 128 Ã— 128

The icons are used in the Chrome toolbar, extension-management page, and extension metadata.

## Verdicts

### No Known Threats

Shown in green when VirusTotal reports no known malicious or suspicious detections and no local warning overrides the result.

The **Open Website** button is available.

### Suspicious

Shown in orange when Link Guardian detects warning signs, such as:

- A shortened URL
- An unusual redirect chain
- An HTTPS-to-HTTP redirect
- Suspicious URL structure
- A suspicious VirusTotal result

The user may select **Proceed Anyway** or **Proceed to Destination**.

### Unknown

Shown in amber when no reliable reputation report is available.

The user may proceed manually.

### Dangerous

Shown in red when:

- VirusTotal reports malicious detections
- A redirect targets a private or unsupported destination
- Another high-risk condition blocks opening

Link Guardian does not display an open button for dangerous results.

## Project Structure

Project Structure

Link-Guardian/
├── extension/
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon32.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   ├── background.js
│   ├── manifest.json
│   ├── popup.css
│   ├── popup.html
│   └── popup.js
│
├── privacy-site/
│   ├── icon128.png
│   └── index.html
│
├── worker/
│   ├── src/
│   │   └── index.js
│   ├── package.json
│   ├── package-lock.json
│   └── wrangler.jsonc
│
├── .gitignore
├── PRIVACY.md
└── README.md

## Development Requirements

- Google Chrome
- Visual Studio Code
- Git for Windows
- Node.js
- npm
- Cloudflare account
- VirusTotal API key

macOS is not required for Chrome extension development.

## Chrome Extension Setup

1. Open Chrome.
2. Navigate to:

```text
chrome://extensions/
```

3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose:

```text
C:\Projects\Link-Guardian\extension
```

After modifying extension files, return to `chrome://extensions/` and reload Link Guardian.

## Cloudflare Worker Setup

Install project dependencies:

```powershell
cd C:\Projects\Link-Guardian\worker
npm install
```

Authenticate Wrangler:

```powershell
npx wrangler login
```

Verify authentication:

```powershell
npx wrangler whoami
```

Store the VirusTotal API key securely:

```powershell
npx wrangler secret put VIRUSTOTAL_API_KEY
```

Do not place the VirusTotal API key inside the Chrome extension or source code.

## Local Worker Development

Start the local Worker:

```powershell
cd C:\Projects\Link-Guardian\worker
npx wrangler dev
```

The local API normally runs at:

```text
http://127.0.0.1:8787
```

## Worker Validation

Run a Cloudflare build validation without deploying:

```powershell
cd C:\Projects\Link-Guardian\worker
npx wrangler deploy --dry-run
```

## Worker Deployment

Deploy the Worker:

```powershell
cd C:\Projects\Link-Guardian\worker
npx wrangler deploy
```

Live API:

```text
https://qr-guardian-api.qr-guardian-hari.workers.dev
```

URL-check endpoint:

```text
POST /v1/check
```

Example request body:

```json
{
  "url": "https://example.com"
}
```

## PowerShell API Test

```powershell
Invoke-RestMethod `
  -Uri "https://qr-guardian-api.qr-guardian-hari.workers.dev/v1/check" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"url":"https://example.com"}' |
  ConvertTo-Json -Depth 10
```

## Git Workflow

Check repository status:

```powershell
cd C:\Projects\Link-Guardian
git status
```

Stage changes:

```powershell
git add .
```

Commit changes:

```powershell
git commit -m "Describe the completed change"
```

## Security Notes

- API keys remain in Cloudflare Worker secrets.
- The Chrome extension never receives the VirusTotal key.
- Only HTTP and HTTPS links are supported.
- URLs longer than 4,096 characters are rejected.
- Redirect resolution is limited to five hops.
- Redirect requests time out after five seconds.
- Local and private redirect destinations are blocked.
- Dangerous results cannot be opened through Link Guardian.
- Unknown URLs are not automatically submitted to VirusTotal.

## Planned Improvements

Potential future improvements include:

- QR-code decoding from images
- Right-click QR-image scanning
- Additional threat-intelligence providers
- Better domain-age and reputation checks
- Dark mode
- Improved result details
- Privacy documentation
- Optional scan history
- Chrome Web Store packaging
- Shared backend support for a future iOS app
