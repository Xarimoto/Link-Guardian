# QR Guardian Privacy Policy

**Effective date:** July 23, 2026  
**Last updated:** July 23, 2026

QR Guardian is a Chrome extension developed and published by **Hari Bozhinov**.

This Privacy Policy explains what information QR Guardian processes, why it is processed, how third-party services are involved, and the choices available to users.

## 1. Overview

QR Guardian helps users inspect website links before opening them.

The extension analyzes links only when a user takes an explicit action, such as:

- Entering or pasting a URL into the extension
- Pressing the **Check URL** button
- Pressing Enter while a URL is entered
- Right-clicking a hyperlink and selecting **Check link with QR Guardian**

QR Guardian does not passively monitor browsing activity and does not automatically inspect every website a user visits.

## 2. Information Processed

When a user requests a security check, QR Guardian processes the submitted website address, also known as a URL.

The URL may contain:

- The website domain
- The protocol, such as HTTP or HTTPS
- A path to a specific webpage
- Query parameters
- A port number
- Other information included by the website in the URL

For shortened links, QR Guardian may also process:

- Redirect destinations
- Redirect status codes
- The final resolved URL
- The domains appearing in the redirect chain

QR Guardian also processes security-analysis results, including:

- VirusTotal reputation information
- Malicious detection counts
- Suspicious detection counts
- Harmless and undetected counts
- Local URL warning indicators
- Redirect-security warnings
- The date of the latest available VirusTotal analysis

Users should avoid submitting private, confidential, authenticated, or sensitive URLs that contain personal information, access tokens, session identifiers, or other confidential data.

## 3. How Information Is Used

Submitted URLs are processed only to provide the security-checking features requested by the user.

QR Guardian may use a submitted URL to:

- Validate and normalize the URL
- Detect suspicious URL characteristics
- Identify URL-shortening services
- Resolve shortened-link destinations
- Detect unusual redirect behavior
- Detect redirects from HTTPS to HTTP
- Retrieve an existing VirusTotal reputation report
- Display a security verdict and related warnings
- Determine which destination should be opened if the user chooses to continue

QR Guardian does not use submitted URLs for advertising, behavioral profiling, marketing, or unrelated purposes.

## 4. VirusTotal

QR Guardian uses the VirusTotal API to retrieve existing URL reputation reports.

Depending on the link being checked, QR Guardian may request an existing VirusTotal report for:

- The original URL
- The website homepage
- A shortened URL
- The resolved destination URL

QR Guardian does not automatically submit unknown URLs to VirusTotal for a new scan or rescan.

VirusTotal receives the URL information or URL-derived identifier required to locate an existing report. VirusTotal may process this information according to its own terms, privacy policy, and data-retention practices.

VirusTotal is operated independently from QR Guardian. QR Guardian does not control VirusTotal’s systems or policies.

## 5. Cloudflare

QR Guardian’s backend API runs on Cloudflare Workers.

The submitted URL is transmitted over HTTPS from the extension to the QR Guardian Cloudflare Worker so that the requested analysis can be performed.

QR Guardian’s application code:

- Does not intentionally store submitted URLs
- Does not maintain a scan-history database
- Does not use Cloudflare KV, D1, R2, Durable Objects, or Analytics Engine to store scans
- Does not include custom request logging
- Has automatic Worker invocation logging disabled
- Does not intentionally record user IP addresses

Cloudflare may still process limited technical information necessary to operate, secure, route, and maintain its network. This may include IP addresses, timestamps, routing data, request metadata, and aggregate service metrics.

Cloudflare processes this technical information according to its own privacy policy and service terms.

## 6. Redirect and Destination Requests

When a user checks a known shortened URL, the QR Guardian Worker may contact the shortening service to determine the final destination.

QR Guardian may make limited HTTP HEAD or GET requests while following the redirect chain.

As a result, the shortening service, intermediate redirect services, and destination website may receive a request originating from Cloudflare infrastructure. Those services may independently record technical request information according to their own server configurations and privacy policies.

QR Guardian follows a maximum of five redirects and applies a timeout to redirect requests.

The redirect information is processed temporarily for the requested scan and is not intentionally stored by QR Guardian after the request is completed.

## 7. Data Storage and Retention

QR Guardian does not intentionally retain:

- Submitted URLs
- Redirect chains
- Scan results
- Browsing history
- User profiles
- User accounts
- Persistent identifiers

Submitted information is processed temporarily in memory while the requested security check is performed.

QR Guardian does not provide a scan-history feature in its current version.

Third-party service providers, including Cloudflare, VirusTotal, URL-shortening services, and destination websites, may process or retain information according to their own policies and operational requirements.

## 8. Personal Information

QR Guardian does not require users to create an account.

QR Guardian does not intentionally request or collect:

- Names
- Email addresses
- Mailing addresses
- Telephone numbers
- Payment information
- Government identification numbers
- Precise physical location
- Contact lists
- Authentication credentials

However, a URL submitted by a user could contain personal or sensitive information. Users are responsible for reviewing URLs before submitting them and should not submit confidential or private links.

## 9. Sale, Advertising, and Profiling

QR Guardian does not:

- Sell user data
- Rent user data
- Use user data for targeted advertising
- Build advertising profiles
- Track users across unrelated websites
- Use submitted URLs for marketing
- Transfer submitted data for credit, insurance, employment, or lending decisions

Data is transmitted only as necessary to perform the security analysis requested by the user, operate the service, protect the service from abuse, or comply with applicable legal obligations.

## 10. Security

QR Guardian uses reasonable technical measures intended to protect submitted information, including:

- HTTPS connections between the extension and the backend API
- HTTPS connections to VirusTotal
- Cloudflare Worker secrets for the VirusTotal API key
- No VirusTotal API key stored inside the Chrome extension
- URL-length restrictions
- HTTP and HTTPS protocol validation
- Redirect-hop limits
- Redirect timeouts
- Blocking of unsafe redirect destinations
- Disabled automatic Worker invocation logging

No internet service can guarantee absolute security.

A QR Guardian result stating **No Known Threats** means that no known threats were identified by the available checks at that time. It does not guarantee that a website is completely safe.

## 11. User Choices

Users control when QR Guardian processes a URL.

A user may choose not to submit a URL, may close the extension without running a check, or may uninstall QR Guardian at any time through Chrome’s extension-management settings.

Because QR Guardian does not intentionally maintain user accounts or scan-history records, there is normally no QR Guardian account data or stored scan history to access, modify, or delete.

Questions or privacy requests may be sent to the contact address listed below.

## 12. Children’s Privacy

QR Guardian is a general-purpose website-security utility.

QR Guardian does not knowingly request names, contact information, account registrations, or other identifying information from children.

Users of any age should avoid submitting URLs containing personal, private, educational-record, authentication, or confidential information.

A parent, guardian, or school representative with a privacy concern may contact the publisher using the email address below.

## 13. Legal Requirements

Information may be disclosed if reasonably necessary to:

- Comply with applicable law, regulation, legal process, or governmental request
- Protect the security and integrity of QR Guardian
- Investigate abuse, fraud, or security incidents
- Protect the rights or safety of users, the publisher, or others

Because QR Guardian does not intentionally store submitted URLs or scan histories, it may not possess historical scan information to disclose.

## 14. Changes to This Privacy Policy

This Privacy Policy may be updated when QR Guardian’s features, service providers, data practices, or legal requirements change.

The updated policy will include a revised **Last updated** date.

Material changes affecting how user information is processed will be disclosed through an updated Chrome Web Store listing, updated extension documentation, or another appropriate notice.

## 15. Contact

For questions, privacy concerns, or requests relating to QR Guardian, contact:

**Hari Bozhinov**  
**Email:** hari.bozinov@gmail.com