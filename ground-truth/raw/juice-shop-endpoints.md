# OWASP Juice Shop — HTTP Endpoint & API Gateway Allowlist Specification

> **Provenance & Target Metadata**
> - **Target Application:** OWASP Juice Shop
> - **Repository Tag:** `v20.1.1` (Pinned via `target-app/TARGET.lock`)
> - **Commit SHA:** `f915bddd82790d0f3018902d36ae9b4241a5f51f`
> - **Source Location:** `target-app/juice-shop` (`server.ts`, `routes/`, `models/`, `frontend/`)
> - **Purpose:** Ground-truth endpoint catalog for API Gateway routing, Allowlist enforcement, WAF rules, Authentication policies, and Rate Limiting.

---

## 1. Executive Summary & Architecture Overview

OWASP Juice Shop exposes several layers of HTTP interfaces:
1. **Custom REST API (`/rest/*`)**: Business logic endpoints (authentication, basket checkout, search, chat, 2FA, wallet, admin config).
2. **Finale/Sequelize Auto-generated REST API (`/api/*`)**: Auto-generated CRUD endpoints for Sequelize models with custom access control hooks.
3. **Enterprise B2B API (`/b2b/v2/*`)**: JSON-based B2B order creation with Swagger OpenAPI 3.0 documentation.
4. **File & Media Handling (`/file-upload`, `/profile/image/*`, `/ftp/*`, etc.)**: Multipart file uploads, directory listings, static assets, and log servers.
5. **Server-Side Rendered (SSR) & Dynamic Pages (`/profile`, `/dataerasure`, `/promotion`, `/video`, `/redirect`)**: Template rendering (Pug/Handlebars) and media streaming.
6. **Coding Challenges & Vulnerability Fix Engine (`/snippets/*`)**: Interactive code review and fix verification.
7. **Hidden, Easter Egg & CTF Challenge Endpoints**: Intentionally hidden routes for security exercises.
8. **Real-time WebSockets (`/socket.io/*`)**: Real-time notifications and challenge status tracking.
9. **Single Page Application (SPA) Client Routes (`/#/*`)**: Angular client routes served via hash routing with a root index fallback.

---

## 2. API Gateway Security Policy Levels

| Policy Level | Gateway Behavior | Description |
| :--- | :--- | :--- |
| **`PUBLIC_ANONYMOUS`** | `ALLOW` | Publicly accessible without credentials. |
| **`RATE_LIMITED_PUBLIC`** | `ALLOW + RATE_LIMIT` | Publicly accessible but throttled by IP/client identifier. |
| **`AUTHENTICATED_USER`** | `REQUIRE_JWT` | Requires valid Bearer JWT (`Authorization: Bearer <token>`) or `token` cookie. |
| **`ROLE_ADMIN`** | `REQUIRE_ADMIN` | Requires JWT with payload claim `role: admin`. |
| **`ROLE_ACCOUNTING`** | `REQUIRE_ACCOUNTING` | Requires JWT with payload claim `role: accounting`. |
| **`IP_RESTRICTED`** | `IP_ALLOWLIST` | Accessible only from trusted IP CIDR blocks (e.g. `123.456.789`). |
| **`DENIED_BLOCKED`** | `DENY_ALL (403)` | Blocked by default in production; explicit denial in application middleware. |
| **`INSPECT_PAYLOAD`** | `WAF_INSPECT` | High-risk input surface (e.g. XML/YAML/ZIP file upload, SQL query strings). |

---

## 3. Comprehensive Backend Endpoint Matrix

### 3.1. Authentication, Identity & Session (`/rest/user/*`, `/rest/2fa/*`, `/profile`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/rest/user/login` | `RATE_LIMITED_PUBLIC` | Authenticates user credentials.<br>**Body:** `{ "email": string, "password": string }`<br>**Returns:** `{ "authentication": { "token": string, "bid": number, "um": string } }` | Rate Limit: 30 req/min.<br>Inspect for SQL injection. |
| `GET` | `/rest/user/whoami` | `PUBLIC_ANONYMOUS` | Returns current logged-in user details from JWT cookie or `null`. | Allow with caching disabled. |
| `GET` | `/rest/user/change-password` | `AUTHENTICATED_USER` | Updates password.<br>**Query:** `?current=...&new=...&repeat=...`<br>**Header:** `Authorization: Bearer <token>` | Require Auth.<br>Recommend migrating to `POST`. |
| `POST` | `/rest/user/reset-password` | `RATE_LIMITED_PUBLIC` | Password reset via security question answer.<br>**Body:** `{ "email": string, "answer": string, "new": string }` | Rate Limit: 100 req / 5 min.<br>Monitor for brute-force. |
| `GET` | `/rest/user/security-question` | `PUBLIC_ANONYMOUS` | Retrieves security question registered for given email.<br>**Query:** `?email=string` | Allow. Validate email format. |
| `GET` | `/rest/user/authentication-details` | `ROLE_ADMIN` / `AUTHENTICATED_USER` | Lists all active user sessions.<br>**Header:** `Authorization: Bearer <token>` | Restrict to Admin or internal audit. |
| `POST` | `/rest/user/data-export` | `AUTHENTICATED_USER` | Requests user data export (orders, reviews, memories).<br>**Body:** `{ "imageCaptchaId": number, "answer": string, "UserId": number }`<br>**Header:** `Authorization: Bearer <token>` | Require Auth + Captcha validation. |
| `POST` | `/rest/2fa/verify` | `RATE_LIMITED_PUBLIC` | Verifies TOTP 2FA code.<br>**Body:** `{ "tmpToken": string, "totpToken": string }` | Rate Limit: 100 req / 5 min. |
| `GET` | `/rest/2fa/status` | `AUTHENTICATED_USER` | Checks if 2FA is enabled for current user.<br>**Header:** `Authorization: Bearer <token>` | Require Auth. |
| `POST` | `/rest/2fa/setup` | `AUTHENTICATED_USER` | Generates 2FA TOTP secret and QR code URI.<br>**Body:** `{ "password": string }`<br>**Header:** `Authorization: Bearer <token>` | Rate Limit: 100 req / 5 min.<br>Require Auth. |
| `POST` | `/rest/2fa/disable` | `AUTHENTICATED_USER` | Disables 2FA for current user.<br>**Body:** `{ "password": string }`<br>**Header:** `Authorization: Bearer <token>` | Rate Limit: 100 req / 5 min.<br>Require Auth. |
| `GET` | `/profile` | `AUTHENTICATED_USER` | Renders user profile SSR page.<br>**Cookie:** `token=<JWT>` | Require Auth.<br>Sanitize Pug SSR output. |
| `POST` | `/profile` | `AUTHENTICATED_USER` | Updates profile username.<br>**Body:** `username=string` (form URL-encoded)<br>**Cookie:** `token=<JWT>` | Require Auth + SameSite / CSRF mitigation. |

---

### 3.2. Product Catalog, Search & Reviews (`/rest/products/*`, `/api/Products*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/rest/products/search` | `PUBLIC_ANONYMOUS` | Searches product catalog.<br>**Query:** `?q=string`<br>**Returns:** `{ "status": "success", "data": Product[] }` | Allow.<br>High risk of SQL injection (`q`). |
| `GET` | `/rest/products/:id/reviews` | `PUBLIC_ANONYMOUS` | Retrieves MongoDB reviews for product `:id`.<br>**Param:** `id` (integer)<br>**Returns:** `{ "status": "success", "data": Review[] }` | Allow. Cacheable response. |
| `PUT` | `/rest/products/:id/reviews` | `PUBLIC_ANONYMOUS` | Submits a new product review.<br>**Param:** `id` (integer)<br>**Body:** `{ "message": string, "author": string }` | Rate Limit.<br>Inspect for stored XSS payloads. |
| `PATCH` | `/rest/products/reviews` | `AUTHENTICATED_USER` | Updates review content.<br>**Body:** `{ "id": string, "message": string }`<br>**Header:** `Authorization: Bearer <token>` | Require Auth.<br>Validate MongoDB ObjectId. |
| `POST` | `/rest/products/reviews` | `AUTHENTICATED_USER` | Increments review like count.<br>**Body:** `{ "id": string }`<br>**Header:** `Authorization: Bearer <token>` | Require Auth. |
| `GET` | `/api/Products` | `PUBLIC_ANONYMOUS` | Lists all products via Finale ORM.<br>**Returns:** `{ "status": "success", "data": Product[] }` | Allow. Standard catalog endpoint. |
| `GET` | `/api/Products/:id` | `PUBLIC_ANONYMOUS` | Retrieves single product details by `:id`. | Allow. |
| `POST` | `/api/Products` | `ROLE_ADMIN` / `AUTHENTICATED_USER` | Creates a new product catalog item.<br>**Body:** `{ "name": string, "description": string, "price": number, "image": string }` | Require Auth (Admin recommended). |
| `PUT` | `/api/Products/:id` | `ROLE_ADMIN` | Modifies product details. | Require Admin. |
| `DELETE` | `/api/Products/:id` | `DENIED_BLOCKED` | Deletes product (Explicitly denied). | Deny (403). |

---

### 3.3. Cart, Baskets & Checkout (`/rest/basket/*`, `/api/BasketItems*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/rest/basket/:id` | `AUTHENTICATED_USER` | Retrieves shopping basket details for basket `:id`.<br>**Header:** `Authorization: Bearer <token>` | Require Auth.<br>Verify Basket ownership (`UserId == bid`). |
| `POST` | `/rest/basket/:id/checkout` | `AUTHENTICATED_USER` | Places order for items in basket `:id`.<br>**Param:** `id` (integer)<br>**Header:** `Authorization: Bearer <token>`<br>**Returns:** `{ "orderConfirmation": { ... } }` | Require Auth.<br>Idempotency recommended. |
| `PUT` | `/rest/basket/:id/coupon/:coupon` | `AUTHENTICATED_USER` | Applies discount coupon code to basket `:id`.<br>**Param:** `id`, `coupon` (string, Z85 encoded) | Require Auth. |
| `GET` | `/api/BasketItems` | `AUTHENTICATED_USER` | Lists basket line items for user. | Require Auth. |
| `GET` | `/api/BasketItems/:id` | `AUTHENTICATED_USER` | Retrieves single basket item by `:id`. | Require Auth. |
| `POST` | `/api/BasketItems` | `AUTHENTICATED_USER` | Adds product to basket.<br>**Body:** `{ "ProductId": number, "BasketId": number, "quantity": number }` | Require Auth.<br>Enforce positive integer quantity. |
| `PUT` | `/api/BasketItems/:id` | `AUTHENTICATED_USER` | Updates quantity of basket item.<br>**Body:** `{ "quantity": number }` | Require Auth. |
| `DELETE` | `/api/BasketItems/:id` | `AUTHENTICATED_USER` | Removes item from shopping basket. | Require Auth. |

---

### 3.4. Orders, Delivery & Tracking (`/rest/order-history*`, `/rest/track-order/*`, `/api/Deliverys*`, `/b2b/v2/*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/rest/order-history` | `AUTHENTICATED_USER` | Lists order history for current authenticated user. | Require Auth. |
| `GET` | `/rest/order-history/orders` | `ROLE_ACCOUNTING` | Lists order history across all users.<br>**Header:** `Authorization: Bearer <token>` | Require Accounting role. |
| `PUT` | `/rest/order-history/:id/delivery-status` | `ROLE_ACCOUNTING` | Updates delivery status of order `:id`.<br>**Body:** `{ "deliveryStatus": string }` | Require Accounting role. |
| `GET` | `/rest/track-order/:id` | `PUBLIC_ANONYMOUS` | Tracks order status and delivery timeline by order `:id`.<br>**Query/Param:** `id` | Allow.<br>Inspect for SQL injection in `:id`. |
| `GET` | `/api/Deliverys` | `PUBLIC_ANONYMOUS` | Lists available shipping methods (Standard, Fast, Express). | Allow. Cacheable. |
| `GET` | `/api/Deliverys/:id` | `PUBLIC_ANONYMOUS` | Retrieves delivery method details by `:id`. | Allow. |
| `POST` | `/b2b/v2/orders` | `AUTHENTICATED_USER` | Enterprise B2B bulk order placement.<br>**Body:** `{ "cid": string, "orderLines": OrderLine[] }` or `{ "cid": string, "orderLinesData": string }` | Require Auth.<br>Strict JSON schema validation. |
| `GET` | `/api-docs` | `PUBLIC_ANONYMOUS` | Swagger UI documentation interface for B2B API. | Allow. |
| `GET` | `/api-docs/*` | `PUBLIC_ANONYMOUS` | Swagger UI static assets (JS, CSS, YAML). | Allow. |

---

### 3.5. Wallet, Payment & Deluxe Membership (`/rest/wallet/*`, `/api/Cards*`, `/rest/deluxe-membership`, `/rest/web3/*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/rest/wallet/balance` | `AUTHENTICATED_USER` | Returns current user's digital wallet balance.<br>**Returns:** `{ "data": number }` | Require Auth. |
| `PUT` | `/rest/wallet/balance` | `AUTHENTICATED_USER` | Adds balance to digital wallet.<br>**Body:** `{ "balance": number }` | Require Auth.<br>Validate non-negative balance increments. |
| `GET` | `/rest/deluxe-membership` | `AUTHENTICATED_USER` | Returns status and cost of Deluxe membership. | Require Auth. |
| `POST` | `/rest/deluxe-membership` | `AUTHENTICATED_USER` | Upgrades user to Deluxe tier.<br>**Body:** `{ "paymentMode": string, "paymentId": number }` | Require Auth. |
| `GET` | `/api/Cards` | `AUTHENTICATED_USER` | Lists saved payment cards for user. | Require Auth.<br>Ensure PCI/card number masking. |
| `GET` | `/api/Cards/:id` | `AUTHENTICATED_USER` | Retrieves specific payment card by `:id`. | Require Auth. |
| `POST` | `/api/Cards` | `AUTHENTICATED_USER` | Adds a payment card.<br>**Body:** `{ "fullName": string, "cardNum": number, "expMonth": number, "expYear": number }` | Require Auth.<br>Inspect card length and format. |
| `PUT` | `/api/Cards/:id` | `DENIED_BLOCKED` | Updates card details (Explicitly denied). | Deny (403). |
| `DELETE` | `/api/Cards/:id` | `AUTHENTICATED_USER` | Deletes saved payment card by `:id`. | Require Auth. |
| `POST` | `/rest/web3/submitKey` | `PUBLIC_ANONYMOUS` | Submits private key for Web3 NFT challenge.<br>**Body:** `{ "privateKey": string }` | Rate Limit: 30 req/min. |
| `GET` | `/rest/web3/nftUnlocked` | `PUBLIC_ANONYMOUS` | Checks if Web3 NFT challenge has been unlocked. | Allow. |
| `GET` | `/rest/web3/nftMintListen` | `PUBLIC_ANONYMOUS` | Initializes Alchemy Sepolia WebSocket listener for NFT mint. | Allow / Control backend resource usage. |
| `POST` | `/rest/web3/walletNFTVerify` | `PUBLIC_ANONYMOUS` | Verifies whether wallet address minted NFT.<br>**Body:** `{ "walletAddress": string }` | Allow. |
| `POST` | `/rest/web3/walletExploitAddress` | `PUBLIC_ANONYMOUS` | Registers wallet address to listen for smart contract exploit.<br>**Body:** `{ "walletAddress": string }` | Allow. |

---

### 3.6. Customer Service, Complaints & Chatbot (`/api/Feedbacks*`, `/api/Complaints*`, `/rest/chat`, `/dataerasure`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/Feedbacks` | `PUBLIC_ANONYMOUS` | Returns customer feedback items (used for carousel). | Allow. |
| `GET` | `/api/Feedbacks/:id` | `AUTHENTICATED_USER` | Retrieves single feedback item by `:id`. | Require Auth. |
| `POST` | `/api/Feedbacks` | `PUBLIC_ANONYMOUS` | Submits feedback.<br>**Body:** `{ "comment": string, "rating": number, "captchaId": number, "captcha": string, "UserId": number }` | Rate Limit.<br>Inspect for XSS / Forgery. |
| `PUT` | `/api/Feedbacks/:id` | `DENIED_BLOCKED` | Updates feedback (Explicitly denied). | Deny (403). |
| `DELETE` | `/api/Feedbacks/:id` | `ROLE_ADMIN` / `AUTHENTICATED_USER` | Deletes feedback item by `:id`. | Require Auth / Admin. |
| `GET` | `/api/Complaints` | `AUTHENTICATED_USER` | Lists customer complaints filed by user. | Require Auth. |
| `GET` | `/api/Complaints/:id` | `DENIED_BLOCKED` | Retrieves complaint by `:id` (Explicitly denied). | Deny (403). |
| `POST` | `/api/Complaints` | `AUTHENTICATED_USER` | Submits customer complaint.<br>**Body:** `{ "message": string, "file": string }` | Require Auth. |
| `PUT` | `/api/Complaints/:id` | `DENIED_BLOCKED` | Updates complaint (Explicitly denied). | Deny (403). |
| `DELETE` | `/api/Complaints/:id` | `DENIED_BLOCKED` | Deletes complaint (Explicitly denied). | Deny (403). |
| `POST` | `/rest/chat` | `PUBLIC_ANONYMOUS` / `AUTHENTICATED_USER` | AI Chatbot interface (Juicy).<br>**Header:** `Accept: text/event-stream`<br>**Body:** `{ "messages": [{ "role": "user", "content": string }] }`<br>**Returns:** Server-Sent Events stream | Streaming enabled (`text/event-stream`).<br>Rate Limit: 20 req/min.<br>Prompt injection guard. |
| `GET` | `/dataerasure` | `AUTHENTICATED_USER` | Renders GDPR Data Erasure Form.<br>**Cookie:** `token=<JWT>` | Require Auth. |
| `POST` | `/dataerasure` | `AUTHENTICATED_USER` | Executes GDPR Data Erasure.<br>**Body:** `{ "email": string, "securityAnswer": string, "layout": string }` | Require Auth.<br>Sanitize `layout` path parameter (LFI risk). |

---

### 3.7. Address, Security Questions & Privacy Requests (`/api/Addresss*`, `/api/SecurityQuestions*`, `/api/SecurityAnswers*`, `/api/PrivacyRequests*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/Addresss` | `AUTHENTICATED_USER` | Lists delivery addresses for logged-in user. | Require Auth. |
| `GET` | `/api/Addresss/:id` | `AUTHENTICATED_USER` | Retrieves delivery address by `:id`. | Require Auth. |
| `POST` | `/api/Addresss` | `AUTHENTICATED_USER` | Adds delivery address.<br>**Body:** `{ "country": string, "fullName": string, "mobileNum": number, "zipCode": string, "streetAddress": string, "city": string, "state": string }` | Require Auth. |
| `PUT` | `/api/Addresss/:id` | `AUTHENTICATED_USER` | Updates delivery address by `:id`. | Require Auth. |
| `DELETE` | `/api/Addresss/:id` | `AUTHENTICATED_USER` | Deletes delivery address by `:id`. | Require Auth. |
| `GET` | `/api/SecurityQuestions` | `PUBLIC_ANONYMOUS` | Lists standard security questions. | Allow. Cacheable. |
| `GET` | `/api/SecurityQuestions/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `POST` | `/api/SecurityQuestions` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `PUT` | `/api/SecurityQuestions/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/SecurityQuestions/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/api/SecurityAnswers` | `DENIED_BLOCKED` | Denied by default to prevent leakage. | Deny (403). |
| `GET` | `/api/SecurityAnswers/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `POST` | `/api/SecurityAnswers` | `PUBLIC_ANONYMOUS` | Sets security answer during registration or password change.<br>**Body:** `{ "SecurityQuestionId": number, "UserId": number, "answer": string }` | Allow during user flow. |
| `PUT` | `/api/SecurityAnswers/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/SecurityAnswers/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/api/PrivacyRequests` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/api/PrivacyRequests/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `POST` | `/api/PrivacyRequests` | `AUTHENTICATED_USER` | Creates a GDPR privacy deletion request.<br>**Body:** `{ "UserId": number, "deletionRequested": boolean }` | Require Auth. |
| `PUT` | `/api/PrivacyRequests/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/PrivacyRequests/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |

---

### 3.8. App Config, Captcha, Languages & Utilities (`/rest/admin/*`, `/rest/captcha*`, `/rest/continue-code*`, `/redirect`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/rest/admin/application-version` | `PUBLIC_ANONYMOUS` | Returns current application version string. | Allow. |
| `GET` | `/rest/admin/application-configuration` | `PUBLIC_ANONYMOUS` | Returns runtime application configuration metadata. | Allow. (Contains challenge configs). |
| `GET` | `/rest/captcha` | `PUBLIC_ANONYMOUS` | Generates mathematical text captcha.<br>**Returns:** `{ "captchaId": number, "captcha": string }` | Rate Limit: 60 req/min. |
| `GET` | `/rest/image-captcha` | `PUBLIC_ANONYMOUS` | Generates SVG image captcha.<br>**Returns:** `{ "imageCaptchaId": number, "image": string }` | Rate Limit: 60 req/min. |
| `GET` | `/rest/languages` | `PUBLIC_ANONYMOUS` | Returns list of supported language locales. | Allow. Cacheable. |
| `GET` | `/rest/country-mapping` | `PUBLIC_ANONYMOUS` | Returns country IP mapping configuration. | Allow. |
| `GET` | `/rest/saveLoginIp` | `AUTHENTICATED_USER` | Records last login IP for user session. | Allow. |
| `GET` | `/rest/repeat-notification` | `PUBLIC_ANONYMOUS` | Re-emits notification for solved challenge.<br>**Query:** `?challenge=string` | Allow. |
| `GET` | `/rest/continue-code` | `PUBLIC_ANONYMOUS` | Returns continuous progress token for solved challenges. | Allow. |
| `GET` | `/rest/continue-code-findIt` | `PUBLIC_ANONYMOUS` | Returns continue code for "Find It" challenges. | Allow. |
| `GET` | `/rest/continue-code-fixIt` | `PUBLIC_ANONYMOUS` | Returns continue code for "Fix It" challenges. | Allow. |
| `PUT` | `/rest/continue-code/apply/:continueCode` | `PUBLIC_ANONYMOUS` | Restores challenge progress from continue code. | Allow. |
| `PUT` | `/rest/continue-code-findIt/apply/:continueCode` | `PUBLIC_ANONYMOUS` | Restores "Find It" challenge progress. | Allow. |
| `PUT` | `/rest/continue-code-fixIt/apply/:continueCode` | `PUBLIC_ANONYMOUS` | Restores "Fix It" challenge progress. | Allow. |
| `GET` | `/redirect` | `PUBLIC_ANONYMOUS` | Redirects to external URLs.<br>**Query:** `?to=url`<br>**Validation:** Checked against `redirectAllowlist` | Inspect `to` parameter.<br>Block unapproved destinations. |

---

### 3.9. Coding Challenges & Vulnerability Fixes (`/api/Challenges*`, `/api/Hints*`, `/snippets/*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/Challenges` | `PUBLIC_ANONYMOUS` | Lists all CTF challenges and status. | Allow. |
| `GET` | `/api/Challenges/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `POST` | `/api/Challenges` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `PUT` | `/api/Challenges/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/Challenges/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/api/Hints` | `PUBLIC_ANONYMOUS` | Lists challenge hints. | Allow. |
| `GET` | `/api/Hints/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `PUT` | `/api/Hints/:id` | `PUBLIC_ANONYMOUS` | Updates hint text.<br>**Body:** `{ "text": string }` | Allow. |
| `POST` | `/api/Hints` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/Hints/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/snippets/:challenge` | `PUBLIC_ANONYMOUS` | Retrieves vulnerable code snippet for challenge key. | Allow. |
| `POST` | `/snippets/verdict` | `PUBLIC_ANONYMOUS` | Submits line verdict for "Find It" challenge.<br>**Body:** `{ "key": string, "selectedLines": number[] }` | Allow. |
| `GET` | `/snippets/fixes/:key` | `PUBLIC_ANONYMOUS` | Retrieves code fix candidates for challenge key. | Allow. |
| `POST` | `/snippets/fixes` | `PUBLIC_ANONYMOUS` | Submits code fix selection for "Fix It" challenge.<br>**Body:** `{ "key": string, "selectedFix": number }` | Allow. |
| `GET` | `/solve/challenges/server-side` | `PUBLIC_ANONYMOUS` | Verifies SSTI / SSRF challenge solving state.<br>**Query:** `?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3` | Allow. |

---

### 3.10. Recycling, Memories & Administration Models (`/api/Recycles*`, `/rest/memories`, `/api/Quantitys*`, `/api/Users*`)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/Recycles` | `DENIED_BLOCKED` | Blocked via `recycles.blockRecycleItems()`. | Deny (403). |
| `GET` | `/api/Recycles/:id` | `PUBLIC_ANONYMOUS` | Retrieves single recycle item by `:id`. | Allow. |
| `POST` | `/api/Recycles` | `AUTHENTICATED_USER` | Submits recycle request `{ quantity, address, isPickup, date }`. | Require Auth. |
| `PUT` | `/api/Recycles/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/Recycles/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/rest/memories` | `PUBLIC_ANONYMOUS` | Retrieves shared memories / photos posted by users. | Allow. |
| `POST` | `/rest/memories` | `AUTHENTICATED_USER` | Uploads memory image.<br>**Multipart:** `caption=string`, `image=<file>` | Require Auth.<br>Max file size 200KB. |
| `GET` | `/api/Quantitys` | `PUBLIC_ANONYMOUS` | Lists stock item quantities. | Allow. |
| `GET` | `/api/Quantitys/:id` | `IP_RESTRICTED` & `ROLE_ACCOUNTING` | Retrieves item stock quantity by ID.<br>**Requires:** Role `accounting` AND Client IP `123.456.789`. | Restrict to Accounting role & trusted IP. |
| `PUT` | `/api/Quantitys/:id` | `IP_RESTRICTED` & `ROLE_ACCOUNTING` | Updates item stock quantity.<br>**Requires:** Role `accounting` AND Client IP `123.456.789`. | Restrict to Accounting role & trusted IP. |
| `POST` | `/api/Quantitys` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `DELETE` | `/api/Quantitys/:id` | `DENIED_BLOCKED` | Denied by default. | Deny (403). |
| `GET` | `/api/Users` | `AUTHENTICATED_USER` | Lists users (Finale ORM). | Require Auth (Admin recommended). |
| `GET` | `/api/Users/:id` | `AUTHENTICATED_USER` | Retrieves single user details by `:id`. | Require Auth. |
| `POST` | `/api/Users` | `PUBLIC_ANONYMOUS` | Registers new user account.<br>**Body:** `{ "email": string, "password": string, "passwordRepeat": string, "securityQuestion": object, "securityAnswer": string }` | Rate Limit: 20 req/min. |
| `PUT` | `/api/Users/:id` | `DENIED_BLOCKED` | Explicitly denied (`denyAll()`). | Deny (403). |
| `DELETE` | `/api/Users/:id` | `DENIED_BLOCKED` | Explicitly denied (`denyAll()`). | Deny (403). |

---

### 3.11. File Uploads & Static / Directory Serving (`/file-upload`, `/profile/image/*`, `/ftp/*`, `/encryptionkeys/*`, etc.)

| HTTP Method | Endpoint Path | Auth Level | Description & Parameters | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/file-upload` | `RATE_LIMITED_PUBLIC` | Complaint / B2B file upload handler.<br>**Multipart:** `file=<binary>` (ZIP, XML, YAML, PDF).<br>**Vulnerabilities:** XXE, YAML deserialization, Zip slip. | Strict body inspection / Antivirus scan.<br>Limit upload size to 200KB. |
| `POST` | `/profile/image/file` | `AUTHENTICATED_USER` | Uploads user profile image file.<br>**Multipart:** `file=<image/png\|jpg>` | Require Auth.<br>Validate MIME type & size. |
| `POST` | `/profile/image/url` | `AUTHENTICATED_USER` | Fetches avatar image from external URL.<br>**Body:** `{ "imageUrl": string }`<br>**Vulnerability:** SSRF. | Require Auth.<br>Egress proxy allowlist for `imageUrl`. |
| `GET` | `/ftp` | `PUBLIC_ANONYMOUS` | Directory listing of `ftp/` directory. | Block in production / Sandbox in CTF. |
| `GET` | `/ftp/:file` | `PUBLIC_ANONYMOUS` | Downloads file from `ftp/` (`.md`, `.pdf`, `.kdbx`).<br>**Vulnerability:** Poison null byte / Path traversal. | Sanitize path parameter. |
| `GET` | `/ftp/quarantine/:file` | `PUBLIC_ANONYMOUS` | Downloads quarantined file from `ftp/quarantine/`. | Sanitize path parameter. |
| `GET` | `/.well-known` | `PUBLIC_ANONYMOUS` | Directory listing of `/.well-known/`. | Allow. |
| `GET` | `/.well-known/*` | `PUBLIC_ANONYMOUS` | Static `.well-known` files (e.g. CSAF metadata). | Allow. |
| `GET` | `/.well-known/security.txt` | `PUBLIC_ANONYMOUS` | RFC 9116 Security contact information. | Allow. Cacheable. |
| `GET` | `/security.txt` | `PUBLIC_ANONYMOUS` | Security contact information alias. | Allow. Cacheable. |
| `GET` | `/robots.txt` | `PUBLIC_ANONYMOUS` | Robots exclusion file (Disallow: `/ftp`). | Allow. Cacheable. |
| `GET` | `/encryptionkeys` | `PUBLIC_ANONYMOUS` | Directory listing of `encryptionkeys/`. | Block in production / Allow in CTF. |
| `GET` | `/encryptionkeys/:file` | `PUBLIC_ANONYMOUS` | Serves public/private keys (e.g. `jwt.pub`, `jwt.key`). | Block in production / Allow in CTF. |
| `GET` | `/support/logs` | `PUBLIC_ANONYMOUS` | Directory listing of `logs/` directory. | Block in production / Allow in CTF. |
| `GET` | `/support/logs/:file` | `PUBLIC_ANONYMOUS` | Serves log files (e.g. `access.log.YYYY-MM-DD`). | Block in production / Allow in CTF. |
| `GET` | `/promotion` | `PUBLIC_ANONYMOUS` | Promotional video HTML page (Pug SSR). | Allow. |
| `GET` | `/video` | `PUBLIC_ANONYMOUS` | Streams promo video (`owasp_promo.mp4`) with `Range` header support. | Allow byte-range requests (HTTP 206). |
| `GET` | `/vendor/beercss/*` | `PUBLIC_ANONYMOUS` | Static BeerCSS library assets. | Allow. Cacheable static assets. |
| `GET` | `/vendor/material-icons/*` | `PUBLIC_ANONYMOUS` | Material Icons fonts. | Allow. Cacheable static assets. |
| `GET` | `/vendor/fontsource-roboto/*`| `PUBLIC_ANONYMOUS` | Roboto font family assets. | Allow. Cacheable static assets. |
| `GET` | `/assets/public/images/padding/*` | `PUBLIC_ANONYMOUS` | Challenge verification tracking images (e.g. `1px.png`). | Allow. |
| `GET` | `/assets/public/images/products/*` | `PUBLIC_ANONYMOUS` | Product images. | Allow. Cacheable. |
| `GET` | `/assets/public/images/uploads/*` | `PUBLIC_ANONYMOUS` | Uploaded memory images. | Allow. |
| `GET` | `/assets/i18n/*` | `PUBLIC_ANONYMOUS` | Internationalization translation JSON files. | Allow. Cacheable. |

---

### 3.12. Hidden, Easter Egg & Paywall Endpoints

| HTTP Method | Endpoint Path | Auth Level | Description | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg` | `PUBLIC_ANONYMOUS` | Serves Three.js Easter Egg 3D planet visualization (`threejs-demo.html`). | Allow (CTF challenge). |
| `GET` | `/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us` | `PUBLIC_ANONYMOUS` | Serves premium 1080p VR wallpaper (`JuiceShop_Wallpaper_1920x1080_VR.jpg`). | Allow (CTF challenge). |
| `GET` | `/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility` | `PUBLIC_ANONYMOUS` | Serves Privacy Policy proof image (`thank-you.jpg`). | Allow (CTF challenge). |

---

### 3.13. Observability & Monitoring

| HTTP Method | Endpoint Path | Auth Level | Description & Content-Type | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/metrics` | `PUBLIC_ANONYMOUS` / `INTERNAL_MONITORING` | Prometheus metric exposition (`text/plain`). Exposes request counters, latency gauges, token metrics. | Allow or restrict to Prometheus scraper IP range. |

---

### 3.14. Real-time WebSocket Gateway Routes

| Protocol | Path | Direction | Events Handled | Gateway Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| `WS / WSS` / `HTTP` | `/socket.io/*` | Bidirectional | **Server -> Client:**<br>- `server started`<br>- `challenge solved`<br>**Client -> Server:**<br>- `notification received`<br>- `verifyLocalXssChallenge`<br>- `verifySvgInjectionChallenge`<br>- `verifyCloseNotificationsChallenge` | Enable WebSocket upgrade headers (`Upgrade: websocket`, `Connection: Upgrade`).<br>Set sticky sessions if scaling horizontally. |

---

## 4. Frontend Single Page Application (SPA) Routes

The Angular frontend operates via HTML5 hash routing (`/#/<route>`) and is served by Express via `serveAngularClient()` for all non-`/api` and non-`/rest` root paths:

| Client Hash Route | Guard / Protection | Component / View |
| :--- | :--- | :--- |
| `/#/` | None | Search & Product Grid (`SearchResultComponent`) |
| `/#/administration` | `AdminGuard` | Admin Dashboard (`AdministrationComponent`) |
| `/#/accounting` | `AccountingGuard` | Accounting Order Dashboard (`AccountingComponent`) |
| `/#/about` | None | About OWASP Juice Shop (`AboutComponent`) |
| `/#/address/select` | `LoginGuard` | Select Shipping Address (`AddressSelectComponent`) |
| `/#/address/saved` | `LoginGuard` | Manage Saved Addresses (`SavedAddressComponent`) |
| `/#/address/create` | `LoginGuard` | Create New Address (`AddressCreateComponent`) |
| `/#/address/edit/:addressId` | `LoginGuard` | Edit Existing Address (`AddressCreateComponent`) |
| `/#/delivery-method` | None | Select Delivery Speed (`DeliveryMethodComponent`) |
| `/#/deluxe-membership` | `LoginGuard` | Upgrade Deluxe Tier (`DeluxeUserComponent`) |
| `/#/saved-payment-methods` | None | Manage Saved Cards (`SavedPaymentMethodsComponent`) |
| `/#/basket` | None | Shopping Basket View (`BasketComponent`) |
| `/#/order-completion/:id` | None | Order Success Receipt (`OrderCompletionComponent`) |
| `/#/contact` | None | Feedback & Rating Submission (`ContactComponent`) |
| `/#/photo-wall` | None | Community Photo Wall (`PhotoWallComponent`) |
| `/#/complain` | None | File Complaint / Upload (`ComplaintComponent`) |
| `/#/order-summary` | None | Order Summary Before Payment (`OrderSummaryComponent`) |
| `/#/order-history` | None | User Order History (`OrderHistoryComponent`) |
| `/#/payment/:entity` | None | Payment Checkout (`PaymentComponent`) |
| `/#/wallet` | None | Digital Wallet (`WalletComponent`) |
| `/#/login` | None | Login Form (`LoginComponent`) |
| `/#/forgot-password` | None | Security Question Password Reset (`ForgotPasswordComponent`) |
| `/#/recycle` | None | Green Recycling Request (`RecycleComponent`) |
| `/#/register` | None | User Registration (`RegisterComponent`) |
| `/#/search` | None | Search Results (`SearchResultComponent`) |
| `/#/hacking-instructor` | None | Interactive Hacking Tutorial (`SearchResultComponent`) |
| `/#/score-board` | None | CTF Score Board (`ScoreBoardComponent`) |
| `/#/track-result` | None | Order Status Tracker (`TrackResultComponent`) |
| `/#/track-result/new` | None | New Order Tracking (`TrackResultComponent`) |
| `/#/2fa/enter` | None | 2FA TOTP Form (`TwoFactorAuthEnterComponent`) |
| `/#/privacy-security` | None | Privacy & Security Management Hub |
| `/#/privacy-security/privacy-policy` | None | Privacy Policy View |
| `/#/privacy-security/change-password` | None | Password Change Form |
| `/#/privacy-security/two-factor-authentication` | None | 2FA QR Code Setup |
| `/#/privacy-security/data-export` | None | GDPR Data Export Download |
| `/#/privacy-security/last-login-ip` | None | Last Login IP Address Audit |
| `/#/juicy-nft` | None | NFT Web3 Challenge View (`NFTUnlockComponent`) |
| `/#/wallet-web3` | None | Web3 Wallet Interface (`WalletWeb3Module`) |
| `/#/web3-sandbox` | None | Web3 Sandbox (`Web3SandboxModule`) |
| `/#/chatbot` | None | Juicy AI Assistant (`ChatbotComponent`) |
| `/#/chatbot/conversation/:id` | None | Chatbot History View (`ChatConversationComponent`) |
| `/#/bee-haven` | None | Faucet / Mining Module (`FaucetModule`) |
| `/#/coding-challenge/:challengeKey` | None | Code Review Challenge (`CodingChallengePageComponent`) |
| `/#/tokensale-ico-ea` | None | Hidden Token Sale Challenge (`TokenSaleComponent`) |
| `/#/403` | None | Forbidden Error Page (`ErrorPageComponent`) |
