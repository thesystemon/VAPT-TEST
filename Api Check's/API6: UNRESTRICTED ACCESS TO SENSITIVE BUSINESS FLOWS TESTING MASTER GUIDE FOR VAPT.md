# 🏦 **API6: UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS TESTING MASTER GUIDE FOR VAPT**
*A Professional Penetration Tester's Comprehensive Deep Dive into Business Logic Abuse & Process Flows*

---

## 📋 **TABLE OF CONTENTS**

1. [Coupon or Discount Code Abuse (Reuse, Stacking, High Value)](#1-coupon-or-discount-code-abuse-reuse-stacking-high-value)
2. [Price or Quantity Manipulation During Checkout](#2-price-or-quantity-manipulation-during-checkout)
3. [Inventory Hoarding (Cart Reservation Exploit)](#3-inventory-hoarding-cart-reservation-exploit)
4. [Race Condition in Limited Stock Purchase (Over‑selling)](#4-race-condition-in-limited-stock-purchase-over-selling)
5. [Gift Card Balance Manipulation or Brute Force](#5-gift-card-balance-manipulation-or-brute-force)
6. [Loyalty Points or Rewards Abuse (Double Earning, Unauthorised Redemption)](#6-loyalty-points-or-rewards-abuse-double-earning-unauthorised-redemption)
7. [Unauthorised Access to High‑Value or Admin Business Flows](#7-unauthorised-access-to-high-value-or-admin-business-flows)
8. [Automated Bot Participation in Time‑Limited Sales (Flash Sales, Ticket Booking)](#8-automated-bot-participation-in-time-limited-sales-flash-sales-ticket-booking)
9. [Vote Manipulation (Repeated Voting, Bot Voting)](#9-vote-manipulation-repeated-voting-bot-voting)
10. [Referral or Affiliate Programme Abuse (Self‑Referral, Fake Referrals)](#10-referral-or-affiliate-programme-abuse-self-referral-fake-referrals)
11. [Loan or Credit Application Approval Flow Bypass](#11-loan-or-credit-application-approval-flow-bypass)
12. [Insurance Claim Manipulation (Duplicate, Inflated)](#12-insurance-claim-manipulation-duplicate-inflated)
13. [Money Transfer or Payment Reversal Exploits](#13-money-transfer-or-payment-reversal-exploits)
14. [Shipping Address Change After Order (Redirecting Goods)](#14-shipping-address-change-after-order-redirecting-goods)
15. [Return & Refund Fraud (Returning Wrong Item, Keeping Refund)](#15-return--refund-fraud-returning-wrong-item-keeping-refund)
16. [Subscription Plan Abuse (Free Trial Extension, Plan Downgrade with Feature Retention)](#16-subscription-plan-abuse-free-trial-extension-plan-downgrade-with-feature-retention)
17. [Digital Product Access Without Purchase (DRM Bypass)](#17-digital-product-access-without-purchase-drm-bypass)
18. [Resume Parsing or Profile Scoring Manipulation (Fake Experience)](#18-resume-parsing-or-profile-scoring-manipulation-fake-experience)
19. [Unrestricted Access to PDF Generation or Invoice Download](#19-unrestricted-access-to-pdf-generation-or-invoice-download)
20. [API Endpoints That Trigger Emails or SMS (Spam, Cost Abuse)](#20-api-endpoints-that-trigger-emails-or-sms-spam-cost-abuse)
21. [Rate Limiting Absent on Sensitive Business Actions (Money Transfer, Order Placement)](#21-rate-limiting-absent-on-sensitive-business-actions-money-transfer-order-placement)
22. [Workflow Bypass (Skipping Mandatory Steps – e.g., Payment)](#22-workflow-bypass-skipping-mandatory-steps--eg-payment)
23. [Unverified Document Upload (Fake Identity, Fake Invoice)](#23-unverified-document-upload-fake-identity-fake-invoice)
24. [Account Registration Without Email or Phone Verification (Fake Accounts)](#24-account-registration-without-email-or-phone-verification-fake-accounts)
25. [Bulk Action Abuse (Mass Message, Mass Unsubscribe)](#25-bulk-action-abuse-mass-message-mass-unsubscribe)
26. [API Endpoints That Expose Internal Business Logic (Debug Info, Decision Trees)](#26-api-endpoints-that-expose-internal-business-logic-debug-info-decision-trees)
27. [Timing Attacks on Business Decisions (Loan Approval, Discount Eligibility)](#27-timing-attacks-on-business-decisions-loan-approval-discount-eligibility)
28. [Unrestricted Access to Promotional or Secret Offers (Hidden Parameters)](#28-unrestricted-access-to-promotional-or-secret-offers-hidden-parameters)
29. [Manipulation of Business Status Flags (e.g., `isVerified`, `isApproved`)](#29-manipulation-of-business-status-flags)
30. [No Validation of Business Rule Sequence (Completing Steps Out of Order)](#30-no-validation-of-business-rule-sequence-completing-steps-out-of-order)

---

## 1. COUPON OR DISCOUNT CODE ABUSE (REUSE, STACKING, HIGH VALUE)

**Description**  
Coupon codes intended for single use, limited use, or specific products can be abused if the API lacks proper validation. Attackers may reuse codes, apply multiple codes together, or apply codes that give excessive discounts.

**What to Look For**
- Coupon codes that can be applied multiple times by the same user.
- Ability to apply more than one coupon to a single order.
- Coupon codes that apply to excluded items or exceed allowed discount amounts.

**What to Ignore**
- Coupons that are correctly limited (one per user, one per order, product restrictions enforced).

**How to Test with Burp Suite**
1. Apply a coupon code to an order and capture the request.
2. Replay the same request again; if the discount is reapplied, the coupon is reusable.
3. Try to apply multiple coupon codes in the same request (e.g., `coupon=SAVE10&coupon=SAVE20` or `{"coupons":["SAVE10","SAVE20"]}`).
4. Modify the coupon value to a larger discount if the API sends the discount amount.

**Example**
```http
POST /api/cart/apply-coupon HTTP/1.1
{"code":"WELCOME10"}
```
Send again with same code; discount applied twice.

**Tools**
- Burp Repeater
- Burp Intruder (to test many coupons)

**Risk Rating**  
High

**Remediation**
- Implement server‑side checks: one coupon per user, per order, per time period.
- Invalidate coupon after use.
- Validate coupon applicability against product and user.

---

## 2. PRICE OR QUANTITY MANIPULATION DURING CHECKOUT

**Description**  
Attackers can modify price or quantity parameters in checkout requests to pay less or receive more products than allowed.

**What to Look For**
- Price parameters in the checkout request (e.g., `"price":100`, `"total":500`).
- Quantity parameters without upper bounds.

**What to Ignore**
- Server‑side price calculation that ignores client‑supplied values.

**How to Test with Burp Suite**
1. Intercept the checkout request.
2. Change the price of an item to a very low value (e.g., `0.01` or `0`).
3. Change the quantity to a negative number (e.g., `-10`) or a very large number.
4. Send the request and see if the order processes at the manipulated price.

**Example**
```http
POST /api/checkout HTTP/1.1
{"items":[{"id":123,"price":0.01,"quantity":999}]}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Never trust client‑supplied price or total; calculate server‑side based on current product prices.
- Validate quantity against inventory and business limits.

---

## 3. INVENTORY HOARDING (CART RESERVATION EXPLOIT)

**Description**  
Some APIs reserve inventory when a user adds an item to the cart and hold it for a period. Attackers can hoard limited‑stock items by creating many cart sessions or refreshing the hold timer.

**What to Look For**
- Cart reservation endpoints that allow extending hold time or creating many carts.
- No limit on the number of items or carts per user.

**What to Ignore**
- Cart reservations with short timers and limits on items per user.

**How to Test with Burp Suite**
1. Add a limited‑stock item to the cart and capture the reservation request.
2. Send many identical requests from different sessions (or with different user IDs) to reserve multiple quantities.
3. If the stock is locked, the attacker prevents others from buying.

**Example**
```http
POST /api/cart/reserve HTTP/1.1
{"item_id":123,"quantity":1}
```
Repeat 100 times with different session tokens.

**Tools**
- Burp Intruder
- Turbo Intruder (concurrent requests)

**Risk Rating**  
High

**Remediation**
- Limit the number of items a single user can reserve.
- Release reservations after a short timeout.
- Do not allow the same user to reserve more than the available stock.

---

## 4. RACE CONDITION IN LIMITED STOCK PURCHASE (OVER‑SELLING)

**Description**  
When multiple users attempt to buy the last item simultaneously, a race condition can allow over‑selling if the stock check and decrement are not atomic.

**What to Look For**
- Limited stock products (e.g., “only 1 left”).
- No database locking or atomic operations on inventory.

**What to Ignore**
- Atomic stock updates (e.g., `UPDATE stock SET qty=qty-1 WHERE qty>0`).

**How to Test with Burp Suite**
1. Use Turbo Intruder to send many concurrent checkout requests for the same limited‑stock item.
2. Observe if the number of successful purchases exceeds the available stock.

**Example**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1)
    for i in range(20):
        engine.queue(target.req)
```

**Tools**
- Burp Turbo Intruder
- Custom scripts

**Risk Rating**  
Critical

**Remediation**
- Use atomic database updates (e.g., `UPDATE ... WHERE stock > 0`).
- Use row‑level locks or transactions.
- Use optimistic locking with version numbers.

---

## 5. GIFT CARD BALANCE MANIPULATION OR BRUTE FORCE

**Description**  
Gift card systems that allow checking balances or redeeming without proper rate limiting can be abused to brute force card numbers or manipulate balances.

**What to Look For**
- Endpoints that check gift card balance without authentication.
- Ability to add arbitrary balance to a gift card.
- Predictable gift card numbers.

**What to Ignore**
- Gift cards with random, long codes and rate‑limited balance checks.

**How to Test with Burp Suite**
1. Try to guess gift card numbers by brute force (sequential or pattern‑based).
2. Attempt to add balance via parameter manipulation (e.g., `{"amount":1000}` on a zero‑balance card).
3. Try to redeem a card multiple times.

**Example**
```http
POST /api/giftcard/redeem HTTP/1.1
{"code":"GIFT123","amount":500}
```
If the same code can be redeemed again, vulnerable.

**Tools**
- Burp Intruder (for brute force)
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Use long, random, unpredictable gift card codes.
- Rate limit balance checks and redemption attempts.
- Never allow client‑supplied balance amounts.

---

## 6. LOYALTY POINTS OR REWARDS ABUSE (DOUBLE EARNING, UNAUTHORISED REDEMPTION)

**Description**  
Attackers may earn points multiple times for the same action, redeem points without having enough, or transfer points to other accounts.

**What to Look For**
- Points awarded for actions that can be repeated (e.g., sharing, referring).
- No validation that the user has sufficient points before redemption.
- Points transfer endpoints without ownership checks.

**What to Ignore**
- Idempotent point awards and strict balance checks.

**How to Test with Burp Suite**
1. Perform an action that awards points (e.g., write a review) and capture the request.
2. Replay the request multiple times; if points are awarded each time, vulnerable.
3. Attempt to redeem more points than you have.
4. Try to transfer points from another user’s account.

**Example**
```http
POST /api/loyalty/earn HTTP/1.1
{"action":"review","productId":123}
```
Replayed 10 times → 10× points.

**Tools**
- Burp Repeater
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Implement idempotency keys for point‑awarding actions.
- Always check balance before redemption.
- Require re‑authentication for point transfers.

---

## 7. UNAUTHORISED ACCESS TO HIGH‑VALUE OR ADMIN BUSINESS FLOWS

**Description**  
Business flows intended for administrators or premium users (e.g., bulk discounts, special pricing, manual refunds) may be accessible to regular users via hidden API endpoints.

**What to Look For**
- API endpoints with names like `/bulkDiscount`, `/manualRefund`, `/specialOffer`.
- No role checks on these endpoints.

**What to Ignore**
- Endpoints properly protected by role‑based access control.

**How to Test with Burp Suite**
1. Use forced browsing or API discovery to find high‑value business endpoints.
2. Call them with a regular user’s session.
3. If they perform the action (e.g., apply a discount), vulnerable.

**Example**
```http
POST /api/apply-manual-discount HTTP/1.1
Cookie: session=REGULAR_USER_SESSION
{"orderId":123,"discountPercent":100}
```

**Tools**
- Burp Repeater
- Gobuster / FFUF

**Risk Rating**  
Critical

**Remediation**
- Enforce role‑based access on all business‑critical endpoints.
- Use consistent authorization middleware.

---

## 8. AUTOMATED BOT PARTICIPATION IN TIME‑LIMITED SALES (FLASH SALES, TICKET BOOKING)

**Description**  
Flash sales and ticket booking systems without bot detection can be overwhelmed by automated scripts, allowing attackers to buy all stock instantly.

**What to Look For**
- No CAPTCHA or rate limiting on checkout.
- Ability to programmatically add items to cart and checkout.

**What to Ignore**
- CAPTCHA, rate limiting, and device fingerprinting.

**How to Test with Burp Suite**
1. Write a script that repeatedly adds a high‑demand item to cart and checks out.
2. Use Turbo Intruder to simulate many concurrent users.
3. If you can purchase faster than legitimate users, vulnerable.

**Example**
```python
for i in range(100):
    requests.post("/api/cart/add", json={"item":123})
    requests.post("/api/checkout")
```

**Tools**
- Burp Turbo Intruder
- Custom Python scripts

**Risk Rating**  
Critical

**Remediation**
- Implement CAPTCHA before checkout for high‑demand items.
- Use rate limiting and bot detection (e.g., Cloudflare, PerimeterX).

---

## 9. VOTE MANIPULATION (REPEATED VOTING, BOT VOTING)

**Description**  
Polling or rating systems that allow unlimited voting can be manipulated to skew results.

**What to Look For**
- No check for whether the user has already voted.
- No rate limiting on voting endpoints.

**What to Ignore**
- Voting restricted to one per user, per IP, or with CAPTCHA.

**How to Test with Burp Suite**
1. Vote for a candidate and capture the request.
2. Replay the request multiple times with different session tokens or IP spoofing.
3. If votes increase each time, vulnerable.

**Example**
```http
POST /api/vote HTTP/1.1
{"candidateId":1}
```
Replay 100 times with different `X-Forwarded-For` headers.

**Tools**
- Burp Intruder
- Turbo Intruder

**Risk Rating**  
Medium

**Remediation**
- Store votes per user or per IP and enforce one vote.
- Use CAPTCHA for public polls.

---

## 10. REFERRAL OR AFFILIATE PROGRAMME ABUSE (SELF‑REFERRAL, FAKE REFERRALS)

**Description**  
Attackers can create multiple accounts to refer themselves and earn referral bonuses.

**What to Look For**
- No check for whether the referred account is new and not the referrer.
- No limit on referral bonuses per account.

**What to Ignore**
- Referral codes that are validated (IP, device fingerprint, email domain).

**How to Test with Burp Suite**
1. Create a new account using your own referral code.
2. If you receive a bonus, try to repeat with multiple new accounts.

**Example**
```http
POST /api/register HTTP/1.1
{"email":"fake1@temp.com","referralCode":"ATTACKER_CODE"}
```
If each fake registration gives a bonus, vulnerable.

**Tools**
- Burp Repeater
- Scripted registrations

**Risk Rating**  
High

**Remediation**
- Limit referral bonuses to one per referrer per referred email/IP.
- Require the referred account to make a purchase before awarding bonus.

---

## 11. LOAN OR CREDIT APPLICATION APPROVAL FLOW BYPASS

**Description**  
Financial APIs that approve loans or credit without proper validation can be tricked by manipulating income, credit score, or other parameters.

**What to Look For**
- Client‑supplied income or credit score in the application.
- No verification of uploaded documents.

**What to Ignore**
- Server‑side verification of financial data.

**How to Test with Burp Suite**
1. Submit a loan application with inflated income (e.g., `"income":9999999`).
2. If the loan is approved without verification, vulnerable.

**Example**
```http
POST /api/loan/apply HTTP/1.1
{"income":9999999,"creditScore":850}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Validate income via external sources (e.g., tax returns, bank statements).
- Do not trust client‑supplied financial data.

---

## 12. INSURANCE CLAIM MANIPULATION (DUPLICATE, INFLATED)

**Description**  
Attackers can submit duplicate claims or inflate claim amounts if the API lacks validation.

**What to Look For**
- No check for duplicate claim IDs or invoice numbers.
- Claim amount supplied by the client.

**What to Ignore**
- Deduplication logic and server‑side amount calculation.

**How to Test with Burp Suite**
1. Submit a claim and capture the request.
2. Replay the same request; if a second payout is issued, duplicate claim possible.
3. Increase the `amount` parameter beyond the actual loss.

**Example**
```http
POST /api/claims HTTP/1.1
{"invoiceId":"INV123","amount":10000}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Deduplicate claims using unique identifiers (e.g., invoice number).
- Validate claim amounts against external data (e.g., repair estimates).

---

## 13. MONEY TRANSFER OR PAYMENT REVERSAL EXPLOITS

**Description**  
Attackers may reverse a payment after receiving goods (chargeback fraud) or transfer money to themselves without sufficient balance.

**What to Look For**
- No balance check before transfer.
- Ability to cancel or reverse a transfer without proper authorization.

**What to Ignore**
- Atomic balance updates and reversible transaction logs with authorization.

**How to Test with Burp Suite**
1. Transfer money to another account and capture the request.
2. Attempt to reverse the transfer by calling a refund endpoint without approval.
3. Try to transfer more than your balance.

**Example**
```http
POST /api/transfer HTTP/1.1
{"from":"user123","to":"attacker","amount":999999}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Always check balance before debit.
- Require MFA or approval for reversals.

---

## 14. SHIPPING ADDRESS CHANGE AFTER ORDER (REDIRECTING GOODS)

**Description**  
After an order is placed, an attacker may change the shipping address to redirect goods to themselves.

**What to Look For**
- Address change endpoint that allows modification after shipment.
- No verification (e.g., OTP or email confirmation).

**What to Ignore**
- Address changes locked after a short window or requiring confirmation.

**How to Test with Burp Suite**
1. Place an order with your own address.
2. After order confirmation, call the address update endpoint with a different address.
3. If the order is shipped to the new address, vulnerable.

**Example**
```http
PUT /api/orders/123/address HTTP/1.1
{"address":"attacker address"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Prevent address changes after payment or after a short grace period.
- Require email confirmation for address changes.

---

## 15. RETURN & REFUND FRAUD (RETURNING WRONG ITEM, KEEPING REFUND)

**Description**  
Attackers may request a return for an expensive item but send back a cheap item, then receive a full refund.

**What to Look For**
- Return process that does not verify the returned item matches the original.
- No tracking or inspection before refund.

**What to Ignore**
- Return inspection and matching against original order.

**How to Test with Burp Suite**
1. Initiate a return for an expensive item.
2. Send a different item (or empty box) and mark as returned.
3. If the refund is processed without verification, vulnerable.

**Example**
```http
POST /api/returns HTTP/1.1
{"orderId":123,"itemId":456,"reason":"defective"}
```

**Tools**
- Burp Repeater
- Manual manipulation of return requests

**Risk Rating**  
High

**Remediation**
- Require return verification (photos, inspection).
- Use unique return labels and match returned items.

---

## 16. SUBSCRIPTION PLAN ABUSE (FREE TRIAL EXTENSION, PLAN DOWNGRADE WITH FEATURE RETENTION)

**Description**  
Attackers may extend free trials indefinitely, downgrade plans but keep premium features, or cancel and get refunds while retaining access.

**What to Look For**
- No check on trial usage per account.
- Downgrade endpoint that does not revoke premium features.
- Cancel endpoint that refunds but does not revoke access.

**What to Ignore**
- Trial limits (one per payment method/IP), feature downgrade on plan change.

**How to Test with Burp Suite**
1. Start a free trial and capture the request.
2. Replay the trial start request with a new email or different parameters.
3. Downgrade from premium to free and see if premium features are still available.
4. Cancel subscription and check if access is revoked.

**Example**
```http
POST /api/subscription/trial HTTP/1.1
{"email":"new@example.com"}
```

**Tools**
- Burp Repeater
- Burp Intruder (email variations)

**Risk Rating**  
High

**Remediation**
- Limit free trials per payment method, IP, or device fingerprint.
- On downgrade, immediately remove premium features.
- On cancellation, revoke access and pro‑rate refunds.

---

## 17. DIGITAL PRODUCT ACCESS WITHOUT PURCHASE (DRM BYPASS)

**Description**  
APIs that serve digital products (eBooks, software, videos) may allow access without payment by manipulating purchase status or direct file links.

**What to Look For**
- Direct file URLs that are predictable or not authenticated.
- Purchase status parameter that can be changed from `false` to `true`.

**What to Ignore**
- Signed, time‑limited URLs and server‑side purchase validation.

**How to Test with Burp Suite**
1. Attempt to download a digital product without purchasing.
2. Try to access the download link before payment.
3. Modify a `purchased` flag in the API response or request.

**Example**
```http
GET /api/download?file=ebook.pdf&purchased=true HTTP/1.1
```

**Tools**
- Burp Repeater
- Burp Intruder (for guessing file IDs)

**Risk Rating**  
Critical

**Remediation**
- Use signed, expiring download URLs.
- Validate purchase status on every download request.

---

## 18. RESUME PARSING OR PROFILE SCORING MANIPULATION (FAKE EXPERIENCE)

**Description**  
Job portals or ranking systems that accept user‑supplied resume data may allow attackers to inflate their scores.

**What to Look For**
- Resume upload that directly sets skills or experience without validation.
- Scoring parameters sent by the client.

**What to Ignore**
- Server‑side parsing and verification of claims.

**How to Test with Burp Suite**
1. Upload a resume with fabricated experience and skills.
2. If the system assigns a high score without verification, vulnerable.
3. Modify scoring parameters in the request (e.g., `"score":100`).

**Example**
```http
POST /api/profile/score HTTP/1.1
{"skills":["AI","Blockchain"],"experience":20}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Verify claims via third‑party sources or certificates.
- Do not allow client‑supplied scores.

---

## 19. UNRESTRICTED ACCESS TO PDF GENERATION OR INVOICE DOWNLOAD

**Description**  
PDF generation endpoints that allow arbitrary content injection or invoice download without ownership checks can leak data.

**What to Look For**
- Endpoints like `/api/invoice/pdf?orderId=123` without authorization.
- Ability to inject HTML/JavaScript into PDF.

**What to Ignore**
- Ownership checks and HTML sanitisation.

**How to Test with Burp Suite**
1. Change `orderId` to another user’s order.
2. If you receive their invoice, vulnerable.
3. Try to inject HTML/JS into the invoice content.

**Example**
```http
GET /api/invoice/456/pdf HTTP/1.1
Cookie: session=USER_A_SESSION
```
If invoice 456 belongs to User B, vulnerable.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Validate ownership before generating PDFs.
- Sanitise any user input used in PDF generation.

---

## 20. API ENDPOINTS THAT TRIGGER EMAILS OR SMS (SPAM, COST ABUSE)

**Description**  
APIs that send email or SMS without rate limiting can be abused to spam users or incur high costs for the service provider.

**What to Look For**
- Endpoints like `/api/send-otp`, `/api/invite`, `/api/contact`.
- No rate limiting or CAPTCHA.

**What to Ignore**
- Rate limiting and CAPTCHA on communication endpoints.

**How to Test with Burp Suite**
1. Use Intruder to send 1000 requests to an SMS OTP endpoint with the same phone number.
2. If all requests succeed, cost abuse is possible.

**Example**
```http
POST /api/send-sms HTTP/1.1
{"phone":"+1234567890"}
```
Repeated 1000 times.

**Tools**
- Burp Intruder

**Risk Rating**  
High

**Remediation**
- Implement rate limiting per recipient, per IP, per time period.
- Use CAPTCHA before triggering communications.

---

## 21. RATE LIMITING ABSENT ON SENSITIVE BUSINESS ACTIONS (MONEY TRANSFER, ORDER PLACEMENT)

**Description**  
Sensitive actions (money transfer, order placement) without rate limiting can be abused to cause financial loss or denial of service.

**What to Look For**
- No `429 Too Many Requests` responses on transfer or order endpoints.
- Ability to place hundreds of orders in seconds.

**What to Ignore**
- Rate limiting on all state‑changing business flows.

**How to Test with Burp Suite**
1. Send 100 concurrent order placement requests.
2. If all succeed, rate limiting is missing.

**Tools**
- Burp Turbo Intruder

**Risk Rating**  
Critical

**Remediation**
- Apply rate limiting per user, per IP, per time window.

---

## 22. WORKFLOW BYPASS (SKIPPING MANDATORY STEPS – E.G., PAYMENT)

**Description**  
Multi‑step business flows (e.g., checkout) may allow skipping mandatory steps like payment by directly calling the final endpoint.

**What to Look For**
- Ability to access `/order/confirm` without first calling `/checkout/payment`.
- No state validation.

**What to Ignore**
- Server‑side workflow state tracking.

**How to Test with Burp Suite**
1. Identify the final step URL of a workflow (e.g., `/order/finalize`).
2. Call it directly without completing prior steps.
3. If the order is processed without payment, vulnerable.

**Example**
```http
POST /api/order/finalize HTTP/1.1
{"orderId":123}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Critical

**Remediation**
- Maintain workflow state on the server and validate step completion.

---

## 23. UNVERIFIED DOCUMENT UPLOAD (FAKE IDENTITY, FAKE INVOICE)

**Description**  
Systems that accept document uploads (KYC, proof of purchase) without verification can be exploited with forged documents.

**What to Look For**
- No validation of document authenticity (e.g., watermark, checksum).
- Documents accepted without manual review.

**What to Ignore**
- Document validation (e.g., against government databases, manual review).

**How to Test with Burp Suite**
1. Upload a forged document (e.g., edited PDF) for KYC.
2. If the system approves it automatically, vulnerable.

**Tools**
- Burp Repeater (file upload)
- Image/PDF editors

**Risk Rating**  
High

**Remediation**
- Use automated document verification services.
- Implement manual review for high‑risk documents.

---

## 24. ACCOUNT REGISTRATION WITHOUT EMAIL OR PHONE VERIFICATION (FAKE ACCOUNTS)

**Description**  
Allowing account registration without email or phone verification enables mass creation of fake accounts for abuse (e.g., coupon farming, fake reviews).

**What to Look For**
- Registration endpoint that creates an active account without verification.
- No CAPTCHA.

**What to Ignore**
- Email/phone verification required before activation.

**How to Test with Burp Suite**
1. Register an account with a fake email address.
2. If you can log in immediately, verification is missing.

**Example**
```http
POST /api/register HTTP/1.1
{"email":"fake@temp.com","password":"pass"}
```

**Tools**
- Burp Intruder (for mass registration)

**Risk Rating**  
High

**Remediation**
- Require email or phone verification before account activation.
- Use CAPTCHA to prevent automated registration.

---

## 25. BULK ACTION ABUSE (MASS MESSAGE, MASS UNSUBSCRIBE)

**Description**  
APIs that allow bulk actions (e.g., send messages to many users, unsubscribe all) without proper authorization can be abused.

**What to Look For**
- Endpoints like `/api/messages/bulk`, `/api/unsubscribe-all`.
- No per‑recipient validation.

**What to Ignore**
- Bulk actions restricted to admins or with confirmation.

**How to Test with Burp Suite**
1. Attempt to send a bulk message to all users with a regular user token.
2. If messages are sent, vulnerable.

**Example**
```http
POST /api/admin/bulk-message HTTP/1.1
{"message":"spam","recipients":"all"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Restrict bulk actions to admin roles.
- Require confirmation and rate limit.

---

## 26. API ENDPOINTS THAT EXPOSE INTERNAL BUSINESS LOGIC (DEBUG INFO, DECISION TREES)

**Description**  
API responses may include internal decision details (e.g., “loan denied due to low credit score”), which helps attackers fine‑tune their exploitation.

**What to Look For**
- Error messages or responses that reveal why a business decision was made.
- Debug parameters that enable verbose output.

**What to Ignore**
- Generic error messages without internal details.

**How to Test with Burp Suite**
1. Submit a loan application with various inputs.
2. Observe if the response reveals why it was rejected (e.g., `"reason":"income too low"`).
3. Use this information to adjust subsequent requests.

**Example**
```json
{"status":"rejected","reason":"credit_score below 600"}
```

**Tools**
- Burp Repeater

**Risk Rating**  
Medium

**Remediation**
- Return generic rejection messages.
- Do not expose internal decision logic.

---

## 27. TIMING ATTACKS ON BUSINESS DECISIONS (LOAN APPROVAL, DISCOUNT ELIGIBILITY)

**Description**  
If business decision logic takes different time for valid vs invalid inputs, attackers can infer sensitive information via timing.

**What to Look For**
- Response time difference between “approved” and “rejected” decisions.
- No constant‑time implementation.

**What to Ignore**
- Uniform response times.

**How to Test with Burp Suite**
1. Send requests that trigger approval and rejection.
2. Measure response times in Repeater (or use a script).
3. If consistently different, a timing attack may be possible.

**Tools**
- Burp Repeater (time column)
- Custom timing scripts

**Risk Rating**  
Low to Medium

**Remediation**
- Add random delays or constant‑time comparisons.

---

## 28. UNRESTRICTED ACCESS TO PROMOTIONAL OR SECRET OFFERS (HIDDEN PARAMETERS)

**Description**  
Special offers or secret discounts may be accessible by adding hidden parameters (e.g., `?promo=SECRET`).

**What to Look For**
- Parameters like `offerCode`, `secretDiscount`, `internalPromo`.
- No validation of who can use them.

**What to Ignore**
- Offers tied to specific user roles or accounts.

**How to Test with Burp Suite**
1. Use Param Miner to discover hidden parameters.
2. Try common promo codes (`SECRET`, `TEST`, `VIP`, `DEBUG`).
3. If a discount is applied, vulnerable.

**Example**
```http
GET /api/checkout?secretDiscount=100 HTTP/1.1
```

**Tools**
- Burp Param Miner
- Burp Intruder (with promo wordlist)

**Risk Rating**  
High

**Remediation**
- Remove debug or test promo codes in production.
- Validate promo codes against server‑side rules.

---

## 29. MANIPULATION OF BUSINESS STATUS FLAGS (E.G., `ISVERIFIED`, `ISAPPROVED`)

**Description**  
Some APIs accept status flags in requests, allowing attackers to mark themselves as verified or approved without going through the proper process.

**What to Look For**
- Parameters like `verified`, `approved`, `kycStatus` in profile updates.
- No server‑side validation of these flags.

**What to Ignore**
- Flags that are read‑only and set only by server processes.

**How to Test with Burp Suite**
1. Capture a profile update request.
2. Add a status flag: `"isVerified": true`, `"kycStatus": "approved"`.
3. If the flag is accepted, vulnerable.

**Example**
```http
PATCH /api/user/profile HTTP/1.1
{"isVerified": true}
```

**Tools**
- Burp Repeater
- Param Miner

**Risk Rating**  
Critical

**Remediation**
- Never accept status flags from clients.
- Derive status from server‑side processes.

---

## 30. NO VALIDATION OF BUSINESS RULE SEQUENCE (COMPLETING STEPS OUT OF ORDER)

**Description**  
Business flows (e.g., “submit → review → approve”) may allow users to complete later steps before earlier ones, bypassing controls.

**What to Look For**
- Ability to call `/approve` without first calling `/submit`.
- No state machine validation.

**What to Ignore**
- Server‑side sequence validation.

**How to Test with Burp Suite**
1. Identify the endpoint for the final step of a business process.
2. Call it directly without completing previous steps.
3. If the action succeeds, sequence validation is missing.

**Example**
```http
POST /api/loan/approve HTTP/1.1
{"loanId":123}
```
Called without prior submission.

**Tools**
- Burp Repeater

**Risk Rating**  
High

**Remediation**
- Implement a state machine that tracks the current step.
- Validate that the user is at the correct step before allowing progression.

---

## ✅ **SUMMARY**

Unrestricted Access to Sensitive Business Flows (API6) occurs when APIs lack controls to prevent abuse of business logic, such as coupon reuse, price manipulation, inventory hoarding, and workflow bypasses. This guide provides 30 testing vectors.

### **Key Testing Areas Summary**

| Failure Type | Key Indicators | Risk |
|--------------|----------------|------|
| Coupon Abuse | Reuse, stacking | High |
| Price Manipulation | Client‑supplied price | Critical |
| Inventory Hoarding | Many cart reservations | High |
| Race Condition | Over‑selling | Critical |
| Gift Card Abuse | Predictable codes | Critical |
| Loyalty Points | Double earning | High |
| Admin Flows | Accessible to regular users | Critical |
| Bot Sales | No CAPTCHA | Critical |
| Vote Manipulation | Repeated voting | Medium |
| Referral Fraud | Self‑referral | High |
| Loan Application | Fake income | Critical |
| Insurance Claim | Duplicate claim | Critical |
| Money Transfer | No balance check | Critical |
| Address Change | After order | High |
| Return Fraud | Wrong item returned | High |
| Subscription Abuse | Trial extension | High |
| Digital Product | No purchase check | Critical |
| Resume Manipulation | Fake experience | Medium |
| PDF Access | IDOR | High |
| SMS/Email Abuse | No rate limit | High |
| Rate Limit Missing | On transfers | Critical |
| Workflow Bypass | Skip payment | Critical |
| Document Upload | Forgery | High |
| Fake Accounts | No verification | High |
| Bulk Actions | Mass messages | High |
| Business Logic Leak | Debug info | Medium |
| Timing Attacks | Decision inference | Low-Medium |
| Secret Offers | Hidden parameters | High |
| Status Flags | Client‑set `isVerified` | Critical |
| Sequence Bypass | Step skipping | High |

### **Pro Tips for Testing Sensitive Business Flows**
1. **Think like an attacker** – what business rule would you like to break?
2. **Map workflows** – document every step and try to skip or reorder them.
3. **Use Param Miner** – discover hidden parameters that control discounts, status, etc.
4. **Test for race conditions** – concurrent requests on limited resources.
5. **Fuzz for coupon codes** – many systems use predictable patterns.
6. **Check for client‑side business logic** – price, quantity, status flags should not be trusted.

---

*This guide is for professional security testing purposes only. Unauthorized testing is illegal.*
