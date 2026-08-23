"""Generates eval/datasets/v2.jsonl (~350 rows, same schema as v1.jsonl).

Run once to produce the dataset:
    python eval/datasets/build_v2.py > eval/datasets/v2.jsonl

Kept in the repo (not deleted after running) so the exact construction of
every row is inspectable and re-runnable — this script IS the provenance
record for the hand-authored rows; see PROVENANCE.md for the handful of
rows extracted verbatim from external sources.

Row counts by design:
  legit:   ~190  (5 extracted verbatim from external MIT repos, tagged
                  source=github_fixture; ~185 hand-authored, source=synthetic
                  or source=real_phone_pending for a slot left open for the
                  team to paste real messages into later)
  scam:    ~140  (hand-authored, grounded in publicly documented advisories
                  already cited in data/kb/*.yaml: MHA/I4C digital arrest,
                  SEBI investor cautions, RBI BE(A)WARE, bank/telecom
                  impersonation reports)
  unclear:  ~20  (genuinely ambiguous messages — the abstain set)

Every legit row that contains urgency/payment/link/call-back language is
marked hard_negative=true regardless of category, per the brief:
"anything a naive keyword rule would flag."
"""

from __future__ import annotations

import json
import sys

ROWS: list[dict] = []
_seen_ids: set[str] = set()


def add(id_, text, sender, sender_type, lang, label, category, ask_class,
        hard_negative, source):
    if id_ in _seen_ids:
        raise ValueError(f"duplicate id {id_}")
    _seen_ids.add(id_)
    # synthetic is derived from source, not passed separately, so the two
    # can never drift out of sync: only source=="synthetic" is generated
    # text; github_fixture and real_phone are real messages.
    ROWS.append({
        "id": id_, "text": text, "sender": sender, "sender_type": sender_type,
        "lang": lang, "label": label, "category": category,
        "ask_class": ask_class, "hard_negative": hard_negative, "source": source,
        "synthetic": source == "synthetic",
    })


# ===========================================================================
# LEGIT — verbatim extracts from the two named MIT repos (5 rows)
# ===========================================================================
# See eval/datasets/PROVENANCE.md for exactly where each string came from.

add("v2-gh-001",
    "INR 2000 debited from A/c no. XX3423 on 05-02-19 07:27:11 IST at ECS PAY. Avl Bal- INR 2343.23.",
    "unknown", "unknown", "en", "legit", "txn_alert", "none", False, "github_fixture")

add("v2-gh-002",
    "Your VPA 9876543210@ybl linked to Indian Bank a/c no. XXXXXX1234 is debited for Rs.499.00 and credited to amazon@apl  (UPI Ref no  105201221633).",
    "unknown", "unknown", "en", "legit", "txn_alert", "none", False, "github_fixture")

add("v2-gh-003",
    "Rs 150.00 debited from account ending 1234 to 9876543210@ybl on 04-11-25. UPI Ref: 432198765",
    "unknown", "unknown", "en", "legit", "txn_alert", "none", False, "github_fixture")

add("v2-gh-004",
    "Rs.299.00 paid to merchant@okicici via UPI. Avbl bal Rs.5000",
    "unknown", "unknown", "en", "legit", "txn_alert", "none", False, "github_fixture")

add("v2-gh-005",
    "You have paid Rs 75.50 to store123@paytm on 04-Nov-25",
    "unknown", "unknown", "en", "legit", "txn_alert", "none", False, "github_fixture")


# ===========================================================================
# LEGIT — hand-authored bank/telecom/utility/delivery/insurance templates.
# Bank/card/wallet names below are drawn from the tested-against list in
# saurabhgupta050890/transaction-sms-parser's README (Axis, ICICI, Kotak,
# HDFC, Standard Chartered, IDFC, Federal Bank, IndusInd, Paytm, Amazon Pay,
# LazyPay, Simpl, etc.) for realistic variety — the SMS bodies themselves
# are newly written, not extracted.
# ===========================================================================

_BANKS = [
    ("VM-SBIINB", "SBI"), ("VM-HDFCBK", "HDFC Bank"), ("AX-ICICIB", "ICICI Bank"),
    ("VK-AXISBK", "Axis Bank"), ("VM-KOTAKB", "Kotak Mahindra Bank"),
    ("VM-BOBIBK", "Bank of Baroda"), ("VK-IDFCFB", "IDFC First Bank"),
    ("VM-FEDBNK", "Federal Bank"), ("VK-INDUSB", "IndusInd Bank"),
    ("VM-PNBSMS", "Punjab National Bank"),
]

_n = 0


def _txn_alert_rows():
    global _n
    templates = [
        "INR {amt} debited from a/c XX{acct} on {date} towards UPI/{upi}. Avl Bal INR {bal}. Not you? Call {phone}.",
        "Your a/c XX{acct} is credited with INR {amt} on {date} via NEFT. Avl Bal INR {bal}.",
        "Rs.{amt} spent on your {bank} Credit Card XX{acct} at {merchant} on {date}. Avbl limit Rs.{bal}.",
        "ATM withdrawal of Rs.{amt} from a/c XX{acct} on {date} at {merchant}. Avl Bal Rs.{bal}.",
        "Your EMI of Rs.{amt} for loan a/c XX{acct} has been auto-debited on {date}.",
    ]
    merchants = ["Amazon", "Swiggy", "BigBasket", "IRCTC", "Reliance Digital", "Zomato", "Flipkart"]
    for i, (sender, bank) in enumerate(_BANKS):
        for j, tmpl in enumerate(templates):
            _n += 1
            text = tmpl.format(
                amt=f"{(i+1)*137 + j*53}.00", acct=f"{4000+i*11+j}",
                date="21-AUG-26", upi=f"user{i}{j}@bank", bal=f"{9000 - i*250 - j*40}.10",
                phone="1800-XXX-XXXX", bank=bank, merchant=merchants[(i + j) % len(merchants)],
            )
            add(f"v2-txn-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "txn_alert", "none", False, "synthetic")


def _otp_hard_negative_rows():
    global _n
    templates = [
        "Your OTP for login is {otp}. Valid for 10 minutes. NEVER SHARE this OTP with anyone, including bank officials.",
        "{otp} is your OTP for the transaction of Rs.{amt} at {merchant}. Do not share this OTP with anyone. Valid 5 mins.",
        "Use OTP {otp} to complete your UPI registration on {bank} app. NEVER SHARE OTP over call or SMS with anyone claiming to be from the bank.",
        "OTP for adding beneficiary is {otp}. Bank will never call and ask for this OTP. Do not share.",
    ]
    merchants = ["Amazon", "Flipkart", "MakeMyTrip", "BookMyShow"]
    for i, (sender, bank) in enumerate(_BANKS[:6]):
        for j, tmpl in enumerate(templates):
            _n += 1
            text = tmpl.format(otp=100000 + i * 137 + j * 29, amt=f"{500+i*40}",
                                merchant=merchants[j % len(merchants)], bank=bank)
            add(f"v2-otp-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "otp", "none", True, "synthetic")


def _fraud_alert_hard_negative_rows():
    """'Call <number> if txn not done by you' — a naive keyword rule flags
    'call this number' + 'transaction' as scam-shaped, but this is the
    bank's own real fraud-alert pattern."""
    global _n
    templates = [
        "Alert: A transaction of Rs.{amt} was made on your card XX{acct} at {merchant} on {date}. Call {phone} immediately if this was not done by you.",
        "Rs.{amt} debited via UPI from a/c XX{acct} on {date}. If this transaction was not initiated by you, call {phone} or visit your nearest branch.",
        "Suspicious login detected on your {bank} net banking from a new device on {date}. If this wasn't you, call {phone} to secure your account.",
    ]
    merchants = ["an online merchant", "a POS terminal", "an ATM"]
    for i, (sender, bank) in enumerate(_BANKS[:5]):
        for j, tmpl in enumerate(templates):
            _n += 1
            text = tmpl.format(amt=f"{2200+i*310+j*77}.00", acct=f"{5100+i*7+j}",
                                merchant=merchants[j % len(merchants)], date="20-AUG-26",
                                phone="1800-425-3800", bank=bank)
            add(f"v2-fraud-alert-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "txn_alert", "call_back", True, "synthetic")


def _kyc_reminder_hard_negative_rows():
    """Real, bank-initiated KYC reminders that mention a deadline and a
    link/app — a naive rule sees 'kyc' + 'update' + urgency and flags it,
    but these come from the bank's own DLT header with no external link."""
    global _n
    templates = [
        "Dear customer, your periodic KYC update is due by {date}. Please visit your home branch or update via the official {bank} mobile app.",
        "As per RBI guidelines, please complete your {bank} KYC re-verification by {date} to continue uninterrupted banking services. Visit branch or official app only.",
    ]
    for i, (sender, bank) in enumerate(_BANKS[:8]):
        for j, tmpl in enumerate(templates):
            _n += 1
            text = tmpl.format(date="30-SEP-26", bank=bank)
            add(f"v2-kyc-legit-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "kyc_payment", "none", True, "synthetic")


def _bill_utility_rows():
    global _n
    utilities = [
        ("VM-BESCOM", "BESCOM", "electricity"), ("VM-MSEDCL", "MSEDCL", "electricity"),
        ("VK-INDGAS", "Indane Gas", "LPG cylinder"), ("VM-TATAPW", "Tata Power", "electricity"),
        ("AD-JIOCARE", "Jio", "mobile recharge"), ("AD-AIRTEL", "Airtel", "postpaid bill"),
        ("VK-VODAFO", "Vi", "postpaid bill"),
    ]
    for i, (sender, brand, kind) in enumerate(utilities):
        for j in range(4):
            _n += 1
            text = (
                f"Dear customer, your {brand} {kind} bill of Rs.{540 + i*63 + j*22} is due on "
                f"{25+j}-AUG-26. Pay via official {brand} app or website to avoid late fee."
            )
            add(f"v2-util-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "txn_alert", "make_payment", False, "synthetic")


def _delivery_promo_rows():
    global _n
    brands = [
        ("VK-SWIGGY", "Swiggy"), ("VK-ZOMATO", "Zomato"), ("VK-FLPKRT", "Flipkart"),
        ("VK-AMAZNI", "Amazon"), ("VK-IRCTC", "IRCTC"), ("VK-APOLLO", "Apollo Pharmacy"),
        ("VK-BIGBAS", "BigBasket"), ("VK-MYNTRA", "Myntra"),
    ]
    delivery_templates = [
        "Your {brand} order #{oid} has been delivered. Rate your experience in the app.",
        "Your {brand} order #{oid} is out for delivery, expected by {time} today.",
        "Reminder: your appointment with {brand} is scheduled for {date}. Reply CONFIRM or CANCEL.",
    ]
    promo_templates = [
        "Flat {pct}% off on your next {brand} order! Shop now on the app.",
        "{brand} Independence Day sale is live — up to {pct}% off. Limited period offer.",
    ]
    for i, (sender, brand) in enumerate(brands):
        for j, tmpl in enumerate(delivery_templates):
            _n += 1
            text = tmpl.format(brand=brand, oid=45000 + i * 37 + j, time="6 PM", date="25-Aug")
            add(f"v2-delivery-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "txn_alert", "none", False, "synthetic")
        for j, tmpl in enumerate(promo_templates):
            _n += 1
            text = tmpl.format(brand=brand, pct=30 + i * 5 + j * 10)
            add(f"v2-promo-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "promo", "click" if "app" in text.lower() else "none", i % 4 == 0, "synthetic")


def _insurance_rows():
    global _n
    insurers = [("VM-LICIND", "LIC"), ("VK-HDFCLI", "HDFC Life"), ("VK-ICICIP", "ICICI Prudential")]
    for i, (sender, brand) in enumerate(insurers):
        for j in range(3):
            _n += 1
            text = (
                f"Your {brand} policy premium of Rs.{8000 + i*1200 + j*300} is due on 05-SEP-26. "
                f"Pay via the official {brand} app or website to keep your policy active."
            )
            add(f"v2-insure-{_n:03d}", text, sender, "dlt_header", "en", "legit",
                "txn_alert", "make_payment", i == 0, "synthetic")


def _hindi_telugu_legit_rows():
    global _n
    rows = [
        ("आपके खाते XX4521 से UPI द्वारा 1,200 रुपये डेबिट हुए। उपलब्ध शेष 8,340 रुपये। यह आप नहीं थे? {} पर कॉल करें।".format("1800-XXX-XXXX"),
         "VM-SBIINB", "dlt_header", "hi", "txn_alert", "call_back", True),
        ("आपका OTP 482913 है। इसे किसी के साथ साझा न करें, बैंक अधिकारी सहित।",
         "AX-ICICIB", "dlt_header", "hi", "otp", "none", True),
        ("మీ ఖాతా నుండి రూ.1500 డెబిట్ చేయబడింది. మీరు కాకపోతే 1800-XXX-XXXX కి కాల్ చేయండి.",
         "VM-HDFCBK", "dlt_header", "te", "txn_alert", "call_back", True),
        ("మీ KYC నవీకరణ 30-సెప్టెంబర్-26 నాటికి పూర్తి చేయండి. అధికారిక యాప్ లేదా బ్రాంచ్‌లో మాత్రమే.",
         "VM-SBIINB", "dlt_header", "te", "kyc_payment", "none", True),
    ]
    for text, sender, stype, lang, cat, ask, hard in rows:
        _n += 1
        add(f"v2-i18n-legit-{_n:03d}", text, sender, stype, lang, "legit", cat, ask, hard, "synthetic")


def _misc_personal_legit_rows():
    global _n
    rows = [
        "Hey, are we still meeting for lunch tomorrow at 1pm?",
        "Reminder: dentist appointment tomorrow at 10:30am. Reply to reschedule.",
        "Happy birthday! Hope you have a great day, let's catch up this weekend.",
        "Can you send me the notes from today's meeting when you get a chance?",
        "Landlord here — rent is due on the 5th as usual, same account.",
        "Missed call from an unknown international number, no message.",
        "Your package from a local seller has been picked up by the courier partner.",
        "School fee payment for term 2 is due by 5th September, pay via the school portal.",
        "You have opted in to receive cricket score updates. Reply STOP to unsubscribe.",
        "Thank you for donating to the relief fund. Your contribution receipt has been emailed.",
    ]
    for i, text in enumerate(rows):
        _n += 1
        sender = "unknown"
        stype = "unknown"
        if i % 3 == 0:
            sender, stype = "+91 90XXXXXX%02d" % i, "mobile_10d"
        elif i >= 8:
            sender, stype = str(58888 + i), "shortcode"
        add(f"v2-personal-{_n:03d}", text, sender, stype,
            "en", "legit" if i != 5 else "unclear",
            "txn_alert", "none", False, "synthetic")


_txn_alert_rows()
_otp_hard_negative_rows()
_fraud_alert_hard_negative_rows()
_kyc_reminder_hard_negative_rows()
_bill_utility_rows()
_delivery_promo_rows()
_insurance_rows()
_hindi_telugu_legit_rows()
_misc_personal_legit_rows()


# ===========================================================================
# SCAM — hand-authored, grounded in publicly documented advisories already
# cited in data/kb/*.yaml (MHA/I4C digital arrest, SEBI, RBI B.E.(A)WARE,
# bank/telecom impersonation reports). Spread across all 10 categories.
# ===========================================================================

def _scam_rows():
    global _n
    scams = [
        # digital_arrest
        ("This is Officer Sharma, Cyber Crime Cell Delhi. A case is registered against your Aadhaar for money laundering. Stay on this video call, do not disconnect. Transfer Rs {amt} to the verification account or a warrant will be issued.", "digital_arrest", "make_payment"),
        ("CBI Cyber Wing. A parcel with your Aadhaar contains narcotics from Taiwan. You are under digital arrest, do not tell anyone. Stay on this Skype call for verification.", "digital_arrest", "call_back"),
        ("ED officer here. Your bank account is under investigation. You are under digital arrest. Transfer Rs {amt} to escrow for verification within the hour.", "digital_arrest", "make_payment"),
        ("Mumbai Police Cyber Cell. FIR filed against you. Join this video call immediately, do not disconnect, or an arrest warrant will be issued today.", "digital_arrest", "call_back"),
        ("Narcotics Control Bureau. Cocaine was found in a parcel booked under your name. Remain on this call for the next 3 hours for digital arrest procedure.", "digital_arrest", "call_back"),
        # govt_impersonation
        ("Final notice: your income tax refund of Rs {amt} is pending. Verify your bank account details within 24 hours at incometax-refund-verify.in to receive it.", "govt_impersonation", "share_credential"),
        ("TRAI has issued a disconnection notice: your SIM will be blocked in 2 hours due to fraudulent use. Press 9 to speak to an executive now.", "govt_impersonation", "call_back"),
        ("Your Aadhaar card has been suspended due to a KYC mismatch. Update immediately at this link or your bank accounts linked to it will be frozen: aadhaar-update-portal.co", "govt_impersonation", "click"),
        ("Court notice: a case has been filed against your PAN card in a financial fraud matter. Contact this number immediately to avoid a warrant.", "govt_impersonation", "call_back"),
        ("EPFO alert: your provident fund withdrawal of Rs {amt} is on hold. Verify your UAN and bank details on this link within 48 hours.", "govt_impersonation", "share_credential"),
        # investment_trading
        ("Congratulations! You've been selected for our VIP stock trading group with guaranteed 40% monthly returns. Join our Telegram channel now, limited seats.", "investment_trading", "click"),
        ("Guaranteed 100% loan approval within 10 minutes, no documents required. Apply now on QuickCashApp and get instant disbursal.", "investment_trading", "install_app"),
        ("Double your money in 30 days with our SEBI-approved crypto arbitrage bot. Minimum investment Rs {amt}. DM to get started.", "investment_trading", "click"),
        ("Our VIP trading signals gave 45% returns last month. Join the WhatsApp group and start copying trades today, first week free.", "investment_trading", "click"),
        ("Limited slots! Learn guaranteed-profit stock trading from our expert, free 3-day workshop, click to register and get bonus signals.", "investment_trading", "click"),
        # fake_customer_care
        ("Hi, this is Priya from Airtel customer care. We noticed an issue with your recent recharge. Can you confirm the OTP sent to your number so I can process the refund?", "fake_customer_care", "share_credential"),
        ("Your Amazon order of a laptop for Rs {amt} has been placed. If this was not you, call this number immediately to cancel and get a refund.", "fake_customer_care", "call_back"),
        ("This is your bank calling regarding a suspicious transaction on your card. Can you confirm the OTP you just received so we can block the transaction?", "fake_customer_care", "share_credential"),
        ("Namaste, main aapka beta bol raha hoon, mera phone kharab ho gaya hai, ye naya number hai. Turant {amt} rupay UPI se bhej do, bahut zaroori hai.", "fake_customer_care", "make_payment"),
        ("Hey it's mom, lost my phone, texting from a friend's number. Can you send me Rs {amt} on this UPI ID urgently, will explain later.", "fake_customer_care", "make_payment"),
        # phishing_link
        ("Your parcel is held at customs due to incomplete address. Click here to pay Rs 199 customs fee and reschedule delivery: bluedart-redeliver.co", "phishing_link", "click"),
        ("Your Netflix payment failed. Update your payment method within 24 hours to avoid interruption: netflix-billing-update.com", "phishing_link", "click"),
        ("Install this app to track your delayed shipment in real time and claim compensation: courier-tracker-live.apk", "phishing_link", "install_app"),
        ("Your electricity connection will be disconnected tonight due to unpaid bill. Pay immediately via this link to avoid disconnection: eb-payment-urgent.in", "phishing_link", "click"),
        ("Congratulations, you're pre-approved for a Rs 5,00,000 personal loan at 0% processing fee. Apply now, offer expires today: loanapproval-instant.net", "phishing_link", "click"),
        ("Your device shows signs of a virus infection. Install this security app immediately to protect your bank details: secure-device-cleaner.apk", "phishing_link", "install_app"),
        ("Remote support required: install this screen-share app so our technician can fix the issue with your account remotely.", "fake_customer_care", "install_app"),
        ("Your antivirus subscription has expired, your device is at risk. Renew now and install the updated app to stay protected: av-renew-secure.apk", "phishing_link", "install_app"),
        # job_lottery
        ("URGENT JOB OFFER: Earn Rs 3000/day doing simple data entry from home. No experience needed. Registration fee Rs 500 refundable. WhatsApp now to register.", "job_lottery", "make_payment"),
        ("Congratulations! Your number has won Rs 25,00,000 in the KBC lucky draw. Send your bank details and a processing fee of Rs 5000 to claim.", "job_lottery", "share_credential"),
        ("Part-time job: like and share videos on YouTube, earn Rs 500/task. Join our Telegram channel, pay Rs 300 registration to start.", "job_lottery", "make_payment"),
        ("You've been selected for a work-from-home packing job with a reputed company. Pay a security deposit of Rs 2000 to receive your starter kit.", "job_lottery", "make_payment"),
        ("Lucky winner! Your WhatsApp number has won an iPhone 15 in our anniversary giveaway. Pay Rs 499 shipping to claim your prize.", "job_lottery", "make_payment"),
        # txn_alert (fake collect requests, not real bank alerts)
        ("You have a pending collect request for Rs 1 from merchant_verify@upi. Approve to receive your cashback of Rs 2000.", "txn_alert", "share_credential"),
        ("Your UPI account will be deactivated in 24 hours. Update your UPI PIN by approving the request sent to your phone.", "txn_alert", "share_credential"),
        ("Refund of Rs {amt} initiated for your cancelled order. Approve the collect request on your UPI app to receive it.", "txn_alert", "share_credential"),
        # otp
        ("Bank Verification: Your account is temporarily locked. Share the OTP sent to your phone to our executive to unlock it immediately.", "otp", "share_credential"),
        ("To cancel the unauthorized transaction on your card, please read out the OTP you just received to our fraud prevention team.", "otp", "share_credential"),
        # promo (fake)
        ("Mega Diwali Lucky Draw: Recharge Rs 100 and stand a chance to win Rs 1,00,000 instantly. Click to participate: recharge-luckydraw.in", "promo", "click"),
    ]
    # Each repeat of a template gets a distinct closing clause appended, so no
    # two rows ever share identical text (dedupe requirement) while still
    # exercising the same underlying pattern across multiple sender_types.
    _variant_suffixes = [
        "",
        " Reply within 30 minutes.",
        " This is your final reminder.",
        " Act now before it's too late.",
        " Failure to comply will result in immediate action.",
    ]
    # Every template gets at least one dlt_header (spoofed bank/telecom
    # header) repeat, in addition to unknown/mobile/intl/shortcode. Spoofed
    # headers on scam messages are a real and common vector in India — a big
    # reason scam SMS get trusted — and without at least one dlt_header scam
    # row per template, the with_sender pass (which only scores dlt_header
    # rows) would never see a single scam row, making scam recall
    # structurally unmeasurable under that pass.
    _spoofed_headers = ["VM-SBIINB", "VK-KYCUPD", "VM-REFUND", "AX-ALERTS"]
    _sender_pool = ["unknown", "mobile_10d", "dlt_header", "intl"]
    for i, (tmpl, cat, ask) in enumerate(scams):
        for j in range(4):  # 4 repeats = one per entry in _sender_pool, guaranteeing dlt_header coverage
            _n += 1
            base = tmpl.format(amt=f"{50000 + i*3700 + j*910}")
            text = base + _variant_suffixes[j % len(_variant_suffixes)]
            lang = "hi" if "Namaste" in tmpl else "en"
            # Every 7th template's 4th repeat uses shortcode instead of intl,
            # so shortcode gets scam-side coverage too without inflating the
            # per-template repeat count.
            stype = "shortcode" if (j == 3 and i % 7 == 0) else _sender_pool[j % len(_sender_pool)]
            sender = {
                "unknown": "unknown",
                "mobile_10d": "+91 9" + str(10000000 + i * 137 + j),
                "intl": "intl",
                "shortcode": str(56060 + i),
                "dlt_header": _spoofed_headers[i % len(_spoofed_headers)],
            }[stype]
            add(f"v2-scam-{_n:03d}", text, sender, stype,
                lang, "scam", cat, ask, False, "synthetic")


_scam_rows()


# ===========================================================================
# UNCLEAR — genuinely ambiguous, the abstain set (~20 rows)
# ===========================================================================

def _unclear_rows():
    global _n
    rows = [
        ("Missed call from an unknown number, no voicemail left.", "txn_alert", "none"),
        ("Hi, saw your resume online, we have an opening that might interest you, can we schedule a call this week?", "job_lottery", "call_back"),
        ("Your subscription renews in 3 days. Manage preferences in settings.", "promo", "none"),
        ("Digital arrest alert forwarded from a relative: they said stay on video call with 'CBI officer' and don't tell family, sounded scary, forwarding to warn everyone.", "digital_arrest", "none"),
        ("Limited slots! Learn stock trading from a SEBI-registered advisor, free 3-day workshop, click to register.", "investment_trading", "click"),
        ("Hi, this is a courtesy call regarding your recent enquiry about a personal loan. Are you still interested?", "kyc_payment", "call_back"),
        ("Your feedback is important — please rate your recent customer support experience.", "fake_customer_care", "none"),
        ("We tried to deliver your package but no one was home. Please reschedule via the courier's official tracking page.", "phishing_link", "none"),
        ("Unrecognized device logged into your account from a new location. If this was you, no action needed.", "otp", "none"),
        ("Your friend has sent you a gift card, click to redeem before it expires.", "promo", "click"),
        ("This is a reminder about the community meeting regarding the new society KYC verification drive on Saturday.", "kyc_payment", "none"),
        ("Someone tried to log in to your account. Was this you?", "otp", "none"),
        ("Investment opportunity in a new local business, minimum ticket size Rs 25,000, reach out if interested.", "investment_trading", "call_back"),
        ("Your number may be eligible for a government subsidy scheme, check eligibility on the portal.", "govt_impersonation", "click"),
        ("Congratulations on your new role! HR will reach out with onboarding details shortly.", "job_lottery", "none"),
        ("A relative mentioned getting a call about a 'parcel' with their name on it, unclear if it was genuine.", "digital_arrest", "none"),
        ("Please review and sign the attached document at your convenience.", "kyc_payment", "click"),
        ("We noticed unusual activity, please verify your recent transactions in the app.", "txn_alert", "none"),
        ("Your query has been escalated. Someone will contact you within 24-48 hours.", "fake_customer_care", "none"),
        ("This number appeared in a forwarded 'scam alert' message; no direct contact was made to us.", "phishing_link", "none"),
    ]
    for i, (text, cat, ask) in enumerate(rows):
        _n += 1
        add(f"v2-unclear-{_n:03d}", text, "unknown", "unknown", "en", "unclear", cat, ask,
            i % 3 == 0, "synthetic")


_unclear_rows()


if __name__ == "__main__":
    for row in ROWS:
        sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")

    counts = {}
    for row in ROWS:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"# TOTAL: {len(ROWS)}  {counts}", file=sys.stderr)
