from flask import Flask, render_template, request
import joblib
import re

app = Flask(__name__)

# Load AI model
model = joblib.load("model/phishing_model.pkl")


def clean_url(url):
    return re.sub(r'[^a-zA-Z0-9]', ' ', url)


def analyze_url(url):
    risk = 10
    reasons = []

    # HTTPS check
    if not url.startswith("https"):
        risk += 20
        reasons.append("No HTTPS security")

    # Suspicious keywords
    keywords = [
        "login",
        "verify",
        "update",
        "free",
        "prize",
        "bank",
        "account",
        "password"
    ]

    for word in keywords:
        if word in url.lower():
            risk += 10
            reasons.append(f"Suspicious keyword found: {word}")

    # URL length
    if len(url) > 60:
        risk += 15
        reasons.append("URL length is very long")

    if risk > 100:
        risk = 100

    return risk, reasons


@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    risk = 0
    reasons = []

    if request.method == "POST":

        url = request.form["url"]

        cleaned = clean_url(url)

        prediction = model.predict([cleaned])[0]

        risk, reasons = analyze_url(url)

        if prediction == 1:
            result = "⚠️ This URL looks like a PHISHING link!"
            risk = max(risk, 80)

        else:
            result = "✅ This URL looks SAFE!"

    return render_template(
        "index.html",
        result=result,
        risk=risk,
        reasons=reasons
    )


if __name__ == "__main__":
    app.run(debug=True)