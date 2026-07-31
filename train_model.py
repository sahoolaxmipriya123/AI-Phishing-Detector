import pandas as pd
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# Load dataset
data = pd.read_csv("phishing.csv")


# URL feature extraction
def clean_url(url):
    return re.sub(r'[^a-zA-Z0-9]', ' ', url)


data["url"] = data["url"].apply(clean_url)


# Create AI pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("classifier", LogisticRegression())
])


# Train model
model.fit(data["url"], data["label"])


# Save trained model
joblib.dump(model, "model/phishing_model.pkl")


print("✅ Phishing Detection Model Trained Successfully!")