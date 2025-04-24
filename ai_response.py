import os  # Add this line at the very top
from nltk.sentiment import SentimentIntensityAnalyzer
import spacy
if os.getenv("GITHUB_ACTIONS") == "true":
    respond_to_emails()  # Run once
else:
    while True:  # Local testing
        respond_to_emails()
        time.sleep(300)
