import os
import spacy
from nltk.sentiment import SentimentIntensityAnalyzer

nlp = spacy.load("en_core_web_sm")
sia = SentimentIntensityAnalyzer()

def generate_response(email_text):
    # Your existing response generation logic here
    doc = nlp(email_text)
    # ... rest of your function
