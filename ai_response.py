import spacy
from nltk.sentiment import SentimentIntensityAnalyzer

nlp = spacy.load("en_core_web_sm")
sia = SentimentIntensityAnalyzer()

def generate_response(email_text):
    doc = nlp(email_text)
    sentiment = sia.polarity_scores(email_text)

    # Just an example response logic
    if sentiment["compound"] >= 0.5:
        return "Thank you for your kind message! I'll get back to you shortly."
    elif sentiment["compound"] <= -0.5:
        return "I'm sorry to hear that. Let me know how I can help."
    else:
        return "Thanks for your email. I'll respond to you as soon as possible."
