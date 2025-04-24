import spacy
from nltk.sentiment import SentimentIntensityAnalyzer

nlp = spacy.load("en_core_web_sm")
sia = SentimentIntensityAnalyzer()

def generate_response(email_text):
    # Analyze intent
    doc = nlp(email_text)
    entities = [(ent.text, ent.label_) for ent in doc.ents]
    
    # Sentiment analysis
    sentiment = sia.polarity_scores(email_text)['compound']
    
    # Simple rule-based response
    if sentiment > 0.5:
        return "Thank you for your positive feedback!"
    elif 'question' in email_text.lower():
        return "We'll get back to you with a detailed response within 24 hours."
    else:
        return "Thank you for your email. We're processing your request."
