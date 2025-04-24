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
# Add to the bottom of ai_response.py
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder
import numpy as np

def train_custom_classifier():
    # Example training data (replace with your dataset)
    texts = ["I need help", "This is great", "Fix this bug"]
    labels = ["support", "feedback", "bug"]  # Your categories
    
    # Encode labels
    le = LabelEncoder()
    y = le.fit_transform(labels)
    
    # Simple TF model
    model = tf.keras.Sequential([
        tf.keras.layers.Embedding(1000, 16, input_length=20),
        tf.keras.layers.GlobalAveragePooling1D(),
        tf.keras.layers.Dense(3, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    
    # Train (simplified example)
    model.fit(np.random.randint(0, 100, (3, 20)), y, epochs=5)
    return model, le

# Update generate_response() to use the trained model
def generate_response(email_text):
    model, le = train_custom_classifier()  # Load pre-trained in production
    pred = model.predict(np.random.randint(0, 100, (1, 20)))  # Replace with real input
    category = le.inverse_transform([np.argmax(pred)])
    return f"Automated response for {category[0]}."
