import joblib
import torch
from transformers import BertTokenizer, BertForSequenceClassification

# Load the saved traditional model (Voting Classifier) and TF-IDF vectorizer
tfidf = joblib.load('v1_tfidf_vectorizer.pkl')
voting_clf = joblib.load('traditional_email_classifier.pkl')

# Load the saved BERT model and tokenizer
# tokenizer = BertTokenizer.from_pretrained('bert_email_classifier')
# model = BertForSequenceClassification.from_pretrained('bert_email_classifier')

# Function to predict using the traditional model
def predict_with_traditional_models(email_text):
    email_tfidf = tfidf.transform([email_text])
    prediction = voting_clf.predict(email_tfidf)[0]  # prediction is already a string label like 'spam'
    return prediction


# Function to predict using the BERT model
# def predict_with_bert(email_text):
#     inputs = tokenizer(email_text, return_tensors='pt', padding=True, truncation=True, max_length=512)
#     model.eval()
#     with torch.no_grad():
#         outputs = model(**inputs)
#         logits = outputs.logits
#         prediction = torch.argmax(logits, dim=-1).item()  # Get the class prediction
#     label_map_reverse = {0: 'ham', 1: 'phishing', 2: 'spam'}
#     return label_map_reverse[prediction]

# Example usage: Classify a new email
new_email = "Congratulations! You've won a $1000 gift card. Click here to claim your prize."
print("Traditional Model Prediction:", predict_with_traditional_models(new_email))
#print("BERT Model Prediction:", predict_with_bert(new_email))
