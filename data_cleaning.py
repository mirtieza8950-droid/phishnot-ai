import os
import re
import pandas as pd
from email import policy
from email.parser import BytesParser
from collections import Counter
from sklearn.utils import resample  # <-- added

# ===============================
# PATHS
# ===============================
SMS_DATASET = "datasets/spam.csv"
SPAMASSASSIN_SPAM = "datasets/span_2/"
SPAMASSASSIN_HAM = "datasets/hard_ham/"
PHISHING_DATASET = "datasets/Phishing_Email.csv"   # <-- Your phishing CSV file
EMAIL_DATASET = "datasets/emails.csv"

# ===============================
# CLEANING FUNCTION
# ===============================
def clean_text(text):
    """ Clean the text by removing URLs, emails, special chars, and normalizing whitespace. """

    text = str(text)

    # Remove 'Subject:' from start (case insensitive)
    text = re.sub(r"^\s*subject:\s*", "", text, flags=re.IGNORECASE)

    # Remove URLs
    text = re.sub(r"http\S+|www\S+", " ", text)

    # Remove email addresses
    text = re.sub(r"\S+@\S+", " ", text)

    # Remove HTML tags
    text = re.sub(r"<.*?>", " ", text)

    # Remove non-ASCII chars (emojis, symbols)
    text = text.encode('ascii', errors='ignore').decode()

    # Remove punctuation and special characters (keep letters, numbers, spaces)
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)

    # Normalize whitespace (tabs, newlines, multiple spaces)
    text = re.sub(r"\s+", " ", text)

    # Strip leading/trailing spaces and lowercase
    return text.strip().lower()


# ===============================
# LOAD SPAMASSASSIN EMAILS
# ===============================
def load_spamassassin(directory, label):
    """ Load emails from the SpamAssassin dataset (both spam and ham). """
    records = []

    for root, _, files in os.walk(directory):
        for file in files:
            if not file:
                continue

            file_path = os.path.join(root, file)

            try:
                # Open the file as a regular text file
                with open(file_path, "r", encoding="latin-1") as fp:
                    full_text = fp.read()

                records.append([full_text, label])

            except Exception as e:
                print(f"Error processing file {file}: {e}")
                continue

    return pd.DataFrame(records, columns=["text", "label"])


# ===============================
# LOAD PHISHING DATASET
# ===============================
def load_phishing_dataset(path):
    """ Load the phishing dataset and normalize column names. """
    df = pd.read_csv(path)

    df.columns = [c.lower().strip() for c in df.columns]

    print("Phishing Dataset Columns: ", df.columns)

    df = df[['email text', 'email type']]

    # Rename the columns for consistency
    df.columns = ["text", "label"]

    # Standardize the label names
    df["label"] = df["label"].astype(str).str.lower()
    df["label"] = df["label"].replace({
        "phishing email": "phishing",
        "safe email": "ham",
    })

    return df


def load_email_dataset(path):
    """ Load the email.csv dataset and rename columns accordingly. """
    df = pd.read_csv(path)

    # Lowercase and strip column names
    df.columns = [c.lower().strip() for c in df.columns]

    # Rename columns to match others
    df = df.rename(columns={"text": "text", "spam": "label"})

    # Convert label 0/1 to ham/spam strings
    df["label"] = df["label"].map({0: "ham", 1: "spam"}).fillna("ham")

    # Clean the email text (including removing 'Subject:')
    df["text"] = df["text"].apply(clean_text)

    # Remove empty or very short rows after cleaning
    df = df[df["text"].str.len() > 10]

    return df


# ===============================
# LOAD ALL DATASETS
# ===============================

print("[DL]  Loading SMS dataset...")
sms_df = pd.read_csv(SMS_DATASET, encoding="latin-1", usecols=[0, 1])

# Rename the columns
sms_df.columns = ["label", "text"]

print("SMS Dataset Shape: ", sms_df.shape)
print(sms_df.head())

print("[DL]  Loading SpamAssassin dataset (Spam)...")
spam_df = load_spamassassin(SPAMASSASSIN_SPAM, "spam")
print("[DL]  Loading SpamAssassin dataset (Ham)...")
ham_df = load_spamassassin(SPAMASSASSIN_HAM, "ham")

print("[DL]  Loading Phishing dataset...")
phish_df = load_phishing_dataset(PHISHING_DATASET)

print("[DL]  Loading Email dataset...")
email_df = load_email_dataset(EMAIL_DATASET)

# ===============================
# MERGE + CLEAN
# ===============================
print(" Cleaning text...")

# Combine all datasets into one
combined_df = pd.concat([sms_df, spam_df, ham_df, phish_df, email_df], ignore_index=True)

# Apply cleaning function to text column
combined_df["clean_text"] = combined_df["text"].apply(clean_text)

# Remove empty rows or short texts
combined_df = combined_df.dropna(subset=["clean_text"])
combined_df = combined_df[combined_df["clean_text"].str.strip() != ""]
combined_df = combined_df[combined_df["clean_text"].str.len() > 10]

# ===============================
# BALANCE THE DATASET
# ===============================

label_counts = Counter(combined_df["label"])
print("Label distribution before balancing:", label_counts)

# Separate classes
ham_df = combined_df[combined_df.label == 'ham']
phishing_df = combined_df[combined_df.label == 'phishing']
spam_df = combined_df[combined_df.label == 'spam']

# Find the smallest class size
min_size = min(len(ham_df), len(phishing_df), len(spam_df))

# Downsample each class to min_size
ham_downsampled = resample(ham_df, replace=False, n_samples=min_size, random_state=42)
phishing_downsampled = resample(phishing_df, replace=False, n_samples=min_size, random_state=42)
spam_downsampled = resample(spam_df, replace=False, n_samples=min_size, random_state=42)

# Combine balanced dataset
balanced_df = pd.concat([ham_downsampled, phishing_downsampled, spam_downsampled])

print("Label distribution after balancing:", balanced_df.label.value_counts())

# ===============================
# SAVE OUTPUT
# ===============================
output_path = "final_data_balanced.csv"
balanced_df.to_csv(output_path, index=False)

print("\n[OK]  Final balanced dataset created!")
print(f"Label distribution:\n{balanced_df['label'].value_counts()}")
print(balanced_df.head())
