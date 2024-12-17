# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import joblib
import logging
from dotenv import load_dotenv
import os

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("train_model.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

MODEL_FILE = 'models/scam_detector_model.pkl'

def train_model(data_path='scam_dataset.csv', model_path=MODEL_FILE):
    try:
        data = pd.read_csv(data_path)
        X = data['url']
        y = data['label']

        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer()),
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])

        pipeline.fit(X, y)
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(pipeline, model_path)
        logger.info("Model trained and saved.")
    except Exception as e:
        logger.error(f"Error training model: {e}")

if __name__ == "__main__":
    train_model()
