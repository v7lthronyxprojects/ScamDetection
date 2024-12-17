from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QGuiApplication  
import sys
from gui import ScamDetectorGUI
from scanner import load_model, train_model, init_cache_db
import os
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def ensure_directories():
    directories = ['models', 'logs', 'cache']
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

def main():
    try:
        ensure_directories()
        init_cache_db()

        gui_app = QGuiApplication([])
        app = QApplication(sys.argv)

        model_path = 'models/scam_detector_model.pkl'
        if not os.path.exists(model_path):
            if not os.path.exists('scam_dataset.csv'):
                logger.error("Dataset file 'scam_dataset.csv' not found.")
                return
            logger.info("Training new model...")
            train_model()

        model = load_model()
        if model:
            window = ScamDetectorGUI(model)
            window.setWindowTitle("v7lthronyx ScamDetection نسخه ی اول بتا")
            window.show()
            sys.exit(app.exec())
        else:
            logger.error("Failed to load the ML model.")

    except Exception as e:
        logger.error(f"Application error: {e}")
        raise

if __name__ == "__main__":
    main()
