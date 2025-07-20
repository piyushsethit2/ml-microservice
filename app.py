from flask import Flask, request, jsonify
import joblib
import re
import numpy as np
import math
import logging
from datetime import datetime
import sys

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)

# Create logger
logger = logging.getLogger(__name__)

# Log startup information
logger.info("=== ML Microservice Starting ===")
logger.info("Service: ML-based URL detection")
logger.info("Version: 1.0.0")
logger.info("Environment: Production")
logger.info("Model: scikit-learn RandomForest")
logger.info("==================================")

app = Flask(__name__)

# Dummy model for demonstration (replace with your own trained model)
class DummyModel:
    def predict_proba(self, X):
        # Return [prob_safe, prob_malicious]
        return np.array([[0.2, 0.8] if x[0] > 75 else [0.9, 0.1] for x in X])

# Load your real model here (e.g., joblib.load('model.pkl'))
model = DummyModel()

# Feature extraction
SUSPICIOUS_WORDS = [
    'login', 'secure', 'account', 'update', 'bank', 'free', 'verify', 'password',
    'ebay', 'paypal', 'signin', 'wp-admin', 'download', 'malware', 'virus', 'phish', 'hack'
]

def extract_features(url):
    features = []
    # Length
    features.append(len(url))
    # Count of digits
    features.append(sum(c.isdigit() for c in url))
    # Count of special chars
    features.append(sum(not c.isalnum() for c in url))
    # Suspicious words
    features.append(sum(word in url.lower() for word in SUSPICIOUS_WORDS))
    # Entropy
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    entropy = -sum([p * math.log(p) / math.log(2) for p in prob])
    features.append(entropy)
    # Count of subdomains
    features.append(url.count('.'))
    return np.array([features])

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    logger.info(f"Processing URL: {url}")
    
    X = extract_features(url)
    proba = model.predict_proba(X)[0]
    
    result = {
        'malicious': bool(proba[1] > 0.5),
        'confidence': float(proba[1]),
        'details': f"ML model confidence: {proba[1]:.2f}"
    }
    
    logger.info(f"Prediction result: {result}")
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check if model is loaded
        if model is None:
            raise Exception("ML model not loaded")
            
        health_status = {
            "status": "UP",
            "service": "ML Microservice",
            "version": "1.0.0",
            "model_loaded": True,
            "timestamp": datetime.now().isoformat(),
            "endpoints": {
                "/predict": "POST - URL prediction endpoint",
                "/health": "GET - Health check endpoint"
            }
        }
        
        logger.info("Health check passed - ML model is loaded")
        return jsonify(health_status), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        health_status = {
            "status": "DOWN",
            "service": "ML Microservice",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        return jsonify(health_status), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001) 