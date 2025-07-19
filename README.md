# ML Microservice

Simple Flask-based microservice for malicious URL detection.

## Quick Start

### Local Development
```bash
pip install -r requirements.txt
python3 app.py
```

### Docker
```bash
docker build -t ml-microservice .
docker run -p 5001:5001 ml-microservice
```

## Port: 5001
## Model: Basic feature extraction 