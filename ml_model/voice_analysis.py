"""
voice_analysis.py
Wraps the trained deepfake voice detection model (Member 1's work) and
converts its output into the same risk-score format used by risk_engine.py.
"""
import os
import pickle
from tensorflow.keras.models import load_model
from ml_model.predict import predict_audio

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, 'final_model.keras')
ENCODER_PATH = os.path.join(MODEL_DIR, 'label_encoder.pkl')

# Load the model ONCE when this module is first imported (not per-request)
print("Loading deepfake voice detection model...")
_model = load_model(MODEL_PATH)
with open(ENCODER_PATH, 'rb') as f:
    _label_encoder = pickle.load(f)
print("Voice detection model loaded successfully.")


def analyze_voice(filepath: str) -> dict:
    """
    Runs the deepfake voice detector on an audio file and returns a result
    in the same shape as analyze_file() / analyze_text() in risk_engine.py.
    """
    result = predict_audio(filepath, _model, _label_encoder)
    label = result['label']          # 'bonafide' or 'spoof'
    confidence = result['confidence']  # 0-100

    if label == 'spoof':
        risk_score = int(confidence)
        threats = [f'Deepfake voice detected ({confidence:.1f}% confidence)']
    else:
        risk_score = int(100 - confidence)
        threats = [f'Voice appears authentic ({confidence:.1f}% confidence)']

    risk_score = max(0, min(risk_score, 100))
    risk_level = _score_to_level(risk_score)

    details = {
        'predicted_label': label,
        'confidence': confidence,
    }

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'threats': threats,
        'details': details,
    }


def _score_to_level(score: int) -> str:
    if score >= 70:
        return 'Critical'
    elif score >= 45:
        return 'High'
    elif score >= 20:
        return 'Medium'
    else:
        return 'Low'