import librosa
import numpy as np
import cv2
from pydub import AudioSegment
from tensorflow.keras.applications.efficientnet import preprocess_input
from tensorflow.keras.models import load_model
import pickle
import os
import tempfile

def load_detector(model_path, encoder_path):
    model = load_model(model_path)
    with open(encoder_path, 'rb') as f:
        le = pickle.load(f)
    return model, le

def predict_audio(filepath, model, le, tmp_dir=None):
    if tmp_dir is None:
        tmp_dir = tempfile.gettempdir()
    os.makedirs(tmp_dir, exist_ok=True)
    SAMPLE_RATE, SAMPLES, IMG_SIZE = 16000, 32000, 128

    audio_seg = AudioSegment.from_file(filepath)
    tmp_mp3 = os.path.join(tmp_dir, 'infer_tmp.mp3')
    audio_seg.export(tmp_mp3, format='mp3', bitrate='128k')
    audio, sr = librosa.load(tmp_mp3, sr=SAMPLE_RATE, mono=True)
    os.remove(tmp_mp3)

    audio, _ = librosa.effects.trim(audio, top_db=20)
    if np.max(np.abs(audio)) > 0:
        audio = audio / np.max(np.abs(audio))
    audio = audio[:SAMPLES] if len(audio) > SAMPLES else np.pad(audio, (0, SAMPLES - len(audio)))

    mel = librosa.feature.melspectrogram(y=audio, sr=SAMPLE_RATE, n_mels=128)
    mel_db = librosa.power_to_db(mel, ref=np.max)
    mel_img = cv2.normalize(mel_db, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    mel_img = cv2.resize(mel_img, (IMG_SIZE, IMG_SIZE))
    mel_img = cv2.cvtColor(mel_img, cv2.COLOR_GRAY2RGB)

    img_batch = preprocess_input(np.expand_dims(mel_img.astype("float32"), axis=0))
    probs = model.predict(img_batch, verbose=0)[0]
    pred_label = le.inverse_transform([np.argmax(probs)])[0]
    confidence = float(probs.max() * 100)

    return {"label": str(pred_label), "confidence": round(confidence, 2)}