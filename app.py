import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from risk_engine import analyze_file, analyze_text, get_risk_summary
from database import init_db, save_scan, get_all_scans, get_scan_by_id
from ml_model.voice_analysis import analyze_voice
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json', 'pcap', 'exe', 'py', 'zip'}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    recent_scans = get_all_scans(limit=5)
    return render_template('home.html', recent_scans=recent_scans)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            analysis = analyze_file(filepath, filename)
            scan_id = save_scan(
                filename=filename,
                risk_score=analysis['risk_score'],
                risk_level=analysis['risk_level'],
                threats=analysis['threats'],
                details=analysis['details'],
                source_type='File'
            )
            return redirect(url_for('result', scan_id=scan_id))
        else:
            flash('File type not allowed')
            return redirect(request.url)

    return render_template('upload.html')


@app.route('/result/<int:scan_id>')
def result(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        flash('Scan not found')
        return redirect(url_for('home'))
    return render_template('result.html', scan=scan)

@app.route('/text-detection')
def text_detection():
    return render_template('text_detection.html')

@app.route('/voice-detection')
def voice_detection():
    return render_template('voice_detection.html')


@app.route('/api/analyze-voice', methods=['POST'])
def api_analyze_voice():
    if 'audio' not in request.files:
        return jsonify({'error': 'No audio file provided'}), 400

    file = request.files['audio']
    if file.filename == '':
        return jsonify({'error': 'No audio file selected'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        analysis = analyze_voice(filepath)
    except Exception as e:
        return jsonify({'error': f'Audio analysis failed: {str(e)}'}), 500

    scan_id = save_scan(
        filename=filename,
        risk_score=analysis['risk_score'],
        risk_level=analysis['risk_level'],
        threats=analysis['threats'],
        details=analysis['details'],
        source_type='Voice'
    )

    return jsonify({
        'scan_id': scan_id,
        'risk_score': analysis['risk_score'],
        'risk_level': analysis['risk_level'],
        'threats': analysis['threats'],
        'predicted_label': analysis['details'].get('predicted_label'),
        'confidence': analysis['details'].get('confidence'),
        'source_type': 'Voice',
        'result_url': url_for('result', scan_id=scan_id)
    })

@app.route('/api/analyze-text', methods=['POST'])
def api_analyze_text():
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()

    if not text:
        return jsonify({'error': 'Please enter some text to analyze'}), 400
    analysis = analyze_text(text)
    preview = ' '.join(text.split()[:6])
    label = f'Text: "{preview}{"..." if len(text.split()) > 6 else ""}"'

    scan_id = save_scan(
        filename=label,
        risk_score=analysis['risk_score'],
        risk_level=analysis['risk_level'],
        threats=analysis['threats'],
        details=analysis['details'],
        source_type='Text'
    )
    return jsonify({
        'scan_id': scan_id,
        'risk_score': analysis['risk_score'],
        'risk_level': analysis['risk_level'],
        'threats': analysis['threats'],
        'matched_keywords': analysis['details'].get('matched_keywords', []),
        'char_count': analysis['details'].get('char_count', len(text)),
        'word_count': analysis['details'].get('word_count', len(text.split())),
        'source_type': 'Text',
        'result_url': url_for('result', scan_id=scan_id)
    })

@app.route('/dashboard')
def dashboard():
    scans = get_all_scans(limit=100)
    summary = get_risk_summary(scans)
    return render_template('dashboard.html', scans=scans, summary=summary)


@app.errorhandler(413)
def file_too_large(_e):
    flash('File is too large. Maximum allowed size is 25 MB.')
    return redirect(url_for('upload'))


@app.errorhandler(404)
def not_found(_e):
    flash('That page does not exist.')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
