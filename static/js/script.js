// ==============================
// AI Cybersecurity Project - script.js
// ==============================

document.addEventListener('DOMContentLoaded', () => {
  initUploadZone();
  initRiskMeter();
});

// ---- Drag & drop upload zone ----
function initUploadZone() {
  const zone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('file-input');
  const fileNameEl = document.getElementById('file-name');
  const form = document.getElementById('upload-form');
  const submitBtn = document.getElementById('submit-btn');

  if (!zone || !fileInput) return;

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      fileNameEl.textContent = `Selected: ${fileInput.files[0].name}`;
    }
  });

  ['dragenter', 'dragover'].forEach(evt => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(evt => {
    zone.addEventListener(evt, (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
    });
  });

  zone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length) {
      fileInput.files = files;
      fileNameEl.textContent = `Selected: ${files[0].name}`;
    }
  });

  if (form && submitBtn) {
    form.addEventListener('submit', () => {
      submitBtn.textContent = 'Analyzing...';
      submitBtn.disabled = true;
      submitBtn.style.opacity = '0.7';
    });
  }
}

// ---- Animated linear risk meter fill ----
function initRiskMeter() {
  const fill = document.querySelector('.risk-meter-fill');
  if (!fill) return;

  const score = parseFloat(fill.dataset.score || 0); // 0-100
  setTimeout(() => {
    fill.style.width = `${score}%`;
  }, 200);
}
