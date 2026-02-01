from flask import Flask, render_template, request, redirect, url_for
import hashlib
import os
import mimetypes
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Upload config
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB limit

# Heuristic indicators
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".js", ".vbs"}
SUSPICIOUS_KEYWORDS = ["powershell", "cmd.exe", "wget", "curl", "password"]

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def keyword_scan(file_path):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()
            for k in SUSPICIOUS_KEYWORDS:
                if k in content:
                    findings.append(k)
    except Exception:
        pass
    return findings


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        if "file" not in request.files:
            return redirect(url_for("index"))

        file = request.files["file"]

        if file.filename == "":
            return redirect(url_for("index"))

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # File details
        extension = os.path.splitext(filename)[1].lower()
        mime_type, _ = mimetypes.guess_type(file_path)

        # Hash
        file_hash = calculate_hash(file_path)

        # Keyword scan
        keywords = keyword_scan(file_path)

        # Risk scoring
        score = 0
        if extension in SUSPICIOUS_EXTENSIONS:
            score += 40
        if keywords:
            score += 40
        if mime_type and mime_type.startswith("application"):
            score += 20

        if score >= 60:
            risk = "High"
        elif score >= 30:
            risk = "Medium"
        else:
            risk = "Low"

        result = {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type or "Unknown",
            "sha256": file_hash,
            "keywords": keywords,
            "risk": risk,
            "score": score
        }

    return render_template("maindashboard.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
