from flask import Flask, send_from_directory

app = Flask(__name__)


@app.route("/")
def index():
    # Intentionally NO security headers set here (no CSP, HSTS,
    # X-Frame-Options, etc.) — the point of this target is to be
    # scanned and have Postura's header checks correctly flag all of
    # them as missing.
    return "<html><body><h1>Vulnerable Test Target</h1></body></html>"


@app.route("/.git/<path:filename>")
def fake_git(filename):
    # Serves fake .git files from a local folder, simulating an
    # accidentally-committed .git directory being exposed on a live
    # site — a classic real-world misconfiguration.
    return send_from_directory("fake_git", filename)


@app.route("/wp-content/")
def fake_wp_content():
    # Simulates a WordPress CMS fingerprint signature existing, so
    # CMSFingerprintCheck has something real to detect.
    return "", 200


@app.route("/backup/")
def directory_listing():
    # Simulates an Apache-style directory listing page.
    return (
        "<html><head><title>Index of /backup/</title></head>"
        "<body><h1>Index of /backup/</h1>"
        "<a href='backup.sql'>backup.sql</a></body></html>"
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
