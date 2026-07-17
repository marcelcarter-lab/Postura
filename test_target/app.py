from flask import Flask, send_from_directory

app = Flask(__name__)


@app.after_request
def add_security_header(response):
    # Deliberately added mid-Sprint-7 to create a real, observable
    # change for the diff feature's manual regression test — this
    # target previously sent zero security headers at all.
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/")
def index():
    return "<html><body><h1>Vulnerable Test Target</h1></body></html>"


@app.route("/.git/<path:filename>")
def fake_git(filename):
    return send_from_directory("fake_git", filename)


@app.route("/wp-content/")
def fake_wp_content():
    return "", 200


@app.route("/backup/")
def directory_listing():
    return (
        "<html><head><title>Index of /backup/</title></head>"
        "<body><h1>Index of /backup/</h1>"
        "<a href='backup.sql'>backup.sql</a></body></html>"
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
