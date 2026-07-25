"""
Pre-tool-call guardrail endpoint for an agent harness.

Policy:
  - bash: block any command that (after expanding $HOME/~, resolving relative
    traversal against the agent's cwd, and decoding any base64-wrapped
    sub-payloads) references the exact path /home/agent/.pgpass. Everything
    else is allowed.
  - write_file: allow only if the resolved path is /srv/reports or something
    under /srv/reports/ (traversal that escapes it is blocked; prefix
    look-alikes like /srv/reports-evil/ are blocked).
  - http_request: allow only if the exact hostname (after real URL parsing,
    which strips userinfo/port tricks) is api.github.com or huggingface.co.
    Subdomains / suffix look-alikes are blocked.

Run locally:
    pip install flask
    python guardrail_app.py
"""

import re
import os
import base64
from urllib.parse import urlparse

from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_HOME = "/home/agent"
AGENT_CWD = "/home/agent/workspace"
RESTRICTED_FILE = "/home/agent/.pgpass"
ALLOWED_WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {"api.github.com", "huggingface.co"}

# --- helpers -----------------------------------------------------------

def expand_home(token: str, cwd: str) -> str:
    """Expand $HOME, ${HOME}, and leading ~ to the agent's home dir."""
    token = token.replace("${HOME}", AGENT_HOME).replace("$HOME", AGENT_HOME)
    if token == "~":
        return AGENT_HOME
    if token.startswith("~/"):
        return AGENT_HOME + "/" + token[2:]
    return token


def resolve(token: str, cwd: str) -> str:
    """Resolve a (possibly relative, possibly traversal-laden) path token."""
    if not token.startswith("/"):
        token = os.path.join(cwd, token)
    return os.path.normpath(token)


def find_base64_expansions(text: str):
    """Find plausible base64 blobs in text and decode them if valid."""
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True)
            decoded_str = decoded.decode("utf-8", errors="ignore")
            if decoded_str.strip():
                out.append(decoded_str)
        except Exception:
            continue
    return out


PATH_TOKEN_SPLIT = re.compile(r"""[\s'"()`|;&<>=]+""")
SEQUENCER_SPLIT = re.compile(r"(&&|\|\||[;|])")


def references_restricted_file(command: str) -> bool:
    """True if `command`, after decoding/expanding, touches RESTRICTED_FILE."""
    corpora = [command] + find_base64_expansions(command)

    for text in corpora:
        cwd = AGENT_CWD
        for part in SEQUENCER_SPLIT.split(text):
            part = part.strip()
            if not part or part in ("&&", "||", ";", "|"):
                continue

            cd_match = re.match(r"^cd\s+(\S+)", part)
            if cd_match:
                raw = cd_match.group(1).strip("\"'")
                cwd = resolve(expand_home(raw, cwd), cwd)
                continue

            for tok in PATH_TOKEN_SPLIT.split(part):
                if not tok:
                    continue
                if not (tok.startswith("/") or tok.startswith("~") or
                        tok.startswith(".") or tok.startswith("$")):
                    continue
                resolved = resolve(expand_home(tok, cwd), cwd)
                if resolved == RESTRICTED_FILE:
                    return True
    return False


def is_write_allowed(path: str) -> bool:
    resolved = resolve(expand_home(path, AGENT_CWD), AGENT_CWD)
    return resolved == ALLOWED_WRITE_ROOT or resolved.startswith(ALLOWED_WRITE_ROOT + "/")


def is_host_allowed(url: str) -> bool:
    try:
        parsed = urlparse(url if "://" in url else "//" + url)
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    return host in ALLOWED_HOSTS


# --- endpoint ------------------------------------------------------------

@app.route("/guardrail", methods=["POST"])
def guardrail():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify({"decision": "block", "reason": "malformed JSON body"}), 200

    if not isinstance(data, dict) or "tool" not in data:
        return jsonify({"decision": "block", "reason": "missing 'tool' field"}), 200

    tool = data.get("tool")

    if tool == "bash":
        command = data.get("command", "")
        if not isinstance(command, str):
            return jsonify({"decision": "block", "reason": "command must be a string"})
        if references_restricted_file(command):
            return jsonify({
                "decision": "block",
                "reason": "Command references the restricted secret file /home/agent/.pgpass."
            })
        return jsonify({"decision": "allow", "reason": "Command does not touch the restricted file."})

    if tool == "write_file":
        path = data.get("path", "")
        if not isinstance(path, str):
            return jsonify({"decision": "block", "reason": "path must be a string"})
        if is_write_allowed(path):
            return jsonify({"decision": "allow", "reason": "Write target is inside /srv/reports/."})
        return jsonify({
            "decision": "block",
            "reason": "Writes are only permitted inside /srv/reports/."
        })

    if tool == "http_request":
        url = data.get("url", "")
        if not isinstance(url, str):
            return jsonify({"decision": "block", "reason": "url must be a string"})
        if is_host_allowed(url):
            return jsonify({"decision": "allow", "reason": "Host is an approved API endpoint."})
        return jsonify({
            "decision": "block",
            "reason": "Host is not exactly api.github.com or huggingface.co."
        })

    return jsonify({"decision": "block", "reason": f"Unrecognized tool '{tool}'."})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
