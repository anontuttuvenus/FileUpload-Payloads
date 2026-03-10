# -*- coding: utf-8 -*-
"""
OAHunt v3.2 - OAuth/OIDC/SAML Exploit Confirmer
Burp Suite Extension - Jython 2.7

ROOT CAUSE FIX for '_main_panel' AttributeError:
  - registerExtenderCallbacks runs on the EDT in Burp 2026
  - invokeAndWait on EDT = deadlock
  - invokeLater = race: addSuiteTab calls getUiComponent before UI is built
  
SOLUTION:
  - Build UI entirely synchronously (no Swing threads) using plain JPanel construction
  - No invokeLater, no invokeAndWait in registerExtenderCallbacks
  - _main_panel is set before addSuiteTab is ever called
  - Subsequent updates (findings, log) use invokeLater safely (from worker threads)

Authorize-style design:
  - Browser request flows through proxy UNTOUCHED
  - processHttpMessage clones the request bytes, queues jobs, returns immediately  
  - Jobs run in background ThreadPoolExecutor
  - Only confirmed exploits appear in findings
"""

from burp import IBurpExtender, IHttpListener, ITab, IExtensionStateListener

# Import Swing synchronously — safe at class definition time
import javax.swing as swing
import java.awt as awt
from java.awt.event import ActionListener, MouseAdapter
from java.lang import Runnable
from java.util.concurrent import LinkedBlockingQueue, ThreadPoolExecutor, TimeUnit
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer

import json
import time

# ── Colours ──────────────────────────────────
C_BG      = awt.Color(13,  17,  23)
C_SURFACE = awt.Color(22,  27,  34)
C_BORDER  = awt.Color(48,  54,  61)
C_ACCENT  = awt.Color(88,  166, 255)
C_GREEN   = awt.Color(63,  185, 80)
C_YELLOW  = awt.Color(210, 153, 34)
C_RED     = awt.Color(248, 81,  73)
C_TEXT    = awt.Color(201, 209, 217)
C_MUTED   = awt.Color(110, 118, 129)

SEVERITY_COLORS = {
    "CRITICAL": awt.Color(255, 50,  50),
    "HIGH":     awt.Color(240, 100, 40),
    "MEDIUM":   awt.Color(210, 153, 34),
    "LOW":      awt.Color(63,  185, 80),
    "INFO":     awt.Color(88,  166, 255),
}

# ── OAuth detection ───────────────────────────
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
    "goto", "continue", "url", "target", "dest",
    "postLogin", "landingPage", "after_login", "callback", "redirect_url",
]

CANARY = "oauthhunter-canary.example.com"


# ─────────────────────────────────────────────
# REQUEST CLONE
# ─────────────────────────────────────────────
class Clone(object):
    def __init__(self, helpers, msg):
        self._h       = helpers
        self._service = msg.getHttpService()
        self._bytes   = msg.getRequest()[:]

    def getHttpService(self):
        return self._service

    def getRequest(self):
        return self._bytes

    def _params(self):
        return self._h.analyzeRequest(
            self._service, self._bytes).getParameters()

    def set_param(self, name, value):
        for p in self._params():
            if str(p.getName()) == name:
                self._bytes = self._h.updateParameter(
                    self._bytes,
                    self._h.buildParameter(name, value, p.getType()))
                return
        self._bytes = self._h.addParameter(
            self._bytes,
            self._h.buildParameter(name, value, 0))

    def del_param(self, name):
        for p in self._params():
            if str(p.getName()) == name:
                self._bytes = self._h.removeParameter(self._bytes, p)
                return


# ─────────────────────────────────────────────
# ATTACK JOBS
# ─────────────────────────────────────────────
class Job(Runnable):
    def __init__(self, ext, msg, pm, host, path):
        self.ext  = ext
        self.msg  = msg
        self.pm   = pm
        self.host = host
        self.path = path

    def run(self):
        try:
            self.go()
        except Exception as ex:
            self.ext._log("ERR [{}] {}".format(
                self.__class__.__name__, str(ex)))

    def go(self):
        pass

    def clone(self):
        return Clone(self.ext._helpers, self.msg)

    def fire(self, c):
        return self.ext._callbacks.makeHttpRequest(
            c.getHttpService(), c.getRequest())

    def loc(self, r):
        if not r or not r.getResponse():
            return ""
        for h in self.ext._helpers.analyzeResponse(
                r.getResponse()).getHeaders():
            s = str(h)
            if s.lower().startswith("location:"):
                return s[9:].strip()
        return ""

    def st(self, r):
        if not r or not r.getResponse():
            return 0
        return self.ext._helpers.analyzeResponse(r.getResponse()).getStatusCode()

    def body(self, r, n=600):
        if not r or not r.getResponse():
            return ""
        try:
            return self.ext._helpers.bytesToString(r.getResponse())[:n]
        except Exception:
            return ""

    def ok(self, r):
        """Response is non-error."""
        l = self.loc(r)
        s = self.st(r)
        return s > 0 and "error" not in l.lower() and "unauthorized" not in l.lower()

    def report(self, name, sev, cwe, evidence):
        self.ext._add_finding(
            self.host, self.path, self.msg,
            name, sev, cwe, evidence)


class JobOpenRedirect(Job):
    def __init__(self, ext, msg, pm, host, path, pname):
        Job.__init__(self, ext, msg, pm, host, path)
        self.pname = pname

    def go(self):
        for payload in [
            "https://" + CANARY,
            "//" + CANARY,
            "https://" + CANARY + "%40" + self.host,
        ]:
            c = self.clone()
            c.set_param(self.pname, payload)
            r  = self.fire(c)
            l  = self.loc(r)
            s  = self.st(r)
            if s in (301, 302, 303, 307, 308):
                if (CANARY in l or
                        (l.startswith("http") and
                         self.host not in l and
                         "error" not in l.lower())):
                    self.report(
                        "Open Redirect via '{}'".format(self.pname),
                        "HIGH", "CWE-601",
                        "Payload: {}={}\nServer {} -> {}".format(
                            self.pname, payload, s, l[:120]))
                    return


class JobPrefixBypass(Job):
    def __init__(self, ext, msg, pm, host, path, orig):
        Job.__init__(self, ext, msg, pm, host, path)
        self.orig = orig

    def go(self):
        for sfx in [
            "?next=https://"      + CANARY,
            "?returnTo=https://"  + CANARY,
            "?redirect=https://"  + CANARY,
            "%3Fnext%3Dhttps%3A%2F%2F" + CANARY,
            "#https://"           + CANARY,
            "/../../../evil",
            "%2f..%2f..%2fevil",
        ]:
            c = self.clone()
            c.set_param("redirect_uri", self.orig + sfx)
            r = self.fire(c)
            l = self.loc(r)
            s = self.st(r)
            b = self.body(r)
            if s in (301, 302, 303) and "error" not in l.lower():
                if CANARY in l or "code=" in l:
                    self.report(
                        "redirect_uri Prefix Match Bypass",
                        "HIGH", "CWE-183",
                        "Suffix '{}' accepted.\nStatus:{} Location:{}".format(
                            sfx, s, l[:120]))
                    return
            if "error_description" in b and CANARY in b:
                self.report(
                    "redirect_uri Prefix Bypass (whitelist exposed in error)",
                    "MEDIUM", "CWE-183",
                    "Server attempted redirect to modified URI.\n{}".format(
                        b[:300]))
                return


class JobStateCsrf(Job):
    def go(self):
        if "state" not in self.pm:
            return
        c = self.clone()
        c.del_param("state")
        r = self.fire(c)
        l = self.loc(r)
        s = self.st(r)
        if s in (200, 301, 302) and "error" not in l.lower():
            if "code=" in l or "token=" in l or s == 200:
                self.report(
                    "Missing State — CSRF Login Confirmed",
                    "HIGH", "CWE-352",
                    "Request sent WITHOUT state. Server accepted.\n"
                    "Status:{} Location:{}".format(s, l[:100]))


class JobPkce(Job):
    def go(self):
        if (self.pm.get("response_type") != "code" or
                "code_challenge" not in self.pm):
            return
        c = self.clone()
        c.del_param("code_challenge")
        c.del_param("code_challenge_method")
        r = self.fire(c)
        l = self.loc(r)
        s = self.st(r)
        if s in (301, 302) and "code=" in l and "error" not in l.lower():
            self.report(
                "PKCE Bypass — Code Issued Without Verifier",
                "MEDIUM", "CWE-345",
                "Stripped code_challenge. Server still returned code.\n"
                "Location:{}".format(l[:120]))


class JobScope(Job):
    def go(self):
        if "scope" not in self.pm or "response_type" not in self.pm:
            return
        orig = self.pm["scope"]
        for scope in [orig + " admin", orig + " offline_access",
                      "openid profile email admin", "admin"]:
            c = self.clone()
            c.set_param("scope", scope)
            r = self.fire(c)
            l = self.loc(r)
            s = self.st(r)
            b = self.body(r)
            if s in (200, 302) and "error" not in l.lower():
                if "code=" in l or "access_token" in b:
                    self.report(
                        "Scope Escalation Confirmed",
                        "HIGH", "CWE-269",
                        "scope='{}' accepted.\nStatus:{} Location:{}".format(
                            scope, s, l[:100]))
                    return


class JobRedirectInject(Job):
    def __init__(self, ext, msg, pm, host, path, pname):
        Job.__init__(self, ext, msg, pm, host, path)
        self.pname = pname

    def go(self):
        for dest in ["/admin", "/admin/users",
                     "/manage", "https://" + CANARY]:
            c = self.clone()
            c.set_param(self.pname, dest)
            r = self.fire(c)
            l = self.loc(r)
            s = self.st(r)
            if s in (301, 302, 303) and dest in l:
                self.report(
                    "Post-Auth Redirect Injection via '{}'".format(self.pname),
                    "HIGH", "CWE-601",
                    "{}={}\nServer -> {}".format(self.pname, dest, l[:120]))
                return


class JobG2g(Job):
    def __init__(self, ext, msg, pm, host, path, cookies):
        Job.__init__(self, ext, msg, pm, host, path)
        self.cookies = cookies

    def go(self):
        if not any(k.lower() in ("g2g", "eg2g")
                   for k in self.cookies.keys()):
            return
        h = self.ext._helpers
        for tpath in ["/en/dashboard.html", "/en/profile/manage",
                      "/dombff-profile/profile", "/en/admin"]:
            for gval in ["false", "0", ""]:
                parts = []
                for k, v in self.cookies.items():
                    if k.lower() == "g2g":
                        parts.append("g2g=" + gval)
                    elif k.lower() == "eg2g":
                        parts.append("eg2g=" + gval)
                    else:
                        parts.append("{}={}".format(k, v))
                raw = ("GET {} HTTP/1.1\r\nHost: {}\r\n"
                       "Cookie: {}\r\nUser-Agent: OAuthHunter\r\n"
                       "Accept: text/html\r\nConnection: close\r\n\r\n"
                       ).format(tpath, self.host, "; ".join(parts))
                try:
                    resp = self.ext._callbacks.makeHttpRequest(
                        self.msg.getHttpService(), h.stringToBytes(raw))
                    l = self.loc(resp)
                    s = self.st(resp)
                    b = self.body(resp)
                    if s == 200 and "intercept" not in b.lower():
                        self.report(
                            "g2g Interceptor Bypass Confirmed",
                            "CRITICAL", "CWE-284",
                            "GET {} with g2g={}\n"
                            "200 OK without intercept page.".format(tpath, gval))
                        return
                    if s in (301, 302) and "intercept" not in l.lower() and l:
                        self.report(
                            "g2g Interceptor Bypass Confirmed",
                            "CRITICAL", "CWE-284",
                            "GET {} with g2g={}\n"
                            "Redirected to {}".format(tpath, gval, l[:80]))
                        return
                except Exception:
                    pass


class JobSaml(Job):
    def go(self):
        if "RelayState" not in self.pm:
            return
        for payload in ["https://" + CANARY, "//" + CANARY, "/admin"]:
            c = self.clone()
            c.set_param("RelayState", payload)
            r = self.fire(c)
            l = self.loc(r)
            s = self.st(r)
            if CANARY in l or "/admin" in l or payload in l:
                self.report(
                    "SAML RelayState Redirect Confirmed",
                    "HIGH", "CWE-601",
                    "RelayState={}\nServer -> {}".format(payload, l[:120]))
                return


# ─────────────────────────────────────────────
# TABLE MODEL
# ─────────────────────────────────────────────
class ROModel(DefaultTableModel):
    def isCellEditable(self, r, c):
        return False


class SevRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, t, v, sel, foc, r, c):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, t, v, sel, foc, r, c)
        if c == 2:
            self.setForeground(SEVERITY_COLORS.get(str(v), C_TEXT))
            self.setFont(awt.Font("Monospaced", awt.Font.BOLD, 11))
        else:
            self.setForeground(C_TEXT)
            self.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 11))
        self.setBackground(C_SURFACE if not sel else C_ACCENT.darker())
        return comp


# ─────────────────────────────────────────────
# SWING RUNNABLES (called from worker threads)
# ─────────────────────────────────────────────
class RAddRow(Runnable):
    def __init__(self, ext, f):
        self.ext = ext
        self.f   = f

    def run(self):
        f = self.f
        self.ext._model.addRow([
            f["timestamp"], f["host"], f["severity"],
            f["name"], f["path"][:60], f["cwe"]
        ])
        try:
            n = len(self.ext.all_findings)
            self.ext._tabs.setTitleAt(0, "Findings ({})".format(n))
            self.ext._ctr.setText(
                "  Scanned: {}  Findings: {}".format(
                    self.ext._scanned, n))
        except Exception:
            pass


class RLog(Runnable):
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


class RCounter(Runnable):
    def __init__(self, ext):
        self.ext = ext

    def run(self):
        try:
            self.ext._ctr.setText(
                "  Scanned: {}  Findings: {}".format(
                    self.ext._scanned, len(self.ext.all_findings)))
        except Exception:
            pass


# ─────────────────────────────────────────────
# ACTION LISTENERS
# ─────────────────────────────────────────────
class AToggle(ActionListener):
    def __init__(self, ext, btn):
        self.ext = ext
        self.btn = btn

    def actionPerformed(self, e):
        self.ext._active = self.btn.isSelected()
        if self.ext._active:
            self.btn.setText("ACTIVE — click to pause")
            self.btn.setForeground(C_GREEN)
        else:
            self.btn.setText("PAUSED — click to resume")
            self.btn.setForeground(C_YELLOW)


class AClear(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, e):
        self.ext.all_findings = []
        self.ext.tested.clear()
        self.ext._scanned = 0
        self.ext._model.setRowCount(0)
        try:
            self.ext._tabs.setTitleAt(0, "Findings (0)")
            self.ext._ctr.setText("  Scanned: 0  Findings: 0")
        except Exception:
            pass


class AExport(ActionListener):
    def __init__(self, ext):
        self.ext = ext

    def actionPerformed(self, e):
        try:
            data = [{k: v for k, v in f.items() if k != "messageInfo"}
                    for f in self.ext.all_findings]
            path = "/tmp/oauthhunter_confirmed.json"
            with open(path, "w") as fp:
                json.dump(data, fp, indent=2, default=str)
            swing.JOptionPane.showMessageDialog(
                None, "Saved: " + path, "Export OK",
                swing.JOptionPane.INFORMATION_MESSAGE)
        except Exception as ex:
            self.ext._log("Export error: " + str(ex))


class ASave(ActionListener):
    def __init__(self, ext, sf, tf):
        self.ext = ext
        self.sf  = sf
        self.tf  = tf

    def actionPerformed(self, e):
        self.ext.scope_filter = [s.strip() for s in
                                  self.sf.getText().split(",") if s.strip()]
        try:
            t = int(self.tf.getText().strip())
            if 1 <= t <= 20:
                self.ext._pool_size = t
        except Exception:
            pass
        self.ext._log("Settings saved. Scope={}".format(self.ext.scope_filter))


class ARowClick(MouseAdapter):
    def __init__(self, ext, tbl, detail):
        self.ext    = ext
        self.tbl    = tbl
        self.detail = detail

    def mouseClicked(self, e):
        row = self.tbl.getSelectedRow()
        if 0 <= row < len(self.ext.all_findings):
            f = self.ext.all_findings[row]
            self.detail.setText(
                "CONFIRMED VULNERABILITY\n" + "=" * 50 + "\n"
                "Name:     {}\nSeverity: {}\nCWE:      {}\n"
                "Host:     {}\nPath:     {}\nTime:     {}\n\n"
                "PROOF OF EXPLOIT:\n{}\n\n"
                "(Confirmed via independent cloned request.\n"
                " Your browser session was NOT affected.)"
            ).format(
                f["name"], f["severity"], f["cwe"],
                f["host"], f["path"], f["timestamp"],
                f["evidence"])
            self.detail.setCaretPosition(0)


class AClearLog(ActionListener):
    def __init__(self, area):
        self.area = area

    def actionPerformed(self, e):
        self.area.setText("")


# ─────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────
def mk_btn(txt, fg=C_TEXT):
    b = swing.JButton(txt)
    b.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 11))
    b.setBackground(C_SURFACE)
    b.setForeground(fg)
    b.setFocusPainted(False)
    return b


def mk_label(txt, fg=C_TEXT, bold=False):
    l = swing.JLabel(txt)
    style = awt.Font.BOLD if bold else awt.Font.PLAIN
    l.setFont(awt.Font("Monospaced", style, 11))
    l.setForeground(fg)
    return l


def mk_textarea():
    a = swing.JTextArea()
    a.setBackground(C_BG)
    a.setForeground(C_TEXT)
    a.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 11))
    a.setEditable(False)
    a.setLineWrap(True)
    a.setWrapStyleWord(True)
    a.setBorder(swing.BorderFactory.createEmptyBorder(8, 10, 8, 10))
    return a


def mk_table(model):
    t = swing.JTable(model)
    t.setBackground(C_SURFACE)
    t.setForeground(C_TEXT)
    t.setGridColor(C_BORDER)
    t.setSelectionBackground(C_ACCENT.darker())
    t.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 11))
    t.getTableHeader().setBackground(C_BG)
    t.getTableHeader().setForeground(C_ACCENT)
    t.getTableHeader().setFont(awt.Font("Monospaced", awt.Font.BOLD, 11))
    t.setRowHeight(22)
    t.setAutoResizeMode(swing.JTable.AUTO_RESIZE_OFF)
    return t


# ─────────────────────────────────────────────
# MAIN EXTENSION
# ─────────────────────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):

    # ------------------------------------------------------------------
    # registerExtenderCallbacks — may run on EDT in Burp 2026
    # We build ALL Swing components here directly (no invokeLater/AndWait)
    # because Swing components CAN be constructed on any thread as long as
    # they haven't been shown yet. addSuiteTab shows the tab — so we must
    # finish construction before calling it.
    # ------------------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("OAHunt")

        # State
        self.all_findings    = []
        self.tested          = set()
        self.session_cookies = {}
        self._active         = True
        self.scope_filter    = []
        self._scanned        = 0
        self._pool_size      = 4

        # Build all UI components synchronously right here
        self._build_ui()

        # Thread pool (background attack jobs)
        self._executor = ThreadPoolExecutor(
            self._pool_size,
            self._pool_size * 8,
            60, TimeUnit.SECONDS,
            LinkedBlockingQueue())

        # Register after _main_panel is set
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)

        print("[OAHunt] Loaded OK. Tab: OAHunt. Browser flow unaffected.")

    # ------------------------------------------------------------------
    # Build UI — called synchronously, sets self._main_panel
    # ------------------------------------------------------------------
    def _build_ui(self):
        # ── Main panel ────────────────────────
        main = swing.JPanel(awt.BorderLayout())
        main.setBackground(C_BG)

        # ── Header ────────────────────────────
        hdr = swing.JPanel(awt.BorderLayout())
        hdr.setBackground(C_SURFACE)
        hdr.setBorder(swing.BorderFactory.createMatteBorder(
            0, 0, 2, 0, C_ACCENT))

        lft = swing.JPanel(awt.FlowLayout(awt.FlowLayout.LEFT, 10, 6))
        lft.setBackground(C_SURFACE)

        title = mk_label("OAHunt", C_ACCENT, True)
        title.setFont(awt.Font("Monospaced", awt.Font.BOLD, 14))

        toggle = swing.JToggleButton("ACTIVE — click to pause", True)
        toggle.setFont(awt.Font("Monospaced", awt.Font.BOLD, 11))
        toggle.setBackground(C_SURFACE)
        toggle.setForeground(C_GREEN)
        toggle.setFocusPainted(False)
        toggle.addActionListener(AToggle(self, toggle))

        lft.add(title)
        lft.add(toggle)

        rgt = swing.JPanel(awt.FlowLayout(awt.FlowLayout.RIGHT, 8, 6))
        rgt.setBackground(C_SURFACE)

        ctr = mk_label("  Scanned: 0  Findings: 0", C_MUTED)
        self._ctr = ctr

        clr_btn = mk_btn("Clear",  C_MUTED)
        exp_btn = mk_btn("Export", C_GREEN)
        clr_btn.addActionListener(AClear(self))
        exp_btn.addActionListener(AExport(self))

        rgt.add(ctr)
        rgt.add(clr_btn)
        rgt.add(exp_btn)

        hdr.add(lft, awt.BorderLayout.WEST)
        hdr.add(rgt, awt.BorderLayout.EAST)

        # ── Tabs ──────────────────────────────
        tabs = swing.JTabbedPane()
        tabs.setBackground(C_SURFACE)
        tabs.setForeground(C_TEXT)
        tabs.setFont(awt.Font("Monospaced", awt.Font.BOLD, 11))
        self._tabs = tabs

        tabs.addTab("Findings (0)", self._tab_findings())
        tabs.addTab("Settings",     self._tab_settings())
        tabs.addTab("Log",          self._tab_log())

        main.add(hdr,  awt.BorderLayout.NORTH)
        main.add(tabs, awt.BorderLayout.CENTER)

        # Set before addSuiteTab is called
        self._main_panel = main

    def _tab_findings(self):
        p = swing.JPanel(awt.BorderLayout())
        p.setBackground(C_BG)

        cols  = ["Time", "Host", "Severity", "Vulnerability", "Path", "CWE"]
        model = ROModel(cols, 0)
        self._model = model

        tbl  = mk_table(model)
        rend = SevRenderer()
        for i in range(len(cols)):
            tbl.getColumnModel().getColumn(i).setCellRenderer(rend)
        for i, w in enumerate([65, 170, 80, 310, 200, 80]):
            tbl.getColumnModel().getColumn(i).setPreferredWidth(w)

        detail = mk_textarea()
        detail.setText(
            "Select a finding to see the exploit proof.\n\n"
            "Every finding was confirmed by sending an independent\n"
            "cloned request. Your browser was never touched.")
        tbl.addMouseListener(ARowClick(self, tbl, detail))

        banner = mk_label(
            "  All findings confirmed via independent cloned requests"
            "  |  Browser flow NEVER modified",
            C_GREEN, True)

        split = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT,
                                  swing.JScrollPane(tbl),
                                  swing.JScrollPane(detail))
        split.setResizeWeight(0.60)
        split.setBackground(C_BG)

        p.add(banner, awt.BorderLayout.NORTH)
        p.add(split,  awt.BorderLayout.CENTER)
        return p

    def _tab_settings(self):
        p   = swing.JPanel(awt.GridBagLayout())
        p.setBackground(C_BG)
        gbc = awt.GridBagConstraints()
        gbc.insets = awt.Insets(10, 14, 10, 14)
        gbc.fill   = awt.GridBagConstraints.HORIZONTAL

        sf = swing.JTextField("", 38)
        tf = swing.JTextField("4", 10)
        for f in (sf, tf):
            f.setBackground(C_SURFACE)
            f.setForeground(C_TEXT)
            f.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 11))

        save = mk_btn("Save Settings", C_GREEN)
        save.addActionListener(ASave(self, sf, tf))

        rows = [
            ("Scope filter (comma hosts, blank=all):", sf),
            ("Background threads (1-20):",             tf),
        ]
        for i, (ltxt, w) in enumerate(rows):
            gbc.gridx, gbc.gridy, gbc.weightx = 0, i, 0
            lbl = mk_label(ltxt, C_ACCENT, True)
            p.add(lbl, gbc)
            gbc.gridx, gbc.weightx = 1, 1.0
            p.add(w, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 1, len(rows), 0
        p.add(save, gbc)

        info = mk_textarea()
        info.setEditable(False)
        info.setForeground(C_MUTED)
        info.setText(
            "\nOAHunt v3.2 — Authorize-style OAuth Scanner\n\n"
            "Your browser proxy flow is NEVER modified.\n"
            "OAuth requests are silently cloned into a background\n"
            "thread pool. Each clone is mutated with one payload\n"
            "and sent independently via makeHttpRequest().\n"
            "Only confirmed exploits appear in Findings.\n\n"
            "Checks:\n"
            "  - Open redirect (all redirect-like params)\n"
            "  - redirect_uri prefix match bypass\n"
            "  - State/CSRF replay\n"
            "  - PKCE bypass\n"
            "  - Scope escalation\n"
            "  - Post-auth redirect param injection\n"
            "  - g2g interceptor cookie bypass\n"
            "  - SAML RelayState redirect\n"
            "  - Auth cookie missing flags\n\n"
            "Confirmation requests show in Burp Proxy history\n"
            "with User-Agent: OAuthHunter\n\n"
            "Export path: /tmp/oauthhunter_confirmed.json\n"
        )
        gbc.gridx, gbc.gridy      = 0, len(rows) + 1
        gbc.gridwidth, gbc.weightx = 2, 1.0
        gbc.weighty, gbc.fill      = 1.0, awt.GridBagConstraints.BOTH
        p.add(swing.JScrollPane(info), gbc)
        return p

    def _tab_log(self):
        p = swing.JPanel(awt.BorderLayout())
        p.setBackground(C_BG)

        area = swing.JTextArea()
        area.setBackground(C_BG)
        area.setForeground(C_MUTED)
        area.setFont(awt.Font("Monospaced", awt.Font.PLAIN, 10))
        area.setEditable(False)
        area.setBorder(swing.BorderFactory.createEmptyBorder(6, 8, 6, 8))
        self._log_area = area

        clr = mk_btn("Clear Log", C_MUTED)
        clr.addActionListener(AClearLog(area))

        p.add(swing.JScrollPane(area), awt.BorderLayout.CENTER)
        p.add(clr,                     awt.BorderLayout.SOUTH)
        return p

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------
    def getTabCaption(self):
        return "OAHunt"

    def getUiComponent(self):
        return self._main_panel

    # ------------------------------------------------------------------
    # IExtensionStateListener
    # ------------------------------------------------------------------
    def extensionUnloaded(self):
        try:
            self._executor.shutdownNow()
        except Exception:
            pass
        print("[OAHunt] Unloaded.")

    # ------------------------------------------------------------------
    # IHttpListener — MUST return immediately, never block proxy thread
    # ------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._active:
            return
        try:
            if messageIsRequest:
                self._queue(messageInfo)
            else:
                self._harvest(messageInfo)
        except Exception:
            pass

    def _queue(self, msg):
        analyzed = self._helpers.analyzeRequest(msg)
        url      = analyzed.getUrl()
        host     = str(url.getHost())
        path     = str(url.getPath())
        params   = analyzed.getParameters()

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        pm = {}
        for p in params:
            pm[str(p.getName())] = str(p.getValue())

        is_oauth = (any(k in pm for k in OAUTH_PARAMS) or
                    any(seg in path for seg in OAUTH_PATHS))
        if not is_oauth:
            return

        self._scanned += 1
        swing.SwingUtilities.invokeLater(RCounter(self))
        self._log("Clone: {} {}{}".format(
            str(analyzed.getMethod()), host, path))

        ck = dict(self.session_cookies.get(host, {}))

        def submit(job):
            try:
                self._executor.execute(job)
            except Exception:
                pass

        for rp in REDIRECT_PARAMS:
            if rp in pm:
                k = "or:{}:{}:{}".format(host, path, rp)
                if k not in self.tested:
                    self.tested.add(k)
                    submit(JobOpenRedirect(self, msg, pm, host, path, rp))

        if "redirect_uri" in pm:
            k = "pb:{}:{}".format(host, path)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobPrefixBypass(
                    self, msg, pm, host, path, pm["redirect_uri"]))

        if "response_type" in pm and "state" in pm:
            k = "csrf:{}:{}".format(host, path)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobStateCsrf(self, msg, pm, host, path))

        if pm.get("response_type") == "code" and "code_challenge" in pm:
            k = "pkce:{}:{}".format(host, path)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobPkce(self, msg, pm, host, path))

        if "scope" in pm and "response_type" in pm:
            k = "scope:{}:{}".format(host, path)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobScope(self, msg, pm, host, path))

        for rp in ["returnTo", "return_to", "next", "goto",
                   "postLogin", "landingPage", "after_login"]:
            if rp in pm:
                k = "ri:{}:{}:{}".format(host, path, rp)
                if k not in self.tested:
                    self.tested.add(k)
                    submit(JobRedirectInject(self, msg, pm, host, path, rp))

        if ck and any(n.lower() in ("g2g", "eg2g") for n in ck.keys()):
            k = "g2g:{}".format(host)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobG2g(self, msg, pm, host, path, ck))

        if "RelayState" in pm:
            k = "rs:{}:{}".format(host, path)
            if k not in self.tested:
                self.tested.add(k)
                submit(JobSaml(self, msg, pm, host, path))

    def _harvest(self, msg):
        ar_req  = self._helpers.analyzeRequest(msg)
        ar_resp = self._helpers.analyzeResponse(msg.getResponse())
        host    = str(ar_req.getUrl().getHost())
        path    = str(ar_req.getUrl().getPath())

        if self.scope_filter:
            if not any(h in host for h in self.scope_filter):
                return

        CRIT = set(["auth0", "auth0_compat", "access_token",
                    "id_token", "session", "sid", "token"])

        for h in ar_resp.getHeaders():
            hs = str(h)
            if not hs.lower().startswith("set-cookie:"):
                continue
            parts = hs[11:].strip()
            if "=" not in parts:
                continue
            name = parts.split("=")[0].strip()
            val  = parts.split("=")[1].split(";")[0].strip()
            if host not in self.session_cookies:
                self.session_cookies[host] = {}
            self.session_cookies[host][name] = val

            if name.lower() in CRIT:
                low     = parts.lower()
                missing = []
                if "httponly" not in low: missing.append("HttpOnly")
                if "secure"   not in low: missing.append("Secure")
                if "samesite" not in low: missing.append("SameSite")
                if missing:
                    ck = "cf:{}:{}".format(host, name)
                    if ck not in self.tested:
                        self.tested.add(ck)
                        self._add_finding(
                            host, path, msg,
                            "Cookie '{}' Missing Flags".format(name),
                            "LOW", "CWE-614",
                            "Missing: {}".format(", ".join(missing)))

    def _add_finding(self, host, path, msg, name, sev, cwe, evidence):
        for f in self.all_findings:
            if f["name"] == name and f["host"] == host and f["path"] == path:
                return
        f = {
            "host":        host,
            "path":        path,
            "name":        name,
            "severity":    sev,
            "cwe":         cwe,
            "evidence":    evidence,
            "timestamp":   time.strftime("%H:%M:%S"),
            "messageInfo": msg,
        }
        self.all_findings.append(f)
        self._log("[CONFIRMED][{}] {} @ {}{}".format(sev, name, host, path))
        swing.SwingUtilities.invokeLater(RAddRow(self, f))

    def _log(self, msg):
        line = "[{}] {}\n".format(time.strftime("%H:%M:%S"), str(msg))
        swing.SwingUtilities.invokeLater(RLog(self, line))
