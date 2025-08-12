# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IParameter
from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import urllib

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLMap Command Generator")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Generate SQLMap Command & Copy", actionPerformed=self.generateSqlmapCmd))
        return menuList

    def generateSqlmapCmd(self, event):
        httpRequestResponse = self._invocation.getSelectedMessages()
        if not httpRequestResponse or len(httpRequestResponse) == 0:
            return

        req_bytes = httpRequestResponse[0].getRequest()
        analyzedRequest = self._helpers.analyzeRequest(httpRequestResponse[0])
        method = analyzedRequest.getMethod()
        url = analyzedRequest.getUrl().toString()

        params = analyzedRequest.getParameters()
        headers = analyzedRequest.getHeaders()

        base_cmd = 'sqlmap -u "{}"'.format(url)

        data_params = []
        cookie_params = []
        extra_headers = []

        # Lấy các param từ body/cookie
        for p in params:
            ptype = p.getType()
            pname = p.getName()
            pvalue = p.getValue()
            if ptype == IParameter.PARAM_BODY:
                data_params.append("{}={}".format(pname, urllib.quote_plus(pvalue)))
            elif ptype == IParameter.PARAM_COOKIE:
                cookie_params.append("{}={}".format(pname, pvalue))

        # Lấy Authorization/Cookie từ headers
        for h in headers:
            h_lower = h.lower()
            if h_lower.startswith("authorization:"):
                extra_headers.append(h)
            elif h_lower.startswith("cookie:") and not cookie_params:
                # Nếu cookie chưa được lấy từ param thì lấy từ header
                cookie_value = h[len("Cookie: "):]
                base_cmd += ' --cookie="{}"'.format(cookie_value)

        if method.upper() == "POST":
            base_cmd += " --method=POST"
            if data_params:
                base_cmd += ' --data="{}"'.format('&'.join(data_params))
        else:
            if method.upper() != "GET":
                base_cmd += ' --method={}'.format(method.upper())

        if cookie_params:
            base_cmd += ' --cookie="{}"'.format('; '.join(cookie_params))

        for h in extra_headers:
            base_cmd += ' --header="{}"'.format(h)

        base_cmd += ' --batch --level=5 --risk=3 --force-ssl'

        # Copy vào clipboard
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(base_cmd), None)

        print("[SQLMap CMD] " + base_cmd)
