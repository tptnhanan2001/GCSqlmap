# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IParameter
from java.util import ArrayList
from javax.swing import JMenuItem, JOptionPane
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import urllib

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLMap Command Generator")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Generate SQLMap Command & Copy", actionPerformed=self.generateSqlmapCmd))
        return menuList

    def generateSqlmapCmd(self, event):
        from javax.swing import JOptionPane  # import ngay đầu hàm, tránh lỗi UnboundLocalError
        
        httpRequestResponse = self._invocation.getSelectedMessages()
        if not httpRequestResponse or len(httpRequestResponse) == 0:
            return
        
        req = httpRequestResponse[0].getRequest()
        analyzedRequest = self._helpers.analyzeRequest(req)
        
        method = analyzedRequest.getMethod()
        
        url = self._helpers.analyzeRequest(httpRequestResponse[0]).getUrl()
        if url is None:
            return
        url = url.toString()
        
        params = analyzedRequest.getParameters()
        
        base_cmd = 'sqlmap -u "{}"'.format(url)
        
        data_params = []
        cookie_params = []

        for p in params:
            ptype = p.getType()
            pname = p.getName()
            pvalue = p.getValue()
            if ptype == IParameter.PARAM_URL:
                pass
            elif ptype == IParameter.PARAM_BODY:
                data_params.append("{}={}".format(pname, urllib.quote_plus(pvalue)))
            elif ptype == IParameter.PARAM_COOKIE:
                cookie_params.append("{}={}".format(pname, pvalue))

        if method.upper() == "POST":
            base_cmd += " --method=POST"
            if data_params:
                base_cmd += ' --data="{}"'.format('&'.join(data_params))
        else:
            if method.upper() != "GET":
                base_cmd += ' --method={}'.format(method.upper())

        if cookie_params:
            base_cmd += ' --cookie="{}"'.format('; '.join(cookie_params))

        base_cmd += ' --batch'

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(base_cmd), None)

