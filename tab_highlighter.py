"""
Change the colour of selected tabs in Burp Repeater. Useful when you have lots of tabs open.

History:
0.0.1: First vresion
0.1.0: Remembers tab setting when re-ordering tabs
1.0.0: Colours are stored in a new item on the Site Map (on unload) to last between restarts of Burp
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "1.0.0"

import json
import sys
import threading
import time
import traceback

from burp import IBurpExtender, IContextMenuFactory, IExtensionStateListener, IHttpService, IHttpRequestResponse

# Java imports
from javax import swing
from java.util import List, ArrayList
from java.awt import Color, Frame, Font
from urlparse import urlparse


NAME = "Repeater Tab Highlighter"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print("\n\n*** PYTHON EXCEPTION")
            print(traceback.format_exc(e))
            print("*** END\n")
            # raise
    return wrapper

class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory):

    _callbacks = None
    _helpers = None
    _repeater = None

    _tabs = {}

    _colours = None

    _running = True
    _shouldSave = False
    _lastIndex = -1

    CONFIG_URL = 'http://tabhighlighterextension.local/state'

    # Note: For some reason we have to use TabbedPane.setBackgroundAt() to set the colour,
    # but (Tab Component).getForeground() to retrieve it :shrug:

    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)

        for frame in Frame.getFrames():
            self._find_repeater(frame)
        if not self._repeater:
            print("ERROR: Unable to locate Repeater")
            return

        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)
        self._repeater.addChangeListener(self.tabChanged)
        # load saved tab colours
        self._colours = self.loadSettings()
        if self._colours:
            for idx, col in enumerate(self._colours):
                if idx > self._repeater.getTabCount()-2:
                    # some tabs must be missing
                    print("Too many entries!!!")
                    break
                if col:  # un-highlighted tabs are empty arrays
                    self._highlight_tab(None, Color(col[0], col[1], col[2]), col[3], idx=idx)

        self._tabCount = self._repeater.getTabCount()
        self._thread = threading.Thread(target=self.scheduledSave)
        self._thread.daemon = True
        self._thread.start()

    def scheduledSave(self):
        while self._running:
            time.sleep(300)
            if self._shouldSave:
                self.saveSettings()
                self._shouldSave = False

    def saveSettings(self, event=None):
        settings = []
        newTabTab = self._repeater.getTabComponentAt(self._repeater.getTabCount()-1)
        baseColor = newTabTab.getComponent(0).getForeground()
        for idx in range(self._repeater.getTabCount()-1):
            tab = self._repeater.getTabComponentAt(idx)
            tabLabel = tab.getComponent(0)
            tabColour = tabLabel.getForeground()
            if tabColour == baseColor:  # not highlighted, ignore it. This should handle theme changes
                settings.append([])
            else:
                settings.append([
                    tabColour.getRed(), tabColour.getGreen(), tabColour.getBlue(), tabLabel.getFont().getStyle()
                ])
        if not settings == self._colours:
            print("Saving colours")
            self._callbacks.addToSiteMap(ConfigStoreRequestResponse(self.CONFIG_URL, json.dumps(settings)))
            self._colours == settings

    def loadSettings(self):
        requestResponse = self._callbacks.getSiteMap(self.CONFIG_URL)
        if requestResponse and requestResponse[0].getResponse():
            print("Loading colours")
            resp = self._helpers.analyzeResponse(requestResponse[0].getResponse())
            body = self._helpers.bytesToString(requestResponse[0].getResponse()[resp.getBodyOffset():]).encode('ascii', 'ignore')
            return json.loads(body)

    @fix_exception
    def tabChanged(self, event):
        idx = self._repeater.getSelectedIndex()
        tab = self._repeater.getTabComponentAt(idx)
        tabLabel = tab.getComponent(0)
        if self._tabs.get(tab):  
            self._highlight_tab(None, *self._tabs.get(tab))
        
        if not self._tabCount == self._repeater.getTabCount():  # opened or closed a tab
            self._shouldSave = True
        elif self._lastIndex and not idx == self._lastIndex:
            self._shouldSave = True

        self._tabCount = self._repeater.getTabCount()
        self._lastIndex = idx

    def extensionUnloaded(self):
        self._repeater.removeChangeListener(self.tabChanged)
        self._running = False
        self.saveSettings()
        print("Unloaded " + NAME)

    def _find_repeater(self, container):
        if container.getComponents() and self._repeater is None:
            for c in container.getComponents():
                try:
                    if c.getTabCount > 0:
                        for x in range(c.getTabCount()):
                            if c.getTitleAt(x) == "Repeater":
                                self._repeater = c.getComponentAt(x)
                                return
                except:
                    pass
                self._find_repeater(c)

    def _createItemStyled(self, text, colour, style):
        item = swing.JMenuItem(text, actionPerformed=lambda x: self._highlight_tab(x, colour, style))
        item.setFont(item.getFont().deriveFont(style))
        return item

    def _createItem(self, name, colour):
        if colour:
            subSubMenu = swing.JMenu(name)
            subSubMenu.setForeground(colour)
            subSubMenu.add(self._createItemStyled("Normal", colour, Font.PLAIN))
            subSubMenu.add(self._createItemStyled("Bold", colour, Font.BOLD))
            subSubMenu.add(self._createItemStyled("Italic", colour, Font.ITALIC))
            return subSubMenu
        else:
            return swing.JMenuItem(name, actionPerformed=lambda x: self._highlight_tab(x, colour, Font.PLAIN))

    def createMenuItems(self, invocation):
        if not invocation.getToolFlag() == self._callbacks.TOOL_REPEATER:
            return

        menu = ArrayList()
        subMenu = swing.JMenu("Highlight Tab")
        # subMenu.setForeground(Color(255, 204, 51))  # uncomment this line if you want the menu item to be highlighted itself
        subMenu.add(self._createItem("Red", Color(255, 50, 0)))
        subMenu.add(self._createItem("Blue", Color(102, 153, 255)))
        subMenu.add(self._createItem("Green", Color(0, 204, 51)))
        subMenu.add(self._createItem("Orange", Color(255, 204, 51)))
        subMenu.add(self._createItem("Purple", Color(204, 51, 255)))
        subMenu.add(self._createItem("None", None))
        subMenu.add(swing.JSeparator())
        save = swing.JMenuItem("Save now", actionPerformed=self.saveSettings)
        save.setFont(save.getFont().deriveFont(Font.ITALIC))
        subMenu.add(save)
        menu.add(subMenu)
        return menu

    @fix_exception
    def _highlight_tab(self, event, colour, style, idx=None):
        if not idx:
            idx = self._repeater.getSelectedIndex()
        # print("Setting tab {} to {}, {}".format(self._repeater.getSelectedIndex(), colour, style))
        self._repeater.setBackgroundAt(idx, colour)
        tab = self._repeater.getTabComponentAt(idx)
        tabLabel = tab.getComponent(0)
        tabLabel.setFont(tabLabel.getFont().deriveFont(style))
        tabName = self._repeater.getTitleAt(idx)
        self._tabs[tab] = [colour, style]
        self._shouldSave = True

class ConfigStoreHttpService(IHttpService):

    def __init__(self, url):
        u = urlparse(url)
        if u.scheme in ("http", "https"):
            self._protocol = u.scheme
        else:
            raise ValueError("Invalid protocol {}".format(u.scheme))

        if not u.hostname:
            raise ValueError("Invalid host {}".format(u.hostname))
        self._host = u.hostname

        self._port = u.port if u.port else 443 if u.scheme.lower() == 'https' else 80

        if not len(u.path) > 1:
            raise ValueError("Invalid path {}".format(u.path))
        self._path = u.path

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol

    def getPath(self):
        return self._path


class ConfigStoreRequestResponse(IHttpRequestResponse):

    def __init__(self, url, value):
        self._service = ConfigStoreHttpService(url)
        self._request = (
            "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n" 
            "You can ignore this item in the site map. It was created by the Tab Highlighter extension because "
            "the Burp extensions API is missing the capability to save project-specific settings.\r\n\r\n"
            "Shamelessly stolen from the Response Clusterer extension - huge thanks! :)"
        ).format(self._service.getPath(), self._service.getHost())
        self.setValue(value)

    def setValue(self, value):
        self._response = (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + value
        )

    def getComment(self):
        return ''

    def getHighlight(self):
        return ''

    def getHttpService(self):
        return self._service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, comment):
        pass

    def setHighlight(self, color):
        pass

    def setHttpService(self, httpService):
        pass

    def setRequest(self, message):
        pass

    def setResponse(self, message):
        pass

