"""
Change the colour of selected tabs in Burp Repeater. Useful when you have lots of tabs open.

History:
0.0.1: First vresion
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "0.0.1"

import re
import sys
import traceback

from burp import IBurpExtender
from burp import IContextMenuFactory

# Java imports
from javax import swing
from java.util import List, ArrayList
from java.awt import Color, Frame, Font


NAME = "Tab Highlighter"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print("\n\n*** PYTHON EXCEPTION")
            print(e)
            print("*** END\n")
            raise
    return wrapper

class BurpExtender(IBurpExtender, IContextMenuFactory):

    _callbacks = None
    _helpers = None
    _repeater = None

    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory(self)

        for frame in Frame.getFrames():
            self._find_repeater(frame)


    def _find_repeater(self, container):
        if container.getComponents() and self._repeater is None:
            for c in container.getComponents():
                try:
                    if c.getTabCount > 0:
                        for x in range(c.getTabCount()):
                            if c.getTitleAt(x) == "Repeater":
                                # print("Got Repeater tab")
                                self._repeater = c.getComponentAt(x)
                                return
                except:
                    pass
                self._find_repeater(c)


    def _createItemStyled(self, text, colour, style):
        item = swing.JMenuItem(text, actionPerformed=lambda x: self._menu_clicked(x, colour, style))
        item.setFont(Font(item.getFont().getName(), style, item.getFont().getSize()))
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
            return swing.JMenuItem(name, actionPerformed=lambda x: self._menu_clicked(x, colour, Font.PLAIN))

    def createMenuItems(self, invocation):
        if not invocation.getToolFlag() == self._callbacks.TOOL_REPEATER:
            return

        menu = ArrayList()
        subMenu = swing.JMenu("Highlight Tab")
        subMenu.add(self._createItem("Red", Color(255,50,0)))
        subMenu.add(self._createItem("Blue", Color(0,102,255)))
        subMenu.add(self._createItem("Green", Color(0,204,51)))
        subMenu.add(self._createItem("Orange", Color(255, 204, 51)))
        subMenu.add(self._createItem("None", None))
        menu.add(subMenu)
        return menu

    @fix_exception
    def _menu_clicked(self, event, colour, style):
        self._repeater.setBackgroundAt(self._repeater.getSelectedIndex(), colour)
        tab = self._repeater.getTabComponentAt(self._repeater.getSelectedIndex())
        tabLabel = tab.getComponent(0)
        font = tabLabel.getFont()
        tabLabel.setFont(Font(font.getName(), style, font.getSize()))

