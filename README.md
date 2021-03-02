_**Update: I have a Java version of this extension in development [here](https://github.com/b4dpxl/Burp-Repeater-Tab-Highlighter-Java)**_

# Burp Repeater Tab Highlighter

This [Burp Suite](https://portswigger.net/burp) extension allows you to highlight Repeater tabs 
in different colours and fonts.

![](screens/tabs.png)

It adds a context menu to a Repeater tab to change the tab's label colour. Right-click the 
request/response body, not the tab itself!

![](screens/menu.png)

The colours are stored in a new entry on the site map, http://tabhighlighterextension.local/state. 
This is updated when the plugin unloads (either shutting down Burp or reloading the extension), or 
manually via the "Save now" menu option. It is not saved on every change to try and be more 
efficient. This may change in the future.

However, this means that if Burp crashes you might lose settings, or things might get confused if 
you've inserted (not added to the end) or moved Repeater tabs. Additionally, if you insert/move 
tabs without the extension running things might get confused. The states are just stored in an 
array by the tab position.
_
