
Components.utils.import("resource://gre/modules/AddonManager.jsm");
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");


var smaugFuncs = {

  APPSHELL_MEDIATOR_CONTRACTID: "@mozilla.org/appshell/window-mediator;1",

/*
  openAboutWindow: function ()
  {
    openWin("about:enigmail",
                           "chrome://enigmail/content/enigmailAbout.xul",
                           "resizable,centerscreen");
  },

  openHelpWindow: function (source)
  {
    openWin("enigmail:help",
                           "chrome://enigmail/content/enigmailHelp.xul?src="+source,
                           "centerscreen,resizable");
  },
*/

  /**
   * Display the preferences dialog
   *
   * @win       - |object| holding the parent window for the dialog
   * @showBasic - |boolean| true if only the 1st page of the preferences window
   *              should be displayed / false otherwise
   * @selectTab - |string| ID of the tab element (in XUL) to display when opening
   *
   * no return value
   */
  openPrefWindow: function (win, showBasic, selectTab)
  {
    // EnigmailCommon.DEBUG_LOG("enigmailCommon.js: prefWindow\n");

    // EnigmailCommon.getService(win,true);  // true: starting preferences dialog

    win.openDialog("chrome://enigmail/content/pref-enigmail.xul",
                   "_blank", "chrome,resizable=yes",
                   {'showBasic': showBasic,
                     'clientType': 'thunderbird',
                     'selectTab': selectTab});
  },

  /**
   * Display the OpenPGP key manager window
   *
   * no return value
   */

/*
  openKeyManager: function (win)
  {
    // EnigmailCommon.getService(win);

    openWin("enigmail:KeyManager",
                           "chrome://enigmail/content/enigmailKeyManager.xul",
                           "resizable");
  },
*/

  openWin: function (winName, spec, winOptions, optList)
  {
    var windowManager = Cc[this.APPSHELL_MEDIATOR_CONTRACTID].getService(Ci.nsIWindowMediator);

    var winEnum=windowManager.getEnumerator(null);
    var recentWin=null;
    while (winEnum.hasMoreElements() && ! recentWin) {
      var thisWin = winEnum.getNext();
      if (thisWin.location.href==spec) {
        recentWin = thisWin;
      }
    }

    if (recentWin) {
      recentWin.focus();
    } else {
      var appShellSvc = Cc[this.APPSHSVC_CONTRACTID].getService(Ci.nsIAppShellService);
      var domWin = appShellSvc.hiddenDOMWindow;
      try {
        domWin.open(spec, winName,
                    "chrome,"+winOptions, optList);
      }
      catch (ex) {
        domWin = windowManager.getMostRecentWindow(null);
        domWin.open(spec,
                    winName,
                    "chrome,"+winOptions,
                    optList);
      }
    }
  },

};


