Components.utils.import("resource://gre/modules/AddonManager.jsm");
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

var smaugCommon = {
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
     var appShellSvc =
     Cc[this.APPSHSVC_CONTRACTID].getService(Ci.nsIAppShellService);
     var domWin = appShellSvc.hiddenDOMWindow;
     try {
       domWin.open(spec, winName,
                   "chrome,"+winOptions,
                   optList);
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


