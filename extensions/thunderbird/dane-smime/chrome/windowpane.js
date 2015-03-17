/* 
Copyright (c) <2014> Verisign, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights 
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

window.addEventListener("load", function load(event){
    window.removeEventListener("load", load, false); //remove listener, no longer needed
    myExtension.init();  
},false);

var myExtension = {
  init: function() {
    var messagepane = document.getElementById("messagepane"); // mail
    if(messagepane){
      messagepane.addEventListener("load", function(event) { myExtension.onPageLoad(event); }, true);
    }
  },

  onPageLoad: function(aEvent) {
    var doc = aEvent.originalTarget; 

    // doc is document that triggered "onload" event
    // do something with the loaded page.
    // doc.location is a Location object (see below for a link).
    // You can use it to make your code executed on certain pages only.

    if  (gFolderDisplay.selectedCount != 1) {
      // alert("Must have 1 message selected");
      return false;
    }

    var msg = gMessageDisplay.displayedMessage;

    if (msg == null ) {
      alert( "No Message Selected");
      return false;
    }

    let msgBody = getMessageBody(msg);
    // currently only supporting the embedded s/mime and NOT attachment
      if (msgBody.search("Content-Type: application/x-pkcs7-mime;")==-1) {
        // alert("No SMime Content Found");
        return false;
      }
/*
      try {
        var key = getKeyFromFile("~/.thunderbird/certs/cert.pem");
        if ( key == "") {
          alert("No Key/Certificate found");
          return;
        }
        // alert(key);
      } catch (e) {
        alert(e);
      }

      myLib.init();

      // alert("JLD_PMD: Here");
      try {
          var data = myLib.decrypt( key, msgBody );
          var dataString = data.readString();
          // alert(data);
          // gMessageDisplay.displayedMessage = dataString;

          //alert(dataString);
      } catch (e) {
        alert (e);
      }
  
    myLib.close();
*/
    datastring = msgBody;
    document.getElementById("messagepane").contentDocument.body.innerHTML = dataString;

    //var msgBody = document.getElementById("messagepane");
    //alert(msgBody.contentwindow);

    //if(doc.location.href.search("forum") > -1)
    //  alert("a forum page is loaded");
    
    // add event listener for page unload 
    aEvent.originalTarget.defaultView.addEventListener("unload", function(event){ myExtension.onPageUnload(event); }, true);
  },

  onPageUnload: function(aEvent) {
    // do something
  }
};
