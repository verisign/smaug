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

Components.utils.import("resource://gre/modules/FileUtils.jsm");
Components.utils.import("resource://gre/modules/NetUtil.jsm");
/* import js-ctypes */
Components.utils.import("resource://gre/modules/ctypes.jsm");

function getMessageBody(aMessageHeader) {

    let messenger = Components.classes["@mozilla.org/messenger;1"].createInstance(Components.interfaces.nsIMessenger);
    let listener = Components.classes["@mozilla.org/network/sync-stream-listener;1"].createInstance(Components.interfaces.nsISyncStreamListener);
    let uri = aMessageHeader.folder.getUriForMsg(aMessageHeader);

    messenger.messageServiceFromURI(uri).streamMessage(uri, listener, null, null, false, "");
    
    let folder = aMessageHeader.folder;
    
    return folder.getMsgTextFromStream(listener.inputStream,
                                       aMessageHeader.Charset,
                                       65536,
                                       32768,
                                       false,
                                       true,
                                       { });
}

function writeTmpFile(dataBuffer) {
    // https://developer.mozilla.org/en-US/docs/Mozilla/JavaScript_code_modules/FileUtils.jsm
    var tmpFile = FileUtils.getFile( "TmpD", [ "tbrd-dane", "tbrd-dane.tmp"], true);
    tmpFile.createUnique(Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 0600);

    var foStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);

    // // use 0x02 | 0x10 to open file for appending.
    foStream.init(tmpFile, 0x02 | 0x08 | 0x20, 0600, 0); 
    // // write, create, truncate

    // // if you are sure there will never ever be any non-ascii text in data you can 
    // // also call foStream.write(data, data.length) directly
    var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"].createInstance(Components.interfaces.nsIConverterOutputStream);
    converter.init(foStream, "UTF-8", 0, 0);
    converter.writeString(dataBuffer);
    // this closes foStream
    converter.close(); 
    return tmpFile;
}

function getKeyFromFile(keyFileName) {

    if ( keyFileName === undefined ) {
        keyFileName = "cert.pem";
    }
    var keyFileName1 = "~/Library/Thunderbird/certs/" + keyFileName;
    var keyFile = new FileUtils.File(keyFileName1);
    if (!keyFile.exists()) {
        keyFileName1 = "~/.thunderbird/certs/" + keyFileName;
    }

    // alert ("keyFileName [" + keyFileName + "]");
    var keyFile = new FileUtils.File(keyFileName1);
    if (keyFile.exists()){
	// now load file
	// alert("Loading key file");

	var data = "";
	var fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].
	    createInstance(Components.interfaces.nsIFileInputStream);
	var cstream = Components.classes["@mozilla.org/intl/converter-input-stream;1"].
	    createInstance(Components.interfaces.nsIConverterInputStream);
	fstream.init(keyFile, -1, 0, 0);
	cstream.init(fstream, "UTF-8", 0, 0); // you can use another encoding here if you wish

	let (str = {}) {
	    let read = 0;
	    do { 
		read = cstream.readString(0xffffffff, str); // read as much as we can and put it in str.value
		data += str.value;
	    } while (read != 0);
	}
	cstream.close(); // this closes fstream

	return data;
    }
    return "";
}

function getEmailHeader() {

    var msgHdr     = gFolderDisplay.selectedMessage;
    var msgUri     = msgHdr.folder.getUriForMsg(msgHdr);
    var messenger  = Components.classes["@mozilla.org/messenger;1"].
	createInstance(Components.interfaces.nsIMessenger);
    var msgService = messenger.messageServiceFromURI(msgUri);
    var scriptableInputStream = Components.classes["@mozilla.org/scriptableinputstream;1"].
	createInstance(Components.interfaces.nsIScriptableInputStream);
    var syncStreamListener = Components.classes["@mozilla.org/network/sync-stream-listener;1"].
	createInstance(Components.interfaces.nsISyncStreamListener);

    scriptableInputStream.init(syncStreamListener);

    var messageUri = msgService.streamHeaders(msgUri, syncStreamListener, null);
    var data       = new String();
    var count      = scriptableInputStream.available();

    while (count) {
	data  = data + scriptableInputStream.read(count);
	count = scriptableInputStream.available();
    }

    scriptableInputStream.close();
    return data;
}

function getSenderEmail() {
    var sender = "";

    var headers = getEmailHeader();

    try {

	var start = headers.indexOf("\nFrom:");		
	var from  = headers.substr(start+7);
	var end   = from.indexOf("\n");

	from = from.substr(0, end);	

	var emailList = from.replace(/[^,;]*.?</g,"").replace(/>/g,"").replace(/[,; ]{1,}/g, "\n").replace(/[\n]{2,}/g, "\n").split("\n");
	sender = emailList[0];
    } catch (e) {
	alert(e);
    }
    return sender.replace(/(\r\n|\n|\r)/gm,"");
}

function fixFormatFlowed(messageBuffer) {
    // OK, from what I have read and can tell, there is an annoying
    // mail standard for "formatting" mail which just happens to 
    // affect the signing verification of a mail buffer due to adding
    // whitespace
    
    // Is format=flowed ? Must check header
    let data = getEmailHeader();
    if (data.indexOf("format=flowed") != -1) {
	// format is flowed, so let us edit

	dataBuffer = messageBuffer.replace(/ (\r\n|\n)/gm, ' ');
	dataBuffer = dataBuffer.replace(/(\r\n)/gm, '\n');
	dataBuffer = dataBuffer.replace(/[ ]+$/, '');

	// remove whitespace stuffing
	// http://tools.ietf.org/html/rfc3676#section-4.4
	dataBuffer = dataBuffer.replace(/^ /gm, '');
	dataBuffer = dataBuffer + "\n";
    }
    // writeTmpFile(dataBuffer);
    return dataBuffer;
}

var myLib = {
    // reference: http://stackoverflow.com/questions/6485312/need-a-working-example-of-firefox-ctypes-output-string-parameter
    lib: null,

    init: function() {
        //Open the library you want to call
        try {
            lib = ctypes.open("libsmaug.so.0.7.0");
        } catch (e) {
            alert(e);
            lib = ctypes.open("libsmaug.so.0.7.0");
        }

        //Declare the function you want to call
	try {
            hash_sha224 = lib.declare("hash_sha224",
				      ctypes.default_abi,
				      ctypes.char.ptr,
				      ctypes.char.ptr);

            encrypt      = lib.declare("ds_encrypt",
				       ctypes.default_abi,
				       ctypes.char.ptr,
				       ctypes.char.ptr,
				       ctypes.char.ptr);

            decrypt      = lib.declare("ds_decrypt",
				       ctypes.default_abi,
				       ctypes.char.ptr,
				       ctypes.char.ptr,
				       ctypes.char.ptr);

            sign         = lib.declare("ds_sign",
				       ctypes.default_abi,
				       ctypes.char.ptr,
				       ctypes.char.ptr,
				       ctypes.char.ptr);

            verify        = lib.declare("ds_verify",
					ctypes.default_abi,
					ctypes.int,
					ctypes.char.ptr,
					ctypes.char.ptr);
    	} catch (e) {
    	    alert(e);
    	}

    },

    hash_sha224: function(key) {
        return hash_sha224(key);
    },

    encrypt: function(emailRecipient, emailBody) {
     	return encrypt(emailRecipient, emailBody);
    },

    decrypt: function(key, emailBody) {
    	return decrypt(key, emailBody);
    },

    sign: function(key, emailBody) {
    	return sign(key, emailBody);
    },

    verify: function(cacert, emailBody) {
    	return verify(cacert, emailBody);
    },

    //need to close the library once we're finished with it
    close: function() {
        lib.close();
    }
}

// Thunderbird composition window is:
// http://mxr.mozilla.org/comm-central/source/mail/components/compose/content/addressingWidgetOverlay.js
// looks like I could use msgCompFields.to for recipient

CustomButton = {

    1: function () {
	var listbox = document.getElementById('addressingWidget');
	var listitem1 = awGetListItem(1);

	var inputField = awGetInputElement(1);
	var recipientField = inputField.value;

	if (recipientField == null) {
	    recipientField = inputField.getAttribute("value");
	}

	if (recipientField == "") {
	    alert("Recipient cannot be empty");
	    return;
	}

	var editor = GetCurrentEditor();  
	var editor_type = GetCurrentEditorType();  
	
	editor.beginTransaction();  
	editor.beginningOfDocument(); // seek to beginning  

	var emailBody;
	if( editor_type == "textmail" || editor_type == "text" ) {
	} else { 	    
	    // if ( editor_type == "htmlmail" || editor_type == ) {
	    emailBody = editor.outputToString( 'text/plain', 4);
	}

	// alert( emailBody );
	editor.endTransaction();
	
	myLib.init();

    	try {
	    var data = myLib.encrypt( recipientField, emailBody );
    	    var dataString = data.readString();
	    if ( dataString != "" ) {
		// clear out buffer
	 	editor.selectAll();
		editor.cut();
		// insert encrypted text
		editor.insertText( dataString );
		editor.endTransaction();
	    } else {
		alert("No SECURE Key information available for [" 
		      +  recipientField + "]" );
	    }
	} catch (e) {
	    alert (e);
	}
	
        myLib.close();
    },

    2: function() {
	// DECRYPT Logic no longer a button
	// SEE windowpane.js for functionality
	// VERY helpful reference
        // http://mdn.beonex.com/en/Extensions/Thunderbird/HowTos/Common_Thunderbird_Use_Cases/View_Message.html#Access_Message
        // Note: I tried using the MIME attachement functions, but the current s/mime message is encoded
        // as the message body rather than an attachment. I must search the body for indication that
        // it might be a mime encoding. looking for [Content-Type: application/x-pkcs7-mime;]

        // make sure that we have at least one private key
        // TODO: Loop through all file keys until decode works or run out of keys


        //alert("selected [" + gFolderDisplay.selectedCount + "]" );
        if (gFolderDisplay.selectedCount != 1) {
            alert("Must have 1 message selected");
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
            alert("No SMime Content Found");
            return false;
        }

        // alert( msgBody );
        // alert("preattachment syndrome: msg size [" + msgBody.length + "]");
        // alert("We have SMime message");

        try {
        var key = getKeyFromFile();
        if ( key == "") {
            alert("No Key/Certificate found");
            return;
         }
         } catch (e) {
            alert(e);
         }


         myLib.init();

         // alert("JLD_PMD: Here");
         try {
             var data = myLib.decrypt( key, msgBody );
             var dataString = data.readString();
             // alert(data);
             // alert(dataString);
// if ( dataString != "" ) {
// // clear out buffer
// editor.selectAll();
// editor.cut();
// // insert encrypted text
// editor.insertText( dataString );
// editor.endTransaction();
// } else {
// alert("No Key information available for ["
// + recipientField + "]" );
// }
} catch (e) {
alert (e);
}

        myLib.close();

/*
	var editor = GetCurrentEditor();  
	var editor_type = GetCurrentEditorType();
	alert(editor_type);
	editor.beginTransaction();  
	editor.beginningOfDocument(); // seek to beginning  

	// clear out buffer
	editor.selectAll();
	editor.cut();
	// insert encrypted text
	editor.insertText( dataString );
	editor.endTransaction();
*/
        document.getElementById("messagepane").contentDocument.body.innerHTML = dataString;

    	return; 
    },

    3: function() {
	// create message signature and append to end of email

	var editor = GetCurrentEditor();  
	var editor_type = GetCurrentEditorType();
	
	editor.beginTransaction();  
	editor.beginningOfDocument(); // seek to beginning  

	var emailBody;
	if( editor_type == "textmail" || editor_type == "text" ) {
	} else { 	    
	    // if ( editor_type == "htmlmail" || editor_type == ) {
	    emailBody = editor.outputToString( 'text/plain', 4);
	}

	editor.endTransaction();
	
	myLib.init();
	var pemFile = getKeyFromFile("smime.pem");
	try {
	    var data = myLib.sign( pemFile, emailBody );
    	    var dataString = data.readString();
	    alert(dataString);
	    if ( dataString != "" ) {
		// clear out buffer
		editor.selectAll();
		editor.cut();
		// insert encrypted text
		editor.insertText( dataString );
		editor.endTransaction();
	    } else {
		alert("Certificate Problem: Please check log");
	    }
	} catch (e) {
	    alert (e);
	}
	
        myLib.close();
    },

    4: function() {
	// create message signature and append to end of email

	try {
	    var msg = gMessageDisplay.displayedMessage;

	    if (msg == null ) {
		alert( "No Message Selected");
		return false;
	    }

	    var senderEmail = getSenderEmail();
	    // alert("sender [" + senderEmail + "]");
	    var msgBody     = getMessageBody(msg);

	} catch (e) {
	    alert(e);
	}

	// currently only supporting the embedded s/mime and NOT attachment
	if (msgBody.search("protocol=\"application/pkcs7-signature\"")==-1) {
	    alert("No Signature");
	    return false;
	}

	myLib.init();

	// fix emailBody if format == flowed
	try {
	    let data = getEmailHeader();
	    if (data.indexOf("format=flowed") != -1) {
	    	// msgBody = myLib.decodeFlowed(msgBody);
	    	msgBody = fixFormatFlowed(msgBody);
	    }
	} catch (e) {
	    alert(e);
	}
	try {
	    var data = myLib.verify( msgBody, senderEmail );
            if ( data == 1 ) {
          	alert("Valid Signature");
            } else {
          	alert("InValid Signature");
            }
	} catch (e) {
            alert (e);
	}
	
	myLib.close();
    }
}
