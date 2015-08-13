/*
Copyright (c) 2009-2010 C-DAC
All Rights Reserved

Developed by:
        C-DAC Hyderabad
    
Project:
        Browser JSGuard

Module Name:
        main.js
*********** Module for loading various scripts by using SDK libraries ********/



/**************************************************************************
 **Loading SDK libraries, To get functionalities like executing scripts, **
 **tab information, adding widget, panel, storage**************************
 *************************************************************************/
var data = require("sdk/self").data;
var tabs = require("sdk/tabs");
const { version } = require('sdk/system/xul-app');
var { ToggleButton } = require('sdk/ui/button/toggle');
var Request = require("sdk/request").Request;
var ss = require("sdk/simple-storage");

ss.storage.bl = ""; 

// Release Notes for new installation or upgrade
exports.main = function (options) {
    if (options.loadReason == 'install' || options.loadReason == 'upgrade') {
	require("sdk/timers").setTimeout(function() {
            let _ = require("sdk/l10n").get;
            tabs.open(data.url(_('release-notes.html')));
	}, 2000);
    }
};


var blstatus="",blstatusN="",blstatusNUA="",blstatusND="", host="";
var proto="",header="",msg1 = "",msg2="",msg3="",msg4="",msg5="";
var msg6="",msg7="",msg8="",msg9="",msg10="",encode1="";


//initializing Reporting panel  
var paraPanel = require("sdk/panel").Panel({
  width: 300,
  height: 530,
  contentURL: data.url("text-entry.html")
});

/************************************************************************
 *Executing dyn.js script(with inline css and few other scripts like,**** 
 *jquery, jquery-alert) on "start" state of webpage load****************/

require("sdk/page-mod").PageMod({
  include: "*",
  contentScriptWhen: 'start',
  contentStyle: "#cdac_content.confirm { background:16px 16px no-repeat url(" + data.url("my-pic.png") + ") !important}" ,
  contentScriptFile: [data.url("jquery.js"),data.url("alert-main.js"),data.url("dyn.js")],
  onAttach: function (worker) {
    //Passing storage variable to content scripts
    worker.port.emit("storage",ss.storage.bl);
    
    /* Filling storage with current malicious URL
     * If user whitelists(ignore option is choosen) any malicious URL, 
     * URL will be stored in the storage variable until browser restarts. 
     */
    worker.port.on("temp1", function(ms) {
        ss.storage.bl+=ms;
    });
     
   
    /*GSB cross verification of iframe source for maliciousness through 
     * HTTP POST Request using SDK APIs 
     */ 
    worker.port.on("gsbifrD", function(susp) {  
        blstatusND=""; 
        Request({
            url: "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAbGCfKCqsDWjnYMB6oR6BMBQhaseUGRYAz3ND9sVr3rLu2W0mhQ&appver=1.5.2&pver=3.0",
            content: susp,
            onComplete: function (response) {
                blstatusND=response.text;
                worker.port.emit("gsbifrstatD",blstatusND);
            }
        }).post();
    });
     
    /*Recieving the Status of Panel tabs from Content Script*/
    worker.port.on("para", function(ms7,ms8,ms9,ms10) { // DYN: iframe, script, docw, encode status
        msg7= ms7;msg8= ms8;msg9= ms9;msg10= ms10;
    });
    
  }
})


//Running tag.js script on "ready" state while the Webpage is rendering
require("sdk/page-mod").PageMod({
    include: "*",
    contentScriptWhen: 'ready',
    contentStyleFile: data.url("alert-style.css"),
    contentStyle: "#cdac_content.confirm { background:16px 16px no-repeat url(" + data.url("my-pic.png") + ") !important}" ,
    contentScriptFile: [data.url("jquery.js"),data.url("alert-main.js"),data.url("trackers.js"),data.url("tag.js")],
    onAttach: function (worker) {
        worker.port.emit("storage",ss.storage.bl);
        worker.port.on("temp", function(ms) {
            ss.storage.bl+=ms;   
        });
        //cross verifying iframe source for maliciousness with GSB
        worker.port.on("gsbifr", function(susp) { 
            blstatusN=""; 
            Request({
                url: "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAbGCfKCqsDWjnYMB6oR6BMBQhaseUGRYAz3ND9sVr3rLu2W0mhQ&appver=1.5.2&pver=3.0",
                content: susp,
                onComplete: function (response) {
                    blstatusN=response.text;
                    //Sending the iframe related GSB status to Content Scripts
                    worker.port.emit("gsbifrstat",blstatusN); 
                }
            }).post();
        });

         /*GSB Cross verification of all external sources for maliciousness
          * through HTTP POST request
          */
        worker.port.on("gsbUA", function(susp) {
            blstatusNUA=""; 
            Request({
                url: "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAAJSULs6tpjXDMF0K14oOm4RQ9qooyV2W4Bg-UPkm1JcA2CKNLrg&appver=1.5.2&pver=3.0",
                content: susp,
                onComplete: function (response) {
                    blstatusNUA=response.text;
                    worker.port.emit("gsbUAstat",blstatusNUA);
                }
            }).post();
        });

        /*Recieving the Status of Panel tabs from Content Script*/
        worker.port.on("para1", function(ms0,ms1,ms2,ms3,ms4,ms5,ms6,ms7) {
            //tag:if,sc,encoded,meta,Ext,tracker,encode status
            host=ms0;msg1= ms1;msg2= ms2;msg3= ms3;msg4= ms4;msg5= ms5;msg6= ms6;encode1=ms7;
        });
    }
})

/*Adding Browser JSGuard widget to add-on bar and send content to panel tabs 
 * whenever the widget is clicked 
 */
if (version < 29)
require("sdk/widget").Widget({
    id: "ff",
    label: "Click To See Webpage Details after loading a webpage",
    contentURL: data.url("my-pic.png"),
    panel: paraPanel,
    onClick: function() {
  	var x=[];
  	x.push(blstatus);
  	x.push(host);
  	x.push(header);
  	x.push(msg1);
  	x.push(msg2);
  	x.push(msg3);
  	x.push(msg4);
  	x.push(msg5);
  	x.push(msg6);
  	x.push(msg7);
  	x.push(msg8);
  	x.push(msg9);
  	x.push(msg10);
  	x.push(encode1);
        //Sending current tab URL, recently loaded URL and its Analysis Report
 	paraPanel.port.emit("curTabMsg",{'curTab': tabs.activeTab.url, 'host': host,'details': x}); 
  
    }
});

else
var button = ToggleButton({
  id: "ff",
  label: "Click To See Webpage Details after loading a webpage",
  icon: "./my-pic.png",
  onClick: function() {
	var x=[];
  	x.push(blstatus);
  	x.push(host);
  	x.push(header);
  	x.push(msg1);
  	x.push(msg2);
  	x.push(msg3);
  	x.push(msg4);
  	x.push(msg5);
  	x.push(msg6);
  	x.push(msg7);
  	x.push(msg8);
  	x.push(msg9);
  	x.push(msg10);
  	x.push(encode1);
 
 	paraPanel.port.emit("curTabMsg",{'curTab': tabs.activeTab.url, 'host': host,'details': x});
  
	paraPanel.show({
      position: button
    }); 
 }

});
