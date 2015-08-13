/*
Copyright (c) C-DAC
All Rights Reserved

Developed by:
        C-DAC Hyderabad
    
Project:
        Browser JS Guard

Module Name:
        tag.js
/*
 * Module for accesing user requested webpage and monitor for vulnerable tags 
 * & javascript injections
 */

(function () {

/* Defines that JavaScript code should be executed in "strict mode". With strict mode, you cannot use undeclared variables.*/
"use strict";   

/*plugin score */
var plugcnt = 0;

/*variables for sending log details to panel widget
 * (meta, iframe, unauth red,encoded js, ext domains respectively)
 */
var warns="",warns1="",warns2="",warns3="",Domainreport="";

/* patterns */
var patt=/www/gi, patt1=/http/gi;
var TLDS = new Array(/com/gi, /net/gi, /in/gi);

/*variables for scrptTag function*/
var scrpa="";

/*variables for imgTag function*/
var socpa="";

/*variables for iframeTag function*/
var alert2="", count=0;

/*variables for scriptTag function*/
var alert2sc="", countsc=0;

/*variables for encodeJS function*/
var alert3="",encode1="";

/*variables for UATag function*/
var alert2UA="", countUA=0;

/*other tags like object, meta, anchor and link*/
var plugs="",vulplug="",redirect1="",red1="",redirect2="",red2="";

/*Retreiving domain name from the URL*/
var hostt, host;
hostt = window.location.host;
host = hostt.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

// It holds the tags to be monitored in the incoming web page
var monitorTags = new Array("script","img","area","link","frame","form","embed","applet","meta","object","iframe");

//variables to corresponding tags
var tagsArray = new Array("scrtag", "imgsrc", "are","lin","fra","frm","emb","app","met","obje","ifr");

//attributes of corresponding tags
var attrArray = new Array("src", "src","href","href","src","action","src","codebase","content","classid","src");

for(var i = 0; i<monitorTags.length; i++) 
{
    if((document.getElementsByTagName(monitorTags[i])).length > 0)
    {
        switch(i)
        {
            case 0:scrptTag();
                break;
            case 1:imgTag();
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:findhref();
                break;
            case 10:iframeTag();
                break;

            default: warns +="no tags"+ "<br>";

        }

    }
}

/*individual functions of switch */

/* This function monitors the iframe tags in the incoming web page */
function iframeTag()
{
	var k,ifrm,widt,hgt,styl,src;
	ifrm = document.getElementsByTagName("iframe");

	/* Monitoring and checking width, height and style properties of every iframe*/ 
	for(k=0;k<ifrm.length;k++)
	{
		widt=ifrm[k].getAttribute("width");
		hgt=ifrm[k].getAttribute("height");
		styl=ifrm[k].getAttribute("style");
		src =ifrm[k].getAttribute("src");
		if(src===null || src === "/blank.html" || src === "about:blank"){
			continue;
		}
		/*if the height or width of iframe is very small, i.e, lessthan 3 */
		if(hgt < 3 && hgt !== null) {
			domainmatch(src,ifrm,k);					
		}
		if(widt < 3 && widt !== null){
			domainmatch(src,ifrm,k);		
		}

		/* if style property contains height, width or some content and if "src" present */
		if(styl){
			
			var str, d=0;
			if(styl.match(/;/)) {
				var arr_str = styl.split(";");
				while(d < arr_str.length){
					str = arr_str[d].split(":");
					if(str[0] === "height" || str[0] === "width"){ 
						var ext = str[1].substring(0, str[1].length-2);
						if(ext < 3){
							domainmatch(src,ifrm,k);
						}
					}
                    
                                        else if(str[0] === "left" || str[0] === "right" || str[0] === "top" || str[0] === "bottom"){ 
						var ext1 = str[1].substring(0, str[1].length-2);
						if(ext1 < -99){
							domainmatch(src,ifrm,k);
						}
					}
					else if(str[0] === "visibility" || str[0] === "display"){

						if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
							domainmatch(src,ifrm,k);
						}
					}
					d++;
				}
			}
			else if(styl.match(/:/))
			{
				str = styl.split(":");
				if(str[0] === "visibility" || str[0] === "display"){
					if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
						domainmatch(src,ifrm,k);
					}
				}
			}
		}
        
		/* write code to find domain in src if it iframe not hidden */
		if(src) 
		{
                    extdomain(src);
		}	
	}
}

/*
 * Cross verify the source of the hidden iframe property with the host name 
 * of the original URL and if it does not belongs to the same origin then 
 * alerts the user 
 * */

function domainmatch(src,ifrm,k)
{
	var flag=0,src1;
	src1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

	if(alert2.match(src1) === null){           
		for(var m=0;m<whitelist.length;m++)
		{
			if(src1.match(whitelist[m]) !== null){

				var n=whitelist[m].toString().length;
				redirect1+=whitelist[m].toString().substring(1,n-3)+"<br>";
				flag=1;
				return;
			}
		}
		if(flag===0 && !alert2){
			alert2 += "\n"+src1; count++;
			warns1 += "<b>HTML:Hidden Iframe</b>"+"<br>"+"<b>URL(s)::</b><br>==>" +src+"<br>";          
			//ifrm[k].setAttribute("src",null);
		}
        	else if(flag===0 && alert2 && warns1.match(src1) === null){
			alert2 += "\n"+src1;count++;
			warns1 += "<br>==>"+src+"<br>";          
			//ifrm[k].setAttribute("src",null);
		
		}
	}
	
}

/*
 * Monitoring UnAuthorized redirections through image tag
 * @returns {undefined}
 */
function imgTag()
{
    var i, k, wid, hig, len, soc, soc1, flag = -1;
    /*
     * Image formats to be monitored
     * @type Array
     */
    var format = new Array(/png/gi, /jpg/gi, /gif/gi, /bmp/gi, /jpeg/gi, /Icons/gi, /ico/gi, /amp/gi);
    var imgsrc = document.getElementsByTagName("img");
      
    len = imgsrc.length;
    for(i=0;i<len;i=i+1)
    {
        var flag1=0;
        soc = imgsrc[i].getAttribute("src");
        wid = imgsrc[i].getAttribute("width");
        hig = imgsrc[i].getAttribute("height");

        if(soc === null ){
                continue;
        }

        socpa=getFileName(soc);			
        soc1=soc.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
        var parts = soc1.split('.');
        var socc = parts.slice(-1).join('.');
        for(var m=0;m<TLDS.length;m++)
        {
                if(socc.match(TLDS[m]) !== null){
                        flag1=1;
                }
        }
        if(host.match(soc1) !== null || soc.match(host) !== null/* || flag1 === 1*/){
                continue;
        }	
        for(k=0; k<format.length; ++k)
        {
                //searching for image extensions, i.e. .jpg.........
                if(soc.match(format[k]) !== null) {
                        if(socpa) {
                                if(socpa.match(".php\\.")!==null ){
                                        domainmatchUA(soc1);

                                }
                        }

                        flag = 1;
                        break;
                }
        }if(flag !== 1) { 

                if(socpa){
                        if(socpa.match("\\.php")!==null ){
                                domainmatchUA(soc1);
                        }
                }

        }


        // If the image is hidden, hidden activity will be displayed in the panel
        if((wid < 1 && wid !== null)||(hig < 1 && hig !== null))
        {
                warns2 += "<br><b>Threat::Hidden Image::</b>"+"<br>==>"+soc+"<br>";
        }
        else {

                extdomain(soc);
        }
    }
}

/*
 * Monitoring Script tag for detecting UnAuthorized redirections and 
 * Encoded JavaScript
 * @returns {undefined}
 */
function scrptTag()
{
	var len, scr,scr1,scrr, patt2=/.js/g;
	var scrpt = document.getElementsByTagName("script");
	var totalScript = "";
        var enablewordsize=0,enableinddigiden=0;
	
    	len = scrpt.length;
	for(var i=0;i<len;i++)
	{
        	//encoded js detection        
                var scriptstring = scrpt[i].innerHTML;
		scriptstring = scriptstring.replace(/(\r\n|\n|\r)/gm,""); //convert the innerHTML to one line, easier to match
		//scriptstring=scriptstring.replace(/(\/\*([\s\S]*?)\*\/)|(\/\/(.*)$)/gm, ''); //to remove commented javascript // or /* */
		scriptstring = scriptstring.replace(/<!--[\s\S]+?-->/g,"");   //to remove commented javascript <!-- //-->
		scriptstring = scriptstring.replace(/<![CDATA[\s\S]+?]]>/g,""); // //to remove commented javascript <![CDATA //]]>               

                
                if(scriptstring.length>250){
			/*
                         * dividing the script string into lines, words and 
                         * then calculating word size
                        */

                        
			var words;
			var lines = scriptstring.split(";");                
			for(var m = 0; (lines !== null) && (m<lines.length); m++) {
				words = lines[m].split(" ");                
				for(var k = 0; (words !== null) && (k<words.length); k++) {
					if(words[k].length > 6500){
                        			enablewordsize++;
					}
				}
			}
                        
                        // pecentage of digits in each script 
			var indScriptLength = scriptstring.length;
			var indNumLength = scriptstring.replace(/\D/g, '').length;
			var inddigitdensity=((indNumLength*100)/indScriptLength);
			if(((indNumLength*100)/indScriptLength) >= 30){
            			enableinddigiden++;
			}

                        /* n-gram for individual script*/
			var specialChars = new Array (/%/g,/$/g,/</g,/>/g,/@/g,/!/g,/#/g,/^/g,/&/g,/\*/g,/\(/g,/\)/g,/_/g,/\+/g,/\[/g,/\]/g,/\{/g,/\}/g,/\?/g,/:/g,/;/g,/'/g,/"/g,/,/g,/\./g,/\//g,/~/g,/\`/g,/-/g,/=/g,/\\/g, /u/g, /x/g);
			var totalnumbersc=0, encodenumbers=0, encodedanddigitnumbers=0;
			for(var n = 0; n < specialChars.length;n++){
				if(scriptstring.match(specialChars[n])){
					totalnumbersc +=scriptstring.match(specialChars[n]).length;
					if(n==0 || n==3 || n== 4 || n == 5 || n == 7 || n==8 || n==10 || n==12 || n==18 || n==19 || n ==22 || n==23 || n==28 || n ==31 || n==32)
					{
						encodenumbers +=scriptstring.match(specialChars[n]).length;
					}
				}
			}
			encodedanddigitnumbers=(indNumLength) + (encodenumbers);
			var indspdensity=(encodedanddigitnumbers*100)/scriptstring.length;
						
			var scriptstringN = scriptstring.replace(/[^a-zA-Z]/g,'');
			var scriptstringNN = scriptstring.replace(/\</g,"&lt;");   //for <
			var scriptstringNNN = scriptstringNN.replace(/\>/g,"&gt;");   //for >
                	scriptstring = scriptstring.replace(/ /g,"");				
                           
                        /*
                         * Searching for the functions unescape and fromCharCode in the script string
                         */
			if((scriptstringN.match(/unescape/g) || scriptstringN.match(/fromCharCode/g) || (scriptstringN.indexOf(/fro/g) < scriptstringN.indexOf(/mCharCode/g) )|| (scriptstringN.indexOf(/fromChar/g) < scriptstringN.indexOf(/Code/g) ) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omCh/g) < scriptstringN.indexOf(/arCode/g) ) || (scriptstringN.indexOf(/fro/g) < scriptstringN.indexOf(/mc/g) < scriptstringN.indexOf(/harCode/g)) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omCh/g) < scriptstringN.indexOf(/arCo/g)< scriptstringN.indexOf(/de/g)) || (scriptstringN.indexOf(/fr/g) < scriptstringN.indexOf(/omC/g) < scriptstringN.indexOf(/ha/g)< scriptstringN.indexOf(/rCode/g))) && !alert3 && indspdensity > 57){
                    		alert3 += "Threat:: Encoded JavaScript Malware";
                    		warns3 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br>" +scriptstringNNN+"<br>";
                	}/*
                         * Searching for suspicious string pattenrs inside unescape function
                         */
			else if((scriptstringN.match(/unescape/g) && scriptstringN.match(/newArray/g) && scriptstring.match(/%u9090/g)) && !alert3 && indspdensity > 25){
                    		alert3 += "Threat:: Encoded JavaScript Malware";
                    		warns3 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br>" +scriptstringNNN+"<br>";
                	}/*
                         * Searching for hex code starting with var.
                         * This will be displayed in panel report
                         */                        
			else if(scriptstringN.match(/var/g)&& !encode1 && !warns3 && indspdensity > 57){
				encode1 += "<b>Threat:: Encoded JavaScript Malware</b>"+"<br>"+"<b>Malicious content is::</b><br> " +scriptstringNNN+"<br>";
			}
                }
        
		totalScript += scriptstring+" ";
        
        
		var flag1=0;    
		scr = scrpt[i].getAttribute("src");
		if(scr === null ){
			continue;
		}
		
		scr1=scr.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
		        
		var parts = scr1.split('.');
		scrr = parts.slice(-1).join('.');
		
		if(scr.match(patt2) !== null || ( scr.match(patt) !== null || scr.match(patt1) !== null)){
        	extdomain(scr);
		}
		for(var m=0;m<TLDS.length;m++)
		{
			if(scrr.match(TLDS[m]) !== null){
				flag1=1;
			}
		}
		if(host.match(scr1)!== null || scr.match(host) !== null )
		{
			continue;		
		}
		
		scrpa=getFileName(scr);
		if(scr.match(patt2) !== null){
			if(scrpa){
				if(scrpa.match("\\.js.php")!==null || scrpa.match("\\.php.js")!==null ){
					domainmatchUA(scr1);			
                		}
			}
        	}
		//checking for non js(php/asp) pattern
        	else {           		
            		if(scrpa){
                                if(scrpa.match("\\.php")!==null ){
                                    domainmatchUA(scr1);

                                }
                        }
		}
                //if .js and http
		if(scr.match(patt2) !== null || ( scr.match(patt) !== null || scr.match(patt1) !== null)){
			
			extdomain(scr);	
		}
    
	} //for loop ends
    
}
// Matches the UnAuth src property with the host name of the original URL and if it is not from same origin then alerts the user
function domainmatchUA(src)
{	
	var dots=src.match(/\./g);
	if(src === null || !dots )
		return;
    	  
	if(alert2UA.match(src) === null){          		
		if(!alert2UA){		
			alert2UA += "\n"+src; countUA++;
			warns2 += "<b>HTML:Redirector::</b>"+"<br><b>URL(s)::</b><br>==>"+src+"<br>";  			
		}
        	else if(alert2UA && warns2.match(src) === null){		
			alert2UA += "\n"+src;countUA++;
			//warns2 += "Threat:: HTML:Redirector"+"<br>"+src+"<br>";
			warns2 += "<br>==>"+src+"<br>";			
		}
	}	
}	
/*function is_valid_url(url)
{
     return url.match(/^(ht|f)tps?:\/\/[a-z0-9-\.]+\.[a-z]{2,4}\/?([^\s<>\#%"\,\{\}\\|\\\^\[\]`]+)?$/);
}*/
                        
function findhref()
{
        var conten;
	var pattmeta1=/refresh/gi, pattmeta2=/index.php?spl=/g;
	tagsArray[i] =document.getElementsByTagName(monitorTags[i]);

	var alink=tagsArray[i];
			
	for(var k=0;k<alink.length;k++)
	{
		var hr=alink[k].getAttribute(attrArray[i]);
		if(hr){ //error checking
			// display meta content
			if(i=== 8)
			{
				// code to stop meta redirection == bad idea in some cases
				/*
				var i, refAttr;
				var metaTags = document.getElementsByTagName('meta');
				for i in metaTags {
				    if( (refAttr = metaTags[i].getAttribute("http-equiv")) && (refAttr == 'refresh') ) {
					        metaTags[i].parentNode.removeChild(metaTags[i]);
    					}
				}
                                // report +="meta contains: "+hr+"\n";
				*/
				var str;
				
				var refres=alink[k].getAttribute("http-equiv");
				
				//    if meta contains refersh attribute	
				if(refres && refres.match(pattmeta1)!==null){
					//comparing content with known malicious patterns of meta content
					conten=alink[k].getAttribute("content");
					if(conten){
						if(conten.match(pattmeta2)!==null){
							warns +="meta redirected to known malicious contents<br>";	
						}
						else{
							// only url part
							str = conten.split(";");
							if(str[1] !== undefined && str[1].match(/url/gi) !== null){
								var src=str[1].replace('url=','');
								extdomain(src);
								warns+="in meta tag after "+str[0]+" seconds,it will redirect to "+src+"<br>";
								redirect2+="meta tag redirection to: "+src+"<br>";
							}
						}
					}
				}	
										
			}
                        /*
                         * Searching for the plugins inside the webpage and 
                         * detecting vulnerable plugins through object ID
                         */
			if(i===9)
			{
				plugcnt++;		
			/*	for(var m=0;m<clsidlist.length;m++)
				{						
					if(hr.match(clsidlist[m])!==null){
						warns+="vulnerable plugin<br>";
						vulplug+="Threat:vulnerable plugin invoked<br><br>";
					}
				}
			*/
			}	
                        /*
                         * Collecting all the external domains from various tags
                        */
			if(hr.match(patt) !== null || hr.match(patt1) !== null) 
			{
                		extdomain(hr);
			}
		}// if hr
	}//for
}

/*
 * This function gathers all the cross domain URLs coming through various 
 * vulnerable tags and filtering duplicate URLs and Same domain URLs
 * @param {type} src : URL is the argument
 * @returns {undefined}
 */
function extdomain(src)
{
        try{
            var src1;
    		src1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
			var dots=src1.match(/\./g);
			if((host.match(src1) === null && src1.match(host) === null) && Domainreport.match(src1)===null && dots){
				alert2sc += "\n"+src1; countsc++;
				Domainreport +="==>"+src1+"<br>";
				//isTracker(src1);
				for(var m=0;m<whitelist.length;m++)
				{
					if(src1.match(whitelist[m]) !== null){

						var n=whitelist[m].toString().length;
						var temp=whitelist[m].toString().substring(1,n-3);
						if(redirect1.match(temp) === null){
							redirect1+=whitelist[m].toString().substring(1,n-3)+"<br>";
						}					
					}
				}

				
			}
        }
        catch(e){
            
        }
}

/*
 * Retreiving the resource name from the URL
 * @param {type} path : URL including Resource name
 * @returns {unresolved} : Returns Resource Name
 */
function getFileName(path)
{
	if(path.match(/^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?((\/[\w/-]+)*\/)([\w\-\.]+[^#?\s]+)(\?([^#]*))?(#(.*))?$/i))
	{
		return path.match(/^((http[s]?|ftp):\/)?\/?([^:\/\s]+)(:([^\/]*))?((\/[\w/-]+)*\/)([\w\-\.]+[^#?\s]+)(\?([^#]*))?(#(.*))?$/i)[8];
	}
}

/*
 * Filling the default values for Reporting in Panel
 */
if(plugcnt){
	plugs +=plugcnt+" plugins loaded in this webpage<br>";
	if(vulplug){
            plugs +=vulplug+"<br>";
        }
}

/*
 * Displaying trackers and Static Redirections in Report
 */
if(redirect1){
	red1="Tracker(s) found:<br>"+redirect1;
}
if(redirect2){
	red2="Static html redirections:<br>"+redirect2;
}



$(document).ready(function(){
    /*
     * Filling the GSB Request in proper format
     * Ex: 2 URL1\nURL2
     * count is the number of URLs 
     * alert2 contains all the URLs with \n as the delimiter
     */
    
    /*
     * Filling GSB request for iframe cross verification 
     * and sending the request msg to main.js
     */
    var gsbreq=count+alert2;
    if(count){
        self.port.emit("gsbifr",gsbreq);
    }
    
    /*
     * Filling GSB request for UnAuthorized Redirection cross verification 
     * and sending the request msg to main.js
     */
    var gsbreqUA=countUA+alert2UA;
    if(countUA){
        self.port.emit("gsbUA",gsbreqUA);
    }
    
    /*
     * Filling GSB request for Cross Domain(s) cross verification 
     * and sending the request msg to main.js
     */

    /*Commented to reduce the GSB requests (only for addon published in Webstores) 
     * var gsbreqsc=countsc+alert2sc;
    if(countsc){
            self.port.emit("gsbsc",gsbreqsc);
    }*/
    
    /*
     * Finding the number of frames present in a single webpage
     */
    var frameEl = window.frameElement;
    
    /*
     * Receiving the user ignored URL(s) from the confirmation box 
     * ps is the storage variable to store all the ignored URL(s)
     */
    self.port.on("storage", function(ps) {
        /*
         * Check whether current URL is already ignored by the user or not
         */
        if(ps.match(hostt)===null){   
            /*
             * Checking for iframe, Encoded JS and Unauthorized redirections
             * alert2 : hidden iframe
             * alert3 : Encoded JS
             * alert2UA : UnAuthorized Redirections
             */
            if(alert2 || alert3 || alert2UA){
                /*
                 * Processing the Alerting mechanism on detecting hidden Iframe
                 */
                if(alert2 && frameEl === null){
                    /*
                     * Receiving blacklisted status of hidden iframe src from GSB 
                     */
                    self.port.on("gsbifrstat", function(blstatusN) {
                        if(blstatusN.match("malware") || blstatusN.match("phishing") || blstatusN.match("phishing,malware")){

			    var x1=alert2, x2=blstatusN, x3="", i;
			    var reqx=x1.split("\n");
			    var resx=x2.split("\n");
			    for(i=0;i<resx.length;i++){
			        if(resx[i].match("malware")){
				    x3+=reqx[i+1]+"\n";
			        }				
			    }
                            var s2='Threat:: HTML Hidden Iframe<br>Evil URL(s) :::<br> '+x3+"<br>";
                            $('body').html($.parseHTML(""));
                            //document.body.innerHTML = ""; //To block the rendering page and to show the blank background
                            /*
                             * Alerting the User and taking the option choosen
                             * if option is Ignore: Store the URL in the 
                             *    storage variable(ps) and reload the webpage
                             */
                            var r=jConfirm("<b>In the requested URL</b><br><br>"+hostt+"<br><br><b>A threat has been found</b><br><br>"+s2+"<br>To get more information click on widget shown in Add-on Bar<br><br>", "CDAC's Browser JSGuard Warning",function(r) {
                                if(r=== false){	
                                    self.port.emit("temp",hostt);
                                    location.reload();
                                }
                            });
                        }
                    });
                }//end of alert2

                /*
                 *  Processing the Alerting mechanism on detecting Encoded JS
                */
                if(alert3){
                    //document.body.innerHTML = "";
                    $('body').html($.parseHTML(""));
                    var r=jConfirm("<b>In the requested URL</b><br><br>"+hostt+"<br><br><b>A threat has been found</b><br><br>"+alert3+"<br><br>To get more information click on widget shown in Add-on Bar<br><br>", "CDAC's Browser JSGuard Warning",function(r) {
                        if(r=== false){	
                            self.port.emit("temp",hostt);
                            location.reload();
                        }
                    });
                }//end of alert3
                
                /*
                 * Processing the Alerting mechanism on detecting UnAuthorized Redirections
                 */
                if(alert2UA){
                    self.port.on("gsbUAstat", function(blstatusN) {
                        if(blstatusN.match("malware") || blstatusN.match("phishing") || blstatusN.match("phishing,malware")){
			
			    var x1=alert2UA, x2=blstatusN, x3="", i;
			    var reqx=x1.split("\n");
			    var resx=x2.split("\n");
			    for(i=0;i<resx.length;i++){
			        if(resx[i].match("malware")){
				    x3+=reqx[i+1]+"\n";
			        }				
			    }
                            var s2='Threat:: UNAuthorized Redirection<br>Evil URL(s) :::<br> '+x3+"<br>";
                            //document.body.innerHTML = "";
                            $('body').html($.parseHTML(""));
                            var r=jConfirm("<b>In the requested URL</b><br><br>"+hostt+"<br><br><b>A threat has been found</b><br><br>"+s2+"<br>To get more information click on widget shown in Add-on Bar<br><br>", "CDAC's Browser JSGuard Warning",function(r) {
                                if(r === false){	
                                    self.port.emit("temp",hostt);
                                    location.reload();
                                }
                            });
                        }
                    });//port

			



                }//end of alert2UA


            } // any of 3

        } //ps.match and frameEl

    });   //storage


});  //doc.ready

/*
 * Sending the webpage Report to panel for displaying
 * hostt: name of the URL
 * warns1: hidden iframe
 * warns2: UnAuthorized Redirections
 * warns3: Encoded JS
 * red2: Meta Tag Redirections
 * DomainReport: Cross domains present in the webpage
 * red1: Trackers
 * encode1: Encode JS for Hex code
 */
window.addEventListener("load", function() { 
    self.port.emit("para1",hostt,warns1,warns2,warns3,red2,Domainreport,red1,encode1);}, false); //tag:host,if,sc,encoded,meta,Ext,tracker,encode status
})();
   
