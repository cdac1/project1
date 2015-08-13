/*
Copyright (c) C-DAC
All Rights Reserved

Developed by:
        C-DAC Hyderabad
    
Project:
        MPS-II

Module Name:
        dyn.js
/*
 * Module for injecting a script into webpage to acess javascript functions & 
 * its arguments  and check for maliciousness  
 */


/*
 * Receiving the user ignored URLs for storing in temporary storage 
 * @type String|pss
 */
var ps="";
self.port.on("storage", function(pss) {
    ps=pss;
});

/*
 * To get page title
 */
var host=window.location.hostname;
var proto=location.protocol;
var host1 = host.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
var score_ifd=0,score_w=0,score_ev=0,score_sh=0,score_req=0,score=0,shellp1=[],docWrite1=[],re1=[],req1=[],reqq1=[],alertt2=[],alertt3=[];//create global arrays to store the parameters of dynamic functions

/*
 * Calling handy injection function for injecting the variables into the webpage
 * @returns {undefined}
 */
addJS_Node ("var count=0,shellp=[],docWrite=[],re=[],req=[],reqq=[],alert2=[],alert3=[],al2='';");// create local arrays

/*
 * Creating hook to document.create and document.write for obtaining the 
 * parameters of the respective methods
 * @returns {undefined}
 */
function LogDocCreateElement ()
{ 
    var host1=document.location.hostname;

    try{
        var oldDocumentCreateElement = document.createElement;   
	document.createElement = function(tagName)
	{
            var elem = oldDocumentCreateElement.apply (document, arguments); 

            if (tagName === "script"){
                getScriptAttributes (elem, tagName); //Identifying the attributes of suspicious tags
            }
            if (tagName === "iframe"){
                getScriptAttributes (elem, tagName);
            }
            if (tagName === "a"){
                getScriptAttributes (elem, tagName);
            }
            if (tagName === "link"){
                getScriptAttributes (elem, tagName);
            }
	return elem;
	}

        //Creating hook to document.write to obtain the parameters of the method
	var oldDocumentWrite = document.write; 
	document.write      = function (str) 
	{   
            var host1=document.location.hostname;     
            var elem1 = oldDocumentWrite.apply (document,arguments); 
            /*
             * Filling the content of doc.write into the docWrite array variable
             * which is already injected into the webpage
             */
            docWrite.push(str);
            if(str.length > 20){
                encodeJs(str); // verifying the existance of encoded JS
                nonPrint(str); //verifying the presence of shellcode;
            }
            
            /*
             * Checking whether any tags are created through doc.write content
             * Uses DOM parser for converting string into DOM format
             * @type DOMParser
             */
            var parser = new DOMParser();
            var div = parser.parseFromString(str, "text/html");

            //Verifying the presence of suspicious tags
            var tagifr=div.getElementsByTagName("iframe");
            var tagsc=div.getElementsByTagName("script");
            //iframe properties
            if(tagifr.length>0){
                /* ----  Retrieving the attributes of the iframe tag ---- */    
                for(var j=0;j<tagifr.length;j++)
                {

                    if(tagifr[j].src){
                        var x,y,styl,src,ext;
                        x=tagifr[j].height;        // height
                        y=tagifr[j].width;         // width
                        styl=tagifr[j].style;
                        src=tagifr[j].src;
                        if(x || y || styl)
                        {
                            if(x)
                            {
                                if(x.match(/px/gi))
                                {
                                    ext = x.substring(0, x.length-2);
                                    if(ext < 3)
                                    {
                                        domainmatch(src);
                                    }
                                }

                                else if(x<3)
                                {
                                    domainmatch(src);
                                }
                            }
                            else if(y) 
                            {
                                if(y.match(/px/gi))
                                {
                                    ext = y.substring(0, y.length-2);
                                    if(ext < 3)
                                    {
                                        domainmatch(src);	
                                    }
                                }
                                else if(y<3)
                                {
                                    domainmatch(src);
                                }
                            }
                            else if(styl)
                            {
                                var str,d=0;
                                if(String(styl).match(/;/))
                                {
                                    var arr_str = String(styl).split(";");
                                    while(d < arr_str.length){
                                        str = arr_str[d].split(":");
                                        if(str[0] === "height" || str[0] === "width"){ 
                                            var ext = str[1].substring(0, str[1].length-2);
                                            if(ext < 3){
                                                domainmatch(src);
                                            }
                                        }
                                        else if(str[0] === "left" || str[0] === "right" || str[0] === "top" || str[0] === "bottom"){ 
                                        var ext = str[1].substring(0, str[1].length-2);
                                            if(ext < -99){
                                                domainmatch(src);
                                            }
                                        }
                                        else if(str[0] === "visibility" || str[0] === "display"){
                                                if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
                                                    domainmatch(src);
                                                }
                                        }
                                        d++;
                                    }
                                }
                                else if(String(styl).match(/:/))
                                {
                                    str = String(styl).split(":");
                                    if(str[0] === "visibility" || str[0] === "display"){
                                        if(str[1].match(/hidden/gi) || str[1].match(/none/gi)){
                                                domainmatch(src);
                                        }
                                    }
                                }							

                            }

                        }

                    }

                }
            }
            /*
             * Monitoring the Script tag creating through doc.write
             */
            if(tagsc.length>0)
            {
                for(var m=0;m<tagsc.length;m++)
                {
                    if(tagsc[m].src)
                    {
                        var flag1=0,srcc1, srcc, src2, patt2=/.js/g ;
                        var TLDS = new Array(/com/gi, /net/gi, /in/gi);
                        var myvar = tagsc[m].src;
                        srcc1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

                        var parts = srcc1.split('.');
                        var srcc = parts.slice(-1).join('.');
                        for(var k=0;k<TLDS.length;k++)
                        {
                            if(srcc.match(TLDS[k]) !== null){
                                flag1=1;
                            }
                        }    
                        /*
                         * Finding Redirectors in Script tag if the domain name
                         * does not belongs to TLDS array patterns
                         */
                        if((host1.match(srcc1) === null && myvar.match(host1) === null) && tagsc[m].src.match(host1) === null && flag1 === 0 && !re.length){								
                            if(tagsc[m].src.match(patt2) !== null){
                                if(tagsc[m].src.match("\\.js.php")!==null  || tagsc[m].src.match("\\.php.js")!==null ){
                                    src2='Evil URL is ::: '+srcc1;
                                    re.push('Threat::  Malicious JS:Redirector<br>'+src2);
                                   // req.push('Threat::  Malicious JS:Redirector<br>'+src2);
                                }
                            }
                            //checking for non js(php/asp) pattern
                            else {
                                if(tagsc[m].src.match("\\.php")!==null ){
                                    src2='Evil URL is ::: '+srcc1;				
                                    re.push('Threat::  Malicious JS:Redirector<br>'+src2);
                                    //req.push('Threat::  Malicious JS:Redirector<br>'+src2);
                                }
                            }
                        }
                    }
                }
            }//if
            return elem1;      
	}
    }//try
    catch(err)
    {
        //alert("error");
    }
    
    /*
     * Detecting Encoded JavaScript in the content of the doc.write
     * @param {type} text
     * @returns {undefined}
     */
    function encodeJs(text)
    {
        var scriptstring = text.replace(/(\r\n|\n|\r)/gm,""); //convert the innerHTML to one line, easier to match               
        if(scriptstring.length>250){
         /*dividing into lines, then words, then word size*/
            var words;
            var lines = scriptstring.split(";");                
            for(var m = 0; (lines !== null) && (m<lines.length); m++) {
                words = lines[m].split(" ");                
                for(var k = 0; (words !== null) && (k<words.length); k++) {
                    if(words[k].length > 5000){
                        shellp.push("Wdyn: 1 ");
                    }			
                }
            }
            
            // pecentage of digits in each script 			
            var indScriptLength = scriptstring.length;
            var indNumLength = scriptstring.replace(/\D/g, '').length;
            var inddigitdensity=((indNumLength*100)/indScriptLength);
            if(((indNumLength*100)/indScriptLength) > 30){
                shellp.push("IDDdyn: 1 ");
            }
            
            /* n-gram for individual script*/
            var specialChars = new Array (/%/g,/$/g,/</g,/>/g,/@/g,/!/g,/#/g,/^/g,/&/g,/\*/g,/\(/g,/\)/g,/_/g,/\+/g,/\[/g,/\]/g,/\{/g,/\}/g,/\?/g,/:/g,/;/g,/'/g,/"/g,/,/g,/\./g,/\//g,/~/g,/\`/g,/-/g,/=/g,/\\/g);
            var totalnumbersc=0, encodenumbers=0, encodedanddigitnumbers=0;
            for(var n = 0; n < specialChars.length;n++){
                if(scriptstring.match(specialChars[n])){
                    totalnumbersc +=scriptstring.match(specialChars[n]).length;
                    if(n==0 || n== 4 || n == 5 || n==12 || n ==22 || n==23)
                    {
                        encodenumbers +=scriptstring.match(specialChars[n]).length;
                    }
                }
            }
            encodedanddigitnumbers=(indNumLength) + (encodenumbers);
            indspdensity=(encodedanddigitnumbers*100)/scriptstring.length;
            if(indspdensity > 50){
//                    shellp.push("ISPdyn: 1 ");
                var scriptstringN = scriptstring.replace(/[^a-zA-Z]/g,'');
                if((scriptstringN.match(/unescape/g) || scriptstringN.match(/fromCharCode/g)) && !alert3){
                    alert3.push("Threat:: Encoded JavaScript Malware</n>");
                    shellp.push("Threat:: Encoded JavaScript Malware"+"<br>"+"Malicious content is:: " +scriptstring);
                }
            }

        }
    }
    
    /*
     * Detecting Non printable characters or shellcode in the content of doc.write
     * @param {type} text
     * @returns {undefined}
     */
    function nonPrint(text)
    {
        var pat=/[^\x00-\x80]+/g;//Regex for checking non-printable characters
        if(pat.test(text))
        {
            shellp.push("Non Printable characters are present\n");
            shellp.push(text);
        }
        var r = new RegExp("^[a-f0-9]+$", 'i');//regex for identifying consecutive Hexadecimal characters in a string
        if(r.test(text))
        {
            shellp.push("consecutive block of hexadecimal characters\n");
            shellp.push(text);
        }
    }
    
    /*
     * Cross verify the source of the hidden iframe property with the host name 
     * of the original URL and if it does not belongs to the same origin then 
     * alerts the user 
     * @param {type} src
     * @returns {undefined}
     */
    function domainmatch(src)
    {
          /*  //whitelist, 3rd party advertising sites and tracking sites*/

        var whitelist = new Array (/about:blank/gi,/blank.html/gi,/wp/gi,/google/gi ,/facebook/gi ,/youtube/gi ,/quantserve/gi ,/vizury/gi , /Media/gi , /33across/gi , /AOLAdvertising/gi , /AWeber/gi , /Acerno/gi , /AcxiomRelevance-X/gi , /AdLegend/gi , /AdMeld/gi , /AdNexus/gi , /AdSafe/gi , /AdShuffle/gi , /AdTech/gi , /Adap.TV/gi , /AdaptiveBlueSmartlinks/gi , /AdaraMedia/gi , /Adblade/gi , /Adbrite/gi , /Adcentric/gi , /Adconion/gi , /AddThis/gi , /AddToAny/gi , /Adify/gi , /Adition/gi , /Adjuggler/gi , /AdnetInteractive/gi , /Adnetik/gi , /Adreactor/gi , /Adrolays/gi , /Adroll/gi , /Advertise.com/gi , /Advertising.com/gi , /Adxpose/gi , /Adzerk/gi ,/affinity/gi , /AggregateKnowledge/gi , /AlexaMetrics/gi , /AlmondNet/gi , /Aperture/gi , /BTBuckets/gi , /Baynote/gi , /Bing/gi , /Bizo/gi , /BlogRollr/gi , /Blogads/gi , /BlueKai/gi , /BlueLithium/gi , /BrandReach/gi , /BrightTag/gi , /Brightcove/gi , /Brightroll/gi , /Brilig/gi , /BurstMedia/gi , /BuySellAds/gi , /CNETTracking/gi , /CPXInteractive/gi , /CasaleMedia/gi , /CedexisRadar/gi , /CertonaResonance/gi , /Chango/gi , /ChannelAdvisor/gi , /ChartBeat/gi , /Checkm8/gi , /Chitika/gi , /ChoiceStream/gi , /ClearSaleing/gi , /ClickDensity/gi , /Clickability/gi , /Clicksor/gi , /Clicktale/gi , /Clicky/gi , /CognitiveMatch/gi , /Collarity/gi , /CollectiveMedia/gi , /Comscore Beacon/gi , /Connextra/gi , /ContextWeb/gi , /CoreMetrics/gi , /CrazyEgg/gi , /Criteo/gi , /Cross PixelMedia/gi , /CrowdScience/gi , /DC Storm/gi , /Dapper/gi , /DedicatedMedia/gi , /Demandbase/gi , /Demdex/gi , /DeveloperMedia/gi , /Didit/gi , /DiggWidget/gi , /DiggThis/gi , /Disqus/gi , /Dotomi/gi , /DoubleVerify/gi , /Doubleclick/gi , /DynamicLogic/gi , /EffectiveMeasure/gi , /Eloqua/gi , /Ensighten/gi , /EpicMarketplace/gi , /Etology/gi , /Evidon/gi , /Exponential/gi , /EyeWonder/gi , /Facebook Beacon/gi , /FacebookConnect/gi , /FederatedMedia/gi , /Feedjit/gi , /FetchBack/gi , /Flashtalking/gi , /ForeseeResults/gi , /FoxAudienceNetwork/gi , /FreeWheel/gi , /GetSatisfaction/gi , /Gigya/gi , /GlamMedia/gi , /Gomez/gi ,  /GoogleAdsense/gi , /GoogleAdwordsConversion/gi , /GoogleAnalytics/gi , /GoogleFriendConnect/gi , /GoogleWebsiteOptimizer/gi , /GoogleWidgets/gi , /Gravatar/gi , /Gravity/gi , /Hellobar/gi , /HitTail/gi , /Hurra/gi , /InfoLinks/gi , /Inkfrog/gi , /InsightExpress/gi , /InterClick/gi , /InviteMedia/gi , /Iovation/gi , /KissMetrics/gi , /KonteraContentLink/gi , /KruxDigital/gi , /LeadLander/gi , /Leadformix/gi , /Leadsius/gi , /LifeStreet Media/gi , /Lijit/gi , /LinkedIn/gi , /Linkshare/gi , /LiveInternet/gi , /LivePerson/gi , /Lotame/gi , /LucidMedia/gi , /LyrisClicktracks/gi , /MAGNETIC/gi , /MSNAds/gi , /MarinSoftware/gi , /MarketGID/gi , /Marketo/gi , /MaxPointInteractive/gi , /Maxymizer/gi , /MediaInnovationGroup/gi , /Media6Degrees/gi , /MediaMath/gi , /MediaMind/gi , /MediaPlex/gi , /Meebo/gi , /Mercent/gi , /Meteor/gi , /MicrosoftAnalytics/gi , /MicrosoftAtlas/gi , /MindsetMedia/gi , /Mint/gi , /Mixpanel/gi , /Monetate/gi , /MyBlogLog/gi , /NDN/gi , /Navegg/gi , /NetMining/gi , /NetShelter/gi , /NetratingsSiteCensus/gi , /NewRelic/gi , /NewsRight/gi , /NextAction/gi , /Nuggad/gi , /Omniture/gi , /OpenAds/gi , /OpenX/gi , /Optimizely/gi , /Optimost/gi , /OutBrain/gi , /OwnerIQ/gi , /PO.ST/gi , /Parse.ly/gi , /Piwik/gi , /PointRoll/gi , /PostRank/gi , /Pubmatic/gi , /Qualaroo/gi , /Quantcast/gi , /QuigoAdsonar/gi , /RadiumOne/gi , /RapLeaf/gi , /RealMedia/gi , /Reinvigorate/gi , /Relestar/gi , /RevenueScience/gi , /RevenueMantra/gi , /RightMedia/gi , /RocketFuel/gi , /Rubicon/gi , /RubiconProject/gi , /SafeCount/gi , /Salesforce/gi , /ShareThis/gi , /SiteMeter/gi , /SiteScout/gi , /SkimLinks/gi , /Smart Adserver/gi , /Snaps/gi , /Snoobi/gi , /Specific Meida/gi , /SpecificClick/gi , /Sphere/gi , /StatCounter/gi , /TARGUSinfoAdAdvisor/gi , /Taboola/gi , /Tacoda/gi , /TeaLeaf/gi , /Tealium/gi , /Technorati/gi , /TechnoratiMedia/gi , /Tellapart/gi , /Teracent/gi , /TestandTarget/gi , /TidalTV/gi , /TorbitInsight/gi , /TradeDoubler/gi , /TravelAdvertising/gi , /TremorVideo/gi , /TribalFusion/gi , /Tumri/gi , /Turn/gi , /TweetMeme/gi , /TwitterBadge/gi , /TyntTracer/gi , /Typekit/gi , /UnderdogMedia/gi , /UndertoneNetworks/gi , /Unica/gi , /ValueClick/gi , /ValuedOpinions/gi , /VibrantAds/gi , /VigLink/gi , /VisualSciences/gi , /VisualWebsiteOptimizer/gi , /VisualRevenue/gi , /ViziSense/gi , /Vizu/gi , /Vizury/gi ,/WebAds/gi , /Webtrends/gi , /Whos.amung.us/gi , /Wibiya/gi , /Woopra/gi , /WordpressStats/gi , /WorldNow/gi , /XGraph/gi , /Yadro/gi , /YahooBuzz/gi , /YahooWebAnalytics/gi , /YuMeNetworks/gi , /Zango/gi , /Zedo/gi , /Zemanta/gi , /e-planning/gi , /eXTReMe Tracking/gi , /eXelate/gi , /etracker/gi , /iPerception/gi, /bs.serving-sys.com/gi);
        var flag=0, src1, srcc1;	
        al2+=reqq;
        srcc1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
        if((host1.match(srcc1) === null && src.match(host1) === null) && al2.match(srcc1) ===null){
            for(var m=0;m<whitelist.length;m++)
            {
                if(srcc1.match(whitelist[m]) !== null){
                        flag=1;
                        return;
                }
            }
            if(flag===0 && !al2){
                alert2.push("\n"+srcc1);
                reqq.push("<b>JS:Hidden Iframe<br>URL(s)::</b><br>==>"+src);

            }
            else if(flag===0 && al2 && al2.match(srcc1) === null){
                alert2.push("\n"+srcc1);
                reqq.push("<br>==>"+src);	
            }
        }
    }

    shellp1=shellp;
    docWrite1=docWrite;
    re1=re;
    //req1=req;
    reqq1=reqq;
    alertt2=alert2;
    alertt3=alert3;
}


/*
 * Analyzing the content of document.createElement function
 * @param {type} elem : Properties of tags present in the contents
 * @param {type} tagName : Name of the tag present in the contents
 * @param {type} timerIntVar 
 * @returns {undefined}
 */
function getScriptAttributes (elem, tagName, timerIntVar) 
{
    var host1=document.location.hostname;     
/*--- Because the tags won't be set for some while, we need
    to poll for when they are added.
---Tracking the attributes which can redirect to malcious web page---*/
    if (elem.src && elem.src !== "/blank.html" && elem.src !=="about:blank") 
    {

        doneWaiting ();
        var flag1=0, src2, srcc1, srcc, patt2=/.js/g ;
        var TLDS = new Array(/com/gi, /net/gi, /in/gi);
        var myvar = elem.src;
        srcc1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

        var parts = srcc1.split('.');
        srcc = parts.slice(-1).join('.');
        for(var m=0;m<TLDS.length;m++)
        {
                if(srcc.match(TLDS[m]) !== null){
                        flag1=1;
                }
        }
        
        if(tagName === "iframe")
        {
            var x,y,src,ext;
            x=elem.height;        // height
            y=elem.width;         // width
            stylh=elem.style.height;      //style
            stylw=elem.style.width;
            styll=elem.style.left;      //style
            stylr=elem.style.right;
            stylt=elem.style.top;      //style
            stylb=elem.style.bottom;
            stylv=elem.style.visibility;
            styld=elem.style.display;
            src=elem.src;
            if(x || y || stylh || stylw || stylv || styld)
            {
                if(x)
                {
                        if(x.match(/px/gi))
                        {
                                var ext = x.substring(0, x.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);
                                }
                        }	                                    
                        else if(x<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(y) 
                {
                        if(y.match(/px/gi))
                        {
                                var ext = y.substring(0, y.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(y<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylh) 
                {
                        if(stylh.match(/px/gi))
                        {
                                var ext = stylh.substring(0, stylh.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(stylh<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylw) 
                {
                        if(stylw.match(/px/gi))
                        {
                                var ext = stylw.substring(0, stylw.length-2);
                                if(ext < 3)
                                {
                                        domainmatch1(src);	
                                }
                        }
                        else if(stylw<3)
                        {
                                domainmatch1(src);
                        }
                }
                if(stylv) 
                {
                        if(stylv.match(/hidden/gi))
                        {                        		
                                domainmatch1(src);	
                        }

                }
                if(styld) 
                {
                        if(styld.match(/none/gi))
                        {                        		
                                domainmatch1(src);	
                        }
                }
            }
            if(styll || stylr || stylt || stylb)
            {
                    if(styll){
                            var ext = styll.substring(0, styll.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylr){
                            var ext = stylr.substring(0, stylr.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylt){
                            var ext = stylt.substring(0, stylt.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
                    if(stylb){
                            var ext = stylb.substring(0, stylb.length-2);
                            if(ext < -99)
                            {
                                    domainmatch1(src);	
                            }
                    }
            }
        }  //iframe  
        else if(elem.src.match(host1) === null && host1.match(srcc1) === null && flag1 === 0 && !re.length){
            var myvar = elem.src;
            var s1=myvar.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];

            if(elem.src.match(patt2) !== null){

                if(elem.src.match("\\.js.php")!==null  || elem.src.match("\\.php.js")!==null ){
                    src2='Evil URL is ::: '+elem.src;
                    re.push('Threat::  Malicious JS:Redirector<br>'+src2);
                    //req.push('Threat::  Malicious JS:Redirector<br>'+src2);
                }
            }
            //checking for non js(php/asp) pattern
            else {
                if(elem.src.match("\\.php")!==null ){
                    src2='Evil URL is ::: '+s1;
                    re.push('Threat::  Malicious JS:Redirector<br>'+src2);
                    //req.push('Threat::  Malicious JS:Redirector<br>'+src2);
                }
            }
        }
    }
    else
    {
        if ( ! timerIntVar) //Setting the time interval to wait for the tags untill they are well-set
        {
            var timerIntVar = setInterval 
            (
            function () 
            {
                getScriptAttributes (elem, tagName,timerIntVar);                    
            },
            50
            );            
        }        
    }    
    function doneWaiting () //clear the time interval when the tags are set
    {
            if (timerIntVar) 
            {
                    clearInterval (timerIntVar);
            }       
    }
    function domainmatch1(src){
            //whitelist, 3rd party advertising sites and tracking sites
            var dots=src.match(/\./g);
            if(src === null || !dots){
                    return;
            }

            var whitelist = new Array (/about:blank/gi,/blank.html/gi,/wp/gi,/google/gi ,/facebook/gi ,/youtube/gi ,/quantserve/gi ,/vizury/gi , /Media/gi , /33across/gi , /AOLAdvertising/gi , /AWeber/gi , /Acerno/gi , /AcxiomRelevance-X/gi , /AdLegend/gi , /AdMeld/gi , /AdNexus/gi , /AdSafe/gi , /AdShuffle/gi , /AdTech/gi , /Adap.TV/gi , /AdaptiveBlueSmartlinks/gi , /AdaraMedia/gi , /Adblade/gi , /Adbrite/gi , /Adcentric/gi , /Adconion/gi , /AddThis/gi , /AddToAny/gi , /Adify/gi , /Adition/gi , /Adjuggler/gi , /AdnetInteractive/gi , /Adnetik/gi , /Adreactor/gi , /Adrolays/gi , /Adroll/gi , /Advertise.com/gi , /Advertising.com/gi , /Adxpose/gi , /Adzerk/gi ,/affinity/gi , /AggregateKnowledge/gi , /AlexaMetrics/gi , /AlmondNet/gi , /Aperture/gi , /BTBuckets/gi , /Baynote/gi , /Bing/gi , /Bizo/gi , /BlogRollr/gi , /Blogads/gi , /BlueKai/gi , /BlueLithium/gi , /BrandReach/gi , /BrightTag/gi , /Brightcove/gi , /Brightroll/gi , /Brilig/gi , /BurstMedia/gi , /BuySellAds/gi , /CNETTracking/gi , /CPXInteractive/gi , /CasaleMedia/gi , /CedexisRadar/gi , /CertonaResonance/gi , /Chango/gi , /ChannelAdvisor/gi , /ChartBeat/gi , /Checkm8/gi , /Chitika/gi , /ChoiceStream/gi , /ClearSaleing/gi , /ClickDensity/gi , /Clickability/gi , /Clicksor/gi , /Clicktale/gi , /Clicky/gi , /CognitiveMatch/gi , /Collarity/gi , /CollectiveMedia/gi , /Comscore Beacon/gi , /Connextra/gi , /ContextWeb/gi , /CoreMetrics/gi , /CrazyEgg/gi , /Criteo/gi , /Cross PixelMedia/gi , /CrowdScience/gi , /DC Storm/gi , /Dapper/gi , /DedicatedMedia/gi , /Demandbase/gi , /Demdex/gi , /DeveloperMedia/gi , /Didit/gi , /DiggWidget/gi , /DiggThis/gi , /Disqus/gi , /Dotomi/gi , /DoubleVerify/gi , /Doubleclick/gi , /DynamicLogic/gi , /EffectiveMeasure/gi , /Eloqua/gi , /Ensighten/gi , /EpicMarketplace/gi , /Etology/gi , /Evidon/gi , /Exponential/gi , /EyeWonder/gi , /Facebook Beacon/gi , /FacebookConnect/gi , /FederatedMedia/gi , /Feedjit/gi , /FetchBack/gi , /Flashtalking/gi , /ForeseeResults/gi , /FoxAudienceNetwork/gi , /FreeWheel/gi , /GetSatisfaction/gi , /Gigya/gi , /GlamMedia/gi , /Gomez/gi ,  /GoogleAdsense/gi , /GoogleAdwordsConversion/gi , /GoogleAnalytics/gi , /GoogleFriendConnect/gi , /GoogleWebsiteOptimizer/gi , /GoogleWidgets/gi , /Gravatar/gi , /Gravity/gi , /Hellobar/gi , /HitTail/gi , /Hurra/gi , /InfoLinks/gi , /Inkfrog/gi , /InsightExpress/gi , /InterClick/gi , /InviteMedia/gi , /Iovation/gi , /KissMetrics/gi , /KonteraContentLink/gi , /KruxDigital/gi , /LeadLander/gi , /Leadformix/gi , /Leadsius/gi , /LifeStreet Media/gi , /Lijit/gi , /LinkedIn/gi , /Linkshare/gi , /LiveInternet/gi , /LivePerson/gi , /Lotame/gi , /LucidMedia/gi , /LyrisClicktracks/gi , /MAGNETIC/gi , /MSNAds/gi , /MarinSoftware/gi , /MarketGID/gi , /Marketo/gi , /MaxPointInteractive/gi , /Maxymizer/gi , /MediaInnovationGroup/gi , /Media6Degrees/gi , /MediaMath/gi , /MediaMind/gi , /MediaPlex/gi , /Meebo/gi , /Mercent/gi , /Meteor/gi , /MicrosoftAnalytics/gi , /MicrosoftAtlas/gi , /MindsetMedia/gi , /Mint/gi , /Mixpanel/gi , /Monetate/gi , /MyBlogLog/gi , /NDN/gi , /Navegg/gi , /NetMining/gi , /NetShelter/gi , /NetratingsSiteCensus/gi , /NewRelic/gi , /NewsRight/gi , /NextAction/gi , /Nuggad/gi , /Omniture/gi , /OpenAds/gi , /OpenX/gi , /Optimizely/gi , /Optimost/gi , /OutBrain/gi , /OwnerIQ/gi , /PO.ST/gi , /Parse.ly/gi , /Piwik/gi , /PointRoll/gi , /PostRank/gi , /Pubmatic/gi , /Qualaroo/gi , /Quantcast/gi , /QuigoAdsonar/gi , /RadiumOne/gi , /RapLeaf/gi , /RealMedia/gi , /Reinvigorate/gi , /Relestar/gi , /RevenueScience/gi , /RevenueMantra/gi , /RightMedia/gi , /RocketFuel/gi , /Rubicon/gi , /RubiconProject/gi , /SafeCount/gi , /Salesforce/gi , /ShareThis/gi , /SiteMeter/gi , /SiteScout/gi , /SkimLinks/gi , /Smart Adserver/gi , /Snaps/gi , /Snoobi/gi , /Specific Meida/gi , /SpecificClick/gi , /Sphere/gi , /StatCounter/gi , /TARGUSinfoAdAdvisor/gi , /Taboola/gi , /Tacoda/gi , /TeaLeaf/gi , /Tealium/gi , /Technorati/gi , /TechnoratiMedia/gi , /Tellapart/gi , /Teracent/gi , /TestandTarget/gi , /TidalTV/gi , /TorbitInsight/gi , /TradeDoubler/gi , /TravelAdvertising/gi , /TremorVideo/gi , /TribalFusion/gi , /Tumri/gi , /Turn/gi , /TweetMeme/gi , /TwitterBadge/gi , /TyntTracer/gi , /Typekit/gi , /UnderdogMedia/gi , /UndertoneNetworks/gi , /Unica/gi , /ValueClick/gi , /ValuedOpinions/gi , /VibrantAds/gi , /VigLink/gi , /VisualSciences/gi , /VisualWebsiteOptimizer/gi , /VisualRevenue/gi , /ViziSense/gi , /Vizu/gi , /Vizury/gi ,/WebAds/gi , /Webtrends/gi , /Whos.amung.us/gi , /Wibiya/gi , /Woopra/gi , /WordpressStats/gi , /WorldNow/gi , /XGraph/gi , /Yadro/gi , /YahooBuzz/gi , /YahooWebAnalytics/gi , /YuMeNetworks/gi , /Zango/gi , /Zedo/gi , /Zemanta/gi , /e-planning/gi , /eXTReMe Tracking/gi , /eXelate/gi , /etracker/gi , /iPerception/gi, /bs.serving-sys.com/gi);
            var flag=0, srcc1;
            al2+=reqq;
            srcc1=src.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
            if((host1.match(srcc1) === null && src.match(host1) === null) && al2.match(srcc1) ===null){

                    for(var m=0;m<whitelist.length;m++)
                    {
                            if(srcc1.match(whitelist[m]) !== null){//alert("alert");
                                    flag=1;
                                    return;
                            }
                    }
                    if(flag===0 && !al2){
                            alert2.push("\n"+srcc1);
                            reqq.push("<b>JS:Hidden Iframe<br>URL(s)::</b><br>==>"+src);
                    }
                    else if(flag===0 && al2 && al2.match(srcc1) === null){
                            alert2.push("\n"+srcc1);
                            reqq.push("<br>==>"+src);	
                    }
            }
    }    
}

//---Injecting the above methods to the web page 
addJS_Node (getScriptAttributes.toString());
//---Injecting the above method to the web page
addJS_Node (null, null, LogDocCreateElement);
//--- Handy injection function.
function addJS_Node (text, s_URL, funcToRun) {
/*--- This function is for injecting the desired functionality in the web page by creating a script tag */
    var D                                   = window.document;
    var scriptNode                          = D.createElement ('script');
    scriptNode.type                         = "text/javascript";
    if (text){       scriptNode.textContent  = text;}
    if (s_URL){      scriptNode.src          = s_URL;}
    if (funcToRun)  scriptNode.textContent  = '(' + funcToRun.toString() + ')()';
    var targ = D.getElementsByTagName ('head')[0] || D.body || D.documentElement;
    targ.appendChild (scriptNode);
    targ.removeChild (scriptNode);    
}
/* when the page is loaded Send emit all the parameters to addon sciript */
window.addEventListener("load", function() {
	var i,res="",reqs="";var docW="";var reqqs="";var shellps="";var alertts="",encodes="",Head="CDAC's Browser JSGuard Warning";
	if(window.wrappedJSObject.re1.length>0)
	{
		for(i=0;i<window.wrappedJSObject.re1.length;i++)
		{
			res+=window.wrappedJSObject.re1[i]+"<br>";
	    		      
		}
		score_req=1;
	}

	/*if(window.wrappedJSObject.req1.length>0)
	{
		for(i=0;i<window.wrappedJSObject.req1.length;i++)
		{
			reqs+=window.wrappedJSObject.req1[i]+"<br>";		      
		}
		score_req=1;
	}*/

	if(window.wrappedJSObject.reqq1.length>0)
	{
		for(i=0;i<window.wrappedJSObject.reqq1.length;i++)
		{
			reqqs+=window.wrappedJSObject.reqq1[i]+"<br>";
		}
		score_ifd=1;
	}

	if(window.wrappedJSObject.alertt2.length>0)
	{
		for(i=0;i<window.wrappedJSObject.alertt2.length;i++)
		{
			//alertts+=window.wrappedJSObject.alertt2[i]+"<br>";
			alertts+=window.wrappedJSObject.alertt2[i];
		}
		score_ifd=1;
	}
	if(window.wrappedJSObject.alertt3.length>0)
	{
		for(i=0;i<window.wrappedJSObject.alertt3.length;i++)
		{
			encodes+=window.wrappedJSObject.alertt3[i]+"<br>";
		
		}
		score_ifd=1;
	}
   

	score=score_ifd+score_ev+score_sh+score_w;


var lines = alertts.split("\n");  
var noOfIframes=(lines.length)-1;
var gsbreq=noOfIframes+alertts;
if(noOfIframes){
    self.port.emit("gsbifrD",gsbreq);
}
//self.port.on("gsbstatD", function(blstatus) {
	var frameEl = window.frameElement;
	if((alertts || res  || encodes) && frameEl===null){
	        if(ps.match(host)===null){     //intially null and host diffrenet so block
			if(alertts){
				self.port.on("gsbifrstatD", function(blstatusN) {
					//if(blstatusN === "malware" || blstatusN === "phishing" || blstatusN === "phishing,malware"){
					if(blstatusN.match("malware") || blstatusN.match("phishing") || blstatusN.match("phishing,malware")){

						var x1=alertts, x2=blstatusN, x3="", i;
		  			        var reqx=x1.split("\n");
			    			var resx=x2.split("\n");
			    			for(i=0;i<resx.length;i++){
			        			if(resx[i].match("malware")){
				    				x3+=reqx[i+1]+"\n";
			        			}				
			    			}

                                                var src2='Threat:: JS Hidden Iframe<br>Evil URL(s) :::<br> '+x3+"<br>";
			    			//document.body.innerHTML = "";
                                                $('body').html($.parseHTML(""));
						jConfirm("<b>In the requested webpage at URL</b><br><br>"+host+"<br><br><b>Threat has been found:</b><br><br>"+src2+"<br>To get more information click on widget shown in Add-on Bar<br><br>", Head,function(r) {
            	    					if(r=== false){	
            	        					self.port.emit("temp1",host);
                        					location.reload();
        						}
						});
					}
				});
		    	}
		    	
		    	if(encodes) {
                                $('body').html($.parseHTML(""));
			    	//document.body.innerHTML = "";
				jConfirm("<b>In the requested webpage at URL</b><br><br>"+host+"<br><br><b>Threat has been found:</b><br><br>"+encodes+"<br><br>To get more information click on widget shown in Add-on Bar<br><br>", Head,function(r) {
            	    			if(r=== false){	
                        
            	        			self.port.emit("temp1",host);
                        			location.reload();
        				}
				});
		    	}
                        if(res){

				self.port.on("gsbstatD", function(blstatus) {
                                var gsbresponse=blstatus;
                                //for(var k=0;k<3;k++)
					if(blstatus === "malware" || blstatus === "phishing" || blstatus === "phishing,malware"){
	    					//document.body.innerHTML = "";
						$('body').html($.parseHTML(""));
	    					jConfirm("<b>In the requested webpage at URL</b><br><br>"+host+"<br><br><b>Threat has been found:</b><br><br>"+res+"<br>To get more information click on widget shown in Add-on Bar<br><br>", Head ,function(r) {
            	    					if(r== false){	
                        
            	        					self.port.emit("temp1",host);
                        					location.reload();
        		    				}
						});
					}
				});
			}
        	} //ps.
    
   	}//if
//});

   self.port.emit("para",reqqs,res,docW,shellps);//DYN:iframe, script, docw, encode status
}, false);
