/*
 * Dynamically Changing/Updating the Content of Panel Tabs depending 
 * on the Active Web page URL
 */

addon.port.on('curTabMsg', function(curTabMsg) {
       
    var activetab=curTabMsg['curTab'];  //active tab
    var details=curTabMsg['details'];
    var host1=curTabMsg['host'];        //last loaded tab

    var blstatus="",host="",header="",msg1="",msg2="",msg3="",msg4="",msg5="";
    var msg6="",msg7="",msg8="",msg9="",msg10="",encode1="";

    /*
     * if active tab and recently loaded tab are same, display the same in Panel
     * and store the same in the storage variable with url name as the key
     */
    if(activetab.match(host1)){ //
        sessionStorage.setItem(activetab, JSON.stringify(details));
        blstatus=details[0];
        host=details[1];
        header=details[2];
        msg1=details[3];
        msg2=details[4];
        msg3=details[5];
        msg4=details[6];
        msg5=details[7];
        msg6=details[8];
        msg7=details[9];
        msg8=details[10];
        msg9=details[11];
        msg10=details[12];
        encode1=details[13];

    }
    else{  
        /*
         *  if active tab and recently loaded tab are not equal and 
         *  if the active tab is already existing in the storage then retrieve 
         *  it with the key as name of the active tab url
         */
        var details=sessionStorage.getItem(activetab);
        details=JSON.parse(details);
        if(details){  
            blstatus=details[0];
            host=details[1];
            header=details[2];
            msg1=details[3];
            msg2=details[4];
            msg3=details[5];
            msg4=details[6];
            msg5=details[7];
            msg6=details[8];
            msg7=details[9];
            msg8=details[10];
            msg9=details[11];
            msg10=details[12];
            encode1=details[13];
        }
        else{
            blstatus="",host="",header="",msg1="",msg2="",msg3="",msg4="";
            msg5="",msg6="",msg7="",msg8="",msg9="",msg10="",encode1="";
            $('#cdac_domain').html($.parseHTML("Reload the page to view details"));	
        }
    }

    if(host){
        $('#cdac_domain').html($.parseHTML("<center>Analysis Report for "+host+"</center>"));
    }

    if(msg1 || msg7){
        if(msg1){msg1+="<br>********************************<br>";}
            $('#cdac_one').html($.parseHTML(msg1+"<br>"+msg7));
            $('#cdac_menuone').html($.parseHTML("<div>Hidden iframe(s) Redirections<div id='topCount' class='count'>  </div></div>"));
    }
    else{
       	$('#cdac_one').html($.parseHTML("No Hidden iframes"));
	$('#cdac_menuone').html($.parseHTML("<div>Hidden iframe(s) Redirections</div>"));  
    }
    if(msg2 || msg8){
	if(msg2){msg2+="<br>********************************<br>";}
       	$('#cdac_two').html($.parseHTML(msg2+"<br>"+msg8));
	$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections<div id='topCount' class='count'>  </div></div>"));	
    }
    else{
       	$('#cdac_two').html($.parseHTML("No UnAuthorized Redirections"));
	$('#cdac_menutwo').html($.parseHTML("<div>UnAuthorized Redirections</div>"));  
    }
    if(msg3 || encode1){
       	$('#cdac_three').html($.parseHTML(msg3+"<br>"+encode1));
	$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript<div id='topCount' class='count'>  </div></div>"));
    }
    else{
       	$('#cdac_three').html($.parseHTML("No Encoded JavaScript"));
	$('#cdac_menuthree').html($.parseHTML("<div>Encoded JavaScript</div>"));  
    }
    if(msg4){
       	$('#cdac_four').html($.parseHTML("<div style='color:red'>"+msg4+"</div>"+"<br><br>"+host+" links to the following External Domains:<br>"+msg5));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests<div id='topCount' class='count'>  </div></div>"));
    }
    else if(msg5){
       	$('#cdac_four').html($.parseHTML(host+" links to the following External Domains:<br>"+msg5));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests<div id='topCount' class='county'>  </div></div>"));
    }
    else{
      	$('#cdac_four').html($.parseHTML("No External Domain Requests"));
	$('#cdac_menufour').html($.parseHTML("<div>External Domain Requests</div>"));   
    }
    if(msg6){
      	$('#cdac_five').html($.parseHTML(msg6));
	$('#cdac_menufive').html($.parseHTML("<div>Trackers<div id='topCount' class='county'>  </div></div>"));
    }else{
       	$('#cdac_five').html($.parseHTML("No Trackers found"));
	$('#cdac_menufive').html($.parseHTML("<div>Trackers</div>"));  
    }
});

