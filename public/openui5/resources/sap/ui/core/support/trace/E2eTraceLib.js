/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./EppLib'],function(q,E){"use strict";var a=(function(){var b=E;var t=/sap-ui-xx-e2e-trace-level=(low|medium|high)/.exec(location.search);var d;if(t&&t.length>=2){d=t[1]}else{d="medium"}var D="/sap/bc/sdf/E2E_Trace_upl";var c;var e=false;var M=function(x){this.idx=x.xidx;this.dsrGuid=x.xDsrGuid;this.method=x.xmethod;this.url=x.xurl;this.reqHeader=x.xRequestHeaders;this.respHeader=x.getAllResponseHeaders();this.statusCode=x.status;this.status=x.statusText;this.startTimestamp=x.xstartTimestamp;this.firstByteSent=x.xfirstByteSent?x.xfirstByteSent:x.xstartTimestamp;this.lastByteSent=this.firstByteSent;this.firstByteReceived=x.xfirstByteReceived?x.xfirstByteReceived:x.xlastByteReceived;this.lastByteReceived=x.xlastByteReceived;this.sentBytes=0;this.receivedBytes=x.responseText.length;this.getDuration=function(){return this.lastByteReceived-this.startTimestamp};this.getRequestLine=function(){return this.method+" "+this.url+" HTTP/?.?"};this.getRequestHeader=function(){var r=this.getRequestLine()+"\r\n";for(var i=0,l=this.reqHeader.length;i<l;i+=1){r+=this.reqHeader[i][0]+": "+this.reqHeader[i][1]+"\r\n"}r+="\r\n";return r};this.getResponseHeader=function(){var r="HTTP?/? "+this.statusCode+" "+this.status+"\r\n";r+=this.respHeader;r+="\r\n";return r}};var T=function(c,h,i,j){this.busTrx=c;this.trxStepIdx=h;this.name="Step-"+(h+1);this.date=i;this.trcLvl=j;this.messages=[];this.msgIdx=-1;this.pendingMessages=0;this.transactionStepTimeoutId=null;this.messageStarted=function(){this.msgIdx+=1;this.pendingMessages+=1;return this.msgIdx};this.onMessageFinished=function(x,k){if(x.xurl===D){return}x.xlastByteReceived=k;this.messages.push(new M(x));this.pendingMessages-=1;if(this.pendingMessages===0){if(this.transactionStepTimeoutId){clearTimeout(this.transactionStepTimeoutId)}this.transactionStepTimeoutId=setTimeout(o,3000)}};this.getId=function(){return this.busTrx.id+"-"+this.trxStepIdx};this.getTraceFlagsAsString=function(){return this.trcLvl[1].toString(16)+this.trcLvl[0].toString(16)}};var B=function(i,h,j,C){this.id=i;this.date=h;this.trcLvl=j;this.trxSteps=[];this.fnCallback=C;this.createTransactionStep=function(){var k=new T(this,this.trxSteps.length,new Date(),this.trcLvl);this.trxSteps.push(k)};this.getCurrentTransactionStep=function(){return this.trxSteps[this.trxSteps.length-1]};this.getBusinessTransactionXml=function(){var x="<?xml version=\"1.0\" encoding=\"UTF-8\"?><BusinessTransaction id=\""+this.id+"\" time=\""+f(this.date)+"\" name=\""+(window.document.title||"SAPUI5 Business Transaction")+"\">";for(var k=0,n=this.trxSteps.length;k<n;k+=1){var l=this.trxSteps[k];x+="<TransactionStep id=\""+l.getId()+"\" time=\""+f(l.date)+"\" name=\""+l.name+"\" traceflags=\""+l.getTraceFlagsAsString()+"\">";var m=l.messages;for(var p=0,r=m.length;p<r;p+=1){var s=m[p];x+="<Message id=\""+s.idx+"\" dsrGuid=\""+s.dsrGuid+"\">";x+="<x-timestamp>"+f(new Date(s.startTimestamp))+"</x-timestamp>";x+="<duration>"+s.getDuration()+"</duration>";x+="<returnCode>"+s.statusCode+"</returnCode>";x+="<sent>"+s.sentBytes+"</sent>";x+="<rcvd>"+s.receivedBytes+"</rcvd>";if(s.firstByteSent&&s.lastByteReceived){x+="<firstByteSent>"+f(new Date(s.firstByteSent))+"</firstByteSent>";x+="<lastByteSent>"+f(new Date(s.lastByteSent))+"</lastByteSent>";x+="<firstByteReceived>"+f(new Date(s.firstByteReceived))+"</firstByteReceived>";x+="<lastByteReceived>"+f(new Date(s.lastByteReceived))+"</lastByteReceived>"}x+="<requestLine><![CDATA["+s.getRequestLine()+"]]></requestLine>";x+="<requestHeader><![CDATA["+s.getRequestHeader()+"]]></requestHeader>";x+="<responseHeader><![CDATA["+s.getResponseHeader()+"]]></responseHeader>";x+="</Message>"}x+="</TransactionStep>"}x+="</BusinessTransaction>";return x}};var o=function(){if(c.getCurrentTransactionStep().pendingMessages===0&&c.getCurrentTransactionStep().messages.length>0){var r=confirm("End of transaction step detected.\nNumber of new message(s): "+c.getCurrentTransactionStep().messages.length+"\n\nDo you like to record another transaction step?");if(r){c.createTransactionStep()}else{(function(){var h=c.getBusinessTransactionXml();if(c.fnCallback&&typeof(c.fnCallback)==='function'){c.fnCallback(h)}var i="----------ieoau._._+2_8_GoodLuck8.3-ds0d0J0S0Kl234324jfLdsjfdAuaoei-----";var p=i+"\r\nContent-Disposition: form-data\r\nContent-Type: application/xml\r\n"+h+"\r\n"+i;var x=new window.XMLHttpRequest();x.open("HEAD",D,false);x.send();if(x.status==200){var j=new window.XMLHttpRequest();j.open("POST",D,false);j.setRequestHeader('Content-type','multipart/form-data; boundary="'+i+'"');j.send(p);alert(j.responseText)}else{try{var k=true;while(k){var u=window.prompt('Please enter a valid URL for the store server','http://<host>:<port>');if(u===''||u===null){break}var P=new RegExp("(https?:\/\/(?:www\.|(?!www))[^\s\.]+\.[^\s]{2,}|www\.[^\s]+\.[^\s]{2,})");var R=P.test(u);if(R){var j=new window.XMLHttpRequest();j.open("POST",u+'/E2EClientTraceUploadW/UploadForm.jsp',false);j.setRequestHeader('Content-type','multipart/form-data; boundary="'+i+'"');j.send(p);break}}}catch(l){q.sap.log.error(l.name+": "+l.message,"","sap.ui.core.support.trace.E2eTraceLib")}}})();c=null;e=false}}};var f=function(h){var u="";u+=h.getUTCDate()<10?"0"+h.getUTCDate():h.getUTCDate();u+="."+(h.getUTCMonth()<9?"0"+(h.getUTCMonth()+1):h.getUTCMonth()+1);u+="."+h.getUTCFullYear();u+=" "+(h.getUTCHours()<10?"0"+h.getUTCHours():h.getUTCHours());u+=":"+(h.getUTCMinutes()<10?"0"+h.getUTCMinutes():h.getUTCMinutes());u+=":"+(h.getUTCSeconds()<10?"0"+h.getUTCSeconds():h.getUTCSeconds());u+="."+(h.getUTCMilliseconds()<100?h.getUTCMilliseconds()<10?"00"+h.getUTCMilliseconds():"0"+h.getUTCMilliseconds():h.getUTCMilliseconds());u+=" UTC";return u};(function(){var h,i;h=window.XMLHttpRequest.prototype.open;i=window.XMLHttpRequest.prototype.setRequestHeader;function j(p){this.xfirstByteSent=p.timeStamp}function k(p){if(p.loaded>0){if(!this.xfirstByteReceived){this.xfirstByteReceived=p.timeStamp}this.xlastByteReceived=p.timeStamp}}function l(p){c.getCurrentTransactionStep().onMessageFinished(this,p.timeStamp)}function m(p){c.getCurrentTransactionStep().onMessageFinished(this,p.timeStamp)}function n(p){c.getCurrentTransactionStep().onMessageFinished(this,p.timeStamp)}window.XMLHttpRequest.prototype.setRequestHeader=function(){i.apply(this,arguments);if(e){this.xRequestHeaders.push(arguments)}};window.XMLHttpRequest.prototype.open=function(){h.apply(this,arguments);if(e){var p=c.getCurrentTransactionStep().messageStarted();this.xidx=p;this.xstartTimestamp=Date.now();this.xmethod=arguments[0];this.xurl=arguments[1];this.xRequestHeaders=[];this.xDsrGuid=b.createGUID();this.setRequestHeader("SAP-PASSPORT",b.passportHeader(c.getCurrentTransactionStep().trcLvl,c.id,this.xDsrGuid));this.setRequestHeader("X-CorrelationID",c.getCurrentTransactionStep().getId()+"-"+p);this.addEventListener("loadstart",j,false);this.addEventListener("progress",k,false);this.addEventListener("error",l,false);this.addEventListener("abort",m,false);this.addEventListener("load",n,false);p+=1}}})();var g={start:function(s,C){if(!e){if(!s){s=d}c=new B(b.createGUID(),new Date(),b.traceFlags(s),C);c.createTransactionStep();e=true}},isStarted:function(){return e}};if(/sap-ui-xx-e2e-trace=(true|x|X)/.test(location.search)){g.start()}return g}());return a},true);
