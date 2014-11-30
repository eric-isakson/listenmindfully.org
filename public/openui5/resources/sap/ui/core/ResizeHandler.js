/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','sap/ui/Global','sap/ui/base/Object','jquery.sap.act','jquery.sap.script'],function(q,G,B){"use strict";var l=q.sap.log.getLogger("sap.ui.core.ResizeHandler",q.sap.log.Level.ERROR);var c=null;var R=B.extend("sap.ui.core.ResizeHandler",{constructor:function(C){B.apply(this);c=C;this.aResizeListeners=[];this.bRegistered=false;this.iIdCounter=0;this.fDestroyHandler=q.proxy(this.destroy,this);q(window).bind("unload",this.fDestroyHandler);q.sap.act.attachActivate(i,this)}});function a(){if(this.bRegistered){this.bRegistered=false;sap.ui.getCore().detachIntervalTimer(this.checkSizes,this)}}function i(){if(!this.bRegistered&&this.aResizeListeners.length>0){this.bRegistered=true;sap.ui.getCore().attachIntervalTimer(this.checkSizes,this)}}R.prototype.destroy=function(e){q.sap.act.detachActivate(i,this);q(window).unbind("unload",this.fDestroyHandler);c=null;this.aResizeListeners=[];a.apply(this)};R.prototype.attachListener=function(r,h){var I=r instanceof sap.ui.core.Control,d=I?r.getDomRef():r,w=d?d.offsetWidth:0,H=d?d.offsetHeight:0,s="rs-"+new Date().valueOf()+"-"+this.iIdCounter++,b;if(I){b=("Control "+r.getId())}else if(r.id){b=r.id}else{b=String(r)}this.aResizeListeners.push({sId:s,oDomRef:I?null:r,oControl:I?r:null,fHandler:h,iWidth:w,iHeight:H,dbg:b});l.debug("registered "+b);i.apply(this);return s};R.prototype.detachListener=function(I){var t=this;q.each(this.aResizeListeners,function(b,r){if(r.sId==I){t.aResizeListeners.splice(b,1);l.debug("deregistered "+I);return false}});if(this.aResizeListeners.length==0){a.apply(this)}};R.prototype.checkSizes=function(){var d=l.isLoggable();if(d){l.debug("checkSizes:")}q.each(this.aResizeListeners,function(b,r){if(r){var C=!!r.oControl,D=C?r.oControl.getDomRef():r.oDomRef;if(D&&q.contains(document.documentElement,D)){var o=r.iWidth,O=r.iHeight,n=D.offsetWidth,N=D.offsetHeight;if(o!=n||O!=N){r.iWidth=n;r.iHeight=N;var e=q.Event("resize");e.target=D;e.currentTarget=D;e.size={width:n,height:N};e.oldSize={width:o,height:O};e.control=C?r.oControl:null;if(d){l.debug("resize detected for '"+r.dbg+"': "+e.oldSize.width+"x"+e.oldSize.height+" -> "+e.size.width+"x"+e.size.height)}r.fHandler(e)}}}});if(R._keepActive!=true&&R._keepActive!=false){R._keepActive=false}if(!q.sap.act.isActive()&&!R._keepActive){a.apply(this)}};R.register=function(r,h){if(!c||!c.oResizeHandler){return null}return c.oResizeHandler.attachListener(r,h)};R.deregister=function(I){if(!c||!c.oResizeHandler){return}c.oResizeHandler.detachListener(I)};R.deregisterAllForControl=function(C){if(!c||!c.oResizeHandler){return}var I=[];q.each(c.oResizeHandler.aResizeListeners,function(b,r){if(r&&r.oControl&&r.oControl.getId()===C){I.push(r.sId)}});q.each(I,function(b,s){R.deregister(s)})};return R},true);
