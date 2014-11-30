/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./Control','./library'],function(q,C,l){"use strict";var S=C.extend("sap.ui.core.ScrollBar",{metadata:{library:"sap.ui.core",properties:{vertical:{type:"boolean",group:"Behavior",defaultValue:true},scrollPosition:{type:"int",group:"Behavior",defaultValue:null},size:{type:"sap.ui.core.CSSSize",group:"Dimension",defaultValue:null},contentSize:{type:"sap.ui.core.CSSSize",group:"Dimension",defaultValue:null},steps:{type:"int",group:"Dimension",defaultValue:null}},events:{scroll:{parameters:{action:{type:"sap.ui.core.ScrollBarAction"},forward:{type:"boolean"},newScrollPos:{type:"int"},oldScrollPos:{type:"int"}}}}}});S.prototype.init=function(){this._$ScrollDomRef=null;this._iOldScrollPos=0;this._iOldStep=0;this._bScrollPosIsChecked=false;this._bRTL=sap.ui.getCore().getConfiguration().getRTL();this._bSuppressScroll=false;this._iMaxContentDivSize=1000000;if(q.sap.touchEventMode==="ON"){q.sap.require("sap.ui.thirdparty.zyngascroll");this._iLastTouchScrollerPosition=null;this._iTouchStepTreshold=24;this._bSkipTouchHandling=false;this._oTouchScroller=new window.Scroller(q.proxy(this._handleTouchScroll,this),{bouncing:false})}};S.prototype.onBeforeRendering=function(){this.$("sb").unbind("scroll",this.onscroll)};S.prototype.onAfterRendering=function(){this._iSteps=this.getSteps();var c=this.getContentSize();this._bStepMode=!c;var s=this.getSize();if(q.sap.endsWith(s,"px")){s=s.substr(0,s.length-2)}else{s=this.getVertical()?this.$().height():this.$().width()}var a=null;var $=this.$("ffsize");if(!!sap.ui.Device.browser.firefox){a=$.outerHeight()}$.remove();if(!!sap.ui.Device.browser.webkit){if(!document.width){a=Math.round(40/(window.outerWidth/q(document).width()))}else{a=Math.round(40/(document.width/q(document).width()))}}if(this.getVertical()){if(!!sap.ui.Device.browser.firefox){this._iFactor=a}else if(!!sap.ui.Device.browser.webkit){this._iFactor=a}else{this._iFactor=Math.floor(s*0.125)}this._iFactorPage=!!sap.ui.Device.browser.firefox?s-a:Math.floor(s*0.875)}else{if(!!sap.ui.Device.browser.firefox){this._iFactor=10;this._iFactorPage=Math.floor(s*0.8)}else if(!!sap.ui.Device.browser.webkit){this._iFactor=a;this._iFactorPage=Math.floor(s*0.875)}else{this._iFactor=7;this._iFactorPage=s-14}}this._$ScrollDomRef=this.$("sb");if(this._bStepMode){if(this.getVertical()){var i=this._iSteps*this._iFactor;if(i>this._iMaxContentDivSize){this._iFactor=Math.ceil(this._iFactor/Math.ceil(i/this._iMaxContentDivSize))}var b=this._$ScrollDomRef.height()+this._iSteps*this._iFactor;this._$ScrollDomRef.find("div").height(b)}else{var b=this._$ScrollDomRef.width()+this._iSteps*this._iFactor;this._$ScrollDomRef.find("div").width(b)}}this.setCheckedScrollPosition(this.getScrollPosition()?this.getScrollPosition():0,true);this._$ScrollDomRef.bind("scroll",q.proxy(this.onscroll,this));if(q.sap.touchEventMode==="ON"){this._bSkipTouchHandling=true;var o={width:0,height:0};o[this.getVertical()?"height":"width"]=this._bStepMode?(this.getSteps()*this._iTouchStepTreshold):parseInt(this.getContentSize(),10);this._oTouchScroller.setDimensions(0,0,o.width,o.height);var e=this._$ScrollDomRef.get(0);var r=e.getBoundingClientRect();this._oTouchScroller.setPosition(r.left+e.clientLeft,r.top+e.clientTop);this._bSkipTouchHandling=false}};S.prototype.onmousewheel=function(e){if(this.$().is(":visible")){var o=e.originalEvent;var w=o.detail?o.detail:o.wheelDelta*(-1)/40;var f=w>0?true:false;if(q.sap.containsOrEquals(this._$ScrollDomRef[0],e.target)){this._doScroll(sap.ui.core.ScrollBarAction.MouseWheel,f)}else{this._bMouseWheel=true;var p=null;if(this._bStepMode){p=w+this._iOldStep}else{p=w*this._iFactor+this._iOldScrollPos}this.setCheckedScrollPosition(p,true)}e.preventDefault();e.stopPropagation();return false}};S.prototype.ontouchstart=function(e){var t=e.touches;var f=t[0];if(f&&f.target&&f.target.tagName.match(/input|textarea|select/i)){return}if(this._oTouchScroller){this._oTouchScroller.doTouchStart(t,e.timeStamp)}if(t.length==1){e.preventDefault()}};S.prototype.ontouchmove=function(e){if(this._oTouchScroller){this._oTouchScroller.doTouchMove(e.touches,e.timeStamp,e.scale)}};S.prototype.ontouchend=function(e){if(this._oTouchScroller){this._oTouchScroller.doTouchEnd(e.timeStamp)}};S.prototype.ontouchcancel=function(e){if(this._oTouchScroller){this._oTouchScroller.doTouchEnd(e.timeStamp)}};S.prototype.onscroll=function(e){if(this._bSuppressScroll){this._bSuppressScroll=false;e.preventDefault();e.stopPropagation();return false}var s=null;if(this._$ScrollDomRef){if(this.getVertical()){s=Math.round(this._$ScrollDomRef.scrollTop())}else{s=Math.round(this._$ScrollDomRef.scrollLeft());if(!!sap.ui.Device.browser.firefox&&this._bRTL){s=Math.abs(s)}else if(!!sap.ui.Device.browser.webkit&&this._bRTL){var o=this._$ScrollDomRef.get(0);s=o.scrollWidth-o.clientWidth-o.scrollLeft}}}var d=s-this._iOldScrollPos;var f=d>0?true:false;if(d<0){d=d*(-1)}var a=sap.ui.core.ScrollBarAction.Drag;if(d==this._iFactor){a=sap.ui.core.ScrollBarAction.Step}else if(d==this._iFactorPage){a=sap.ui.core.ScrollBarAction.Page}else if(this._bMouseWheel){a=sap.ui.core.ScrollBarAction.MouseWheel}this._doScroll(a,f);e.preventDefault();e.stopPropagation();return false};S.prototype._handleTouchScroll=function(L,t,z){if(this._bSkipTouchHandling){return}var v=this.getVertical()?t:L;var p;if(this._bStepMode){p=Math.max(Math.round(v/this._iTouchStepTreshold),0)}else{p=Math.round(v)}if(this._iLastTouchScrollerPosition!==p){this._iLastTouchScrollerPosition=p;this.setCheckedScrollPosition(p,true);this.fireScroll()}};S.prototype.unbind=function(o){if(o){this._$OwnerDomRef=q(o);if(this.getVertical()){this._$OwnerDomRef.unbind(!!sap.ui.Device.browser.firefox?"DOMMouseScroll":"mousewheel",this.onmousewheel)}if(q.sap.touchEventMode==="ON"){this._$OwnerDomRef.unbind(this._getTouchEventType("touchstart"),q.proxy(this.ontouchstart,this));this._$OwnerDomRef.unbind(this._getTouchEventType("touchmove"),q.proxy(this.ontouchmove,this));this._$OwnerDomRef.unbind(this._getTouchEventType("touchend"),q.proxy(this.ontouchend,this));this._$OwnerDomRef.unbind(this._getTouchEventType("touchcancle"),q.proxy(this.ontouchcancle,this))}}};S.prototype.bind=function(o){if(o){this._$OwnerDomRef=q(o);if(this.getVertical()){this._$OwnerDomRef.bind(!!sap.ui.Device.browser.firefox?"DOMMouseScroll":"mousewheel",q.proxy(this.onmousewheel,this))}if(q.sap.touchEventMode==="ON"){this._$OwnerDomRef.bind(this._getTouchEventType("touchstart"),q.proxy(this.ontouchstart,this));this._$OwnerDomRef.bind(this._getTouchEventType("touchmove"),q.proxy(this.ontouchmove,this));this._$OwnerDomRef.bind(this._getTouchEventType("touchend"),q.proxy(this.ontouchend,this));this._$OwnerDomRef.bind(this._getTouchEventType("touchcancle"),q.proxy(this.ontouchcancle,this))}}};S.prototype._getTouchEventType=function(t){return q.sap.touchEventMode==="SIM"?("sap"+t):t};S.prototype.pageUp=function(){this._doScroll(sap.ui.core.ScrollBarAction.Page,false)};S.prototype.pageDown=function(){this._doScroll(sap.ui.core.ScrollBarAction.Page,true)};S.prototype.setScrollPosition=function(s){if(this._$ScrollDomRef){this.setCheckedScrollPosition(s,true)}else{this.setProperty("scrollPosition",s)}return this};S.prototype.setCheckedScrollPosition=function(s,c){var i=Math.max(s,0);if(this._bStepMode===undefined){this._bStepMode=!this.getContentSize()}var a=i;if(this._bStepMode){i=Math.min(i,this.getSteps());a=i*this._iFactor}i=Math.round(i);this._bSuppressScroll=!c;this.setProperty("scrollPosition",i,true);if(this.getVertical()){this._$ScrollDomRef.scrollTop(a)}else{if(!!sap.ui.Device.browser.firefox&&this._bRTL){this._$ScrollDomRef.scrollLeft(-a)}else if(!!sap.ui.Device.browser.webkit&&this._bRTL){var o=this._$ScrollDomRef.get(0);this._$ScrollDomRef.scrollLeft(o.scrollWidth-o.clientWidth-a)}else{this._$ScrollDomRef.scrollLeft(a)}}if(q.sap.touchEventMode==="ON"){var v=i;if(this._bStepMode){v=Math.round(i*this._iTouchStepTreshold)}this._oTouchScroller.__scrollTop=this.getVertical()?v:0;this._oTouchScroller.__scrollLeft=this.getVertical()?0:v}};S.prototype.setContentSize=function(c){this.setProperty("contentSize",c);this._bStepMode=false;var s=this.$("sbcnt");if(s){if(this.getVertical()){s.height(c)}else{s.width(c)}}return this};S.prototype._doScroll=function(e,f){var s=null;if(this._$ScrollDomRef){if(this.getVertical()){s=Math.round(this._$ScrollDomRef.scrollTop())}else{s=Math.round(this._$ScrollDomRef.scrollLeft());if(!!sap.ui.Device.browser.firefox&&this._bRTL){s=Math.abs(s)}else if(!!sap.ui.Device.browser.webkit&&this._bRTL){var o=this._$ScrollDomRef.get(0);s=o.scrollWidth-o.clientWidth-o.scrollLeft}}}if(this._bStepMode){var i=Math.round(s/this._iFactor);var O=this._iOldStep;if(O!==i){this.setCheckedScrollPosition(i,false);q.sap.log.debug("-----STEPMODE-----: New Step: "+i+" --- Old Step: "+O+" --- Scroll Pos in px: "+s+" --- Action: "+e+" --- Direction is forward: "+f);this.fireScroll({action:e,forward:f,newScrollPos:i,oldScrollPos:O});this._iOldStep=i}}else{s=Math.round(s);this.setProperty("scrollPosition",s,true);q.sap.log.debug("-----PIXELMODE-----: New ScrollPos: "+s+" --- Old ScrollPos: "+this._iOldScrollPos+" --- Action: "+e+" --- Direction is forward: "+f);this.fireScroll({action:e,forward:f,newScrollPos:s,oldScrollPos:this._iOldScrollPos})}this._bSuppressScroll=false;this._iOldScrollPos=s;this._bMouseWheel=false};S.prototype.onThemeChanged=function(){this.rerender()};S.prototype.getNativeScrollPosition=function(){if(this._$ScrollDomRef){if(this.getVertical()){return Math.round(this._$ScrollDomRef.scrollTop())}else{return Math.round(this._$ScrollDomRef.scrollLeft())}}return 0};S.prototype.setNativeScrollPosition=function(n){var s=Math.round(n);if(this._$ScrollDomRef){if(this.getVertical()){this._$ScrollDomRef.scrollTop(s)}else{this._$ScrollDomRef.scrollLeft(s)}}};return S},true);
