/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','sap/ui/core/Element','sap/ui/core/IconPool','./library'],function(q,E,I,l){"use strict";var S=E.extend("sap.ui.unified.ShellHeadUserItem",{metadata:{library:"sap.ui.unified",properties:{username:{type:"string",group:"Appearance",defaultValue:''},image:{type:"sap.ui.core.URI",group:"Appearance",defaultValue:null}},events:{press:{}}}});I.getIconInfo("","");S.prototype.onclick=function(e){this.firePress()};S.prototype.onsapspace=S.prototype.onclick;S.prototype.setImage=function(i){this.setProperty("image",i,true);if(this.getDomRef()){this._refreshImage()}return this};S.prototype._refreshImage=function(){var i=this.$("img");var s=this.getImage();if(!s){i.html("").css("style","").css("display","none")}else if(I.isIconURI(s)){var o=I.getIconInfo(s);i.html("").css("style","");if(o){i.text(o.content).css("font-family","'"+o.fontFamily+"'")}}else{var $=this.$("img-inner");if($.length==0||$.attr("src")!=s){i.css("style","").html("<img id='"+this.getId()+"-img-inner' src='"+q.sap.encodeHTML(s)+"'></img>")}}};S.prototype._checkAndAdaptWidth=function(s){if(!this.getDomRef()){return false}var r=this.$(),n=this.$("name");var b=r.width();r.toggleClass("sapUiUfdShellHeadUsrItmLimit",false);var m=240;if(s){m=Math.min(m,0.5*document.documentElement.clientWidth-225)}if(m<n.width()){r.toggleClass("sapUiUfdShellHeadUsrItmLimit",true)}return b!=r.width()};return S},true);
