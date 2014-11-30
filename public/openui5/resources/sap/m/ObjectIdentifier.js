/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./library','sap/ui/core/Control','sap/ui/core/IconPool'],function(q,l,C,I){"use strict";var O=C.extend("sap.m.ObjectIdentifier",{metadata:{library:"sap.m",properties:{title:{type:"string",group:"Misc",defaultValue:null},text:{type:"string",group:"Misc",defaultValue:null},badgeNotes:{type:"boolean",group:"Misc",defaultValue:null,deprecated:true},badgePeople:{type:"boolean",group:"Misc",defaultValue:null,deprecated:true},badgeAttachments:{type:"boolean",group:"Misc",defaultValue:null,deprecated:true},visible:{type:"boolean",group:"Appearance",defaultValue:true},titleActive:{type:"boolean",group:"Misc",defaultValue:false}},aggregations:{_titleControl:{type:"sap.ui.core.Control",multiple:false,visibility:"hidden"},_textControl:{type:"sap.ui.core.Control",multiple:false,visibility:"hidden"}},events:{titlePress:{parameters:{domRef:{type:"object"}}}}}});O.prototype.exit=function(){if(this._attachmentsIcon){this._attachmentsIcon.destroy();this._attachmentsIcon=null}if(this._peopleIcon){this._peopleIcon.destroy();this._peopleIcon=null}if(this._notesIcon){this._notesIcon.destroy();this._notesIcon=null}};O.prototype._getAttachmentsIcon=function(){if(!this._attachmentsIcon){this._attachmentsIcon=this._getIcon(I.getIconURI("attachment"),this.getId()+"-attachments")}return this._attachmentsIcon};O.prototype._getPeopleIcon=function(){if(!this._peopleIcon){this._peopleIcon=this._getIcon(I.getIconURI("group"),this.getId()+"-people")}return this._peopleIcon};O.prototype._getNotesIcon=function(){if(!this._notesIcon){this._notesIcon=this._getIcon(I.getIconURI("notes"),this.getId()+"-notes")}return this._notesIcon};O.prototype._getIcon=function(u,i){var s=sap.ui.Device.system.phone?"1em":"1em";var o;o=this._icon||I.createControlByURI({src:u,id:i+"-icon",size:s},sap.m.Image);o.setSrc(u);return o};O.prototype._getTitleControl=function(){var t=this.getAggregation("_titleControl"),i;if(!t){if(this.getProperty("titleActive")){t=new sap.m.Link({text:this.getProperty("title")})}else{t=new sap.m.Text({text:this.getProperty("title")})}this.setAggregation("_titleControl",t)}else{i=this.getProperty("titleActive");if(i&&t instanceof sap.m.Text){this.destroyAggregation("_titleControl",true);t=new sap.m.Link({text:this.getProperty("title")});this.setAggregation("_titleControl",t)}else if(!i&&t instanceof sap.m.Link){this.destroyAggregation("_titleControl",true);t=new sap.m.Text({text:this.getProperty("title")});this.setAggregation("_titleControl",t)}}return t};O.prototype._getTextControl=function(){var t=this.getAggregation("_textControl");if(!t){t=new sap.m.Text();t.setProperty("text",this.getProperty("text"));this.setAggregation("_textControl",t)}return t};O.prototype._rerenderTitle=function(){var t=this._getTitleControl();t.setProperty("text",this.getProperty("title"),true);var r=sap.ui.getCore().createRenderManager();r.renderControl(t);r.flush(this.$("title")[0]);r.destroy()};O.prototype.setTitle=function(t){var T=this._getTitleControl();T.setProperty("text",t,false);this.setProperty("title",t,true);this.$("text").toggleClass("sapMObjectIdentifierTextBellow",!!this.getProperty("text")&&!!this.getProperty("title"));return this};O.prototype.setText=function(t){var T=this._getTextControl();T.setProperty("text",t,false);this.setProperty("text",t,true);this.$("text").toggleClass("sapMObjectIdentifierTextBellow",!!this.getProperty("text")&&!!this.getProperty("title"));return this};O.prototype.setTitleActive=function(v){var p=this.getProperty("titleActive");if(p!=v){this.setProperty("titleActive",v,true);if(this.$("title").children().length>0){this._rerenderTitle()}}return this};O.prototype._handlePress=function(e){var c=e.target;if(this.getTitleActive()&&this.$("title")[0].firstChild==c){this.fireTitlePress({domRef:c})}};O.prototype.onsapenter=function(e){O.prototype._handlePress.apply(this,arguments)};O.prototype.onsapspace=function(e){O.prototype._handlePress.apply(this,arguments)};O.prototype.ontap=function(e){O.prototype._handlePress.apply(this,arguments)};return O},true);
