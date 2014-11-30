/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./library','sap/ui/core/TooltipBase'],function(q,l,T){"use strict";var R=T.extend("sap.ui.commons.RichTooltip",{metadata:{library:"sap.ui.commons",properties:{title:{type:"string",group:"Misc",defaultValue:null},imageSrc:{type:"sap.ui.core.URI",group:"Misc",defaultValue:null},valueStateText:{type:"string",group:"Misc",defaultValue:null},imageAltText:{type:"string",group:"Misc",defaultValue:null}},aggregations:{formattedText:{type:"sap.ui.commons.FormattedTextView",multiple:false,visibility:"hidden"},individualStateText:{type:"sap.ui.commons.FormattedTextView",multiple:false,visibility:"hidden"}}}});R.prototype.onAfterRendering=function(){var t=this.getAggregation("formattedText");if(t&&t.getDomRef()){t.$().attr("role","tooltip");if(this.getImageSrc()!==""){this.$().addClass("sapUiRttContentWide")}}};R.prototype.setValueStateText=function(t){var v=this.getAggregation("individualStateText");if(t){if(v){v.setHtmlText(t)}else{v=new sap.ui.commons.FormattedTextView(this.getId()+"-valueStateText",{htmlText:t}).addStyleClass("sapUiRttValueStateText").addStyleClass("individual");this.setAggregation("individualStateText",v);this.setProperty("valueStateText",t,true)}}else{if(v){this.setAggregation("individualStateText",v)}}};R.prototype.getValueStateText=function(){var v=this.getAggregation("individualStateText");if(v){return v.getHtmlText()}return""};R.prototype.setText=function(t){if(!!t){t=t.replace(/(\r\n|\n|\r)/g,"<br />")}var o=this.getAggregation("formattedText");if(o){o.setHtmlText(t)}else{o=new sap.ui.commons.FormattedTextView(this.getId()+"-txt",{htmlText:t}).addStyleClass("sapUiRttText");this.setAggregation("formattedText",o);this.setProperty("text",t,true)}};R.prototype.getText=function(){var t=this.getAggregation("formattedText");if(t){return t.getHtmlText()}return""};R.prototype.onfocusin=function(e){T.prototype.onfocusin.apply(this,arguments);var s=q(e.target).control(0);if(s!=null){var i=this.getId();var I="";if(this.getTitle()!==""){I+=i+"-title "}var $=this.$("valueStateText");if($.length>0){I+=i+"-valueStateText "}if(this.getImageSrc()!==""){I+=i+"-image "}if(this.getText()!==""){I+=i+"-txt"}var d=s.getFocusDomRef();d.setAttribute("aria-describedby",I)}};return R},true);
