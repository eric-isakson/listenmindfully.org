/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','sap/ui/core/Renderer'],function(q,R){"use strict";var T={};T.render=function(r,t){var w=t.getWidth(),s=t.getText(true),a=t.getTextDirection(),b=t.getTooltip_AsString(),n=t.getMaxLines(),W=t.getWrapping(),c=t.getTextAlign();r.write("<span");r.writeControlData(t);r.addClass("sapMText");r.addClass("sapUiSelectable");if(!W||n==1){r.addClass("sapMTextNoWrap")}else if(W){if(!/\s/.test(s)){r.addClass("sapMTextBreakWord")}}w?r.addStyle("width",w):r.addClass("sapMTextMaxWidth");a&&r.addStyle("direction",a.toLowerCase());b&&r.writeAttributeEscaped("title",b);if(c){c=R.getTextAlign(c,a);if(c){r.addStyle("text-align",c)}}r.writeClasses();r.writeStyles();r.write(">");if(t.hasMaxLines()){this.renderMaxLines(r,t)}else{this.renderText(r,t)}r.write("</span>")};T.renderMaxLines=function(r,t){r.write("<div");r.writeAttribute("id",t.getId()+"-inner");r.addClass("sapMTextMaxLine");if(t.canUseNativeLineClamp()){r.addClass("sapMTextLineClamp");r.addStyle("-webkit-line-clamp",t.getMaxLines())}r.writeClasses();r.writeStyles();r.write(">");this.renderText(r,t);r.write("</div>")};T.renderText=function(r,t){var s=t.getText(true);r.writeEscaped(s)};return T},true);
