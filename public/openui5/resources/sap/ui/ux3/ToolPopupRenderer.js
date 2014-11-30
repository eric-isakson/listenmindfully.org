/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global'],function(q){"use strict";var T={};T.render=function(r,c){var a=sap.ui.getCore().getLibraryResourceBundle("sap.ui.ux3");var I=c.getId();var C=c.getContent();var b=c.getButtons();var t=c.getTitle();var s=sap.ui.resource('sap.ui.core','themes/base/img/1x1.gif');r.write("<div");r.writeControlData(c);r.addClass("sapUiUx3TP");if(t===""){r.addClass("sapUiUx3TPNoTitle")}if(b.length===0){r.addClass("sapUiUx3TPNoButtons")}if(c.isInverted()){r.addClass("sapUiTPInverted");r.addClass("sapUiInverted-CTX")}r.writeClasses();r.write(" aria-labelledby='",I,"-title ",I,"-acc' role='dialog'");r.writeAttribute("tabindex","-1");r.write(">");r.write("<div id='"+I+"-arrow' class='sapUiUx3TPArrow sapUiUx3TPArrowLeft'><div class='sapUiUx3TPArrowBorder'></div></div>");r.write("<span style='display:none;' id='",I,"-acc'>");r.writeEscaped(a.getText("DIALOG_CLOSE_HELP"));r.write("</span>");r.write('<span id="'+I+'-firstFocusable'+'" tabindex="0" class="sapUiUxTPFocus">');r.write('<img src="'+s+'">');r.write('</span>');if(t&&(t.length!=="")){r.write('<div class="sapUiUx3TPTitle" id="'+I+'-title">');r.write('<span class="sapUiUx3TPTitleText">');r.writeEscaped(t);r.write('</span>');r.write('</div>');r.write('<div class="sapUiUx3TPTitleSep" id="'+I+'-title-separator"></div>')}else{var d=c.getTooltip_AsString();if(d){r.write("<h1 id='"+I+"-title' style='display:none;'>");r.writeEscaped(d);r.write("</h1>")}}r.write('<div id="'+I+'-content"');r.addClass("sapUiUx3TPContent");r.writeClasses();r.write(">");for(var i=0;i<C.length;i++){r.renderControl(C[i])}r.write('</div>');if(b.length>0){r.write('<div class="sapUiUx3TPButtonsSep" id="'+I+'-buttons-separator"></div>');r.write('<div class="sapUiUx3TPBtnRow" id="'+I+'-buttons">');for(var i=0;i<b.length;i++){r.renderControl(b[i].addStyleClass("sapUiUx3TPBtn"))}}else{r.write('<div class="sapUiUx3TPButtonsSep sapUiUx3TPButtonRowHidden" id="'+I+'-buttons-separator"></div>');r.write('<div class="sapUiUx3TPBtnRow sapUiUx3TPButtonRowHidden" id="'+I+'-buttons">')}r.write("</div>");r.write('<span id="'+I+'-lastFocusable'+'" tabindex="0" class="sapUiUxTPFocus">');r.write('<img src="'+s+'">');r.write('</span>');r.write("</div>")};return T},true);
