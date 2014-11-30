/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global'],function(q){"use strict";var M={};M.render=function(r,m){if(m.oHoveredItem&&m.indexOfItem(m.oHoveredItem)<0){m.oHoveredItem=null}r.write("<div tabindex=\"-1\" hideFocus=\"true\"");if(m.getTooltip_AsString()){r.writeAttributeEscaped("title",m.getTooltip_AsString())}var a=sap.ui.getCore().getConfiguration().getAccessibility();if(a){r.writeAttribute("aria-orientation","vertical");r.writeAttribute("role","menu");var _=function(k,A){var b=sap.ui.getCore().getLibraryResourceBundle("sap.ui.unified");if(b){return b.getText(k,A)}return k};r.writeAttributeEscaped("aria-label",m.getAriaDescription()?m.getAriaDescription():_("MNU_ARIA_NAME"));r.writeAttribute("aria-level",m.getMenuLevel());if(m.oHoveredItem){r.writeAttribute("aria-activedescendant",m.oHoveredItem.getId())}}r.addClass("sapUiMnu");if(m.getRootMenu().bUseTopStyle){r.addClass("sapUiMnuTop")}r.writeClasses();r.writeControlData(m);r.write(">");M.renderItems(r,m);r.write("</div>")};M.renderItems=function(r,m){var I=m.getItems();var a=sap.ui.getCore().getConfiguration().getAccessibility();r.write("<ul class=\"sapUiMnuLst");var h=false;var H=false;for(var b=0;b<I.length;b++){if(I[b].getIcon&&I[b].getIcon()){h=true}if(I[b].getSubmenu()){H=true}}if(!h){r.write(" sapUiMnuNoIco")}if(!H){r.write(" sapUiMnuNoSbMnu")}r.write("\">");var n=0;for(var i=0;i<I.length;i++){if(I[i].getVisible()&&I[i].render){n++}}var c=0;for(var i=0;i<I.length;i++){var o=I[i];if(o.getVisible()&&o.render){c++;if(o.getStartsSection()){r.write("<li ");if(a){r.write("role=\"separator\" ")}r.write("class=\"sapUiMnuDiv\"><div class=\"sapUiMnuDivL\"></div><hr><div class=\"sapUiMnuDivR\"></div></li>")}o.render(r,o,m,{bAccessible:a,iItemNo:c,iTotalItems:n})}}r.write("</ul>")};return M},true);
