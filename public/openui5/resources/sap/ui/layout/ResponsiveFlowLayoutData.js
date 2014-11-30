/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','sap/ui/core/LayoutData','./library'],function(q,L,l){"use strict";var R=L.extend("sap.ui.layout.ResponsiveFlowLayoutData",{metadata:{library:"sap.ui.layout",properties:{minWidth:{type:"int",group:"Misc",defaultValue:100},weight:{type:"int",group:"Misc",defaultValue:1},linebreak:{type:"boolean",group:"Misc",defaultValue:false},margin:{type:"boolean",group:"Misc",defaultValue:true},linebreakable:{type:"boolean",group:"Misc",defaultValue:true}}}});R.MIN_WIDTH=100;R.WEIGHT=1;R.LINEBREAK=false;R.MARGIN=true;R.LINEBREAKABLE=true;R.prototype.setWeight=function(w){if(w>=1){this.setProperty("weight",w)}else{q.sap.log.warning("Values smaller than 1 are not valid. Default value '1' is used instead",this);this.setProperty("weight",R.WEIGHT)}return this};R.prototype.setLinebreak=function(b){if(this.getLinebreakable()==false&&b){q.sap.log.warning("Setting 'linebreak' AND 'linebreakable' doesn't make any sense! Please set either 'linebreak' or 'linebreakable'",this)}else{this.setProperty("linebreak",b)}};R.prototype.setLinebreakable=function(b){if(this.getLinebreak()===true&&b===false){q.sap.log.warning("Setting 'linebreak' AND 'linebreakable' doesn't make any sense! Please set either 'linebreak' or 'linebreakable'",this)}else{this.setProperty("linebreakable",b)}};return R},true);
