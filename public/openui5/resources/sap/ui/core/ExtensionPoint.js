/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
(function(){"use strict";sap.ui.extensionpoint=function(c,e,C,t,a){var b,v,r;if(sap.ui.core.CustomizingConfiguration){if(c instanceof sap.ui.core.mvc.View){b=sap.ui.core.CustomizingConfiguration.getViewExtension(c.sViewName,e);v=c}else if(c instanceof sap.ui.core.Fragment){b=sap.ui.core.CustomizingConfiguration.getViewExtension(c.getFragmentName(),e);v=c._oContainingView}if(b){if(b.className){jQuery.sap.require(b.className);var o=jQuery.sap.getObject(b.className);jQuery.sap.log.info("Customizing: View extension found for extension point '"+e+"' in View '"+v.sViewName+"': "+b.className+": "+(b.viewName||b.fragmentName));if(b.className==="sap.ui.core.Fragment"){var f=new o({type:b.type,fragmentName:b.fragmentName,containingView:v});r=(jQuery.isArray(f)?f:[f])}else if(b.className==="sap.ui.core.mvc.View"){var v=sap.ui.view({type:b.type,viewName:b.viewName});r=[v]}else{jQuery.sap.log.warning("Customizing: Unknown extension className configured (and ignored) in Component.js for extension point '"+e+"' in View '"+v.sViewName+"': "+b.className)}}else{jQuery.sap.log.warning("Customizing: no extension className configured in Component.js for extension point '"+e+"' in View '"+v.sViewName+"': "+b.className)}}}if(!r&&jQuery.isFunction(C)){r=C()}if(r&&!jQuery.isArray(r)){r=[r]}if(r&&t){var A;if(!a){jQuery.sap.log.debug("no target aggregationName given - trying to attach the extension point content to the targetControl's default aggregation");A=t.getMetadata().getDefaultAggregation()}else{A=t.getMetadata().getJSONKeys()[a]}if(A){for(var i=0,l=r.length;i<l;i++){t[A._sMutator](r[i])}}else{jQuery.sap.log.error("Creating extension point failed - Tried to add extension point with name "+e+" to an aggregation of "+t.getId()+" in view "+v.sViewName+", but sAggregationName was not provided correctly and I could not find a default aggregation")}}return r||[]}}());
