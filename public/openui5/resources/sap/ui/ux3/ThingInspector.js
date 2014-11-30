/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./ActionBar','./Overlay','./ThingViewer','./library'],function(q,A,O,T,l){"use strict";var a=O.extend("sap.ui.ux3.ThingInspector",{metadata:{library:"sap.ui.ux3",properties:{firstTitle:{type:"string",group:"Misc",defaultValue:null},type:{type:"string",group:"Misc",defaultValue:null},icon:{type:"sap.ui.core.URI",group:"Misc",defaultValue:null},secondTitle:{type:"string",group:"Misc",defaultValue:null},followState:{type:"sap.ui.ux3.FollowActionState",group:"Misc",defaultValue:sap.ui.ux3.FollowActionState.Default},flagState:{type:"boolean",group:"Misc",defaultValue:false},favoriteState:{type:"boolean",group:"Misc",defaultValue:false},favoriteActionEnabled:{type:"boolean",group:"Misc",defaultValue:true},updateActionEnabled:{type:"boolean",group:"Misc",defaultValue:true},followActionEnabled:{type:"boolean",group:"Misc",defaultValue:true},flagActionEnabled:{type:"boolean",group:"Misc",defaultValue:true},headerType:{type:"sap.ui.ux3.ThingViewerHeaderType",group:"Misc",defaultValue:sap.ui.ux3.ThingViewerHeaderType.Standard}},aggregations:{actions:{type:"sap.ui.ux3.ThingAction",multiple:true,singularName:"action"},headerContent:{type:"sap.ui.ux3.ThingGroup",multiple:true,singularName:"headerContent"},facets:{type:"sap.ui.ux3.NavigationItem",multiple:true,singularName:"facet"},facetContent:{type:"sap.ui.ux3.ThingGroup",multiple:true,singularName:"facetContent"},actionBar:{type:"sap.ui.ux3.ActionBar",multiple:false},thingViewer:{type:"sap.ui.ux3.ThingViewer",multiple:false,visibility:"hidden"}},associations:{selectedFacet:{type:"sap.ui.ux3.NavigationItem",multiple:false}},events:{actionSelected:{parameters:{id:{type:"string"},action:{type:"sap.ui.ux3.ThingAction"}}},facetSelected:{allowPreventDefault:true,parameters:{id:{type:"string"},item:{type:"sap.ui.ux3.NavigationItem"},key:{type:"string"}}},feedSubmit:{parameters:{text:{type:"string"}}}}}});(function(){a.prototype.init=function(){var o,t=this;O.prototype.init.apply(this);this._oThingViewer=new T(this.getId()+"-thingViewer");this.setAggregation("thingViewer",this._oThingViewer);this._oThingViewer.attachFacetSelected(function(e){var i=e.getParameters().item;if(t.fireFacetSelected({id:i.getId(),key:i.getKey(),item:i})){t.setSelectedFacet(i)}else{e.preventDefault()}});this._oSocialActions={};if(this.getActionBar()==null){o=new A(this.getId()+"-actionBar");o.setShowOpen(false);o.setAlwaysShowMoreMenu(false);o.setDividerWidth("252px");o.attachActionSelected(function(e){var s=e.getParameters().id,b=e.getParameters().action,c;if(s.indexOf('Favorite')!=-1||s.indexOf('Follow')!=-1||s.indexOf('Flag')!=-1){if(t._oSocialActions[s]){c=t._oSocialActions[s]}else{c=new sap.ui.ux3.ThingAction({id:t.getId()+"-"+s.toLowerCase(),text:b.text,enabled:b.enabled});t._oSocialActions[s]=c}t.fireActionSelected({id:s.toLowerCase(),action:c})}else{t.fireActionSelected({id:e.getParameters().id,action:e.getParameters().action})}});o.attachFeedSubmit(function(e){t.fireFeedSubmit({text:e.getParameters().text})});this.setActionBar(o)}};a.prototype.onAfterRendering=function(){O.prototype.onAfterRendering.apply(this,arguments);var s=this._getShell();this._bShell=!!s;if(!s){this._applyChanges({showOverlay:false})}};a.prototype.onBeforeRendering=function(){O.prototype.onBeforeRendering.apply(this,arguments)};a.prototype.exit=function(){this._oThingViewer.exit(arguments);this._oThingViewer.destroy();O.prototype.exit.apply(this,arguments)};a.prototype.open=function(i){if(this.getDomRef()){this.rerender()}O.prototype.open.apply(this,arguments);this._selectDefault()};a.prototype._getNavBar=function(){return this._oThingViewer._oNavBar};a.prototype._selectDefault=function(){this._oThingViewer._selectDefault()};a.prototype._equalColumns=function(){this._oThingViewer._equalColumns()};a.prototype._setTriggerValue=function(){this._oThingViewer._setTriggerValue()};a.prototype._setFocusLast=function(){var f=this.$("thingViewer-toolbar").lastFocusableDomRef();if(!f&&this.getCloseButtonVisible()&&this.$("close").is(":sapFocusable")){f=this.getDomRef("close")}else if(!f&&this.getOpenButtonVisible()&&this.$("openNew").is(":sapFocusable")){f=this.getDomRef("openNew")}q.sap.focus(f)};a.prototype._setFocusFirst=function(){if(this.getOpenButtonVisible()&&this.$("openNew").is(":sapFocusable")){q.sap.focus(this.getDomRef("openNew"))}else if(this.getCloseButtonVisible()&&this.$("close").is(":sapFocusable")){q.sap.focus(this.getDomRef("close"))}else{q.sap.focus(this.$("thingViewer-content").firstFocusableDomRef())}};a.prototype.insertAction=function(o,i){if(this.getActionBar()){this.getActionBar().insertBusinessAction(o,i)}return this};a.prototype.addAction=function(o){if(this.getActionBar()){this.getActionBar().addBusinessAction(o)}return this};a.prototype.removeAction=function(o){var r;if(this.getActionBar()){r=this.getActionBar().removeBusinessAction(o)}return r};a.prototype.removeAllActions=function(){var r;if(this.getActionBar()){r=this.getActionBar().removeAllBusinessActions()}return r};a.prototype.getActions=function(){var r;if(this.getActionBar()){r=this.getActionBar().getBusinessActions()}return r};a.prototype.destroyActions=function(){if(this.getActionBar()){this.getActionBar().destroyBusinessActions()}return this};a.prototype.indexOfAction=function(o){var r=-1;if(this.getActionBar()){r=this.getActionBar().indexOfBusinessAction(o)}return r};a.prototype.getFacets=function(){return this._oThingViewer.getFacets()};a.prototype.insertFacet=function(f,i){this._oThingViewer.insertFacet(f,i);return this};a.prototype.addFacet=function(f){this._oThingViewer.addFacet(f);return this};a.prototype.removeFacet=function(e){return this._oThingViewer.removeFacet(e)};a.prototype.removeAllFacets=function(){return this._oThingViewer.removeAllFacets()};a.prototype.destroyFacets=function(){this._oThingViewer.destroyFacets();return this};a.prototype.indexOfFacet=function(f){return this._oThingViewer.indexOfFacet(f)};a.prototype.setFollowState=function(f){if(this.getActionBar()){this.getActionBar().setFollowState(f)}return this};a.prototype.getFollowState=function(){var r=null;if(this.getActionBar()){r=this.getActionBar().getFollowState()}return r};a.prototype.setFlagState=function(f){if(this.getActionBar()){this.getActionBar().setFlagState(f)}return this};a.prototype.getFlagState=function(){var r=null;if(this.getActionBar()){r=this.getActionBar().getFlagState()}return r};a.prototype.setFavoriteState=function(f){if(this.getActionBar()){this.getActionBar().setFavoriteState(f)}return this};a.prototype.getFavoriteState=function(){var r=null;if(this.getActionBar()){r=this.getActionBar().getFavoriteState()}return r};a.prototype.setIcon=function(i){this._oThingViewer.setIcon(i);if(this.getActionBar()){this.getActionBar().setThingIconURI(i)}return this};a.prototype.getIcon=function(){return this._oThingViewer.getIcon()};a.prototype.setType=function(t){this._oThingViewer.setType(t);return this};a.prototype.getType=function(){return this._oThingViewer.getType()};a.prototype.insertFacetContent=function(f,i){this._oThingViewer.insertFacetContent(f,i);return this};a.prototype.addFacetContent=function(f){this._oThingViewer.addFacetContent(f);return this};a.prototype.removeFacetContent=function(f){var r=this._oThingViewer.removeFacetContent(f);return r};a.prototype.removeAllFacetContent=function(){var r=this._oThingViewer.removeAllFacetContent();return r};a.prototype.destroyFacetContent=function(){this._oThingViewer.destroyFacetContent();return this};a.prototype.getFacetContent=function(){return this._oThingViewer.getFacetContent()};a.prototype.indexOfFacetContent=function(f){return this._oThingViewer.indexOfFacetContent(f)};a.prototype.setActionBar=function(o){this._oThingViewer.setActionBar(o);return this};a.prototype.getActionBar=function(){return this._oThingViewer.getActionBar()};a.prototype.destroyActionBar=function(){this._oThingViewer.destroyActionBar()};a.prototype.insertHeaderContent=function(h,i){this._oThingViewer.insertHeaderContent(h,i);return this};a.prototype.addHeaderContent=function(h){this._oThingViewer.addHeaderContent(h);return this};a.prototype.getHeaderContent=function(){return this._oThingViewer.getHeaderContent()};a.prototype.removeHeaderContent=function(h){var r=this._oThingViewer.removeHeaderContent(h);return r};a.prototype.removeAllHeaderContent=function(){var r=this._oThingViewer.removeAllHeaderContent();return r};a.prototype.destroyHeaderContent=function(){this._oThingViewer.destroyHeaderContent();return this};a.prototype.indexOfHeaderContent=function(h){return this._oThingViewer.indexOfHeaderContent(h)};a.prototype.setSelectedFacet=function(s){this._oThingViewer.setSelectedFacet(s)};a.prototype.getSelectedFacet=function(s){return this._oThingViewer.getSelectedFacet()};a.prototype.setFavoriteActionEnabled=function(e){if(this.getActionBar()){this.getActionBar().setShowFavorite(e)}return this};a.prototype.getFavoriteActionEnabled=function(){var r;if(this.getActionBar()){r=this.getActionBar().getShowFavorite()}return r};a.prototype.setFlagActionEnabled=function(e){if(this.getActionBar()){this.getActionBar().setShowFlag(e)}return this};a.prototype.getFlagActionEnabled=function(){var r;if(this.getActionBar()){r=this.getActionBar().getShowFlag()}return r};a.prototype.setUpdateActionEnabled=function(e){if(this.getActionBar()){this.getActionBar().setShowUpdate(e)}return this};a.prototype.getUpdateActionEnabled=function(){var r;if(this.getActionBar()){r=this.getActionBar().getShowUpdate()}return r};a.prototype.setFollowActionEnabled=function(e){if(this.getActionBar()){this.getActionBar().setShowFollow(e)}return this};a.prototype.getFollowActionEnabled=function(){var r;if(this.getActionBar()){r=this.getActionBar().getShowFollow()}return r};a.prototype.setFirstTitle=function(t){this._oThingViewer.setTitle(t)};a.prototype.getFirstTitle=function(){return this._oThingViewer.getTitle()};a.prototype.setSecondTitle=function(t){this._oThingViewer.setSubtitle(t)};a.prototype.getSecondTitle=function(){return this._oThingViewer.getSubtitle()};a.prototype.setHeaderType=function(h){this._oThingViewer.setHeaderType(h);return this};a.prototype.getHeaderType=function(){var r=this._oThingViewer.getHeaderType();return r};a.prototype._applyChanges=function(c){this.oChanges=c;if(c.showOverlay){this.$().removeClass("sapUiUx3TINoFrame")}else{this.$().addClass("sapUiUx3TINoFrame")}return this}}());return a},true);
