/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./ColumnListItem','./P13nPanel','./P13nColumnsItem','./SearchField','./Table','./library','sap/ui/core/Control'],function(q,C,P,a,S,T,l,b){"use strict";var c=P.extend("sap.m.P13nColumnsPanel",{metadata:{library:"sap.m",aggregations:{columnsItems:{type:"sap.m.P13nColumnsItem",multiple:true,singularName:"columnsItem",bindable:"bindable"}},events:{addColumnsItem:{parameters:{newItem:{type:"sap.m.P13nColumnsItem"}}},removeColumnsItem:{item:{type:"sap.m.P13nColumnsItem"}}}}});c.prototype._ItemMoveToTop=function(){var o=-1,n=-1,i=null,t=null;if(this._oSelectedItem){i=this._oSelectedItem.data('P13nColumnKey');t=this._oTable.getItems();o=this._getArrayIndexByItemKey(i,t);n=o;if(o>0){n=0}if(n!=-1&&o!=-1&&o!=n){this._moveItem(o,n)}}};c.prototype._ItemMoveUp=function(){var o=-1,n=-1,i=null,t=null;if(this._oSelectedItem){i=this._oSelectedItem.data('P13nColumnKey');t=this._oTable.getItems();o=this._getArrayIndexByItemKey(i,t);n=o;if(o>0){if(this._bShowSelected===true){n=this._getPreviousSelectedItemIndex(o)}else{n=o-1}}if(n!=-1&&o!=-1&&o!=n){this._moveItem(o,n)}}};c.prototype._ItemMoveDown=function(){var o=-1,n=-1,i=null,t=null;var d=null;if(this._oSelectedItem){d=this._oTable.getItems().length;i=this._oSelectedItem.data('P13nColumnKey');t=this._oTable.getItems();o=this._getArrayIndexByItemKey(i,t);n=o;if(o<d-1){if(this._bShowSelected===true){n=this._getNextSelectedItemIndex(o)}else{n=o+1}}if(n!=-1&&o!=-1&&o!=n){this._moveItem(o,n)}}};c.prototype._ItemMoveToBottom=function(){var o=-1,n=-1,i=null,t=null;var d=null;if(this._oSelectedItem){d=this._oTable.getItems().length;i=this._oSelectedItem.data('P13nColumnKey');t=this._oTable.getItems();o=this._getArrayIndexByItemKey(i,t);n=o;if(o<d){n=d-1}if(n!=-1&&o!=-1&&o!=n){this._moveItem(o,n)}}};c.prototype._moveItem=function(o,n){var m=null;var L=-1;if(o!==null&&n!==null&&o!=n){m=this._oTable.getItems();if(m&&m.length){L=m.length;if(o>-1&&o<=L-1&&n>-1&&n<=L-1){this._handleMoveItem(this._oSelectedItem,m[n])}}}};c.prototype._handleMoveItem=function(o,n){var t,i=0;var O=null,N=null;var s=null,d=null;if(n===null||o===null){return}if(this._oTable!==null){O=this._oTable.indexOfItem(o);N=this._oTable.indexOfItem(n)}if(O!==null&&N!==null&&(Math.abs(O-N)==1)){this._handleItemIndexChanged(o,N);this._handleItemIndexChanged(n,O)}else{t=this._oTable.getItems();if(t&&t.length){if(O>N){for(i=O;i>N;i--){s=this._oTable.getItems()[i];d=this._oTable.getItems()[i-1];this._handleItemIndexChanged(s,i-1);this._handleItemIndexChanged(d,i)}}else{for(i=O;i<N;i++){s=this._oTable.getItems()[i];d=this._oTable.getItems()[i+1];this._handleItemIndexChanged(s,i+1);this._handleItemIndexChanged(d,i)}}}}this._afterMoveItem()};c.prototype._afterMoveItem=function(){this._scrollToSelectedItem(this._oSelectedItem);this._calculateMoveButtonAppearance()};c.prototype._swopShowSelectedButton=function(){var n;this._bShowSelected=!this._bShowSelected;if(this._bShowSelected){n=this._oRb.getText('COLUMNSPANEL_SHOW_ALL')}else{n=this._oRb.getText('COLUMNSPANEL_SHOW_SELECTED')}this._oShowSelectedButton.setText(n);this._filterItems();if(this._oSelectedItem&&this._oSelectedItem.getVisible()!==true){this._deactivateSelectedItem()}this._fnHandleResize()};c.prototype._filterItems=function(){var s=null,t=null;var L=0,d=0,i=0,j=0;var I=null,o=null;var e,f;var g=null,h=null,r=null;if(this._bShowSelected){s=this._oTable.getSelectedItems()}else{s=this._oTable.getItems()}if(this._bSearchFilterActive){h=this._oSearchField.getValue();if(h!==null){r=new RegExp(h,'igm')}}t=this._oTable.getItems();L=t.length;for(i=0;i<L;i++){I=t[i];e=true;f=false;if(this._bSearchFilterActive){e=false;g=I.getCells()[0].getText();if(g&&r!==null&&g.match(r)!==null){e=true}if(e!==true&&I.getTooltip_Text){g=(I.getTooltip()instanceof sap.ui.core.TooltipBase?I.getTooltip().getTooltip_Text():I.getTooltip_Text());if(g&&r!==null&&g.match(r)!==null){e=true}}}d=s.length;for(j=0;j<d;j++){o=s[j];if(o){if(o.getId()==I.getId()){f=true;break}}}I.setVisible(f&&e)}};c.prototype._executeSearch=function(){var v=this._oSearchField.getValue();var L=v.length||0;if(L>0){this._bSearchFilterActive=true;this._deactivateSelectedItem()}else{this._bSearchFilterActive=false}this._filterItems()};c.prototype._getPreviousSelectedItemIndex=function(s){var r=-1,i=0;var t=this._oTable.getItems(),o=null;if(s!==null&&s!==undefined&&s>0){if(t&&t.length>0){for(i=s-1;i>=0;i--){o=t[i];if(o&&o.getSelected()===true){r=i;break}}}}return r};c.prototype._getNextSelectedItemIndex=function(s){var r=-1,i=0,L=null;var t=this._oTable.getItems(),o=null;if(t&&t.length>0){L=t.length;if(s!==null&&s!==undefined&&s>=0&&s<L-1){for(i=s+1;i<L;i++){o=t[i];if(o&&o.getSelected()===true){r=i;break}}}}return r};c.prototype._updateSelectAllDescription=function(e){var t=this._oTable.getItems().length;var s=this._oTable.getSelectedContexts(true).length;var d=null;var o=this._oTable.getColumns()[0];if(o){d=this._oRb.getText('COLUMNSPANEL_SELECT_ALL');if(s&&s>0){d=this._oRb.getText('COLUMNSPANEL_SELECT_ALL_WITH_COUNTER',[s,t])}o.getHeader().setText(d)}if(this._bShowSelected){this._filterItems()}};c.prototype._itemPressed=function(e){var n=null;if(this._bSearchFilterActive===true){return}if(this._oSelectedItem!==null&&this._oSelectedItem!==undefined){this._removeHighLightingFromItem(this._oSelectedItem)}n=e.getParameter('listItem');if(n!=this._oSelectedItem){this._oSelectedItem=n;this._setHighLightingToItem(this._oSelectedItem)}else{this._oSelectedItem=null}this._calculateMoveButtonAppearance()};c.prototype._calculateMoveButtonAppearance=function(){var i=null,t=null;var L=-1,I=-1;var m=false,M=false;if(this._oSelectedItem!==null&&this._oSelectedItem!==undefined){i=this._oSelectedItem.data('P13nColumnKey');if(this._bShowSelected===true){t=this._oTable.getSelectedItems()}else{t=this._oTable.getItems()}I=this._getArrayIndexByItemKey(i,t);if(I!==-1){if(t&&t.length){L=t.length}if(I===0){M=true}else if(I===L-1){m=true}else if(I>0&&I<L-1){M=true;m=true}}}else{m=M=false}if(this._oMoveToTopButton.getEnabled()!==m){this._oMoveToTopButton.setEnabled(m);this._oMoveToTopButton.rerender()}if(this._oMoveUpButton.getEnabled()!==m){this._oMoveUpButton.setEnabled(m);this._oMoveUpButton.rerender()}if(this._oMoveDownButton.getEnabled()!==M){this._oMoveDownButton.setEnabled(M);this._oMoveDownButton.rerender()}if(this._oMoveToBottomButton.getEnabled()!==M){this._oMoveToBottomButton.setEnabled(M);this._oMoveToBottomButton.rerender()}};c.prototype._setHighLightingToItem=function(i){if(i!==null&&i!==undefined&&i.addStyleClass){i.addStyleClass("sapMP13nColumnsPanelItemSelected")}};c.prototype._removeHighLightingFromItem=function(i){if(i!==null&&i!==undefined&&i.removeStyleClass){i.removeStyleClass("sapMP13nColumnsPanelItemSelected")}};c.prototype._deactivateSelectedItem=function(){if(this._oSelectedItem){this._removeHighLightingFromItem(this._oSelectedItem);this._oSelectedItem=null;this._calculateMoveButtonAppearance()}};c.prototype._getArrayIndexByItemKey=function(I,d){var r=-1;var L=0,i=0;var o=null,s=null;if(I!==null&&I!==undefined&&I!==""){if(d&&d.length>0){L=d.length;for(i=0;i<L;i++){s=null;o=d[i];if(o){if(o.getColumnKey){s=o.getColumnKey()}else{s=o.data('P13nColumnKey')}if(s!==null&&s!==undefined&&s!==""){if(s===I){r=i;break}}}}}}return r};c.prototype._scrollToSelectedItem=function(i){var e;if(i){sap.ui.getCore().applyChanges();if(!!i.getDomRef()){e=i.$().position().top;this._oScrollContainer.scrollTo(0,e)}}};c.prototype._handleItemIndexChanged=function(i,n){var I=null,d=null;var e,o=null;I=i.data('P13nColumnKey');e=this.getColumnsItems();d=this._getArrayIndexByItemKey(I,e);if(d!==null&&d!==undefined&&d!==-1){o=e[d]}if(o===null){o=this._createNewColumnsItem(I);o.setIndex(n);this.fireAddColumnsItem({newItem:o})}else{o.setIndex(n);this._updateTableItems(o)}this._condenseColumnsItem(o)};c.prototype._handleItemVisibilityChanged=function(i){var I=null,d=null;var e,o=null;I=i.data('P13nColumnKey');e=this.getColumnsItems();d=this._getArrayIndexByItemKey(I,e);if(d!==null&&d!==undefined&&d!==-1){o=e[d]}if(o===null){o=this._createNewColumnsItem(I);o.setVisible(i.getSelected());this.fireAddColumnsItem({newItem:o})}else{o.setVisible(i.getSelected());this._updateTableItems(o)}this._condenseColumnsItem(o)};c.prototype._createNewColumnsItem=function(i){var n=new sap.m.P13nColumnsItem({"columnKey":i});return n};c.prototype._getColumnsItemByKey=function(i){var d=null;var e=-1,o=null;if(i!==null&&i!==undefined&&i!==""){d=this.getColumnsItems();e=this._getArrayIndexByItemKey(i,d);if(e!==null&&e>-1){o=d[e]}}return o};c.prototype._condenseColumnsItem=function(o){var p=null;var d=null,i=null,e=null,r=false;if(o!==null){p=this.getItems();i=o.getColumnKey();e=this._getArrayIndexByItemKey(i,p);if(e!==null&&e!==undefined&&e>-1){d=p[e];if(d!==null){r=this._isColumnsItemEqualToPanelItem(o,d);if(r){this.fireRemoveColumnsItem({item:o})}}}}};c.prototype._isColumnsItemEqualToPanelItem=function(o,p){var v=false,i=false,d=null;var e=null;if(o!==null&&p!==null){if(o.getVisible()===undefined||o.getVisible()===null){v=true}else{if(o.getVisible()===p.getVisible()){v=true;delete o.mProperties.visible}}if(o.getIndex()===undefined||o.getIndex()===null){i=true}else{if(p.getParent){e=p.getParent();if(e&&e.indexOfItem){d=e.indexOfItem(p)}}if(d!=null&&d!=undefined&&o.getIndex()===d){i=true;delete o.mProperties.index}}}return v&&i};c.prototype._updateTableItems=function(o){var t=null,i,d=null;var e=null,s=null;if(o){e=[];e.push(o)}else{e=this.getColumnsItems()}t=this._oTable.getItems();if(t&&t.length>0){e.forEach(function(o){s=o.getColumnKey();i=this._getArrayIndexByItemKey(s,t);if(i!==-1){d=t[i];this._applyColumnsItem2TableItem(o,d)}},this)}};c.prototype._applyColumnsItem2TableItem=function(o,t){var d=this._oTable.getItems();var m=0,r=null,i;if(o&&t&&d&&d.length>0){m=d.length;i=d.indexOf(t);if(o.getIndex()!==undefined&&i!==o.getIndex()&&o.getIndex()<=m){r=this._oTable.removeItem(t);this._oTable.insertItem(r,o.getIndex())}if(o.getVisible()!==undefined&&t.getSelected()!==o.getVisible()){t.setSelected(o.getVisible())}}};c.prototype.init=function(){var L=0;var t=this;this._bOnAfterRenderingFirstTimeExecuted=false;this.setVerticalScrolling(false);this._fnHandleResize=function(){if(t.getParent){var p=t.getParent();var $=q("#"+p.getId()+"-cont");if($.children().length>0&&t._oToolbar.$().length>0){var i=$.children()[0].clientHeight;var h=t._oToolbar?t._oToolbar.$()[0].clientHeight:0;t._oScrollContainer.setHeight((i-h)+'px')}}};this._oRb=sap.ui.getCore().getLibraryResourceBundle("sap.m");this._oMoveToTopButton=new sap.m.Button({icon:sap.ui.core.IconPool.getIconURI("collapse-group"),tooltip:this._oRb.getText('COLUMNSPANEL_MOVE_TO_TOP'),press:function(){t._ItemMoveToTop()}});this._oMoveUpButton=new sap.m.Button({icon:sap.ui.core.IconPool.getIconURI("slim-arrow-up"),tooltip:this._oRb.getText('COLUMNSPANEL_MOVE_UP'),press:function(){t._ItemMoveUp()}});this._oMoveDownButton=new sap.m.Button({icon:sap.ui.core.IconPool.getIconURI("slim-arrow-down"),tooltip:this._oRb.getText('COLUMNSPANEL_MOVE_DOWN'),press:function(){t._ItemMoveDown()}});this._oMoveToBottomButton=new sap.m.Button({icon:sap.ui.core.IconPool.getIconURI("expand-group"),tooltip:this._oRb.getText('COLUMNSPANEL_MOVE_TO_BOTTOM'),press:function(){t._ItemMoveToBottom()}});this._oShowSelectedButton=new sap.m.Button({text:this._oRb.getText('COLUMNSPANEL_SHOW_SELECTED'),press:function(){t._swopShowSelectedButton()}});this._bShowSelected=false;this._bSearchFilterActive=false;this._oSearchField=new S(this.getId()+"-searchField",{width:"100%",liveChange:function(e){var v=e.getSource().getValue(),d=(v?300:0);window.clearTimeout(L);if(d){L=window.setTimeout(function(){t._executeSearch()},d)}else{t._executeSearch()}},search:function(e){t._executeSearch()}});this._oToolbar=new sap.m.Toolbar({active:true,design:sap.m.ToolbarDesign.Solid,content:[this._oMoveToTopButton,this._oMoveUpButton,this._oMoveDownButton,this._oMoveToBottomButton,this._oSearchField,this._oShowSelectedButton]});this._oTable=new T({mode:sap.m.ListMode.MultiSelect,rememberSelections:false,itemPress:function(e){t._itemPressed(e)},selectionChange:function(e){var o=e.getParameter('listItem');t._handleItemVisibilityChanged(o);t._updateSelectAllDescription(e)},columns:[new sap.m.Column({header:new sap.m.Text({text:this._oRb.getText('COLUMNSPANEL_SELECT_ALL')})})]});this._oScrollContainer=new sap.m.ScrollContainer({horizontal:false,vertical:true,content:[this._oTable],width:'100%',height:'100%'});this._oScrollContainer.setParent(this)};c.prototype.onAfterRendering=function(){var L=0;var t=this;if(!this._bOnAfterRenderingFirstTimeExecuted){this._bOnAfterRenderingFirstTimeExecuted=true;this._calculateMoveButtonAppearance();sap.ui.Device.resize.attachHandler(this._fnHandleResize)}window.clearTimeout(L);L=window.setTimeout(function(){t._fnHandleResize()},0);this._updateSelectAllDescription()};c.prototype.exit=function(){sap.ui.Device.resize.detachHandler(this._fnHandleResize);this._oMoveToTopButton.destroy();this._oMoveToTopButton=null;this._oMoveDownButton.destroy();this._oMoveDownButton=null;this._oMoveUpButton.destroy();this._oMoveUpButton=null;this._oMoveToBottomButton.destroy();this._oMoveToBottomButton=null;this._oSearchField.destroy();this._oSearchField=null;this._oToolbar.destroy();this._oToolbar=null;this._oTable.destroy();this._oTable=null};c.prototype.addItem=function(i){P.prototype.addItem.apply(this,arguments);var o=null;var n=null,s=null;if(i){s=i.getColumnKey();o=this._getColumnsItemByKey(s);n=new sap.m.ColumnListItem({cells:[new sap.m.Text({text:i.getText()})],visible:true,selected:i.getVisible(),tooltip:i.getTooltip(),type:sap.m.ListType.Active});n.data('P13nColumnKey',s);if(o){n.setVisible(o.getVisible());this._oTable.insertItem(n,o.getIndex())}else{this._oTable.addItem(n)}}};c.prototype.removeItem=function(i){P.prototype.removeItem.apply(this,arguments);var t=null,I=null,d=null,s=null;if(i){s=i.getColumnKey();d=this._oTable.getItems();if(d&&d.length>0&&s!==null&&s!==""){I=this._getArrayIndexByItemKey(s,d);if(I!==null&&I!==-1){t=d[I];if(t){this._oTable.removeItem(t)}}}}};c.prototype.destroyItems=function(){this.destroyAggregation("items");this._oTable.destroyItems();return this};c.prototype.addColumnsItem=function(o){this.addAggregation("columnsItems",o);this._updateTableItems(o)};c.prototype.removeColumnsItem=function(o){var i=null;this.removeAggregation("columnsItems",o);this._oTable.removeAllItems();i=this.getItems();i.forEach(function(I){this._oTable.addItem(I)},this);this._updateTableItems()};return c},true);