/*!
 * SAP UI development toolkit for HTML5 (SAPUI5/OpenUI5)
 * (c) Copyright 2009-2014 SAP SE or an SAP affiliate company.
 * Licensed under the Apache License, Version 2.0 - see LICENSE.txt.
 */
sap.ui.define(['jquery.sap.global','./Input','./Token','./library','sap/ui/core/Item'],function(q,I,T,l,a){"use strict";var M=I.extend("sap.m.MultiInput",{metadata:{library:"sap.m",aggregations:{tokens:{type:"sap.m.Token",multiple:true,singularName:"token"},tokenizer:{type:"sap.m.Tokenizer",multiple:false,visibility:"hidden"}},events:{tokenChange:{parameters:{type:{type:"string"},token:{type:"sap.m.Token"},tokens:{type:"sap.m.Token[]"},addedTokens:{type:"sap.m.Token[]"},removedTokens:{type:"sap.m.Token[]"}}}}}});M.prototype.init=function(){var t=this;I.prototype.init.call(this);this._bIsValidating=false;this._tokenizer=new sap.m.Tokenizer();this.setAggregation("tokenizer",this._tokenizer);this._tokenizer.attachTokenChange(function(b){t.fireTokenChange(b.getParameters());t.invalidate();t._setContainerSizes();if(b.getParameter("type")==="tokensChanged"&&b.getParameter("removedTokens").length>0){t.focus()}});this.setShowValueHelp(true);this.setShowSuggestion(true);this.addStyleClass("sapMMultiInput");this.attachSuggestionItemSelected(function(e){var i=null;var b=null;if(this._hasTabularSuggestions()){i=e.getParameter("selectedRow")}else{i=e.getParameter("selectedItem");if(i){b=new T({text:i.getText(),key:i.getKey()})}}if(i){var c=this.getValue();t._tokenizer.addValidateToken({text:c,token:b,suggestionObject:i,validationCallback:function(v){if(v){t.setValue("")}}})}});this.attachLiveChange(function(e){t._tokenizer.removeSelectedTokens();t._setContainerSizes()});sap.ui.Device.orientation.attachHandler(this._onOrientationChange,this);if(this._tokenizer._bDoTouchScroll&&this._oSuggestionPopup){this._oSuggestionPopup.attachAfterClose(function(){setTimeout(function(){t.setValue("");t._tokenizer.scrollToEnd()},0)})}};M.prototype._onOrientationChange=function(){this._setContainerSizes()};M.prototype.getScrollDelegate=function(){return this._tokenizer._oScroller};M.prototype.exit=function(){I.prototype.exit.apply(this,arguments);if(this._sResizeHandlerId){sap.ui.core.ResizeHandler.deregister(this._sResizeHandlerId);delete this._sResizeHandlerId}};M.prototype._setContainerSizes=function(){var t=this.getDomRef();if(!t){return}var $=this.$();q($.find(".sapMInputBaseInner")[0]).removeAttr("style");var b=$.find(".sapMMultiInputBorder").width();var s=$.children(".sapMMultiInputShadowDiv")[0];q(s).text(this.getValue());var i=q(s).width();var c=this._tokenizer.getScrollWidth();var d=$.find(".sapMInputValHelp").outerWidth(true);var e=c+i+d;var f;var g=1;if(e<b){f=i+b-e}else{f=i+g;c=b-f-d}q($.find(".sapMInputBaseInner")[0]).css("width",f+"px");this._tokenizer.setPixelWidth(c);if(this.getPlaceholder()){this._sPlaceholder=this.getPlaceholder()}if(this.getTokens().length>0){this.setPlaceholder("")}else{this.setPlaceholder(this._sPlaceholder)}};M.prototype.onAfterRendering=function(){var t=this;I.prototype.onAfterRendering.apply(this,arguments);this._setContainerSizes();this._sResizeHandlerId=sap.ui.core.ResizeHandler.register(this.getDomRef(),function(){t._setContainerSizes()})};M.prototype.addValidator=function(v){this._tokenizer.addValidator(v)};M.prototype.removeValidator=function(v){this._tokenizer.removeValidator(v)};M.prototype.removeAllValidators=function(){this._tokenizer.removeAllValidators()};M.prototype.onsapnext=function(e){if(e.isMarked()){return}var f=q(document.activeElement).control()[0];if(!f){return}if(this._tokenizer===f||this._tokenizer.$().find(f.$()).length>0){this._scrollAndFocus()}};M.prototype.onsapbackspace=function(e){if(this.getCursorPosition()>0||!this.getEditable()||this.getValue().length>0){return}sap.m.Tokenizer.prototype.onsapbackspace.apply(this._tokenizer,arguments);e.preventDefault();e.stopPropagation()};M.prototype.onsapdelete=function(e){if(!this.getEditable()){return}if(this.getValue()&&!this._completeTextIsSelected()){return}sap.m.Tokenizer.prototype.onsapdelete.apply(this._tokenizer,arguments)};M.prototype.onkeydown=function(e){if((e.ctrlKey||e.metaKey)&&e.which===q.sap.KeyCodes.A){if(document.activeElement===this._$input[0]){if(this._$input.getSelectedText()!==this.getValue()){this.selectText(0,this.getValue().length)}else if(this._tokenizer){this._tokenizer.selectAllTokens(true)}}else if(document.activeElement===this._tokenizer.$()[0]){if(this._tokenizer._iSelectedToken===this._tokenizer.getTokens().length){this.selectText(0,this.getValue().length)}}e.preventDefault()}};M.prototype.onsapprevious=function(e){if(this._getIsSuggestionPopupOpen()){return}if(this.getCursorPosition()===0){if(e.srcControl===this){sap.m.Tokenizer.prototype.onsapprevious.apply(this._tokenizer,arguments);e.preventDefault()}}};M.prototype._scrollAndFocus=function(){this._tokenizer.scrollToEnd();this.$().find("input").focus()};M.prototype.onsaphome=function(e){sap.m.Tokenizer.prototype.onsaphome.apply(this._tokenizer,arguments)};M.prototype.onsapend=function(e){sap.m.Tokenizer.prototype.onsapend.apply(this._tokenizer,arguments);e.preventDefault()};M.prototype.onsapenter=function(e){this._validateCurrentText();if(I.prototype.onsapenter){I.prototype.onsapenter.apply(this,arguments)}};M.prototype.onsapfocusleave=function(e){var p=this._oSuggestionPopup;var n=false;var N=false;if(p instanceof sap.m.Popover){if(e.relatedControlId){n=q.sap.containsOrEquals(p.getFocusDomRef(),sap.ui.getCore().byId(e.relatedControlId).getFocusDomRef());N=q.sap.containsOrEquals(this._tokenizer.getFocusDomRef(),sap.ui.getCore().byId(e.relatedControlId).getFocusDomRef())}}if(!N&&!n){this._setContainerSizes();this._tokenizer.scrollToEnd()}if(this._bIsValidating){if(I.prototype.onsapfocusleave){I.prototype.onsapfocusleave.apply(this,arguments)}return}if(I.prototype.onsapfocusleave){I.prototype.onsapfocusleave.apply(this,arguments)}if(!n&&e.relatedControlId!==this.getId()&&e.relatedControlId!==this._tokenizer.getId()&&!N){this._validateCurrentText(true)}sap.m.Tokenizer.prototype.onsapfocusleave.apply(this._tokenizer,arguments)};M.prototype.ontap=function(e){I.prototype.ontap.apply(this,arguments);if(document.activeElement===this._$input[0]){this._tokenizer.selectAllTokens(false)}};M.prototype.onsapescape=function(e){this._tokenizer.selectAllTokens(false);this.selectText(0,0);I.prototype.onsapescape.apply(this,arguments)};M.prototype._validateCurrentText=function(e){var t=this.getValue();if(!t||!this.getEditable()){return}t=t.trim();if(!t){return}var i=null;if(e||this._getIsSuggestionPopupOpen()){if(this._hasTabularSuggestions()){i=this._oSuggestionTable._oSelectedItem}else{i=this._getSuggestionItem(t,e)}}var b=null;if(i&&i.getText&&i.getKey){b=new T({text:i.getText(),key:i.getKey()})}var c=this;this._bIsValidating=true;this._tokenizer.addValidateToken({text:t,token:b,suggestionObject:i,validationCallback:function(v){c._bIsValidating=false;if(v){c.setValue("")}}})};M.prototype.getCursorPosition=function(){return this._$input.cursorPos()};M.prototype._completeTextIsSelected=function(){var i=this._$input[0];if(i.selectionStart!==0){return false}if(i.selectionEnd!==this.getValue().length){return false}return true};M.prototype._selectAllInputText=function(){var i=this._$input[0];i.selectionStart=0;i.selectionEnd=this.getValue().length;return this};M.prototype._getIsSuggestionPopupOpen=function(){return this._oSuggestionPopup&&this._oSuggestionPopup.isOpen()};M.prototype.setEditable=function(e){if(e===this.getEditable()){return this}if(I.prototype.setEditable){I.prototype.setEditable.apply(this,arguments)}this._tokenizer.setEditable(e);if(e){this.removeStyleClass("sapMMultiInputNotEditable")}else{this.addStyleClass("sapMMultiInputNotEditable")}return this};M.prototype._findItem=function(t,b,e,g){if(!t){return}if(!(b&&b.length)){return}t=t.toLowerCase();var c=b.length;for(var i=0;i<c;i++){var d=b[i];var f=g(d);if(!f){continue}f=f.toLowerCase();if(f===t){return d}if(!e&&f.indexOf(t)===0){return d}}};M.prototype._getSuggestionItem=function(t,e){var b=null;var c=null;if(this._hasTabularSuggestions()){b=this.getSuggestionRows();c=this._findItem(t,b,e,function(r){var d=r.getCells();var f=null;if(d){var i;for(i=0;i<d.length;i++){if(d[i].getText){f=d[i].getText();break}}}return f})}else{b=this.getSuggestionItems();c=this._findItem(t,b,e,function(c){return c.getText()})}return c};M.prototype.addToken=function(t){return this._tokenizer.addToken(t)};M.prototype.removeToken=function(t){return this._tokenizer.removeToken(t)};M.prototype.removeAllTokens=function(){return this._tokenizer.removeAllTokens()};M.prototype.getTokens=function(){return this._tokenizer.getTokens()};M.prototype.insertToken=function(t,i){return this._tokenizer.insertToken(t,i)};M.prototype.indexOfToken=function(t){return this._tokenizer.indexOfToken(t)};M.prototype.destroyTokens=function(){return this._tokenizer.destroyTokens()};M.prototype.clone=function(){var c=I.prototype.clone.apply(this,arguments);var t=this.getTokens();var i;for(i=0;i<t.length;i++){var n=t[i].clone();c.addToken(n)}return c};M.prototype.getPopupAnchorDomRef=function(){return this.getDomRef("border")};M.prototype.setTokens=function(t){this._tokenizer.setTokens(t)};M.TokenChangeType={Added:"added",Removed:"removed",RemovedAll:"removedAll"};M.WaitForAsyncValidation="sap.m.Tokenizer.WaitForAsyncValidation";M.prototype.getDomRefForValueStateMessage=M.prototype.getPopupAnchorDomRef;return M},true);