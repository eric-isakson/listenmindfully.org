jQuery.sap.require('sap.m.MessageToast');

sap.ui.controller('listenmindfully.ui.Main', {

    onInit: function () {
//        var oData = {};
//        var currentUserResponse = jQuery.sap.syncGetJSON('./api/user/current', {});
//        if (currentUserResponse.success) {
//            oData.user = currentUserResponse.data;
//        }
//        else {
//            // TODO we aren't logged in, need to present the login view
//        }
//        oData.logo = jQuery.sap.getModulePath('listenmindfully.ui', '/') + 'mimes/logo/logo_50x26.png';
//        var oModel = new sap.ui.model.json.JSONModel();
//        oModel.setData(oData);
//
//        this.getView().setModel(oModel);
    },

    handlePressConfiguration: function (oEvent) {
        var oItem = oEvent.getSource();
        var oShell = this.getView().byId('myShell');
        var bState = oShell.getShowPane();
        oShell.setShowPane(!bState);
        oItem.setShowMarker(!bState);
        oItem.setSelected(!bState);
    },

    handleLogoffPress: function (oEvent) {
        window.location = './auth/logout'; // TODO what happened to this API? sap.m.URLHelper.redirect('./auth/logout');
    },

    handleUserItemPressed: function (oEvent) {
        sap.m.MessageToast.show('User Button Pressed');
    },

    handleShellOverlayClosed: function () {
        sap.m.MessageToast.show('Overlay closed');
    },

    handleSearchPressed: function (oEvent) {
        var sQuery = oEvent.getParameter('query');
        if (sQuery === '') {
            return;
        }

        // create Overlay only once
        if (!this._overlay) {
            this._overlay = sap.ui.xmlfragment(
                'listenmindfully.ui.ShellOverlay',
                this
            );
            this.getView().addDependent(this._overlay);
        }

        // mock data
        var aResultData = [];
        for (var i = 0; i < 10; i++) {
            aResultData.push({
                title: (i + 1) + '. ' + sQuery,
                text: 'Lorem ipsum sit dolem'
            });
        }
        var oData = {
            searchFieldContent: sQuery,
            resultData: aResultData
        };
        var oModel = new sap.ui.model.json.JSONModel();
        oModel.setData(oData);
        this._overlay.setModel(oModel);

        // set reference to shell and open overlay
        this._overlay.setShell(this.getView().byId('myShell'));
        this._overlay.open();
    }
});