(function () {
    function getCurrentUser() {
        var oCurrentUserResponse = jQuery.sap.syncGetJSON('./api/user/current', {});
        if (oCurrentUserResponse.success) {
            return oCurrentUserResponse.data;
        }
        return null;
    }

    function onLogin(user) {
        var eBody = jQuery('body')
            , oData = {
                logo: jQuery.sap.getModulePath('listenmindfully.ui', '/') + 'mimes/logo/logo_50x26.png',
                user: user
            }
            , oModel = new sap.ui.model.json.JSONModel(oData)
            , oListenMindfully;
        sap.ui.getCore().setModel(oModel);
        var oListenMindfully = sap.ui.xmlview('listenmindfully', 'listenmindfully.ui.Shell');
        oListenMindfully.placeAt(eBody, 'only');
    }

    var currentUser = getCurrentUser();
    if (currentUser) {
        onLogin(currentUser);
    }
})();
