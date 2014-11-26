/**
 * Initialization Code and shared classes of library listenmindfully.ui (1.0.0)
 */
jQuery.sap.declare('listenmindfully.ui');
jQuery.sap.require('sap.ui.core.Core');
/**
 * OpenUI5 library with controls specialized for the listenmindfully.org website.
 *
 * @namespace
 * @name listenmindfully.ui
 * @public
 */


// library dependencies
jQuery.sap.require('sap.ui.core.library');
jQuery.sap.require('sap.m.library');
jQuery.sap.require('sap.ui.unified.library');
jQuery.sap.require('sap.ui.layout.library');

// delegate further initialization of this library to the Core
sap.ui.getCore().initLibrary({
    name: 'listenmindfully.ui',
    dependencies: ['sap.ui.core', 'sap.m', 'sap.ui.unified', 'sap.ui.layout'],
    types: [
    ],
    interfaces: [
    ],
    controls: [
        'listenmindfully.ui.Shell'
    ],
    elements: [
    ],
    version: '1.0.0'
});
