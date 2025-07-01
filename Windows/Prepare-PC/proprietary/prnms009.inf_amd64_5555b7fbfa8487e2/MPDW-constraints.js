// PSK NameSpace's
var pskNs = "http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords";
var psk11Ns = "http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11";
var psk12Ns = "http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12";

// psf NameSpace's
var psf2Ns = "http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2";
var psfNs = "http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework";

// XML Schema NameSpace's
var xsiNs = "http://www.w3.org/2001/XMLSchema-instance";
var xsdNs = "http://www.w3.org/2001/XMLSchema";

// PDF driver NameSpace
var pdfNs = "http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf";


function completePrintCapabilities(printTicket, scriptContext, printCapabilities) {
    /// <param name="printTicket" type="IPrintSchemaTicket" mayBeNull="true">
    ///     If not 'null', the print ticket's settings are used to customize the print capabilities.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>

    // Get PrintCapabilites XML node
    var xmlCapabilities = printCapabilities.XmlNode;

    var rootCapabilities;
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(xmlCapabilities);

    rootCapabilities = xmlCapabilities.selectSingleNode("psf:PrintCapabilities");

    if (rootCapabilities != null) {
        var pdcConfig = scriptContext.QueueProperties.GetReadStreamAsXML("PrintDeviceCapabilities");
        SetStandardNameSpaces(pdcConfig);

        // Get PDC root XML Node
        var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
        // Get all ParameterDef nodes in PDC
        var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");
        // Get prefix for PDF namespace
        var pdfNsPrefix = getPrefixForNamespace(xmlCapabilities, pdfNs);

        // Convert PDC ParameterDefs Nodes to PrintCapabilites ParameterDefs Nodes
        for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
            var pdcParameterDef = parameterDefs[defCount];
            var capabilitiesParamDef = CreateCapabilitiesParamDefFromPDC(pdcParameterDef, pdfNsPrefix, printCapabilities);
            rootCapabilities.appendChild(capabilitiesParamDef);
        }
    }
}



function convertDevModeToPrintTicket(devModeProperties, scriptContext, printTicket) {
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode property bag.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted from the DevMode.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);
    // Get prefix for PDF namespace
    var pdfNsPrefix = getPrefixForNamespace(printTicket.XmlNode, pdfNs);

    // If pdf namespace prefix is not found, that means that print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (pdfNsPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Get Devmode string related to ParameterDefs in PDC
            var paramString = devModeProperties.getString(pdcParameterDefs[defCount]);

            if (paramString != null && paramString.length > 0) {
                // If Devmode string is present map to print ticket either by creating a new node or modifying the existing node 

                // Add prefix to ParameterDef base name
                var paramName = pdfNsPrefix + ":" + pdcParameterDefs[defCount];

                // Try getting the related ParameterInit in the PrintTicket
                var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], pdfNs)
                if (currNode == null) {
                    // Create node if no node is present
                    var ptRoot = printTicket.XmlNode.selectSingleNode("psf:PrintTicket");
                    var newParam = createProperty(paramName, "psf:ParameterInit", "xsd:string", paramString, printTicket);
                    ptRoot.appendChild(newParam);
                } else {
                    // Change the value of the node to Devmode string value
                    currNode.Value = paramString;
                }
            }
        }
    }
}

function convertPrintTicketToDevMode(printTicket, scriptContext, devModeProperties) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted to DevMode.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode property bag.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);

    // Get prefix for PDF namespace
    var pdfNsPrefix = getPrefixForNamespace(printTicket.XmlNode, pdfNs);

    // If pdf namespace prefix is not found, that means that print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (pdfNsPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Try getting the related ParameterInit in the PrintTicket
            var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], pdfNs)
            if (currNode != null) {
                // Set Devmode string with the value present in ParameterInit
                devModeProperties.setString(pdcParameterDefs[defCount], currNode.Value);
            }
        }
    }
}

function validatePrintTicket(printTicket, scriptContext) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be validated.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <returns type="Number" integer="true">
    ///     Integer value indicating validation status.
    ///         1 - Print ticket is valid and was not modified.
    ///         2 - Print ticket was modified to make it valid.
    ///         0 - Print ticket is invalid.
    /// </returns>

    // There is nothing wrong with having only 1, 2 or 3 ParameterInit’s in PrintTicket for the same ParameterDefs that are present in PDC. 
    // For that reason we just going to return 1 without any check
    return 1;
}

function createProperty(strPropertyName, strNodeName, strValueType, strValue, documentNode) {
    /// <summary>
    /// Create a property XML Node with child Value Node containing the value
    /// </summary>
    /// <param name="strPropertyName" type="String">
    ///   Name of the property Node
    /// </param>
    /// <param name="strNodeName" type="String">
    ///   Name to be assigned to the "name" attribute of the property
    /// </param>
    /// <param name="strValueType" type="String">
    ///   Type of the value the in the Value Node
    /// </param>
    /// <param name="strValue" type="String">
    ///   Actual value that is to be placed in the value node
    /// </param>
    /// <param name="documentNode" type="IXMLNode">
    ///   Contains Document XML Node
    /// </param>

    var newNode = documentNode.XmlNode.createNode(1, strNodeName, psfNs);
    newNode.setAttribute("name", strPropertyName);

    if (strValueType.length > 0) {
        var newProp = documentNode.XmlNode.createNode(1, "psf:Value", psfNs);
        var newAttr = documentNode.XmlNode.createNode(2, "xsi:type", xsiNs);
        newAttr.nodeValue = strValueType;
        newProp.setAttributeNode(newAttr);

        var newText = documentNode.XmlNode.createTextNode(strValue);

        newProp.appendChild(newText);

        newNode.appendChild(newProp);
    }
    return newNode;
}


function getParameterDefs(scriptContext) {
    /// <summary>
    /// Get the base names for the ParameterDefs defined in the JS file
    /// </summary>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>

    // Get PDC configuration file from script context
    var pdcConfig = scriptContext.QueueProperties.GetReadStreamAsXML("PrintDeviceCapabilities");
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(pdcConfig);

    // Get PDC root XML Node
    var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
    // Get all ParameterDef nodes in PDC
    var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");

    // Make an array containing all base names for all the ParameterDef's
    var pdcParameterDefs = new Array();
    for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
        pdcParameterDefs[defCount] = parameterDefs[defCount].baseName;
    }
    return pdcParameterDefs;
}

function CreateCapabilitiesParamDefFromPDC(pdcParameterDef, pdfNsPrefix, printCapabilities) {
    /// <summary>
    /// Converts ParameterDef Node that in PDC into ParameterDef node in PrintCapabilites
    /// </summary>
    /// <param name="pdcParameterDef" type="IXMLNode">
    ///     Contains a ParameterDef node in PDC
    /// </param>
    /// <param name="pdfNsPrefix" type="string">
    ///     Contains PDF name sapce
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>
    var capabilitiesParamDef = createProperty(pdfNsPrefix + ":" + pdcParameterDef.baseName, "psf:ParameterDef", "", "", printCapabilities);

    var properties = pdcParameterDef.selectNodes("*[@psf2:psftype='Property']");


    for (var propCount = 0; propCount < properties.length; propCount++) {
        var property = properties[propCount];
        var type = property.getAttribute("xsi:type");
        var childProperty = createProperty(property.nodeName, "psf:Property", type, property.text, printCapabilities);
        capabilitiesParamDef.appendChild(childProperty);
    }
    return capabilitiesParamDef;
}


function SetStandardNameSpaces(xmlNode) {
    /// <summary>
    /// Set the Selection namespace values to below namesapces
    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' 
    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' 
    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' 
    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'
    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'
    /// xmlns:xsd='http://www.w3.org/2001/XMLSchema'
    /// xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'
    ///</summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>

    xmlNode.setProperty(
        "SelectionNamespaces",
        "xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' "
            + "xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' "
            + "xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' "
            + "xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' "
            + "xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' "
            + "xmlns:xsd='http://www.w3.org/2001/XMLSchema' "
            + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
            + "xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' "
        );
}


function getPrefixForNamespace(node, namespace) {
    /// <summary>
    ///     This function returns the prefix for a given namespace.
    ///     Example: In 'psf:printTicket', 'psf' is the prefix for the namespace.
    ///     xmlns:psf="http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework"
    /// </summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>
    /// <param name="namespace" type="String">
    ///     The namespace for which prefix is returned.
    /// </param>
    /// <returns type="String">
    ///     Returns the namespace corresponding to the prefix.
    /// </returns>

    if (!node) {
        return null;
    }

    // Navigate to the root element of the document.
    var rootNode = node.documentElement;

    // Query to retrieve the list of attribute nodes for the current node
    // that matches the namespace in the 'namespace' variable.
    var xPathQuery = "namespace::node()[.='"
                + namespace
                + "']";
    var namespaceNode = rootNode.selectSingleNode(xPathQuery);

    var prefix;
    if (namespaceNode != null){
        prefix = namespaceNode.baseName;
    }

    return prefix;
}