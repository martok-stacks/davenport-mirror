<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html"/>

<xsl:param name="version" select="''"/>

<xsl:template match="/">
<html>
<head>
<title>
    <xsl:text>Davenport Change Log</xsl:text>
    <xsl:if test="$version">
        <xsl:text> - Version </xsl:text>
        <xsl:value-of select="$version"/>
    </xsl:if>
</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css"/>
<style type="text/css">
    .hidden {
        display: none;
    }

    .shown {
        display: block;
        border-left: 1px dotted #bbccaa;
        border-right: 1px dotted #bbccaa;
        border-bottom: 1px dotted #bbccaa;
        padding: 0px 10px 10px 10px;
    }
</style>
<script>
    function showHide(nodeId) {
        node = document.getElementById(nodeId);
        node.className = (node.className == "shown") ? "hidden" : "shown";
    }
    function showHideAll(newState) {
        nodes = document.getElementsByTagName("div");
        for (var i = 0; i &lt; nodes.length; i++) {
            if (nodes[i].className == "shown" ||
                    nodes[i].className == "hidden") {
                nodes[i].className = newState;
            }
        }
    }
    function hideOnLoad() {
        if (document.location.href.indexOf("#") != -1) return;
        nodes = document.getElementsByTagName("div");
        for (var i = 0; i &lt; nodes.length; i++) {
            if (nodes[i].className == "shown") nodes[i].className = "hidden";
        }
    }
</script>
</head>
    <xsl:apply-templates select="changelog"/>
</html>
</xsl:template>
<xsl:template match="changelog">
<body onLoad="hideOnLoad()">
    <h1>
        <xsl:text>Davenport Change Log</xsl:text>
        <xsl:if test="$version">
            <xsl:text> - Version </xsl:text>
            <xsl:value-of select="$version"/>
         </xsl:if>
    </h1>
    <p>
        Enhancements and defect resolution summaries are listed by version; selecting "Show/Hide Details" will expand the detailed change descriptions for the version.
    </p>
    <p>
        <a href="javascript:showHideAll('shown')">Show All Details</a>
        <xsl:text>&#160;&#183;&#160;</xsl:text>
        <a href="javascript:showHideAll('hidden')">Hide All Details</a>
    </p>
    <hr/>
    <xsl:apply-templates select="version"/>
</body>
</xsl:template>
<xsl:template match="version">
<a name="{@id}"/>
<h3>Version <xsl:value-of select="@id"/>: <xsl:value-of select="@date"/></h3>
<xsl:apply-templates select="overview"/>
<xsl:if test="change">
    <h5>Summary of Changes:</h5>
    <ul>
        <xsl:apply-templates mode="summary" select="change"/>
    </ul>
    <a>
        <xsl:attribute name="href">
            <xsl:text>javascript:showHide('</xsl:text>
            <xsl:value-of select="@id"/>
            <xsl:text>-details')</xsl:text>
        </xsl:attribute>
        <xsl:text>Show/Hide Details</xsl:text>
    </a>
    <div class="shown">
        <xsl:attribute name="id">
            <xsl:value-of select="@id"/>
            <xsl:text>-details</xsl:text>
        </xsl:attribute>
        <xsl:apply-templates select="change"/>
    </div>
</xsl:if>
</xsl:template>
<xsl:template match="overview">
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
<xsl:template match="change" mode="summary">
    <li><xsl:value-of select="summary"/></li>
</xsl:template>
<xsl:template match="change">
    <xsl:apply-templates select="summary"/>
    <xsl:apply-templates select="description"/>
    <xsl:apply-templates select="resolution"/>
</xsl:template>
<xsl:template match="summary">
    <h5>Change:</h5>
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
<xsl:template match="description">
    <h5>Details:</h5>
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
<xsl:template match="resolution">
    <h5>Resolution:</h5>
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
</xsl:stylesheet>
