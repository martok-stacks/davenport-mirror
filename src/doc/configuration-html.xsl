<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html"/>

<xsl:param name="version" select="''"/>

<xsl:template name="output-important-parameters">
    <xsl:param name="important-parameters"/>
    <xsl:if test="$important-parameters">
        <h3>Important Parameters</h3>
        <p>One or more of the following parameters must typically be specified to run Davenport successfully:</p>
        <ul>
            <xsl:for-each select="$important-parameters">
                <li>
                    <xsl:call-template name="output-parameter-link">
                        <xsl:with-param name="parameter" select="@name"/>
                    </xsl:call-template>
                </li>
            </xsl:for-each>
        </ul>
    </xsl:if>
</xsl:template>

<xsl:template name="output-parameter-link">
    <xsl:param name="parameter"/>
    <a>
        <xsl:attribute name="href">
            <xsl:text>#</xsl:text>
            <xsl:value-of select="$parameter"/>
        </xsl:attribute>
        <xsl:attribute name="onClick">
            <xsl:text>showNode('</xsl:text>
            <xsl:value-of select="//parameter-class[parameter/@name = $parameter]/@name"/>
            <xsl:text>')</xsl:text>
        </xsl:attribute>
        <xsl:value-of select="$parameter"/>
    </a>
</xsl:template>

<xsl:template match="/">
<html>
<head>
<title>
    <xsl:text>Davenport Configuration Reference</xsl:text>
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
    function showNode(nodeId) {
        node = document.getElementById(nodeId);
        if (node.className == "hidden") node.className = "shown";
    }
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
    <xsl:apply-templates select="config"/>
</html>
</xsl:template>
<xsl:template match="config">
<body onLoad="hideOnLoad()">
    <h1>
        <xsl:text>Davenport Configuration Reference</xsl:text>
        <xsl:if test="$version">
            <xsl:text> - Version </xsl:text>
            <xsl:value-of select="$version"/>
        </xsl:if>
    </h1>
    <p>
        This document describes the configuration settings commonly specified in the Davenport deployment descriptor (&quot;web.xml&quot;, located in the &quot;webapps/root/WEB-INF&quot; subdirectory of the Davenport root).  For container-specific configuration, consult your container documentation.  Information on configuring Jetty (the default container shipping with Davenport) can be found at <a href="http://jetty.mortbay.org/jetty/faq/">http://jetty.mortbay.org/jetty/faq/</a>.
    </p>
    <p>
    The deployment descriptor can be edited directly with any text editor, and is liberally commented (for those unfamiliar with XML, everything between a &quot;&lt;!--&quot; and &quot;--&gt;&quot; pair is a comment).  It is recommended that you review the deployment descriptor and tailor it to your environment prior to running Davenport for the first time.  Reading this document and noting relevant settings is an excellent first step.
    </p>
    <p>
        Settings are broken into categories; selecting "Expand/Collapse Category" will expand the category to display the relevant configuration parameters.
    </p>
    <p>
        <a href="javascript:showHideAll('shown')">Expand All Categories</a>
        <xsl:text>&#160;&#183;&#160;</xsl:text>
        <a href="javascript:showHideAll('hidden')">Collapse All Categories</a>
    </p>
    <hr/>
    <xsl:call-template name="output-important-parameters">
        <xsl:with-param name="important-parameters" select="parameter-class/parameter[@importance = 'high']"/>
    </xsl:call-template>
    <xsl:apply-templates select="parameter-class"/>
</body>
</xsl:template>
<xsl:template match="parameter-class">
    <h3><xsl:value-of select="@name"/></h3>
    <xsl:apply-templates select="description"/>
    <a>
        <xsl:attribute name="href">
            <xsl:text>javascript:showHide('</xsl:text>
            <xsl:value-of select="@name"/>
            <xsl:text>')</xsl:text>
        </xsl:attribute>
        <xsl:text>Expand/Collapse Category</xsl:text>
    </a>
    <div class="shown" id="{@name}">
        <xsl:apply-templates select="references"/>
        <xsl:apply-templates select="parameter"/>
    </div>
</xsl:template>
<xsl:template match="summary">
    <xsl:value-of select="."/>
</xsl:template>
<xsl:template match="description">
    <xsl:apply-templates select="*"/>
</xsl:template>
<xsl:template match="para">
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
<xsl:template match="list">
    <ul>
        <xsl:apply-templates select="list-item"/>
    </ul>
</xsl:template>
<xsl:template match="list-item">
    <li><xsl:value-of select="."/></li>
</xsl:template>
<xsl:template match="parameter-class/references">
    <h5>References for Further Information</h5>
    <ul>
        <xsl:apply-templates select="reference"/>
    </ul>
</xsl:template>
<xsl:template match="reference">
    <li><a href="{@location}"><xsl:value-of select="@label"/></a></li>
</xsl:template>
<xsl:template match="parameter">
    <a name="{@name}"/>
    <h4><xsl:value-of select="@name"/></h4>
    <xsl:apply-templates select="summary"/>
    <xsl:if test="@importance = 'high'">
        <p>
            <b>Configuration of this parameter may be necessary to run Davenport successfully.</b>
        </p>
    </xsl:if>
    <xsl:apply-templates select="description"/>
    <xsl:apply-templates select="valid-values"/>
    <xsl:apply-templates select="default-value"/>
    <xsl:apply-templates select="example"/>
    <xsl:apply-templates select="example-value"/>
    <xsl:apply-templates select="references"/>
    <xsl:apply-templates select="related-parameters"/>
</xsl:template>
<xsl:template match="parameter/references">
    <h6>References for Further Information</h6>
    <ul>
        <xsl:apply-templates select="reference"/>
    </ul>
</xsl:template>
<xsl:template match="valid-values">
    <h6>Valid Values for &quot;<xsl:value-of select="../@name"/>&quot;</h6>
    <table width="60%">
        <xsl:apply-templates select="valid-value"/>
    </table>
</xsl:template>
<xsl:template match="valid-value">
    <tr>
        <th class="rowHeader"><xsl:value-of select="value"/></th>
        <td><xsl:value-of select="description"/></td>
    </tr>
</xsl:template>
<xsl:template match="default-value">
    <h6>Default Value</h6>
    <p>
        <xsl:value-of select="."/>
    </p>
</xsl:template>
<xsl:template match="example">
    <h6>Example</h6>
    <pre><xsl:apply-templates select="comment|text()"/></pre>
</xsl:template>
<xsl:template match="comment">
    <xsl:text>&lt;!-- </xsl:text>
    <xsl:value-of select="."/>
    <xsl:text> --&gt;</xsl:text>
</xsl:template>
<xsl:template match="example-value">
    <h6>Example</h6>
    <pre><xsl:text>
    &lt;init-param&gt;
        &lt;param-name&gt;</xsl:text>
        <xsl:value-of select="../@name"/>
    <xsl:text>&lt;/param-name&gt;
        &lt;param-value&gt;</xsl:text>
        <xsl:value-of select="."/>
    <xsl:text>&lt;/param-value&gt;
    &lt;/init-param&gt;
</xsl:text></pre>
</xsl:template>
<xsl:template match="related-parameters">
    <h6>Related Parameters</h6>
    <ul>
        <xsl:for-each select="related-parameter">
            <li>
                <xsl:call-template name="output-parameter-link">
                    <xsl:with-param name="parameter" select="@name"/>
                </xsl:call-template>
            </li>
        </xsl:for-each>
    </ul>
</xsl:template>

</xsl:stylesheet>
