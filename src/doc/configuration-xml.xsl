<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="xml" indent="yes" doctype-system="http://java.sun.com/dtd/web-app_2_3.dtd" doctype-public="-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"/>

<xsl:param name="version" select="''"/>

<xsl:template name="format-line">
    <xsl:param name="line"/>
    <xsl:param name="pad"/>
    <xsl:param name="count" select="0"/>
    <xsl:if test="string-length($line)">
        <xsl:choose>
            <xsl:when test="$count = 0 and string-length($pad)">
                <xsl:if test="string-length($pad)">
                    <xsl:value-of select="$pad"/>
                    <xsl:call-template name="format-line">
                        <xsl:with-param name="line" select="$line"/>
                        <xsl:with-param name="pad" select="$pad"/>
                        <xsl:with-param name="count" select="$count + string-length($pad)"/>
                    </xsl:call-template>
                </xsl:if>
            </xsl:when>
            <xsl:otherwise>
                <xsl:variable name="word" select="substring-before($line, ' ')"/>
                <xsl:choose>
                    <xsl:when test="string-length($word)">
                        <xsl:choose>
                            <xsl:when test="$count + string-length($word) &gt; 78">
                                <xsl:text>
</xsl:text>
                                <xsl:call-template name="format-line">
                                    <xsl:with-param name="line" select="$line"/>
                                    <xsl:with-param name="pad" select="$pad"/>
                                    <xsl:with-param name="count" select="0"/>
                                </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                                <xsl:value-of select="$word"/>
                                <xsl:text> </xsl:text>
                                <xsl:call-template name="format-line">
                                    <xsl:with-param name="line" select="substring-after($line, ' ')"/>
                                    <xsl:with-param name="pad" select="$pad"/>
                                    <xsl:with-param name="count" select="$count + string-length($word) + 1"/>
                                </xsl:call-template>
                            </xsl:otherwise>
                        </xsl:choose>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:choose>
                            <xsl:when test="starts-with($line, ' ')">
                                <xsl:call-template name="format-line">
                                    <xsl:with-param name="line" select="substring-after($line, ' ')"/>
                                    <xsl:with-param name="pad" select="$pad"/>
                                    <xsl:with-param name="count" select="$count + 1"/>
                                </xsl:call-template>
                            </xsl:when>
                            <xsl:otherwise>
                                <xsl:if test="$count + string-length($line) &gt; 78">
                                    <xsl:text>
</xsl:text>
                                    <xsl:value-of select="$pad"/>
                                </xsl:if>
                                <xsl:value-of select="$line"/>
                                <xsl:text>
</xsl:text>
                            </xsl:otherwise>
                        </xsl:choose>
                    </xsl:otherwise>
                </xsl:choose>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:if>
</xsl:template>

<xsl:template match="/">
    <web-app>
        <display-name>
            <xsl:text>Davenport WebDAV-SMB Gateway</xsl:text>
            <xsl:if test="$version">
                <xsl:text> - Version </xsl:text>
                <xsl:value-of select="$version"/>
            </xsl:if>
        </display-name>
        <filter>
            <filter-name>Compression</filter-name>
            <filter-class>smbdav.CompressionFilter</filter-class>
            <xsl:apply-templates select="//compression-parameter"/>
        </filter>
        <filter-mapping>
            <filter-name>Compression</filter-name>
            <servlet-name>Davenport</servlet-name>
        </filter-mapping>
        <servlet>
            <servlet-name>Davenport</servlet-name>
            <servlet-class>smbdav.Davenport</servlet-class>
            <xsl:apply-templates select="//parameter[@importance = 'high']"/>
            <xsl:apply-templates select="//parameter[not(@importance = 'high')]"/>
        </servlet>
        <servlet-mapping>
            <servlet-name>Davenport</servlet-name>
            <url-pattern>/*</url-pattern>
        </servlet-mapping>
    </web-app>
</xsl:template>
<xsl:template match="compression-parameter">
    <xsl:comment>
        <xsl:text>
    </xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>:

</xsl:text>
        <xsl:call-template name="format-line">
            <xsl:with-param name="line" select="summary"/>
            <xsl:with-param name="pad" select="'        '"/>
        </xsl:call-template>
        <xsl:text>
</xsl:text>
        <xsl:apply-templates select="description"/>
        <xsl:apply-templates select="valid-values"/>
        <xsl:apply-templates select="default-value"/>
    </xsl:comment>
    <xsl:apply-templates select="example"/>
    <xsl:apply-templates select="example-value"/>
</xsl:template>
<xsl:template match="parameter">
    <xsl:comment>
        <xsl:text>
    </xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>:

</xsl:text>
        <xsl:call-template name="format-line">
            <xsl:with-param name="line" select="summary"/>
            <xsl:with-param name="pad" select="'        '"/>
        </xsl:call-template>
        <xsl:text>
</xsl:text>
        <xsl:apply-templates select="description"/>
        <xsl:apply-templates select="valid-values"/>
        <xsl:apply-templates select="default-value"/>
    </xsl:comment>
    <xsl:apply-templates select="example"/>
    <xsl:apply-templates select="example-value"/>
</xsl:template>
<xsl:template match="description">
    <xsl:apply-templates select="*"/>
</xsl:template>
<xsl:template match="para">
    <xsl:if test="position() != 1">
    <xsl:text>
</xsl:text>
    </xsl:if>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'        '"/>
    </xsl:call-template>
</xsl:template>
<xsl:template match="list">
    <xsl:text>
</xsl:text>
    <xsl:apply-templates select="list-item"/>
</xsl:template>
<xsl:template match="list-item">
    <xsl:if test="position() != 1">
    <xsl:text>
</xsl:text>
    </xsl:if>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'            '"/>
    </xsl:call-template>
</xsl:template>
<xsl:template match="valid-values">
    <xsl:text>
        Valid settings include:

</xsl:text>
    <xsl:apply-templates select="valid-value"/>
</xsl:template>
<xsl:template match="valid-value">
    <xsl:if test="position() != 1">
    <xsl:text>
</xsl:text>
    </xsl:if>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="value"/>
        <xsl:with-param name="pad" select="'            '"/>
    </xsl:call-template>
    <xsl:text>

</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="description"/>
        <xsl:with-param name="pad" select="'                '"/>
    </xsl:call-template>
</xsl:template>
<xsl:template match="default-value">
    <xsl:text>
        Default Value:
    
</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'            '"/>
    </xsl:call-template>
</xsl:template>
<xsl:template match="example">
    <xsl:comment>
        <xsl:apply-templates select="text()"/>
    </xsl:comment>
</xsl:template>
<xsl:template match="example-value">
    <xsl:comment>
        <xsl:text>
    &lt;init-param&gt;
        &lt;param-name&gt;</xsl:text>
        <xsl:value-of select="../@name"/>
        <xsl:text>&lt;/param-name&gt;
        &lt;param-value&gt;</xsl:text>
        <xsl:value-of select="."/>
        <xsl:text>&lt;/param-value&gt;
    &lt;/init-param&gt;
</xsl:text>
    </xsl:comment>
</xsl:template>

</xsl:stylesheet>
