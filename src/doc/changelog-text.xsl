<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="text" encoding="iso-8859-1"/>

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
    <xsl:apply-templates select="changelog"/>
</xsl:template>
<xsl:template match="changelog">
    <xsl:text>Davenport Change Log - Version </xsl:text>
    <xsl:value-of select="$version"/>
    <xsl:text>
-------------------------------------------------------------------------------
</xsl:text>
    <xsl:apply-templates select="version"/>
</xsl:template>
<xsl:template match="version">
    <xsl:if test="position() != 1">
        <xsl:text>_______________________________________________________________________________

</xsl:text>
    </xsl:if>
    <xsl:text>Version </xsl:text>
    <xsl:value-of select="@id"/>: <xsl:value-of select="@date"/>
    <xsl:text>
</xsl:text>
<xsl:apply-templates select="overview"/>
<xsl:if test="change">
    <xsl:text>
SUMMARY OF CHANGES:
</xsl:text>
    <xsl:text>
</xsl:text>
    <xsl:apply-templates mode="summary" select="change"/>
    <xsl:text>
</xsl:text>
    <xsl:apply-templates select="change"/>
</xsl:if>
    <xsl:text>
</xsl:text>
</xsl:template>
<xsl:template match="overview">
    <xsl:text>
</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="''"/>
    </xsl:call-template>
</xsl:template>
<xsl:template match="change" mode="summary">
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="summary"/>
        <xsl:with-param name="pad" select="'    '"/>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
</xsl:template>
<xsl:template match="change">
    <xsl:apply-templates select="summary"/>
    <xsl:apply-templates select="description"/>
    <xsl:apply-templates select="resolution"/>
</xsl:template>
<xsl:template match="summary">
    <xsl:text>CHANGE:</xsl:text>
    <xsl:text>
</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'    '"/>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
</xsl:template>
<xsl:template match="description">
    <xsl:text>DETAILS:</xsl:text>
    <xsl:text>
</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'    '"/>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
</xsl:template>
<xsl:template match="resolution">
    <xsl:text>RESOLUTION:</xsl:text>
    <xsl:text>
</xsl:text>
    <xsl:call-template name="format-line">
        <xsl:with-param name="line" select="."/>
        <xsl:with-param name="pad" select="'    '"/>
    </xsl:call-template>
    <xsl:text>
</xsl:text>
</xsl:template>
</xsl:stylesheet>
