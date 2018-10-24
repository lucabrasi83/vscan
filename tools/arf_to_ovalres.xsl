<?xml version="1.0" encoding="ISO-8859-1"?>
<!--

  Copyright (C) 2013 jOVAL.org.  All rights reserved.

  Description: Extract the first OVAL results from an ARF document. Useful in conjunction with oval-wrapper-xccdf.xml
  Filename:    arf_to_ovalres.xsl

-->
<xsl:stylesheet version="1.0" 
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:oval-res="http://oval.mitre.org/XMLSchema/oval-results-5">
    <xsl:output method="xml" indent="yes"/>
    <xsl:template match="/">
        <oval-res:oval_results>
            <xsl:copy-of select="//oval-res:oval_results/*"/>
        </oval-res:oval_results>
    </xsl:template>
</xsl:stylesheet>
