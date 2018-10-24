<?xml version="1.0" encoding="UTF-8"?>
<!--

  Copyright (C) 2014 jOVAL.org.  All rights reserved.

  Description: Converts XCCDF 1.2 to XCCDF 1.1.4, for applications requiring legacy SCAP 1.0 support
  Filename:    xccdf_convert_1.2_to_1.1.4.xsl

-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:cdf="http://checklists.nist.gov/xccdf/1.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cpe="http://cpe.mitre.org/dictionary/2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:sccf="http://checklists.nist.gov/sccf/0.1" xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns="http://checklists.nist.gov/xccdf/1.2" xpath-default-namespace="http://checklists.nist.gov/xccdf/1.2" exclude-result-prefixes="xs cdf" version="2.0">
     <xsl:output method="xml" indent="yes"/>
     <xsl:strip-space elements="*"/>

     <!-- default element handling: fix namespace -->
     <xsl:template match="*">
          <xsl:choose>
               <xsl:when test="namespace-uri(.)='http://checklists.nist.gov/xccdf/1.2'">
                    <xsl:element name="{local-name()}" namespace="http://checklists.nist.gov/xccdf/1.1">
                         <xsl:copy-of select="@*"/>
                         <xsl:apply-templates/>
                    </xsl:element>
               </xsl:when>
               <xsl:otherwise>
                    <xsl:copy copy-namespaces="no">
                         <xsl:copy-of select="@*"/>
                         <xsl:apply-templates/>
                    </xsl:copy>
               </xsl:otherwise>
          </xsl:choose>
     </xsl:template>

     <!-- Bechmark/metadata can contain either dc:* OR sccf:* -->
     <xsl:template match="Benchmark/metadata">
          <xsl:variable name="DublinCoreChildren" select="*[namespace-uri() = 'http://purl.org/dc/elements/1.1/']"/>
          <xsl:variable name="SccFChildren" select="*[namespace-uri() = 'http://checklists.nist.gov/sccf/0.1']"/>
          <xsl:variable name="OtherChildren" select="./*[namespace-uri() != 'http://purl.org/dc/elements/1.1/' and namespace-uri() != 'http://checklists.nist.gov/sccf/0.1']"/>
          <xsl:element name="metadata" namespace="http://checklists.nist.gov/xccdf/1.1">
               <xsl:choose>
                    <xsl:when test="$DublinCoreChildren">
                         <xsl:apply-templates select="$DublinCoreChildren"/>
                         <xsl:if test="$SccFChildren or $OtherChildren">
                              <xsl:comment>NOTE: unsupported metadata removed. Metadata may only contain dublin core or sccf elements in XCCDF 1.1.4</xsl:comment>
                         </xsl:if>
                    </xsl:when>
                    <xsl:when test="$SccFChildren">
                         <xsl:apply-templates select="$SccFChildren"/>
                         <xsl:if test="$DublinCoreChildren or $OtherChildren">
                              <xsl:comment>NOTE: unsupported metadata removed. Metadata may only contain dublin core or sccf elements in XCCDF 1.1.4</xsl:comment>
                         </xsl:if>
                    </xsl:when>
                    <xsl:when test="$OtherChildren">
                         <xsl:comment>NOTE: unsupported metadata removed. Metadata may only contain dublin core or sccf elements in XCCDF 1.1.4</xsl:comment>
                    </xsl:when>
               </xsl:choose>
          </xsl:element>
     </xsl:template>

     <!-- Rule/metadata not allowed in 1.1.4 -->
     <xsl:template match="Rule/metadata">
          <!-- TBD: move <impact-metric /> to Rule\impact-data in proper sequence -->
          <xsl:comment>NOTE: metadata removed. Metadata not supported in this location in XCCDF 1.1.4</xsl:comment>
     </xsl:template>

     <!-- metadata not allowed in 1.1.4 unless under Benchmark (handled above) -->
     <xsl:template match="metadata">
          <xsl:comment>NOTE: metadata removed. Metadata not supported in this location in XCCDF 1.1.4</xsl:comment>
     </xsl:template>

     <!-- sub@use attribute not supported in 1.1.4 -->
     <xsl:template match="sub">
          <xsl:if test="@use and @use != 'legacy'">
               <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "sub" element "use" attribute value "<xsl:value-of select="@use" />" is not supported in XCCDF 1.1.4.</xsl:message>
          </xsl:if>
          <!-- remove sub@use -->
          <xsl:element name="sub" namespace="http://checklists.nist.gov/xccdf/1.1">
               <xsl:copy-of select="@*[name(.)!='use']"/>
          </xsl:element>
     </xsl:template>

     <!-- dc-status not allowed in 1.1.4 -->
     <xsl:template match="dc-status">
          <xsl:comment>NOTE: dc-status removed. Element not supported in XCCDF 1.1.4</xsl:comment>
     </xsl:template>

     <!-- check@negate, complex-check@negate, check@multi-check, complex-check@multi-check not allowed in 1.1.4 -->
     <xsl:template match="check[@negate]|complex-check[@negate]|check[@multi-check]|complex-check[@multi-check]">
          <xsl:if test="@multi-check and @multi-check = true()">
               <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "<xsl:value-of select="./local-name()" />" element "multi-check" attribute value "true" is not supported in XCCDF 1.1.4.</xsl:message>
          </xsl:if>
          <xsl:if test="@negate and @negate = true()">
               <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "<xsl:value-of select="./local-name()" />" element "negate" attribute value "true" is not supported in XCCDF 1.1.4.</xsl:message>
          </xsl:if>
          <!-- if negate=false and/or multi-check=false, we can remove the attributes and continue -->
          <xsl:element name="{./local-name()}" namespace="http://checklists.nist.gov/xccdf/1.1">
               <xsl:copy-of select="@*[name(.)!='negate' and name(.)!='multi-check']"/>
               <xsl:apply-templates/>
          </xsl:element>
     </xsl:template>

     <!-- Value/complex-value and Value/complex-default not allowed in 1.1.4 -->
     <xsl:template match="Value/complex-value|Value/complex-default">
          <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "Value/<xsl:value-of select="./local-name()" />" element is not supported in XCCDF 1.1.4.</xsl:message>
     </xsl:template>

     <!-- check-import@import-xpath not allowed in 1.1.4 -->
     <xsl:template match="check-import[@import-xpath]">
          <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "check-import" element "import-xpath" attribute is not supported in XCCDF 1.1.4.</xsl:message>
     </xsl:template>
     <!-- Tailoring and tailoring-file not allowed in 1.1.4 -->
     <xsl:template match="Tailoring|tailoring-file">
          <xsl:message terminate="yes">ERROR: document cannot be downconverted. The "<xsl:value-of select="./local-name()" />" element is not supported in XCCDF 1.1.4.</xsl:message>
     </xsl:template>

     <!-- TestResult/benchmark id attribute not supported in 1.1.4 -->
     <xsl:template match="TestResult/benchmark[@id]">
          <xsl:element name="benchmark" namespace="http://checklists.nist.gov/xccdf/1.1">
               <xsl:copy-of select="@*[name(.)!='id']"/>
          </xsl:element>
     </xsl:template>

     <!-- TestResult/target-id-ref not allowed in 1.1.4 -->
     <xsl:template match="TestResult/target-id-ref">
          <xsl:comment>NOTE: target-id-ref removed. Element not supported in XCCDF 1.1.4</xsl:comment>
     </xsl:template>

     <!-- Arbitrary contents, namespace=”##other”, as TestResult children not allowed 1.1.4 -->
     <xsl:template match="TestResult/*[namespace-uri() != 'http://checklists.nist.gov/xccdf/1.2']">
          <xsl:comment>NOTE: arbitrary TestResult child from non-xccdf namespace (http://checklists.nist.gov/xccdf/1.2) removed. Element not supported in XCCDF 1.1.4</xsl:comment>
     </xsl:template>

     <!-- Copy comments -->
     <xsl:template match="comment()">
          <xsl:variable name="newline">
               <xsl:text>
</xsl:text>
          </xsl:variable>
          <xsl:comment>
               <xsl:value-of select="."/>
          </xsl:comment>
          <xsl:value-of select="$newline"/>
     </xsl:template>
</xsl:stylesheet>
