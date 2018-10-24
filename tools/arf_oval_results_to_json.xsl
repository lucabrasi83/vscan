<?xml version="1.0"?>
<!--

  Copyright (C) 2014-2018 JovalCM.com.  All rights reserved.

  Description: Sample conversion of ARF Results and OVAL results to a JSON-formatted event stream
  Filename:    arf_oval_results_to_json.xsl

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                xmlns:oval-res="http://oval.mitre.org/XMLSchema/oval-results-5">
  <xsl:output method="text" omit-xml-declaration="yes" indent="no" encoding="utf-8" />
  <xsl:strip-space elements="*" />
  
<xsl:template match="/">
  <xsl:variable name="testResult" select="//xccdf:TestResult"/>
  <xsl:variable name="results" select="//oval-res:oval_results/oval-res:results//oval-res:definition"/>  
  <xsl:variable name="definitions" select="//oval-def:oval_definitions/oval-def:definitions"/>  

  { 
    "start_time" : "<xsl:value-of select="$testResult/@start-time" />",
    "end_time" : "<xsl:value-of select="$testResult/@end-time" />",
    <xsl:if test="$testResult/@test-system">"test_system" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$testResult/@test-system" /></xsl:call-template>",</xsl:if>
    <xsl:if test="$testResult/xccdf:target">
    "target_names" : [ <xsl:for-each select="$testResult/xccdf:target[1]">"<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"<xsl:if test="position() != last()">, </xsl:if></xsl:for-each> ],</xsl:if>
    <xsl:if test="$testResult/xccdf:target-address">
    "target_addresses" : [ <xsl:for-each select="$testResult/xccdf:target-address">"<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"<xsl:if test="position() != last()">, </xsl:if></xsl:for-each> ],</xsl:if>
    <xsl:if test="$testResult/xccdf:identity">
    "identities" : [ <xsl:for-each select="$testResult/xccdf:identity">
        {
          "name" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>",
          "authenticated" : <xsl:value-of select="./@authenticated" />,
          "privileged" : <xsl:value-of select="./@privileged" />
        }<xsl:if test="position() != last()">, </xsl:if>
      </xsl:for-each>
    ],</xsl:if><!--
    <xsl:for-each select="$testResult/xccdf:target-facts/xccdf:fact">
    "fact_<xsl:call-template name="string-to-json-key"><xsl:with-param name="input" select="./@name" /></xsl:call-template>" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>",      
    </xsl:for-each>-->
    "definition_results" : [
      <xsl:variable name="results_count" select="count($results)"/>
      <xsl:for-each select="$results">
        <xsl:variable name="definitionId" select="./@definition_id"/>
        <xsl:variable name="definition" select="$definitions/oval-def:definition[@id = $definitionId]"/>
        <xsl:variable name="deprecated">
          <xsl:choose>
            <xsl:when test="$definition/@deprecated and $definition/@deprecated = 'true'">true</xsl:when>
            <xsl:otherwise>false</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:variable name="result">
          <xsl:choose>
            <xsl:when test="$deprecated = 'true'">deprecated</xsl:when>
            <xsl:otherwise><xsl:value-of select="./@result" /></xsl:otherwise>
          </xsl:choose>
        </xsl:variable>  
        { 
          "definition_id" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$definitionId" /></xsl:call-template>",
          "version" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$definition/@version" /></xsl:call-template>",
          "class" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$definition/@class" /></xsl:call-template>",
          "deprecated" : <xsl:value-of select="$deprecated" />,
          "result" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$result" /></xsl:call-template>",
          "title" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$definition/oval-def:metadata/oval-def:title/text()" /></xsl:call-template>",<!-- "
            description" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$definition/oval-def:metadata/oval-def:description/text()" /></xsl:call-template>",
            "affected_platforms" : [ <xsl:for-each select="$definition//oval-def:platform">"<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"<xsl:if test="position() != last()">, </xsl:if></xsl:for-each> ],-->
          "references" : [ <xsl:for-each select="$definition//oval-def:reference">"<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./@ref_id" /></xsl:call-template>"<xsl:if test="position() != last()">, </xsl:if></xsl:for-each> ]
        }<xsl:if test="position() &lt; $results_count">, </xsl:if>
      </xsl:for-each>
    ]
  }

</xsl:template>

<xsl:template match="text()" />

<!-- MISC UTILITY TEMPLATES -->

<xsl:template name="string-to-json-key">
  <xsl:param name="input" />
  <xsl:variable name="sAllowed" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'"/>
  <xsl:variable name="inputLower" select="translate($input, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"/>
  <xsl:variable name="output">
    <xsl:value-of select="translate($inputLower, translate($inputLower, $sAllowed, ''), '_')"/>
  </xsl:variable>
  <xsl:value-of select="$output" />
</xsl:template>

<xsl:template name="boolean-string-to-int">
  <xsl:param name="input" />
  <xsl:variable name="inputLower" select="translate($input, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"/>
  <xsl:variable name="output">
    <xsl:choose>
      <xsl:when test="contains($inputLower, 'true')">1</xsl:when>
      <xsl:otherwise>0</xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:value-of select="$output" />
</xsl:template> 

<xsl:template name="json-escape-string">
  <xsl:param name="input" />
  <xsl:variable name="step1">
    <xsl:call-template name="replace-substring">
      <xsl:with-param name="from">\</xsl:with-param>
      <xsl:with-param name="to">\\</xsl:with-param>
      <xsl:with-param name="subject" select="$input" />
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="step2">
    <xsl:call-template name="replace-substring">
      <xsl:with-param name="from">"</xsl:with-param>
      <xsl:with-param name="to">\"</xsl:with-param>
      <xsl:with-param name="subject" select="$step1" />
    </xsl:call-template>
  </xsl:variable>
  <xsl:value-of select="normalize-space($step2)" />
</xsl:template>

<xsl:template name="replace-substring">
  <xsl:param name="subject" />
  <xsl:param name="from" />
  <xsl:param name="to" />
  <xsl:choose>
    <xsl:when test="contains($subject,$from)">
      <xsl:value-of select="substring-before($subject,$from)" />
      <xsl:value-of select="$to" />
      <xsl:call-template name="replace-substring">
        <xsl:with-param name="subject" select="substring-after($subject,$from)" />
        <xsl:with-param name="from" select="$from" />
        <xsl:with-param name="to" select="$to" />
      </xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
      <xsl:value-of select="$subject" />
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template name="mysqlDateTime">
  <xsl:param name="date"/>
  <xsl:call-template name="printDate">
    <xsl:with-param name="date" select="$date"/>
  </xsl:call-template>
  at
  <xsl:call-template name="printTime">
    <xsl:with-param name="date" select="$date"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="printDate">
  <xsl:param name="date"/>
  <xsl:variable name="year">
    <xsl:value-of select="substring-before($date, '-')"/>
  </xsl:variable>
  <xsl:variable name="mon">
    <xsl:value-of select="substring-before(substring-after($date, '-'), '-') - 1"/>
  </xsl:variable>
  <xsl:variable name="months">
    <xsl:value-of select="'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'"/>
  </xsl:variable>
  <xsl:variable name="month">
    <xsl:value-of select="substring($months, $mon * 4, 4)"/>
  </xsl:variable>
  <xsl:variable name="day">
    <xsl:value-of select="substring-before(substring-after(substring-after($date, '-'), '-'), 'T')"/>
  </xsl:variable>
  <xsl:value-of select="concat($day, ' ', $month, ' ', $year)"/>
</xsl:template>

<xsl:template name="printTime">
  <xsl:param name="date"/>
  <xsl:variable name="hh">
    <xsl:value-of select="format-number(substring-before(substring-after($date, 'T'), ':'), '00')"/>
  </xsl:variable>
  <xsl:variable name="mm">
    <xsl:value-of select="format-number(substring-before(substring-after($date, ':'), ':'), '00')"/>
  </xsl:variable>
  <xsl:variable name="ss">
    <xsl:value-of select="format-number(substring-before(substring-after(substring-after($date, ':'), ':'), '.'), '00')"/>
  </xsl:variable>
  <xsl:value-of select="concat($hh, ':', $mm, ':', $ss)"/>
</xsl:template>


</xsl:stylesheet>
