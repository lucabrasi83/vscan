<?xml version="1.0"?>
<!--

  Copyright (C) 2014 jOVAL.org.  All rights reserved.

  Description: Sample conversion of XCCDF Results to JSON-formatted event stream
  Filename:    xccdf_results_to_json.xsl

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:diagnostic="http://www.joval.org/schemas/scap/1.2/diagnostic">
  <xsl:output method="text" omit-xml-declaration="yes" indent="no" encoding="utf-8" />
  <xsl:strip-space elements="*" />
  
<xsl:template match="/">
  <xsl:variable name="selectedProfileId"><xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/xccdf:profile/@idref"/></xsl:variable>
  <xsl:variable name="results" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:rule-result"/>
  <xsl:variable name="errors" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:metadata/diagnostic:error"/>
{ 
    "@timestamp" : "<xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/@end-time" />",
    <!--"@message":"Benchmark result: <xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:title/text()" /></xsl:call-template>", -->
    "start_time" : "<xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/@start-time" />",
    "end_time" : "<xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/@end-time" />",
    "benchmark" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:title/text()" /></xsl:call-template>",
    "benchmark_version" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:version/text()" /></xsl:call-template>",
    "benchmark_id" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/@id" /></xsl:call-template>",
    "profile" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:Profile[@id=$selectedProfileId]/xccdf:title/text()" /></xsl:call-template>",
    "profile_id" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$selectedProfileId" /></xsl:call-template>",
    <xsl:if test="/xccdf:Benchmark/xccdf:TestResult/@test-system">"test_system" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/@test-system" /></xsl:call-template>",</xsl:if>
    <xsl:if test="/xccdf:Benchmark/xccdf:TestResult/xccdf:target">"target_names" : [
      <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target[1]">
        "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"
        <xsl:if test="position() != last()">, </xsl:if>
      </xsl:for-each>
    ],</xsl:if>
    <xsl:if test="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-address">"target_addresses" : [
      <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-address">
        "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"
        <xsl:if test="position() != last()">, </xsl:if>
      </xsl:for-each>
    ],</xsl:if>
    <xsl:if test="/xccdf:Benchmark/xccdf:TestResult/xccdf:identity">"identities" : [
      <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:identity">
        {
          "name" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>",
          "authenticated" : <xsl:value-of select="./@authenticated" />,
          "privileged" : <xsl:value-of select="./@privileged" />
        }<xsl:if test="position() != last()">, </xsl:if>              
      </xsl:for-each>
    ],</xsl:if>
    <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-facts/xccdf:fact">
      "fact_<xsl:call-template name="string-to-json-key"><xsl:with-param name="input" select="./@name" /></xsl:call-template>" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>",      
    </xsl:for-each>
    <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:score">
      <xsl:variable name="scoringSystemName">
        <xsl:choose>
          <xsl:when test="./@system = 'urn:xccdf:scoring:default'">sys_default</xsl:when>
          <xsl:when test="./@system = 'urn:xccdf:scoring:flat'">sys_flat</xsl:when>
          <xsl:when test="./@system = 'urn:xccdf:scoring:flat-unweighted'">sys_flat_unweighted</xsl:when>
          <xsl:when test="./@system = 'urn:xccdf:scoring:absolute'">sys_absolute</xsl:when>
          <xsl:otherwise>sys_<xsl:call-template name="string-to-json-key"><xsl:with-param name="input" select="./@system" /></xsl:call-template></xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      "<xsl:value-of select="$scoringSystemName"/>_system" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./@system" /></xsl:call-template>",
      "<xsl:value-of select="$scoringSystemName"/>_score" : <xsl:value-of select="format-number(./text(),'#0.000000')"/>,
      "<xsl:value-of select="$scoringSystemName"/>_maximum" : <xsl:value-of select="format-number(./@maximum,'#0.000000')"/>,
      "<xsl:value-of select="$scoringSystemName"/>_percentage" : <xsl:value-of select='format-number((./text() div ./@maximum), "0.00")' />,
    </xsl:for-each>
    <xsl:choose>
      <xsl:when test="$errors">
        <xsl:for-each select="$errors">"error_trace" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./diagnostic:trace/text()" /></xsl:call-template>",</xsl:for-each>
        "type" : "benchmark_error"
      </xsl:when>
      <xsl:otherwise>"type" : "benchmark_result"</xsl:otherwise>      
    </xsl:choose>    
  }

<xsl:if test="$results"><xsl:for-each select="/xccdf:Benchmark//xccdf:Rule"><xsl:variable name="ruleId" select="./@id"/>
  <xsl:variable name="ruleResultElt" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:rule-result[@idref = $ruleId]"/>
{ 
        "@timestamp" : "<xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/@end-time" />",
        <!--"@message":"Rule result: <xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./xccdf:title/text()" /></xsl:call-template>, <xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$ruleResultElt/xccdf:result/text()" /></xsl:call-template>", -->
        "rule_id" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$ruleId" /></xsl:call-template>",
        "rule_title" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./xccdf:title/text()" /></xsl:call-template>",
        "rule_description" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./xccdf:description/text()" /></xsl:call-template>",
        "rule_result" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$ruleResultElt/xccdf:result/text()" /></xsl:call-template>",
        <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-facts/xccdf:fact">
          "fact_<xsl:call-template name="string-to-json-key"><xsl:with-param name="input" select="./@name" /></xsl:call-template>" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>",
        </xsl:for-each>
        "rule_identifiers" : [
          <xsl:for-each select="./xccdf:ident">
            {
              "system" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./@system" /></xsl:call-template>",
              "identifier" : "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"
            }<xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        ],
        "target_names" : [
          <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target">
            "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"
            <xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        ],
        "target_addresses" : [
          <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-address">
            "<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>"
            <xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        ],
        "type" : "rule_result"
      }
</xsl:for-each></xsl:if>
{ "type" : "end_of_file" }

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

</xsl:stylesheet>
