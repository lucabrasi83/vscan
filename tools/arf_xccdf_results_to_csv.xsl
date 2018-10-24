<?xml version="1.0"?>
<!--

  Copyright (C) 2015 JovalCM.com.  All rights reserved.

  Description: Sample conversion of XCCDF Results into a comma-separated values ("CSV")
  Filename:    arf_xccdf_results_to_csv.xsl

  Title:  Target results CSV
  OutputFormat: CSV
  InpytType:  arf : Asset Report Format

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:diagnostic="http://www.joval.org/schemas/scap/1.2/diagnostic">
  <xsl:output method="text" omit-xml-declaration="yes" indent="no" encoding="utf-8" />
  <xsl:strip-space elements="*" />
  
  <xsl:template match="/">
    <xsl:variable name="benchmark" select="//xccdf:Benchmark[1]" />
    <xsl:variable name="testResult" select="//xccdf:TestResult[1]" />
    <xsl:variable name="selectedProfileId"><xsl:value-of select="$testResult/xccdf:profile/@idref"/></xsl:variable>
    <xsl:variable name="results" select="$testResult/xccdf:rule-result"/>
    <xsl:variable name="errors" select="$testResult/xccdf:metadata/diagnostic:error"/>

    <xsl:text>start_time,end_time,benchmark,benchmark_version,benchmark_id,profile,profile_id,test_system,target_names,target_addresses,identities|authenticated|privileged,facts|value,system|score|max|percentage,error_trace,rule_id,rule_title,rule_description,rule_result,system|identifier</xsl:text>
    <xsl:text>&#xa;</xsl:text>

    <xsl:variable name="benchmark_fields">
      <xsl:value-of select="$testResult/@start-time" /><xsl:text>,</xsl:text>
      <xsl:value-of select="$testResult/@end-time" /><xsl:text>,</xsl:text>
      <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$benchmark/xccdf:title/text()" /></xsl:call-template><xsl:text>,</xsl:text>
      <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$benchmark/xccdf:version/text()" /></xsl:call-template><xsl:text>,</xsl:text>
      <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$benchmark/@id" /></xsl:call-template><xsl:text>,</xsl:text>
      <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$benchmark/xccdf:Profile[@id=$selectedProfileId]/xccdf:title/text()" /></xsl:call-template><xsl:text>,</xsl:text>
      <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$selectedProfileId" /></xsl:call-template><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/@test-system">
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$testResult/@test-system" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/xccdf:target">
        <xsl:variable name="subfields">
          <xsl:for-each select="$testResult/xccdf:target[1]">
            <xsl:value-of select="./text()" /><xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/xccdf:target-address">
        <xsl:variable name="subfields">
          <xsl:for-each select="$testResult/xccdf:target-address">
            <xsl:value-of select="./text()" /><xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/xccdf:identity">
        <xsl:variable name="subfields">
          <xsl:for-each select="$testResult/xccdf:identity">
            <xsl:value-of select="concat(./text(), '|', ./@authenticated,'|' , ./@privileged)" />
            <xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/xccdf:target-facts/xccdf:fact">
        <xsl:variable name="subfields">
          <xsl:for-each select="$testResult/xccdf:target-facts/xccdf:fact">
            <xsl:value-of select="concat(./@name, '|', ./text())" /><xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$testResult/xccdf:score">
        <xsl:variable name="subfields">
          <xsl:for-each select="$testResult/xccdf:score">
            <xsl:value-of select="concat(./@system, '|', format-number(./text(),'#0.000000'), '|', format-number(./@maximum,'#0.000000'), '|', format-number((./text() div ./@maximum), '0.00'))" /><xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>

      <xsl:if test="$errors">
        <xsl:variable name="subfields">
          <xsl:for-each select="$errors">
            <xsl:value-of select="./diagnostic:trace/text()" /><xsl:if test="position() != last()">, </xsl:if>
          </xsl:for-each>
        </xsl:variable>
        <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
      </xsl:if><xsl:text>,</xsl:text>    
    </xsl:variable>

    <xsl:choose>
      <xsl:when test="$results">
        <xsl:for-each select="$benchmark//xccdf:Rule">
          <xsl:variable name="ruleId" select="./@id"/>
          <xsl:variable name="ruleResultElt" select="$testResult/xccdf:rule-result[@idref = $ruleId]"/>

          <xsl:value-of select="$benchmark_fields" />
          <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$ruleId" /></xsl:call-template><xsl:text>,</xsl:text>
          <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="./xccdf:title/text()" /></xsl:call-template><xsl:text>,</xsl:text>
          <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="./xccdf:description/text()" /></xsl:call-template><xsl:text>,</xsl:text>
          <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$ruleResultElt/xccdf:result/text()" /></xsl:call-template><xsl:text>,</xsl:text>

          <xsl:if test="./xccdf:ident">
            <xsl:variable name="subfields">
              <xsl:for-each select="./xccdf:ident">
                <xsl:value-of select="concat(./@system, '|', ./text())" /><xsl:if test="position() != last()">, </xsl:if>
              </xsl:for-each>
            </xsl:variable>
            <xsl:call-template name="output-csv-field"><xsl:with-param name="input" select="$subfields" /></xsl:call-template>
          </xsl:if>
          <xsl:text>&#xa;</xsl:text>
        </xsl:for-each>
        
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$benchmark_fields" />
        <xsl:text>&#xa;</xsl:text>
      </xsl:otherwise>
    </xsl:choose>

  </xsl:template>

  <xsl:template match="text()" />

  <!-- MISC UTILITY TEMPLATES -->

  <xsl:template name="output-csv-field">
    <xsl:param name="input" />

    <xsl:variable name="input">
      <xsl:value-of select="normalize-space($input)" />
    </xsl:variable>

    <xsl:choose>
      <xsl:when test="contains($input, '&quot;')">
        <!-- input contains quotes: escape quotes and enclose with quotes -->
        <xsl:variable name="quotes_escaped">
          <xsl:call-template name="replace-substring">
            <xsl:with-param name="from">&quot;</xsl:with-param>
            <xsl:with-param name="to">&quot;&quot;</xsl:with-param>
            <xsl:with-param name="subject" select="$input" />
          </xsl:call-template>
        </xsl:variable>
        <xsl:value-of select="concat('&quot;', $quotes_escaped, '&quot;')" />
      </xsl:when>
      <xsl:when test="contains($input, ',') or contains($input, '&#xa;')">
        <!-- input contains comma and/or line feed: enclose with quotes -->
        <xsl:value-of select="concat('&quot;', $input, '&quot;')" />
      </xsl:when>
      <xsl:otherwise>
        <!-- simply output value -->
        <xsl:value-of select="$input" />
      </xsl:otherwise>
    </xsl:choose>  

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
