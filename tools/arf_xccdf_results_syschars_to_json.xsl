<?xml version="1.0"?>
<!--

  Copyright (C) 2015-2018 JovalCM.com.  All rights reserved.

  Description: Sample conversion of XCCDF Results and OVAL System Characteristics to a JSON-formatted event stream
  Filename:    arf_xccdf_results_syschars_to_json.xsl
  To do:       add support for collected item@status and entity@status

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:fn="http://www.w3.org/2005/xpath-functions"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:oval-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
                xmlns:ind-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent"
                xmlns:json="http://joval.org/xsl/json"
                xmlns:diagnostic="http://www.joval.org/schemas/scap/1.2/diagnostic">
  <xsl:output method="text" omit-xml-declaration="yes" indent="no" encoding="utf-8" />
  <xsl:strip-space elements="*" />
  
<xsl:template match="/">

  <!-- Convenience Variables -->
  <xsl:variable name="benchmark" select="//xccdf:Benchmark[1]" />
  <xsl:variable name="testResult" select="//xccdf:TestResult[1]" />
  <xsl:variable name="selectedProfileId"><xsl:value-of select="$testResult/xccdf:profile/@idref"/></xsl:variable>

  <!-- Get results, collected items and errors -->
  <xsl:variable name="results" select="$testResult/xccdf:rule-result"/>
  <xsl:variable name="collectedItems" select="//oval-sc:system_data/(* except ind-sc:variable_item)"/>
  <xsl:variable name="errors" select="$testResult/xccdf:metadata/diagnostic:error"/>

  <xsl:variable name="n">&#10;</xsl:variable>
  <xsl:variable name="t">&#9;</xsl:variable>

  <xsl:text>{&#10;</xsl:text>
    <!-- Scan Metadata: start time, end time, benchmark, profile, etc. -->
    <xsl:value-of select="json:key-value('start_time', $testResult/@start-time, 1, true())" />
    <xsl:value-of select="json:key-value('end_time', $testResult/@end-time, 1, true())" />
    <xsl:value-of select="json:key-value('benchmark', $benchmark/xccdf:title/text(), 1, true())" />
    <xsl:value-of select="json:key-value('benchmark_version', $benchmark/xccdf:version/text(), 1, true())" />
    <xsl:value-of select="json:key-value('benchmark_id', $benchmark/@id, 1, true())" />
    <xsl:value-of select="json:key-value('profile', $benchmark/xccdf:Profile[@id=$selectedProfileId]/xccdf:title/text(), 1, true())" />
    <xsl:value-of select="json:key-value('profile_id', $selectedProfileId, 1, true())" />

    <!-- Target Metadata: system, name, address, user identity, etc. -->
    <xsl:if test="$testResult/@test-system">
      <xsl:value-of select="json:key-value('test_system', $testResult/@test-system, 1, true())" />
    </xsl:if>
    <xsl:if test="$testResult/xccdf:target">
      <xsl:value-of select="json:key-values('target_names', $testResult/xccdf:target[1], 1, true())" />
    </xsl:if>
    <xsl:if test="$testResult/xccdf:target-address">
      <xsl:value-of select="json:key-values('target_addresses', $testResult/xccdf:target-address, 1, true())" />
    </xsl:if>
    <xsl:if test="$testResult/xccdf:identity">
      <xsl:value-of select="json:key('identities', 1)" /><xsl:text> : [&#10;</xsl:text>
        <xsl:for-each select="$testResult/xccdf:identity">
          <xsl:text>&#9;&#9;{&#10;</xsl:text>
            <xsl:value-of select="json:key-value('name', ./text(), 3, true())" />
            <xsl:value-of select="json:key-value('authenticated', ./@authenticated, 3, true())" />
            <xsl:value-of select="json:key-value('privileged', ./@privileged, 3, false())" />
          <xsl:text>&#9;&#9;}</xsl:text>
          <xsl:if test="position() != last()">, </xsl:if>
          <xsl:text>&#10;</xsl:text>
        </xsl:for-each>
      <xsl:text>&#9;],&#10;</xsl:text>
    </xsl:if>
    <xsl:if test="$testResult/xccdf:target-facts/xccdf:fact">
      <xsl:value-of select="json:key('target_facts', 1)" /><xsl:text> : {&#10;</xsl:text>
        <xsl:for-each select="$testResult/xccdf:target-facts/xccdf:fact">
          <xsl:value-of select="json:key-value(./@name, ./text(), 2, boolean(position() != last()) )" />
        </xsl:for-each>
      <xsl:text>&#9;},&#10;</xsl:text>
    </xsl:if>

    <!-- Scan Result Scores: for each available system -->
    <xsl:if test="$testResult/xccdf:score">
      <xsl:value-of select="json:key('scores', 1)" /><xsl:text> : [&#10;</xsl:text>
        <xsl:for-each select="$testResult/xccdf:score">
          <xsl:text>&#9;&#9;{&#10;</xsl:text>
            <xsl:value-of select="json:key-value('system', ./@system, 3, true())" />
            <xsl:value-of select="json:key-value('score', format-number(./text(),'#0.000000'), 3, true())" />
            <xsl:value-of select="json:key-value('maximum', format-number(./@maximum,'#0.000000'), 3, true())" />
            <xsl:value-of select="json:key-value('percentage', format-number((./text() div ./@maximum), '0.00'), 3, false())" />
          <xsl:text>&#9;&#9;}</xsl:text>
          <xsl:if test="position() != last()">, </xsl:if>
          <xsl:text>&#10;</xsl:text>
        </xsl:for-each>
      <xsl:text>&#9;],&#10;</xsl:text>
    </xsl:if>

    <!-- Scan Errors -->
    <xsl:if test="$errors">
      <xsl:value-of select="json:key-values('errors', ./diagnostic:trace/text(), 1, true())" />
    </xsl:if>

    <!-- Individual Rule Results: rollup pass/fail/error/etc for each rule -->
    <xsl:value-of select="json:key('rule_results', 1)" /><xsl:text> : [&#10;</xsl:text>
      <xsl:for-each select="$benchmark//xccdf:Rule">
        <xsl:variable name="ruleId" select="./@id"/>
        <xsl:variable name="ruleResultElt" select="$testResult/xccdf:rule-result[@idref = $ruleId]"/>
        <xsl:text>&#9;&#9;{&#10;</xsl:text>
          <xsl:value-of select="json:key-value('rule_id', $ruleId, 3, true())" />
          <xsl:value-of select="json:key-value('rule_title', ./xccdf:title/text(), 3, true())" />
          <xsl:value-of select="json:key-value('rule_result', $ruleResultElt/xccdf:result/text(), 3, false())" />

          <!-- Additional Metadata for each rule
          
          <xsl:value-of select="json:key-value('rule_description', ./xccdf:description/text(), 3, true())" />
          <xsl:if test="./xccdf:ident">
            <xsl:value-of select="json:key('rule_identifiers', 3)" /><xsl:text> : [&#10;</xsl:text>
              <xsl:for-each select="./xccdf:ident">
                <xsl:text>&#9;&#9;&#9;&#9;{&#10;</xsl:text>
                  <xsl:value-of select="json:key-value('system', ./@system, 4, true())" />
                  <xsl:value-of select="json:key-value('identifier', ./text(), 4, false())" />
                <xsl:text>&#9;&#9;&#9;&#9;}</xsl:text>
                <xsl:if test="position() != last()">, </xsl:if>
                <xsl:text>&#10;</xsl:text>
              </xsl:for-each>
            <xsl:text>&#9;&#9;&#9;],&#10;</xsl:text>
          </xsl:if> -->

        <xsl:text>&#9;&#9;}</xsl:text>
        <xsl:if test="position() != last()">, </xsl:if>
        <xsl:text>&#10;</xsl:text>
      </xsl:for-each>
    <xsl:text>&#9;],&#10;</xsl:text>

    <!-- Collected Items: raw values of posture attributes collected -->
    <xsl:value-of select="json:key('collected_items', 1)" /><xsl:text> : [&#10;</xsl:text>
      <xsl:for-each select="$collectedItems">
        <!-- Handle standard and record type entities separately -->
        <xsl:variable name="recordEntities" select="./*[oval-sc:field]" />
        <xsl:variable name="standardEntities" select="./*[not(oval-sc:field)]" />
        <xsl:text>&#9;&#9;{&#10;</xsl:text>
          <xsl:value-of select="json:key-value('item_name', ./local-name(), 3, true())" />

          <xsl:value-of select="json:key('values', 3)" /><xsl:text> : {&#10;</xsl:text>
            <!-- Standard Item Entities: group values with same entity name and output as key:value or key:[value,value...] -->
            <xsl:for-each-group select="$standardEntities" group-by="local-name()">
              <xsl:choose>
                <xsl:when test="count(current-group()) = 1">
                  <xsl:value-of select="json:key-value(current-grouping-key(), ./text(), 4, boolean(position() != last() or ($standardEntities and $recordEntities)) )" />
                </xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="json:key-values(current-grouping-key(), current-group(), 4, boolean(position() != last() or ($standardEntities and $recordEntities)) )" />
                </xsl:otherwise>
              </xsl:choose>    
            </xsl:for-each-group>

            <!-- Record Type Item Entities:  -->
            <xsl:for-each-group select="$recordEntities" group-by="local-name()">
              <xsl:value-of select="json:key(current-grouping-key(), 4)" /><xsl:text> : [&#10;</xsl:text>
                <xsl:for-each select="current-group()">
                  <xsl:text>&#9;&#9;&#9;&#9;&#9;{&#10;</xsl:text>
                    <xsl:for-each select="./oval-sc:field">
                      <xsl:value-of select="json:key-value(./@name, ./text(), 6, boolean(position() != last()) )" />
                    </xsl:for-each>
                  <xsl:text>&#9;&#9;&#9;&#9;&#9;}</xsl:text>
                  <xsl:if test="position() != last()">, </xsl:if>
                  <xsl:text>&#10;</xsl:text>
                </xsl:for-each>
              <xsl:text>&#9;&#9;&#9;&#9;]</xsl:text>
              <xsl:if test="position() != last()">, </xsl:if>
              <xsl:text>&#10;</xsl:text>
            </xsl:for-each-group>

          <xsl:text>&#9;&#9;&#9;}&#10;</xsl:text>
        <xsl:text>&#9;&#9;}</xsl:text>
        <xsl:if test="position() != last()">, </xsl:if>
        <xsl:text>&#10;</xsl:text>
      </xsl:for-each>
    <xsl:text>&#9;]&#10;</xsl:text>  

    <xsl:text>}</xsl:text>
</xsl:template>

<xsl:template match="text()" />

<!-- MISC UTILITY TEMPLATES -->

<xsl:function name="json:key-values">
  <xsl:param name="key" />
  <xsl:param name="values" />
  <xsl:param name="tabLevel" />
  <xsl:param name="bComma" />
  <xsl:value-of select="json:key($key,$tabLevel)"/><xsl:text> : </xsl:text>
  <xsl:text>[ </xsl:text>
    <xsl:for-each select="$values">
      <xsl:value-of select="json:value(./text())"/><xsl:if test="position() != last()">, </xsl:if>
    </xsl:for-each>
  <xsl:text> ]</xsl:text>
  <xsl:if test="$bComma">,</xsl:if>
  <xsl:text>&#10;</xsl:text>
</xsl:function>

<xsl:function name="json:key-value">
  <xsl:param name="key" />
  <xsl:param name="value" />
  <xsl:param name="tabLevel" />
  <xsl:param name="bComma" />
  <xsl:value-of select="json:key($key,$tabLevel)"/> : <xsl:value-of select="json:value($value)"/>
  <xsl:if test="$bComma">,</xsl:if>
  <xsl:text>&#10;</xsl:text>
</xsl:function>

<xsl:function name="json:key">
  <xsl:param name="input" />
  <xsl:param name="tabLevel" />
  <xsl:for-each select="1 to $tabLevel">
    <xsl:text>&#9;</xsl:text>
  </xsl:for-each>
  <xsl:text>"</xsl:text>
    <xsl:value-of select="fn:replace(lower-case($input), '[^a-z0-9]', '_')"/>
  <xsl:text>"</xsl:text>
</xsl:function>

<xsl:function name="json:value">
  <xsl:param name="input" />
  <xsl:text>"</xsl:text>
    <xsl:value-of select="normalize-space(replace(replace(replace(replace(replace(replace(replace(replace(replace($input,
      '\\','\\\\'),
      '/', '\\/'),
      '&quot;', '\\&quot;'),
      '&#xA;','\\n'),
      '&#xD;','\\r'),
      '&#x9;','\\t'),
      '\n','\\n'),
      '\r','\\r'),
      '\t','\\t'))"/>
  <xsl:text>"</xsl:text>
</xsl:function>

</xsl:stylesheet>
