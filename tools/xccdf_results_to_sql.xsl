<?xml version="1.0"?>
<!--

  Copyright (C) 2014 jOVAL.org.  All rights reserved.

  Description: Sample conversion of XCCDF Results to a SQL file, to store result information in a schema specified herein.
  Filename:    xccdf_results_to_sql.xsl

  Title:	Target results -> SQL file
  OutputFormat: SQL
  InputType:	xccdf_results	: XCCDF rule results

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:diagnostic="http://www.joval.org/schemas/scap/1.2/diagnostic">
  <xsl:output method="text" omit-xml-declaration="yes" indent="no" encoding="utf-8" />

<xsl:template match="/">
  <xsl:variable name="results" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:rule-result"/>
  <xsl:variable name="errors" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:metadata/diagnostic:error"/>
 /**********************************************************************************************************
  * 
  * Sample Transformation of an XCCDF Result to SQL for MySQL
  *
  ********************************************************************************************************/


  /**********************************************************************************************************
   * 1. Create tables if necessary
   ********************************************************************************************************/

  CREATE TABLE IF NOT EXISTS xccdf_result (
    id INT(11) NOT NULL AUTO_INCREMENT,
    start_time DATETIME NULL DEFAULT NULL,
    end_time DATETIME NULL DEFAULT NULL,
    benchmark_title VARCHAR(250) NULL DEFAULT NULL,
    benchmark_version VARCHAR(150) NULL DEFAULT NULL,
    benchmark_id VARCHAR(150) NULL DEFAULT NULL,
    profile_title VARCHAR(150) NULL DEFAULT NULL,
    profile_id VARCHAR(150) NULL DEFAULT NULL,
    test_system VARCHAR(150) NULL DEFAULT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS target (
    id INT(11) NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT(11) NOT NULL,
    type VARCHAR(50) NOT NULL,
    value VARCHAR(250) NOT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS identity (
    id INT(11) NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT(11) NOT NULL,
    name VARCHAR(250) NULL DEFAULT NULL,
    authenticated TINYINT(4) NULL DEFAULT NULL,
    privileged TINYINT(4) NULL DEFAULT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS facts (
    id INT(11) NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT(11) NOT NULL,
    name VARCHAR(50) NOT NULL,
    value VARCHAR(250) NOT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS score (
    id INT NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT NULL DEFAULT NULL,
    method VARCHAR(150) NULL DEFAULT NULL,
    score FLOAT NULL DEFAULT NULL,
    maximum FLOAT NULL DEFAULT NULL,  
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS errors (
    id INT(11) NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT(11) NOT NULL,
    trace TEXT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS rule_result (
    id INT(11) NOT NULL AUTO_INCREMENT,
    xccdf_result_id INT(11) NULL DEFAULT NULL,
    rule_id VARCHAR(250) NULL DEFAULT NULL,
    title VARCHAR(250) NULL DEFAULT NULL,
    description TEXT NULL,
    result VARCHAR(50) NULL DEFAULT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;

  CREATE TABLE IF NOT EXISTS rule_identifier (
    id INT(11) NOT NULL AUTO_INCREMENT,
    rule_result_id INT(11) NULL DEFAULT NULL,
    system VARCHAR(250) NULL DEFAULT NULL,
    identifier VARCHAR(250) NULL DEFAULT NULL,
    PRIMARY KEY (id)
  ) ENGINE=InnoDB;


  /**********************************************************************************************************
   * 2. XCCDF_RESULT: insert 1 row for this xccdf_result
   ********************************************************************************************************/

  <xsl:variable name="selectedProfileId"><xsl:value-of select="/xccdf:Benchmark/xccdf:TestResult/xccdf:profile/@idref"/></xsl:variable>

  INSERT INTO xccdf_result (
    start_time, end_time,
    benchmark_title, benchmark_version, benchmark_id, 
    profile_title, profile_id,
    test_system
  ) VALUES (
    '<xsl:call-template name="mysql-date-format"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/@start-time" /></xsl:call-template>',
    '<xsl:call-template name="mysql-date-format"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/@end-time" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:title/text()" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/@version" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:benchmark/@id" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:Profile[@id=$selectedProfileId]/xccdf:title/text()" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="$selectedProfileId" /></xsl:call-template>',
    '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="/xccdf:Benchmark/xccdf:TestResult/@test-system" /></xsl:call-template>'
  );

  SET @xccdf_result_id = LAST_INSERT_ID();


  /**********************************************************************************************************
   * 3. TARGET NAME(s): add name(s) of the target system
   ********************************************************************************************************/

  <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target[1]">
    INSERT INTO target (
      xccdf_result_id, type, value
    ) VALUES (
      @xccdf_result_id, 'name', '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>'
    );
  </xsl:for-each>


  /**********************************************************************************************************
   * 4. TARGET ADDRESS(ES): add network address(es) of the target system
   ********************************************************************************************************/
   
   <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-address">
    INSERT INTO target (
      xccdf_result_id, type, value
    ) VALUES (
      @xccdf_result_id, 'address', '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>'
    );
  </xsl:for-each>


  /**********************************************************************************************************
   * 5. IDENTITY(IES): add system identity(ies) or user(s) employed during application of the benchmark
   ********************************************************************************************************/

  <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:identity">
    INSERT INTO identity (
      xccdf_result_id, name, authenticated, privileged
    ) VALUES (
      @xccdf_result_id, 
      '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>',
      <xsl:call-template name="boolean-string-to-int"><xsl:with-param name="input" select="./@authenticated" /></xsl:call-template>,
      <xsl:call-template name="boolean-string-to-int"><xsl:with-param name="input" select="./@privileged" /></xsl:call-template>
    );
  </xsl:for-each>


  /**********************************************************************************************************
   * 6. TARGET FACT(s): add facts(s) from TestResult meta data
   ********************************************************************************************************/

  <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:target-facts/xccdf:fact">
    INSERT INTO facts (
      xccdf_result_id, name, value
    ) VALUES (
      @xccdf_result_id, 
      '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./@name" /></xsl:call-template>',
      '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>'
    );
  </xsl:for-each>


  /**********************************************************************************************************
   * 7. SCORE(S): add overall score(s) for this benchmark test
   ********************************************************************************************************/

  <xsl:for-each select="/xccdf:Benchmark/xccdf:TestResult/xccdf:score">
    INSERT INTO score (
      xccdf_result_id, method, score, maximum
    ) VALUES (
      @xccdf_result_id, 
      '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./@system" /></xsl:call-template>',
      <xsl:value-of select="format-number(./text(),'#0.000000')"/>,
      <xsl:value-of select="format-number(./@maximum,'#0.000000')"/>
    );
  </xsl:for-each>

  /**********************************************************************************************************
   * 8. ERROR(s): add errors, if any
   ********************************************************************************************************/
  <xsl:for-each select="$errors">
    INSERT INTO errors (
      xccdf_result_id, trace
    ) VALUES (
      @xccdf_result_id, 
      '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./diagnostic:trace/text()" /></xsl:call-template>'
    );
  </xsl:for-each>

  /**********************************************************************************************************
   * 9. RULES: if there are results, add rule-level results
   ********************************************************************************************************/

  <xsl:if test="$results">
    <xsl:for-each select="/xccdf:Benchmark//xccdf:Rule">
      <xsl:variable name="ruleId" select="./@id"/>
      <xsl:variable name="ruleResultElt" select="/xccdf:Benchmark/xccdf:TestResult/xccdf:rule-result[@idref = $ruleId]"/>

        INSERT INTO rule_result (
          xccdf_result_id, rule_id, title, description, result
        ) VALUES (
          @xccdf_result_id, 
          '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="$ruleId" /></xsl:call-template>',
          '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./xccdf:title/text()" /></xsl:call-template>',
          '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./xccdf:description/text()" /></xsl:call-template>',
          '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="$ruleResultElt/xccdf:result/text()" /></xsl:call-template>'
        );
        <!-- xml_diagnostics: <xsl:copy-of select="$ruleResultElt/xccdf:metadata/diagnostic:rule_diagnostics" /> -->

        SET @rule_result_id = LAST_INSERT_ID();

        <xsl:for-each select="./xccdf:ident">
          INSERT INTO rule_identifier (
            rule_result_id, system, identifier
          ) VALUES (
            @rule_result_id, 
            '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./@system" /></xsl:call-template>',
            '<xsl:call-template name="mysql-escape-string"><xsl:with-param name="input" select="./text()" /></xsl:call-template>'
          );
        </xsl:for-each>
    </xsl:for-each>
  </xsl:if>

</xsl:template>

<!-- MISC UTILITY TEMPLATES -->

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

<xsl:template name="mysql-date-format">
  <xsl:param name="input" />
  <xsl:variable name="output">
    <xsl:choose>
      <xsl:when test="contains($input, '.')">
        <xsl:value-of select="substring-before($input, '.')" />
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$input" />
      </xsl:otherwise>
    </xsl:choose>
  </xsl:variable>
  <xsl:value-of select="$output" />
</xsl:template> 

<xsl:template name="mysql-escape-string">
  <xsl:param name="input" />
  <xsl:variable name="output">
    <xsl:call-template name="replace-substring">
      <xsl:with-param name="from">'</xsl:with-param>
      <xsl:with-param name="to">''</xsl:with-param>
      <xsl:with-param name="subject" select="$input" />
    </xsl:call-template>
  </xsl:variable>
  <xsl:value-of select="$output" />
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
