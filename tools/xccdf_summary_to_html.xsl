<?xml version="1.0"?>
<!--

  Copyright (C) 2013 jOVAL.org.  All rights reserved.

  Description: Converts a jOVAL XCCDF summary report source into an HTML document, from which detailed reports can be browsed.
  Filename:    xccdf_summary_to_html.xsl

-->
<xsl:stylesheet xmlns:xs="http://www.w3.org/2001/XMLSchema"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                xmlns:diagnostic="http://www.joval.org/schemas/scap/1.2/diagnostic">
  <xsl:output method="html" indent="yes"/>
  <xsl:template match="/">
    <xsl:text disable-output-escaping='yes'>&lt;!DOCTYPE html&gt;</xsl:text>
    <xsl:variable name="errors" select="/xccdf:Benchmark/xccdf:TestResult[xccdf:metadata/diagnostic:error]" />
    <xsl:variable name="results" select="/xccdf:Benchmark/xccdf:TestResult[xccdf:score]" />
    <xsl:variable name="TARGET_REPORTS_PATH" select="'./'" />
    <xsl:variable name="TARGET_REPORTS_EXTENSION" select="'.diagnostic.html'" />

    <html>
      <head>
        <title>Scan Results Summary</title>
        <xsl:call-template name="DetailJsCss" />
      </head>
      <body>
        <style type="text/css">
          body { padding:0; }
          #leftnav { position:absolute; width:160px; top:0; left:0; bottom:0px; overflow-y:auto; border-right: 1px solid #eee; padding-top:20px; background-color:#fcfcfc; }
            div.nav-header { font-weight:bold; color:#999; padding:5px 5px 5px 10px; font-size:12px; text-transform:uppercase; }
            ul.nav { margin:0 0 20px 0; border-top: 1px solid #eee; }
              ul.nav li { border-bottom: 1px solid #eee; margin:0; padding:5px 5px 8px 15px; color:#999; background-color:#FaFaFa; cursor:pointer; }
              ul.nav li:hover, ul.nav li.active { color:black; background-color:#ddd; }
          #content { position:absolute; top:0; left:161px; right:0; bottom:0; padding:20px; overflow-y:auto;}
            #overview_chart { height:400px; width:100%; margin-bottom:20px; }
            #external-content { position:absolute; top:0; left:0; right:0; bottom:0; width:100%; height:100%; padding:0; overflow-y:auto; margin:0; border:0; }
        </style>

        <div id="leftnav">

          <ul class="nav unstyled">
            <li rel="overview" class="active">Overview</li>
          </ul>

          <xsl:if test="$results">
            <div class="nav-header">Results (<xsl:value-of select="count($results)"/>)</div>
            <ul class="nav unstyled">
              <xsl:for-each select="$results">
                <xsl:variable name="FriendlyName" select="./xccdf:target-facts/xccdf:fact[@name='FriendlyName']/text()" />
                <li>
                  <xsl:attribute name="rel">
                    <xsl:value-of select="$TARGET_REPORTS_PATH"/><xsl:value-of select="$FriendlyName"/><xsl:value-of select="$TARGET_REPORTS_EXTENSION"/></xsl:attribute>
                  <xsl:value-of select="$FriendlyName"/>
                </li>
              </xsl:for-each>
            </ul>
          </xsl:if>

          <xsl:if test="$errors">
            <div class="nav-header">Errors (<xsl:value-of select="count($errors)"/>)</div>
            <ul class="nav unstyled">
              <xsl:for-each select="$errors">
                <xsl:variable name="FriendlyName" select="./xccdf:target-facts/xccdf:fact[@name='FriendlyName']/text()" />
                <li>
                  <xsl:attribute name="rel">
                    <xsl:value-of select="$TARGET_REPORTS_PATH"/><xsl:value-of select="$FriendlyName"/><xsl:value-of select="$TARGET_REPORTS_EXTENSION"/></xsl:attribute>
                  <xsl:value-of select="$FriendlyName"/>
                </li>
              </xsl:for-each>
            </ul>
          </xsl:if>
        </div>

        <div id="content">

          <h1>Scan Results Summary</h1>
          <table class="keyvalue striped">
            <tr><td>Benchmark</td><td>
              <xsl:value-of select="//xccdf:Benchmark/xccdf:title/text()"/>
              version <xsl:value-of select="//xccdf:Benchmark/xccdf:version/text()"/>
              <small> <xsl:value-of select="//xccdf:Benchmark/@id"/></small>
            </td></tr>

            <tr><td>Profile</td><td>
              <xsl:variable name="profileId"><xsl:value-of select="//xccdf:Benchmark/xccdf:TestResult/xccdf:profile/@idref"/></xsl:variable>
              <xsl:value-of select="//xccdf:Benchmark/xccdf:Profile[@id=$profileId]/xccdf:title/text()"/> <small> <xsl:value-of select="$profileId"/></small>
            </td></tr>

            <tr><td>Targets</td><td>
              <xsl:value-of select="count(/xccdf:Benchmark/xccdf:TestResult)"/> targets in scan
            </td></tr>
          </table>

          <xsl:if test="$errors">
            <h2>Errors (<xsl:value-of select="count($errors)"/> targets)</h2>
            <table class="errors striped">
              <tr class="header">
                <td>Target</td>
                <td>Error Trace</td>
              </tr>
              <xsl:for-each select="$errors">
                <tr>
                  <td><xsl:value-of select="./xccdf:target-facts/xccdf:fact[@name='FriendlyName']/text()"/></td>
                  <td><pre><code class="dos result-error">TRACE: <xsl:value-of select="./xccdf:metadata/diagnostic:error/diagnostic:trace/text()"/></code></pre></td>
                </tr>
              </xsl:for-each>
            </table>
          </xsl:if>

          <xsl:if test="$results">
            <xsl:variable name="scoringSystem" select="//xccdf:Benchmark/xccdf:TestResult/xccdf:score[1]/@system" />
            <xsl:variable name="scoringSystemName">
              <xsl:choose>
                <xsl:when test="$scoringSystem = 'urn:xccdf:scoring:default'">Default Scoring System</xsl:when>
                <xsl:when test="$scoringSystem = 'urn:xccdf:scoring:flat'">Flat Scoring System</xsl:when>
                <xsl:when test="$scoringSystem = 'urn:xccdf:scoring:flat-unweighted'">Flat Unweighted Scoring System</xsl:when>
                <xsl:when test="$scoringSystem = 'urn:xccdf:scoring:absolute'">Absolute Scoring System</xsl:when>
                <xsl:otherwise><xsl:value-of select="$scoringSystem" /></xsl:otherwise>
              </xsl:choose>
            </xsl:variable> 

            <h2>Results (<xsl:value-of select="count($results)" /> targets, <xsl:value-of select="$scoringSystemName" />)</h2>

            <div id="overview_chart"></div>

            <table class="scores striped">
              <tr class="header">
                <td class="method">Target (Friendly Name)</td>
                <td class="score">Score</td>
                <td class="maximum">Max</td>
                <td class="percentage">%</td>
              </tr>

              <xsl:for-each select="$results">
                <xsl:variable name="friendlyName" select="./xccdf:target-facts/xccdf:fact[@name='FriendlyName']/text()" />
                <xsl:variable name="score" select="./xccdf:score/text()" />
                <xsl:variable name="maximum" select="./xccdf:score/@maximum" />
                <xsl:variable name="percentage" select="$score div $maximum" />
                <tr>
                  <td class="method"><xsl:value-of select="$friendlyName" /></td>
                  <td class="score"><xsl:value-of select="format-number($score,'###,##0.00')"/></td>
                  <td class="maximum"><xsl:value-of select="format-number($maximum,'###,##0.00')"/></td>
                  <td class="percentage"><xsl:value-of select='format-number(($percentage), "0.00%")' /></td>
                </tr>
              </xsl:for-each>
                  
            </table>

            <script langauge="javascript">
              var arTargetScores = [];
              var iMaxScore = 0;
            
              <xsl:for-each select="$results">
                <xsl:variable name="friendlyName" select="./xccdf:target-facts/xccdf:fact[@name='FriendlyName']/text()" />
                <xsl:variable name="score" select="./xccdf:score/text()" />
                <xsl:variable name="maximum" select="./xccdf:score/@maximum" />
                <xsl:variable name="percentage" select="$score div $maximum" />
                arTargetScores.push(['<xsl:call-template name="json-escape-string"><xsl:with-param name="input" select="$friendlyName" /></xsl:call-template>', <xsl:value-of select="format-number($score,'###,##0.00')"/>, <xsl:value-of select="format-number($score,'###,##0.00')"/>]);
                if (<xsl:value-of select="format-number($maximum,'###,##0.00')"/> > iMaxScore) iMaxScore = <xsl:value-of select="format-number($maximum,'###,##0.00')"/>;
              </xsl:for-each>

              arTargetScores = _.sortBy(arTargetScores, function(arTargetScore){ return arTargetScore[1]; }).reverse();
              arTargetScores.unshift([ 'Target', 'Score', { role : 'annotation' } ]);

            </script>

          </xsl:if>

        </div>

      </body>
    </html>
  </xsl:template>

  <xsl:template name="DetailJsCss">
    <script langauge="javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
    <style type="text/css">
      /*!
       * Bootstrap v2.3.1
       *
       * Copyright 2012 Twitter, Inc
       * Licensed under the Apache License v2.0
       * http://www.apache.org/licenses/LICENSE-2.0
       *
       * Designed and built with all the love in the world @twitter by @mdo and @fat.
       */
       html,body,div,span,applet,object,iframe,h1,h2,h3,h4,h5,h6,p,blockquote,pre,a,abbr,acronym,address,big,cite,code,del,dfn,em,img,ins,kbd,q,s,samp,small,strike,strong,sub,sup,tt,var,b,u,i,center,dl,dt,dd,ol,ul,li,fieldset,form,label,legend,table,caption,tbody,tfoot,thead,tr,th,td,article,aside,canvas,details,embed,figure,figcaption,footer,header,hgroup,menu,nav,output,ruby,section,summary,time,mark,audio,video{border:0;font-size:100%;font:inherit;vertical-align:baseline;margin:0;padding:0}article,aside,details,figcaption,figure,footer,header,hgroup,menu,nav,section{display:block}body{line-height:1}ol,ul{list-style:none}blockquote,q{quotes:none}blockquote:before,blockquote:after,q:before,q:after{content:none}table{border-collapse:collapse;border-spacing:0}body{font:normal 13px/18px Tahoma,'Lucida Grande',Verdana,Arial,Helvetica,sans-serif;color:#333;background-color:#fff;padding:20px}small{font-size:.80em;padding-left:5px;font-weight:400}a,a:link,a:visited{color:#327dcd;text-decoration:none}a:active,a:hover{color:#0064cd;text-decoration:underline}h1,h2,h3,h4,h5,h6{margin:0 0 9px 0;text-rendering:optimizelegibility;line-height:1.1em;font-weight:700}h1{font-size:32px;font-weight:400}h2{font-size:26px;font-weight:400}h3{font-size:21px;font-weight:400}h4{font-size:18px;font-weight:400}h5{font-size:16px;font-weight:400}h6{font-size:13px}table{width:100%;margin-bottom:18px}td{padding:4px 5px;line-height:18px;text-align:left;vertical-align:top;border:1px solid #bbb}tr.header td{font-weight:700;vertical-align:bottom;background:#d3d3d3}table.striped tr:nth-child(odd) td,.altBg{background-color:#f9f9f9}table.striped tr.header:nth-child(odd) td{background:#d3d3d3}table.keyvalue td:first-child{font-weight:700}table.scores td.method{text-align:left}table.scores td.score{text-align:right;width:100px}table.scores td.maximum{text-align:right;width:100px}table.scores td.percentage{text-align:right;width:100px}table.rule-results tr.group{background:#e3e3e3;font-weight:700}table.rule-results td.identifiers{width:212px;text-alig
-left:2px solid #b94a48}table.rule-diagnostics tr#content li.group.result-unknown>ul,table.rule-results tr.diagnostics li.group.result-unknown>ul{border-left:2px solid #c09853}table.rule-diagnostics tr#content li.group.result-error>ul,table.rule-results tr.diagnostics li.group.result-error>ul{border-left:2px solid #c09853}table.rule-diagnostics tr#content li.group.result-not_evaluated>ul,table.rule-results tr.diagnostics li.group.result-not_evaluated>ul{border-left:2px solid #c09853}table.rule-diagnostics tr#content li.group.result-not_applicable>ul,table.rule-results tr.diagnostics li.group.result-not_applicable>ul{border-left:2px solid #999}table.rule-diagnostics tr#content ul.logic ul.logic,table.rule-results tr.diagnostics ul.logic ul.logic{border-width:0;margin-left:0!important;padding-top:0!important}table.rule-diagnostics tr#content ul.logic h5,table.rule-results tr.diagnostics ul.logic h5{margin-bottom:0!important;padding-bottom:0!important}table.rule-diagnostics tr#content li.extend-definition.group,table.rule-results tr.diagnostics li.extend-definition.group{text-transform:none;font-weight:400}table.rule-diagnostics tr#content li.test small,table.rule-results tr.diagnostics li.test small,table.rule-diagnostics tr#content li.sce small,table.rule-results tr.diagnostics li.sce small,table.rule-diagnostics tr#content li.ocil small,table.rule-results tr.diagnostics li.ocil small{margin:0;text-transform:uppercase;font-weight:700;color:inherit;font-size:inherit}table.rule-diagnostics tr#content span.test-title,table.rule-results tr.diagnostics span.test-title,table.rule-diagnostics tr#content span.sce-title,table.rule-results tr.diagnostics span.sce-title{cursor:pointer;text-transform:none;font-weight:400}table.rule-diagnostics tr#content div.detail-section,table.rule-results tr.diagnostics div.detail-section{background-color:#fff;color:#333;margin-bottom:18px;font-size:12px;line-height:16px}table.rule-diagnostics tr#content div.detail-section.result-true,table.rule-results tr.diagnostics div.detail-section.r
    </style>
    <script type="text/javascript" src="https://www.google.com/jsapi"></script>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/underscore.js/1.6.0/underscore-min.js"></script>
    
    <script langauge="javascript">
        <![CDATA[ 
          $(document).ready(function(){

            $('.nav').on('click', 'li', function(){
              var jLi = $(this);
              if (jLi.is('.active')) return false;

              var jCurrent = $('.nav li.active');
              var sUrl = jLi.attr('rel');

              if ($('#summary-content').length == 0){
                $('#content').wrapInner('<div id="summary-content"></div>').append('<iframe id="external-content"></iframe>');
              }

              if (sUrl == 'overview') {
                $('#external-content').hide();
                $('#summary-content').show();
              } else {
                $('#summary-content').hide();
                $('#external-content').attr('src', sUrl).show();                
              }

              jCurrent.removeClass('active');
              jLi.addClass('active');
            });
            
          });

          // setup overview chart
          google.load('visualization', '1.0', {'packages':['corechart']});
          google.setOnLoadCallback(function drawChart() {

            var data = new google.visualization.arrayToDataTable(arTargetScores);
            var options = {
              animation:{ duration: 750, easing: 'out' },
              axisTitlesPosition: 'out',                    // 'in', 'none'
              backgroundColor: {
                stroke: '#bbb',
                strokeWidth: 1,
                fill: '#fff'
              },
              //chartArea: {left:auto, top:0, width:auot,height:"100%"},
              dataOpacity: 0.6,
              enableInteractivity: true,
              fontSize: 13,
              fontName: 'Tahoma',
              hAxis: { title: 'Target (Friendly Name)', textStyle: { fontSize : 11 }, titleTextStyle : { bold:true, italic:false, color:'#333' } },
              vAxis: { title: 'Score', maxValue: iMaxScore, minValue:0, textStyle: { fontSize : 11 }, titleTextStyle : { bold:true, italic:false, color:'#333' } },
              legend: { position: 'none' }
            };

            //if (arTargetScores.length > 0) options.hAxis.slantedText = true;
            if (arTargetScores.length > 20) data.removeColumn(2);            

            var chart = new google.visualization.ColumnChart(document.getElementById('overview_chart'));
            chart.draw(data, options);
          });
        ]]>
    </script>
  </xsl:template>

  <!-- Utility Formatting Templates -->

  
  <xsl:template name="string-to-upper">
    <xsl:param name="input" />
    <xsl:variable name="inputUpper" select="translate($input, 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')" />
    <xsl:value-of select="$inputUpper" />
  </xsl:template> 

  <xsl:template name="ToHTML">
    <xsl:param name="sourceElt"/>
    <xsl:for-each select="$sourceElt">
      <!-- remove element's ns prefix -->
      <xsl:element name="div">
        <!-- add attributes sans ns prefix -->
        <xsl:for-each select="@*">
          <xsl:attribute name="{local-name()}">
            <xsl:value-of select="."/>
          </xsl:attribute>
        </xsl:for-each>

        <!-- add class attribute as xccdf_class -->
        <xsl:if test="@class">
          <xsl:attribute name="xccdf_class">
            <xsl:value-of select="@class"/>
          </xsl:attribute>
        </xsl:if>

        <!-- add element name as html class attribute -->
        <xsl:if test="true()">
          <xsl:attribute name="class">
            <xsl:value-of select="local-name()"/>
          </xsl:attribute>
        </xsl:if>
        
        <!-- add elt value, trimmed if human readable -->
        <xsl:choose>
          <xsl:when test="local-name() = 'title' or local-name() = 'description'">
            <xsl:value-of select="normalize-space(./text())"/>            
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="./text()"/>
          </xsl:otherwise>
        </xsl:choose>

        <!-- apply to children -->
        <xsl:for-each select="./*">
          <xsl:call-template name="ToHTML">
            <xsl:with-param name="sourceElt" select="."/>
          </xsl:call-template>
        </xsl:for-each>

      </xsl:element>
    </xsl:for-each>
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

  <xsl:template name="printDateTime">
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
