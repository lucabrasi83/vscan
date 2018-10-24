/**
  Copyright (C) 2015-2016 JovalCM.com. All rights reserved.
  Description: Converts a JSON summary result into a human-readable HTML report

  Title: Scan summary HTML report
  OutputFormat: HTML
  InputType: summary_json : Scan summary JSON
*/

function transform(sData){
  var oData = prepData(JSON.parse(sData));
  var arOutput = [];

  arOutput.push(getPageTop());
  arOutput.push(getBenchmarkSection(oData));
  arOutput.push(getChartsSection(oData));
  arOutput.push(getRuleResultsSection(oData));
  arOutput.push(getTargetResultsSection(oData));
  arOutput.push(getPageBottom(oData));

  return arOutput.join('\n');
}

function prepData(oData){
  // if a target has no rule results (b/c of error probably, make results all "ERROR")
  var oTarget;
  for (var iTarget=0; iTarget < oData.targets.length; iTarget++){
    oTarget = oData.targets[iTarget];
    if (oTarget.rule_results) continue;

    oTarget.rule_results = [];
    for (var iRule=0; iRule < oData.rules.length; iRule++) {
      oTarget.rule_results.push(3);
      oData.rules[iRule].result_totals[2]++;
    }
  }
  return oData;
}

function getBenchmarkSection(oData){
  var arOutput = [];
  var oBenchmark = oData.benchmark;
  arOutput.push('<section><a name="benchmark"></a>');
    arOutput.push('<h2>Benchmark</h2>');
    arOutput.push('<dl class="dl-horizontal">');
      arOutput.push('<dt>Benchmark</dt><dd>'+ oBenchmark.benchmark_title +' '+ ((oBenchmark.xccdf_version && oBenchmark.xccdf_version > 0) ? oBenchmark.xccdf_version : '') +' <small>'+ oBenchmark.xccdf_id +'</small></dd>');
      arOutput.push('<dt>Profile</dt><dd>'+ oBenchmark.profile_name +'</dd>');
      //arOutput.push('<dt>Scoring</dt><dd>'+ oBenchmark.scoring_model_id +' with a pass threshold of '+ oBenchmark.pass_threshold +'</dd>');
      arOutput.push('<dt></dt><dd></dd>');
    arOutput.push('</dl>');
    arOutput.push('</section>');
  return arOutput.join('\n');
}

function getChartsSection(oData){
  var arOutput = [];
  var oBenchmark = oData.benchmark;
  arOutput.push('<section><a name="results-summary"></a>');
    arOutput.push('<h2>Results Summary</h2>');
    arOutput.push('<div class="row">');
        arOutput.push('<div class="col-sm-4 col-md-3"><h4 class="text-center">Rule Results</h4><canvas id="rules-chart"></canvas><ul class="list-unstyled"><li><span style="color:#5cb85c" class="glyphicon glyphicon-stop"></span><span style="color:#5cb85c">Pass (no failures or errors)</span></li><li><span style="color:#d9534f" class="glyphicon glyphicon-stop"></span> <span style="color:#d9534f">Fail (some failures)</span></li><li><span style="color:#ec971f" class="glyphicon glyphicon-stop"></span> <span style="color:#ec971f">Unknown (some unknown, no failures)</span></li><li><span style="color:#31b0d5" class="glyphicon glyphicon-stop"></span> <span style="color:#31b0d5">Not Applicable</span></li></ul></div>');
        arOutput.push('<div class="col-sm-4 col-md-3 col-md-offset-1"><h4 class="text-center">Target Results</h4><canvas id="targets-chart"></canvas><ul class="list-unstyled"><li><span style="color:#5cb85c" class="glyphicon glyphicon-stop"></span><span style="color:#5cb85c">Pass (no failures or errors)</span></li><li><span style="color:#d9534f" class="glyphicon glyphicon-stop"></span> <span style="color:#d9534f">Fail (some failures)</span></li><li><span style="color:#ec971f" class="glyphicon glyphicon-stop"></span> <span style="color:#ec971f">Unknown (some unknown, no failures)</span></li><li><span style="color:#31b0d5" class="glyphicon glyphicon-stop"></span> <span style="color:#31b0d5">Not Applicable</span></li></ul></div>');
      arOutput.push('</div>');
    arOutput.push('</section>');
  return arOutput.join('\n');
}

function getRuleResultsSection(oData){
  var arOutput = [];
  var arRules = oData.rules;
  var oRule, oTarget, bOddRow, sTdClass;
  var arTargetNameToIndex = [];

  for (var iRule=0; iRule < arRules.length; iRule++){
    arRules[iRule].targets_by_result = [ [],[],[],[],[],[],[],[] ];
  }
  for (var iTarget=0; iTarget < oData.targets.length; iTarget++){
    oTarget = oData.targets[iTarget];
    arTargetNameToIndex[oTarget.friendly_name] = iTarget;
    for (var iRule=0; iRule < oTarget.rule_results.length; iRule++) {
      arRules[iRule].targets_by_result[oTarget.rule_results[iRule] - 1].push(oTarget.friendly_name);
    }
  }
  oData.rule_result_totals = [ 0, 0, 0, 0 ];

  arOutput.push('<section><a name="rules"></a>');
    arOutput.push('<h2>Results by Rule</h2>');
      arOutput.push('<table class="table table-bordered table-hover expand-details rules-list">');
        arOutput.push('<thead><tr><th>Rule</th><th>References</th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="targets with PASS result">Pass</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="targets with FAIL result">Fail</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="targets with UKNOWN, ERROR or NOT CHECKED result">Unknown</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="targets with NOT APPLICABLE, NOT SELECTED or INFORMATIONAL result">Not Applicable</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
        arOutput.push('</tr></thead>');
        
        arOutput.push('<tbody>');
          for (var iRule=0; iRule < arRules.length; iRule++){
            oRule = arRules[iRule];
            bOddRow = !bOddRow;

            var iPass = oRule.result_totals[0];
            var iFail = oRule.result_totals[1];
            var iUnkown = oRule.result_totals[2] + oRule.result_totals[3] + oRule.result_totals[4];
            var iNA = oRule.result_totals[5] + oRule.result_totals[6] +oRule.result_totals[7];

            if (iFail > 0) {
              oData.rule_result_totals[1]++;
            } else if (iUnkown > 0) {
              oData.rule_result_totals[2]++;
            } else if (iPass > 0) {
              oData.rule_result_totals[0]++;
            } else {
              oData.rule_result_totals[3]++;
            }

            arOutput.push('<tr class="'+ ((bOddRow) ? 'odd':'even') +' toggle">');
              // Rule Column
              arOutput.push('<td>');
                arOutput.push('<span class="glyphicon glyphicon-menu-right on-closed" aria-hidden="true"></span><span class="glyphicon glyphicon-menu-down on-open" aria-hidden="true"></span> ');
                arOutput.push(oRule.title);
                arOutput.push('<a name="rule-'+ iRule +'"></a>');
              arOutput.push('</td>');

              // References Column
              arOutput.push('<td>');
                if (!oRule.references) oRule.references = [];
                arOutput.push('<ul class="list-unstyled" style="margin-bottom:0;">');
                for (var iRef=0; iRef < oRule.references.length; iRef++){
                  arOutput.push('<li>'+ getReferenceAsLink(oRule.references[iRef]) +'</li>');
                }
                arOutput.push('</ul>');
              arOutput.push('</td>');

              arOutput.push('<td>'+ iPass +'</td>');
              arOutput.push('<td class="'+ ((iFail > 0) ? 'danger text-danger' : '') +'">'+ iFail +'</td>');
              arOutput.push('<td class="'+ ((iUnkown > 0) ? 'warning text-warning' : '') +'">'+ iUnkown +'</td>');
              arOutput.push('<td class="'+ ((iNA > 0) ? 'info text-info' : '') +'">'+ iNA +'</td>');
            arOutput.push('</tr>');

            // Details Row
            arOutput.push('<tr class="details-row hide">');
              arOutput.push('<td colspan="6">');
                arOutput.push('<h4>'+ oRule.title +' <small>'+ oRule.id +'</small></h4>');
                if (oRule.description != '') arOutput.push('<p class="small">'+ oRule.description +'</p>');
                if (oRule.references.length > 0) {
                  arOutput.push('<h5>References</h5><ul>');
                  for (var iRef=0; iRef < oRule.references.length; iRef++){
                    arOutput.push('<li>'+ getReferenceAsLink(oRule.references[iRef]) +'</li>');
                  }
                  arOutput.push('</ul>');
                }

                arOutput.push('<h5>Target Results</h5>');
                var arResults = [ 'PASS', 'FAIL', 'ERROR', 'UNKNOWN', 'NOT CHECKED', 'NOT APPLICABLE', 'NOT SELECTED', 'INFORMATIONAL' ];
                var arResultClass = [ 'success', 'danger', 'warning', 'warning', 'warning', 'info', 'info', 'info' ];
                arOutput.push('<div class="btn-group btn-group-xs" role="group">');
                  for (var iResult = 0; iResult < arResults.length; iResult++){
                    if (oRule.targets_by_result[iResult] == 0) continue;
                    arOutput.push('<button type="button" class="btn btn-xs tabby btn-'+ arResultClass[iResult] +'" href="#rule-'+ iRule +'-result-'+ iResult +'">'+ arResults[iResult] +' ('+ oRule.targets_by_result[iResult].length +')</button>');
                  }
                arOutput.push('</div><br/>');
                
                for (var iResult = 0; iResult < arResults.length; iResult++){
                  arOutput.push('<div class="alert alert-'+ arResultClass[iResult] +' tabby-target hide" id="rule-'+ iRule +'-result-'+ iResult +'">');
                  arOutput.push('<strong>Targets</strong>: ');
                    var arLinks = [];
                    for (var iTarget=0; iTarget < oRule.targets_by_result[iResult].length; iTarget++) {
                      var sTargetName = oRule.targets_by_result[iResult][iTarget];
                      arLinks.push('<a class="small goto-target" href="#target-'+ arTargetNameToIndex[sTargetName] +'">'+ sTargetName +'</a>');  
                    }
                    arOutput.push(arLinks.join(', '));
                  arOutput.push('</div>');
                }
              arOutput.push('</td>');
            arOutput.push('</tr>');
          }
        
        arOutput.push('</tbody>');
      arOutput.push('</table>');
    arOutput.push('</section>');
    return arOutput.join('\n');
}

function getTargetResultsSection(oData){
  var arOutput = [];
  var arRules = oData.rules;
  var arTargets = oData.targets;
  var oTarget, bOddRow, sTdClass, sTargetId;

  for (var iTarget=0; iTarget < arTargets.length; iTarget++){
    oTarget = arTargets[iTarget];
    oTarget.rules_by_result = [ [],[],[],[],[],[],[],[] ];
    for (var iRule=0; iRule < oTarget.rule_results.length; iRule++) {
      oTarget.rules_by_result[oTarget.rule_results[iRule] - 1].push(iRule);
    }
  }

  oData.targets_result_totals = [ 0, 0, 0, 0 ];

  arOutput.push('<section><a name="targets"></a>');
    arOutput.push('<h2>Results by Target</h2>');
      arOutput.push('<table class="table table-bordered table-hover expand-details targets-list">');
        arOutput.push('<thead><tr><th>Target</th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="rules with PASS result">Pass</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="rules with FAIL result">Fail</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="rules with UKNOWN, ERROR or NOT CHECKED result">Unknown</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
          arOutput.push('<th><span class="with-tooltip" data-toggle="tooltip" data-placement="bottom" title="rules with NOT APPLICABLE, NOT SELECTED or INFORMATIONAL result">Not Applicable</span><span class="glyphicon glyphicon-filter pull-right small text-muted filter"></span></th>');
        arOutput.push('</tr></thead>');

        arOutput.push('<tbody>');
          for (var iTarget=0; iTarget < oData.targets.length; iTarget++){
            oTarget = arTargets[iTarget];
            bOddRow = !bOddRow;

            var iPass = oTarget.rules_by_result[0].length;
            var iFail = oTarget.rules_by_result[1].length;
            var iUnkown = oTarget.rules_by_result[2].length + oTarget.rules_by_result[3].length + oTarget.rules_by_result[4].length;
            var iNA = oTarget.rules_by_result[5].length + oTarget.rules_by_result[6].length +oTarget.rules_by_result[7].length;

            if (iFail > 0) {
              oData.targets_result_totals[1]++;
            } else if (iUnkown > 0) {
              oData.targets_result_totals[2]++;
            } else if (iPass > 0) {
              oData.targets_result_totals[0]++;
            } else {
              oData.targets_result_totals[3]++;
            }

            arOutput.push('<tr class="'+ ((bOddRow) ? 'odd':'even') +' toggle">');
              // Target Column
              arOutput.push('<td>');
                arOutput.push('<span class="glyphicon glyphicon-menu-right on-closed" aria-hidden="true"></span><span class="glyphicon glyphicon-menu-down on-open" aria-hidden="true"></span> ');
                arOutput.push(oTarget.friendly_name);
                arOutput.push('<a name="target-'+ iTarget +'"></a>');
              arOutput.push('</td>');

              arOutput.push('<td>'+ iPass +'</td>');
              arOutput.push('<td class="'+ ((iFail > 0) ? 'danger text-danger' : '') +'">'+ iFail +'</td>');
              arOutput.push('<td class="'+ ((iUnkown > 0) ? 'warning text-warning' : '') +'">'+ iUnkown +'</td>');
              arOutput.push('<td class="'+ ((iNA > 0) ? 'info text-info' : '') +'">'+ iNA +'</td>');
            arOutput.push('</tr>');

            // Details Row
            arOutput.push('<tr class="details-row hide">');
              arOutput.push('<td colspan="6">');
                arOutput.push('<h4>'+ oTarget.friendly_name +'</h4>');

                if (oTarget.status_detail || oTarget.error_trace) {
                  arOutput.push('<div class="alert alert-warning">');
                    if (oTarget.status_detail) arOutput.push('<strong>'+ oTarget.status_detail +'</strong>');
                    if (oTarget.error_trace) arOutput.push('<pre style="border:0;background-color:inherit;padding:0;color:inherit;">'+ oTarget.error_trace +'</pre>');
                  arOutput.push('</div>');
                } 

                arOutput.push('<h5>Rule Results</h5>');
                var arResults = [ 'PASS', 'FAIL', 'ERROR', 'UNKNOWN', 'NOT CHECKED', 'NOT APPLICABLE', 'NOT SELECTED', 'INFORMATIONAL' ];
                var arResultClass = [ 'success', 'danger', 'warning', 'warning', 'warning', 'info', 'info', 'info' ];
                arOutput.push('<div class="btn-group btn-group-xs" role="group">');
                  for (var iResult = 0; iResult < arResults.length; iResult++){
                    if (oTarget.rules_by_result[iResult].length == 0) continue;
                    arOutput.push('<button type="button" class="btn btn-xs tabby btn-'+ arResultClass[iResult] +'" href="#target-'+ iTarget +'-result-'+ iResult +'">'+ arResults[iResult] +' ('+ oTarget.rules_by_result[iResult].length +')</button>');
                  }
                arOutput.push('</div><br/>');
                
                for (var iResult = 0; iResult < arResults.length; iResult++){
                  arOutput.push('<div class="alert alert-'+ arResultClass[iResult] +' tabby-target hide" id="target-'+ iTarget +'-result-'+ iResult +'">');
                  arOutput.push('<strong>Rules</strong>: ');
                    var arLinks = [];
                    for (var iRuleResult=0; iRuleResult < oTarget.rules_by_result[iResult].length; iRuleResult++) {
                      var iRule = oTarget.rules_by_result[iResult][iRuleResult];
                      arLinks.push('<a class="small goto-rule" href="#rule-'+ iRule +'">'+ arRules[iRule].title +'</a>');  
                    }
                    arOutput.push(arLinks.join(', '));
                  arOutput.push('</div>');
                }
              arOutput.push('</td>');
            arOutput.push('</tr>');
          }
        
        arOutput.push('</tbody>');
      arOutput.push('</table>');
    arOutput.push('</section>');
    return arOutput.join('\n');
}

function getPageTop(){
  return '\
    <!DOCTYPE html>\
    <html lang="en">\
      <head>\
        <meta charset="utf-8">\
        <meta http-equiv="X-UA-Compatible" content="IE=edge">\
        <meta name="viewport" content="width=device-width, initial-scale=1">\
        <title>Joval Scan Result Summary</title>\
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" crossorigin="anonymous">\
        <!--[if lt IE 9]>\
          <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>\
          <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>\
        <![endif]-->\
        <style type="text/css">\
          body { padding-top:70px; } \
          a[name] { display:block; position:relative; top:-75px; visibility:hidden; } \
          tr.toggle .on-open { display:none; } \
          tr.toggle .on-closed { display:inline; } \
          tr.toggle.open .on-open { display:inline; } \
          tr.toggle.open .on-closed { display:none; } \
          tr th span.filter { padding:3px; border-radius:3px; position:relative; top:1px; } \
          tr th span.filter.active { background-color:rgb(51,51,51); color:white; } \
          tr.details-row, tr.toggle.open { background-color:#f9f9f9; }\
          table > tbody > tr.details-row > td { padding:24px; } \
          td { min-width:100px; }\
          .label-expander { background-color:#bbb; cursor:pointer; }\
          .with-tooltip { border-bottom:1px dotted #777; }\
          .panel { margin-bottom:5px; }\
        </style>\
      </head>\
      <body>\
        <nav class="navbar navbar-default navbar-fixed-top"> \
          <div class="container-fluid"> \
            <div class="navbar-header"> \
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false"><span class="sr-only">Toggle navigation</span><span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span></button> \
              <a class="navbar-brand" href="#top">Joval Scan Summary</a> \
            </div> \
            <div class="collapse navbar-collapse"> \
              <ul class="nav navbar-nav"> \
                <li><a href="#benchmark">Benchmark</a></li> \
                <li><a href="#results-summary">Results Summary</a></li> \
                <li><a href="#rules">Results by Rule</a></li> \
                <li><a href="#targets">Results by Target</a></li> \
              </ul> \
            </div> \
          </div> \
        </nav> \
        <div class="container">';
}

function getPageBottom(oData){
  var minRuleSlice = Math.round((oData.rule_result_totals[0] + oData.rule_result_totals[1] + oData.rule_result_totals[2] + oData.rule_result_totals[3]) / 72);
  var minTargetSlice = Math.round((oData.targets_result_totals[4] = oData.targets_result_totals[0] + oData.targets_result_totals[1] + oData.targets_result_totals[2] + oData.targets_result_totals[3]) / 72);

  return '\
        </div>\
        <scri'+'pt src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></scri'+'pt>\
        <scri'+'pt src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==" crossorigin="anonymous"></scri'+'pt>\
        <scri'+'pt src="https://cdnjs.cloudflare.com/ajax/libs/underscore.js/1.8.3/underscore-min.js"></scri'+'pt>\
        <scri'+'pt src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/1.0.2/Chart.js"></scri'+'pt>\
        <scri'+'pt>\
          $(document).ready(function(){ initializeJS(); }); \
          window.setTimeout(initializeJS, 500); \
          var bInitialized = false; \
          function initializeJS(){ \
            if (bInitialized) return true; \
            bInitialized = true; \
            $(".with-tooltip").tooltip(); \
            $("table.expand-details").on("click", ".tabby", function(){ \
              var jButton = $(this); \
              var jContext = jButton.closest("tr"); \
              jContext.find(".tabby-target").hide(); \
              if (jButton.is(".active")) { jButton.removeClass("active"); return; } \
              jContext.find(".tabby.active").removeClass("active"); \
              jButton.addClass("active"); \
              jContext.find(jButton.attr("href")).removeClass("hide").show(); \
            }); \
            $("table.expand-details").on("click", "tr.toggle", function(){ \
              var jTR = $(this); \
              var jDetailsTR = jTR.next("tr"); \
              if (jTR.hasClass("open")) { \
                jDetailsTR.hide(); \
                jTR.removeClass("open"); \
              } else { \
                jDetailsTR.removeClass("hide").show(); \
                jTR.addClass("open"); \
              } \
            }); \
            $("table.expand-details").on("mouseenter", "span.filter", function(){ \
              $(this).removeClass("text-muted"); \
            }).on("mouseleave", "span.filter", function(){ \
              $(this).addClass("text-muted"); \
            }).on("click", "span.filter", function(){ \
              var jButton = $(this); \
              var jTable = $(this).closest("table"); \
              jTable.find("tr.toggle.open").click(); \
              if (jButton.hasClass("active")) { \
                jTable.find("tr.toggle").show(); \
                jButton.removeClass("active"); \
                return; \
              } \
              jTable.find("span.filter.active").removeClass("active"); \
              jButton.addClass("active"); \
              var iColumnIndex = jButton.closest("th").index(); \
              jTable.find("tr.toggle").each(function(){ \
                var jTR = $(this); \
                if (jTR.find("td").eq(iColumnIndex).text() == "0") { \
                  jTR.hide(); \
                } else { \
                  jTR.show(); \
                } \
              }); \
            }); \
            $("table.expand-details").on("click", ".goto-rule", function(){ \
              $("table.rules-list span.filter.active").click(); \
              return true; \
            }); \
            $("table.expand-details").on("click", ".goto-target", function(){ \
              $("table.targets-list span.filter.active").click(); \
              return true; \
            }); \
            \
            Chart.defaults.global.responsive = true; \
            \
            var oRulesChartContext = $("#rules-chart").get(0).getContext("2d"); \
            var arData = [ \
              { value: '+ ((oData.rule_result_totals[0] == 0 || oData.rule_result_totals[0] > minRuleSlice) ? oData.rule_result_totals[0] : minRuleSlice + oData.rule_result_totals[0] ) +', rawValue:10, color:"#5cb85c", highlight: "#dff0d8", label: "Pass: '+ oData.rule_result_totals[0] +' Rules" }, \
              { value: '+ ((oData.rule_result_totals[1] == 0 || oData.rule_result_totals[1] > minRuleSlice) ? oData.rule_result_totals[1] : minRuleSlice + oData.rule_result_totals[1] ) +', rawValue:10, color:"#d9534f", highlight: "#f2dede", label: "Fail: '+ oData.rule_result_totals[1] +' Rules" }, \
              { value: '+ ((oData.rule_result_totals[2] == 0 || oData.rule_result_totals[2] > minRuleSlice) ? oData.rule_result_totals[2] : minRuleSlice + oData.rule_result_totals[2] ) +', rawValue:10, color:"#ec971f", highlight: "#fcf8e3", label: "Unknown: '+ oData.rule_result_totals[2] +' Rules" }, \
              { value: '+ ((oData.rule_result_totals[3] == 0 || oData.rule_result_totals[3] > minRuleSlice) ? oData.rule_result_totals[3] : minRuleSlice + oData.rule_result_totals[3] ) +', rawValue:10, color:"#31b0d5", highlight: "#d9edf7", label: "Not Applicable: '+ oData.rule_result_totals[3] +' Rules" } \
            ]; \
            var oRulesChart = new Chart(oRulesChartContext).Pie(arData, { \
              tooltipTemplate: "<%= label %>" \
            }); \
            \
            var oTargetsRulesContext = $("#targets-chart").get(0).getContext("2d"); \
            var arData = [ \
              { value: '+ ((oData.targets_result_totals[0] == 0 || oData.targets_result_totals[0] > minTargetSlice) ? oData.targets_result_totals[0] : minTargetSlice + oData.targets_result_totals[0]) +', rawValue:10, color:"#5cb85c", highlight: "#dff0d8", label: "Pass: '+ oData.targets_result_totals[0] +' Targets" }, \
              { value: '+ ((oData.targets_result_totals[1] == 0 || oData.targets_result_totals[1] > minTargetSlice) ? oData.targets_result_totals[1] : minTargetSlice + oData.targets_result_totals[1]) +', rawValue:10, color:"#d9534f", highlight: "#f2dede", label: "Fail: '+ oData.targets_result_totals[1] +' Targets" }, \
              { value: '+ ((oData.targets_result_totals[2] == 0 || oData.targets_result_totals[2] > minTargetSlice) ? oData.targets_result_totals[2] : minTargetSlice + oData.targets_result_totals[2]) +', rawValue:10, color:"#ec971f", highlight: "#fcf8e3", label: "Unknown: '+ oData.targets_result_totals[2] +' Targets" }, \
              { value: '+ ((oData.targets_result_totals[3] == 0 || oData.targets_result_totals[3] > minTargetSlice) ? oData.targets_result_totals[3] : minTargetSlice + oData.targets_result_totals[3]) +', rawValue:10, color:"#31b0d5", highlight: "#d9edf7", label: "Not Applicable: '+ oData.targets_result_totals[3] +' Targets" } \
            ]; \
            var oRulesChart = new Chart(oTargetsRulesContext).Pie(arData, { \
              tooltipTemplate: "<%= label %>" \
            }); \
          } \
        </scri'+'pt>\
      </body>\
    </html>';
}

function getReferenceAsLink(oReference){
  switch(oReference.system.toLowerCase()) {
    case 'http://cce.mitre.org': var sUrl = 'http://scapsync.com/cce/' + oReference.value; break;
    case 'http://cpe.mitre.org': var sUrl = 'http://web.nvd.nist.gov/view/cpe/search/results?searchChoice=name&amp;includeDeprecated=on&amp;searchText=' + oReference.value; break;
    case 'http://cve.mitre.org': var sUrl = 'http://web.nvd.nist.gov/view/vuln/detail?vulnId=' + oReference.value; break;
    case 'http://www.cert.org': var sUrl = 'http://www.cert.org/advisories/' + oReference.value + '.html'; break;
    case 'http://www.kb.cert.org': var sUrl = 'http://www.kb.cert.org/vuls/id/' + oReference.value; break;
    case 'http://www.us-cert.gov/cas/techalerts': var sUrl = 'http://www.us-cert.gov/ncas/alerts/' + oReference.value; break;
    case 'http://rhn.redhat.com/errata': var sUrl = 'http://rhn.redhat.com/errata/' + oReference.value.toString().replace(/-[0-9]+$/g,'').replace(/[^a-zA-Z0-9]+/g,'-') + '.html'; break;
    case 'http://tools.cisco.com/security/center/content/ciscosecurityadvisory': var sUrl = 'http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/' + oReference.value; break;
    case 'http://iase.disa.mil/cci': var sUrl = 'http://jovalcm.com/references/cci/' + oReference.value; break;
    default: return oReference.value;
  }
  return '<a href="'+ sUrl +'" target="_blank"><nobr>'+ oReference.value +'</nobr></a>';
}
