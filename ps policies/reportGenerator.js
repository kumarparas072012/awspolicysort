const fs = require('fs');
const path = require('path');

class ReportGenerator {
    constructor() {
        this.reportTypes = {
            'security': 'Security Analysis Report',
            'optimization': 'Policy Optimization Report',
            'comparison': 'Policy Comparison Report',
            'compliance': 'Compliance Assessment Report',
            'executive': 'Executive Summary Report',
            'detailed': 'Detailed Technical Report'
        };
    }

    generateSecurityReport(analysisResults, options = {}) {
        const template = this.getSecurityReportTemplate();
        const report = this.populateTemplate(template, {
            ...analysisResults,
            metadata: {
                generatedAt: new Date().toISOString(),
                reportType: 'Security Analysis',
                version: '1.0',
                ...options.metadata
            }
        });

        if (options.format === 'html') {
            return this.convertToHtml(report, 'security');
        }
        
        return report;
    }

    generateOptimizationReport(optimizationResults, options = {}) {
        const template = this.getOptimizationReportTemplate();
        const report = this.populateTemplate(template, {
            ...optimizationResults,
            metadata: {
                generatedAt: new Date().toISOString(),
                reportType: 'Policy Optimization',
                version: '1.0',
                ...options.metadata
            }
        });

        if (options.format === 'html') {
            return this.convertToHtml(report, 'optimization');
        }
        
        return report;
    }

    generateComparisonReport(comparisonResults, options = {}) {
        const template = this.getComparisonReportTemplate();
        const report = this.populateTemplate(template, {
            ...comparisonResults,
            metadata: {
                generatedAt: new Date().toISOString(),
                reportType: 'Policy Comparison',
                version: '1.0',
                ...options.metadata
            }
        });

        if (options.format === 'html') {
            return this.convertToHtml(report, 'comparison');
        }
        
        return report;
    }

    generateExecutiveSummary(allResults, options = {}) {
        const summary = {
            metadata: {
                generatedAt: new Date().toISOString(),
                reportType: 'Executive Summary',
                version: '1.0',
                ...options.metadata
            },
            overview: this.generateOverview(allResults),
            keyFindings: this.extractKeyFindings(allResults),
            riskAssessment: this.generateRiskAssessment(allResults),
            recommendations: this.prioritizeRecommendations(allResults),
            metrics: this.calculateExecutiveMetrics(allResults),
            actionItems: this.generateActionItems(allResults)
        };

        if (options.format === 'html') {
            return this.convertToHtml(summary, 'executive');
        }
        
        return summary;
    }

    generateComprehensiveReport(allResults, options = {}) {
        const report = {
            metadata: {
                generatedAt: new Date().toISOString(),
                reportType: 'Comprehensive Analysis',
                version: '1.0',
                scope: 'Full Policy Analysis',
                ...options.metadata
            },
            executiveSummary: this.generateExecutiveSummary(allResults, { format: 'json' }),
            securityAnalysis: allResults.security || {},
            optimizationAnalysis: allResults.optimization || {},
            comparisonAnalysis: allResults.comparison || {},
            detailedFindings: this.generateDetailedFindings(allResults),
            appendices: this.generateAppendices(allResults)
        };

        if (options.format === 'html') {
            return this.convertToHtml(report, 'comprehensive');
        }
        
        return report;
    }

    getSecurityReportTemplate() {
        return {
            title: 'AWS IAM Policy Security Analysis Report',
            sections: [
                {
                    name: 'Executive Summary',
                    fields: ['riskScore', 'criticalIssues', 'recommendations']
                },
                {
                    name: 'Security Issues',
                    fields: ['securityIssues']
                },
                {
                    name: 'Compliance Assessment',
                    fields: ['complianceChecks']
                },
                {
                    name: 'Recommendations',
                    fields: ['recommendations']
                }
            ]
        };
    }

    getOptimizationReportTemplate() {
        return {
            title: 'AWS IAM Policy Optimization Report',
            sections: [
                {
                    name: 'Optimization Summary',
                    fields: ['savings', 'optimizations']
                },
                {
                    name: 'Before and After',
                    fields: ['original', 'optimized']
                },
                {
                    name: 'Detailed Optimizations',
                    fields: ['optimizations']
                },
                {
                    name: 'Implementation Guide',
                    fields: ['recommendations']
                }
            ]
        };
    }

    getComparisonReportTemplate() {
        return {
            title: 'AWS IAM Policy Comparison Report',
            sections: [
                {
                    name: 'Comparison Summary',
                    fields: ['summary', 'mergeability']
                },
                {
                    name: 'Differences Analysis',
                    fields: ['differences']
                },
                {
                    name: 'Similarities',
                    fields: ['similarities']
                },
                {
                    name: 'Merge Recommendations',
                    fields: ['recommendations']
                }
            ]
        };
    }

    populateTemplate(template, data) {
        const populated = {
            ...template,
            metadata: data.metadata,
            data: data,
            generatedSections: []
        };

        template.sections.forEach(section => {
            const sectionData = {};
            section.fields.forEach(field => {
                if (data[field] !== undefined) {
                    sectionData[field] = data[field];
                }
            });
            
            populated.generatedSections.push({
                name: section.name,
                data: sectionData
            });
        });

        return populated;
    }

    generateOverview(allResults) {
        const overview = {
            totalPoliciesAnalyzed: this.countPolicies(allResults),
            analysisTypes: Object.keys(allResults),
            overallRiskLevel: this.calculateOverallRisk(allResults),
            keyMetrics: this.extractKeyMetrics(allResults)
        };

        return overview;
    }

    extractKeyFindings(allResults) {
        const findings = [];

        if (allResults.security) {
            const criticalIssues = allResults.security.securityIssues?.filter(issue => issue.type === 'CRITICAL') || [];
            if (criticalIssues.length > 0) {
                findings.push({
                    type: 'CRITICAL',
                    category: 'Security',
                    finding: `${criticalIssues.length} critical security issues identified`,
                    impact: 'HIGH',
                    action: 'Immediate remediation required'
                });
            }
        }

        if (allResults.optimization) {
            const savings = allResults.optimization.savings;
            if (savings && savings.statementReductionPercent > 20) {
                findings.push({
                    type: 'OPPORTUNITY',
                    category: 'Optimization',
                    finding: `Policy can be reduced by ${savings.statementReductionPercent}%`,
                    impact: 'MEDIUM',
                    action: 'Apply optimization recommendations'
                });
            }
        }

        if (allResults.comparison) {
            const mergeability = allResults.comparison.mergeability;
            if (mergeability && mergeability.level === 'DANGEROUS') {
                findings.push({
                    type: 'WARNING',
                    category: 'Comparison',
                    finding: 'Policies have conflicting permissions',
                    impact: 'HIGH',
                    action: 'Resolve conflicts before merging'
                });
            }
        }

        return findings;
    }

    generateRiskAssessment(allResults) {
        const assessment = {
            overallRisk: this.calculateOverallRisk(allResults),
            riskFactors: this.identifyRiskFactors(allResults),
            mitigationStrategies: this.generateMitigationStrategies(allResults)
        };

        return assessment;
    }

    prioritizeRecommendations(allResults) {
        const allRecommendations = [];

        Object.values(allResults).forEach(result => {
            if (result.recommendations) {
                result.recommendations.forEach(rec => {
                    allRecommendations.push({
                        ...rec,
                        source: this.getSourceFromResult(result)
                    });
                });
            }
        });

        // Sort by priority
        const priorityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
        allRecommendations.sort((a, b) => {
            return (priorityOrder[a.priority] || 99) - (priorityOrder[b.priority] || 99);
        });

        return allRecommendations.slice(0, 10); // Top 10 recommendations
    }

    calculateExecutiveMetrics(allResults) {
        const metrics = {
            securityScore: 0,
            optimizationOpportunities: 0,
            complianceStatus: 'Unknown',
            recommendationCount: 0
        };

        if (allResults.security) {
            metrics.securityScore = Math.max(0, 100 - (allResults.security.riskScore || 0));
            metrics.complianceStatus = this.assessOverallCompliance(allResults.security.complianceChecks);
        }

        if (allResults.optimization) {
            metrics.optimizationOpportunities = allResults.optimization.optimizations?.length || 0;
        }

        Object.values(allResults).forEach(result => {
            if (result.recommendations) {
                metrics.recommendationCount += result.recommendations.length;
            }
        });

        return metrics;
    }

    generateActionItems(allResults) {
        const actionItems = [];
        const recommendations = this.prioritizeRecommendations(allResults);

        recommendations.slice(0, 5).forEach((rec, index) => {
            actionItems.push({
                priority: index + 1,
                action: rec.action || rec.type,
                description: rec.description,
                timeline: this.getTimelineForPriority(rec.priority),
                owner: 'Security Team',
                status: 'Pending'
            });
        });

        return actionItems;
    }

    generateDetailedFindings(allResults) {
        const findings = {
            securityFindings: this.extractSecurityFindings(allResults.security),
            optimizationFindings: this.extractOptimizationFindings(allResults.optimization),
            comparisonFindings: this.extractComparisonFindings(allResults.comparison)
        };

        return findings;
    }

    generateAppendices(allResults) {
        return {
            rawData: allResults,
            methodology: this.getMethodologyDescription(),
            glossary: this.getGlossary(),
            references: this.getReferences()
        };
    }

    convertToHtml(report, reportType) {
        const css = this.getReportCSS();
        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${report.title || 'AWS Policy Analysis Report'}</title>
    <style>${css}</style>
</head>
<body>
    <div class="report-container">
        ${this.generateHtmlHeader(report)}
        ${this.generateHtmlContent(report, reportType)}
        ${this.generateHtmlFooter(report)}
    </div>
</body>
</html>`;
        
        return html;
    }

    generateHtmlHeader(report) {
        return `
        <header class="report-header">
            <h1>${report.title || 'AWS Policy Analysis Report'}</h1>
            <div class="report-meta">
                <p>Generated: ${report.metadata?.generatedAt}</p>
                <p>Type: ${report.metadata?.reportType}</p>
                <p>Version: ${report.metadata?.version}</p>
            </div>
        </header>`;
    }

    generateHtmlContent(report, reportType) {
        switch (reportType) {
            case 'executive':
                return this.generateExecutiveHtml(report);
            case 'security':
                return this.generateSecurityHtml(report);
            case 'optimization':
                return this.generateOptimizationHtml(report);
            case 'comparison':
                return this.generateComparisonHtml(report);
            default:
                return this.generateGenericHtml(report);
        }
    }

    generateExecutiveHtml(report) {
        return `
        <main class="report-content">
            <section class="executive-overview">
                <h2>Executive Overview</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <h3>Overall Risk Level</h3>
                        <div class="risk-indicator ${this.getRiskClass(report.riskAssessment?.overallRisk)}">
                            ${report.riskAssessment?.overallRisk || 'Unknown'}
                        </div>
                    </div>
                    <div class="metric-card">
                        <h3>Security Score</h3>
                        <div class="score">${report.metrics?.securityScore || 0}/100</div>
                    </div>
                    <div class="metric-card">
                        <h3>Action Items</h3>
                        <div class="count">${report.actionItems?.length || 0}</div>
                    </div>
                </div>
            </section>
            
            <section class="key-findings">
                <h2>Key Findings</h2>
                ${this.generateFindingsHtml(report.keyFindings)}
            </section>
            
            <section class="recommendations">
                <h2>Priority Recommendations</h2>
                ${this.generateRecommendationsHtml(report.recommendations)}
            </section>
            
            <section class="action-items">
                <h2>Action Items</h2>
                ${this.generateActionItemsHtml(report.actionItems)}
            </section>
        </main>`;
    }

    generateSecurityHtml(report) {
        const data = report.data || {};
        return `
        <main class="report-content">
            <section class="security-summary">
                <h2>Security Summary</h2>
                <div class="risk-score">
                    <h3>Risk Score: ${data.riskScore || 0}/100</h3>
                    <div class="risk-bar">
                        <div class="risk-fill" style="width: ${data.riskScore || 0}%"></div>
                    </div>
                </div>
            </section>
            
            <section class="security-issues">
                <h2>Security Issues</h2>
                ${this.generateIssuesHtml(data.securityIssues)}
            </section>
            
            <section class="compliance">
                <h2>Compliance Status</h2>
                ${this.generateComplianceHtml(data.complianceChecks)}
            </section>
        </main>`;
    }

    generateOptimizationHtml(report) {
        const data = report.data || {};
        return `
        <main class="report-content">
            <section class="optimization-summary">
                <h2>Optimization Summary</h2>
                <div class="savings-metrics">
                    <div class="saving-item">
                        <h3>Statement Reduction</h3>
                        <p>${data.savings?.statementReduction || 0} statements (${data.savings?.statementReductionPercent || 0}%)</p>
                    </div>
                    <div class="saving-item">
                        <h3>Size Reduction</h3>
                        <p>${data.savings?.sizeReduction || 0} characters</p>
                    </div>
                </div>
            </section>
            
            <section class="optimizations">
                <h2>Applied Optimizations</h2>
                ${this.generateOptimizationsHtml(data.optimizations)}
            </section>
        </main>`;
    }

    generateHtmlFooter(report) {
        return `
        <footer class="report-footer">
            <p>Generated by AWS Policy Analyzer - ${new Date().getFullYear()}</p>
            <p>This report is for internal use only and contains sensitive security information.</p>
        </footer>`;
    }

    getReportCSS() {
        return `
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .report-container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .report-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .report-header h1 { margin: 0 0 10px 0; font-size: 28px; }
        .report-meta p { margin: 5px 0; opacity: 0.9; }
        .report-content { padding: 30px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .metric-card h3 { margin: 0 0 10px 0; color: #495057; }
        .risk-indicator { font-size: 24px; font-weight: bold; padding: 10px; border-radius: 4px; }
        .risk-low { background: #d4edda; color: #155724; }
        .risk-medium { background: #fff3cd; color: #856404; }
        .risk-high { background: #f8d7da; color: #721c24; }
        .score, .count { font-size: 32px; font-weight: bold; color: #007bff; }
        section { margin: 30px 0; }
        section h2 { border-bottom: 2px solid #667eea; padding-bottom: 10px; color: #333; }
        .issue-item { background: #f8f9fa; margin: 10px 0; padding: 15px; border-left: 4px solid #dc3545; border-radius: 4px; }
        .issue-critical { border-left-color: #dc3545; }
        .issue-high { border-left-color: #fd7e14; }
        .issue-medium { border-left-color: #ffc107; }
        .issue-low { border-left-color: #28a745; }
        .report-footer { background: #f8f9fa; padding: 20px 30px; border-radius: 0 0 8px 8px; text-align: center; color: #6c757d; }
        .risk-bar { background: #e9ecef; height: 20px; border-radius: 10px; overflow: hidden; }
        .risk-fill { background: linear-gradient(90deg, #28a745, #ffc107, #dc3545); height: 100%; transition: width 0.3s ease; }
        `;
    }

    // Helper methods
    countPolicies(allResults) {
        return Object.keys(allResults).length;
    }

    calculateOverallRisk(allResults) {
        if (allResults.security && allResults.security.riskScore) {
            const score = allResults.security.riskScore;
            if (score < 30) return 'LOW';
            if (score < 70) return 'MEDIUM';
            return 'HIGH';
        }
        return 'UNKNOWN';
    }

    extractKeyMetrics(allResults) {
        const metrics = {};
        
        if (allResults.security) {
            metrics.securityIssues = allResults.security.securityIssues?.length || 0;
            metrics.riskScore = allResults.security.riskScore || 0;
        }
        
        if (allResults.optimization) {
            metrics.optimizations = allResults.optimization.optimizations?.length || 0;
            metrics.savings = allResults.optimization.savings?.statementReductionPercent || 0;
        }
        
        return metrics;
    }

    getRiskClass(risk) {
        switch (risk) {
            case 'LOW': return 'risk-low';
            case 'MEDIUM': return 'risk-medium';
            case 'HIGH': return 'risk-high';
            default: return '';
        }
    }

    getTimelineForPriority(priority) {
        switch (priority) {
            case 'CRITICAL': return 'Immediate (24 hours)';
            case 'HIGH': return 'Within 1 week';
            case 'MEDIUM': return 'Within 1 month';
            case 'LOW': return 'Within 3 months';
            default: return 'TBD';
        }
    }

    // Additional helper methods for specific report sections
    generateFindingsHtml(findings) {
        if (!findings || findings.length === 0) {
            return '<p>No significant findings identified.</p>';
        }
        
        return findings.map(finding => `
            <div class="finding-item ${finding.type.toLowerCase()}">
                <h4>[${finding.type}] ${finding.category}</h4>
                <p>${finding.finding}</p>
                <p><strong>Impact:</strong> ${finding.impact}</p>
                <p><strong>Recommended Action:</strong> ${finding.action}</p>
            </div>
        `).join('');
    }

    generateRecommendationsHtml(recommendations) {
        if (!recommendations || recommendations.length === 0) {
            return '<p>No recommendations available.</p>';
        }
        
        return recommendations.map(rec => `
            <div class="recommendation-item">
                <h4>[${rec.priority}] ${rec.type || rec.action}</h4>
                <p>${rec.description}</p>
            </div>
        `).join('');
    }

    generateActionItemsHtml(actionItems) {
        if (!actionItems || actionItems.length === 0) {
            return '<p>No action items identified.</p>';
        }
        
        return `
            <table class="action-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Action</th>
                        <th>Timeline</th>
                        <th>Owner</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${actionItems.map(item => `
                        <tr>
                            <td>${item.priority}</td>
                            <td>${item.action}</td>
                            <td>${item.timeline}</td>
                            <td>${item.owner}</td>
                            <td>${item.status}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    saveReport(report, filename, format = 'json') {
        try {
            let content;
            let extension;
            
            if (format === 'html') {
                content = typeof report === 'string' ? report : this.convertToHtml(report, 'generic');
                extension = '.html';
            } else {
                content = JSON.stringify(report, null, 2);
                extension = '.json';
            }
            
            const fullPath = filename.includes('.') ? filename : filename + extension;
            fs.writeFileSync(fullPath, content);
            
            return {
                success: true,
                path: fullPath,
                size: content.length
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Placeholder methods for additional functionality
    getMethodologyDescription() {
        return {
            security: 'Security analysis based on AWS IAM best practices and NIST frameworks',
            optimization: 'Policy optimization using statement consolidation and pattern recognition',
            comparison: 'Semantic comparison of policy statements and conditions'
        };
    }

    getGlossary() {
        return {
            'IAM': 'Identity and Access Management',
            'SID': 'Statement ID - unique identifier for policy statements',
            'ARN': 'Amazon Resource Name - unique identifier for AWS resources',
            'Principal': 'Entity that can perform actions on AWS resources'
        };
    }

    getReferences() {
        return [
            'AWS IAM Best Practices - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
            'AWS Security Best Practices - https://aws.amazon.com/architecture/security-identity-compliance/',
            'NIST Cybersecurity Framework - https://www.nist.gov/cyberframework'
        ];
    }
}

module.exports = ReportGenerator;

if (require.main === module) {
    const generator = new ReportGenerator();
    
    // Example usage
    const sampleResults = {
        security: {
            riskScore: 65,
            securityIssues: [
                { type: 'HIGH', category: 'Wildcard Usage', message: 'Wildcard permissions detected' }
            ],
            recommendations: [
                { priority: 'HIGH', type: 'Security', description: 'Remove wildcard permissions' }
            ]
        }
    };
    
    console.log('📊 Generating sample reports...\n');
    
    // Generate executive summary
    const execSummary = generator.generateExecutiveSummary(sampleResults);
    generator.saveReport(execSummary, 'executive-summary.json');
    console.log('✅ Executive summary saved to executive-summary.json');
    
    // Generate HTML executive summary
    const execHtml = generator.generateExecutiveSummary(sampleResults, { format: 'html' });
    generator.saveReport(execHtml, 'executive-summary.html', 'html');
    console.log('✅ Executive summary HTML saved to executive-summary.html');
    
    console.log('\n📄 Report generation complete!');
}