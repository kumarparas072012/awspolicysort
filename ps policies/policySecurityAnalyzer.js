const fs = require('fs');

class PolicySecurityAnalyzer {
    constructor() {
        this.securityIssues = [];
        this.optimizationSuggestions = [];
        
        this.dangerousActions = [
            '*',
            'iam:*',
            's3:*',
            'ec2:*',
            'sts:AssumeRole',
            'iam:PassRole',
            'iam:CreateRole',
            'iam:AttachRolePolicy',
            'iam:PutRolePolicy',
            'lambda:InvokeFunction',
            'dynamodb:*',
            'rds:*'
        ];
        
        this.privilegedServices = [
            'iam',
            'sts',
            'organizations',
            'account',
            'billing',
            'support'
        ];
    }

    analyzePolicy(policy) {
        this.securityIssues = [];
        this.optimizationSuggestions = [];
        
        if (!policy || !policy.Statement) {
            return { error: 'Invalid policy format' };
        }

        policy.Statement.forEach((statement, index) => {
            this.analyzeStatement(statement, index);
        });

        return {
            securityIssues: this.securityIssues,
            optimizationSuggestions: this.optimizationSuggestions,
            riskScore: this.calculateRiskScore(),
            summary: this.generateSummary(policy)
        };
    }

    analyzeStatement(statement, index) {
        const statementId = statement.Sid || `Statement-${index + 1}`;
        
        this.checkWildcardUsage(statement, statementId);
        this.checkDangerousActions(statement, statementId);
        this.checkResourceWildcards(statement, statementId);
        this.checkCrossAccountAccess(statement, statementId);
        this.checkMissingConditions(statement, statementId);
        this.checkOverlyBroadPermissions(statement, statementId);
        this.checkDuplicateStatements(statement, statementId);
    }

    checkWildcardUsage(statement, statementId) {
        if (statement.Effect === 'Allow') {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            
            actions.forEach(action => {
                if (action === '*') {
                    this.securityIssues.push({
                        type: 'CRITICAL',
                        category: 'Wildcard Usage',
                        statementId,
                        message: 'Statement allows all actions (*) which is extremely dangerous',
                        recommendation: 'Restrict to specific actions needed'
                    });
                } else if (action.includes('*')) {
                    this.securityIssues.push({
                        type: 'HIGH',
                        category: 'Wildcard Usage',
                        statementId,
                        action,
                        message: `Action contains wildcard: ${action}`,
                        recommendation: 'Consider using specific actions instead of wildcards'
                    });
                }
            });
        }
    }

    checkDangerousActions(statement, statementId) {
        if (statement.Effect === 'Allow') {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            
            actions.forEach(action => {
                if (this.dangerousActions.includes(action)) {
                    this.securityIssues.push({
                        type: 'HIGH',
                        category: 'Dangerous Action',
                        statementId,
                        action,
                        message: `Potentially dangerous action detected: ${action}`,
                        recommendation: 'Ensure this permission is absolutely necessary and properly conditioned'
                    });
                }
            });
        }
    }

    checkResourceWildcards(statement, statementId) {
        if (statement.Effect === 'Allow' && statement.Resource) {
            const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
            
            resources.forEach(resource => {
                if (resource === '*') {
                    this.securityIssues.push({
                        type: 'HIGH',
                        category: 'Resource Wildcard',
                        statementId,
                        message: 'Statement allows access to all resources (*)',
                        recommendation: 'Limit to specific resources or use resource conditions'
                    });
                }
            });
        }
    }

    checkCrossAccountAccess(statement, statementId) {
        if (statement.Condition && statement.Condition['ForAnyValue:StringLike']) {
            const accounts = statement.Condition['ForAnyValue:StringLike']['aws:PrincipalAccount'];
            if (accounts && Array.isArray(accounts) && accounts.length > 1) {
                this.securityIssues.push({
                    type: 'MEDIUM',
                    category: 'Cross-Account Access',
                    statementId,
                    message: `Statement allows access from ${accounts.length} different AWS accounts`,
                    accounts,
                    recommendation: 'Verify all cross-account access is intentional and necessary'
                });
            }
        }
    }

    checkMissingConditions(statement, statementId) {
        if (statement.Effect === 'Allow' && !statement.Condition) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            const hasPrivilegedAction = actions.some(action => 
                this.privilegedServices.some(service => action.startsWith(service + ':'))
            );
            
            if (hasPrivilegedAction) {
                this.securityIssues.push({
                    type: 'MEDIUM',
                    category: 'Missing Conditions',
                    statementId,
                    message: 'Privileged actions without conditions',
                    recommendation: 'Add conditions to restrict when these actions can be performed'
                });
            }
        }
    }

    checkOverlyBroadPermissions(statement, statementId) {
        if (statement.Effect === 'Allow' && statement.Action) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            
            if (actions.length > 20) {
                this.optimizationSuggestions.push({
                    type: 'OPTIMIZATION',
                    category: 'Statement Complexity',
                    statementId,
                    message: `Statement contains ${actions.length} actions`,
                    recommendation: 'Consider splitting into multiple focused statements'
                });
            }
        }
    }

    checkDuplicateStatements(statement, statementId) {
        if (statement.Action && statement.Resource) {
            const actionStr = JSON.stringify(statement.Action);
            const resourceStr = JSON.stringify(statement.Resource);
            const key = `${actionStr}-${resourceStr}`;
            
            if (!this.statementHashes) {
                this.statementHashes = new Set();
            }
            
            if (this.statementHashes.has(key)) {
                this.optimizationSuggestions.push({
                    type: 'OPTIMIZATION',
                    category: 'Duplicate Statement',
                    statementId,
                    message: 'Potential duplicate or overlapping statement detected',
                    recommendation: 'Review for consolidation opportunities'
                });
            }
            
            this.statementHashes.add(key);
        }
    }

    calculateRiskScore() {
        let score = 0;
        
        this.securityIssues.forEach(issue => {
            switch (issue.type) {
                case 'CRITICAL':
                    score += 10;
                    break;
                case 'HIGH':
                    score += 5;
                    break;
                case 'MEDIUM':
                    score += 2;
                    break;
                case 'LOW':
                    score += 1;
                    break;
            }
        });
        
        return Math.min(score, 100);
    }

    generateSummary(policy) {
        const statements = policy.Statement || [];
        const totalActions = statements.reduce((count, stmt) => {
            if (stmt.Action) {
                return count + (Array.isArray(stmt.Action) ? stmt.Action.length : 1);
            }
            return count;
        }, 0);

        return {
            totalStatements: statements.length,
            totalActions,
            allowStatements: statements.filter(s => s.Effect === 'Allow').length,
            denyStatements: statements.filter(s => s.Effect === 'Deny').length,
            statementsWithConditions: statements.filter(s => s.Condition).length,
            wildcardActions: statements.filter(s => {
                const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
                return actions.some(a => a && a.includes('*'));
            }).length
        };
    }

    generateSecurityReport(policy, filename = 'security-report.json') {
        const analysis = this.analyzePolicy(policy);
        const report = {
            timestamp: new Date().toISOString(),
            policyAnalysis: analysis,
            recommendations: this.generateRecommendations(analysis),
            complianceChecks: this.performComplianceChecks(policy)
        };

        fs.writeFileSync(filename, JSON.stringify(report, null, 2));
        return report;
    }

    generateRecommendations(analysis) {
        const recommendations = [];
        
        if (analysis.riskScore > 50) {
            recommendations.push({
                priority: 'HIGH',
                action: 'Immediate review required',
                description: 'Policy has high risk score and needs immediate attention'
            });
        }
        
        const criticalIssues = analysis.securityIssues.filter(i => i.type === 'CRITICAL');
        if (criticalIssues.length > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                action: 'Remove wildcard permissions',
                description: 'Replace wildcard (*) actions with specific permissions'
            });
        }
        
        if (analysis.optimizationSuggestions.length > 5) {
            recommendations.push({
                priority: 'MEDIUM',
                action: 'Optimize policy structure',
                description: 'Consider consolidating statements and removing duplicates'
            });
        }
        
        return recommendations;
    }

    performComplianceChecks(policy) {
        const checks = {
            leastPrivilege: this.checkLeastPrivilege(policy),
            principleOfSeparation: this.checkSeparationOfDuties(policy),
            conditionalAccess: this.checkConditionalAccess(policy),
            resourceRestriction: this.checkResourceRestriction(policy)
        };
        
        return checks;
    }

    checkLeastPrivilege(policy) {
        const statements = policy.Statement || [];
        const violations = statements.filter(stmt => {
            if (stmt.Effect === 'Allow' && stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                return actions.some(action => action === '*' || action.endsWith(':*'));
            }
            return false;
        });
        
        return {
            compliant: violations.length === 0,
            violations: violations.length,
            description: 'Checks if policy follows least privilege principle'
        };
    }

    checkSeparationOfDuties(policy) {
        const statements = policy.Statement || [];
        const adminActions = ['iam:*', 'sts:*', '*'];
        const hasAdminPermissions = statements.some(stmt => {
            if (stmt.Effect === 'Allow' && stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                return actions.some(action => adminActions.includes(action));
            }
            return false;
        });
        
        return {
            compliant: !hasAdminPermissions,
            violations: hasAdminPermissions ? 1 : 0,
            description: 'Checks for separation between administrative and operational permissions'
        };
    }

    checkConditionalAccess(policy) {
        const statements = policy.Statement || [];
        const privilegedStatements = statements.filter(stmt => {
            if (stmt.Effect === 'Allow' && stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                return actions.some(action => 
                    this.privilegedServices.some(service => action.startsWith(service + ':'))
                );
            }
            return false;
        });
        
        const unconditionedPrivileged = privilegedStatements.filter(stmt => !stmt.Condition);
        
        return {
            compliant: unconditionedPrivileged.length === 0,
            violations: unconditionedPrivileged.length,
            description: 'Checks if privileged actions have appropriate conditions'
        };
    }

    checkResourceRestriction(policy) {
        const statements = policy.Statement || [];
        const unrestricted = statements.filter(stmt => {
            return stmt.Effect === 'Allow' && stmt.Resource === '*';
        });
        
        return {
            compliant: unrestricted.length === 0,
            violations: unrestricted.length,
            description: 'Checks if resources are properly restricted'
        };
    }
}

module.exports = PolicySecurityAnalyzer;

if (require.main === module) {
    const analyzer = new PolicySecurityAnalyzer();
    
    try {
        const policyFile = process.argv[2] || './alpha_ps.json';
        const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
        
        console.log('🔍 AWS Policy Security Analysis Report');
        console.log('=====================================\n');
        
        const analysis = analyzer.analyzePolicy(policyData);
        
        console.log(`📊 Policy Summary:`);
        console.log(`  Total Statements: ${analysis.summary.totalStatements}`);
        console.log(`  Total Actions: ${analysis.summary.totalActions}`);
        console.log(`  Risk Score: ${analysis.riskScore}/100`);
        console.log(`  Security Issues: ${analysis.securityIssues.length}`);
        console.log(`  Optimization Suggestions: ${analysis.optimizationSuggestions.length}\n`);
        
        if (analysis.securityIssues.length > 0) {
            console.log('🚨 Security Issues:');
            analysis.securityIssues.forEach((issue, i) => {
                console.log(`  ${i + 1}. [${issue.type}] ${issue.category} (${issue.statementId})`);
                console.log(`     ${issue.message}`);
                console.log(`     💡 ${issue.recommendation}\n`);
            });
        }
        
        if (analysis.optimizationSuggestions.length > 0) {
            console.log('💡 Optimization Suggestions:');
            analysis.optimizationSuggestions.forEach((suggestion, i) => {
                console.log(`  ${i + 1}. ${suggestion.category} (${suggestion.statementId})`);
                console.log(`     ${suggestion.message}`);
                console.log(`     💡 ${suggestion.recommendation}\n`);
            });
        }
        
        const report = analyzer.generateSecurityReport(policyData, 'security-analysis-report.json');
        console.log('📄 Detailed report saved to: security-analysis-report.json');
        
    } catch (error) {
        console.error('Error analyzing policy:', error.message);
    }
}