const fs = require('fs');

class PolicyLimitValidator {
    constructor() {
        // AWS IAM Policy Limits (as of 2024)
        this.limits = {
            // Policy document limits
            managedPolicy: {
                maxSize: 6144,  // 6KB for customer managed policies
                maxSizeBytes: 6144,
                description: 'Customer Managed Policy'
            },
            awsManagedPolicy: {
                maxSize: 6144,  // 6KB for AWS managed policies
                maxSizeBytes: 6144,
                description: 'AWS Managed Policy'
            },
            inlinePolicy: {
                maxSize: 2048,  // 2KB for inline policies
                maxSizeBytes: 2048,
                description: 'Inline Policy (attached to users, groups, roles)'
            },
            assumeRolePolicy: {
                maxSize: 2048,  // 2KB for assume role policy documents
                maxSizeBytes: 2048,
                description: 'Assume Role Policy Document'
            },
            
            // Statement limits
            statements: {
                maxPerPolicy: 50,  // Maximum statements per policy
                description: 'Maximum statements per policy'
            },
            
            // String length limits
            strings: {
                policyName: 128,          // Policy name max length
                policyPath: 512,          // Policy path max length
                description: 1000,        // Policy description max length
                sid: 100,                 // Statement ID max length
                actionString: 128,        // Individual action string
                resourceArn: 2048,        // Resource ARN max length
                conditionKey: 64,         // Condition key max length
                conditionValue: 1024      // Condition value max length
            },

            // Array limits
            arrays: {
                maxActions: 100,          // Max actions per statement
                maxResources: 100,        // Max resources per statement
                maxPrincipals: 100,       // Max principals per statement
                maxConditionValues: 100   // Max values per condition key
            },

            // Account limits
            account: {
                managedPoliciesPerAccount: 1500,    // Customer managed policies per account
                policiesPerRole: 20,                // Managed policies per role
                policiesPerUser: 20,                // Managed policies per user
                policiesPerGroup: 20,               // Managed policies per group
                inlinePoliciesPerRole: 1,           // Inline policies per role
                inlinePoliciesPerUser: 1,           // Inline policies per user
                inlinePoliciesPerGroup: 1           // Inline policies per group
            }
        };

        this.warnings = [];
        this.errors = [];
        this.recommendations = [];
    }

    validatePolicy(policy, policyType = 'managedPolicy', options = {}) {
        this.warnings = [];
        this.errors = [];
        this.recommendations = [];

        const validation = {
            policyType,
            isValid: true,
            sizeAnalysis: this.analyzePolicySize(policy, policyType),
            structureAnalysis: this.analyzeStructure(policy),
            stringLengthAnalysis: this.analyzeStringLengths(policy),
            arrayLimitAnalysis: this.analyzeArrayLimits(policy),
            awsCompatibility: this.assessAWSCompatibility(policy, policyType),
            recommendations: [],
            warnings: [],
            errors: []
        };

        // Check if policy exceeds limits
        if (!validation.sizeAnalysis.withinLimit) {
            validation.isValid = false;
            this.errors.push({
                type: 'SIZE_LIMIT_EXCEEDED',
                message: `Policy size ${validation.sizeAnalysis.currentSize} bytes exceeds ${policyType} limit of ${this.limits[policyType].maxSize} bytes`,
                currentValue: validation.sizeAnalysis.currentSize,
                limit: this.limits[policyType].maxSize,
                severity: 'CRITICAL'
            });
        }

        // Compile all findings
        validation.warnings = this.warnings;
        validation.errors = this.errors;
        validation.recommendations = this.recommendations;

        return validation;
    }

    analyzePolicySize(policy, policyType) {
        const policyString = JSON.stringify(policy);
        const currentSize = Buffer.byteLength(policyString, 'utf8');
        const limit = this.limits[policyType].maxSizeBytes;
        const utilization = (currentSize / limit) * 100;
        
        const analysis = {
            currentSize,
            limit,
            withinLimit: currentSize <= limit,
            utilization: Math.round(utilization * 100) / 100,
            remainingBytes: limit - currentSize,
            compressionPotential: this.estimateCompressionPotential(policy),
            breakdown: this.analyzeSizeBreakdown(policy)
        };

        // Add warnings for high utilization
        if (utilization > 90) {
            this.warnings.push({
                type: 'HIGH_SIZE_UTILIZATION',
                message: `Policy using ${utilization.toFixed(1)}% of size limit`,
                recommendation: 'Consider optimizing policy to reduce size'
            });
        } else if (utilization > 75) {
            this.warnings.push({
                type: 'MEDIUM_SIZE_UTILIZATION',
                message: `Policy using ${utilization.toFixed(1)}% of size limit`,
                recommendation: 'Monitor policy size when adding new permissions'
            });
        }

        return analysis;
    }

    analyzeSizeBreakdown(policy) {
        const breakdown = {
            version: this.getFieldSize('Version', policy.Version),
            statements: 0,
            statementBreakdown: []
        };

        if (policy.Statement && Array.isArray(policy.Statement)) {
            policy.Statement.forEach((stmt, index) => {
                const stmtSize = Buffer.byteLength(JSON.stringify(stmt), 'utf8');
                breakdown.statements += stmtSize;
                
                breakdown.statementBreakdown.push({
                    index,
                    sid: stmt.Sid || `Statement-${index + 1}`,
                    size: stmtSize,
                    percentage: 0, // Will be calculated after total
                    components: {
                        effect: this.getFieldSize('Effect', stmt.Effect),
                        action: this.getFieldSize('Action', stmt.Action),
                        resource: this.getFieldSize('Resource', stmt.Resource),
                        condition: this.getFieldSize('Condition', stmt.Condition),
                        principal: this.getFieldSize('Principal', stmt.Principal),
                        other: 0
                    }
                });
            });

            // Calculate percentages
            const totalSize = breakdown.version + breakdown.statements;
            breakdown.statementBreakdown.forEach(stmt => {
                stmt.percentage = Math.round((stmt.size / totalSize) * 100 * 100) / 100;
            });
        }

        return breakdown;
    }

    getFieldSize(fieldName, fieldValue) {
        if (fieldValue === undefined || fieldValue === null) return 0;
        return Buffer.byteLength(JSON.stringify({ [fieldName]: fieldValue }), 'utf8') - 4; // Subtract quotes and colon
    }

    estimateCompressionPotential(policy) {
        // Estimate potential size reduction through optimization
        let potential = 0;
        
        if (policy.Statement) {
            policy.Statement.forEach(stmt => {
                // Check for redundant whitespace (if policy is formatted)
                const minified = JSON.stringify(stmt);
                const formatted = JSON.stringify(stmt, null, 2);
                potential += formatted.length - minified.length;

                // Check for duplicate string patterns
                if (stmt.Action && Array.isArray(stmt.Action)) {
                    const actionStr = JSON.stringify(stmt.Action);
                    const uniqueActions = [...new Set(stmt.Action)];
                    if (uniqueActions.length < stmt.Action.length) {
                        potential += actionStr.length - JSON.stringify(uniqueActions).length;
                    }
                }

                // Check for wildcard consolidation opportunities
                if (stmt.Action && Array.isArray(stmt.Action)) {
                    const wildcardOpportunities = this.findWildcardOpportunities(stmt.Action);
                    potential += wildcardOpportunities.potentialSavings;
                }
            });
        }

        return {
            estimatedBytes: potential,
            percentage: potential > 0 ? Math.round((potential / Buffer.byteLength(JSON.stringify(policy), 'utf8')) * 100 * 100) / 100 : 0
        };
    }

    findWildcardOpportunities(actions) {
        const serviceGroups = {};
        let potentialSavings = 0;

        actions.forEach(action => {
            const parts = action.split(':');
            if (parts.length >= 2) {
                const service = parts[0];
                if (!serviceGroups[service]) serviceGroups[service] = [];
                serviceGroups[service].push(action);
            }
        });

        Object.entries(serviceGroups).forEach(([service, serviceActions]) => {
            if (serviceActions.length > 3) {
                const currentSize = JSON.stringify(serviceActions).length;
                const wildcardSize = JSON.stringify([`${service}:*`]).length;
                if (wildcardSize < currentSize) {
                    potentialSavings += currentSize - wildcardSize;
                }
            }
        });

        return { potentialSavings };
    }

    analyzeStructure(policy) {
        const analysis = {
            statementCount: 0,
            exceedsStatementLimit: false,
            averageStatementSize: 0,
            largestStatement: null,
            smallestStatement: null,
            statementSizeDistribution: []
        };

        if (policy.Statement && Array.isArray(policy.Statement)) {
            analysis.statementCount = policy.Statement.length;
            analysis.exceedsStatementLimit = analysis.statementCount > this.limits.statements.maxPerPolicy;

            if (analysis.exceedsStatementLimit) {
                this.errors.push({
                    type: 'TOO_MANY_STATEMENTS',
                    message: `Policy has ${analysis.statementCount} statements, exceeding limit of ${this.limits.statements.maxPerPolicy}`,
                    currentValue: analysis.statementCount,
                    limit: this.limits.statements.maxPerPolicy,
                    severity: 'HIGH'
                });
            }

            // Calculate statement sizes
            const statementSizes = policy.Statement.map((stmt, index) => ({
                index,
                sid: stmt.Sid || `Statement-${index + 1}`,
                size: Buffer.byteLength(JSON.stringify(stmt), 'utf8')
            }));

            analysis.averageStatementSize = Math.round(
                statementSizes.reduce((sum, s) => sum + s.size, 0) / statementSizes.length
            );

            analysis.largestStatement = statementSizes.reduce((max, s) => s.size > max.size ? s : max);
            analysis.smallestStatement = statementSizes.reduce((min, s) => s.size < min.size ? s : min);
            analysis.statementSizeDistribution = statementSizes.sort((a, b) => b.size - a.size);

            // Warning for large statements
            if (analysis.largestStatement.size > 1000) {
                this.warnings.push({
                    type: 'LARGE_STATEMENT',
                    message: `Statement '${analysis.largestStatement.sid}' is ${analysis.largestStatement.size} bytes (very large)`,
                    recommendation: 'Consider splitting large statements for better maintainability'
                });
            }
        }

        return analysis;
    }

    analyzeStringLengths(policy) {
        const analysis = {
            violations: [],
            warnings: []
        };

        // Check statement SIDs
        if (policy.Statement) {
            policy.Statement.forEach((stmt, index) => {
                if (stmt.Sid && stmt.Sid.length > this.limits.strings.sid) {
                    analysis.violations.push({
                        type: 'SID_TOO_LONG',
                        statementIndex: index,
                        sid: stmt.Sid,
                        currentLength: stmt.Sid.length,
                        limit: this.limits.strings.sid
                    });
                }

                // Check individual action strings
                if (stmt.Action) {
                    const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                    actions.forEach(action => {
                        if (typeof action === 'string' && action.length > this.limits.strings.actionString) {
                            analysis.violations.push({
                                type: 'ACTION_STRING_TOO_LONG',
                                statementIndex: index,
                                action: action,
                                currentLength: action.length,
                                limit: this.limits.strings.actionString
                            });
                        }
                    });
                }

                // Check resource ARNs
                if (stmt.Resource) {
                    const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
                    resources.forEach(resource => {
                        if (typeof resource === 'string' && resource.length > this.limits.strings.resourceArn) {
                            analysis.violations.push({
                                type: 'RESOURCE_ARN_TOO_LONG',
                                statementIndex: index,
                                resource: resource,
                                currentLength: resource.length,
                                limit: this.limits.strings.resourceArn
                            });
                        }
                    });
                }
            });
        }

        // Add violations to errors
        analysis.violations.forEach(violation => {
            this.errors.push({
                type: violation.type,
                message: `${violation.type.replace(/_/g, ' ').toLowerCase()}: ${violation.currentLength} > ${violation.limit}`,
                severity: 'HIGH'
            });
        });

        return analysis;
    }

    analyzeArrayLimits(policy) {
        const analysis = {
            violations: [],
            warnings: []
        };

        if (policy.Statement) {
            policy.Statement.forEach((stmt, index) => {
                // Check actions array
                if (stmt.Action && Array.isArray(stmt.Action)) {
                    if (stmt.Action.length > this.limits.arrays.maxActions) {
                        analysis.violations.push({
                            type: 'TOO_MANY_ACTIONS',
                            statementIndex: index,
                            sid: stmt.Sid,
                            count: stmt.Action.length,
                            limit: this.limits.arrays.maxActions
                        });
                    }
                }

                // Check resources array
                if (stmt.Resource && Array.isArray(stmt.Resource)) {
                    if (stmt.Resource.length > this.limits.arrays.maxResources) {
                        analysis.violations.push({
                            type: 'TOO_MANY_RESOURCES',
                            statementIndex: index,
                            sid: stmt.Sid,
                            count: stmt.Resource.length,
                            limit: this.limits.arrays.maxResources
                        });
                    }
                }

                // Check condition values
                if (stmt.Condition) {
                    Object.values(stmt.Condition).forEach(conditionBlock => {
                        if (typeof conditionBlock === 'object') {
                            Object.values(conditionBlock).forEach(values => {
                                if (Array.isArray(values) && values.length > this.limits.arrays.maxConditionValues) {
                                    analysis.violations.push({
                                        type: 'TOO_MANY_CONDITION_VALUES',
                                        statementIndex: index,
                                        sid: stmt.Sid,
                                        count: values.length,
                                        limit: this.limits.arrays.maxConditionValues
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }

        // Add violations to errors
        analysis.violations.forEach(violation => {
            this.errors.push({
                type: violation.type,
                message: `Statement '${violation.sid || violation.statementIndex}': ${violation.count} items exceeds limit of ${violation.limit}`,
                severity: 'HIGH'
            });
        });

        return analysis;
    }

    assessAWSCompatibility(policy, policyType) {
        const compatibility = {
            isCompatible: true,
            recommendedType: policyType,
            alternativeTypes: [],
            optimizationSuggestions: []
        };

        const currentSize = Buffer.byteLength(JSON.stringify(policy), 'utf8');

        // Check compatibility with different policy types
        Object.entries(this.limits).forEach(([type, limit]) => {
            if (limit.maxSizeBytes && currentSize <= limit.maxSizeBytes) {
                compatibility.alternativeTypes.push({
                    type,
                    description: limit.description,
                    sizeUtilization: Math.round((currentSize / limit.maxSizeBytes) * 100 * 100) / 100
                });
            }
        });

        // Determine best policy type
        if (currentSize <= this.limits.inlinePolicy.maxSizeBytes) {
            compatibility.recommendedType = 'inlinePolicy';
            this.recommendations.push({
                type: 'POLICY_TYPE_OPTIMIZATION',
                message: 'Policy is small enough to be used as inline policy',
                benefit: 'Simpler management, no separate policy to maintain'
            });
        } else if (currentSize <= this.limits.managedPolicy.maxSizeBytes) {
            compatibility.recommendedType = 'managedPolicy';
        } else {
            compatibility.isCompatible = false;
            compatibility.recommendedType = null;
            
            this.recommendations.push({
                type: 'SIZE_REDUCTION_REQUIRED',
                message: `Policy exceeds all AWS limits. Current: ${currentSize} bytes`,
                benefit: 'Split into multiple policies or optimize content',
                priority: 'CRITICAL'
            });
        }

        // Generate optimization suggestions
        if (currentSize > this.limits.inlinePolicy.maxSizeBytes && currentSize <= this.limits.managedPolicy.maxSizeBytes) {
            this.recommendations.push({
                type: 'SIZE_OPTIMIZATION',
                message: 'Consider optimizing policy to fit inline policy limits',
                benefit: 'Enable use as inline policy for simpler management'
            });
        }

        return compatibility;
    }

    generateOptimizationReport(policy, policyType = 'managedPolicy') {
        const validation = this.validatePolicy(policy, policyType);
        
        const report = {
            timestamp: new Date().toISOString(),
            policyType,
            validation,
            optimizationOpportunities: this.findOptimizationOpportunities(policy, validation),
            recommendations: this.generateDetailedRecommendations(validation),
            sizingGuidance: this.generateSizingGuidance(validation)
        };

        return report;
    }

    findOptimizationOpportunities(policy, validation) {
        const opportunities = [];

        // Statement consolidation opportunities
        if (validation.structureAnalysis.statementCount > 10) {
            opportunities.push({
                type: 'STATEMENT_CONSOLIDATION',
                description: 'Multiple statements could potentially be consolidated',
                potentialSavings: 'Estimated 10-30% size reduction',
                effort: 'Medium'
            });
        }

        // Wildcard optimization
        if (policy.Statement) {
            let wildcardOpportunities = 0;
            policy.Statement.forEach(stmt => {
                if (stmt.Action && Array.isArray(stmt.Action) && stmt.Action.length > 5) {
                    const serviceGroups = {};
                    stmt.Action.forEach(action => {
                        const service = action.split(':')[0];
                        if (!serviceGroups[service]) serviceGroups[service] = 0;
                        serviceGroups[service]++;
                    });
                    
                    Object.values(serviceGroups).forEach(count => {
                        if (count > 3) wildcardOpportunities++;
                    });
                }
            });

            if (wildcardOpportunities > 0) {
                opportunities.push({
                    type: 'WILDCARD_CONSOLIDATION',
                    description: `${wildcardOpportunities} opportunities for wildcard consolidation`,
                    potentialSavings: 'Estimated 5-15% size reduction',
                    effort: 'Low',
                    securityNote: 'Review security implications before applying wildcards'
                });
            }
        }

        // Compression opportunities
        const compressionPotential = validation.sizeAnalysis.compressionPotential;
        if (compressionPotential.estimatedBytes > 100) {
            opportunities.push({
                type: 'FORMAT_OPTIMIZATION',
                description: 'Policy formatting can be optimized',
                potentialSavings: `${compressionPotential.estimatedBytes} bytes (${compressionPotential.percentage}%)`,
                effort: 'Low'
            });
        }

        return opportunities;
    }

    generateDetailedRecommendations(validation) {
        const recommendations = [];

        if (!validation.isValid) {
            recommendations.push({
                priority: 'CRITICAL',
                category: 'Compliance',
                title: 'Policy Exceeds AWS Limits',
                description: 'Policy must be reduced in size or split into multiple policies',
                actions: [
                    'Review and remove unnecessary permissions',
                    'Consolidate similar statements',
                    'Consider splitting into multiple policies',
                    'Use wildcards where appropriate (with security review)'
                ]
            });
        }

        if (validation.sizeAnalysis.utilization > 75) {
            recommendations.push({
                priority: 'HIGH',
                category: 'Optimization',
                title: 'High Size Utilization',
                description: `Policy uses ${validation.sizeAnalysis.utilization}% of size limit`,
                actions: [
                    'Monitor policy size when adding permissions',
                    'Regular policy review and cleanup',
                    'Consider policy splitting strategy'
                ]
            });
        }

        if (validation.structureAnalysis.statementCount > 20) {
            recommendations.push({
                priority: 'MEDIUM',
                category: 'Maintainability',
                title: 'High Statement Count',
                description: `Policy has ${validation.structureAnalysis.statementCount} statements`,
                actions: [
                    'Group related permissions into fewer statements',
                    'Use consistent naming conventions for statements',
                    'Document policy structure and purpose'
                ]
            });
        }

        return recommendations;
    }

    generateSizingGuidance(validation) {
        const guidance = {
            currentStatus: {
                size: validation.sizeAnalysis.currentSize,
                utilization: validation.sizeAnalysis.utilization,
                type: validation.policyType
            },
            recommendations: [],
            futureConsiderations: []
        };

        // Current recommendations
        if (validation.sizeAnalysis.remainingBytes < 500) {
            guidance.recommendations.push({
                type: 'IMMEDIATE',
                message: 'Very little space remaining - optimize before adding permissions',
                action: 'Reduce policy size by at least 20% before modifications'
            });
        } else if (validation.sizeAnalysis.remainingBytes < 1000) {
            guidance.recommendations.push({
                type: 'SHORT_TERM',
                message: 'Limited space remaining - plan optimization',
                action: 'Schedule policy optimization within next sprint'
            });
        }

        // Future considerations
        guidance.futureConsiderations.push({
            scenario: 'Adding 10 more permissions',
            estimatedGrowth: '200-500 bytes',
            feasible: validation.sizeAnalysis.remainingBytes > 500
        });

        guidance.futureConsiderations.push({
            scenario: 'Adding new service permissions',
            estimatedGrowth: '300-800 bytes per service',
            feasible: validation.sizeAnalysis.remainingBytes > 800
        });

        return guidance;
    }

    // Utility methods for integration with other tools
    checkPolicyCompatibility(policyPath, targetType = 'managedPolicy') {
        try {
            const policyData = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
            const validation = this.validatePolicy(policyData, targetType);
            
            return {
                compatible: validation.isValid,
                analysis: validation,
                recommendations: validation.recommendations
            };
        } catch (error) {
            return {
                compatible: false,
                error: error.message
            };
        }
    }

    suggestPolicyType(policy) {
        const sizes = {};
        const policyString = JSON.stringify(policy);
        const currentSize = Buffer.byteLength(policyString, 'utf8');

        // Test against all policy types
        Object.entries(this.limits).forEach(([type, limit]) => {
            if (limit.maxSizeBytes) {
                sizes[type] = {
                    fits: currentSize <= limit.maxSizeBytes,
                    utilization: Math.round((currentSize / limit.maxSizeBytes) * 100 * 100) / 100,
                    description: limit.description
                };
            }
        });

        // Find best fit
        const compatibleTypes = Object.entries(sizes)
            .filter(([type, info]) => info.fits)
            .sort((a, b) => a[1].utilization - b[1].utilization);

        return {
            currentSize,
            recommendedType: compatibleTypes.length > 0 ? compatibleTypes[0][0] : null,
            allCompatibleTypes: compatibleTypes,
            sizingDetails: sizes
        };
    }
}

module.exports = PolicyLimitValidator;

// CLI usage
if (require.main === module) {
    const validator = new PolicyLimitValidator();
    
    try {
        const policyFile = process.argv[2];
        const policyType = process.argv[3] || 'managedPolicy';
        
        if (!policyFile) {
            console.log('Usage: node policyLimitValidator.js <policy-file.json> [policy-type]');
            console.log('Policy types: managedPolicy, awsManagedPolicy, inlinePolicy, assumeRolePolicy');
            process.exit(1);
        }

        const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
        
        console.log('🔍 AWS Policy Size & Limit Analysis');
        console.log('====================================\n');
        
        const validation = validator.validatePolicy(policyData, policyType);
        const suggestion = validator.suggestPolicyType(policyData);
        
        // Size Analysis
        console.log('📊 Size Analysis:');
        console.log(`  Current Size: ${validation.sizeAnalysis.currentSize} bytes`);
        console.log(`  Target Type: ${policyType} (${validator.limits[policyType].description})`);
        console.log(`  Size Limit: ${validation.sizeAnalysis.limit} bytes`);
        console.log(`  Utilization: ${validation.sizeAnalysis.utilization}%`);
        console.log(`  Remaining: ${validation.sizeAnalysis.remainingBytes} bytes`);
        console.log(`  Status: ${validation.isValid ? '✅ VALID' : '❌ EXCEEDS LIMITS'}\n`);
        
        // Compatibility Check
        console.log('🎯 AWS Compatibility:');
        console.log(`  Recommended Type: ${suggestion.recommendedType || 'NONE - Too Large'}`);
        console.log('  Compatible Types:');
        suggestion.allCompatibleTypes.forEach(([type, info]) => {
            console.log(`    ✅ ${type}: ${info.utilization}% utilization`);
        });
        
        const incompatibleTypes = Object.entries(suggestion.sizingDetails)
            .filter(([type, info]) => !info.fits);
        if (incompatibleTypes.length > 0) {
            console.log('  Incompatible Types:');
            incompatibleTypes.forEach(([type, info]) => {
                console.log(`    ❌ ${type}: ${info.utilization}% (exceeds limit)`);
            });
        }
        console.log('');

        // Structure Analysis
        console.log('📋 Structure Analysis:');
        console.log(`  Statements: ${validation.structureAnalysis.statementCount}/${validator.limits.statements.maxPerPolicy}`);
        console.log(`  Average Statement Size: ${validation.structureAnalysis.averageStatementSize} bytes`);
        if (validation.structureAnalysis.largestStatement) {
            console.log(`  Largest Statement: ${validation.structureAnalysis.largestStatement.sid} (${validation.structureAnalysis.largestStatement.size} bytes)`);
        }
        console.log('');

        // Errors and Warnings
        if (validation.errors.length > 0) {
            console.log('🚨 Errors:');
            validation.errors.forEach((error, i) => {
                console.log(`  ${i + 1}. [${error.severity}] ${error.message}`);
            });
            console.log('');
        }

        if (validation.warnings.length > 0) {
            console.log('⚠️  Warnings:');
            validation.warnings.forEach((warning, i) => {
                console.log(`  ${i + 1}. ${warning.message}`);
                if (warning.recommendation) {
                    console.log(`     💡 ${warning.recommendation}`);
                }
            });
            console.log('');
        }

        // Optimization Report
        const report = validator.generateOptimizationReport(policyData, policyType);
        if (report.optimizationOpportunities.length > 0) {
            console.log('💡 Optimization Opportunities:');
            report.optimizationOpportunities.forEach((opp, i) => {
                console.log(`  ${i + 1}. ${opp.type}`);
                console.log(`     ${opp.description}`);
                console.log(`     Savings: ${opp.potentialSavings}`);
                console.log(`     Effort: ${opp.effort}`);
                if (opp.securityNote) {
                    console.log(`     ⚠️  ${opp.securityNote}`);
                }
                console.log('');
            });
        }

        // Save detailed report
        const reportFile = 'policy-limits-report.json';
        fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
        console.log(`📄 Detailed report saved to: ${reportFile}`);
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}