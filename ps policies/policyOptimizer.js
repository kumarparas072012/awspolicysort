const fs = require('fs');

class PolicyOptimizer {
    constructor() {
        this.optimizations = [];
        
        this.actionGroups = {
            'ec2:Read': [
                'ec2:Describe*',
                'ec2:Get*',
                'ec2:List*'
            ],
            's3:Read': [
                's3:GetObject',
                's3:GetObjectVersion',
                's3:GetBucketLocation',
                's3:ListBucket'
            ],
            's3:Write': [
                's3:PutObject',
                's3:PutObjectAcl',
                's3:DeleteObject',
                's3:DeleteObjectVersion'
            ],
            'iam:Read': [
                'iam:GetRole',
                'iam:GetUser',
                'iam:GetPolicy',
                'iam:ListRoles',
                'iam:ListUsers',
                'iam:ListPolicies'
            ]
        };
        
        this.serviceCategories = {
            'compute': ['ec2', 'ecs', 'lambda', 'batch'],
            'storage': ['s3', 'ebs', 'efs', 'fsx'],
            'database': ['rds', 'dynamodb', 'elasticache', 'redshift'],
            'security': ['iam', 'sts', 'kms', 'secretsmanager'],
            'networking': ['vpc', 'route53', 'cloudfront', 'elb'],
            'monitoring': ['cloudwatch', 'logs', 'xray', 'cloudtrail']
        };
    }

    optimize(policy) {
        this.optimizations = [];
        
        const optimizedPolicy = JSON.parse(JSON.stringify(policy));
        const statements = optimizedPolicy.Statement || [];
        
        const optimizations = {
            consolidatedStatements: this.consolidateStatements(statements),
            removedDuplicates: this.removeDuplicateStatements(statements),
            groupedActions: this.groupSimilarActions(statements),
            optimizedConditions: this.optimizeConditions(statements),
            simplifiedResources: this.simplifyResources(statements),
            reorganizedByService: this.reorganizeByService(statements)
        };
        
        const finalOptimized = this.applyOptimizations(optimizedPolicy, optimizations);
        
        return {
            original: policy,
            optimized: finalOptimized,
            optimizations: this.optimizations,
            savings: this.calculateSavings(policy, finalOptimized),
            recommendations: this.generateOptimizationRecommendations(policy, finalOptimized)
        };
    }

    consolidateStatements(statements) {
        const consolidated = [];
        const processed = new Set();
        
        statements.forEach((stmt, index) => {
            if (processed.has(index)) return;
            
            const similar = this.findSimilarStatements(stmt, statements, index);
            
            if (similar.length > 0) {
                const consolidatedStmt = this.mergeStatements([stmt, ...similar.map(s => s.statement)]);
                consolidated.push({
                    type: 'CONSOLIDATION',
                    originalIndices: [index, ...similar.map(s => s.index)],
                    consolidatedStatement: consolidatedStmt,
                    description: `Consolidated ${similar.length + 1} similar statements`,
                    savings: `Reduced from ${similar.length + 1} to 1 statement`
                });
                
                similar.forEach(s => processed.add(s.index));
                processed.add(index);
            }
        });
        
        return consolidated;
    }

    findSimilarStatements(targetStmt, statements, targetIndex) {
        const similar = [];
        
        statements.forEach((stmt, index) => {
            if (index === targetIndex) return;
            
            if (this.canConsolidate(targetStmt, stmt)) {
                similar.push({ statement: stmt, index });
            }
        });
        
        return similar;
    }

    canConsolidate(stmt1, stmt2) {
        // Must have same Effect
        if (stmt1.Effect !== stmt2.Effect) return false;
        
        // Must have compatible conditions
        if (!this.areConditionsCompatible(stmt1.Condition, stmt2.Condition)) return false;
        
        // Must have overlapping resources or compatible resource patterns
        const resources1 = this.normalizeArray(stmt1.Resource);
        const resources2 = this.normalizeArray(stmt2.Resource);
        
        if (resources1.length > 0 && resources2.length > 0) {
            const hasOverlap = resources1.some(r1 => 
                resources2.some(r2 => this.areResourcesCompatible(r1, r2))
            );
            if (!hasOverlap) return false;
        }
        
        return true;
    }

    areConditionsCompatible(cond1, cond2) {
        if (!cond1 && !cond2) return true;
        if (!cond1 || !cond2) return false;
        
        const str1 = JSON.stringify(cond1, Object.keys(cond1).sort());
        const str2 = JSON.stringify(cond2, Object.keys(cond2).sort());
        
        return str1 === str2;
    }

    areResourcesCompatible(resource1, resource2) {
        // Exact match
        if (resource1 === resource2) return true;
        
        // Both are wildcards
        if (resource1 === '*' || resource2 === '*') return true;
        
        // Check if they're from the same service
        const service1 = this.extractServiceFromArn(resource1);
        const service2 = this.extractServiceFromArn(resource2);
        
        return service1 === service2;
    }

    extractServiceFromArn(arn) {
        if (typeof arn !== 'string') return null;
        const parts = arn.split(':');
        return parts.length > 2 ? parts[2] : null;
    }

    mergeStatements(statements) {
        const merged = {
            Sid: this.generateConsolidatedSid(statements),
            Effect: statements[0].Effect
        };
        
        // Merge actions
        const allActions = new Set();
        statements.forEach(stmt => {
            const actions = this.normalizeArray(stmt.Action);
            actions.forEach(action => allActions.add(action));
        });
        merged.Action = Array.from(allActions).sort();
        
        // Merge resources
        const allResources = new Set();
        statements.forEach(stmt => {
            const resources = this.normalizeArray(stmt.Resource);
            resources.forEach(resource => allResources.add(resource));
        });
        if (allResources.size > 0) {
            merged.Resource = Array.from(allResources).sort();
        }
        
        // Use the most restrictive condition (first non-empty one)
        const condition = statements.find(stmt => stmt.Condition)?.Condition;
        if (condition) {
            merged.Condition = condition;
        }
        
        return merged;
    }

    generateConsolidatedSid(statements) {
        const sids = statements.map(s => s.Sid).filter(Boolean);
        if (sids.length === 0) return 'ConsolidatedStatement';
        
        // Find common prefix
        const firstSid = sids[0];
        let commonPrefix = '';
        
        for (let i = 0; i < firstSid.length; i++) {
            const char = firstSid[i];
            if (sids.every(sid => sid[i] === char)) {
                commonPrefix += char;
            } else {
                break;
            }
        }
        
        return commonPrefix || `Consolidated${sids.length}Statements`;
    }

    removeDuplicateStatements(statements) {
        const seen = new Map();
        const duplicates = [];
        
        statements.forEach((stmt, index) => {
            const key = this.generateStatementKey(stmt);
            
            if (seen.has(key)) {
                duplicates.push({
                    type: 'DUPLICATE',
                    originalIndex: seen.get(key),
                    duplicateIndex: index,
                    statement: stmt,
                    description: `Duplicate of statement at index ${seen.get(key)}`,
                    recommendation: 'Remove duplicate statement'
                });
            } else {
                seen.set(key, index);
            }
        });
        
        return duplicates;
    }

    generateStatementKey(statement) {
        const normalized = {
            Effect: statement.Effect,
            Action: this.normalizeArray(statement.Action).sort(),
            Resource: this.normalizeArray(statement.Resource).sort(),
            Condition: statement.Condition || {}
        };
        
        return JSON.stringify(normalized);
    }

    groupSimilarActions(statements) {
        const groupings = [];
        
        statements.forEach((stmt, index) => {
            if (!stmt.Action) return;
            
            const actions = this.normalizeArray(stmt.Action);
            const grouped = this.identifyActionGroups(actions);
            
            if (grouped.suggestions.length > 0) {
                groupings.push({
                    type: 'ACTION_GROUPING',
                    statementIndex: index,
                    originalActions: actions,
                    suggestions: grouped.suggestions,
                    description: 'Actions can be grouped for better readability',
                    savings: `Can group ${grouped.groupableActions} actions into ${grouped.suggestions.length} groups`
                });
            }
        });
        
        return groupings;
    }

    identifyActionGroups(actions) {
        const suggestions = [];
        let groupableActions = 0;
        
        Object.entries(this.actionGroups).forEach(([groupName, groupActions]) => {
            const matchingActions = actions.filter(action => 
                groupActions.some(groupAction => this.actionMatches(action, groupAction))
            );
            
            if (matchingActions.length >= 2) {
                suggestions.push({
                    groupName,
                    actions: matchingActions,
                    replacement: groupActions[0], // Use the wildcard version
                    description: `Replace ${matchingActions.length} actions with ${groupActions[0]}`
                });
                groupableActions += matchingActions.length;
            }
        });
        
        return { suggestions, groupableActions };
    }

    actionMatches(action, pattern) {
        if (pattern.endsWith('*')) {
            const prefix = pattern.slice(0, -1);
            return action.startsWith(prefix);
        }
        return action === pattern;
    }

    optimizeConditions(statements) {
        const optimizations = [];
        
        statements.forEach((stmt, index) => {
            if (!stmt.Condition) return;
            
            const optimized = this.simplifyCondition(stmt.Condition);
            
            if (optimized.simplified) {
                optimizations.push({
                    type: 'CONDITION_OPTIMIZATION',
                    statementIndex: index,
                    original: stmt.Condition,
                    optimized: optimized.condition,
                    description: optimized.description,
                    savings: `Reduced condition complexity`
                });
            }
        });
        
        return optimizations;
    }

    simplifyCondition(condition) {
        const simplified = JSON.parse(JSON.stringify(condition));
        let hasChanges = false;
        let description = '';
        
        // Remove redundant string conditions
        Object.keys(simplified).forEach(conditionType => {
            if (typeof simplified[conditionType] === 'object') {
                Object.keys(simplified[conditionType]).forEach(key => {
                    const values = simplified[conditionType][key];
                    
                    if (Array.isArray(values)) {
                        const uniqueValues = [...new Set(values)];
                        if (uniqueValues.length < values.length) {
                            simplified[conditionType][key] = uniqueValues;
                            hasChanges = true;
                            description += 'Removed duplicate condition values. ';
                        }
                    }
                });
            }
        });
        
        return {
            simplified: hasChanges,
            condition: simplified,
            description: description.trim()
        };
    }

    simplifyResources(statements) {
        const optimizations = [];
        
        statements.forEach((stmt, index) => {
            if (!stmt.Resource) return;
            
            const resources = this.normalizeArray(stmt.Resource);
            const simplified = this.consolidateResources(resources);
            
            if (simplified.length < resources.length) {
                optimizations.push({
                    type: 'RESOURCE_SIMPLIFICATION',
                    statementIndex: index,
                    original: resources,
                    simplified: simplified,
                    description: `Consolidated ${resources.length} resources into ${simplified.length}`,
                    savings: `Reduced resource count by ${resources.length - simplified.length}`
                });
            }
        });
        
        return optimizations;
    }

    consolidateResources(resources) {
        const consolidated = [];
        const processed = new Set();
        
        resources.forEach((resource, index) => {
            if (processed.has(index)) return;
            
            // Check if this resource can subsume others
            const subsumed = [];
            resources.forEach((other, otherIndex) => {
                if (index !== otherIndex && !processed.has(otherIndex)) {
                    if (this.resourceSubsumes(resource, other)) {
                        subsumed.push(otherIndex);
                    }
                }
            });
            
            if (subsumed.length > 0) {
                consolidated.push(resource);
                subsumed.forEach(idx => processed.add(idx));
                processed.add(index);
            } else if (!processed.has(index)) {
                consolidated.push(resource);
                processed.add(index);
            }
        });
        
        return consolidated;
    }

    resourceSubsumes(broader, specific) {
        if (broader === '*') return true;
        if (broader === specific) return false;
        
        // Check if broader is a wildcard pattern that includes specific
        if (broader.includes('*')) {
            const pattern = broader.replace(/\*/g, '.*');
            const regex = new RegExp(`^${pattern}$`);
            return regex.test(specific);
        }
        
        return false;
    }

    reorganizeByService(statements) {
        const serviceGroups = new Map();
        
        statements.forEach((stmt, index) => {
            const services = this.extractServicesFromStatement(stmt);
            services.forEach(service => {
                if (!serviceGroups.has(service)) {
                    serviceGroups.set(service, []);
                }
                serviceGroups.get(service).push({ statement: stmt, index });
            });
        });
        
        const reorganization = [];
        serviceGroups.forEach((stmts, service) => {
            if (stmts.length > 1) {
                reorganization.push({
                    type: 'SERVICE_GROUPING',
                    service,
                    statements: stmts,
                    description: `Group ${stmts.length} statements for ${service} service`,
                    recommendation: `Consider organizing statements by service for better readability`
                });
            }
        });
        
        return reorganization;
    }

    extractServicesFromStatement(statement) {
        const services = new Set();
        
        if (statement.Action) {
            const actions = this.normalizeArray(statement.Action);
            actions.forEach(action => {
                if (action !== '*') {
                    const service = action.split(':')[0];
                    if (service) services.add(service);
                }
            });
        }
        
        return Array.from(services);
    }

    normalizeArray(value) {
        if (!value) return [];
        return Array.isArray(value) ? value : [value];
    }

    applyOptimizations(policy, optimizations) {
        const optimized = JSON.parse(JSON.stringify(policy));
        
        // Apply consolidations
        if (optimizations.consolidatedStatements.length > 0) {
            const newStatements = [];
            const processedIndices = new Set();
            
            optimizations.consolidatedStatements.forEach(consolidation => {
                newStatements.push(consolidation.consolidatedStatement);
                consolidation.originalIndices.forEach(idx => processedIndices.add(idx));
                
                this.optimizations.push({
                    type: 'Applied consolidation',
                    description: consolidation.description
                });
            });
            
            // Add non-consolidated statements
            optimized.Statement.forEach((stmt, index) => {
                if (!processedIndices.has(index)) {
                    newStatements.push(stmt);
                }
            });
            
            optimized.Statement = newStatements;
        }
        
        // Remove duplicates
        if (optimizations.removedDuplicates.length > 0) {
            const indicesToRemove = new Set(optimizations.removedDuplicates.map(d => d.duplicateIndex));
            optimized.Statement = optimized.Statement.filter((_, index) => !indicesToRemove.has(index));
            
            this.optimizations.push({
                type: 'Removed duplicates',
                description: `Removed ${optimizations.removedDuplicates.length} duplicate statements`
            });
        }
        
        return optimized;
    }

    calculateSavings(original, optimized) {
        const originalStats = this.getPolicyStats(original);
        const optimizedStats = this.getPolicyStats(optimized);
        
        return {
            statementReduction: originalStats.totalStatements - optimizedStats.totalStatements,
            statementReductionPercent: Math.round(((originalStats.totalStatements - optimizedStats.totalStatements) / originalStats.totalStatements) * 100),
            sizeReduction: JSON.stringify(original).length - JSON.stringify(optimized).length,
            complexity: {
                original: this.calculateComplexity(original),
                optimized: this.calculateComplexity(optimized)
            }
        };
    }

    getPolicyStats(policy) {
        const statements = policy.Statement || [];
        
        return {
            totalStatements: statements.length,
            totalActions: statements.reduce((count, stmt) => {
                if (stmt.Action) {
                    return count + (Array.isArray(stmt.Action) ? stmt.Action.length : 1);
                }
                return count;
            }, 0),
            statementsWithConditions: statements.filter(s => s.Condition).length
        };
    }

    calculateComplexity(policy) {
        const statements = policy.Statement || [];
        let complexity = 0;
        
        statements.forEach(stmt => {
            complexity += 1; // Base complexity per statement
            
            if (stmt.Action) {
                const actions = this.normalizeArray(stmt.Action);
                complexity += actions.length * 0.1;
            }
            
            if (stmt.Resource) {
                const resources = this.normalizeArray(stmt.Resource);
                complexity += resources.length * 0.1;
            }
            
            if (stmt.Condition) {
                complexity += Object.keys(stmt.Condition).length * 0.2;
            }
        });
        
        return Math.round(complexity * 100) / 100;
    }

    generateOptimizationRecommendations(original, optimized) {
        const recommendations = [];
        const savings = this.calculateSavings(original, optimized);
        
        if (savings.statementReduction > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'Statement Consolidation',
                description: `Reduced policy from ${this.getPolicyStats(original).totalStatements} to ${this.getPolicyStats(optimized).totalStatements} statements`,
                benefit: `${savings.statementReductionPercent}% reduction in statement count`
            });
        }
        
        if (savings.complexity.original > savings.complexity.optimized) {
            const complexityReduction = Math.round(((savings.complexity.original - savings.complexity.optimized) / savings.complexity.original) * 100);
            recommendations.push({
                priority: 'MEDIUM',
                type: 'Complexity Reduction',
                description: 'Policy complexity has been reduced',
                benefit: `${complexityReduction}% reduction in complexity score`
            });
        }
        
        recommendations.push({
            priority: 'LOW',
            type: 'Maintenance',
            description: 'Regular policy optimization helps maintain security and performance',
            benefit: 'Improved readability and reduced policy size'
        });
        
        return recommendations;
    }

    generateOptimizationReport(policy, outputFile = 'optimization-report.json') {
        const result = this.optimize(policy);
        
        const report = {
            timestamp: new Date().toISOString(),
            optimization: result,
            statistics: {
                originalSize: JSON.stringify(result.original).length,
                optimizedSize: JSON.stringify(result.optimized).length,
                compressionRatio: Math.round((1 - JSON.stringify(result.optimized).length / JSON.stringify(result.original).length) * 100)
            }
        };
        
        fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
        return report;
    }
}

module.exports = PolicyOptimizer;

if (require.main === module) {
    const optimizer = new PolicyOptimizer();
    
    try {
        const policyFile = process.argv[2] || './alpha_ps.json';
        const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
        
        console.log('⚡ AWS Policy Optimization Report');
        console.log('==================================\n');
        
        const result = optimizer.optimize(policyData);
        
        console.log('📊 Optimization Summary:');
        console.log(`  Original statements: ${optimizer.getPolicyStats(result.original).totalStatements}`);
        console.log(`  Optimized statements: ${optimizer.getPolicyStats(result.optimized).totalStatements}`);
        console.log(`  Statement reduction: ${result.savings.statementReduction} (${result.savings.statementReductionPercent}%)`);
        console.log(`  Size reduction: ${result.savings.sizeReduction} characters`);
        console.log(`  Complexity reduction: ${(result.savings.complexity.original - result.savings.complexity.optimized).toFixed(2)}\n`);
        
        if (result.optimizations.length > 0) {
            console.log('🛠️ Applied Optimizations:');
            result.optimizations.forEach((opt, i) => {
                console.log(`  ${i + 1}. ${opt.type}: ${opt.description}`);
            });
            console.log('');
        }
        
        if (result.recommendations.length > 0) {
            console.log('💡 Recommendations:');
            result.recommendations.forEach((rec, i) => {
                console.log(`  ${i + 1}. [${rec.priority}] ${rec.type}`);
                console.log(`     ${rec.description}`);
                console.log(`     Benefit: ${rec.benefit}\n`);
            });
        }
        
        // Save optimized policy
        const optimizedFile = 'optimized-policy.json';
        fs.writeFileSync(optimizedFile, JSON.stringify(result.optimized, null, 2));
        console.log(`💾 Optimized policy saved to: ${optimizedFile}`);
        
        // Save detailed report
        const reportFile = 'optimization-report.json';
        optimizer.generateOptimizationReport(policyData, reportFile);
        console.log(`📄 Detailed report saved to: ${reportFile}`);
        
    } catch (error) {
        console.error('Error optimizing policy:', error.message);
    }
}