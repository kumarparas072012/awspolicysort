const fs = require('fs');

class PolicyComparator {
    constructor() {
        this.differences = [];
    }

    compare(policy1, policy2, labels = { policy1: 'Policy A', policy2: 'Policy B' }) {
        this.differences = [];
        this.labels = labels;
        
        const comparison = {
            summary: this.generateComparisonSummary(policy1, policy2),
            differences: this.findDifferences(policy1, policy2),
            similarities: this.findSimilarities(policy1, policy2),
            recommendations: this.generateRecommendations(policy1, policy2),
            mergeability: this.assessMergeability(policy1, policy2)
        };
        
        return comparison;
    }

    generateComparisonSummary(policy1, policy2) {
        const stats1 = this.getPolicyStats(policy1);
        const stats2 = this.getPolicyStats(policy2);
        
        return {
            [this.labels.policy1]: stats1,
            [this.labels.policy2]: stats2,
            comparison: {
                statementDifference: stats2.totalStatements - stats1.totalStatements,
                actionDifference: stats2.totalActions - stats1.totalActions,
                permissivenessDifference: stats2.wildcardActions - stats1.wildcardActions
            }
        };
    }

    getPolicyStats(policy) {
        const statements = policy.Statement || [];
        
        return {
            totalStatements: statements.length,
            allowStatements: statements.filter(s => s.Effect === 'Allow').length,
            denyStatements: statements.filter(s => s.Effect === 'Deny').length,
            statementsWithConditions: statements.filter(s => s.Condition).length,
            totalActions: statements.reduce((count, stmt) => {
                if (stmt.Action) {
                    return count + (Array.isArray(stmt.Action) ? stmt.Action.length : 1);
                }
                return count;
            }, 0),
            wildcardActions: statements.filter(s => {
                if (s.Action) {
                    const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
                    return actions.some(a => a && a.includes('*'));
                }
                return false;
            }).length,
            uniqueSids: new Set(statements.map(s => s.Sid).filter(Boolean)).size
        };
    }

    findDifferences(policy1, policy2) {
        const differences = [];
        const statements1 = this.normalizeStatements(policy1.Statement || []);
        const statements2 = this.normalizeStatements(policy2.Statement || []);
        
        const sids1 = new Set(statements1.map(s => s.Sid).filter(Boolean));
        const sids2 = new Set(statements2.map(s => s.Sid).filter(Boolean));
        
        // Find statements only in policy1
        sids1.forEach(sid => {
            if (!sids2.has(sid)) {
                const statement = statements1.find(s => s.Sid === sid);
                differences.push({
                    type: 'ONLY_IN_POLICY1',
                    category: 'Statement Missing',
                    statementId: sid,
                    description: `Statement "${sid}" exists only in ${this.labels.policy1}`,
                    statement: statement,
                    impact: this.assessStatementImpact(statement)
                });
            }
        });
        
        // Find statements only in policy2
        sids2.forEach(sid => {
            if (!sids1.has(sid)) {
                const statement = statements2.find(s => s.Sid === sid);
                differences.push({
                    type: 'ONLY_IN_POLICY2',
                    category: 'Statement Missing',
                    statementId: sid,
                    description: `Statement "${sid}" exists only in ${this.labels.policy2}`,
                    statement: statement,
                    impact: this.assessStatementImpact(statement)
                });
            }
        });
        
        // Find statements with same Sid but different content
        sids1.forEach(sid => {
            if (sids2.has(sid)) {
                const stmt1 = statements1.find(s => s.Sid === sid);
                const stmt2 = statements2.find(s => s.Sid === sid);
                
                const statementDiffs = this.compareStatements(stmt1, stmt2, sid);
                differences.push(...statementDiffs);
            }
        });
        
        return differences;
    }

    compareStatements(stmt1, stmt2, sid) {
        const differences = [];
        
        // Compare Effect
        if (stmt1.Effect !== stmt2.Effect) {
            differences.push({
                type: 'EFFECT_DIFFERENCE',
                category: 'Statement Content',
                statementId: sid,
                description: `Effect differs: ${this.labels.policy1} has "${stmt1.Effect}", ${this.labels.policy2} has "${stmt2.Effect}"`,
                policy1Value: stmt1.Effect,
                policy2Value: stmt2.Effect,
                impact: 'HIGH'
            });
        }
        
        // Compare Actions
        const actions1 = this.normalizeArray(stmt1.Action);
        const actions2 = this.normalizeArray(stmt2.Action);
        const actionDiff = this.compareArrays(actions1, actions2);
        
        if (actionDiff.differences.length > 0) {
            differences.push({
                type: 'ACTION_DIFFERENCE',
                category: 'Actions',
                statementId: sid,
                description: `Actions differ between policies`,
                details: actionDiff,
                impact: this.assessActionImpact(actionDiff)
            });
        }
        
        // Compare Resources
        const resources1 = this.normalizeArray(stmt1.Resource);
        const resources2 = this.normalizeArray(stmt2.Resource);
        const resourceDiff = this.compareArrays(resources1, resources2);
        
        if (resourceDiff.differences.length > 0) {
            differences.push({
                type: 'RESOURCE_DIFFERENCE',
                category: 'Resources',
                statementId: sid,
                description: `Resources differ between policies`,
                details: resourceDiff,
                impact: this.assessResourceImpact(resourceDiff)
            });
        }
        
        // Compare Conditions
        const conditionDiff = this.compareConditions(stmt1.Condition, stmt2.Condition);
        if (conditionDiff.hasDifferences) {
            differences.push({
                type: 'CONDITION_DIFFERENCE',
                category: 'Conditions',
                statementId: sid,
                description: `Conditions differ between policies`,
                details: conditionDiff,
                impact: 'MEDIUM'
            });
        }
        
        return differences;
    }

    normalizeArray(value) {
        if (!value) return [];
        return Array.isArray(value) ? value.sort() : [value];
    }

    compareArrays(arr1, arr2) {
        const set1 = new Set(arr1);
        const set2 = new Set(arr2);
        
        const onlyInFirst = arr1.filter(item => !set2.has(item));
        const onlyInSecond = arr2.filter(item => !set1.has(item));
        const common = arr1.filter(item => set2.has(item));
        
        return {
            onlyInFirst,
            onlyInSecond,
            common,
            differences: onlyInFirst.length > 0 || onlyInSecond.length > 0
        };
    }

    compareConditions(cond1, cond2) {
        const normalizedCond1 = JSON.stringify(cond1 || {}, Object.keys(cond1 || {}).sort());
        const normalizedCond2 = JSON.stringify(cond2 || {}, Object.keys(cond2 || {}).sort());
        
        return {
            hasDifferences: normalizedCond1 !== normalizedCond2,
            condition1: cond1,
            condition2: cond2
        };
    }

    assessStatementImpact(statement) {
        if (!statement) return 'LOW';
        
        if (statement.Effect === 'Deny') return 'HIGH';
        
        if (statement.Action) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            if (actions.some(a => a === '*' || a.includes('*'))) return 'HIGH';
        }
        
        if (statement.Resource === '*') return 'MEDIUM';
        
        return 'LOW';
    }

    assessActionImpact(actionDiff) {
        const hasWildcards = [...actionDiff.onlyInFirst, ...actionDiff.onlyInSecond]
            .some(action => action === '*' || action.includes('*'));
        
        if (hasWildcards) return 'HIGH';
        
        const dangerousActions = ['iam:', 'sts:', 'organizations:', 'account:'];
        const hasDangerous = [...actionDiff.onlyInFirst, ...actionDiff.onlyInSecond]
            .some(action => dangerousActions.some(dangerous => action.startsWith(dangerous)));
        
        if (hasDangerous) return 'HIGH';
        
        return actionDiff.differences.length > 5 ? 'MEDIUM' : 'LOW';
    }

    assessResourceImpact(resourceDiff) {
        const hasWildcards = [...resourceDiff.onlyInFirst, ...resourceDiff.onlyInSecond]
            .includes('*');
        
        return hasWildcards ? 'HIGH' : 'MEDIUM';
    }

    findSimilarities(policy1, policy2) {
        const statements1 = this.normalizeStatements(policy1.Statement || []);
        const statements2 = this.normalizeStatements(policy2.Statement || []);
        
        const similarities = [];
        const sids1 = new Set(statements1.map(s => s.Sid).filter(Boolean));
        const sids2 = new Set(statements2.map(s => s.Sid).filter(Boolean));
        
        // Find common statement IDs
        const commonSids = [...sids1].filter(sid => sids2.has(sid));
        
        commonSids.forEach(sid => {
            const stmt1 = statements1.find(s => s.Sid === sid);
            const stmt2 = statements2.find(s => s.Sid === sid);
            
            const similarity = this.calculateStatementSimilarity(stmt1, stmt2);
            if (similarity.score > 0.8) {
                similarities.push({
                    statementId: sid,
                    similarity: similarity.score,
                    commonElements: similarity.commonElements
                });
            }
        });
        
        return similarities;
    }

    calculateStatementSimilarity(stmt1, stmt2) {
        let score = 0;
        let totalChecks = 0;
        const commonElements = [];
        
        // Effect similarity
        totalChecks++;
        if (stmt1.Effect === stmt2.Effect) {
            score++;
            commonElements.push(`Same effect: ${stmt1.Effect}`);
        }
        
        // Action similarity
        totalChecks++;
        const actions1 = this.normalizeArray(stmt1.Action);
        const actions2 = this.normalizeArray(stmt2.Action);
        const actionOverlap = this.calculateOverlap(actions1, actions2);
        score += actionOverlap;
        if (actionOverlap > 0.5) {
            commonElements.push(`Similar actions (${Math.round(actionOverlap * 100)}% overlap)`);
        }
        
        // Resource similarity
        totalChecks++;
        const resources1 = this.normalizeArray(stmt1.Resource);
        const resources2 = this.normalizeArray(stmt2.Resource);
        const resourceOverlap = this.calculateOverlap(resources1, resources2);
        score += resourceOverlap;
        if (resourceOverlap > 0.5) {
            commonElements.push(`Similar resources (${Math.round(resourceOverlap * 100)}% overlap)`);
        }
        
        // Condition similarity
        totalChecks++;
        const conditionsEqual = JSON.stringify(stmt1.Condition || {}) === JSON.stringify(stmt2.Condition || {});
        if (conditionsEqual) {
            score++;
            commonElements.push('Identical conditions');
        }
        
        return {
            score: score / totalChecks,
            commonElements
        };
    }

    calculateOverlap(arr1, arr2) {
        const set1 = new Set(arr1);
        const set2 = new Set(arr2);
        const intersection = new Set([...set1].filter(x => set2.has(x)));
        const union = new Set([...set1, ...set2]);
        
        return union.size === 0 ? 0 : intersection.size / union.size;
    }

    normalizeStatements(statements) {
        return statements.map((stmt, index) => ({
            ...stmt,
            Sid: stmt.Sid || `Statement-${index + 1}`
        }));
    }

    generateRecommendations(policy1, policy2) {
        const recommendations = [];
        const differences = this.findDifferences(policy1, policy2);
        
        const highImpactDiffs = differences.filter(d => d.impact === 'HIGH');
        if (highImpactDiffs.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'Security Review',
                description: `${highImpactDiffs.length} high-impact differences found. Review carefully before merging.`,
                action: 'Conduct security review of differences'
            });
        }
        
        const onlyInPolicy1 = differences.filter(d => d.type === 'ONLY_IN_POLICY1');
        const onlyInPolicy2 = differences.filter(d => d.type === 'ONLY_IN_POLICY2');
        
        if (onlyInPolicy1.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'Missing Statements',
                description: `${onlyInPolicy1.length} statements exist only in ${this.labels.policy1}`,
                action: `Consider if these statements should be added to ${this.labels.policy2}`
            });
        }
        
        if (onlyInPolicy2.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'Additional Statements',
                description: `${onlyInPolicy2.length} statements exist only in ${this.labels.policy2}`,
                action: `Consider if these statements should be added to ${this.labels.policy1}`
            });
        }
        
        const similarities = this.findSimilarities(policy1, policy2);
        if (similarities.length > 0) {
            recommendations.push({
                priority: 'LOW',
                type: 'Consolidation Opportunity',
                description: `${similarities.length} similar statements found that could potentially be consolidated`,
                action: 'Review similar statements for consolidation opportunities'
            });
        }
        
        return recommendations;
    }

    assessMergeability(policy1, policy2) {
        const differences = this.findDifferences(policy1, policy2);
        const conflicts = differences.filter(d => d.type === 'EFFECT_DIFFERENCE');
        const highImpactDiffs = differences.filter(d => d.impact === 'HIGH');
        
        let mergeability = 'SAFE';
        let issues = [];
        
        if (conflicts.length > 0) {
            mergeability = 'DANGEROUS';
            issues.push(`${conflicts.length} effect conflicts detected`);
        } else if (highImpactDiffs.length > 5) {
            mergeability = 'RISKY';
            issues.push(`${highImpactDiffs.length} high-impact differences`);
        } else if (differences.length > 10) {
            mergeability = 'COMPLEX';
            issues.push(`${differences.length} total differences`);
        }
        
        return {
            level: mergeability,
            issues,
            recommendation: this.getMergeRecommendation(mergeability)
        };
    }

    getMergeRecommendation(mergeability) {
        switch (mergeability) {
            case 'SAFE':
                return 'Policies can be safely merged with minimal review';
            case 'COMPLEX':
                return 'Policies can be merged but require careful review of differences';
            case 'RISKY':
                return 'Policies require thorough security review before merging';
            case 'DANGEROUS':
                return 'Policies have conflicting effects and should not be merged without resolving conflicts';
            default:
                return 'Review required before merging';
        }
    }

    generateDiffReport(policy1, policy2, options = {}) {
        const comparison = this.compare(policy1, policy2, options.labels);
        
        const report = {
            timestamp: new Date().toISOString(),
            comparison,
            visualDiff: this.generateVisualDiff(policy1, policy2),
            mergePreview: this.generateMergePreview(policy1, policy2)
        };
        
        if (options.outputFile) {
            fs.writeFileSync(options.outputFile, JSON.stringify(report, null, 2));
        }
        
        return report;
    }

    generateVisualDiff(policy1, policy2) {
        const statements1 = this.normalizeStatements(policy1.Statement || []);
        const statements2 = this.normalizeStatements(policy2.Statement || []);
        
        const sidMap1 = new Map(statements1.map(s => [s.Sid, s]));
        const sidMap2 = new Map(statements2.map(s => [s.Sid, s]));
        
        const allSids = new Set([...sidMap1.keys(), ...sidMap2.keys()]);
        
        return Array.from(allSids).map(sid => {
            const stmt1 = sidMap1.get(sid);
            const stmt2 = sidMap2.get(sid);
            
            let status;
            if (stmt1 && stmt2) {
                const similar = this.calculateStatementSimilarity(stmt1, stmt2);
                status = similar.score === 1 ? 'IDENTICAL' : 'MODIFIED';
            } else if (stmt1) {
                status = 'REMOVED';
            } else {
                status = 'ADDED';
            }
            
            return {
                sid,
                status,
                statement1: stmt1,
                statement2: stmt2
            };
        });
    }

    generateMergePreview(policy1, policy2) {
        const statements1 = this.normalizeStatements(policy1.Statement || []);
        const statements2 = this.normalizeStatements(policy2.Statement || []);
        
        const merged = {
            Version: policy2.Version || policy1.Version || '2012-10-17',
            Statement: []
        };
        
        const sidMap1 = new Map(statements1.map(s => [s.Sid, s]));
        const sidMap2 = new Map(statements2.map(s => [s.Sid, s]));
        const allSids = new Set([...sidMap1.keys(), ...sidMap2.keys()]);
        
        allSids.forEach(sid => {
            const stmt1 = sidMap1.get(sid);
            const stmt2 = sidMap2.get(sid);
            
            if (stmt2) {
                merged.Statement.push({
                    ...stmt2,
                    _mergeNote: stmt1 ? 'Updated from policy1' : 'Added from policy2'
                });
            } else if (stmt1) {
                merged.Statement.push({
                    ...stmt1,
                    _mergeNote: 'Kept from policy1'
                });
            }
        });
        
        return merged;
    }
}

module.exports = PolicyComparator;

if (require.main === module) {
    const comparator = new PolicyComparator();
    
    try {
        const file1 = process.argv[2];
        const file2 = process.argv[3];
        
        if (!file1 || !file2) {
            console.log('Usage: node policyComparator.js <policy1.json> <policy2.json>');
            process.exit(1);
        }
        
        const policy1 = JSON.parse(fs.readFileSync(file1, 'utf8'));
        const policy2 = JSON.parse(fs.readFileSync(file2, 'utf8'));
        
        console.log('🔍 AWS Policy Comparison Report');
        console.log('================================\n');
        
        const comparison = comparator.compare(policy1, policy2, {
            policy1: file1,
            policy2: file2
        });
        
        console.log('📊 Summary:');
        console.log(`  ${file1}: ${comparison.summary[file1].totalStatements} statements, ${comparison.summary[file1].totalActions} actions`);
        console.log(`  ${file2}: ${comparison.summary[file2].totalStatements} statements, ${comparison.summary[file2].totalActions} actions`);
        console.log(`  Differences: ${comparison.differences.length}`);
        console.log(`  Similarities: ${comparison.similarities.length}`);
        console.log(`  Mergeability: ${comparison.mergeability.level}\n`);
        
        if (comparison.differences.length > 0) {
            console.log('🚨 Key Differences:');
            comparison.differences.slice(0, 10).forEach((diff, i) => {
                console.log(`  ${i + 1}. [${diff.impact || diff.type}] ${diff.category}`);
                console.log(`     ${diff.description}\n`);
            });
            
            if (comparison.differences.length > 10) {
                console.log(`     ... and ${comparison.differences.length - 10} more differences\n`);
            }
        }
        
        if (comparison.recommendations.length > 0) {
            console.log('💡 Recommendations:');
            comparison.recommendations.forEach((rec, i) => {
                console.log(`  ${i + 1}. [${rec.priority}] ${rec.type}`);
                console.log(`     ${rec.description}`);
                console.log(`     Action: ${rec.action}\n`);
            });
        }
        
        console.log(`🔄 Merge Assessment: ${comparison.mergeability.level}`);
        console.log(`   ${comparison.mergeability.recommendation}`);
        
        const reportFile = 'policy-comparison-report.json';
        const report = comparator.generateDiffReport(policy1, policy2, {
            labels: { policy1: file1, policy2: file2 },
            outputFile: reportFile
        });
        
        console.log(`\n📄 Detailed report saved to: ${reportFile}`);
        
    } catch (error) {
        console.error('Error comparing policies:', error.message);
    }
}