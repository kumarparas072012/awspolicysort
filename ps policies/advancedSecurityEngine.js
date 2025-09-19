const fs = require('fs');
const crypto = require('crypto');

class AdvancedSecurityEngine {
    constructor() {
        this.initializeKnowledgeBase();
        this.initializeThreatIntelligence();
        this.initializeMLModels();
        this.initializeComplianceFrameworks();
    }

    initializeKnowledgeBase() {
        // Advanced threat patterns and attack vectors
        this.attackVectors = {
            privilegeEscalation: {
                patterns: [
                    'iam:PassRole + lambda:InvokeFunction',
                    'iam:CreateRole + iam:AttachRolePolicy',
                    'sts:AssumeRole + iam:*',
                    'iam:SetDefaultPolicyVersion + iam:CreatePolicyVersion',
                    'ec2:RunInstances + iam:PassRole',
                    'cloudformation:CreateStack + iam:PassRole'
                ],
                severity: 'CRITICAL',
                description: 'Potential privilege escalation attack paths'
            },
            dataExfiltration: {
                patterns: [
                    's3:GetObject + s3:ListBucket',
                    'dynamodb:Scan + dynamodb:Query',
                    'rds:DescribeDBSnapshots + rds:CreateDBSnapshot',
                    'ec2:CreateSnapshot + ec2:DescribeSnapshots',
                    'lambda:GetFunction + lambda:InvokeFunction'
                ],
                severity: 'HIGH',
                description: 'Potential data exfiltration vectors'
            },
            persistenceEstablishment: {
                patterns: [
                    'iam:CreateUser + iam:CreateAccessKey',
                    'iam:CreateRole + iam:CreateInstanceProfile',
                    'lambda:CreateFunction + lambda:AddPermission',
                    'events:PutRule + lambda:AddPermission',
                    'ec2:CreateSecurityGroup + ec2:AuthorizeSecurityGroupIngress'
                ],
                severity: 'HIGH',
                description: 'Potential persistence establishment techniques'
            },
            lateralMovement: {
                patterns: [
                    'ec2:DescribeInstances + ssm:SendCommand',
                    'sts:AssumeRole + ec2:*',
                    'secretsmanager:GetSecretValue + rds:*',
                    'ssm:GetParameter + lambda:InvokeFunction'
                ],
                severity: 'MEDIUM',
                description: 'Potential lateral movement capabilities'
            }
        };

        // Advanced security controls database
        this.securityControls = {
            conditionKeys: {
                mfaRequired: ['aws:MultiFactorAuthPresent', 'aws:MultiFactorAuthAge'],
                ipRestriction: ['aws:SourceIp', 'aws:VpcSourceIp'],
                timeRestriction: ['aws:CurrentTime', 'aws:EpochTime'],
                secureTransport: ['aws:SecureTransport'],
                requestedRegion: ['aws:RequestedRegion'],
                principalTag: ['aws:PrincipalTag/*'],
                resourceTag: ['aws:ResourceTag/*'],
                sessionName: ['aws:userid', 'aws:username']
            },
            bestPractices: {
                leastPrivilege: 'Grant minimum permissions required',
                regularRotation: 'Rotate credentials regularly',
                conditionUsage: 'Use conditions to restrict access',
                resourceSpecificity: 'Specify exact resources when possible',
                timeBinding: 'Implement time-based restrictions',
                locationBinding: 'Implement location-based restrictions'
            }
        };

        // Service relationship mapping for advanced analysis
        this.serviceRelationships = {
            lambda: ['iam', 's3', 'dynamodb', 'rds', 'sns', 'sqs', 'cloudwatch'],
            ec2: ['iam', 's3', 'vpc', 'cloudwatch', 'ssm'],
            s3: ['cloudfront', 'lambda', 'glacier', 'athena'],
            iam: ['sts', 'organizations', 'sso'],
            rds: ['s3', 'cloudwatch', 'sns', 'lambda'],
            ecs: ['ec2', 'elb', 'cloudwatch', 'ecr']
        };
    }

    initializeThreatIntelligence() {
        // Real-world threat intelligence patterns
        this.threatIntelligence = {
            knownMaliciousPatterns: [
                {
                    pattern: /\*.*\*.*\*/,
                    type: 'wildcard_abuse',
                    description: 'Multiple wildcards indicating potential abuse',
                    mitreId: 'T1078.004'
                },
                {
                    pattern: /arn:aws:iam::\d{12}:role\/.*admin.*/i,
                    type: 'admin_role_assumption',
                    description: 'Assuming administrative roles',
                    mitreId: 'T1078.004'
                }
            ],
            suspiciousActions: [
                'iam:CreateUser',
                'iam:DeleteUser', 
                'iam:CreateAccessKey',
                'iam:DeleteAccessKey',
                'sts:GetSessionToken',
                'sts:AssumeRoleWithWebIdentity',
                'organizations:LeaveOrganization',
                'cloudtrail:StopLogging',
                'cloudtrail:DeleteTrail',
                'config:DeleteConfigurationRecorder',
                'guardduty:DeleteDetector'
            ],
            riskFactors: {
                crossAccountAccess: 3.0,
                wildcardPermissions: 2.5,
                adminPermissions: 3.5,
                noConditions: 1.5,
                publicAccess: 4.0,
                suspiciousActions: 2.8
            }
        };
    }

    initializeMLModels() {
        // Simulated ML models for advanced analysis
        this.mlModels = {
            anomalyDetection: {
                threshold: 0.75,
                features: ['action_count', 'resource_specificity', 'condition_complexity', 'cross_service_permissions']
            },
            riskScoring: {
                weights: {
                    actions: 0.3,
                    resources: 0.25,
                    conditions: 0.2,
                    principals: 0.15,
                    context: 0.1
                }
            },
            patternRecognition: {
                knownGoodPatterns: ['readonly_access', 'service_specific', 'time_bound'],
                knownBadPatterns: ['admin_access', 'wildcard_heavy', 'cross_account_unrestricted']
            }
        };
    }

    initializeComplianceFrameworks() {
        this.complianceFrameworks = {
            SOC2: {
                controls: {
                    CC6_1: 'Logical and physical access controls',
                    CC6_2: 'Authentication and authorization',
                    CC6_3: 'System access authorization'
                },
                requirements: [
                    'principle_of_least_privilege',
                    'access_review_procedures',
                    'authorization_controls'
                ]
            },
            PCI_DSS: {
                controls: {
                    '7.1': 'Limit access to computing resources and cardholder data',
                    '7.2': 'Establish an access control system',
                    '8.1': 'Define and implement policies for proper user identification'
                }
            },
            HIPAA: {
                controls: {
                    '164.312_a_1': 'Access control (Assigned security responsibility)',
                    '164.312_a_2_i': 'Unique user identification',
                    '164.312_a_2_ii': 'Automatic logoff'
                }
            },
            NIST_800_53: {
                controls: {
                    'AC-2': 'Account Management',
                    'AC-3': 'Access Enforcement', 
                    'AC-6': 'Least Privilege'
                }
            },
            CIS_Controls: {
                version: '8.0',
                controls: {
                    'CIS_5': 'Account Management',
                    'CIS_6': 'Access Control Management',
                    'CIS_14': 'Security Awareness and Skills Training'
                }
            }
        };
    }

    async performAdvancedAnalysis(policy, options = {}) {
        const analysis = {
            timestamp: new Date().toISOString(),
            analysisId: this.generateAnalysisId(),
            policy: policy,
            advancedFindings: {
                attackVectorAnalysis: await this.analyzeAttackVectors(policy),
                threatIntelligenceMatch: await this.matchThreatIntelligence(policy),
                behavioralAnalysis: await this.performBehavioralAnalysis(policy),
                mlAnomalyDetection: await this.detectAnomalies(policy),
                complianceMapping: await this.mapToComplianceFrameworks(policy),
                riskChaining: await this.analyzeRiskChains(policy),
                contextualAnalysis: await this.performContextualAnalysis(policy),
                predictiveAssessment: await this.performPredictiveAssessment(policy)
            },
            recommendations: {
                immediate: [],
                shortTerm: [],
                longTerm: [],
                strategic: []
            },
            riskProfile: this.generateRiskProfile(policy),
            securityPosture: this.assessSecurityPosture(policy)
        };

        return analysis;
    }

    async analyzeAttackVectors(policy) {
        const findings = [];
        const statements = policy.Statement || [];

        for (const [vectorType, vectorData] of Object.entries(this.attackVectors)) {
            const detectedPaths = [];
            
            for (const pattern of vectorData.patterns) {
                const [action1, action2] = pattern.split(' + ');
                
                const hasAction1 = this.hasActionInPolicy(statements, action1);
                const hasAction2 = this.hasActionInPolicy(statements, action2);
                
                if (hasAction1 && hasAction2) {
                    detectedPaths.push({
                        pattern: pattern,
                        risk: vectorData.severity,
                        description: `Detected potential ${vectorType} via: ${pattern}`,
                        statements: this.findStatementsWithActions(statements, [action1, action2]),
                        mitigations: this.generateMitigations(vectorType, pattern)
                    });
                }
            }
            
            if (detectedPaths.length > 0) {
                findings.push({
                    vectorType: vectorType,
                    severity: vectorData.severity,
                    description: vectorData.description,
                    detectedPaths: detectedPaths,
                    impactScore: this.calculateAttackVectorImpact(detectedPaths),
                    recommendations: this.generateAttackVectorRecommendations(vectorType)
                });
            }
        }

        return {
            summary: {
                totalVectors: findings.length,
                criticalVectors: findings.filter(f => f.severity === 'CRITICAL').length,
                highRiskVectors: findings.filter(f => f.severity === 'HIGH').length
            },
            findings: findings,
            overallRisk: this.calculateOverallAttackRisk(findings)
        };
    }

    async matchThreatIntelligence(policy) {
        const matches = [];
        const statements = policy.Statement || [];

        // Check against known malicious patterns
        for (const threat of this.threatIntelligence.knownMaliciousPatterns) {
            const policyString = JSON.stringify(policy);
            if (threat.pattern.test(policyString)) {
                matches.push({
                    type: 'pattern_match',
                    threatType: threat.type,
                    description: threat.description,
                    mitreId: threat.mitreId,
                    severity: 'HIGH',
                    evidence: this.extractPatternEvidence(policyString, threat.pattern)
                });
            }
        }

        // Check for suspicious actions
        const suspiciousActionsFound = [];
        statements.forEach((stmt, index) => {
            if (stmt.Action) {
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                actions.forEach(action => {
                    if (this.threatIntelligence.suspiciousActions.includes(action)) {
                        suspiciousActionsFound.push({
                            action: action,
                            statementIndex: index,
                            statementId: stmt.Sid || `Statement-${index + 1}`,
                            riskLevel: this.assessActionRisk(action)
                        });
                    }
                });
            }
        });

        if (suspiciousActionsFound.length > 0) {
            matches.push({
                type: 'suspicious_actions',
                description: 'Policy contains actions commonly used in attacks',
                severity: 'MEDIUM',
                actions: suspiciousActionsFound,
                recommendations: this.generateSuspiciousActionRecommendations(suspiciousActionsFound)
            });
        }

        return {
            summary: {
                totalMatches: matches.length,
                highSeverityMatches: matches.filter(m => m.severity === 'HIGH').length,
                criticalMatches: matches.filter(m => m.severity === 'CRITICAL').length
            },
            matches: matches,
            threatScore: this.calculateThreatScore(matches)
        };
    }

    async performBehavioralAnalysis(policy) {
        const statements = policy.Statement || [];
        
        const behaviorProfile = {
            accessPatterns: this.analyzeAccessPatterns(statements),
            serviceUsage: this.analyzeServiceUsage(statements),
            conditionUsage: this.analyzeConditionUsage(statements),
            resourceSpecificity: this.analyzeResourceSpecificity(statements),
            timeContext: this.analyzeTimeContext(statements),
            geoContext: this.analyzeGeoContext(statements)
        };

        const anomalies = this.detectBehavioralAnomalies(behaviorProfile);
        const riskFactors = this.identifyRiskFactors(behaviorProfile);

        return {
            behaviorProfile: behaviorProfile,
            anomalies: anomalies,
            riskFactors: riskFactors,
            behaviorScore: this.calculateBehaviorScore(behaviorProfile),
            recommendations: this.generateBehavioralRecommendations(behaviorProfile, anomalies)
        };
    }

    async detectAnomalies(policy) {
        const features = this.extractMLFeatures(policy);
        const anomalyScore = this.calculateAnomalyScore(features);
        
        const anomalies = [];
        
        // Statistical anomaly detection
        if (features.action_count > this.calculateStatisticalThreshold('action_count')) {
            anomalies.push({
                type: 'statistical_anomaly',
                feature: 'action_count',
                value: features.action_count,
                threshold: this.calculateStatisticalThreshold('action_count'),
                severity: 'MEDIUM',
                description: 'Unusually high number of actions in policy'
            });
        }

        // Pattern-based anomaly detection
        const patternAnomalies = this.detectPatternAnomalies(policy);
        anomalies.push(...patternAnomalies);

        // Context-based anomaly detection
        const contextAnomalies = this.detectContextAnomalies(policy);
        anomalies.push(...contextAnomalies);

        return {
            summary: {
                anomalyScore: anomalyScore,
                totalAnomalies: anomalies.length,
                highSeverityAnomalies: anomalies.filter(a => a.severity === 'HIGH').length
            },
            anomalies: anomalies,
            mlInsights: this.generateMLInsights(features, anomalyScore),
            recommendations: this.generateAnomalyRecommendations(anomalies)
        };
    }

    async mapToComplianceFrameworks(policy) {
        const complianceResults = {};
        
        for (const [framework, frameworkData] of Object.entries(this.complianceFrameworks)) {
            const assessment = await this.assessFrameworkCompliance(policy, framework, frameworkData);
            complianceResults[framework] = assessment;
        }

        const overallCompliance = this.calculateOverallCompliance(complianceResults);
        const gaps = this.identifyComplianceGaps(complianceResults);
        const recommendations = this.generateComplianceRecommendations(gaps);

        return {
            summary: {
                overallScore: overallCompliance.score,
                compliantFrameworks: overallCompliance.compliant,
                nonCompliantFrameworks: overallCompliance.nonCompliant,
                partiallyCompliantFrameworks: overallCompliance.partial
            },
            frameworkResults: complianceResults,
            gaps: gaps,
            recommendations: recommendations,
            nextSteps: this.generateComplianceNextSteps(gaps)
        };
    }

    async analyzeRiskChains(policy) {
        const statements = policy.Statement || [];
        const riskChains = [];
        
        // Identify potential attack chains
        const services = this.extractServicesFromStatements(statements);
        
        for (const service of services) {
            const relatedServices = this.serviceRelationships[service] || [];
            
            for (const relatedService of relatedServices) {
                if (services.includes(relatedService)) {
                    const chain = this.analyzeServiceChain(service, relatedService, statements);
                    if (chain.riskLevel > 0.6) {
                        riskChains.push(chain);
                    }
                }
            }
        }

        // Analyze permission escalation chains
        const escalationChains = this.analyzeEscalationChains(statements);
        
        // Analyze data flow chains
        const dataFlowChains = this.analyzeDataFlowChains(statements);

        return {
            summary: {
                totalChains: riskChains.length + escalationChains.length + dataFlowChains.length,
                highRiskChains: [...riskChains, ...escalationChains, ...dataFlowChains]
                    .filter(chain => chain.riskLevel > 0.8).length
            },
            serviceChains: riskChains,
            escalationChains: escalationChains,
            dataFlowChains: dataFlowChains,
            recommendations: this.generateRiskChainRecommendations([...riskChains, ...escalationChains, ...dataFlowChains])
        };
    }

    async performContextualAnalysis(policy) {
        return {
            organizationalContext: this.analyzeOrganizationalContext(policy),
            businessContext: this.analyzeBusinessContext(policy),
            technicalContext: this.analyzeTechnicalContext(policy),
            temporalContext: this.analyzeTemporalContext(policy),
            environmentalContext: this.analyzeEnvironmentalContext(policy)
        };
    }

    async performPredictiveAssessment(policy) {
        const currentRisk = this.calculateCurrentRisk(policy);
        const futureRisk = this.predictFutureRisk(policy);
        const riskTrends = this.analyzeTrends(policy);
        
        return {
            currentRisk: currentRisk,
            predictedRisk: futureRisk,
            riskTrends: riskTrends,
            recommendations: this.generatePredictiveRecommendations(currentRisk, futureRisk),
            scenarios: this.generateRiskScenarios(policy)
        };
    }

    // Helper methods for advanced analysis
    generateAnalysisId() {
        return crypto.randomBytes(16).toString('hex');
    }

    hasActionInPolicy(statements, actionPattern) {
        return statements.some(stmt => {
            if (!stmt.Action) return false;
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            return actions.some(action => {
                if (actionPattern.endsWith('*')) {
                    return action.startsWith(actionPattern.slice(0, -1));
                }
                return action === actionPattern || action === '*';
            });
        });
    }

    findStatementsWithActions(statements, actions) {
        return statements.filter(stmt => {
            if (!stmt.Action) return false;
            const stmtActions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            return actions.some(action => 
                stmtActions.some(stmtAction => 
                    stmtAction === action || stmtAction === '*' || 
                    (action.endsWith('*') && stmtAction.startsWith(action.slice(0, -1)))
                )
            );
        });
    }

    generateMitigations(vectorType, pattern) {
        const mitigations = {
            privilegeEscalation: [
                'Implement condition-based restrictions',
                'Use resource-specific ARNs',
                'Enable MFA requirements',
                'Implement time-based access controls'
            ],
            dataExfiltration: [
                'Add IP address restrictions',
                'Implement data classification controls',
                'Enable detailed logging and monitoring',
                'Use VPC endpoints for private access'
            ],
            persistenceEstablishment: [
                'Implement approval workflows',
                'Enable resource creation notifications',
                'Use temporary credentials where possible',
                'Implement resource tagging requirements'
            ],
            lateralMovement: [
                'Segment network access',
                'Implement cross-service restrictions',
                'Enable detailed API logging',
                'Use service-specific roles'
            ]
        };
        
        return mitigations[vectorType] || ['Implement additional security controls'];
    }

    calculateAttackVectorImpact(detectedPaths) {
        let totalImpact = 0;
        const severityWeights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
        
        detectedPaths.forEach(path => {
            totalImpact += severityWeights[path.risk] || 1;
        });
        
        return Math.min(totalImpact / detectedPaths.length, 10);
    }

    extractMLFeatures(policy) {
        const statements = policy.Statement || [];
        
        return {
            action_count: statements.reduce((count, stmt) => {
                if (stmt.Action) {
                    return count + (Array.isArray(stmt.Action) ? stmt.Action.length : 1);
                }
                return count;
            }, 0),
            resource_specificity: this.calculateResourceSpecificity(statements),
            condition_complexity: this.calculateConditionComplexity(statements),
            cross_service_permissions: this.calculateCrossServicePermissions(statements),
            statement_count: statements.length,
            wildcard_usage: this.calculateWildcardUsage(statements)
        };
    }

    calculateAnomalyScore(features) {
        // Simplified ML scoring algorithm
        const weights = this.mlModels.riskScoring.weights;
        let score = 0;
        
        // Normalize features and apply weights
        score += (features.action_count / 100) * weights.actions;
        score += (1 - features.resource_specificity) * weights.resources;
        score += features.condition_complexity * weights.conditions;
        score += features.cross_service_permissions * weights.context;
        
        return Math.min(score, 1.0);
    }

    generateRiskProfile(policy) {
        const statements = policy.Statement || [];
        
        return {
            riskLevel: this.calculateOverallRiskLevel(policy),
            riskFactors: this.identifyRiskFactors(policy),
            mitigationLevel: this.assessMitigationLevel(policy),
            exposureScore: this.calculateExposureScore(policy),
            confidenceLevel: this.calculateConfidenceLevel(policy)
        };
    }

    // Generate detailed reporting
    generateAdvancedReport(analysis, options = {}) {
        return {
            executiveSummary: this.generateExecutiveSummary(analysis),
            technicalFindings: this.generateTechnicalFindings(analysis),
            riskAssessment: this.generateRiskAssessment(analysis),
            complianceReport: this.generateComplianceReport(analysis),
            recommendations: this.generateDetailedRecommendations(analysis),
            actionPlan: this.generateActionPlan(analysis),
            appendices: this.generateAppendices(analysis)
        };
    }

    // Placeholder implementations for complex methods
    calculateResourceSpecificity(statements) { return Math.random() * 0.5 + 0.3; }
    calculateConditionComplexity(statements) { return Math.random() * 0.4 + 0.1; }
    calculateCrossServicePermissions(statements) { return Math.random() * 0.6 + 0.2; }
    calculateWildcardUsage(statements) { return Math.random() * 0.3; }
    calculateStatisticalThreshold(feature) { return 50; }
    detectPatternAnomalies(policy) { return []; }
    detectContextAnomalies(policy) { return []; }
    generateMLInsights(features, score) { return {}; }
    analyzeAccessPatterns(statements) { return {}; }
    analyzeServiceUsage(statements) { return {}; }
    analyzeConditionUsage(statements) { return {}; }
    detectBehavioralAnomalies(profile) { return []; }
    calculateBehaviorScore(profile) { return Math.random() * 0.5 + 0.3; }
    
    // Save analysis results
    saveAnalysis(analysis, filename = 'advanced-security-analysis.json') {
        fs.writeFileSync(filename, JSON.stringify(analysis, null, 2));
        return filename;
    }
}

module.exports = AdvancedSecurityEngine;

// CLI usage
if (require.main === module) {
    const engine = new AdvancedSecurityEngine();
    
    async function runAdvancedAnalysis() {
        try {
            const policyFile = process.argv[2] || './sortedps.json';
            const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
            
            console.log('🤖 Advanced AI-Powered Security Analysis');
            console.log('=========================================\n');
            
            console.log('🔄 Performing advanced analysis...');
            const analysis = await engine.performAdvancedAnalysis(policyData);
            
            console.log('📊 Analysis Results:');
            console.log(`Analysis ID: ${analysis.analysisId}`);
            console.log(`Attack Vectors Detected: ${analysis.advancedFindings.attackVectorAnalysis.summary.totalVectors}`);
            console.log(`Threat Intelligence Matches: ${analysis.advancedFindings.threatIntelligenceMatch.summary.totalMatches}`);
            console.log(`ML Anomalies: ${analysis.advancedFindings.mlAnomalyDetection.summary.totalAnomalies}`);
            console.log(`Overall Risk Level: ${analysis.riskProfile.riskLevel || 'CALCULATING...'}`);
            
            if (analysis.advancedFindings.attackVectorAnalysis.findings.length > 0) {
                console.log('\n🚨 Critical Attack Vectors:');
                analysis.advancedFindings.attackVectorAnalysis.findings
                    .filter(f => f.severity === 'CRITICAL')
                    .forEach(finding => {
                        console.log(`  ⚠️  ${finding.vectorType}: ${finding.description}`);
                    });
            }
            
            if (analysis.advancedFindings.threatIntelligenceMatch.matches.length > 0) {
                console.log('\n🕵️ Threat Intelligence Matches:');
                analysis.advancedFindings.threatIntelligenceMatch.matches.forEach(match => {
                    console.log(`  🎯 ${match.type}: ${match.description}`);
                });
            }
            
            const reportFile = engine.saveAnalysis(analysis);
            console.log(`\n📄 Advanced analysis saved to: ${reportFile}`);
            
        } catch (error) {
            console.error('❌ Advanced analysis failed:', error.message);
        }
    }
    
    runAdvancedAnalysis();
}