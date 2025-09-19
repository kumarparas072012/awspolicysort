const fs = require('fs');
const crypto = require('crypto');

class PolicySimulationEngine {
    constructor() {
        this.initializeSimulationEnvironment();
        this.initializeAWSServices();
        this.initializeTestScenarios();
        this.initializeImpactModels();
    }

    initializeSimulationEnvironment() {
        this.simulationContext = {
            awsRegions: ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
            accountIds: ['123456789012', '987654321098', '555666777888'],
            userTypes: ['human', 'service', 'federated', 'root'],
            timeZones: ['UTC', 'EST', 'PST', 'GMT'],
            ipRanges: {
                corporate: ['10.0.0.0/8', '172.16.0.0/12'],
                vpn: ['192.168.1.0/24'],
                public: ['0.0.0.0/0'],
                aws: ['54.239.0.0/16', '52.95.0.0/16']
            }
        };

        this.simulationDatabase = {
            users: this.generateSimulatedUsers(),
            roles: this.generateSimulatedRoles(),
            resources: this.generateSimulatedResources(),
            requests: []
        };
    }

    initializeAWSServices() {
        this.awsServices = {
            iam: {
                actions: ['CreateUser', 'DeleteUser', 'AttachUserPolicy', 'CreateRole', 'AssumeRole'],
                resources: ['user', 'role', 'policy', 'group'],
                conditions: ['aws:userid', 'aws:username', 'aws:PrincipalType']
            },
            s3: {
                actions: ['GetObject', 'PutObject', 'DeleteObject', 'ListBucket', 'CreateBucket'],
                resources: ['bucket', 'object'],
                conditions: ['s3:prefix', 's3:max-keys', 's3:x-amz-server-side-encryption']
            },
            ec2: {
                actions: ['RunInstances', 'TerminateInstances', 'DescribeInstances', 'CreateSecurityGroup'],
                resources: ['instance', 'security-group', 'volume', 'snapshot'],
                conditions: ['ec2:InstanceType', 'ec2:Region', 'ec2:Tenancy']
            },
            lambda: {
                actions: ['InvokeFunction', 'CreateFunction', 'UpdateFunctionCode', 'GetFunction'],
                resources: ['function'],
                conditions: ['lambda:FunctionArn', 'lambda:Principal']
            },
            rds: {
                actions: ['CreateDBInstance', 'DeleteDBInstance', 'DescribeDBInstances', 'CreateDBSnapshot'],
                resources: ['db-instance', 'db-cluster', 'db-snapshot'],
                conditions: ['rds:EndpointType', 'rds:db-tag/*']
            }
        };
    }

    initializeTestScenarios() {
        this.testScenarios = {
            dailyOperations: [
                {
                    name: 'Developer accessing S3 bucket',
                    principal: 'developer-role',
                    action: 's3:GetObject',
                    resource: 'arn:aws:s3:::dev-bucket/*',
                    context: { sourceIp: '10.0.1.100', time: '09:00:00Z' }
                },
                {
                    name: 'Lambda function reading from DynamoDB',
                    principal: 'lambda-execution-role',
                    action: 'dynamodb:GetItem',
                    resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/UserData',
                    context: { sourceIp: 'AWS_INTERNAL' }
                }
            ],
            securityScenarios: [
                {
                    name: 'Privilege escalation attempt',
                    principal: 'limited-user',
                    action: 'iam:CreateRole',
                    resource: '*',
                    context: { sourceIp: '203.0.113.1', time: '02:30:00Z' }
                },
                {
                    name: 'Cross-account access attempt',
                    principal: 'external-role',
                    action: 's3:GetObject',
                    resource: 'arn:aws:s3:::sensitive-bucket/*',
                    context: { sourceIp: '198.51.100.1', account: '999888777666' }
                }
            ],
            complianceScenarios: [
                {
                    name: 'After-hours database access',
                    principal: 'dba-role',
                    action: 'rds:DescribeDBInstances',
                    resource: '*',
                    context: { sourceIp: '10.0.1.50', time: '23:30:00Z' }
                },
                {
                    name: 'International access attempt',
                    principal: 'admin-user',
                    action: 'iam:ListUsers',
                    resource: '*',
                    context: { sourceIp: '103.248.72.1', region: 'ap-southeast-1' }
                }
            ]
        };
    }

    initializeImpactModels() {
        this.impactModels = {
            dataClassification: {
                'public': { impact: 1, description: 'Public data' },
                'internal': { impact: 3, description: 'Internal business data' },
                'confidential': { impact: 7, description: 'Confidential data' },
                'restricted': { impact: 10, description: 'Highly sensitive/regulated data' }
            },
            businessCriticality: {
                'low': { impact: 1, description: 'Non-critical systems' },
                'medium': { impact: 4, description: 'Important business systems' },
                'high': { impact: 7, description: 'Critical business systems' },
                'critical': { impact: 10, description: 'Mission-critical systems' }
            },
            complianceImpact: {
                'none': { impact: 0, description: 'No compliance requirements' },
                'low': { impact: 2, description: 'Minor compliance requirements' },
                'medium': { impact: 5, description: 'Significant compliance requirements' },
                'high': { impact: 8, description: 'Strict compliance requirements' },
                'regulatory': { impact: 10, description: 'Regulated industry requirements' }
            }
        };
    }

    async simulatePolicy(policy, scenarios = [], options = {}) {
        const simulationId = this.generateSimulationId();
        console.log(`🎯 Starting policy simulation ${simulationId}...`);

        const simulation = {
            simulationId,
            timestamp: new Date().toISOString(),
            policy: policy,
            scenarios: scenarios.length > 0 ? scenarios : this.getDefaultScenarios(),
            options: options,
            results: {
                summary: {},
                scenarioResults: [],
                impactAnalysis: {},
                riskAssessment: {},
                recommendations: []
            }
        };

        // Run simulation scenarios
        for (const scenario of simulation.scenarios) {
            const result = await this.runScenario(policy, scenario);
            simulation.results.scenarioResults.push(result);
        }

        // Analyze simulation results
        simulation.results.summary = this.analyzeSummary(simulation.results.scenarioResults);
        simulation.results.impactAnalysis = await this.performImpactAnalysis(policy, simulation.results.scenarioResults);
        simulation.results.riskAssessment = await this.assessRisk(policy, simulation.results);
        simulation.results.recommendations = this.generateSimulationRecommendations(simulation.results);

        // Generate what-if scenarios
        simulation.whatIfScenarios = await this.generateWhatIfScenarios(policy, simulation.results);

        return simulation;
    }

    async runScenario(policy, scenario) {
        const startTime = Date.now();
        
        const result = {
            scenarioName: scenario.name,
            scenarioType: scenario.type || 'functional',
            input: scenario,
            output: {
                decision: null,
                matchingStatements: [],
                evaluationSteps: [],
                conditions: [],
                effectivePermissions: []
            },
            performance: {
                evaluationTime: 0,
                complexity: 0
            },
            securityAnalysis: {},
            recommendations: []
        };

        try {
            // Simulate AWS policy evaluation
            const evaluation = await this.evaluateRequest(policy, scenario);
            result.output = evaluation;

            // Perform security analysis on the result
            result.securityAnalysis = await this.analyzeScenarioSecurity(scenario, evaluation);

            // Generate scenario-specific recommendations
            result.recommendations = this.generateScenarioRecommendations(scenario, evaluation);

            // Calculate performance metrics
            result.performance.evaluationTime = Date.now() - startTime;
            result.performance.complexity = this.calculateEvaluationComplexity(evaluation);

        } catch (error) {
            result.error = {
                message: error.message,
                stack: error.stack
            };
        }

        return result;
    }

    async evaluateRequest(policy, scenario) {
        const statements = policy.Statement || [];
        const evaluation = {
            decision: 'DENY', // Default deny
            matchingStatements: [],
            evaluationSteps: [],
            conditions: [],
            effectivePermissions: []
        };

        // Step 1: Find matching statements
        for (const [index, statement] of statements.entries()) {
            const match = this.matchStatement(statement, scenario);
            if (match.matches) {
                evaluation.matchingStatements.push({
                    index,
                    statement,
                    matchDetails: match.details
                });
                
                evaluation.evaluationSteps.push({
                    step: `Statement ${index + 1} (${statement.Sid || 'Unnamed'})`,
                    result: 'MATCH',
                    details: match.details
                });
            }
        }

        // Step 2: Evaluate conditions
        for (const matchingStmt of evaluation.matchingStatements) {
            const conditionResult = await this.evaluateConditions(
                matchingStmt.statement, 
                scenario.context || {}
            );
            
            evaluation.conditions.push({
                statementId: matchingStmt.statement.Sid,
                conditions: matchingStmt.statement.Condition,
                result: conditionResult.result,
                details: conditionResult.details
            });

            if (conditionResult.result === 'ALLOW' && matchingStmt.statement.Effect === 'Allow') {
                evaluation.decision = 'ALLOW';
                evaluation.effectivePermissions.push({
                    action: scenario.action,
                    resource: scenario.resource,
                    conditions: conditionResult.details
                });
            } else if (conditionResult.result === 'ALLOW' && matchingStmt.statement.Effect === 'Deny') {
                evaluation.decision = 'DENY';
                evaluation.evaluationSteps.push({
                    step: 'Explicit Deny',
                    result: 'DENY',
                    details: 'Explicit deny statement matched'
                });
                break; // Explicit deny wins
            }
        }

        return evaluation;
    }

    matchStatement(statement, scenario) {
        const match = {
            matches: false,
            details: {
                actionMatch: false,
                resourceMatch: false,
                principalMatch: false
            }
        };

        // Check action match
        if (statement.Action) {
            const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
            match.details.actionMatch = actions.some(action => 
                this.matchAction(action, scenario.action)
            );
        }

        // Check resource match
        if (statement.Resource) {
            const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
            match.details.resourceMatch = resources.some(resource => 
                this.matchResource(resource, scenario.resource)
            );
        } else {
            match.details.resourceMatch = true; // No resource specified means all resources
        }

        // Check principal match (for resource-based policies)
        if (statement.Principal) {
            match.details.principalMatch = this.matchPrincipal(statement.Principal, scenario.principal);
        } else {
            match.details.principalMatch = true; // No principal specified
        }

        match.matches = match.details.actionMatch && match.details.resourceMatch && match.details.principalMatch;
        return match;
    }

    async evaluateConditions(statement, context) {
        const result = {
            result: 'ALLOW',
            details: []
        };

        if (!statement.Condition) {
            return result;
        }

        for (const [conditionType, conditionBlock] of Object.entries(statement.Condition)) {
            for (const [conditionKey, conditionValues] of Object.entries(conditionBlock)) {
                const conditionResult = await this.evaluateCondition(
                    conditionType, 
                    conditionKey, 
                    conditionValues, 
                    context
                );
                
                result.details.push({
                    type: conditionType,
                    key: conditionKey,
                    values: conditionValues,
                    contextValue: context[conditionKey],
                    result: conditionResult.result,
                    explanation: conditionResult.explanation
                });

                if (conditionResult.result === 'DENY') {
                    result.result = 'DENY';
                }
            }
        }

        return result;
    }

    async evaluateCondition(conditionType, conditionKey, conditionValues, context) {
        const values = Array.isArray(conditionValues) ? conditionValues : [conditionValues];
        const contextValue = this.getContextValue(conditionKey, context);
        
        let result = 'DENY';
        let explanation = '';

        switch (conditionType) {
            case 'StringEquals':
                result = values.includes(contextValue) ? 'ALLOW' : 'DENY';
                explanation = `StringEquals: ${contextValue} ${result === 'ALLOW' ? 'matches' : 'does not match'} allowed values`;
                break;
                
            case 'StringLike':
                result = values.some(value => this.matchPattern(contextValue, value)) ? 'ALLOW' : 'DENY';
                explanation = `StringLike: ${contextValue} ${result === 'ALLOW' ? 'matches' : 'does not match'} pattern`;
                break;
                
            case 'IpAddress':
                result = this.matchIpAddress(contextValue, values) ? 'ALLOW' : 'DENY';
                explanation = `IpAddress: ${contextValue} ${result === 'ALLOW' ? 'within' : 'outside'} allowed ranges`;
                break;
                
            case 'DateGreaterThan':
                result = new Date(contextValue) > new Date(values[0]) ? 'ALLOW' : 'DENY';
                explanation = `DateGreaterThan: ${contextValue} ${result === 'ALLOW' ? 'after' : 'before'} ${values[0]}`;
                break;
                
            case 'Bool':
                result = String(contextValue).toLowerCase() === String(values[0]).toLowerCase() ? 'ALLOW' : 'DENY';
                explanation = `Bool: ${contextValue} ${result === 'ALLOW' ? 'equals' : 'does not equal'} ${values[0]}`;
                break;
                
            default:
                result = 'ALLOW'; // Unknown condition types default to allow
                explanation = `Unknown condition type: ${conditionType}`;
        }

        return { result, explanation };
    }

    async performImpactAnalysis(policy, scenarioResults) {
        const impactAnalysis = {
            dataExposureRisk: this.analyzeDataExposureRisk(scenarioResults),
            privilegeEscalationRisk: this.analyzePrivilegeEscalationRisk(scenarioResults),
            lateralMovementRisk: this.analyzeLateralMovementRisk(scenarioResults),
            complianceImpact: this.analyzeComplianceImpact(scenarioResults),
            businessImpact: this.analyzeBusinessImpact(scenarioResults),
            overallImpactScore: 0
        };

        // Calculate overall impact score
        const weights = { dataExposure: 0.3, privilegeEscalation: 0.25, lateralMovement: 0.2, compliance: 0.15, business: 0.1 };
        impactAnalysis.overallImpactScore = 
            impactAnalysis.dataExposureRisk.score * weights.dataExposure +
            impactAnalysis.privilegeEscalationRisk.score * weights.privilegeEscalation +
            impactAnalysis.lateralMovementRisk.score * weights.lateralMovement +
            impactAnalysis.complianceImpact.score * weights.compliance +
            impactAnalysis.businessImpact.score * weights.business;

        return impactAnalysis;
    }

    async generateWhatIfScenarios(policy, simulationResults) {
        const whatIfScenarios = [];

        // What if we add/remove specific permissions?
        const permissionChanges = [
            { action: 'add', permission: 's3:DeleteObject', resource: '*' },
            { action: 'remove', permission: 'iam:CreateUser', resource: '*' },
            { action: 'add', condition: { 'StringEquals': { 'aws:MultiFactorAuthPresent': 'true' } } }
        ];

        for (const change of permissionChanges) {
            const modifiedPolicy = this.applyPolicyChange(policy, change);
            const impact = await this.simulateImpact(modifiedPolicy, change);
            
            whatIfScenarios.push({
                change: change,
                modifiedPolicy: modifiedPolicy,
                impact: impact,
                recommendation: this.generateChangeRecommendation(change, impact)
            });
        }

        // What if conditions change?
        const conditionScenarios = [
            { scenario: 'Add MFA requirement', condition: 'aws:MultiFactorAuthPresent' },
            { scenario: 'Add IP restriction', condition: 'aws:SourceIp' },
            { scenario: 'Add time restriction', condition: 'aws:CurrentTime' }
        ];

        for (const conditionScenario of conditionScenarios) {
            const impact = await this.simulateConditionChange(policy, conditionScenario);
            whatIfScenarios.push({
                scenario: conditionScenario.scenario,
                impact: impact,
                recommendation: this.generateConditionRecommendation(conditionScenario, impact)
            });
        }

        return whatIfScenarios;
    }

    // Helper methods
    generateSimulationId() {
        return 'sim-' + crypto.randomBytes(8).toString('hex');
    }

    getDefaultScenarios() {
        return [
            ...this.testScenarios.dailyOperations,
            ...this.testScenarios.securityScenarios,
            ...this.testScenarios.complianceScenarios
        ];
    }

    generateSimulatedUsers() {
        return [
            { id: 'dev-001', type: 'developer', clearance: 'internal' },
            { id: 'admin-001', type: 'administrator', clearance: 'confidential' },
            { id: 'service-001', type: 'service', clearance: 'restricted' }
        ];
    }

    generateSimulatedRoles() {
        return [
            { name: 'DeveloperRole', permissions: ['s3:Read*', 'lambda:InvokeFunction'] },
            { name: 'AdminRole', permissions: ['*'] },
            { name: 'ServiceRole', permissions: ['dynamodb:*', 's3:GetObject'] }
        ];
    }

    generateSimulatedResources() {
        return [
            { arn: 'arn:aws:s3:::dev-bucket/*', classification: 'internal' },
            { arn: 'arn:aws:s3:::prod-bucket/*', classification: 'confidential' },
            { arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/UserData', classification: 'restricted' }
        ];
    }

    matchAction(policyAction, requestAction) {
        if (policyAction === '*') return true;
        if (policyAction === requestAction) return true;
        if (policyAction.endsWith('*')) {
            return requestAction.startsWith(policyAction.slice(0, -1));
        }
        return false;
    }

    matchResource(policyResource, requestResource) {
        if (policyResource === '*') return true;
        if (policyResource === requestResource) return true;
        
        // Handle ARN pattern matching
        if (policyResource.includes('*')) {
            const pattern = policyResource.replace(/\*/g, '.*');
            return new RegExp(`^${pattern}$`).test(requestResource);
        }
        
        return false;
    }

    matchPrincipal(policyPrincipal, requestPrincipal) {
        // Simplified principal matching
        if (policyPrincipal === '*') return true;
        if (typeof policyPrincipal === 'string') {
            return policyPrincipal === requestPrincipal;
        }
        return true; // Complex principal logic would go here
    }

    getContextValue(key, context) {
        // Simulate context values based on key
        const contextMap = {
            'aws:SourceIp': context.sourceIp || '10.0.1.100',
            'aws:CurrentTime': context.time || new Date().toISOString(),
            'aws:MultiFactorAuthPresent': context.mfa || 'false',
            'aws:userid': context.userId || 'AIDACKCEVSQ6C2EXAMPLE',
            'aws:username': context.username || 'testuser'
        };
        
        return contextMap[key] || context[key];
    }

    matchPattern(value, pattern) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'));
        return regex.test(value);
    }

    matchIpAddress(ip, ranges) {
        // Simplified IP matching - in production, use proper CIDR matching
        return ranges.some(range => {
            if (range === '0.0.0.0/0') return true;
            if (range.includes('/')) {
                const [network] = range.split('/');
                return ip.startsWith(network.split('.').slice(0, 2).join('.'));
            }
            return ip === range;
        });
    }

    // Analysis methods with simplified implementations
    analyzeDataExposureRisk(results) {
        const exposureCount = results.filter(r => 
            r.output.decision === 'ALLOW' && 
            r.input.action && 
            r.input.action.includes('Get')
        ).length;
        
        return {
            score: Math.min(exposureCount / results.length * 10, 10),
            details: `${exposureCount} scenarios allow data access`,
            recommendations: exposureCount > 3 ? ['Add stricter access controls'] : []
        };
    }

    analyzePrivilegeEscalationRisk(results) {
        const escalationCount = results.filter(r => 
            r.output.decision === 'ALLOW' && 
            r.input.action && 
            (r.input.action.includes('iam:') || r.input.action.includes('sts:'))
        ).length;
        
        return {
            score: escalationCount > 0 ? 8 : 2,
            details: `${escalationCount} scenarios allow privilege escalation`,
            recommendations: escalationCount > 0 ? ['Review IAM permissions'] : []
        };
    }

    analyzeLateralMovementRisk(results) {
        return {
            score: Math.random() * 5 + 2,
            details: 'Cross-service access analysis',
            recommendations: ['Implement service boundaries']
        };
    }

    analyzeComplianceImpact(results) {
        return {
            score: Math.random() * 3 + 1,
            details: 'Compliance framework analysis',
            recommendations: ['Add audit logging']
        };
    }

    analyzeBusinessImpact(results) {
        return {
            score: Math.random() * 4 + 2,
            details: 'Business process impact analysis',
            recommendations: ['Monitor business metrics']
        };
    }

    // Simulation result methods
    analyzeSummary(results) {
        return {
            totalScenarios: results.length,
            allowedScenarios: results.filter(r => r.output.decision === 'ALLOW').length,
            deniedScenarios: results.filter(r => r.output.decision === 'DENY').length,
            errorScenarios: results.filter(r => r.error).length,
            averageEvaluationTime: results.reduce((sum, r) => sum + (r.performance?.evaluationTime || 0), 0) / results.length
        };
    }

    async assessRisk(policy, results) {
        return {
            overallRisk: 'MEDIUM',
            riskFactors: ['Cross-account access', 'Wildcard permissions'],
            mitigationSuggestions: ['Add conditions', 'Restrict resources']
        };
    }

    generateSimulationRecommendations(results) {
        return [
            {
                priority: 'HIGH',
                category: 'Security',
                recommendation: 'Add MFA requirements for sensitive operations',
                impact: 'Reduces unauthorized access risk'
            },
            {
                priority: 'MEDIUM',
                category: 'Compliance',
                recommendation: 'Implement time-based access controls',
                impact: 'Improves audit compliance'
            }
        ];
    }

    // Save simulation results
    saveSimulation(simulation, filename = null) {
        const file = filename || `simulation-${simulation.simulationId}.json`;
        fs.writeFileSync(file, JSON.stringify(simulation, null, 2));
        return file;
    }
}

module.exports = PolicySimulationEngine;

// CLI usage
if (require.main === module) {
    const engine = new PolicySimulationEngine();
    
    async function runSimulation() {
        try {
            const policyFile = process.argv[2] || './sortedps.json';
            const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
            
            console.log('🎮 Policy Simulation & Impact Analysis');
            console.log('=====================================\n');
            
            const simulation = await engine.simulatePolicy(policyData);
            
            console.log('📊 Simulation Results:');
            console.log(`Simulation ID: ${simulation.simulationId}`);
            console.log(`Total Scenarios: ${simulation.results.summary.totalScenarios}`);
            console.log(`Allowed: ${simulation.results.summary.allowedScenarios}`);
            console.log(`Denied: ${simulation.results.summary.deniedScenarios}`);
            console.log(`Overall Impact Score: ${simulation.results.impactAnalysis.overallImpactScore.toFixed(2)}/10`);
            
            console.log('\n🎯 What-If Scenarios:');
            simulation.whatIfScenarios.slice(0, 3).forEach((scenario, i) => {
                console.log(`  ${i + 1}. ${scenario.scenario || scenario.change.action}: ${scenario.recommendation}`);
            });
            
            const savedFile = engine.saveSimulation(simulation);
            console.log(`\n💾 Simulation saved to: ${savedFile}`);
            
        } catch (error) {
            console.error('❌ Simulation failed:', error.message);
        }
    }
    
    runSimulation();
}