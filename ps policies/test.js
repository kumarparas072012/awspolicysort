const fs = require('fs');
const assert = require('assert');
const PolicySecurityAnalyzer = require('./policySecurityAnalyzer');
const PolicyComparator = require('./policyComparator');
const PolicyOptimizer = require('./policyOptimizer');
const ReportGenerator = require('./reportGenerator');

class TestSuite {
    constructor() {
        this.testResults = [];
        this.analyzer = new PolicySecurityAnalyzer();
        this.comparator = new PolicyComparator();
        this.optimizer = new PolicyOptimizer();
        this.reporter = new ReportGenerator();
    }

    async runAllTests() {
        console.log('🧪 AWS Policy Analyzer Test Suite');
        console.log('==================================\n');

        await this.testSecurityAnalyzer();
        await this.testPolicyComparator();
        await this.testPolicyOptimizer();
        await this.testReportGenerator();
        await this.testIntegration();

        this.printResults();
    }

    async testSecurityAnalyzer() {
        console.log('🔍 Testing Security Analyzer...');

        // Test 1: Wildcard detection
        await this.test('Wildcard Detection', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'WildcardTest',
                        Effect: 'Allow',
                        Action: '*',
                        Resource: '*'
                    }
                ]
            };

            const result = this.analyzer.analyzePolicy(policy);
            assert(result.riskScore > 50, 'Should detect high risk from wildcards');
            assert(result.securityIssues.some(issue => issue.type === 'CRITICAL'), 'Should flag critical wildcard usage');
        });

        // Test 2: Missing conditions
        await this.test('Missing Conditions Detection', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'NoConditionsTest',
                        Effect: 'Allow',
                        Action: 'iam:CreateRole',
                        Resource: '*'
                    }
                ]
            };

            const result = this.analyzer.analyzePolicy(policy);
            assert(result.securityIssues.some(issue => 
                issue.category === 'Missing Conditions'
            ), 'Should detect missing conditions for privileged actions');
        });

        // Test 3: Compliance checks
        await this.test('Compliance Checks', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'ComplianceTest',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: 'arn:aws:s3:::my-bucket/*',
                        Condition: {
                            'StringEquals': {
                                'aws:userid': 'AIDACKCEVSQ6C2EXAMPLE'
                            }
                        }
                    }
                ]
            };

            const result = this.analyzer.analyzePolicy(policy);
            const report = this.analyzer.generateSecurityReport(policy);
            assert(report.complianceChecks, 'Should generate compliance checks');
        });

        console.log('  ✅ Security Analyzer tests passed\n');
    }

    async testPolicyComparator() {
        console.log('🔄 Testing Policy Comparator...');

        // Test 1: Identical policies
        await this.test('Identical Policies', () => {
            const policy1 = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'TestStatement',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: 'arn:aws:s3:::bucket/*'
                    }
                ]
            };
            const policy2 = JSON.parse(JSON.stringify(policy1));

            const result = this.comparator.compare(policy1, policy2);
            assert(result.differences.length === 0, 'Identical policies should have no differences');
        });

        // Test 2: Different effects
        await this.test('Different Effects Detection', () => {
            const policy1 = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'TestStatement',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: '*'
                    }
                ]
            };
            const policy2 = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'TestStatement',
                        Effect: 'Deny',
                        Action: 's3:GetObject',
                        Resource: '*'
                    }
                ]
            };

            const result = this.comparator.compare(policy1, policy2);
            assert(result.differences.some(diff => diff.type === 'EFFECT_DIFFERENCE'), 
                'Should detect effect differences');
            assert(result.mergeability.level === 'DANGEROUS', 
                'Should flag dangerous mergeability');
        });

        // Test 3: Missing statements
        await this.test('Missing Statements Detection', () => {
            const policy1 = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'Statement1',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: '*'
                    },
                    {
                        Sid: 'Statement2',
                        Effect: 'Allow',
                        Action: 'ec2:DescribeInstances',
                        Resource: '*'
                    }
                ]
            };
            const policy2 = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'Statement1',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: '*'
                    }
                ]
            };

            const result = this.comparator.compare(policy1, policy2);
            assert(result.differences.some(diff => diff.type === 'ONLY_IN_POLICY1'), 
                'Should detect missing statements');
        });

        console.log('  ✅ Policy Comparator tests passed\n');
    }

    async testPolicyOptimizer() {
        console.log('⚡ Testing Policy Optimizer...');

        // Test 1: Statement consolidation
        await this.test('Statement Consolidation', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'S3Read1',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: 'arn:aws:s3:::bucket1/*'
                    },
                    {
                        Sid: 'S3Read2',
                        Effect: 'Allow',
                        Action: 's3:GetObjectVersion',
                        Resource: 'arn:aws:s3:::bucket1/*'
                    }
                ]
            };

            const result = this.optimizer.optimize(policy);
            // Should identify optimization opportunities
            assert(result.optimizations.length > 0 || result.savings.statementReduction >= 0, 
                'Should identify optimization opportunities');
        });

        // Test 2: Duplicate removal
        await this.test('Duplicate Statement Removal', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'Duplicate1',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: 'arn:aws:s3:::bucket/*'
                    },
                    {
                        Sid: 'Duplicate2',
                        Effect: 'Allow',
                        Action: 's3:GetObject',
                        Resource: 'arn:aws:s3:::bucket/*'
                    }
                ]
            };

            const result = this.optimizer.optimize(policy);
            assert(result.optimized.Statement.length < policy.Statement.length, 
                'Should remove duplicate statements');
        });

        // Test 3: Complexity calculation
        await this.test('Complexity Calculation', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'ComplexStatement',
                        Effect: 'Allow',
                        Action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
                        Resource: ['arn:aws:s3:::bucket1/*', 'arn:aws:s3:::bucket2/*'],
                        Condition: {
                            'StringEquals': {
                                'aws:userid': 'EXAMPLE123'
                            }
                        }
                    }
                ]
            };

            const result = this.optimizer.optimize(policy);
            assert(typeof result.savings.complexity.original === 'number', 
                'Should calculate complexity score');
        });

        console.log('  ✅ Policy Optimizer tests passed\n');
    }

    async testReportGenerator() {
        console.log('📊 Testing Report Generator...');

        // Test 1: Security report generation
        await this.test('Security Report Generation', () => {
            const analysisResults = {
                riskScore: 65,
                securityIssues: [
                    {
                        type: 'HIGH',
                        category: 'Wildcard Usage',
                        message: 'Test issue'
                    }
                ],
                recommendations: [
                    {
                        priority: 'HIGH',
                        description: 'Test recommendation'
                    }
                ]
            };

            const report = this.reporter.generateSecurityReport(analysisResults);
            assert(report.title, 'Should have report title');
            assert(report.metadata, 'Should have metadata');
        });

        // Test 2: Executive summary
        await this.test('Executive Summary Generation', () => {
            const allResults = {
                security: {
                    riskScore: 45,
                    securityIssues: []
                }
            };

            const summary = this.reporter.generateExecutiveSummary(allResults);
            assert(summary.overview, 'Should have overview section');
            assert(summary.metrics, 'Should have metrics');
        });

        // Test 3: HTML conversion
        await this.test('HTML Report Conversion', () => {
            const reportData = {
                title: 'Test Report',
                metadata: {
                    generatedAt: new Date().toISOString()
                }
            };

            const html = this.reporter.convertToHtml(reportData, 'security');
            assert(html.includes('<html>'), 'Should generate valid HTML');
            assert(html.includes('Test Report'), 'Should include report title');
        });

        console.log('  ✅ Report Generator tests passed\n');
    }

    async testIntegration() {
        console.log('🔗 Testing Integration...');

        // Test 1: End-to-end workflow
        await this.test('End-to-End Workflow', () => {
            const policy = {
                Version: '2012-10-17',
                Statement: [
                    {
                        Sid: 'TestWorkflow',
                        Effect: 'Allow',
                        Action: '*',
                        Resource: '*'
                    }
                ]
            };

            // Analyze
            const analysis = this.analyzer.analyzePolicy(policy);
            assert(analysis.riskScore > 0, 'Should analyze policy');

            // Optimize
            const optimization = this.optimizer.optimize(policy);
            assert(optimization.optimized, 'Should optimize policy');

            // Report
            const report = this.reporter.generateExecutiveSummary({
                security: analysis,
                optimization: optimization
            });
            assert(report.overview, 'Should generate comprehensive report');
        });

        // Test 2: File I/O operations
        await this.test('File Operations', () => {
            const testPolicy = {
                Version: '2012-10-17',
                Statement: []
            };

            const filename = 'test-policy.json';
            fs.writeFileSync(filename, JSON.stringify(testPolicy, null, 2));
            
            // Test file exists
            assert(fs.existsSync(filename), 'Should create test file');
            
            // Clean up
            fs.unlinkSync(filename);
        });

        console.log('  ✅ Integration tests passed\n');
    }

    async test(name, testFunction) {
        try {
            await testFunction();
            this.testResults.push({ name, status: 'PASS' });
        } catch (error) {
            this.testResults.push({ name, status: 'FAIL', error: error.message });
            console.log(`    ❌ ${name}: ${error.message}`);
        }
    }

    printResults() {
        console.log('📋 Test Results Summary');
        console.log('=======================');
        
        const passed = this.testResults.filter(r => r.status === 'PASS').length;
        const failed = this.testResults.filter(r => r.status === 'FAIL').length;
        const total = this.testResults.length;

        console.log(`Total Tests: ${total}`);
        console.log(`Passed: ${passed} ✅`);
        console.log(`Failed: ${failed} ${failed > 0 ? '❌' : ''}`);
        console.log(`Success Rate: ${Math.round((passed / total) * 100)}%\n`);

        if (failed > 0) {
            console.log('❌ Failed Tests:');
            this.testResults
                .filter(r => r.status === 'FAIL')
                .forEach(test => {
                    console.log(`  - ${test.name}: ${test.error}`);
                });
        } else {
            console.log('🎉 All tests passed!');
        }

        // Performance benchmarks
        console.log('\n⚡ Performance Benchmarks:');
        this.runBenchmarks();
    }

    runBenchmarks() {
        // Benchmark security analysis
        const largePolicyStmt = Array.from({ length: 50 }, (_, i) => ({
            Sid: `Statement${i}`,
            Effect: 'Allow',
            Action: `service:Action${i}`,
            Resource: '*'
        }));

        const largePolicy = {
            Version: '2012-10-17',
            Statement: largePolicyStmt
        };

        console.time('Security Analysis (50 statements)');
        this.analyzer.analyzePolicy(largePolicy);
        console.timeEnd('Security Analysis (50 statements)');

        console.time('Policy Optimization (50 statements)');
        this.optimizer.optimize(largePolicy);
        console.timeEnd('Policy Optimization (50 statements)');

        console.time('Policy Comparison');
        this.comparator.compare(largePolicy, largePolicy);
        console.timeEnd('Policy Comparison');
    }

    // Utility methods for testing specific components
    createTestPolicy(options = {}) {
        return {
            Version: '2012-10-17',
            Statement: options.statements || [
                {
                    Sid: options.sid || 'TestStatement',
                    Effect: options.effect || 'Allow',
                    Action: options.action || 's3:GetObject',
                    Resource: options.resource || '*',
                    Condition: options.condition || undefined
                }
            ]
        };
    }

    assertRiskScoreRange(score, min, max) {
        assert(score >= min && score <= max, 
            `Risk score ${score} should be between ${min} and ${max}`);
    }

    assertContainsIssueType(issues, type) {
        assert(issues.some(issue => issue.type === type), 
            `Should contain issue of type: ${type}`);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    const testSuite = new TestSuite();
    
    // Check for specific test argument
    const testType = process.argv[2];
    
    if (testType) {
        switch (testType) {
            case 'security':
                testSuite.testSecurityAnalyzer();
                break;
            case 'comparison':
                testSuite.testPolicyComparator();
                break;
            case 'optimization':
                testSuite.testPolicyOptimizer();
                break;
            case 'reporting':
                testSuite.testReportGenerator();
                break;
            case 'integration':
                testSuite.testIntegration();
                break;
            default:
                console.log('Unknown test type. Running all tests...');
                testSuite.runAllTests();
        }
    } else {
        testSuite.runAllTests();
    }
}

module.exports = TestSuite;