#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { program } = require('commander');

// Import our enhanced modules
const PolicySecurityAnalyzer = require('./policySecurityAnalyzer');
const PolicyComparator = require('./policyComparator');
const PolicyOptimizer = require('./policyOptimizer');
const ReportGenerator = require('./reportGenerator');
const PolicyLimitValidator = require('./policyLimitValidator');

class PolicyAnalyzerCLI {
    constructor() {
        this.setupCommands();
        this.analyzer = new PolicySecurityAnalyzer();
        this.comparator = new PolicyComparator();
        this.optimizer = new PolicyOptimizer();
        this.reporter = new ReportGenerator();
        this.limitValidator = new PolicyLimitValidator();
    }

    setupCommands() {
        program
            .name('policy-analyzer')
            .description('AWS IAM Policy Analysis, Optimization, and Security Scanner')
            .version('2.0.0');

        // Security Analysis Command
        program
            .command('analyze')
            .alias('a')
            .description('Analyze AWS IAM policy for security issues')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('-o, --output <file>', 'Output file for results')
            .option('-f, --format <type>', 'Output format (json|html|txt)', 'json')
            .option('-r, --report', 'Generate detailed report')
            .option('-v, --verbose', 'Verbose output')
            .action(this.analyzeCommand.bind(this));

        // Policy Comparison Command
        program
            .command('compare')
            .alias('c')
            .description('Compare two AWS IAM policies')
            .argument('<policy1>', 'First policy file')
            .argument('<policy2>', 'Second policy file')
            .option('-o, --output <file>', 'Output file for comparison results')
            .option('-f, --format <type>', 'Output format (json|html|txt)', 'json')
            .option('-l, --labels <labels>', 'Comma-separated labels for policies', 'Policy A,Policy B')
            .action(this.compareCommand.bind(this));

        // Policy Optimization Command
        program
            .command('optimize')
            .alias('opt')
            .description('Optimize AWS IAM policy structure')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('-o, --output <file>', 'Output file for optimized policy')
            .option('-r, --report', 'Generate optimization report')
            .option('--dry-run', 'Show optimizations without applying them')
            .action(this.optimizeCommand.bind(this));

        // Sort Command (enhanced version of original)
        program
            .command('sort')
            .alias('s')
            .description('Sort policy statements and actions alphabetically')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('-o, --output <file>', 'Output file for sorted policy')
            .option('--sort-by <field>', 'Sort statements by field (sid|effect|action)', 'sid')
            .action(this.sortCommand.bind(this));

        // Report Generation Command
        program
            .command('report')
            .alias('r')
            .description('Generate comprehensive analysis reports')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('-t, --type <type>', 'Report type (security|optimization|executive|all)', 'all')
            .option('-f, --format <format>', 'Output format (json|html)', 'html')
            .option('-o, --output <dir>', 'Output directory', './reports')
            .action(this.reportCommand.bind(this));

        // Batch Processing Command
        program
            .command('batch')
            .alias('b')
            .description('Process multiple policy files')
            .argument('<directory>', 'Directory containing policy files')
            .option('-o, --output <dir>', 'Output directory', './batch-results')
            .option('-t, --type <type>', 'Analysis type (analyze|optimize|sort)', 'analyze')
            .option('-p, --pattern <pattern>', 'File pattern to match', '*.json')
            .action(this.batchCommand.bind(this));

        // Interactive Mode Command
        program
            .command('interactive')
            .alias('i')
            .description('Start interactive mode')
            .action(this.interactiveCommand.bind(this));

        // Validation Command
        program
            .command('validate')
            .alias('v')
            .description('Validate policy syntax and structure')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('--strict', 'Enable strict validation mode')
            .action(this.validateCommand.bind(this));

        // AWS Limits Check Command
        program
            .command('check-limits')
            .alias('limits')
            .description('Check AWS policy size limits and compatibility')
            .argument('<policy-file>', 'Path to JSON policy file')
            .option('-t, --type <type>', 'Policy type (managedPolicy|inlinePolicy|assumeRolePolicy)', 'managedPolicy')
            .option('-o, --output <file>', 'Output file for results')
            .option('-f, --format <format>', 'Output format (json|txt)', 'txt')
            .option('--suggest-type', 'Suggest optimal policy type')
            .action(this.checkLimitsCommand.bind(this));

        // Configuration Command
        program
            .command('config')
            .description('Manage CLI configuration')
            .option('--set <key=value>', 'Set configuration value')
            .option('--get <key>', 'Get configuration value')
            .option('--list', 'List all configuration')
            .action(this.configCommand.bind(this));
    }

    async analyzeCommand(policyFile, options) {
        try {
            this.log('🔍 Starting security analysis...', options.verbose);
            
            const policyData = this.loadPolicyFile(policyFile);
            const analysis = this.analyzer.analyzePolicy(policyData);
            
            // Generate output
            const outputData = {
                file: policyFile,
                timestamp: new Date().toISOString(),
                analysis: analysis
            };

            if (options.report) {
                const report = this.reporter.generateSecurityReport(analysis, {
                    format: options.format,
                    metadata: { sourceFile: policyFile }
                });
                outputData.report = report;
            }

            await this.saveOutput(outputData, options.output, options.format);
            this.displayAnalysisResults(analysis, options.verbose);
            
        } catch (error) {
            this.error(`Analysis failed: ${error.message}`);
        }
    }

    async compareCommand(policy1File, policy2File, options) {
        try {
            this.log('🔄 Starting policy comparison...', options.verbose);
            
            const policy1 = this.loadPolicyFile(policy1File);
            const policy2 = this.loadPolicyFile(policy2File);
            const labels = options.labels.split(',').map(l => l.trim());
            
            const comparison = this.comparator.compare(policy1, policy2, {
                policy1: labels[0] || policy1File,
                policy2: labels[1] || policy2File
            });

            const outputData = {
                files: { policy1: policy1File, policy2: policy2File },
                timestamp: new Date().toISOString(),
                comparison: comparison
            };

            await this.saveOutput(outputData, options.output, options.format);
            this.displayComparisonResults(comparison, options.verbose);
            
        } catch (error) {
            this.error(`Comparison failed: ${error.message}`);
        }
    }

    async optimizeCommand(policyFile, options) {
        try {
            this.log('⚡ Starting policy optimization...', options.verbose);
            
            const policyData = this.loadPolicyFile(policyFile);
            const optimization = this.optimizer.optimize(policyData);

            if (options.dryRun) {
                this.log('🔍 Dry run mode - showing potential optimizations:', true);
                this.displayOptimizationResults(optimization, true);
                return;
            }

            const outputData = {
                file: policyFile,
                timestamp: new Date().toISOString(),
                optimization: optimization
            };

            if (options.report) {
                const report = this.reporter.generateOptimizationReport(optimization, {
                    metadata: { sourceFile: policyFile }
                });
                outputData.report = report;
            }

            // Save optimized policy
            if (options.output) {
                fs.writeFileSync(options.output, JSON.stringify(optimization.optimized, null, 2));
                this.success(`Optimized policy saved to: ${options.output}`);
            }

            this.displayOptimizationResults(optimization, options.verbose);
            
        } catch (error) {
            this.error(`Optimization failed: ${error.message}`);
        }
    }

    async sortCommand(policyFile, options) {
        try {
            this.log('📝 Sorting policy...', options.verbose);
            
            const policyData = this.loadPolicyFile(policyFile);
            const sorted = this.sortPolicy(policyData, options.sortBy);

            const outputFile = options.output || this.generateOutputFilename(policyFile, 'sorted');
            fs.writeFileSync(outputFile, JSON.stringify(sorted, null, 2));
            
            this.success(`Sorted policy saved to: ${outputFile}`);
            
        } catch (error) {
            this.error(`Sorting failed: ${error.message}`);
        }
    }

    async reportCommand(policyFile, options) {
        try {
            this.log('📊 Generating reports...', options.verbose);
            
            const policyData = this.loadPolicyFile(policyFile);
            
            // Ensure output directory exists
            if (!fs.existsSync(options.output)) {
                fs.mkdirSync(options.output, { recursive: true });
            }

            const results = {};

            if (options.type === 'security' || options.type === 'all') {
                this.log('  Analyzing security...', options.verbose);
                results.security = this.analyzer.analyzePolicy(policyData);
            }

            if (options.type === 'optimization' || options.type === 'all') {
                this.log('  Analyzing optimization opportunities...', options.verbose);
                results.optimization = this.optimizer.optimize(policyData);
            }

            // Generate reports
            const reports = [];

            if (options.type === 'executive' || options.type === 'all') {
                const execReport = this.reporter.generateExecutiveSummary(results, { format: options.format });
                const execFile = path.join(options.output, `executive-summary.${options.format}`);
                this.reporter.saveReport(execReport, execFile, options.format);
                reports.push(execFile);
            }

            if (results.security) {
                const secReport = this.reporter.generateSecurityReport(results.security, { format: options.format });
                const secFile = path.join(options.output, `security-report.${options.format}`);
                this.reporter.saveReport(secReport, secFile, options.format);
                reports.push(secFile);
            }

            if (results.optimization) {
                const optReport = this.reporter.generateOptimizationReport(results.optimization, { format: options.format });
                const optFile = path.join(options.output, `optimization-report.${options.format}`);
                this.reporter.saveReport(optReport, optFile, options.format);
                reports.push(optFile);
            }

            this.success(`Reports generated:`);
            reports.forEach(report => this.log(`  📄 ${report}`));
            
        } catch (error) {
            this.error(`Report generation failed: ${error.message}`);
        }
    }

    async batchCommand(directory, options) {
        try {
            this.log(`📁 Processing files in ${directory}...`, true);
            
            const pattern = new RegExp(options.pattern.replace('*', '.*'));
            const files = fs.readdirSync(directory)
                .filter(file => pattern.test(file))
                .map(file => path.join(directory, file));

            if (files.length === 0) {
                this.warn(`No files found matching pattern: ${options.pattern}`);
                return;
            }

            // Ensure output directory exists
            if (!fs.existsSync(options.output)) {
                fs.mkdirSync(options.output, { recursive: true });
            }

            const results = [];

            for (const file of files) {
                try {
                    this.log(`  Processing: ${path.basename(file)}`, true);
                    
                    const policyData = this.loadPolicyFile(file);
                    let result = { file: path.basename(file) };

                    switch (options.type) {
                        case 'analyze':
                            result.analysis = this.analyzer.analyzePolicy(policyData);
                            break;
                        case 'optimize':
                            result.optimization = this.optimizer.optimize(policyData);
                            // Save optimized policy
                            const optimizedFile = path.join(options.output, `optimized-${path.basename(file)}`);
                            fs.writeFileSync(optimizedFile, JSON.stringify(result.optimization.optimized, null, 2));
                            break;
                        case 'sort':
                            result.sorted = this.sortPolicy(policyData);
                            const sortedFile = path.join(options.output, `sorted-${path.basename(file)}`);
                            fs.writeFileSync(sortedFile, JSON.stringify(result.sorted, null, 2));
                            break;
                    }

                    results.push(result);
                    
                } catch (error) {
                    this.warn(`Failed to process ${file}: ${error.message}`);
                }
            }

            // Save batch results summary
            const summaryFile = path.join(options.output, 'batch-summary.json');
            fs.writeFileSync(summaryFile, JSON.stringify({
                timestamp: new Date().toISOString(),
                processedFiles: files.length,
                results: results
            }, null, 2));

            this.success(`Batch processing complete. Results saved to: ${options.output}`);
            
        } catch (error) {
            this.error(`Batch processing failed: ${error.message}`);
        }
    }

    async interactiveCommand() {
        const readline = require('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        this.log('🚀 Welcome to AWS Policy Analyzer Interactive Mode!', true);
        this.log('Type "help" for available commands or "exit" to quit.\n', true);

        const promptUser = () => {
            rl.question('policy-analyzer> ', async (input) => {
                const args = input.trim().split(' ');
                const command = args[0];

                if (command === 'exit' || command === 'quit') {
                    this.log('Goodbye!', true);
                    rl.close();
                    return;
                }

                if (command === 'help') {
                    this.showInteractiveHelp();
                    promptUser();
                    return;
                }

                try {
                    await this.executeInteractiveCommand(args);
                } catch (error) {
                    this.error(`Command failed: ${error.message}`);
                }

                promptUser();
            });
        };

        promptUser();
    }

    async validateCommand(policyFile, options) {
        try {
            this.log('✅ Validating policy...', true);
            
            const policyData = this.loadPolicyFile(policyFile);
            const validation = this.validatePolicy(policyData, options.strict);
            
            if (validation.valid) {
                this.success('Policy is valid!');
            } else {
                this.error('Policy validation failed:');
                validation.errors.forEach(error => this.log(`  ❌ ${error}`, true));
            }
            
        } catch (error) {
            this.error(`Validation failed: ${error.message}`);
        }
    }

    async checkLimitsCommand(policyFile, options) {
        try {
            this.log('🔍 Checking AWS policy limits...', true);
            
            const policyData = this.loadPolicyFile(policyFile);
            const validation = this.limitValidator.validatePolicy(policyData, options.type);
            
            if (options.suggestType) {
                const suggestion = this.limitValidator.suggestPolicyType(policyData);
                this.displayPolicyTypeSuggestion(suggestion);
            }
            
            const outputData = {
                file: policyFile,
                timestamp: new Date().toISOString(),
                validation: validation,
                report: this.limitValidator.generateOptimizationReport(policyData, options.type)
            };

            if (options.output) {
                await this.saveOutput(outputData, options.output, options.format);
            }

            this.displayLimitAnalysis(validation, options.type);
            
        } catch (error) {
            this.error(`Limit check failed: ${error.message}`);
        }
    }

    configCommand(options) {
        const configFile = path.join(require('os').homedir(), '.policy-analyzer-config.json');
        let config = {};

        // Load existing config
        if (fs.existsSync(configFile)) {
            config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        }

        if (options.set) {
            const [key, value] = options.set.split('=');
            config[key] = value;
            fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
            this.success(`Configuration set: ${key} = ${value}`);
        } else if (options.get) {
            const value = config[options.get];
            this.log(`${options.get} = ${value || 'undefined'}`, true);
        } else if (options.list) {
            this.log('Configuration:', true);
            Object.entries(config).forEach(([key, value]) => {
                this.log(`  ${key} = ${value}`, true);
            });
        } else {
            this.log('Use --set, --get, or --list options', true);
        }
    }

    // Helper methods
    loadPolicyFile(filePath) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`Policy file not found: ${filePath}`);
        }
        
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    }

    sortPolicy(policy, sortBy = 'sid') {
        const sorted = JSON.parse(JSON.stringify(policy));
        
        if (!sorted.Statement) return sorted;

        // Sort statements
        sorted.Statement.sort((a, b) => {
            switch (sortBy) {
                case 'effect':
                    return (a.Effect || '').localeCompare(b.Effect || '');
                case 'action':
                    const actionA = Array.isArray(a.Action) ? a.Action[0] : (a.Action || '');
                    const actionB = Array.isArray(b.Action) ? b.Action[0] : (b.Action || '');
                    return actionA.localeCompare(actionB);
                case 'sid':
                default:
                    return (a.Sid || '').localeCompare(b.Sid || '');
            }
        });

        // Sort actions and resources within each statement
        sorted.Statement.forEach(stmt => {
            if (Array.isArray(stmt.Action)) {
                stmt.Action.sort();
            }
            if (Array.isArray(stmt.Resource)) {
                stmt.Resource.sort();
            }
        });

        return sorted;
    }

    validatePolicy(policy, strict = false) {
        const errors = [];
        
        // Basic structure validation
        if (!policy.Version) {
            errors.push('Missing Version field');
        }
        
        if (!policy.Statement) {
            errors.push('Missing Statement field');
        }
        
        if (policy.Statement && !Array.isArray(policy.Statement)) {
            errors.push('Statement must be an array');
        }

        // Statement validation
        if (policy.Statement) {
            policy.Statement.forEach((stmt, index) => {
                if (!stmt.Effect) {
                    errors.push(`Statement ${index + 1}: Missing Effect`);
                }
                
                if (stmt.Effect && !['Allow', 'Deny'].includes(stmt.Effect)) {
                    errors.push(`Statement ${index + 1}: Invalid Effect value`);
                }
                
                if (!stmt.Action && !stmt.NotAction) {
                    errors.push(`Statement ${index + 1}: Missing Action or NotAction`);
                }

                if (strict) {
                    if (!stmt.Sid) {
                        errors.push(`Statement ${index + 1}: Missing Sid (strict mode)`);
                    }
                    
                    if (stmt.Resource === '*' && stmt.Action === '*') {
                        errors.push(`Statement ${index + 1}: Overly permissive (strict mode)`);
                    }
                }
            });
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    async saveOutput(data, outputFile, format) {
        if (!outputFile) return;

        let content;
        let extension;

        switch (format) {
            case 'html':
                content = this.reporter.convertToHtml(data, 'generic');
                extension = '.html';
                break;
            case 'txt':
                content = this.formatAsText(data);
                extension = '.txt';
                break;
            default:
                content = JSON.stringify(data, null, 2);
                extension = '.json';
        }

        const fullPath = outputFile.includes('.') ? outputFile : outputFile + extension;
        fs.writeFileSync(fullPath, content);
        this.success(`Results saved to: ${fullPath}`);
    }

    formatAsText(data) {
        // Simple text formatting for console output
        return JSON.stringify(data, null, 2)
            .replace(/[{}]/g, '')
            .replace(/"/g, '')
            .replace(/,$/gm, '');
    }

    generateOutputFilename(inputFile, suffix) {
        const parsed = path.parse(inputFile);
        return path.join(parsed.dir, `${parsed.name}-${suffix}${parsed.ext}`);
    }

    displayAnalysisResults(analysis, verbose = false) {
        this.log('\n📊 Analysis Results:', true);
        this.log(`Risk Score: ${analysis.riskScore}/100`, true);
        this.log(`Security Issues: ${analysis.securityIssues.length}`, true);
        this.log(`Optimization Opportunities: ${analysis.optimizationSuggestions.length}`, true);
        
        if (verbose && analysis.securityIssues.length > 0) {
            this.log('\n🚨 Security Issues:', true);
            analysis.securityIssues.slice(0, 5).forEach((issue, i) => {
                this.log(`  ${i + 1}. [${issue.type}] ${issue.message}`, true);
            });
        }
    }

    displayComparisonResults(comparison, verbose = false) {
        this.log('\n🔄 Comparison Results:', true);
        this.log(`Differences: ${comparison.differences.length}`, true);
        this.log(`Similarities: ${comparison.similarities.length}`, true);
        this.log(`Mergeability: ${comparison.mergeability.level}`, true);
        
        if (verbose && comparison.differences.length > 0) {
            this.log('\n📋 Key Differences:', true);
            comparison.differences.slice(0, 3).forEach((diff, i) => {
                this.log(`  ${i + 1}. ${diff.description}`, true);
            });
        }
    }

    displayOptimizationResults(optimization, verbose = false) {
        this.log('\n⚡ Optimization Results:', true);
        this.log(`Statement Reduction: ${optimization.savings.statementReduction} (${optimization.savings.statementReductionPercent}%)`, true);
        this.log(`Size Reduction: ${optimization.savings.sizeReduction} characters`, true);
        this.log(`Applied Optimizations: ${optimization.optimizations.length}`, true);
        
        if (verbose && optimization.optimizations.length > 0) {
            this.log('\n🛠️ Optimizations Applied:', true);
            optimization.optimizations.slice(0, 3).forEach((opt, i) => {
                this.log(`  ${i + 1}. ${opt.description}`, true);
            });
        }
    }

    displayLimitAnalysis(validation, policyType) {
        this.log('\n📏 AWS Policy Limits Analysis:', true);
        this.log(`Policy Type: ${policyType}`, true);
        this.log(`Current Size: ${validation.sizeAnalysis.currentSize} bytes`, true);
        this.log(`Size Limit: ${validation.sizeAnalysis.limit} bytes`, true);
        this.log(`Utilization: ${validation.sizeAnalysis.utilization}%`, true);
        this.log(`Status: ${validation.isValid ? '✅ WITHIN LIMITS' : '❌ EXCEEDS LIMITS'}`, true);
        
        if (validation.sizeAnalysis.remainingBytes > 0) {
            this.log(`Remaining: ${validation.sizeAnalysis.remainingBytes} bytes`, true);
        }
        
        if (validation.errors.length > 0) {
            this.log('\n🚨 Limit Violations:', true);
            validation.errors.slice(0, 3).forEach((error, i) => {
                this.log(`  ${i + 1}. [${error.severity}] ${error.message}`, true);
            });
        }
        
        if (validation.warnings.length > 0) {
            this.log('\n⚠️  Warnings:', true);
            validation.warnings.slice(0, 3).forEach((warning, i) => {
                this.log(`  ${i + 1}. ${warning.message}`, true);
            });
        }
    }

    displayPolicyTypeSuggestion(suggestion) {
        this.log('\n🎯 Policy Type Recommendation:', true);
        this.log(`Current Size: ${suggestion.currentSize} bytes`, true);
        this.log(`Recommended Type: ${suggestion.recommendedType || 'POLICY TOO LARGE'}`, true);
        
        if (suggestion.allCompatibleTypes.length > 0) {
            this.log('\n✅ Compatible Types:', true);
            suggestion.allCompatibleTypes.forEach(([type, info]) => {
                this.log(`  ${type}: ${info.utilization}% utilization`, true);
            });
        }
        
        const incompatibleTypes = Object.entries(suggestion.sizingDetails)
            .filter(([type, info]) => !info.fits);
        if (incompatibleTypes.length > 0) {
            this.log('\n❌ Incompatible Types:', true);
            incompatibleTypes.forEach(([type, info]) => {
                this.log(`  ${type}: ${info.utilization}% (exceeds limit)`, true);
            });
        }
    }

    showInteractiveHelp() {
        this.log('\nAvailable commands:', true);
        this.log('  analyze <file>     - Analyze policy security', true);
        this.log('  compare <f1> <f2>  - Compare two policies', true);
        this.log('  optimize <file>    - Optimize policy structure', true);
        this.log('  sort <file>        - Sort policy statements', true);
        this.log('  validate <file>    - Validate policy syntax', true);
        this.log('  help               - Show this help', true);
        this.log('  exit               - Exit interactive mode', true);
        this.log('');
    }

    async executeInteractiveCommand(args) {
        // Simplified command execution for interactive mode
        const command = args[0];
        const file = args[1];
        
        if (!file) {
            this.error('File path required');
            return;
        }

        switch (command) {
            case 'analyze':
                await this.analyzeCommand(file, { verbose: true });
                break;
            case 'optimize':
                await this.optimizeCommand(file, { verbose: true });
                break;
            case 'sort':
                await this.sortCommand(file, {});
                break;
            case 'validate':
                await this.validateCommand(file, {});
                break;
            default:
                this.error(`Unknown command: ${command}`);
        }
    }

    // Logging helpers
    log(message, force = false) {
        if (force || program.opts().verbose) {
            console.log(message);
        }
    }

    success(message) {
        console.log(`✅ ${message}`);
    }

    warn(message) {
        console.log(`⚠️  ${message}`);
    }

    error(message) {
        console.error(`❌ ${message}`);
        process.exit(1);
    }

    run() {
        program.parse();
    }
}

// Only run if this file is executed directly
if (require.main === module) {
    const cli = new PolicyAnalyzerCLI();
    cli.run();
}

module.exports = PolicyAnalyzerCLI;