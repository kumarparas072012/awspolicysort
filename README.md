# AWS Policy Analyzer 2.0 🛡️

A comprehensive AWS IAM Policy analysis, security scanning, and optimization tool with interactive dashboard and CLI interface.

## ✨ Features

### 🔍 Security Analysis
- **Risk Assessment**: Comprehensive security scoring (0-100)
- **Vulnerability Detection**: Identifies wildcard usage, missing conditions, and dangerous permissions
- **Compliance Checking**: Validates against security best practices
- **Threat Detection**: Spots potential privilege escalation paths

### ⚡ Policy Optimization
- **Statement Consolidation**: Merge similar statements automatically
- **Duplicate Removal**: Eliminate redundant permissions
- **Action Grouping**: Organize actions for better readability
- **Resource Simplification**: Consolidate overlapping resource patterns

### 🔄 Policy Comparison
- **Side-by-side Diff**: Visual comparison of two policies
- **Merge Assessment**: Analyze compatibility for policy consolidation
- **Change Detection**: Identify additions, removals, and modifications
- **Impact Analysis**: Assess security implications of differences

### 📊 Interactive Dashboard
- **Visual Analytics**: Charts and graphs for policy insights
- **Risk Visualization**: Color-coded security indicators
- **Real-time Analysis**: Upload and analyze policies instantly
- **Export Reports**: Generate PDF/HTML reports

### 🖥️ Powerful CLI
- **Batch Processing**: Analyze multiple policies at once
- **Interactive Mode**: Step-by-step guided analysis
- **Multiple Formats**: JSON, HTML, and text output
- **Configuration Management**: Persistent settings

### 📏 AWS Policy Limits Validation
- **Size Checking**: Validate against 6KB managed policy limits
- **Type Compatibility**: Check compatibility with inline vs managed policies
- **Optimization Suggestions**: Recommendations to fit within limits
- **Real-time Monitoring**: Track size utilization percentage

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/aws-policy-analyzer.git
cd aws-policy-analyzer

# Install dependencies
npm install

# Install globally (optional)
npm run install-global
```

### Basic Usage

```bash
# Analyze a policy for security issues
node cli.js analyze my-policy.json

# Optimize policy structure
node cli.js optimize my-policy.json -o optimized-policy.json

# Compare two policies
node cli.js compare policy1.json policy2.json

# Generate comprehensive reports
node cli.js report my-policy.json --type all --format html

# Check AWS policy size limits
node cli.js check-limits my-policy.json --suggest-type

# Start interactive mode
node cli.js interactive

# Open web dashboard
npm run dashboard
```

## 📖 Detailed Usage

### Security Analysis

```bash
# Basic security analysis
policy-analyzer analyze my-policy.json

# Generate detailed security report
policy-analyzer analyze my-policy.json --report --format html -o security-report.html

# Verbose output with detailed findings
policy-analyzer analyze my-policy.json --verbose
```

### Policy Optimization

```bash
# Optimize policy (dry run to preview changes)
policy-analyzer optimize my-policy.json --dry-run

# Apply optimizations and save result
policy-analyzer optimize my-policy.json -o optimized.json --report

# Show optimization opportunities only
policy-analyzer optimize my-policy.json --dry-run --verbose
```

### Policy Comparison

```bash
# Compare two policies
policy-analyzer compare old-policy.json new-policy.json

# Compare with custom labels
policy-analyzer compare policy-a.json policy-b.json --labels "Production,Staging"

# Generate HTML comparison report
policy-analyzer compare policy1.json policy2.json --format html -o comparison.html
```

### Batch Processing

```bash
# Analyze all JSON files in a directory
policy-analyzer batch ./policies --type analyze

# Optimize all policies in a directory
policy-analyzer batch ./policies --type optimize -o ./optimized

# Custom file pattern
policy-analyzer batch ./policies --pattern "*-iam-*.json" --type analyze
```

### AWS Limits Checking

```bash
# Check if policy fits AWS managed policy limits
policy-analyzer check-limits my-policy.json

# Check specific policy type compatibility
policy-analyzer check-limits my-policy.json --type inlinePolicy

# Get policy type recommendations
policy-analyzer check-limits my-policy.json --suggest-type

# Check limits with detailed output
policy-analyzer check-limits my-policy.json --format json -o limits-report.json
```

### Report Generation

```bash
# Generate all report types
policy-analyzer report my-policy.json --type all --format html

# Executive summary only
policy-analyzer report my-policy.json --type executive --format html

# Security report with custom output directory
policy-analyzer report my-policy.json --type security -o ./reports
```

## 🎯 Examples

### Example 1: Complete Policy Analysis

```bash
# Start with a comprehensive analysis
policy-analyzer analyze production-policy.json --verbose --report

# Output: Identifies 5 high-risk issues including wildcard permissions
# Risk Score: 78/100 (High Risk)

# Optimize the policy
policy-analyzer optimize production-policy.json -o production-optimized.json

# Output: Reduced from 45 to 23 statements (49% reduction)

# Generate executive report
policy-analyzer report production-policy.json --type executive --format html
```

### Example 2: Policy Migration Analysis

```bash
# Compare current vs proposed policy
policy-analyzer compare current-prod.json proposed-prod.json --labels "Current,Proposed"

# Output: 
# - 12 differences found
# - 3 new permissions added
# - 2 permissions removed
# - Mergeability: RISKY (requires review)

# Generate detailed comparison report
policy-analyzer compare current-prod.json proposed-prod.json --format html -o migration-analysis.html
```

### Example 3: AWS Limits Validation

```bash
# Check if policy exceeds AWS limits
policy-analyzer check-limits production-policy.json --suggest-type

# Output:
# Current Size: 5429 bytes
# Recommended Type: managedPolicy
# ✅ Compatible: managedPolicy (88.4% utilization)
# ❌ Incompatible: inlinePolicy (265% - exceeds limit)

# Optimize policy to fit inline limits
policy-analyzer optimize production-policy.json -o optimized.json
policy-analyzer check-limits optimized.json --type inlinePolicy

# Output: 
# ✅ Now compatible with inline policies (67% utilization)
```

### Example 4: Compliance Audit

```bash
# Batch analyze all team policies
policy-analyzer batch ./team-policies --type analyze -o ./audit-results

# Generate executive summary for management
policy-analyzer report ./team-policies/*.json --type executive --format html -o executive-summary.html
```

## 🌐 Web Dashboard

The interactive web dashboard provides a user-friendly interface for policy analysis:

1. **Open the dashboard**: `npm run dashboard` or open `dashboard.html`
2. **Upload a policy**: Drag and drop or select a JSON file
3. **View analysis**: Real-time security scoring and issue detection
4. **Explore insights**: Interactive charts and visualizations
5. **Export reports**: Download HTML or PDF reports

### Dashboard Features

- 📊 **Risk Meter**: Visual risk scoring with color-coded indicators
- 📈 **Analytics Charts**: Action distribution, issue breakdown, compliance status
- 🔍 **Issue Explorer**: Detailed view of security issues with recommendations
- 💡 **Optimization Suggestions**: Interactive optimization opportunities
- 📋 **Compliance Dashboard**: Real-time compliance checking
- 📄 **Policy Viewer**: Syntax-highlighted JSON display

## 🔧 Configuration

### CLI Configuration

```bash
# Set default output format
policy-analyzer config --set defaultFormat=html

# Set default report directory
policy-analyzer config --set reportDir=./reports

# View all configuration
policy-analyzer config --list
```

### Environment Variables

```bash
export POLICY_ANALYZER_OUTPUT_DIR=./reports
export POLICY_ANALYZER_FORMAT=html
export POLICY_ANALYZER_VERBOSE=true
```

## 📊 Output Formats

### JSON Output
```json
{
  "riskScore": 65,
  "securityIssues": [
    {
      "type": "HIGH",
      "category": "Wildcard Usage", 
      "message": "Statement allows all actions (*)",
      "recommendation": "Restrict to specific actions needed"
    }
  ]
}
```

### HTML Reports
- Executive summaries with charts and graphs
- Detailed technical findings
- Interactive policy comparisons
- Printable compliance reports

### Text Output
- Console-friendly formatting
- Perfect for CI/CD integration
- Scriptable output parsing

## 🔒 Security Features

### Risk Assessment Engine
- **Wildcard Detection**: Identifies overly permissive `*` permissions
- **Privilege Escalation**: Detects potential escalation paths
- **Cross-Account Risks**: Analyzes cross-account access patterns
- **Condition Analysis**: Evaluates security conditions

### Compliance Frameworks
- **Least Privilege**: Ensures minimal necessary permissions
- **Separation of Duties**: Identifies administrative vs operational permissions
- **Conditional Access**: Validates appropriate condition usage
- **Resource Restriction**: Checks for proper resource scoping

## 🎨 Advanced Features

### Policy Templates
```bash
# Generate optimized policy template
policy-analyzer template --service s3 --permissions read,write

# Create least-privilege policy
policy-analyzer template --role developer --services ec2,s3,lambda
```

### Integration Capabilities
```bash
# CI/CD Integration
policy-analyzer analyze policy.json --format json --fail-on-risk 70

# Git Hooks
policy-analyzer compare HEAD~1:policy.json HEAD:policy.json
```

### Custom Rules
```javascript
// custom-rules.js
module.exports = {
  rules: [
    {
      name: 'NoProductionWildcards',
      check: (policy) => /* custom logic */,
      severity: 'HIGH'
    }
  ]
};
```

## 🧪 Testing

```bash
# Run test suite
npm test

# Test specific functionality
node test.js security
node test.js optimization
node test.js comparison
```

## 📚 API Reference

### PolicySecurityAnalyzer
```javascript
const analyzer = new PolicySecurityAnalyzer();
const results = analyzer.analyzePolicy(policyJson);
```

### PolicyOptimizer
```javascript
const optimizer = new PolicyOptimizer();
const optimization = optimizer.optimize(policyJson);
```

### PolicyComparator
```javascript
const comparator = new PolicyComparator();
const comparison = comparator.compare(policy1, policy2);
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- AWS IAM documentation and best practices
- NIST Cybersecurity Framework
- Open source security research community

## 📞 Support

- 📧 Email: support@aws-policy-analyzer.com
- 💬 Issues: [GitHub Issues](https://github.com/your-org/aws-policy-analyzer/issues)
- 📖 Documentation: [Wiki](https://github.com/your-org/aws-policy-analyzer/wiki)

---

**⚠️ Security Notice**: This tool analyzes IAM policies but does not store or transmit your policy data. All analysis is performed locally for maximum security.