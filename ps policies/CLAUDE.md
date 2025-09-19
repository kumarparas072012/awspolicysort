# Claude AI Development Context

## Project Overview
This is an AWS IAM Policy analysis and security platform that has been enhanced from a basic policy sorting tool into a comprehensive enterprise-grade security solution.

## Key Commands & Scripts

### Testing Commands
```bash
# Run comprehensive test suite
npm test

# Test specific components
node test.js security
node test.js optimization
node test.js comparison

# Performance testing
node test.js performance
```

### Analysis Commands
```bash
# Security analysis
node cli.js analyze sortedps.json

# Policy optimization
node cli.js optimize sortedps.json -o optimized-policy.json

# Policy comparison
node cli.js compare policy1.json policy2.json

# AWS limits validation
node cli.js check-limits sortedps.json --suggest-type

# Generate comprehensive reports
node cli.js report sortedps.json --type all --format html

# Interactive mode
node cli.js interactive
```

### Advanced Analysis Commands
```bash
# Advanced security analysis with AI
node advancedSecurityEngine.js sortedps.json

# Policy simulation and impact analysis
node policySimulationEngine.js sortedps.json

# AI-powered recommendations
node policyRecommendationEngine.js sortedps.json
```

### Development Commands
```bash
# Install dependencies
npm install

# Start web dashboard
npm run dashboard

# Install globally
npm run install-global

# Run linting (if available)
npm run lint

# Run type checking (if available)
npm run typecheck
```

## Project Structure

### Core Analysis Engines
- `policySecurityAnalyzer.js` - Core security analysis with risk scoring
- `advancedSecurityEngine.js` - AI-powered threat detection and compliance
- `policySimulationEngine.js` - Policy simulation and impact analysis
- `policyRecommendationEngine.js` - AI-powered strategic recommendations

### Utilities & Tools
- `policyOptimizer.js` - Policy optimization and consolidation
- `policyComparator.js` - Policy comparison and diff analysis
- `policyLimitValidator.js` - AWS policy size limit validation
- `reportGenerator.js` - Comprehensive report generation

### Interfaces
- `cli.js` - Command-line interface with comprehensive commands
- `dashboard.html` - Interactive web dashboard with real-time analysis

### Test & Documentation
- `test.js` - Comprehensive testing framework
- `README.md` - Complete documentation and usage examples
- `package.json` - Project configuration and dependencies

## Test Data Files
- `sortedps.json` - Main test policy file (working, validated)
- `alpha_ps.json` - Alternative test file (has JSON syntax issues)

## Common Issues & Solutions

### JSON Syntax Errors
- Use `sortedps.json` for testing as it's validated and working
- `alpha_ps.json` has syntax errors at position 14717

### Performance Testing
- The test suite includes performance benchmarks
- Target: Sub-millisecond analysis for most operations
- Success rate: Aim for >70% test pass rate

### AWS Limits Validation
- Managed policies: 6KB limit (6144 bytes)
- Inline policies: 2KB limit (2048 bytes)
- Current test shows 88.4% utilization for managed policies

## Development Best Practices

### Code Quality
- All engines include comprehensive error handling
- Modular architecture with clear separation of concerns
- Extensive logging and progress indicators for user feedback

### Security Focus
- Never log or expose sensitive policy data
- All analysis performed locally
- Security-first approach in all recommendations

### Testing Strategy
- Test each component independently
- Use realistic policy data for testing
- Include both positive and negative test cases
- Performance benchmarking for enterprise requirements

## Integration Notes

### CLI Integration
- All engines can be used via CLI with `node cli.js [command]`
- Supports multiple output formats: JSON, HTML, text
- Batch processing capabilities for multiple files

### Dashboard Integration
- Real-time analysis capabilities
- Visual risk indicators and charts
- Interactive policy upload and analysis

### API Integration
- Each engine exports classes that can be imported
- Consistent interface patterns across all components
- Suitable for integration into larger applications

## Current Capabilities

### Risk Assessment
- 0-100 risk scoring system
- Multi-dimensional security analysis
- Real-time threat detection

### Compliance
- SOC2, PCI-DSS, HIPAA, NIST framework support
- Automated compliance checking
- Gap analysis and remediation suggestions

### Optimization
- Statement consolidation
- Duplicate removal
- Size optimization for AWS limits

### Recommendations
- Strategic planning with timelines
- Cost-benefit analysis
- Implementation roadmaps

## Future Enhancements
- Real-time AWS integration
- Advanced visualization engine
- Policy version control
- Automated remediation system
- Enhanced ML threat detection