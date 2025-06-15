#!/bin/bash

# SIGMA Engine Git Hooks Setup Script
# Sets up git hooks for automated quality checks

set -e

echo "🔧 Setting up SIGMA Engine Git Hooks"
echo "================================="
echo ""

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: Not in a git repository"
    echo "💡 Run this script from the project root directory"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Set up pre-commit hook
echo "📝 Setting up pre-commit hook..."
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# SIGMA Engine Pre-commit Hook
# This hook runs essential quality checks before allowing a commit

# Run the pre-commit script
exec ./scripts/pre-commit.sh
EOF

# Make the hook executable
chmod +x .git/hooks/pre-commit

echo "✅ Pre-commit hook installed"

# Set up pre-push hook for more comprehensive checks
echo "📝 Setting up pre-push hook..."
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
# SIGMA Engine Pre-push Hook
# This hook runs comprehensive quality checks before allowing a push

echo "🚀 Running comprehensive checks before push..."
echo ""

# Run full quality checks
if ./scripts/quality.sh; then
    echo "✅ All quality checks passed - push allowed"
    exit 0
else
    echo "❌ Quality checks failed - push blocked"
    echo "💡 Fix the issues above before pushing"
    exit 1
fi
EOF

# Make the hook executable
chmod +x .git/hooks/pre-push

echo "✅ Pre-push hook installed"

# Set up commit-msg hook for commit message validation
echo "📝 Setting up commit-msg hook..."
cat > .git/hooks/commit-msg << 'EOF'
#!/bin/bash
# SIGMA Engine Commit Message Hook
# This hook validates commit message format

commit_regex='^(feat|fix|docs|style|refactor|test|chore|perf|ci|build)(\(.+\))?: .{1,50}'

error_msg="❌ Invalid commit message format!

Commit message should follow the format:
<type>(<scope>): <description>

Types:
- feat: A new feature
- fix: A bug fix
- docs: Documentation only changes
- style: Changes that do not affect the meaning of the code
- refactor: A code change that neither fixes a bug nor adds a feature
- test: Adding missing tests or correcting existing tests
- chore: Changes to the build process or auxiliary tools
- perf: A code change that improves performance
- ci: Changes to CI configuration files and scripts
- build: Changes that affect the build system or external dependencies

Examples:
- feat(compiler): add support for complex SIGMA conditions
- fix(vm): resolve stack overflow in nested expressions
- docs(readme): update installation instructions
- test(integration): add end-to-end rule compilation tests"

if ! grep -qE "$commit_regex" "$1"; then
    echo "$error_msg" >&2
    exit 1
fi
EOF

# Make the hook executable
chmod +x .git/hooks/commit-msg

echo "✅ Commit message validation hook installed"

echo ""
echo "🎉 Git hooks setup complete!"
echo ""
echo "📋 Installed hooks:"
echo "  • pre-commit: Runs formatting and basic checks"
echo "  • pre-push: Runs comprehensive quality checks"
echo "  • commit-msg: Validates commit message format"
echo ""
echo "💡 To bypass hooks temporarily, use:"
echo "  git commit --no-verify"
echo "  git push --no-verify"
echo ""
echo "🔧 To run quality checks manually:"
echo "  make quality          # Full quality check"
echo "  ./scripts/quality.sh  # Same as above"
echo "  make quick-check      # Fast development check"
