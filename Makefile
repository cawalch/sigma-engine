.PHONY: help build test test-all clean fmt lint coverage docs bench audit install-tools ci-local

# Default target
help:
	@echo "SIGMA Engine Development Commands"
	@echo "============================="
	@echo ""
	@echo "Development:"
	@echo "  build         - Build the project"
	@echo "  test          - Run unit and integration tests"
	@echo "  test-all      - Run all tests including doc tests"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt           - Format code with rustfmt"
	@echo "  lint          - Run clippy linter"
	@echo "  coverage      - Generate code coverage report"
	@echo "  docs          - Build documentation"
	@echo "  audit         - Run security audit"
	@echo "  quality       - Run comprehensive quality checks"
	@echo ""
	@echo "Performance:"
	@echo "  bench         - Run performance benchmarks"
	@echo "  bench-e2e     - Run end-to-end benchmarks"
	@echo "  bench-scaling - Run rule scaling benchmarks"
	@echo ""
	@echo "CI/CD:"
	@echo "  install-tools - Install required development tools"
	@echo "  ci-local      - Run full CI pipeline locally"
	@echo "  setup-hooks   - Set up git hooks for quality checks"
	@echo ""

build:
	@echo "Building SIGMA Engine..."
	cargo build

build-release:
	@echo "Building SIGMA Engine (release)..."
	cargo build --release

test:
	@echo "Running tests..."
	cargo test --all-features

test-all: test
	@echo "Running doc tests..."
	cargo test --doc

# Code quality targets
fmt:
	@echo "Formatting code..."
	cargo fmt --all

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt --all -- --check

lint:
	@echo "Running clippy linter..."
	cargo clippy --all-targets --all-features -- -D warnings

coverage:
	@echo "Generating coverage report..."
	@./scripts/coverage.sh

docs:
	@echo "Building documentation..."
	cargo doc --all-features --no-deps --open

quality:
	@echo "Running comprehensive quality checks..."
	@./scripts/quality.sh

# Performance targets
bench:
	@echo "Running all benchmarks..."
	cargo bench

bench-e2e:
	@echo "Running end-to-end benchmarks..."
	cargo bench --bench end_to_end

bench-scaling:
	@echo "Running rule scaling benchmarks..."
	cargo bench --bench rule_scaling

# Security and maintenance
audit:
	@echo "Running security audit..."
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed. Run 'make install-tools' first."; \
		exit 1; \
	fi

# Development tools installation
install-tools:
	@echo "Installing development tools..."
	@echo " Installing cargo-tarpaulin (coverage)..."
	cargo install cargo-tarpaulin
	@echo "Installing cargo-audit (security)..."
	cargo install cargo-audit
	@echo "Installing cargo-flamegraph (profiling)..."
	cargo install flamegraph
	@echo "All tools installed successfully!"

# CI pipeline simulation
ci-local: fmt-check lint test-all coverage audit docs
	@echo ""
	@echo "Local CI pipeline completed successfully!"
	@echo "All checks passed - ready for commit/push"

# Utility targets
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/coverage
	rm -rf target/criterion
	rm -rf target/flamegraphs

# Demo targets

demo-2k:
	@echo "Running 2k rules demo..."
	@./scripts/demo_2k_rules.sh

profile-vm:
	@echo "Profiling VM execution..."
	@./scripts/profile.sh

profile-scaling:
	@echo "Profiling rule scaling..."
	cargo flamegraph --bench rule_scaling --output target/flamegraphs/rule_scaling.svg

dev-setup: install-tools setup-hooks
	@echo "Setting up development environment..."
	@echo "Development environment ready!"

setup-hooks:
	@echo "Setting up git hooks..."
	@./scripts/setup-hooks.sh

quick-check: fmt lint test
	@echo "Quick development check completed!"

full-check: ci-local
	@echo "Full quality check completed!"

pre-release: clean ci-local bench
	@echo "Pre-release checks completed!"
	@echo "Ready for release!"
