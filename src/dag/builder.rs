//! DAG builder for converting IR bytecode to optimized DAG representation.

use super::prefilter::LiteralPrefilter;
use super::types::{CompiledDag, DagNode, LogicalOp, NodeId, NodeType};
use crate::compiler::parser::{parse_tokens, tokenize_condition, ConditionAst};
use crate::error::{Result, SigmaError};
use crate::ir::{CompiledRuleset, Primitive, PrimitiveId, RuleId};
use std::collections::{HashMap, VecDeque};

/// Builder for constructing optimized DAGs from IR bytecode.
pub struct DagBuilder {
    /// Nodes being constructed
    nodes: Vec<DagNode>,

    /// Next available node ID
    next_node_id: NodeId,

    /// Mapping from primitive IDs to their DAG nodes
    primitive_nodes: HashMap<PrimitiveId, NodeId>,

    /// Mapping from rule IDs to their result nodes
    rule_result_nodes: HashMap<RuleId, NodeId>,

    /// Enable optimization passes
    enable_optimization: bool,

    /// Enable literal prefiltering
    enable_prefilter: bool,

    /// Prefilter for literal pattern matching
    prefilter: Option<LiteralPrefilter>,
}

impl DagBuilder {
    /// Create a new DAG builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            next_node_id: 0,
            primitive_nodes: HashMap::new(),
            rule_result_nodes: HashMap::new(),

            enable_optimization: true,
            enable_prefilter: true,
            prefilter: None,
        }
    }

    /// Enable or disable optimization passes.
    pub fn with_optimization(mut self, enable: bool) -> Self {
        self.enable_optimization = enable;
        self
    }

    /// Enable or disable literal prefiltering.
    pub fn with_prefilter(mut self, enable: bool) -> Self {
        self.enable_prefilter = enable;
        self
    }

    /// Build DAG from a compiled ruleset.
    pub fn from_ruleset(mut self, ruleset: &CompiledRuleset) -> Self {
        // First pass: Create primitive nodes (shared across rules)
        for &primitive_id in ruleset.primitive_map.values() {
            let node_id = self.create_primitive_node(primitive_id);
            self.primitive_nodes.insert(primitive_id, node_id);
        }

        // Second pass: For each rule, build condition subgraph and result node
        for rule in &ruleset.rules {
            // Tokenize and parse the condition string into AST
            if let Ok(tokens) = tokenize_condition(&rule.condition) {
                if let Ok(ast) = parse_tokens(&tokens, &rule.selections) {
                    if let Ok(root_id) = self.build_condition_subgraph(&ast, &rule.selections) {
                        // Create result node and wire dependency
                        let result_node = self.create_result_node(rule.rule_id);
                        self.add_dependency(result_node, root_id);
                        self.rule_result_nodes.insert(rule.rule_id, result_node);
                    }
                }
            }
        }

        self
    }

    /// Build DAG from primitives with prefilter support.
    pub fn from_primitives(mut self, primitives: &[Primitive]) -> Result<Self> {
        // Build prefilter if enabled
        if self.enable_prefilter {
            match LiteralPrefilter::from_primitives(primitives) {
                Ok(prefilter) => {
                    // Only add prefilter if it has patterns
                    if prefilter.stats().pattern_count > 0 {
                        let prefilter_node_id = self.create_prefilter_node(&prefilter);
                        self.prefilter = Some(prefilter);

                        // Make all primitive nodes depend on the prefilter
                        for node in &mut self.nodes {
                            if matches!(node.node_type, NodeType::Primitive { .. }) {
                                node.add_dependency(prefilter_node_id);
                            }
                        }
                    }
                }
                Err(_) => {
                    // If prefilter creation fails, continue without it
                    self.enable_prefilter = false;
                }
            }
        }

        // Create primitive nodes
        for (primitive_id, _primitive) in primitives.iter().enumerate() {
            let node_id = self.create_primitive_node(primitive_id as PrimitiveId);
            self.primitive_nodes
                .insert(primitive_id as PrimitiveId, node_id);
        }

        Ok(self)
    }

    /// Enable optimization passes.
    pub fn optimize(mut self) -> Self {
        if self.enable_optimization {
            self.perform_optimizations();
        }
        self
    }

    /// Build the final compiled DAG.
    pub fn build(self) -> Result<CompiledDag> {
        // Perform topological sort for execution order
        let execution_order = self.topological_sort()?;

        // Validate the DAG structure
        self.validate_dag_structure()?;

        let dag = CompiledDag {
            nodes: self.nodes,
            execution_order,
            primitive_map: self.primitive_nodes,
            rule_results: self.rule_result_nodes,
            result_buffer_size: self.next_node_id as usize,
        };

        // Final validation
        dag.validate()?;

        Ok(dag)
    }

    /// Create a new primitive node.
    fn create_primitive_node(&mut self, primitive_id: PrimitiveId) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(node_id, NodeType::Primitive { primitive_id });
        self.nodes.push(node);

        node_id
    }

    /// Ensure or create primitive node for a given primitive id, returning its node id.
    fn ensure_primitive_node(&mut self, primitive_id: PrimitiveId) -> NodeId {
        if let Some(&nid) = self.primitive_nodes.get(&primitive_id) {
            return nid;
        }
        let nid = self.create_primitive_node(primitive_id);
        self.primitive_nodes.insert(primitive_id, nid);
        nid
    }

    /// Create a new logical node.
    fn create_logical_node(&mut self, operation: LogicalOp) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;
        let node = DagNode::new(node_id, NodeType::Logical { operation });
        self.nodes.push(node);
        node_id
    }

    /// Create a new result node.
    fn create_result_node(&mut self, rule_id: RuleId) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;
        let node = DagNode::new(node_id, NodeType::Result { rule_id });
        self.nodes.push(node);
        node_id
    }

    /// Add a dependency relationship between nodes (dependent depends on dependency).
    fn add_dependency(&mut self, dependent_id: NodeId, dependency_id: NodeId) {
        if let Some(dep_node) = self.nodes.get_mut(dependent_id as usize) {
            dep_node.add_dependency(dependency_id);
        }
        if let Some(base_node) = self.nodes.get_mut(dependency_id as usize) {
            base_node.add_dependent(dependent_id);
        }
    }

    /// Create a new prefilter node.
    fn create_prefilter_node(&mut self, prefilter: &LiteralPrefilter) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(
            node_id,
            NodeType::Prefilter {
                prefilter_id: 0, // Single prefilter for now
                pattern_count: prefilter.stats().pattern_count,
            },
        );
        self.nodes.push(node);

        node_id
    }

    /// Build a condition subgraph for a rule and return the root node id.
    fn build_condition_subgraph(
        &mut self,
        ast: &ConditionAst,
        selection_map: &HashMap<String, Vec<PrimitiveId>>,
    ) -> Result<NodeId> {
        match ast {
            ConditionAst::Identifier(name) => {
                let primitive_ids = selection_map.get(name).ok_or_else(|| {
                    SigmaError::CompilationError(format!("Unknown selection: {name}"))
                })?;
                if primitive_ids.is_empty() {
                    return Err(SigmaError::CompilationError(format!(
                        "Empty selection: {name}"
                    )));
                }
                if primitive_ids.len() == 1 {
                    Ok(self.ensure_primitive_node(primitive_ids[0]))
                } else {
                    // Implicit AND of all primitives in selection
                    let and_node = self.create_logical_node(LogicalOp::And);
                    for &pid in primitive_ids {
                        let pnode = self.ensure_primitive_node(pid);
                        self.add_dependency(and_node, pnode);
                    }
                    Ok(and_node)
                }
            }
            ConditionAst::And(l, r) => {
                let ln = self.build_condition_subgraph(l, selection_map)?;
                let rn = self.build_condition_subgraph(r, selection_map)?;
                let and_node = self.create_logical_node(LogicalOp::And);
                self.add_dependency(and_node, ln);
                self.add_dependency(and_node, rn);
                Ok(and_node)
            }
            ConditionAst::Or(l, r) => {
                let ln = self.build_condition_subgraph(l, selection_map)?;
                let rn = self.build_condition_subgraph(r, selection_map)?;
                let or_node = self.create_logical_node(LogicalOp::Or);
                self.add_dependency(or_node, ln);
                self.add_dependency(or_node, rn);
                Ok(or_node)
            }
            ConditionAst::Not(o) => {
                let on = self.build_condition_subgraph(o, selection_map)?;
                let not_node = self.create_logical_node(LogicalOp::Not);
                self.add_dependency(not_node, on);
                Ok(not_node)
            }
            ConditionAst::OneOfThem => {
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut any = false;
                for primitive_ids in selection_map.values() {
                    for &pid in primitive_ids {
                        let pnode = self.ensure_primitive_node(pid);
                        self.add_dependency(or_node, pnode);
                        any = true;
                    }
                }
                if !any {
                    return Err(SigmaError::CompilationError(
                        "No primitives found for 'one of them'".to_string(),
                    ));
                }
                Ok(or_node)
            }
            ConditionAst::AllOfThem => {
                let and_node = self.create_logical_node(LogicalOp::And);
                let mut any = false;
                for primitive_ids in selection_map.values() {
                    for &pid in primitive_ids {
                        let pnode = self.ensure_primitive_node(pid);
                        self.add_dependency(and_node, pnode);
                        any = true;
                    }
                }
                if !any {
                    return Err(SigmaError::CompilationError(
                        "No primitives found for 'all of them'".to_string(),
                    ));
                }
                Ok(and_node)
            }
            ConditionAst::OneOfPattern(pattern) => {
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut matched = false;
                for (sel, primitive_ids) in selection_map {
                    if sel.contains(pattern) {
                        for &pid in primitive_ids {
                            let pnode = self.ensure_primitive_node(pid);
                            self.add_dependency(or_node, pnode);
                            matched = true;
                        }
                    }
                }
                if !matched {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {pattern}"
                    )));
                }
                Ok(or_node)
            }
            ConditionAst::AllOfPattern(pattern) => {
                let and_node = self.create_logical_node(LogicalOp::And);
                let mut matched = false;
                for (sel, primitive_ids) in selection_map {
                    if sel.contains(pattern) {
                        for &pid in primitive_ids {
                            let pnode = self.ensure_primitive_node(pid);
                            self.add_dependency(and_node, pnode);
                            matched = true;
                        }
                    }
                }
                if !matched {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {pattern}"
                    )));
                }
                Ok(and_node)
            }
            ConditionAst::CountOfPattern(_count, pattern) => {
                // Simplified as one-of-pattern for now
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut matched = false;
                for (sel, primitive_ids) in selection_map {
                    if sel.contains(pattern) {
                        for &pid in primitive_ids {
                            let pnode = self.ensure_primitive_node(pid);
                            self.add_dependency(or_node, pnode);
                            matched = true;
                        }
                    }
                }
                if !matched {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {pattern}"
                    )));
                }
                Ok(or_node)
            }
        }
    }

    /// Perform optimization passes on the DAG.
    fn perform_optimizations(&mut self) {
        // Apply optimizations using the DagOptimizer
        if let Ok(dag) = self.build_temporary_dag() {
            if let Ok(optimized_dag) = self.apply_dag_optimizations(dag) {
                self.update_from_optimized_dag(optimized_dag);
            }
        }
    }

    /// Build a temporary DAG for optimization.
    fn build_temporary_dag(&self) -> Result<CompiledDag> {
        // Perform topological sort for execution order
        let execution_order = self.topological_sort()?;

        // Validate the DAG structure
        self.validate_dag_structure()?;

        Ok(CompiledDag {
            nodes: self.nodes.clone(),
            execution_order,
            primitive_map: self.primitive_nodes.clone(),
            rule_results: self.rule_result_nodes.clone(),
            result_buffer_size: self.next_node_id as usize,
        })
    }

    /// Apply DAG optimizations using the DagOptimizer.
    fn apply_dag_optimizations(&self, dag: CompiledDag) -> Result<CompiledDag> {
        use super::optimizer::DagOptimizer;

        let optimizer = DagOptimizer::new().with_cse(true).with_dce(true);

        optimizer.optimize(dag)
    }

    /// Update builder state from optimized DAG.
    fn update_from_optimized_dag(&mut self, optimized_dag: CompiledDag) {
        self.nodes = optimized_dag.nodes;
        self.primitive_nodes = optimized_dag.primitive_map;
        self.rule_result_nodes = optimized_dag.rule_results;

        // Update next_node_id to be safe, preserving zero-based contiguous IDs invariant
        if self.nodes.is_empty() {
            self.next_node_id = 0;
        } else {
            self.next_node_id = self.nodes.iter().map(|n| n.id).max().unwrap_or(0) + 1;
        }
    }

    /// Perform topological sort to determine execution order.
    fn topological_sort(&self) -> Result<Vec<NodeId>> {
        let mut in_degree = vec![0; self.nodes.len()];
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        // Calculate in-degrees
        for node in &self.nodes {
            for &dep_id in &node.dependencies {
                if (dep_id as usize) < in_degree.len() {
                    in_degree[node.id as usize] += 1;
                }
            }
        }

        // Find nodes with no dependencies
        for (node_id, &degree) in in_degree.iter().enumerate() {
            if degree == 0 {
                queue.push_back(node_id as NodeId);
            }
        }

        // Process nodes in topological order
        while let Some(node_id) = queue.pop_front() {
            result.push(node_id);

            if let Some(node) = self.nodes.get(node_id as usize) {
                for &dependent_id in &node.dependents {
                    if (dependent_id as usize) < in_degree.len() {
                        in_degree[dependent_id as usize] -= 1;
                        if in_degree[dependent_id as usize] == 0 {
                            queue.push_back(dependent_id);
                        }
                    }
                }
            }
        }

        if result.len() != self.nodes.len() {
            return Err(SigmaError::CompilationError(
                "Cycle detected in DAG".to_string(),
            ));
        }

        Ok(result)
    }

    /// Validate the DAG structure for correctness.
    fn validate_dag_structure(&self) -> Result<()> {
        // Check that all rule result nodes exist
        for &rule_id in self.rule_result_nodes.keys() {
            if !self.rule_result_nodes.contains_key(&rule_id) {
                return Err(SigmaError::CompilationError(format!(
                    "Missing result node for rule: {rule_id}"
                )));
            }
        }

        // Check that all dependencies are valid
        for node in &self.nodes {
            for &dep_id in &node.dependencies {
                if dep_id as usize >= self.nodes.len() {
                    return Err(SigmaError::CompilationError(format!(
                        "Invalid dependency: {} -> {}",
                        node.id, dep_id
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Default for DagBuilder {
    fn default() -> Self {
        Self::new()
    }
}
