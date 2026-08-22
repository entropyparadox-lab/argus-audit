use crate::rules::{AnomalyAlert, RuleEngine};
use argus_common::events::ProcessExec;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub argv: Vec<String>,
    pub alerts: Vec<AnomalyAlert>,
    pub children: Vec<ProcessNode>,
}

pub struct ProcessTreeBuilder;

impl ProcessTreeBuilder {
    /// Build a hierarchical process tree from a flat list of ProcessExec events
    pub fn build_tree(events: &[ProcessExec]) -> Vec<ProcessNode> {
        let mut nodes: HashMap<u32, ProcessNode> = HashMap::new();
        let mut ppid_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut all_pids = HashSet::new();

        for exec in events {
            let alerts = RuleEngine::inspect_process(exec);
            let node = ProcessNode {
                pid: exec.pid,
                ppid: exec.ppid,
                comm: exec.comm.clone(),
                argv: exec.argv.clone(),
                alerts,
                children: Vec::new(),
            };

            nodes.insert(exec.pid, node);
            ppid_map.entry(exec.ppid).or_default().push(exec.pid);
            all_pids.insert(exec.pid);
        }

        // Find root nodes (processes whose parent PID is not in this session's events)
        let root_pids: Vec<u32> = events
            .iter()
            .map(|e| e.pid)
            .filter(|pid| {
                let ppid = nodes.get(pid).map(|n| n.ppid).unwrap_or(0);
                !all_pids.contains(&ppid)
            })
            .collect();

        // Recursively build tree
        fn assemble(
            pid: u32,
            nodes: &HashMap<u32, ProcessNode>,
            ppid_map: &HashMap<u32, Vec<u32>>,
        ) -> Option<ProcessNode> {
            let mut node = nodes.get(&pid)?.clone();
            if let Some(child_pids) = ppid_map.get(&pid) {
                for &cpid in child_pids {
                    if let Some(child_node) = assemble(cpid, nodes, ppid_map) {
                        node.children.push(child_node);
                    }
                }
            }
            Some(node)
        }

        let mut roots = Vec::new();
        for rpid in root_pids {
            if let Some(root_node) = assemble(rpid, &nodes, &ppid_map) {
                roots.push(root_node);
            }
        }

        roots
    }

    /// Render process trees into human-readable ASCII/Unicode tree
    pub fn render_ascii(roots: &[ProcessNode]) -> String {
        let mut output = String::new();

        fn render_node(node: &ProcessNode, prefix: &str, is_last: bool, out: &mut String) {
            let branch = if is_last { "└── " } else { "├── " };
            let alert_marker = if !node.alerts.is_empty() {
                format!(" ⚠️ [{:?}]", node.alerts[0].severity)
            } else {
                String::new()
            };

            out.push_str(&format!(
                "{}{}{} (PID: {}) -> {}{}\n",
                prefix,
                branch,
                node.comm,
                node.pid,
                node.argv.join(" "),
                alert_marker
            ));

            let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
            let len = node.children.len();
            for (i, child) in node.children.iter().enumerate() {
                render_node(child, &next_prefix, i == len - 1, out);
            }
        }

        for (i, root) in roots.iter().enumerate() {
            render_node(root, "", i == roots.len() - 1, &mut output);
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_process_tree_lineage() {
        let events = vec![
            ProcessExec {
                session_id: None,
                timestamp: Utc::now(),
                pid: 1000,
                ppid: 999, // Root
                uid: 1000,
                gid: 1000,
                comm: "bash".into(),
                argv: vec!["bash".into()],
                cwd: Some("/home/ubuntu".into()),
                exit_code: Some(0),
            },
            ProcessExec {
                session_id: None,
                timestamp: Utc::now(),
                pid: 1005,
                ppid: 1000, // Child of bash
                uid: 1000,
                gid: 1000,
                comm: "python".into(),
                argv: vec!["python".into(), "script.py".into()],
                cwd: Some("/home/ubuntu".into()),
                exit_code: Some(0),
            },
            ProcessExec {
                session_id: None,
                timestamp: Utc::now(),
                pid: 1006,
                ppid: 1005, // Child of python (grandchild of bash)
                uid: 1000,
                gid: 1000,
                comm: "curl".into(),
                argv: vec!["curl".into(), "http://example.com".into()],
                cwd: Some("/home/ubuntu".into()),
                exit_code: Some(0),
            },
        ];

        let roots = ProcessTreeBuilder::build_tree(&events);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].pid, 1000);
        assert_eq!(roots[0].children.len(), 1);
        assert_eq!(roots[0].children[0].pid, 1005);
        assert_eq!(roots[0].children[0].children.len(), 1);
        assert_eq!(roots[0].children[0].children[0].pid, 1006);

        let rendered = ProcessTreeBuilder::render_ascii(&roots);
        println!("\nRendered Tree:\n{}", rendered);
        assert!(rendered.contains("bash (PID: 1000)"));
        assert!(rendered.contains("python (PID: 1005)"));
        assert!(rendered.contains("curl (PID: 1006)"));
    }
}
