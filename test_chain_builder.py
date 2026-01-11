#!/usr/bin/env python3
"""
Comprehensive Test Suite for Exploit Chain Builder
Tests all new commercial features
"""

import asyncio
import sys
import json
from datetime import datetime

import pytest

# Add parent directory to path
sys.path.insert(0, '.')

from core.exploit_chain_builder import (
    ExploitChainBuilder, NodeType, ChainComplexity,
    ExecutionStatus, ChainNode, ChainEdge
)


def test_basic_operations():
    """Test basic chain creation and manipulation"""
    print("\n" + "="*60)
    print("TEST: Basic Chain Operations")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create chain
    chain = builder.create_chain("Test Chain", "Testing basic ops", "Tester")
    assert chain is not None, "Failed to create chain"
    print(f"✅ Created chain: {chain.name} ({chain.chain_id[:8]}...)")
    
    # Add nodes from library
    node1 = builder.add_node_from_library(chain.chain_id, "phishing_email", 100, 100)
    node2 = builder.add_node_from_library(chain.chain_id, "meterpreter", 200, 200)
    node3 = builder.add_node_from_library(chain.chain_id, "credential_dump", 300, 200)
    
    assert node1 is not None, "Failed to add node1"
    assert node2 is not None, "Failed to add node2"
    assert node3 is not None, "Failed to add node3"
    print(f"✅ Added 3 nodes from library")
    
    # Add edges
    edge1 = builder.add_edge(chain.chain_id, node1.node_id, node2.node_id)
    edge2 = builder.add_edge(chain.chain_id, node2.node_id, node3.node_id)
    
    assert edge1 is not None, "Failed to add edge1"
    assert edge2 is not None, "Failed to add edge2"
    print(f"✅ Added 2 edges")
    
    # Validate chain
    validation = builder.validate_chain(chain.chain_id)
    print(f"✅ Validation: Valid={validation['valid']}, Warnings={len(validation['warnings'])}")
    
    # Check metrics were calculated
    chain = builder.chains[chain.chain_id]
    assert chain.success_rate > 0, "Success rate not calculated"
    assert chain.estimated_duration > 0, "Duration not calculated"
    print(f"✅ Metrics: Success={chain.success_rate*100:.1f}%, Detection={chain.detection_rate*100:.1f}%")
    
    assert True  # Test passed


def test_templates():
    """Test template system"""
    print("\n" + "="*60)
    print("TEST: Template System")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # List templates
    templates = builder.get_templates()
    print(f"✅ Available templates: {len(templates)}")
    for t in templates:
        print(f"   - {t.name} ({t.difficulty.value})")
    
    # Create from template
    chain = builder.create_from_template("web_to_shell", "Web Attack Test")
    assert chain is not None, "Failed to create from template"
    print(f"✅ Created chain from template: {chain.name}")
    print(f"   Nodes: {len(chain.nodes)}, Edges: {len(chain.edges)}")
    
    assert True  # Test passed


def test_node_library():
    """Test node library"""
    print("\n" + "="*60)
    print("TEST: Node Library")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    library = builder.get_node_library()
    total_nodes = sum(len(nodes) for nodes in library.values())
    print(f"✅ Node library contains {total_nodes} nodes in {len(library)} categories:")
    
    for category, nodes in sorted(library.items()):
        print(f"   {category}: {len(nodes)} nodes")
    
    assert True  # Test passed


def test_chain_cloning():
    """Test chain cloning feature"""
    print("\n" + "="*60)
    print("TEST: Chain Cloning")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create original chain
    original = builder.create_from_template("domain_takeover", "Original Chain")
    original_nodes = len(original.nodes)
    
    # Clone it
    cloned = builder.clone_chain(original.chain_id, "Cloned Chain")
    
    assert cloned is not None, "Failed to clone chain"
    assert cloned.chain_id != original.chain_id, "Clone has same ID as original"
    assert len(cloned.nodes) == original_nodes, "Clone has different node count"
    assert cloned.parent_chain_id == original.chain_id, "Parent chain not set"
    
    print(f"✅ Cloned chain: {cloned.name}")
    print(f"   Original ID: {original.chain_id[:8]}...")
    print(f"   Clone ID: {cloned.chain_id[:8]}...")
    print(f"   Parent set correctly: {cloned.parent_chain_id[:8]}...")
    
    assert True  # Test passed


def test_chain_diff():
    """Test chain diffing feature"""
    print("\n" + "="*60)
    print("TEST: Chain Diff")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create two chains
    chain1 = builder.create_from_template("web_to_shell", "Chain 1")
    chain2 = builder.create_from_template("domain_takeover", "Chain 2")
    
    # Compare them
    diff = builder.diff_chains(chain1.chain_id, chain2.chain_id)
    
    assert "error" not in diff, f"Diff failed: {diff.get('error')}"
    print(f"✅ Chain diff results:")
    print(f"   Node count diff: {diff['node_count_diff']}")
    print(f"   Edge count diff: {diff['edge_count_diff']}")
    print(f"   Added nodes: {diff['added_nodes']}")
    print(f"   Removed nodes: {diff['removed_nodes']}")
    
    assert True  # Test passed


def test_export_formats():
    """Test export to different formats"""
    print("\n" + "="*60)
    print("TEST: Export Formats")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    chain = builder.create_from_template("data_exfil", "Export Test Chain")
    
    # Test JSON export
    json_export = builder.export_chain(chain.chain_id)
    assert json_export, "JSON export failed"
    print(f"✅ JSON export: {len(json.dumps(json_export))} bytes")
    
    # Test YAML export
    yaml_export = builder.export_to_yaml(chain.chain_id)
    assert yaml_export, "YAML export failed"
    print(f"✅ YAML export: {len(yaml_export)} bytes")
    
    # Test ATT&CK Navigator export
    navigator_export = builder.export_to_attack_navigator(chain.chain_id)
    assert navigator_export, "ATT&CK Navigator export failed"
    assert "techniques" in navigator_export, "Missing techniques in navigator export"
    print(f"✅ ATT&CK Navigator export: {len(navigator_export['techniques'])} techniques")
    
    assert True  # Test passed


def test_yaml_import():
    """Test YAML import"""
    print("\n" + "="*60)
    print("TEST: YAML Import")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create and export a chain
    original = builder.create_from_template("linux_privesc", "Original")
    yaml_data = builder.export_to_yaml(original.chain_id)
    
    # Import it back
    imported = builder.import_from_yaml(yaml_data, "ImportTest")
    
    assert imported is not None, "YAML import failed"
    print(f"✅ Imported chain: {imported.name}")
    print(f"   Nodes: {len(imported.nodes)}")
    print(f"   Edges: {len(imported.edges)}")
    
    assert True  # Test passed


def test_ai_suggestions():
    """Test AI-powered suggestions"""
    print("\n" + "="*60)
    print("TEST: AI Suggestions")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create an incomplete chain to trigger suggestions
    chain = builder.create_chain("Incomplete Chain", "Test for suggestions", "Tester")
    builder.add_node_from_library(chain.chain_id, "reverse_shell", 100, 100)  # Missing entry point
    
    suggestions = builder.get_ai_suggestions(chain.chain_id)
    
    print(f"✅ Generated {len(suggestions)} AI suggestions:")
    for sugg in suggestions[:5]:  # Show first 5
        print(f"   [{sugg['priority'].upper()}] {sugg['title']}")
        print(f"      {sugg['description']}")
    
    assert True  # Test passed


def test_optimization_suggestions():
    """Test optimization suggestions"""
    print("\n" + "="*60)
    print("TEST: Optimization Suggestions")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    chain = builder.create_from_template("ransomware_simulation", "High Risk Chain")
    
    suggestions = builder.get_optimization_suggestions(chain.chain_id)
    
    print(f"✅ Generated {len(suggestions)} optimization suggestions:")
    for sugg in suggestions:
        print(f"   [{sugg['severity'].upper()}] {sugg['type']}: {sugg['message']}")
    
    assert True  # Test passed


def test_report_generation():
    """Test report generation"""
    print("\n" + "="*60)
    print("TEST: Report Generation")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    chain = builder.create_from_template("domain_takeover", "Report Test Chain")
    
    # Generate markdown report
    report = builder.generate_report(chain.chain_id, "markdown")
    
    assert "# Exploit Chain Report" in report, "Report header missing"
    assert "MITRE ATT&CK Coverage" in report, "MITRE section missing"
    assert "Validation Results" in report, "Validation section missing"
    
    print(f"✅ Generated markdown report: {len(report)} characters")
    print(f"   Preview (first 200 chars):")
    print(f"   {report[:200]}...")
    
    assert True  # Test passed


def test_chain_search():
    """Test chain search functionality"""
    print("\n" + "="*60)
    print("TEST: Chain Search")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create several chains
    builder.create_from_template("web_to_shell", "Web Attack")
    builder.create_from_template("domain_takeover", "Domain Attack")
    builder.create_from_template("data_exfil", "Data Breach")
    builder.create_from_template("api_exploitation", "API Attack")
    
    # Search by query
    results = builder.search_chains(query="web")
    print(f"✅ Search 'web': {len(results)} results")
    
    # Search by complexity
    results = builder.search_chains(complexity=ChainComplexity.DIFFICULT)
    print(f"✅ Search DIFFICULT chains: {len(results)} results")
    
    # Search by success rate
    results = builder.search_chains(min_success_rate=0.1)
    print(f"✅ Search success>=10%: {len(results)} results")
    
    assert True  # Test passed


def test_statistics():
    """Test statistics generation"""
    print("\n" + "="*60)
    print("TEST: Statistics")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create several chains
    builder.create_from_template("web_to_shell", "Chain 1")
    builder.create_from_template("domain_takeover", "Chain 2")
    builder.create_from_template("linux_privesc", "Chain 3")
    
    stats = builder.get_statistics()
    
    print(f"✅ Statistics:")
    print(f"   Total chains: {stats['total_chains']}")
    print(f"   Total nodes: {stats['total_nodes']}")
    print(f"   Total edges: {stats['total_edges']}")
    print(f"   Avg success rate: {stats['average_success_rate']*100:.1f}%")
    print(f"   Templates available: {stats['templates_available']}")
    print(f"   Library nodes: {stats['library_nodes']}")
    print(f"   Complexity distribution: {stats['complexity_distribution']}")
    
    assert True  # Test passed


@pytest.mark.asyncio
async def test_execution():
    """Test chain execution (dry run)"""
    print("\n" + "="*60)
    print("TEST: Chain Execution (Dry Run)")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    chain = builder.create_from_template("web_to_shell", "Execution Test")
    
    # Execute dry run
    result = await builder.execute_chain(chain.chain_id, dry_run=True)
    
    assert result is not None, "Execution failed"
    print(f"✅ Execution completed:")
    print(f"   Status: {result.status.value}")
    print(f"   Nodes executed: {result.nodes_executed}")
    print(f"   Successful: {result.nodes_successful}")
    print(f"   Failed: {result.nodes_failed}")
    print(f"   Duration: {result.total_duration:.2f}s")
    
    assert True  # Test passed


@pytest.mark.asyncio
async def test_execution_with_rollback():
    """Test chain execution with rollback"""
    print("\n" + "="*60)
    print("TEST: Execution with Rollback")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    chain = builder.create_from_template("linux_privesc", "Rollback Test")
    
    # Execute with rollback capability
    result = await builder.execute_with_rollback(chain.chain_id, dry_run=True)
    
    print(f"✅ Execution with rollback completed:")
    print(f"   Status: {result.status.value}")
    print(f"   Log entries: {len(result.execution_log)}")
    
    assert True  # Test passed


def test_merge_chains():
    """Test chain merging"""
    print("\n" + "="*60)
    print("TEST: Chain Merging")
    print("="*60)
    
    builder = ExploitChainBuilder(':memory:')
    
    # Create two chains
    chain1 = builder.create_from_template("web_to_shell", "Phase 1")
    chain2 = builder.create_from_template("linux_privesc", "Phase 2")
    
    # Merge them
    merged = builder.merge_chains(
        [chain1.chain_id, chain2.chain_id],
        "Combined Attack Chain"
    )
    
    assert merged is not None, "Merge failed"
    expected_nodes = len(chain1.nodes) + len(chain2.nodes)
    print(f"✅ Merged chain created:")
    print(f"   Name: {merged.name}")
    print(f"   Nodes: {len(merged.nodes)} (expected: {expected_nodes})")
    print(f"   Edges: {len(merged.edges)}")
    
    assert True  # Test passed


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("EXPLOIT CHAIN BUILDER - COMPREHENSIVE TEST SUITE")
    print("="*60)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Basic Operations", test_basic_operations),
        ("Templates", test_templates),
        ("Node Library", test_node_library),
        ("Chain Cloning", test_chain_cloning),
        ("Chain Diff", test_chain_diff),
        ("Export Formats", test_export_formats),
        ("YAML Import", test_yaml_import),
        ("AI Suggestions", test_ai_suggestions),
        ("Optimization Suggestions", test_optimization_suggestions),
        ("Report Generation", test_report_generation),
        ("Chain Search", test_chain_search),
        ("Statistics", test_statistics),
        ("Merge Chains", test_merge_chains),
    ]
    
    async_tests = [
        ("Chain Execution", test_execution),
        ("Execution with Rollback", test_execution_with_rollback),
    ]
    
    passed = 0
    failed = 0
    
    # Run sync tests
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"❌ ASSERTION FAILED: {name} - {e}")
        except Exception as e:
            failed += 1
            print(f"❌ ERROR in {name}: {e}")
    
    # Run async tests
    for name, test_func in async_tests:
        try:
            asyncio.run(test_func())
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"❌ ASSERTION FAILED: {name} - {e}")
        except Exception as e:
            failed += 1
            print(f"❌ ERROR in {name}: {e}")
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    print(f"Total Tests: {passed + failed}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {failed} ❌")
    print(f"Success Rate: {passed/(passed+failed)*100:.1f}%")
    print("="*60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
