import pytest
from app.services.log_analyzer import (
    analyze_logs, parse_log_line, classify_severity,
    EventQueue, EventHashTable, EventBST, OperationStack
)

def test_queue_fifo():
    q = EventQueue()
    q.enqueue("a")
    q.enqueue("b")
    q.enqueue("c")
    assert q.dequeue() == "a"
    assert q.dequeue() == "b"

def test_hashtable_lookup():
    ht = EventHashTable()
    ht.put("evt-1", {"msg": "test"})
    assert ht.get("evt-1") == {"msg": "test"}
    assert ht.get("evt-99") is None
    assert ht.contains("evt-1") is True

def test_bst_ordered():
    bst = EventBST()
    bst.insert("2024-01-03", "c")
    bst.insert("2024-01-01", "a")
    bst.insert("2024-01-02", "b")
    ordered = bst.inorder()
    assert ordered == ["a", "b", "c"]

def test_bst_range_query():
    bst = EventBST()
    bst.insert("2024-01-01", "day1")
    bst.insert("2024-01-05", "day5")
    bst.insert("2024-01-10", "day10")
    found = bst.range_query("2024-01-02", "2024-01-07")
    assert "day5" in found
    assert "day1" not in found

def test_stack_operations():
    s = OperationStack()
    s.push("op1")
    s.push("op2")
    assert s.peek() == "op2"
    popped = s.pop()
    assert popped == "op2"
    assert s.peek() == "op1"

def test_classify_severity():
    assert classify_severity("ERROR: connection refused") == "high"
    assert classify_severity("WARNING: too many requests") == "medium"
    assert classify_severity("critical disk failure") == "critical"

def test_parse_json_line():
    line = "{\"timestamp\": \"2024-01-01T10:00:00\", \"level\": \"error\", \"message\": \"Failed login attempt\", \"source_ip\": \"1.2.3.4\"}"
    evt = parse_log_line(line, 0)
    assert evt is not None
    assert evt.source_ip == "1.2.3.4"
    assert evt.severity in ("high", "critical")

def test_analyze_brute_force_detection():
    lines = "\n".join([
        f"2024-01-01 10:{i:02d}:00 Failed password for user admin from 192.168.50.100"
        for i in range(6)
    ])
    result = analyze_logs(lines)
    assert "192.168.50.100" in result["brute_force_ips"]

def test_analyze_empty_logs():
    result = analyze_logs("")
    assert result["total_entries"] == 0
