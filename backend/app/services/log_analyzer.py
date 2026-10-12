"""
Log Analyzer with functional data structures:
- Queue: for ordered event processing (FIFO)
- HashTable: fast O(1) lookup by event ID
- BST: ordered temporal event lookup
- Stack: recent operations / undo history
"""
import re
import json
import datetime
import heapq
from typing import Optional, List
from collections import deque, defaultdict
from dataclasses import dataclass, field

# =================== DATA STRUCTURES ===================

class EventQueue:
    """FIFO queue for sequential log event processing. O(1) enqueue/dequeue."""
    def __init__(self):
        self._q = deque()
    def enqueue(self, item): self._q.append(item)
    def dequeue(self): return self._q.popleft() if self._q else None
    def peek(self): return self._q[0] if self._q else None
    def is_empty(self): return len(self._q) == 0
    def size(self): return len(self._q)

class EventHashTable:
    """Hash-table backed O(1) event lookup by ID. Uses Python dict internally."""
    def __init__(self):
        self._table = {}
    def put(self, key: str, value): self._table[key] = value
    def get(self, key: str): return self._table.get(key)
    def contains(self, key: str): return key in self._table
    def keys(self): return list(self._table.keys())
    def size(self): return len(self._table)

class BSTNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.left = None
        self.right = None

class EventBST:
    """Binary search tree keyed by timestamp for ordered temporal lookup.
    Insert: O(log n) avg. Range query: O(log n + k)."""
    def __init__(self):
        self.root = None
        self._size = 0

    def insert(self, timestamp_key: str, event):
        self.root = self._insert(self.root, timestamp_key, event)
        self._size += 1

    def _insert(self, node, key, value):
        if node is None: return BSTNode(key, value)
        if key < node.key: node.left = self._insert(node.left, key, value)
        elif key > node.key: node.right = self._insert(node.right, key, value)
        else: node.value = value  # update
        return node

    def find(self, key):
        node = self.root
        while node:
            if key == node.key: return node.value
            elif key < node.key: node = node.left
            else: node = node.right
        return None

    def range_query(self, start_key: str, end_key: str) -> list:
        results = []
        self._range(self.root, start_key, end_key, results)
        return results

    def _range(self, node, start, end, results):
        if not node: return
        if start <= node.key <= end: results.append(node.value)
        if node.key > start: self._range(node.left, start, end, results)
        if node.key < end: self._range(node.right, start, end, results)

    def inorder(self) -> list:
        results = []
        self._inorder(self.root, results)
        return results

    def _inorder(self, node, results):
        if not node: return
        self._inorder(node.left, results)
        results.append(node.value)
        self._inorder(node.right, results)

    def size(self): return self._size

class OperationStack:
    """Stack for recent operations / processing history. O(1) push/pop."""
    def __init__(self, max_size: int = 100):
        self._stack = []
        self._max = max_size
    def push(self, item):
        if len(self._stack) >= self._max:
            self._stack.pop(0)
        self._stack.append(item)
    def pop(self): return self._stack.pop() if self._stack else None
    def peek(self): return self._stack[-1] if self._stack else None
    def all(self): return list(reversed(self._stack))
    def size(self): return len(self._stack)

# =================== LOG PARSING ===================

SEVERITY_KEYWORDS = {
    "critical": ["critical", "emergency", "emerg", "alert"],
    "high": ["error", "err", "fail", "denied", "blocked", "malicious", "attack", "exploit", "breach"],
    "medium": ["warning", "warn", "suspicious", "invalid", "unauthorized", "forbidden"],
    "low": ["info", "notice", "debug", "success", "accepted", "allowed"],
}

IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
TIMESTAMP_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"),
]

@dataclass
class ParsedEvent:
    event_id: str
    timestamp: Optional[str]
    level: Optional[str]
    severity: str
    source_ip: Optional[str]
    message: str
    event_type: Optional[str]
    raw_line: str
    flags: List[str] = field(default_factory=list)


def classify_severity(text: str) -> str:
    text_lower = text.lower()
    for sev, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return sev
    return "low"


def extract_timestamp(line: str) -> Optional[str]:
    for pat in TIMESTAMP_PATTERNS:
        m = pat.search(line)
        if m: return m.group(1)
    return None


def extract_ip(line: str) -> Optional[str]:
    m = IP_PATTERN.search(line)
    return m.group(1) if m else None


def detect_flags(line: str) -> List[str]:
    flags = []
    line_lower = line.lower()
    if re.search(r"failed (password|login|auth)", line_lower): flags.append("failed_login")
    if re.search(r"(sql|union select|drop table)", line_lower, re.I): flags.append("sql_injection")
    if re.search(r"(../|etc/passwd|cmd.exe|/bin/sh)", line): flags.append("path_traversal")
    if re.search(r"(script>|onerror=|onload=)", line_lower): flags.append("xss_attempt")
    if re.search(r"(port scan|nmap|masscan)", line_lower): flags.append("port_scan")
    if re.search(r"(brute.?force|dictionary attack)", line_lower): flags.append("brute_force")
    return flags


def parse_log_line(line: str, idx: int) -> ParsedEvent:
    line = line.strip()
    if not line:
        return None
    # Try JSON
    if line.startswith("{"):
        try:
            data = json.loads(line)
            msg = data.get("message") or data.get("msg") or str(data)
            level = data.get("level") or data.get("severity") or data.get("log_level")
            ts = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            ip = data.get("source_ip") or data.get("client_ip") or data.get("ip")
            return ParsedEvent(
                event_id=f"evt-{idx}",
                timestamp=str(ts) if ts else None,
                level=level,
                severity=classify_severity(msg + (level or "")),
                source_ip=ip,
                message=msg[:1000],
                event_type=data.get("event_type") or data.get("type"),
                raw_line=line[:500],
                flags=detect_flags(msg),
            )
        except json.JSONDecodeError:
            pass
    # Plain text
    return ParsedEvent(
        event_id=f"evt-{idx}",
        timestamp=extract_timestamp(line),
        level=None,
        severity=classify_severity(line),
        source_ip=extract_ip(line),
        message=line[:1000],
        event_type=None,
        raw_line=line[:500],
        flags=detect_flags(line),
    )


def analyze_logs(content: str) -> dict:
    """Main log analysis function. Returns structured results with data structure stats."""
    lines = content.splitlines()[:10000]  # cap at 10k lines

    queue = EventQueue()
    hashtable = EventHashTable()
    bst = EventBST()
    op_stack = OperationStack()
    
    events = []
    ip_failure_counts = defaultdict(int)
    
    for idx, line in enumerate(lines):
        evt = parse_log_line(line, idx)
        if evt is None:
            continue
        queue.enqueue(evt)
        op_stack.push({"action": "enqueued", "event_id": evt.event_id, "severity": evt.severity})
    
    # Process queue
    processed = []
    while not queue.is_empty():
        evt = queue.dequeue()
        hashtable.put(evt.event_id, evt)
        if evt.timestamp:
            bst.insert(evt.timestamp + f"-{evt.event_id}", evt)
        if evt.source_ip and "failed_login" in evt.flags:
            ip_failure_counts[evt.source_ip] += 1
        processed.append(evt)
        events.append(evt)

    # Detect brute force (>5 failed logins from same IP)
    brute_force_ips = {ip: count for ip, count in ip_failure_counts.items() if count >= 5}
    
    # Stats
    severity_counts = defaultdict(int)
    for evt in events:
        severity_counts[evt.severity] += 1
    
    flag_counts = defaultdict(int)
    for evt in events:
        for flag in evt.flags:
            flag_counts[flag] += 1
    
    # BST ordered events (sorted by timestamp)
    ordered_events = bst.inorder()
    
    return {
        "total_entries": len(events),
        "severity_counts": dict(severity_counts),
        "flag_counts": dict(flag_counts),
        "brute_force_ips": brute_force_ips,
        "events": events,
        "ordered_count": len(ordered_events),
        "hashtable_size": hashtable.size(),
        "bst_size": bst.size(),
        "recent_ops": op_stack.all()[:20],
        "data_structure_stats": {
            "queue_processed": len(processed),
            "hashtable_entries": hashtable.size(),
            "bst_nodes": bst.size(),
            "op_stack_depth": op_stack.size(),
        }
    }
