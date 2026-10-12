
function loadStatus() {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, data => {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    const count = document.getElementById('ruleCount');
    const sync = document.getElementById('lastSync');
    if (data && data.rule_count !== undefined) {
      dot.className = 'dot green';
      text.textContent = 'Active (' + data.rule_count + ' rules)';
      count.textContent = data.rule_count;
      if (data.last_sync) {
        const d = new Date(data.last_sync);
        sync.textContent = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      } else { sync.textContent = 'Never'; }
    } else {
      dot.className = 'dot red';
      text.textContent = 'No rules loaded';
      count.textContent = '0';
      sync.textContent = 'Never';
    }
  });
}

function syncNow() {
  const btn = document.getElementById('syncBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="syncing">&#8635;</span> Syncing...';
  chrome.runtime.sendMessage({ type: 'SYNC_NOW' }, result => {
    btn.disabled = false;
    btn.innerHTML = '&#8635; Sync Rules Now';
    if (result && result.ok) loadStatus();
  });
}

function openDashboard() {
  chrome.tabs.create({ url: 'http://localhost:5173' });
}

document.addEventListener('DOMContentLoaded', loadStatus);
