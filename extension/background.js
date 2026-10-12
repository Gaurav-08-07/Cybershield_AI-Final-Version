
const API_BASE = 'http://localhost:8000/api/v1';
const SYNC_ALARM = 'cybershield_sync';
const SYNC_INTERVAL_MINUTES = 30;

let ruleIdCounter = 1;

async function syncRules() {
  try {
    const resp = await fetch(API_BASE + '/extension/rules?limit=5000');
    if (!resp.ok) { console.error('[CyberShield] Rule fetch failed:', resp.status); return; }
    const data = await resp.json();
    const domains = data.domains || [];
    if (domains.length === 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: await getCurrentRuleIds(), addRules: [] });
      await chrome.storage.local.set({ rule_count: 0, last_sync: new Date().toISOString() });
      return;
    }
    const newRules = domains.map((domain, i) => ({
      id: i + 1,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: { extensionPath: '/blocked.html?domain=' + encodeURIComponent(domain) }
      },
      condition: {
        urlFilter: '||' + domain + '^',
        resourceTypes: ['main_frame']
      }
    }));
    const oldIds = await getCurrentRuleIds();
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: oldIds, addRules: newRules });
    await chrome.storage.local.set({ rule_count: newRules.length, last_sync: new Date().toISOString(), status: 'operational' });
    console.log('[CyberShield] Synced ' + newRules.length + ' blocking rules');
  } catch (err) {
    console.error('[CyberShield] Sync error:', err);
    await chrome.storage.local.set({ status: 'error', last_error: String(err) });
  }
}

async function getCurrentRuleIds() {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  return rules.map(r => r.id);
}

// Log to backend when a navigation is blocked
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.includes('blocked.html')) {
    const url = new URL(tab.url);
    const domain = url.searchParams.get('domain') || '';
    if (domain) {
      fetch(API_BASE + '/extension/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event_type: 'navigation_blocked', url: 'https://' + domain, domain, extension_version: '1.0.0' })
      }).catch(() => {});
    }
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(SYNC_ALARM, { periodInMinutes: SYNC_INTERVAL_MINUTES });
  syncRules();
});
chrome.runtime.onStartup.addListener(() => { syncRules(); });
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === SYNC_ALARM) syncRules(); });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'SYNC_NOW') { syncRules().then(() => sendResponse({ ok: true })).catch(e => sendResponse({ ok: false, error: String(e) })); return true; }
  if (msg.type === 'GET_STATUS') {
    chrome.storage.local.get(['rule_count', 'last_sync', 'status'], data => sendResponse(data));
    return true;
  }
});
