// ByteChief AI — main.js
// Chat logic is embedded in dashboard.html
// This file is reserved for future shared utilities

function formatRelativeTime(date) {
  const now  = new Date();
  const diff = Math.floor((now - new Date(date)) / 1000);
  if (diff < 60)   return 'just now';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}
