function showTab(name) {
  document.querySelectorAll('.sec-panel').forEach(p=>p.classList.remove('show'));
  document.querySelectorAll('.sec-tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('show');
  if (event && event.currentTarget) event.currentTarget.classList.add('active');
  else document.querySelectorAll('.sec-tab')[['scans','blocks','ips','notices'].indexOf(name)].classList.add('active');
}
function filterScans() {
  const q = document.getElementById('scanSearch').value.toLowerCase();
  document.querySelectorAll('#scanTable tbody tr').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
function confirmClear(tbl) {
  if (confirm('Permanently delete all records from this table?')) {
    window.location.href = '?clear='+tbl;
  }
}

/* ── NOTICE BOARD ── */
function selSwatch(input) {
  document.querySelectorAll('.nf-swatch').forEach(s=>s.classList.remove('sel'));
  input.closest('.nf-swatch').classList.add('sel');
}
function editNotice(id, heading, content, link, colorKey, active) {
  document.getElementById('nfFormTitle').innerHTML = '<i class="fas fa-pen"></i> Edit Notice #'+id;
  document.getElementById('nfId').value = id;
  document.getElementById('nfHeading').value = heading;
  document.getElementById('nfContent').value = content;
  document.getElementById('nfLink').value = link || '';
  document.querySelector('input[name="active"]').checked = !!active;
  document.querySelectorAll('.nf-swatch').forEach(s=>{
    const on = s.dataset.key === colorKey;
    s.classList.toggle('sel', on);
    s.querySelector('input').checked = on;
  });
  document.getElementById('nfSubmit').innerHTML = '<i class="fas fa-check"></i> Update Notice';
  document.getElementById('nfCancel').style.display = 'inline-block';
  document.getElementById('noticeForm').scrollIntoView({behavior:'smooth', block:'start'});
}
function resetNoticeForm() {
  document.getElementById('noticeForm').reset();
  document.getElementById('nfId').value = '';
  document.getElementById('nfFormTitle').innerHTML = '<i class="fas fa-plus"></i> Add Notice';
  document.getElementById('nfSubmit').innerHTML = '<i class="fas fa-check"></i> Publish Notice';
  document.getElementById('nfCancel').style.display = 'none';
  document.querySelectorAll('.nf-swatch').forEach(s=>s.classList.toggle('sel', s.dataset.key==='cyan'));
}
function confirmDeleteNotice(id) {
  if (confirm('Delete this notice permanently?')) {
    window.location.href = '{{ notice_delete_url }}'+id;
  }
}
(function(){
  const tab = new URLSearchParams(window.location.search).get('tab');
  if (tab === 'notices') {
    document.querySelectorAll('.sec-panel').forEach(p=>p.classList.remove('show'));
    document.querySelectorAll('.sec-tab').forEach(t=>t.classList.remove('active'));
    document.getElementById('tab-notices').classList.add('show');
    document.querySelectorAll('.sec-tab')[3].classList.add('active');
  }
})();