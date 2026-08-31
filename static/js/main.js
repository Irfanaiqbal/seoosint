let mode = 'email';
let currentJobId = null;
let resultCount = 0;
let allResults = [];
let scanHistory = JSON.parse(localStorage.getItem('st_history') || '[]');
let progTimer = null;
let progVal = 0;

const $ = id => document.getElementById(id);
const runBtn   = $('runBtn');
const targetIn = $('target');
const errMsg   = $('errMsg');
const okMsg    = $('okMsg');
const loading  = $('loading');
const queueCard= $('queueCard');
const resWrap  = $('resultsWrap');
const resGrid  = $('resGrid');
const resCount = $('resCount');
const emptyState=$('emptyState');
const progWrap = $('progWrap');
const progFill = $('progFill');
const progLabel= $('progLabel');
const progPct  = $('progPct');
const exportBtn= $('exportBtn');
const filterIn = $('filterInput');

const modeIcons = {email:'fa-envelope',username:'fa-user',domain:'fa-globe',phone:'fa-phone'};
const modePH    = {email:'e.g., user@example.com',username:'e.g., johndoe',domain:'e.g., example.com',phone:'e.g., +1234567890'};
const modeLbls  = {email:'EMAIL SCAN MODE',username:'USERNAME TRACE MODE',domain:'DOMAIN INTELLIGENCE MODE',phone:'PHONE OSINT MODE'};

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  mode = t.dataset.mode;
  targetIn.placeholder = modePH[mode];
  $('iicon').className = 'fas ' + modeIcons[mode];
  $('modeLbl').textContent = modeLbls[mode];
}));

targetIn.addEventListener('keydown', e => {
  if (e.key === 'Tab' && document.activeElement === targetIn) {
    e.preventDefault();
    const modes = ['email','username','domain','phone'];
    const next = modes[(modes.indexOf(mode)+1)%modes.length];
    document.querySelector(`[data-mode="${next}"]`).click();
  }
  if (e.key === 'Enter') runBtn.click();
  if (e.key === 'Escape') { targetIn.value = ''; clearMessages(); }
});
document.addEventListener('keydown', e => {
  if ((e.ctrlKey||e.metaKey) && e.key === 'k') { e.preventDefault(); targetIn.focus(); }
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-bg.show').forEach(m => m.classList.remove('show'));
    closeMob();
    document.body.style.overflow = '';
  }
});

runBtn.addEventListener('click', async () => {
  const target = targetIn.value.trim();
  if (!target) { showErr('Enter a target to scan'); return; }
  resetUI();
  loading.classList.add('show');
  runBtn.disabled = true;
  startFakeProgress();
  try {
    const res = await fetch('/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({mode, target})
    });
    const data = await res.json();
    if (data.status === 'error') throw new Error(data.message);
    if (data.status === 'queued') {
      loading.classList.remove('show');
      stopFakeProgress();
      queueCard.classList.add('show');
      $('queuePos').textContent = data.queue_position;
      currentJobId = data.job_id;
      pollQueue();
    } else {
      currentJobId = data.job_id;
      saveHistory(mode, target);
      startStream();
    }
  } catch(err) {
    loading.classList.remove('show');
    stopFakeProgress();
    showErr(err.message || 'Server error');
    runBtn.disabled = false;
  }
});

async function pollQueue() {
  if (!currentJobId) return;
  try {
    const r = await fetch(`/queue-status/${currentJobId}`);
    const d = await r.json();
    if (d.status === 'started') {
      queueCard.classList.remove('show');
      loading.classList.add('show');
      startFakeProgress();
      startStream();
    } else if (d.status === 'queued') {
      $('queuePos').textContent = d.queue_position;
      setTimeout(pollQueue, 3000);
    }
  } catch { showErr('Queue check failed'); runBtn.disabled = false; }
}

function startStream() {
  const es = new EventSource(`/stream/${currentJobId}`);
  $('loadLabel').textContent = mode.toUpperCase();
  es.onmessage = e => {
    if (e.data === '__DONE__') {
      es.close();
      loading.classList.remove('show');
      stopFakeProgress();
      progWrap.classList.remove('show');
      if (resultCount === 0) {
        emptyState.classList.add('show');
        emptyState.querySelector('h3').textContent = 'NO RESULTS';
        emptyState.querySelector('p').textContent = 'Nothing found for this target.';
      } else {
        resWrap.style.display = 'block';
        exportBtn.disabled = false;
      }
      runBtn.disabled = false;
      return;
    }
    try { addCard(JSON.parse(e.data)); } catch {}
  };
  es.onerror = () => {
    es.close();
    loading.classList.remove('show');
    stopFakeProgress();
    showErr('Connection lost during scan');
    runBtn.disabled = false;
  };
}

function addCard(obj) {
  resultCount++;
  updateCount();
  allResults.push(obj);
  const card = document.createElement('div');
  card.className = 'rcard' + (obj.url ? ' link' : '');
  card.dataset.search = (obj.title + ' ' + obj.body).toLowerCase();
  if (obj.url) card.addEventListener('click', () => window.open(obj.url, '_blank'));
  const tagClass = {email:'tag-email',username:'tag-username',domain:'tag-domain',phone:'tag-phone'}[obj.tag] || 'tag-domain';
  card.innerHTML = `
    <div class="rcard-top">
      <div class="rcard-title"><i class="fas ${obj.icon||'fa-info-circle'}"></i> ${obj.title}</div>
      <button class="rcard-copy" onclick="event.stopPropagation();copyText('${escJs(obj.body_plain||obj.body)}')"><i class="fas fa-copy"></i> copy</button>
    </div>
    <div class="rcard-body">${obj.body}</div>
    ${obj.tag ? `<div class="rcard-tag ${tagClass}">${obj.tag.toUpperCase()}</div>` : ''}
  `;
  resGrid.appendChild(card);
  if (!resWrap.style.display || resWrap.style.display==='none') resWrap.style.display='block';
}

function escJs(s){return (s||'').replace(/'/g,"\\'").replace(/"/g,"&quot;")}

function filterResults() {
  const q = filterIn.value.toLowerCase();
  document.querySelectorAll('.rcard').forEach(c => {
    c.style.display = c.dataset.search.includes(q) ? '' : 'none';
  });
}

function exportResults() {
  const blob = new Blob([JSON.stringify(allResults, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `shadowtrace_${Date.now()}.json`;
  a.click();
  showToast('Exported as JSON');
}

function saveHistory(m, t) {
  scanHistory = scanHistory.filter(x => !(x.m===m && x.t===t));
  scanHistory.unshift({m, t});
  if (scanHistory.length > 8) scanHistory = scanHistory.slice(0, 8);
  localStorage.setItem('st_history', JSON.stringify(scanHistory));
  renderHistory();
}
function renderHistory() {
  const panel = $('histPanel'); const list = $('histList');
  if (!scanHistory.length) { panel.classList.remove('show'); return; }
  panel.classList.add('show');
  list.innerHTML = scanHistory.map(x =>
    `<div class="hist-item" onclick="loadHistory('${x.m}','${escJs(x.t)}')"><i class="fas ${modeIcons[x.m]}"></i>${escHtml(x.t)}</div>`
  ).join('');
}
function loadHistory(m, t) {
  document.querySelector(`[data-mode="${m}"]`).click();
  targetIn.value = t; targetIn.focus();
}
function clearHistory() {
  scanHistory = []; localStorage.removeItem('st_history');
  $('histPanel').classList.remove('show');
}
function escHtml(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

function startFakeProgress() {
  progVal=0; progWrap.classList.add('show');
  progFill.style.width='0%'; progLabel.textContent='Initializing...'; progPct.textContent='0%';
  progTimer = setInterval(() => {
    if (progVal < 85) {
      progVal += Math.random() * 2.5;
      progFill.style.width = progVal + '%';
      progPct.textContent = Math.round(progVal) + '%';
    }
  }, 300);
}
function stopFakeProgress() {
  clearInterval(progTimer);
  progVal=100; progFill.style.width='100%'; progPct.textContent='100%'; progLabel.textContent='Complete';
}

function resetUI() {
  clearMessages(); emptyState.classList.remove('show');
  emptyState.querySelector('h3').textContent = 'READY TO TRACE';
  resWrap.style.display='none'; queueCard.classList.remove('show');
  loading.classList.remove('show'); resGrid.innerHTML='';
  resultCount=0; allResults=[]; exportBtn.disabled=true; filterIn.value=''; updateCount();
}
function updateCount(){resCount.textContent=`${resultCount} item${resultCount!==1?'s':''}`}
function showErr(t){errMsg.textContent='⚠ '+t;errMsg.classList.add('show')}
function clearMessages(){errMsg.classList.remove('show');okMsg.classList.remove('show')}

function showToast(msg) {
  $('toastMsg').textContent = msg;
  const t = $('toast'); t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
function copyText(text){navigator.clipboard?.writeText(text).then(()=>showToast('Copied to clipboard'))}
function copyWallet(id,okId){
  navigator.clipboard?.writeText($(id).innerText).then(()=>{
    const el=$(okId);el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2000);
  });
}
function openM(id){$('modal-'+id).classList.add('show');document.body.style.overflow='hidden'}
function closeM(id){$('modal-'+id).classList.remove('show');document.body.style.overflow=''}
document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{if(e.target===m){m.classList.remove('show');document.body.style.overflow=''}}));
function toggleMob(){$('mobPanel').classList.toggle('open');$('mobOverlay').classList.toggle('open')}
function closeMob(){$('mobPanel').classList.remove('open');$('mobOverlay').classList.remove('open')}
renderHistory();