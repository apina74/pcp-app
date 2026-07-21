/* Panel de Control Personal (PCP) v8 — lógica de la app.
   Datos: Supabase (vistas v_cm_* con clave pública; detalle con sesión de Antonio).
   IA: Edge Function cm-qa (cascada Groq→Mistral→OpenRouter→Gemini→Claude).
   Seguridad: candado de identidad en BD (cm_es_antonio) + desbloqueo del dispositivo (WebAuthn). */

'use strict';

// ===== Configuración =====
const URL_SB  = 'https://kczyjihknvjvxmjxowbx.supabase.co';
const ANON    = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtjenlqaWhrbnZqdnhtanhvd2J4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcyMDU5NTUsImV4cCI6MjA5Mjc4MTk1NX0.s11I-DdteJ56XBoKoqapN7lqDANYvIrEWlK7dTPNrQI';
const REST    = URL_SB + '/rest/v1';
const AUTH    = URL_SB + '/auth/v1';
const FUNC_QA = URL_SB + '/functions/v1/cm-qa';
const BUCKET_INBOX = 'tps-ingesta-inbox';

const $  = (id) => document.getElementById(id);
const fmt0 = (n) => (Number(n)||0).toLocaleString('es-ES', { maximumFractionDigits: 0 });
const fmt2 = (n) => (Number(n)||0).toLocaleString('es-ES', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const MESES_ES = ['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'];
const mesLabel = (m) => { const [a, mm] = String(m).split('-'); return mm ? `${MESES_ES[+mm-1]} '${a.slice(2)}` : m; };
$('hoy').textContent = new Date().toISOString().slice(0,10);

// ===== Ejercicio fiscal activo (v_cm_fy) =====
// Los rótulos de FY se leen de la BD: al hacer el rollover (marcar es_actual en
// ejercicio_fiscal) la app se adapta sola, sin tocar código. Si la carga falla, se
// quedan los valores por defecto del HTML.
let FY = null;
const fyCod = () => (FY && FY.codigo) || 'FY26';
const fyFinCorto = () => {
  if (!FY) return '30-sep';
  const d = new Date(FY.fecha_fin + 'T00:00:00');
  return `${d.getDate()}-${MESES_ES[d.getMonth()]}`;
};
async function cargarFy() {
  try {
    const r = await fetch(`${REST}/v_cm_fy?select=*`, { headers: { apikey: ANON, Authorization: `Bearer ${ANON}` } });
    const [f] = r.ok ? await r.json() : [];
    if (!f) return;
    FY = f;
    const ab = (s) => { const d = new Date(s + 'T00:00:00'); return `${MESES_ES[d.getMonth()]}-${String(d.getFullYear()).slice(2)}`; };
    const rot = $('fyRotulo');
    if (rot) rot.textContent = `FY ${ab(f.fecha_inicio)} a ${ab(f.fecha_fin)}`;
    // OJO: la clase 'fy' ya existe en styles.css (.cf-val.fy) sobre el importe #cfPrev.
    // El marcador de rótulo es 'js-fy' a propósito, para no sobrescribir esa cifra.
    document.querySelectorAll('.js-fy').forEach((e) => { e.textContent = f.codigo; });
  } catch { /* rótulos por defecto */ }
}
cargarFy();

// ============================================================
// SESIÓN (sin librerías: REST de Supabase Auth)
// ============================================================
let ses = null;            // { access_token, refresh_token, expires_at } en memoria
let bioKey = null;         // clave AES derivada del desbloqueo del dispositivo (en memoria)
const LS_SES = 'cm_sesion_v8', LS_BIO = 'cm_bio_v8', LS_BIO_DATA = 'cm_bio_data_v8', LS_VOZ = 'cm_voz_v8';

function emailDe(tok) {
  try { return JSON.parse(atob(tok.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).email || ''; }
  catch { return ''; }
}

async function persistirSesion() {
  if (!ses) return;
  if (bioActivada()) {
    if (bioKey) await bioGuardarCifrado(ses.refresh_token);
    localStorage.removeItem(LS_SES); // con desbloqueo activo no se guarda sesión en claro
  } else {
    localStorage.setItem(LS_SES, JSON.stringify(ses));
  }
}

async function loginPassword(email, pass) {
  const r = await fetch(`${AUTH}/token?grant_type=password`, {
    method: 'POST', headers: { apikey: ANON, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: pass })
  });
  const d = await r.json();
  if (!r.ok || !d.access_token) throw new Error(d.error_description || d.msg || 'credenciales incorrectas');
  ses = { access_token: d.access_token, refresh_token: d.refresh_token, expires_at: d.expires_at };
  await persistirSesion();
  return ses;
}

async function refrescar(refresh_token) {
  const r = await fetch(`${AUTH}/token?grant_type=refresh_token`, {
    method: 'POST', headers: { apikey: ANON, 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token })
  });
  const d = await r.json();
  if (!r.ok || !d.access_token) throw new Error('sesión caducada');
  ses = { access_token: d.access_token, refresh_token: d.refresh_token, expires_at: d.expires_at };
  await persistirSesion();
  return ses;
}

async function getToken() {
  if (!ses) return null;
  const ahora = Math.floor(Date.now()/1000);
  if (ses.expires_at && ses.expires_at - 60 < ahora) {
    try { await refrescar(ses.refresh_token); } catch { ses = null; refrescarSesionUI(); return null; }
  }
  return ses.access_token;
}

function cerrarSesion() {
  ses = null; bioKey = null;
  localStorage.removeItem(LS_SES);
  refrescarSesionUI();
  mostrarLogin();
}

// (Google/OAuth retirado 2026-07-05: un solo sistema de acceso — contraseña la primera
//  vez y desbloqueo del dispositivo (huella / Windows Hello / PIN) en adelante.)

// ============================================================
// DESBLOQUEO DEL DISPOSITIVO (WebAuthn: Windows Hello / huella)
// La sesión guardada queda cifrada; solo el desbloqueo la descifra (extensión PRF).
// Si el dispositivo no soporta PRF, actúa como barrera de acceso (aviso al activar).
// ============================================================
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)).buffer
};
function bioActivada() { return !!localStorage.getItem(LS_BIO); }

async function claveDesdePrf(prfOut) {
  const hash = await crypto.subtle.digest('SHA-256', prfOut);
  return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt','decrypt']);
}
async function bioGuardarCifrado(texto) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, bioKey, new TextEncoder().encode(texto));
  localStorage.setItem(LS_BIO_DATA, JSON.stringify({ iv: b64u.enc(iv), ct: b64u.enc(ct) }));
}

async function bioActivar() {
  if (!ses) { alert('Primero inicia sesión.'); return; }
  if (!window.PublicKeyCredential) { alert('Este navegador no soporta el desbloqueo del dispositivo.'); return; }
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: 'Panel de Control Personal' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: emailDe(ses.access_token) || 'antonio', displayName: 'Antonio' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    extensions: { prf: { eval: { first: salt } } }
  }});
  const ext = cred.getClientExtensionResults();
  const conPrf = !!(ext.prf && (ext.prf.enabled || ext.prf.results));
  localStorage.setItem(LS_BIO, JSON.stringify({ credId: b64u.enc(cred.rawId), salt: b64u.enc(salt), prf: conPrf }));
  if (conPrf) {
    // derivar la clave (algunos navegadores ya devuelven el PRF en el create)
    let out = ext.prf.results && ext.prf.results.first;
    if (!out) out = await bioAssertion();
    bioKey = await claveDesdePrf(out);
    await bioGuardarCifrado(ses.refresh_token);
    localStorage.removeItem(LS_SES);
    alert('Desbloqueo del dispositivo activado: la sesión queda cifrada y se abre con huella / Windows Hello / PIN.');
  } else {
    localStorage.setItem(LS_BIO_DATA, JSON.stringify({ plano: ses.refresh_token }));
    localStorage.removeItem(LS_SES);
    alert('Desbloqueo activado como barrera de acceso (este dispositivo no soporta cifrado ligado al sensor).');
  }
  refrescarSesionUI();
}

async function bioAssertion() {
  const cfg = JSON.parse(localStorage.getItem(LS_BIO));
  const asr = await navigator.credentials.get({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [{ id: b64u.dec(cfg.credId), type: 'public-key' }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: new Uint8Array(b64u.dec(cfg.salt)) } } }
  }});
  const ext = asr.getClientExtensionResults();
  return ext.prf && ext.prf.results ? ext.prf.results.first : null;
}

async function bioDesbloquear() {
  try {
    const cfg = JSON.parse(localStorage.getItem(LS_BIO));
    const data = JSON.parse(localStorage.getItem(LS_BIO_DATA) || '{}');
    const prfOut = await bioAssertion();           // aquí salta Windows Hello / huella
    let refresh;
    if (cfg.prf && prfOut && data.ct) {
      bioKey = await claveDesdePrf(prfOut);
      const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(b64u.dec(data.iv)) }, bioKey, b64u.dec(data.ct));
      refresh = new TextDecoder().decode(pt);
    } else if (data.plano) {
      refresh = data.plano;
    } else { throw new Error('no hay sesión guardada'); }
    await refrescar(refresh);
    ocultarLogin(); refrescarSesionUI();
    cargarPanel();
  } catch (e) {
    $('loginError').textContent = 'No se pudo desbloquear: ' + e.message;
  }
}

// ============================================================
// PETICIONES CON DETALLE (token del usuario)
// ============================================================
async function fetchDetalle(ruta, opciones = {}) {
  const tok = await getToken();
  if (!tok) throw new Error('SIN_SESION');
  const r = await fetch(ruta.startsWith('http') ? ruta : REST + ruta, {
    ...opciones,
    headers: { apikey: ANON, Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json', ...(opciones.headers||{}) }
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0,180)}`);
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}
const rpc = (fn, params) => fetchDetalle(`/rpc/${fn}`, { method: 'POST', body: JSON.stringify(params||{}) });

// ============================================================
// UI: login y sesión
// ============================================================
function mostrarLogin() {
  $('loginCapa').style.display = 'flex';
  const bio = bioActivada();
  // Un solo sistema: con desbloqueo activado, la contraseña queda escondida como respaldo.
  $('btnBioLogin').style.display = bio ? 'block' : 'none';
  $('formPass').style.display = bio ? 'none' : 'block';
  $('btnUsarPass').style.display = bio ? 'inline-block' : 'none';
}
function ocultarLogin() { $('loginCapa').style.display = 'none'; }

function refrescarSesionUI() {
  const info = $('sesionInfo'), btn = $('btnSesion');
  if (ses) {
    info.textContent = emailDe(ses.access_token) + (bioActivada() ? ' · 🔒' : '');
    btn.textContent = 'salir';
    $('btnBioActivar').style.display = (bioActivada() || !window.PublicKeyCredential) ? 'none' : 'inline-block';
    cargarClientes(); cargarBadgeAlertas();
  } else {
    info.textContent = 'sin sesión (solo panel)';
    btn.textContent = 'entrar';
    $('btnBioActivar').style.display = 'none';
  }
}

// ============================================================
// NAVEGACIÓN (sidebar, FASE F — antes pestañas superiores)
// ============================================================
document.querySelectorAll('.nav-item[data-pantalla]').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('activa'));
  document.querySelectorAll('.pantalla').forEach(x => x.classList.remove('activa'));
  t.classList.add('activa');
  $('pantalla-' + t.dataset.pantalla).classList.add('activa');
  // Toda la app queda tras el login (decisión 2026-07-05): cualquier pantalla exige sesión.
  if (!ses) mostrarLogin();
  if (t.dataset.pantalla === 'proyectos' && ses) cargarProyectos();
  if (t.dataset.pantalla === 'informes' && ses) cargarInformesGuardados();
}));

// Kira flotante (FASE F: antes pestaña Asistente a pantalla completa)
function abrirKira() {
  $('kiraPanel').classList.add('abierto');
  if (!ses) { mostrarLogin(); return; }
  if (!autoBriefingHecho) {
    autoBriefingHecho = true;
    $('chatLog').innerHTML = '';
    cargarBriefing(addMsg('teo', '<em>preparando briefing…</em>'));
  }
}
$('kiraFab').addEventListener('click', abrirKira);
$('kiraFab').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); abrirKira(); } });
$('kiraCerrar').addEventListener('click', () => $('kiraPanel').classList.remove('abierto'));

// ============================================================
// PANEL (KPIs con clave pública — funciona sin sesión)
// ============================================================
let chartFacObj = null;
async function fetchView(view, extra) {
  const r = await fetch(`${REST}/${view}?select=*${extra||''}`, { headers: { apikey: ANON, Authorization: `Bearer ${ANON}` } });
  if (!r.ok) throw new Error(`${view}: HTTP ${r.status}`);
  return r.json();
}
async function paso(view, render, extra) {
  try { render(await fetchView(view, extra)); return true; }
  catch (e) { console.error(view, e); return false; }
}

async function cargarPanel() {
  const st = $('status'); $('refresh').disabled = true; st.textContent = 'cargando KPIs…'; st.className = 'status';
  const fact = {};   // datos para los gráficos del desglose de facturación
  const r1 = paso('v_cm_hero', (rows) => { const r = rows[0]; if (!r) return;
    $('vFacturado').textContent = fmt0(r.facturado) + ' €';
    $('sFacturado').textContent = `${r.n_facturado||0} facturas reales + placeholders ya emitidos`;
    $('vPendiente').textContent = fmt0(r.pendiente) + ' €';
    $('sPendiente').textContent = `${r.n_pendiente||0} placeholders y hitos hasta ${fyFinCorto()}`;
    $('vPrevision').textContent = fmt0((+r.facturado||0)+(+r.pendiente||0)) + ' €';
    $('sPrevision').textContent = `${(r.n_facturado||0)+(r.n_pendiente||0)} conceptos`;
    $('cfPrev').textContent = fmt0((+r.facturado||0)+(+r.pendiente||0)) + ' €';
    $('vCarryAnt').textContent = '+' + fmt0(r.carry_ant) + ' €';
    $('sCarryAnt').textContent = `${r.n_carry_ant||0} hitos ${fyCod()} de propuestas pre-${fyCod()}`;
    $('vCarryPost').textContent = '−' + fmt0(r.carry_post) + ' €';
    $('sCarryPost').textContent = `${r.n_carry_post||0} hitos posteriores al cierre ${fyCod()}`;
    fact.facturado = +r.facturado||0; fact.pendiente = +r.pendiente||0;
  });
  const r2 = paso('v_cm_serie_mensual', (rows) => pintarChart(rows||[]), '&order=mes.asc');
  const pipe = {};   // datos para los gráficos de actividad comercial
  const r3 = paso('v_cm_ventas', (rows) => { const r = rows[0]; if (!r) return;
    const tot = (+r.ventas||0)+(+r.perdidas||0);
    const pct = (n) => tot>0 ? ((n/tot)*100).toFixed(1).replace('.',',')+'%' : '—';
    $('vVentas').innerHTML = fmt0(r.ventas) + ' € <span class="pct">' + pct(+r.ventas||0) + '</span>';
    $('sVentas').textContent = `${r.n_ventas||0} propuestas aceptadas en ${fyCod()}`;
    $('vPerdidas').innerHTML = fmt0(r.perdidas) + ' € <span class="pct">' + pct(+r.perdidas||0) + '</span>';
    $('sPerdidas').textContent = `${r.n_perdidas||0} propuestas rechazadas ${fyCod()}`;
    pipe.ganadas = +r.ventas||0; pipe.perdidas = +r.perdidas||0;
  });
  const r4 = paso('v_cm_oportunidades', (rows) => { const r = rows[0]; if (!r) return;
    $('vOportu').textContent = fmt0((+r.suma_enviadas||0)+(+r.suma_oportu||0)) + ' €';
    $('sOportu').textContent = `${(r.n_enviadas||0)+(r.n_oportu||0)} propuestas — ${r.n_enviadas||0} enviadas + ${r.n_oportu||0} leads`;
    pipe.abiertas = (+r.suma_enviadas||0)+(+r.suma_oportu||0);
  });
  const r5 = paso('v_cm_desglose_ventas', (rows) => { const r = rows[0]; if (!r) return;
    ['Cartera:cartera','Incidental:incidental','NewBiz:new_biz','Recur:recurrente'].forEach(par => {
      const [id, k] = par.split(':');
      $('v'+id).textContent = fmt0(r[k]) + ' €';
      $('s'+id).textContent = `${r['n_'+k]||0} propuestas`;
    });
    pipe.lineas = { cartera:+r.cartera||0, incidental:+r.incidental||0, new_biz:+r.new_biz||0, recurrente:+r.recurrente||0 };
  });
  // Cobros y mora retirados del dashboard (2026-07-05): datos no fiables.
  const r6 = paso('v_cm_desglose_prevision', (rows) => { const r = rows[0]; if (!r) return;
    ['FacCartera:cartera','FacIncidental:incidental','FacNewBiz:new_biz','FacRecur:recurrente'].forEach(par => {
      const [id, k] = par.split(':');
      $('v'+id).textContent = fmt0(r[k]) + ' €';
      $('s'+id).textContent = `${r['n_'+k]||0} conceptos (previsión)`;
    });
    fact.lineas = { cartera:+r.cartera||0, incidental:+r.incidental||0, new_biz:+r.new_biz||0, recurrente:+r.recurrente||0 };
  });
  const r7 = paso('v_cm_serie_comercial', (rows) => pintarChartComercial(rows||[]), '&order=mes.asc');
  const oks = (await Promise.all([r1,r2,r3,r4,r5,r6,r7])).filter(Boolean).length;
  pintarChartsPipeline(pipe);
  pintarChartsFacturacion(fact);
  st.textContent = oks === 7 ? `actualizado ${new Date().toLocaleTimeString('es-ES')} (7/7)` : `parcial ${oks}/7`;
  st.className = oks === 7 ? 'status' : 'status error';
  $('refresh').disabled = false;
}

let chartComercialObj = null;
function pintarChartComercial(rows) {
  const labels = rows.map(r => mesLabel(r.mes));
  const pres = rows.map(r => +r.presentadas||0), gan = rows.map(r => +r.ganadas||0);
  const nPres = rows.map(r => +r.n_presentadas||0), nGan = rows.map(r => +r.n_ganadas||0);
  Chart.defaults.color = '#6f7ba6';
  Chart.defaults.borderColor = 'rgba(0,240,255,0.08)';
  if (chartComercialObj) chartComercialObj.destroy();
  chartComercialObj = new Chart($('chartComercialEvo'), {
    type: 'bar',
    data: { labels, datasets: [
      { label:'Presentadas', data: pres.map(v => v>0?v:null), backgroundColor:'rgba(0,240,255,0.28)',
        borderColor:'#00f0ff', borderWidth:1, borderRadius:2 },
      { label:'Ganadas', data: gan.map(v => v>0?v:null), backgroundColor:'rgba(10,255,157,0.4)',
        borderColor:'#0aff9d', borderWidth:1, borderRadius:2 }
    ]},
    options: { responsive:true, maintainAspectRatio:false, interaction:{mode:'index',intersect:false},
      scales:{ x:{ grid:{display:false}, ticks:{font:{size:11}} },
               y:{ grid:{color:'rgba(0,240,255,0.07)'}, ticks:{callback:v=>fmt0(v)+' €'} } },
      plugins:{ legend:{display:false}, tooltip:{ callbacks:{ label: (c) => {
        const n = c.datasetIndex === 0 ? nPres[c.dataIndex] : nGan[c.dataIndex];
        return c.parsed.y != null ? ` ${c.dataset.label}: ${fmt0(c.parsed.y)} € (${n} ofertas)` : null;
      } } } } }
  });
  $('chartComercialLegend').innerHTML =
    '<span style="display:inline-block;width:14px;height:10px;background:rgba(0,240,255,0.28);border:1px solid #00f0ff;vertical-align:middle;margin-right:4px;border-radius:2px"></span>Presentadas' +
    ' &nbsp; <span style="display:inline-block;width:14px;height:10px;background:rgba(10,255,157,0.4);border:1px solid #0aff9d;vertical-align:middle;margin-right:4px;border-radius:2px"></span>Ganadas';
}

let chartPipeEstadoObj = null, chartPipeLineasObj = null;
function pintarChartsPipeline(pipe) {
  Chart.defaults.color = '#6f7ba6';
  Chart.defaults.borderColor = 'rgba(0,240,255,0.08)';
  // Donut: a dónde ha ido el pipeline del ejercicio (ganado / abierto / perdido)
  if (pipe.ganadas != null || pipe.abiertas != null) {
    if (chartPipeEstadoObj) chartPipeEstadoObj.destroy();
    chartPipeEstadoObj = new Chart($('chartPipeEstado'), {
      type: 'doughnut',
      data: { labels: ['Ganadas','Abiertas','Perdidas'], datasets: [{
        data: [pipe.ganadas||0, pipe.abiertas||0, pipe.perdidas||0],
        backgroundColor: ['rgba(10,255,157,0.4)','rgba(255,214,10,0.3)','rgba(255,42,109,0.35)'],
        borderColor: ['#0aff9d','#ffd60a','#ff2a6d'], borderWidth: 1.5
      }]},
      options: { responsive:true, maintainAspectRatio:false, cutout:'62%',
        plugins:{ legend:{ position:'bottom', labels:{ boxWidth:10, boxHeight:10, font:{size:11} } },
          tooltip:{ callbacks:{ label: c => ` ${c.label}: ${fmt0(c.parsed)} €` } } } }
    });
  }
  // Barras horizontales: ventas por línea de negocio
  if (pipe.lineas) {
    if (chartPipeLineasObj) chartPipeLineasObj.destroy();
    chartPipeLineasObj = new Chart($('chartPipeLineas'), {
      type: 'bar',
      data: { labels: ['Cartera','Incidental','New business','Recurrente'], datasets: [{
        data: [pipe.lineas.cartera, pipe.lineas.incidental, pipe.lineas.new_biz, pipe.lineas.recurrente],
        backgroundColor: ['rgba(0,240,255,0.3)','rgba(255,42,109,0.3)','rgba(10,255,157,0.3)','rgba(176,38,255,0.3)'],
        borderColor: ['#00f0ff','#ff2a6d','#0aff9d','#b026ff'], borderWidth: 1, borderRadius: 2
      }]},
      options: { responsive:true, maintainAspectRatio:false, indexAxis:'y',
        scales:{ x:{ grid:{color:'rgba(0,240,255,0.07)'}, ticks:{callback:v=>fmt0(v/1000)+'k'} }, y:{ grid:{display:false} } },
        plugins:{ legend:{display:false}, tooltip:{ callbacks:{ label: c => ` ${fmt0(c.parsed.x)} €` } } } }
    });
  }
}

let chartFactEjecObj = null, chartFactLineasObj = null;
function pintarChartsFacturacion(fact) {
  Chart.defaults.color = '#6f7ba6';
  Chart.defaults.borderColor = 'rgba(0,240,255,0.08)';
  // Donut: cuánto del ejercicio está ya ejecutado vs pendiente
  if (fact.facturado != null) {
    if (chartFactEjecObj) chartFactEjecObj.destroy();
    chartFactEjecObj = new Chart($('chartFactEjec'), {
      type: 'doughnut',
      data: { labels: ['Facturado','Pendiente'], datasets: [{
        data: [fact.facturado, fact.pendiente||0],
        backgroundColor: ['rgba(10,255,157,0.4)','rgba(255,214,10,0.3)'],
        borderColor: ['#0aff9d','#ffd60a'], borderWidth: 1.5
      }]},
      options: { responsive:true, maintainAspectRatio:false, cutout:'62%',
        plugins:{ legend:{ position:'bottom', labels:{ boxWidth:10, boxHeight:10, font:{size:11} } },
          tooltip:{ callbacks:{ label: c => ` ${c.label}: ${fmt0(c.parsed)} €` } } } }
    });
  }
  // Barras horizontales: previsión de facturación por línea de negocio
  if (fact.lineas) {
    if (chartFactLineasObj) chartFactLineasObj.destroy();
    chartFactLineasObj = new Chart($('chartFactLineas'), {
      type: 'bar',
      data: { labels: ['Cartera','Incidental','New business','Recurrente'], datasets: [{
        data: [fact.lineas.cartera, fact.lineas.incidental, fact.lineas.new_biz, fact.lineas.recurrente],
        backgroundColor: ['rgba(0,240,255,0.3)','rgba(255,42,109,0.3)','rgba(10,255,157,0.3)','rgba(176,38,255,0.3)'],
        borderColor: ['#00f0ff','#ff2a6d','#0aff9d','#b026ff'], borderWidth: 1, borderRadius: 2
      }]},
      options: { responsive:true, maintainAspectRatio:false, indexAxis:'y',
        scales:{ x:{ grid:{color:'rgba(0,240,255,0.07)'}, ticks:{callback:v=>fmt0(v/1000)+'k'} }, y:{ grid:{display:false} } },
        plugins:{ legend:{display:false}, tooltip:{ callbacks:{ label: c => ` ${fmt0(c.parsed.x)} €` } } } }
    });
  }
}

function pintarChart(rows) {
  // Gráfico representativo del ejercicio: cada mes muestra lo ya facturado (verde) y lo
  // pendiente previsto (ámbar) apilados = previsión mensual; la línea cian es el acumulado
  // del ejercicio (eje derecho), que termina en la previsión total.
  const labels = rows.map(r => mesLabel(r.mes));
  const fac = rows.map(r => +r.facturado||0), pdt = rows.map(r => +r.pendiente||0);
  let suma = 0;
  const acumulado = rows.map((_, i) => (suma += fac[i] + pdt[i]));
  if (chartFacObj) chartFacObj.destroy();
  Chart.defaults.color = '#6f7ba6';
  Chart.defaults.borderColor = 'rgba(0,240,255,0.08)';
  chartFacObj = new Chart($('chartFY26'), {
    data: { labels, datasets: [
      { type:'bar', label:'Facturado', data: fac.map(v => v>0?v:null), backgroundColor:'rgba(10,255,157,0.4)',
        borderColor:'#0aff9d', borderWidth:1, borderRadius:2, stack:'mes', order:2 },
      { type:'bar', label:'Pendiente previsto', data: pdt.map(v => v>0?v:null), backgroundColor:'rgba(255,214,10,0.25)',
        borderColor:'#ffd60a', borderWidth:1, borderRadius:2, stack:'mes', order:3 },
      { type:'line', label:`Acumulado ${fyCod()}`, data: acumulado, yAxisID:'y2', borderColor:'#00f0ff',
        borderWidth:2, tension:0.25, fill:false, pointRadius:3, pointBackgroundColor:'#00f0ff',
        pointBorderColor:'#00f0ff', order:1 }
    ]},
    options: { responsive:true, maintainAspectRatio:false, interaction:{mode:'index',intersect:false},
      scales:{
        x:{ stacked:true, grid:{display:false}, ticks:{font:{size:11}} },
        y:{ stacked:true, grid:{color:'rgba(0,240,255,0.07)'}, ticks:{callback:v=>fmt0(v)+' €'} },
        y2:{ position:'right', grid:{display:false}, ticks:{callback:v=>fmt0(v/1000)+'k'} }
      },
      plugins:{ legend:{display:false}, tooltip:{ callbacks:{ label: (c) =>
        c.parsed.y != null ? `${c.dataset.label}: ${fmt0(c.parsed.y)} €` : null } } } }
  });
  $('chartFY26Legend').innerHTML =
    '<span style="display:inline-block;width:14px;height:10px;background:rgba(10,255,157,0.4);border:1px solid #0aff9d;vertical-align:middle;margin-right:4px;border-radius:2px"></span>Facturado' +
    ' &nbsp; <span style="display:inline-block;width:14px;height:10px;background:rgba(255,214,10,0.25);border:1px solid #ffd60a;vertical-align:middle;margin-right:4px;border-radius:2px"></span>Pendiente previsto' +
    ' &nbsp; <span style="display:inline-block;width:22px;border-top:2px solid #00f0ff;vertical-align:middle;margin-right:4px"></span>Acumulado ' + fyCod() + ' (eje dcho.)';
}

// ============================================================
// EXPLORAR (detalle con sesión) + acciones
// ============================================================
let sub = 'facturas', clientes = {}, usuarios = {};   // id -> {nombre, nif} / id -> {nombre}
let ultimaFilas = [], ultimaCols = [];

const ESTADOS = {
  facturas:   ['EMITIDA','ENVIADA','COBRADA','ANULADA'],
  propuestas: ['OPORTUNIDAD','PROPUESTA_ENVIADA','CERRADA'],
  hitos:      ['previsto','facturable','facturado','cobrado'],
  proyectos:  ['POR_INICIAR','EN_CURSO','PENDIENTE_INFO','PENDIENTE_REVISION_CLIENTE','PAUSADO','FINISHED','LOST'],
};

let clientesTruncado = false;
async function cargarClientes() {
  if (Object.keys(clientes).length) return;
  try {
    const rows = await fetchDetalle('/entidad_legal?select=id,denominacion_social,nif&limit=1000');
    rows.forEach(r => clientes[r.id] = { nombre: r.denominacion_social, nif: r.nif });
    clientesTruncado = rows.length === 1000; // E6: aviso si se supera el límite de carga
  } catch (e) { /* sin sesión */ }
}
async function cargarUsuarios() {
  if (Object.keys(usuarios).length) return;
  try {
    const rows = await fetchDetalle('/usuario_interno?select=id,nombre_visualizacion&limit=200');
    rows.forEach(r => usuarios[r.id] = { nombre: r.nombre_visualizacion });
  } catch (e) { /* sin sesión */ }
}

function ponerEstados() {
  $('fEstado').innerHTML = '<option value="">— estado —</option>' +
    ESTADOS[sub].map(e => `<option>${e}</option>`).join('');
}
document.querySelectorAll('.subtab').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.subtab').forEach(x => x.classList.remove('activa'));
  b.classList.add('activa'); sub = b.dataset.sub; ponerEstados(); $('expTabla').innerHTML = '';
}));

async function buscar() {
  const st = $('expStatus'); st.textContent = 'buscando…'; st.className = 'status';
  try {
    await cargarClientes(); await cargarUsuarios();
    const est = $('fEstado').value, cli = $('fCliente').value.trim().toLowerCase();
    const d1 = $('fDesde').value, d2 = $('fHasta').value;
    let filas = [], cols = [];
    if (sub === 'facturas') {
      let q = '/factura?select=id,numero_auxadi,codigo_legible,fecha_emision,estado,base_imponible,total,fecha_cobro,cliente_facturacion_id&order=fecha_emision.desc&limit=500';
      if (est) q += `&estado=eq.${est}`;
      if (d1) q += `&fecha_emision=gte.${d1}`; if (d2) q += `&fecha_emision=lte.${d2}`;
      let rows = await fetchDetalle(q);
      rows.forEach(r => { const c = clientes[r.cliente_facturacion_id]||{}; r.cliente = c.nombre||'—'; r._nif = c.nif||''; });
      if (cli) rows = rows.filter(r => (r.cliente||'').toLowerCase().includes(cli) || (r._nif||'').toLowerCase().includes(cli));
      filas = rows;
      cols = [
        { k:'numero_auxadi', t:'Número', f:(v,r)=> v || r.codigo_legible },
        { k:'cliente', t:'Cliente' }, { k:'fecha_emision', t:'Emisión' },
        { k:'estado', t:'Estado', pill:true },
        { k:'base_imponible', t:'Base €', num:true }, { k:'total', t:'Total €', num:true },
        { k:'fecha_cobro', t:'Cobro' },
        { k:'_acc', t:'', html:true, f:(v,r)=> ['ENVIADA','EMITIDA'].includes(r.estado)
            ? `<button class="verde mini" data-accion="cobrada" data-id="${r.id}" data-ref="${esc(r.numero_auxadi||r.codigo_legible||'')}">✓ cobrada</button>` : '' }
      ];
    } else if (sub === 'propuestas') {
      let q = '/propuesta?select=id,codigo_legible,estado,resultado_cierre,fecha_envio,fecha_aceptacion,importe_propuesto,importe_aceptado,cliente_servicio_id&order=creado_en.desc&limit=500';
      if (est) q += `&estado=eq.${est}`;
      let rows = await fetchDetalle(q);
      rows.forEach(r => { const c = clientes[r.cliente_servicio_id]||{}; r.cliente = c.nombre||'—'; r._nif = c.nif||''; r.importe = r.importe_aceptado ?? r.importe_propuesto; });
      if (cli) rows = rows.filter(r => (r.cliente||'').toLowerCase().includes(cli) || (r._nif||'').toLowerCase().includes(cli));
      filas = rows;
      cols = [
        { k:'codigo_legible', t:'Código' }, { k:'cliente', t:'Cliente' },
        { k:'estado', t:'Estado', pill:true }, { k:'resultado_cierre', t:'Resultado' },
        { k:'fecha_envio', t:'Envío' }, { k:'fecha_aceptacion', t:'Aceptación' },
        { k:'importe', t:'Importe €', num:true },
        { k:'_acc', t:'', html:true, f:(v,r)=> r.estado === 'PROPUESTA_ENVIADA'
            ? `<button class="azul mini" data-accion="seguimiento" data-id="${r.id}" data-ref="${esc(r.codigo_legible||'')}">📞 seguir</button>` : '' }
      ];
    } else if (sub === 'hitos') {
      let q = '/hito_facturacion?select=id,codigo_legible,estado,fecha_prevista,importe_neto,descripcion,proyecto_linea_id&order=fecha_prevista.asc&limit=500';
      if (est) q += `&estado=eq.${est}`;
      if (d1) q += `&fecha_prevista=gte.${d1}`; if (d2) q += `&fecha_prevista=lte.${d2}`;
      let rows = await fetchDetalle(q);
      // Cliente/Proyecto vía embedding REST (v_cm_hitos_det no es legible por authenticated, F1)
      const plIds = [...new Set(rows.map(r => r.proyecto_linea_id).filter(Boolean))];
      let plMap = {};
      if (plIds.length) {
        const pls = await fetchDetalle(`/proyecto_linea?select=id,proyecto_id&id=in.(${plIds.join(',')})`);
        const prIds = [...new Set(pls.map(p => p.proyecto_id))];
        const prs = prIds.length ? await fetchDetalle(`/proyecto?select=id,codigo_legible,cliente_facturacion_id&id=in.(${prIds.join(',')})`) : [];
        const prMap = {}; prs.forEach(p => prMap[p.id] = p);
        pls.forEach(p => plMap[p.id] = prMap[p.proyecto_id]);
      }
      rows.forEach(r => {
        const pr = plMap[r.proyecto_linea_id];
        r.proyecto = pr ? pr.codigo_legible : '—';
        r.cliente = pr ? (clientes[pr.cliente_facturacion_id]||{}).nombre || '—' : '—';
      });
      filas = rows;
      cols = [
        { k:'codigo_legible', t:'Hito' }, { k:'cliente', t:'Cliente' }, { k:'proyecto', t:'Proyecto' },
        { k:'descripcion', t:'Descripción' },
        { k:'estado', t:'Estado', pill:true }, { k:'fecha_prevista', t:'Prevista' },
        { k:'importe_neto', t:'Importe €', num:true },
        { k:'_acc', t:'', html:true, f:(v,r)=> ['previsto','facturable'].includes(r.estado)
            ? `<button class="azul mini" data-accion="mover-hito" data-id="${r.id}" data-ref="${esc(r.codigo_legible||'')}" data-fecha="${esc(r.fecha_prevista||'')}">📅 mover</button>` : '' }
      ];
    }
    ultimaFilas = filas; ultimaCols = cols;
    $('expTabla').innerHTML = tablaHtml(filas, cols);
    st.textContent = `${filas.length} resultado(s)` + (filas.length === 500 ? ' — ⚠ limitados a 500, afina el filtro' : '')
      + (clientesTruncado ? ' — ⚠ lista de clientes limitada a 1000, el filtro por cliente puede estar incompleto' : '');
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); st.textContent = 'inicia sesión para ver el detalle'; }
    else { st.textContent = e.message; st.className = 'status error'; }
  }
}

// ============================================================
// PROYECTOS (Kanban, FASE F — antes subpestaña de Explorar)
// ============================================================
async function cargarProyectos() {
  const st = $('pStatus'); st.textContent = 'buscando…'; st.className = 'status';
  try {
    await cargarClientes(); await cargarUsuarios();
    const est = $('pEstado').value, resp = $('pResponsable').value.trim().toLowerCase();
    let q = '/proyecto?select=id,codigo_legible,estado,fecha_inicio,fecha_cierre_estimada,cliente_facturacion_id,client_owner_id,manager_id&order=actualizado_en.desc&limit=500';
    if (est) q += `&estado=eq.${est}`;
    let rows = await fetchDetalle(q);
    const lineas = await fetchDetalle('/proyecto_linea?select=proyecto_id,importe&limit=1000');
    const importePorProyecto = {};
    lineas.forEach(l => { importePorProyecto[l.proyecto_id] = (importePorProyecto[l.proyecto_id]||0) + (+l.importe||0); });
    rows.forEach(r => {
      const c = clientes[r.cliente_facturacion_id]||{};
      r.cliente = c.nombre||'—';
      r.owner = (usuarios[r.client_owner_id]||{}).nombre || '—';
      r.manager = (usuarios[r.manager_id]||{}).nombre || '—';
      r.importe = importePorProyecto[r.id] || 0;
    });
    if (resp) rows = rows.filter(r => (r.owner||'').toLowerCase().includes(resp) || (r.manager||'').toLowerCase().includes(resp));
    const porEstado = {};
    ESTADOS.proyectos.forEach(e => porEstado[e] = []);
    rows.forEach(r => { (porEstado[r.estado] || (porEstado[r.estado] = [])).push(r); });
    $('proyectosKanban').innerHTML = Object.entries(porEstado).map(([estado, ps]) => `
      <div class="kanban-col"><h4>${esc(estado)} (${ps.length})</h4>${ps.map(p => `
        <div class="kanban-card">
          <span class="cod">${esc(p.codigo_legible)}</span>
          ${esc(p.cliente)}<br>
          <span class="imp">${fmt0(p.importe)} €</span>
          <div class="resp">${esc(p.owner)}${p.manager !== '—' ? ' · ' + esc(p.manager) : ''}</div>
        </div>`).join('')}
      </div>`).join('');
    st.textContent = `${rows.length} proyecto(s)`;
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); st.textContent = 'inicia sesión'; }
    else { st.textContent = e.message; st.className = 'status error'; }
  }
}

// E1/E2: cualquier valor que venga de datos (denominaciones sociales, descripciones de
// hitos, notas...) se escapa antes de insertarse en el DOM. Solo las columnas marcadas
// c.html (botones de acción, construidos por este propio código con data-* + delegación,
// nunca con el dato del usuario interpolado en el atributo onclick) se insertan tal cual.
function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function tablaHtml(filas, cols) {
  if (!filas.length) return '<div style="padding:20px;color:#888">sin resultados</div>';
  const numCols = cols.filter(c => c.num).map(c => c.k);
  const sum = {}; numCols.forEach(k => sum[k] = filas.reduce((a,r) => a + (+r[k]||0), 0));
  const th = cols.map(c => `<th>${esc(c.t)}</th>`).join('');
  const trs = filas.map(r => '<tr>' + cols.map(c => {
    let v = c.f ? c.f(r[c.k], r) : r[c.k];
    if (v == null) v = '';
    if (c.pill && v) return `<td><span class="pill ${esc(r[c.k])}">${esc(v)}</span></td>`;
    if (c.html) return `<td>${v}</td>`;
    if (c.num) return `<td class="num">${v === '' ? '' : fmt2(v)}</td>`;
    return `<td>${esc(v)}</td>`;
  }).join('') + '</tr>').join('');
  const tf = '<tr>' + cols.map(c => c.num ? `<td class="num">${fmt2(sum[c.k])}</td>` : '<td></td>').join('') + '</tr>';
  return `<table class="datos"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody><tfoot>${tf}</tfoot></table>`;
}
// Delegación de eventos para los botones de acción de las tablas (E2): nunca se interpola
// el dato del usuario en un atributo onclick, solo en data-* ya escapados por esc().
$('expTabla').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-accion]');
  if (!b) return;
  const { accion, id, ref, fecha } = b.dataset;
  if (accion === 'cobrada') accionCobrada(id, ref);
  else if (accion === 'mover-hito') accionMoverHito(id, ref, fecha);
  else if (accion === 'seguimiento') accionSeguimiento(id, ref);
});

// Acciones de escritura (RPC controladas)
window.accionCobrada = async (id, ref) => {
  const fecha = prompt(`Marcar ${ref} como COBRADA (estimación — no es un dato confirmado por el cliente).\nFecha de cobro (YYYY-MM-DD):`, new Date().toISOString().slice(0,10));
  if (!fecha) return;
  try {
    const r = await rpc('cm_marcar_cobrada', { p_factura_id: id, p_fecha: fecha });
    alert(r.ok ? `✓ ${r.factura} cobrada — estimado (${r.fecha_cobro})` : `No se pudo: ${r.error}`);
    if (r.ok) { buscar(); cargarBadgeAlertas(); }
  } catch (e) { alert('Error: ' + e.message); }
};
window.accionMoverHito = async (id, ref, actual) => {
  const fecha = prompt(`Nueva fecha prevista para ${ref} (actual ${actual}):`, actual);
  if (!fecha) return;
  try {
    const r = await rpc('cm_reprogramar_hito', { p_hito_id: id, p_fecha: fecha });
    alert(r.ok ? `✓ ${r.hito}: ${r.antes} → ${r.ahora}` : `No se pudo: ${r.error}`);
    if (r.ok) { buscar(); cargarBadgeAlertas(); }
  } catch (e) { alert('Error: ' + e.message); }
};
window.accionSeguimiento = async (id, ref) => {
  const nota = prompt(`Registrar seguimiento de ${ref}.\n¿Qué se ha hecho/hablado?`);
  if (!nota) return;
  try {
    const r = await rpc('cm_registrar_seguimiento_propuesta', { p_propuesta_id: id, p_nota: nota });
    alert(r.ok ? `✓ Seguimiento registrado en ${r.propuesta} (${r.fecha})` : `No se pudo: ${r.error}`);
    if (r.ok) { buscar(); cargarBadgeAlertas(); }
  } catch (e) { alert('Error: ' + e.message); }
};

// Exportar CSV (lo último buscado)
function exportarCsv() {
  if (!ultimaFilas.length) { alert('Busca algo primero.'); return; }
  const cols = ultimaCols.filter(c => c.k !== '_acc');
  const cab = cols.map(c => c.t).join(';');
  const lineas = ultimaFilas.map(r => cols.map(c => {
    let v = c.f ? c.f(r[c.k], r) : r[c.k];
    if (v == null) v = '';
    return String(v).replace(/<[^>]+>/g,'').replace(/;/g,',');
  }).join(';'));
  const blob = new Blob(['﻿' + [cab, ...lineas].join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `pcp_${sub}_${new Date().toISOString().slice(0,10)}.csv`;
  a.click(); URL.revokeObjectURL(a.href);
}

// ============================================================
// BADGE DE ALERTAS (en Kira flotante; el detalle lo da el briefing del chat)
// ============================================================
function ponerBadge(n) {
  const b = $('badgeAlertas');
  if (n > 0) { b.textContent = n; b.style.display = 'inline-block'; } else b.style.display = 'none';
}
async function cargarBadgeAlertas() {
  try { const rows = await fetchDetalle('/v_cm_alertas?select=tipo'); ponerBadge(rows.length); } catch {}
}

// Columnas automáticas para resultados de informe (catálogo o SQL libre): mismo criterio
// en las dos superficies que muestran filas arbitrarias (chat de Kira e Informes).
function colsAuto(filas) {
  return filas.length ? Object.keys(filas[0]).map(k => ({
    k, t: k.replace(/^p?_/,'').replace(/_/g,' '),
    num: typeof filas[0][k] === 'number' && !['n','orden'].includes(k)
  })) : [];
}

// ============================================================
// CLIENTE 360º (FASE F): rpt_cliente_resumen ya está en el catálogo clásico de cm-qa
// ("resumen del cliente X" desde el chat) — aquí se añade la vista dedicada y una tarjeta
// compacta reutilizable en ambos sitios. cobrado_fy es una ESTIMACIÓN (cm_marcar_cobrada
// registra la fecha de cobro a mano, no un dato confirmado por el cliente).
// ============================================================
function renderClienteMini(r) {
  return `<div class="cliente-mini">
    <div class="nombre">${esc(r.cliente)}</div>
    <div class="fila"><span>Facturado FY</span><span>${fmt0(r.facturado_fy)} €</span></div>
    <div class="fila"><span>Cobrado FY (estimación)</span><span>${fmt0(r.cobrado_fy)} €</span></div>
    <div class="fila"><span>Pendiente de cobro</span><span>${fmt0(r.pendiente_cobro)} €</span></div>
    <div class="fila"><span>Propuestas abiertas</span><span>${r.propuestas_abiertas}</span></div>
  </div>`;
}
async function buscarCliente360(nombre) {
  const cont = $('c360Resultado'); cont.innerHTML = '<span class="status">buscando…</span>';
  try {
    const filas = await rpc('rpt_cliente_resumen', { p_cliente: nombre });
    if (!filas.length) { cont.innerHTML = `<span class="status">Sin coincidencias para "${esc(nombre)}".</span>`; return; }
    if (filas.length > 1) {
      cont.innerHTML = '<div class="sub" style="margin-bottom:8px">Varias coincidencias, elige una:</div>' +
        filas.map(r => `<button class="mini gris" data-c360="${esc(r.cliente)}" style="margin:0 6px 6px 0">${esc(r.cliente)}</button>`).join('');
      return;
    }
    await pintarCliente360(filas[0]);
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); cont.innerHTML = ''; }
    else cont.innerHTML = `<span class="status error">${esc(e.message)}</span>`;
  }
}
$('c360Resultado').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-c360]');
  if (b) buscarCliente360(b.dataset.c360);
});
async function pintarCliente360(r) {
  const cont = $('c360Resultado');
  cont.innerHTML = `
    <div class="c360-header"><div>
      <h2 style="margin:0;font-family:'Orbitron','Rajdhani',sans-serif;font-size:18px;color:var(--navy-800)">${esc(r.cliente)}</h2>
      <div class="sub">NIF ${esc(r.nif || '—')}</div>
    </div></div>
    <div class="c360-kpis">
      <div class="c360-kpi"><div class="label">Facturado FY</div><div class="valor">${fmt0(r.facturado_fy)} €</div></div>
      <div class="c360-kpi"><div class="label">Cobrado FY</div><div class="valor">${fmt0(r.cobrado_fy)} €</div><div class="nota-estim">estimación</div></div>
      <div class="c360-kpi"><div class="label">Pendiente de cobro</div><div class="valor">${fmt0(r.pendiente_cobro)} €</div></div>
      <div class="c360-kpi"><div class="label">Propuestas abiertas</div><div class="valor">${r.propuestas_abiertas}</div></div>
    </div>
    <h2 class="section-title">Cronología</h2>
    <div id="c360Timeline"><span class="status">cargando…</span></div>`;
  await cargarTimelineCliente360(r.cliente);
}
async function cargarTimelineCliente360(nombreCliente) {
  try {
    await cargarClientes();
    const id = Object.entries(clientes).find(([, c]) => (c.nombre || '').toLowerCase() === nombreCliente.toLowerCase())?.[0];
    if (!id) { $('c360Timeline').innerHTML = '<span class="status">sin cronología (cliente no resuelto)</span>'; return; }
    const [facturas, propuestas] = await Promise.all([
      fetchDetalle(`/factura?select=numero_auxadi,codigo_legible,fecha_emision,estado,total&cliente_facturacion_id=eq.${id}&order=fecha_emision.desc&limit=5`),
      fetchDetalle(`/propuesta?select=codigo_legible,estado,fecha_envio,fecha_aceptacion,importe_propuesto&or=(cliente_servicio_id.eq.${id},cliente_facturacion_id.eq.${id})&order=creado_en.desc&limit=5`),
    ]);
    const items = [
      ...facturas.map(f => ({ fecha: f.fecha_emision, texto: `Factura ${f.numero_auxadi || f.codigo_legible} ${f.estado.toLowerCase()} (${fmt2(f.total)} €)` })),
      ...propuestas.map(p => ({ fecha: p.fecha_aceptacion || p.fecha_envio, texto: `Propuesta ${p.codigo_legible} — ${p.estado.toLowerCase().replace(/_/g,' ')} (${fmt2(p.importe_propuesto)} €)` })),
    ].filter(i => i.fecha).sort((a, b) => b.fecha.localeCompare(a.fecha)).slice(0, 8);
    $('c360Timeline').innerHTML = items.length
      ? '<div class="timeline">' + items.map(i => `<div class="item"><span class="fecha">${esc(i.fecha)}</span> — ${esc(i.texto)}</div>`).join('') + '</div>'
      : '<span class="status">sin movimientos recientes</span>';
  } catch (e) { $('c360Timeline').innerHTML = `<span class="status error">${esc(e.message)}</span>`; }
}

// ============================================================
// INFORMES (FASE F): generar/refinar con Kira (modo informe_libre), ejecutar vía
// cm_ejecutar_informe (candado + solo lectura, ya construido en F1), guardar/exportar.
// ============================================================
let infSql = '', infFilas = [], infCols = [];
async function generarInforme(refinar) {
  const pregunta = $('infPregunta').value.trim();
  if (!pregunta) return;
  const st = $('infStatus'); st.className = 'status'; st.textContent = refinar ? 'refinando…' : 'generando…';
  try {
    const tok = await getToken();
    if (!tok) { mostrarLogin(); st.textContent = 'inicia sesión'; return; }
    const r = await fetch(FUNC_QA, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: ANON, Authorization: `Bearer ${tok}` },
      body: JSON.stringify({ modo: 'informe_libre', pregunta, sql_actual: refinar ? infSql : '' }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    infSql = d.sql || '';
    $('infSqlBox').style.display = 'block'; $('infSqlBox').textContent = infSql;
    $('infTitulo').textContent = d.titulo || '';
    $('btnInfRefinar').disabled = false;
    st.textContent = `vía ${d.proveedor || 'IA'}`;
    await ejecutarInformeActual();
  } catch (e) { st.className = 'status error'; st.textContent = e.message; }
}
async function ejecutarInformeActual() {
  if (!infSql) return;
  const st = $('infStatus');
  try {
    infFilas = await rpc('cm_ejecutar_informe', { p_sql: infSql });
    infCols = colsAuto(infFilas);
    $('infTabla').innerHTML = tablaHtml(infFilas, infCols);
    $('infAcciones').style.display = 'flex';
    st.textContent = `${infFilas.length} fila(s)`;
  } catch (e) { st.className = 'status error'; st.textContent = e.message; }
}
async function guardarInformeActual() {
  if (!infSql) return;
  const nombre = prompt('Nombre para guardar este informe:', $('infTitulo').textContent || $('infPregunta').value);
  if (!nombre) return;
  try {
    await fetchDetalle('/cm_informes_guardados', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ nombre, descripcion: $('infPregunta').value, sql_informe: infSql, config: {} }),
    });
    $('infStatus').textContent = '✓ informe guardado';
    cargarInformesGuardados();
  } catch (e) { $('infStatus').className = 'status error'; $('infStatus').textContent = e.message; }
}
async function cargarInformesGuardados() {
  try {
    const rows = await fetchDetalle('/cm_informes_guardados?select=id,nombre,descripcion,sql_informe,creado_en&order=creado_en.desc');
    $('infGuardados').innerHTML = rows.length ? rows.map(r => `
      <div class="informe-guardado">
        <span class="nombre">${esc(r.nombre)} <span class="fecha">— ${esc((r.creado_en||'').slice(0,10))}</span></span>
        <span style="display:flex;gap:6px">
          <button class="mini" data-inf-run="${r.id}" data-inf-sql="${esc(r.sql_informe)}" data-inf-nombre="${esc(r.nombre)}">Ejecutar</button>
          <button class="mini gris" data-inf-del="${r.id}">Borrar</button>
        </span>
      </div>`).join('') : '<span class="status">sin informes guardados</span>';
  } catch (e) { if (e.message !== 'SIN_SESION') $('infGuardados').innerHTML = `<span class="status error">${esc(e.message)}</span>`; }
}
$('infGuardados').addEventListener('click', async (e) => {
  const bRun = e.target.closest('button[data-inf-run]');
  const bDel = e.target.closest('button[data-inf-del]');
  if (bRun) {
    infSql = bRun.dataset.infSql;
    $('infPregunta').value = bRun.dataset.infNombre;
    $('infSqlBox').style.display = 'block'; $('infSqlBox').textContent = infSql;
    $('infTitulo').textContent = bRun.dataset.infNombre;
    $('btnInfRefinar').disabled = false;
    await ejecutarInformeActual();
  } else if (bDel) {
    if (!confirm('¿Borrar este informe guardado?')) return;
    try { await fetchDetalle(`/cm_informes_guardados?id=eq.${bDel.dataset.infDel}`, { method: 'DELETE' }); cargarInformesGuardados(); }
    catch (e) { alert('Error: ' + e.message); }
  }
});
function exportarInformePdf() {
  if (!infFilas.length) { alert('Ejecuta un informe primero.'); return; }
  const doc = new window.jspdf.jsPDF();
  doc.text($('infTitulo').textContent || 'Informe PCP', 14, 14);
  doc.autoTable({ startY: 20, head: [infCols.map(c => c.t)], body: infFilas.map(r => infCols.map(c => r[c.k] ?? '')) });
  doc.save(`informe_${new Date().toISOString().slice(0,10)}.pdf`);
}
function exportarInformeExcel() {
  if (!infFilas.length) { alert('Ejecuta un informe primero.'); return; }
  const ws = window.XLSX.utils.json_to_sheet(infFilas);
  const wb = window.XLSX.utils.book_new();
  window.XLSX.utils.book_append_sheet(wb, ws, 'Informe');
  window.XLSX.writeFile(wb, `informe_${new Date().toISOString().slice(0,10)}.xlsx`);
}

// ============================================================
// SUBIR DOCUMENTOS (bandeja de entrada → la ingesta del PC la vacía)
// ============================================================
async function subirFicheros(files) {
  const tipo = $('subTipo').value, lista = $('listaSubidas');
  for (const f of files) {
    const item = document.createElement('div'); item.className = 'item';
    item.innerHTML = `<span>${f.name}</span><span class="status">subiendo…</span>`;
    lista.prepend(item);
    try {
      const tok = await getToken();
      if (!tok) throw new Error('inicia sesión');
      const nombre = f.name.replace(/[^\w.\-() ]/g, '_');
      const r = await fetch(`${URL_SB}/storage/v1/object/${BUCKET_INBOX}/${tipo}/${encodeURIComponent(nombre)}`, {
        method: 'POST', headers: { apikey: ANON, Authorization: `Bearer ${tok}`, 'Content-Type': f.type || 'application/pdf' },
        body: f
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      item.lastElementChild.textContent = '✓ en bandeja (' + tipo + ')';
    } catch (e) {
      item.lastElementChild.textContent = '✗ ' + e.message;
      item.lastElementChild.className = 'error';
      if (e.message.includes('sesión')) mostrarLogin();
    }
  }
}
async function verBandeja() {
  const st = $('subStatus'); st.textContent = 'consultando…';
  try {
    const tok = await getToken(); if (!tok) { mostrarLogin(); st.textContent=''; return; }
    let html = '';
    for (const tipo of ['facturas','propuestas','correspondencia']) {
      const r = await fetch(`${URL_SB}/storage/v1/object/list/${BUCKET_INBOX}`, {
        method:'POST', headers:{ apikey:ANON, Authorization:`Bearer ${tok}`, 'Content-Type':'application/json' },
        body: JSON.stringify({ prefix: tipo + '/', limit: 100 })
      });
      const objetos = (await r.json()).filter(o => o.name && !o.name.endsWith('/'));
      if (objetos.length) html += `<div class="sub" style="margin:6px 0"><strong>${tipo}</strong>: ${objetos.map(o=>o.name).join(' · ')}</div>`;
    }
    $('bandejaLista').innerHTML = html || '<span class="sub">bandeja vacía — todo procesado</span>';
    st.textContent = '';
  } catch (e) { st.textContent = e.message; }
}

// ============================================================
// ASISTENTE: chat + informes + voz + Teo
// ============================================================
// En SVG, className es de solo lectura: hay que usar setAttribute.
function teoEstado(e) { $('teo').setAttribute('class', e); }  // reposo | escuchando | pensando | hablando

function addMsg(cls, html) {
  const d = document.createElement('div'); d.className = 'msg ' + cls; d.innerHTML = html;
  $('chatLog').appendChild(d); $('chatLog').scrollTop = 1e9;
  return d;
}

function vozFemenina() {
  const esVoces = speechSynthesis.getVoices().filter(v => v.lang && v.lang.toLowerCase().startsWith('es'));
  const fem = /helena|laura|elvira|sabina|paloma|luc[ií]a|m[oó]nica|montse|dalia|camila|isidora|catalina|female|mujer/i;
  return esVoces.find(v => fem.test(v.name))
      || esVoces.find(v => /google/i.test(v.name))
      || esVoces[0] || null;
}

function hablar(texto) {
  if (!$('chkVoz').checked || !('speechSynthesis' in window) || !texto) return;
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(texto);
  u.lang = 'es-ES';
  u.pitch = 1.05;
  const voz = vozFemenina();
  if (voz) u.voice = voz;
  u.onstart = () => teoEstado('hablando');
  u.onend = () => teoEstado('reposo');
  speechSynthesis.speak(u);
}

// FASE E: la IA propone una acción con un identificador NATURAL (nunca un UUID); la
// resolución a un documento real la hace este código, determinista, para no confiar en
// que la IA "sepa" qué facturas/hitos hay. Solo tras confirmación explícita se llama a la RPC.
async function resolverIdentificador(rpcNombre, identificador) {
  await cargarClientes();
  const q = (identificador || '').trim();
  if (!q) return [];
  if (rpcNombre === 'cm_marcar_cobrada') {
    const idsCliente = Object.entries(clientes)
      .filter(([, c]) => (c.nombre || '').toLowerCase().includes(q.toLowerCase()))
      .map(([id]) => id);
    const or = [`numero_auxadi.ilike.*${q}*`, `codigo_legible.ilike.*${q}*`];
    if (idsCliente.length) or.push(`cliente_facturacion_id.in.(${idsCliente.join(',')})`);
    const rows = await fetchDetalle(`/factura?select=id,numero_auxadi,codigo_legible,estado,base_imponible,total,cliente_facturacion_id&or=(${or.join(',')})&limit=20`);
    return rows.map(r => ({
      id: r.id, ref: r.numero_auxadi || r.codigo_legible, estado: r.estado,
      cliente: (clientes[r.cliente_facturacion_id] || {}).nombre || '—',
      importe: r.total ?? r.base_imponible,
    }));
  }
  if (rpcNombre === 'cm_reprogramar_hito') {
    const rows = await fetchDetalle(`/hito_facturacion?select=id,codigo_legible,estado,importe_neto,fecha_prevista&codigo_legible=ilike.*${q}*&limit=20`);
    return rows.map(r => ({ id: r.id, ref: r.codigo_legible, estado: r.estado, importe: r.importe_neto, fecha_prevista: r.fecha_prevista }));
  }
  // cm_registrar_seguimiento_propuesta
  const idsCliente = Object.entries(clientes)
    .filter(([, c]) => (c.nombre || '').toLowerCase().includes(q.toLowerCase()))
    .map(([id]) => id);
  const or = [`codigo_legible.ilike.*${q}*`];
  if (idsCliente.length) or.push(`cliente_servicio_id.in.(${idsCliente.join(',')})`, `cliente_facturacion_id.in.(${idsCliente.join(',')})`);
  const rows = await fetchDetalle(`/propuesta?select=id,codigo_legible,estado,importe_propuesto,cliente_servicio_id&or=(${or.join(',')})&limit=20`);
  return rows.map(r => ({
    id: r.id, ref: r.codigo_legible, estado: r.estado,
    cliente: (clientes[r.cliente_servicio_id] || {}).nombre || '—',
    importe: r.importe_propuesto,
  }));
}

async function pintarTarjetaAccion(d, msg) {
  msg.textContent = 'resolviendo…';
  let candidatos;
  try { candidatos = await resolverIdentificador(d.rpc, d.identificador); }
  catch (e) {
    if (e.message === 'SIN_SESION') { msg.innerHTML = 'Para confirmar acciones necesitas <strong>iniciar sesión</strong> (botón "entrar" arriba).'; mostrarLogin(); }
    else msg.textContent = 'Error al resolver: ' + e.message;
    return;
  }

  // Ambigüedad o sin resultado: SIN tarjeta de confirmación, solo texto pidiendo precisión
  // (nunca se propone un botón "Confirmar" sobre algo que no identifica un único documento).
  if (candidatos.length === 0) {
    msg.textContent = `No encuentro ningún documento que case con "${d.identificador}". Dime el número o código exacto.`;
    return;
  }
  if (candidatos.length > 1) {
    msg.textContent = `Hay ${candidatos.length} coincidencias con "${d.identificador}" (${candidatos.map(c => c.ref).join(', ')}). Precisa el número o código exacto.`;
    return;
  }
  const resuelto = candidatos[0];

  msg.textContent = '';
  const cont = document.createElement('div'); cont.className = 'tarjeta-accion';
  const resumen = document.createElement('div'); resumen.textContent = d.resumen || 'Confirmar acción';
  cont.appendChild(resumen);
  if (d.rpc === 'cm_marcar_cobrada') {
    const aviso = document.createElement('div'); aviso.className = 'sub';
    aviso.textContent = 'El cobro es una estimación tuya, no un dato confirmado por el cliente.';
    cont.appendChild(aviso);
  }
  const imp = resuelto.importe != null ? fmt2(resuelto.importe) + ' €' : '';
  const linea = document.createElement('div'); linea.className = 'sub';
  linea.textContent = `${resuelto.ref}${resuelto.cliente ? ' — ' + resuelto.cliente : ''}${imp ? ' — ' + imp : ''} (estado: ${resuelto.estado})`;
  cont.appendChild(linea);
  const btns = document.createElement('div'); btns.style.marginTop = '8px';
  const bConf = document.createElement('button'); bConf.className = 'verde mini'; bConf.textContent = 'Confirmar';
  const bCanc = document.createElement('button'); bCanc.className = 'gris mini'; bCanc.textContent = 'Cancelar'; bCanc.style.marginLeft = '6px';
  btns.appendChild(bConf); btns.appendChild(bCanc); cont.appendChild(btns);
  msg.appendChild(cont);
  $('chatLog').scrollTop = 1e9;

  bCanc.onclick = () => { btns.remove(); linea.textContent += ' — cancelado'; };
  bConf.onclick = async () => {
    bConf.disabled = true; bCanc.disabled = true;
    linea.textContent = 'ejecutando…';
    try {
      const params = d.rpc === 'cm_marcar_cobrada' ? { p_factura_id: resuelto.id, p_fecha: d.fecha || new Date().toISOString().slice(0, 10) }
        : d.rpc === 'cm_reprogramar_hito' ? { p_hito_id: resuelto.id, p_fecha: d.fecha }
        : { p_propuesta_id: resuelto.id, p_nota: d.nota || d.resumen };
      const r = await rpc(d.rpc, params);
      if (r.ok) {
        linea.textContent = d.rpc === 'cm_marcar_cobrada' ? `✓ ${r.factura} marcada como cobrada (estimado) — ${r.fecha_cobro}`
          : d.rpc === 'cm_reprogramar_hito' ? `✓ ${r.hito} reprogramado: ${r.antes} → ${r.ahora}`
          : `✓ Seguimiento registrado en ${r.propuesta} (${r.fecha})`;
        cargarBadgeAlertas();
        if (document.getElementById('pantalla-explorar').classList.contains('activa')) buscar().catch(() => {});
      } else {
        linea.textContent = 'No se pudo: ' + r.error;
      }
    } catch (e) { linea.textContent = 'Error: ' + e.message; }
    btns.remove();
  };
}

// FASE I: briefing con datos reales (alertas + previsión del próximo mes + propuestas a
// seguir), en vez del saludo fijo. Disponible también a demanda ("dame el briefing").
let autoBriefingHecho = false;
async function cargarBriefing(msg) {
  try {
    const alertas = await fetchDetalle('/v_cm_alertas?select=tipo,severidad,referencia,cliente,fecha,importe');
    const hoy = new Date();
    const inicio = new Date(hoy.getFullYear(), hoy.getMonth() + 1, 1);
    const fin = new Date(hoy.getFullYear(), hoy.getMonth() + 2, 0);
    const iso = (dt) => dt.toISOString().slice(0, 10);
    let prevision = { n: 0, suma: 0 };
    try {
      const filas = await rpc('rpt_facturas_previstas', { p_desde: iso(inicio), p_hasta: iso(fin) });
      prevision = { n: filas.length, suma: filas.reduce((a, r) => a + (+r.importe || 0), 0) };
    } catch { /* previsión no disponible, el briefing sigue sin ella */ }
    // Los recuentos se calculan aquí, no se le piden a la IA: contar elementos de una
    // lista larga es justo el tipo de cifra que un LLM tiende a inventar mal.
    const propuestasASeguir = alertas.filter(a => a.tipo === 'PROPUESTA_SIN_RESPUESTA');
    const porTipo = {};
    alertas.forEach(a => { porTipo[a.tipo] = (porTipo[a.tipo]||0) + 1; });
    const datos = {
      n_alertas_total: alertas.length,
      n_alertas_por_tipo: porTipo,
      alertas_muestra: alertas.slice(0, 8),
      prevision_proximo_mes: prevision,
      n_propuestas_a_seguir: propuestasASeguir.length,
      propuestas_a_seguir: propuestasASeguir,
    };
    // FASE B: cm-qa exige JWT de usuario real, no la clave ANON (evita que cualquiera con
    // la URL pública queme la cascada de IA). fetchDetalle ya habría lanzado SIN_SESION arriba.
    const tokBrief = await getToken();
    const r = await fetch(FUNC_QA, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: ANON, Authorization: `Bearer ${tokBrief}` },
      body: JSON.stringify({ modo: 'briefing', datos }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    msg.innerHTML = esc(d.respuesta || 'Todo tranquilo por ahora.').replace(/\n/g,'<br>') +
      `<span class="prov">vía ${esc(d.proveedor||'IA')}</span>`;
    hablar(d.habla || d.respuesta);
  } catch (e) {
    if (e.message === 'SIN_SESION') { msg.innerHTML = 'Para el briefing necesitas <strong>iniciar sesión</strong> (botón "entrar" arriba).'; mostrarLogin(); }
    else msg.textContent = 'No he podido preparar el briefing: ' + e.message;
  }
  teoEstado('reposo');
}

async function preguntar(texto) {
  texto = (texto || $('chatInput').value).trim();
  if (!texto) return;
  $('chatInput').value = '';
  addMsg('usuario', esc(texto));
  teoEstado('pensando');
  const msg = addMsg('teo', '<em>pensando…</em>');
  if (/\bbriefing\b/i.test(texto)) { await cargarBriefing(msg); return; }
  // FASE B: cm-qa exige JWT de usuario real (antes se llamaba con la clave ANON pública,
  // invocable por cualquiera que conociera la URL — quemaba la cascada de IA sin control).
  const tok = await getToken();
  if (!tok) {
    msg.innerHTML = 'Para preguntar a Kira necesitas <strong>iniciar sesión</strong> (botón "entrar" arriba).';
    mostrarLogin(); teoEstado('reposo'); return;
  }
  try {
    const r = await fetch(FUNC_QA, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: ANON, Authorization: `Bearer ${tok}` },
      body: JSON.stringify({ pregunta: texto })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);

    if (d.tipo === 'informe') {
      msg.innerHTML = `<strong>${d.titulo || 'Informe'}</strong>`;
      let filas;
      if (d.rpc === 'alertas') {
        filas = await fetchDetalle('/v_cm_alertas?select=*&order=severidad.asc,fecha.asc');
      } else {
        const params = {};
        Object.entries(d.params || {}).forEach(([k,v]) => { if (v !== null && v !== '') params[k] = v; });
        filas = await rpc(d.rpc, params);
      }
      const cont = document.createElement('div'); cont.style.marginTop = '6px';
      if (d.rpc === 'rpt_cliente_resumen' && filas.length === 1) {
        cont.innerHTML = renderClienteMini(filas[0]);
      } else {
        cont.className = 'tabla-scroll';
        cont.innerHTML = tablaHtml(filas, colsAuto(filas));
      }
      msg.appendChild(cont);
      const prov = document.createElement('span'); prov.className = 'prov'; prov.textContent = 'vía ' + (d.proveedor||'IA');
      msg.appendChild(prov);
      hablar(d.habla || `${d.titulo}: ${filas.length} resultados.`);
    } else if (d.tipo === 'accion') {
      await pintarTarjetaAccion(d, msg);
      hablar(d.habla || d.resumen);
    } else {
      msg.innerHTML = esc(d.respuesta || '(sin respuesta)').replace(/\n/g,'<br>') +
        `<span class="prov">vía ${esc(d.proveedor||'IA')}</span>`;
      hablar(d.habla || d.respuesta);
    }
    teoEstado($('chkVoz').checked ? 'hablando' : 'reposo');
  } catch (e) {
    if (e.message === 'SIN_SESION') {
      msg.innerHTML = 'Para informes de detalle necesitas <strong>iniciar sesión</strong> (botón "entrar" arriba).';
      mostrarLogin();
    } else {
      msg.innerHTML = '<span class="error">' + esc(e.message) + '</span>';
    }
    teoEstado('reposo');
  }
}

// --- Instalación PWA: el navegador ofrece su instalador nativo (Windows y Android) ---
let installEvt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault(); installEvt = e;
  const b = $('btnInstalar'); if (b) b.style.display = 'inline-block';
});
window.addEventListener('appinstalled', () => {
  installEvt = null;
  const b = $('btnInstalar'); if (b) b.style.display = 'none';
});

// --- Voz de entrada (Web Speech API) ---
let rec = null;
function initVoz() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) { $('btnMic').style.display = 'none'; return; }
  rec = new SR();
  rec.lang = 'es-ES'; rec.interimResults = false; rec.maxAlternatives = 1;
  rec.onstart = () => { $('btnMic').classList.add('escuchando'); teoEstado('escuchando'); };
  rec.onend = () => { $('btnMic').classList.remove('escuchando'); if ($('teo').getAttribute('class') === 'escuchando') teoEstado('reposo'); };
  rec.onerror = () => { $('btnMic').classList.remove('escuchando'); teoEstado('reposo'); };
  rec.onresult = (ev) => {
    const t = ev.results[0][0].transcript;
    $('chatInput').value = t;
    preguntar(t);
  };
}

// ============================================================
// Arranque
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // botones extra en el login (desbloqueo + respaldo por contraseña)
  const caja = document.querySelector('.login-caja');
  const bB = document.createElement('button'); bB.id='btnBioLogin'; bB.className='verde'; bB.style.marginTop='8px';
  bB.textContent = '🔓 Entrar (huella / Windows Hello / PIN)'; bB.onclick = bioDesbloquear; bB.style.display='none';
  caja.insertBefore(bB, caja.querySelector('.peq'));
  const bP = document.createElement('button'); bP.id='btnUsarPass'; bP.className='gris mini'; bP.style.marginTop='8px'; bP.style.display='none';
  bP.textContent = 'usar contraseña'; bP.onclick = () => { $('formPass').style.display='block'; bP.style.display='none'; $('loginPass').focus(); };
  caja.insertBefore(bP, caja.querySelector('.peq'));
  const bA = document.createElement('button'); bA.id='btnBioActivar'; bA.className='gris mini'; bA.style.display='none';
  bA.textContent = '🔒 activar desbloqueo'; bA.onclick = bioActivar;
  $('btnSesion').after(bA);

  $('btnLogin').onclick = async () => {
    $('loginError').textContent = '';
    try {
      await loginPassword($('loginEmail').value.trim(), $('loginPass').value); ocultarLogin(); refrescarSesionUI();
      cargarPanel();
      // Onboarding del sistema único: tras la primera contraseña, ofrecer el desbloqueo.
      if (!bioActivada() && window.PublicKeyCredential) {
        setTimeout(() => {
          if (confirm('¿Activar el desbloqueo del dispositivo (huella / Windows Hello / PIN)? No volverás a necesitar la contraseña en este equipo.')) bioActivar();
        }, 300);
      }
    }
    catch (e) { $('loginError').textContent = e.message; }
  };
  $('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnLogin').click(); });
  // la capa de login es modal: toda la app (dashboard incluido) queda tras el login
  $('btnSesion').onclick = () => { if (ses) cerrarSesion(); else mostrarLogin(); };
  $('btnInstalar').onclick = async () => {
    if (!installEvt) return;
    installEvt.prompt(); await installEvt.userChoice;
    installEvt = null; $('btnInstalar').style.display = 'none';
  };

  $('refresh').onclick = cargarPanel;
  $('btnBuscar').onclick = buscar;
  $('fCliente').addEventListener('keydown', e => { if (e.key === 'Enter') buscar(); });
  $('btnCsv').onclick = exportarCsv;
  $('pEstado').innerHTML = '<option value="">— estado —</option>' + ESTADOS.proyectos.map(e => `<option>${e}</option>`).join('');
  $('btnProyectos').onclick = cargarProyectos;
  $('btnElegir').onclick = () => $('inputFicheros').click();
  $('inputFicheros').addEventListener('change', e => subirFicheros(e.target.files));
  const zona = $('zonaSubir');
  zona.addEventListener('dragover', e => { e.preventDefault(); zona.classList.add('arrastre'); });
  zona.addEventListener('dragleave', () => zona.classList.remove('arrastre'));
  zona.addEventListener('drop', e => { e.preventDefault(); zona.classList.remove('arrastre'); subirFicheros(e.dataTransfer.files); });
  $('btnVerBandeja').onclick = verBandeja;
  $('btnInfGenerar').onclick = () => generarInforme(false);
  $('btnInfRefinar').onclick = () => generarInforme(true);
  $('btnInfGuardar').onclick = guardarInformeActual;
  $('btnInfPdf').onclick = exportarInformePdf;
  $('btnInfExcel').onclick = exportarInformeExcel;
  $('btnC360Buscar').onclick = () => buscarCliente360($('c360Buscar').value.trim());
  $('c360Buscar').addEventListener('keydown', e => { if (e.key === 'Enter') buscarCliente360($('c360Buscar').value.trim()); });
  $('btnEnviar').onclick = () => preguntar();
  $('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter') preguntar(); });
  $('btnMic').onclick = () => { if (rec) { try { rec.start(); } catch {} } };

  ponerEstados();
  initVoz();
  // E8: la preferencia de voz sobrevive a recargar (antes se marcaba siempre por defecto)
  const vozGuardada = localStorage.getItem(LS_VOZ);
  if (vozGuardada !== null) $('chkVoz').checked = vozGuardada === '1';
  $('chkVoz').addEventListener('change', () => localStorage.setItem(LS_VOZ, $('chkVoz').checked ? '1' : '0'));
  if ('speechSynthesis' in window) speechSynthesis.getVoices(); // precarga de voces

  // sesión previa: sesión en claro > desbloqueo del dispositivo > login obligatorio
  const guardada = localStorage.getItem(LS_SES);
  if (guardada && !bioActivada()) {
    ses = JSON.parse(guardada);
    getToken(); // refresca si caducó
  }
  refrescarSesionUI();
  if (ses) cargarPanel();
  else mostrarLogin();   // dashboard incluido: sin sesión no se carga nada

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
});
