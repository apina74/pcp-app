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

// ============================================================
// SESIÓN (sin librerías: REST de Supabase Auth)
// ============================================================
let ses = null;            // { access_token, refresh_token, expires_at } en memoria
let bioKey = null;         // clave AES derivada del desbloqueo del dispositivo (en memoria)
const LS_SES = 'cm_sesion_v8', LS_BIO = 'cm_bio_v8', LS_BIO_DATA = 'cm_bio_data_v8';

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
// PESTAÑAS
// ============================================================
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('activa'));
  document.querySelectorAll('.pantalla').forEach(x => x.classList.remove('activa'));
  t.classList.add('activa');
  $('pantalla-' + t.dataset.pantalla).classList.add('activa');
  // Toda la app queda tras el login (decisión 2026-07-05): cualquier pestaña exige sesión.
  if (!ses) mostrarLogin();
  if (t.dataset.pantalla === 'alertas' && ses) cargarAlertas();
}));

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
    $('sPendiente').textContent = `${r.n_pendiente||0} placeholders y hitos hasta 30-sep`;
    $('vPrevision').textContent = fmt0((+r.facturado||0)+(+r.pendiente||0)) + ' €';
    $('sPrevision').textContent = `${(r.n_facturado||0)+(r.n_pendiente||0)} conceptos`;
    $('cfPrev').textContent = fmt0((+r.facturado||0)+(+r.pendiente||0)) + ' €';
    $('vCarryAnt').textContent = '+' + fmt0(r.carry_ant) + ' €';
    $('sCarryAnt').textContent = `${r.n_carry_ant||0} hitos FY26 de propuestas pre-FY26`;
    $('vCarryPost').textContent = '−' + fmt0(r.carry_post) + ' €';
    $('sCarryPost').textContent = `${r.n_carry_post||0} hitos posteriores al cierre FY26`;
    fact.facturado = +r.facturado||0; fact.pendiente = +r.pendiente||0;
  });
  const r2 = paso('v_cm_serie_mensual', (rows) => pintarChart(rows||[]), '&order=mes.asc');
  const pipe = {};   // datos para los gráficos de actividad comercial
  const r3 = paso('v_cm_ventas', (rows) => { const r = rows[0]; if (!r) return;
    const tot = (+r.ventas||0)+(+r.perdidas||0);
    const pct = (n) => tot>0 ? ((n/tot)*100).toFixed(1).replace('.',',')+'%' : '—';
    $('vVentas').innerHTML = fmt0(r.ventas) + ' € <span class="pct">' + pct(+r.ventas||0) + '</span>';
    $('sVentas').textContent = `${r.n_ventas||0} propuestas aceptadas en FY26`;
    $('vPerdidas').innerHTML = fmt0(r.perdidas) + ' € <span class="pct">' + pct(+r.perdidas||0) + '</span>';
    $('sPerdidas').textContent = `${r.n_perdidas||0} propuestas rechazadas FY26`;
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
      { type:'line', label:'Acumulado FY26', data: acumulado, yAxisID:'y2', borderColor:'#00f0ff',
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
    ' &nbsp; <span style="display:inline-block;width:22px;border-top:2px solid #00f0ff;vertical-align:middle;margin-right:4px"></span>Acumulado FY26 (eje dcho.)';
}

// ============================================================
// EXPLORAR (detalle con sesión) + acciones
// ============================================================
let sub = 'facturas', clientes = {};       // id -> {nombre, nif}
let ultimaFilas = [], ultimaCols = [];

const ESTADOS = {
  facturas:   ['EMITIDA','ENVIADA','COBRADA','ANULADA'],
  propuestas: ['OPORTUNIDAD','PROPUESTA_ENVIADA','CERRADA'],
  hitos:      ['previsto','facturable','facturado'],
};

async function cargarClientes() {
  if (Object.keys(clientes).length) return;
  try {
    const rows = await fetchDetalle('/entidad_legal?select=id,denominacion_social,nif&limit=1000');
    rows.forEach(r => clientes[r.id] = { nombre: r.denominacion_social, nif: r.nif });
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
    await cargarClientes();
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
        { k:'_acc', t:'', f:(v,r)=> ['ENVIADA','EMITIDA'].includes(r.estado)
            ? `<button class="verde mini" onclick="accionCobrada('${r.id}','${(r.numero_auxadi||r.codigo_legible||'').replace(/'/g,'')}')">✓ cobrada</button>` : '' }
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
        { k:'importe', t:'Importe €', num:true }
      ];
    } else {
      let q = '/hito_facturacion?select=id,codigo_legible,estado,fecha_prevista,importe_neto,descripcion&order=fecha_prevista.asc&limit=500';
      if (est) q += `&estado=eq.${est}`;
      if (d1) q += `&fecha_prevista=gte.${d1}`; if (d2) q += `&fecha_prevista=lte.${d2}`;
      filas = await fetchDetalle(q);
      cols = [
        { k:'codigo_legible', t:'Hito' }, { k:'descripcion', t:'Descripción' },
        { k:'estado', t:'Estado', pill:true }, { k:'fecha_prevista', t:'Prevista' },
        { k:'importe_neto', t:'Importe €', num:true },
        { k:'_acc', t:'', f:(v,r)=> ['previsto','facturable'].includes(r.estado)
            ? `<button class="azul mini" onclick="accionMoverHito('${r.id}','${(r.codigo_legible||'').replace(/'/g,'')}','${r.fecha_prevista||''}')">📅 mover</button>` : '' }
      ];
    }
    ultimaFilas = filas; ultimaCols = cols;
    $('expTabla').innerHTML = tablaHtml(filas, cols);
    st.textContent = `${filas.length} resultado(s)`;
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); st.textContent = 'inicia sesión para ver el detalle'; }
    else { st.textContent = e.message; st.className = 'status error'; }
  }
}

function tablaHtml(filas, cols) {
  if (!filas.length) return '<div style="padding:20px;color:#888">sin resultados</div>';
  const numCols = cols.filter(c => c.num).map(c => c.k);
  const sum = {}; numCols.forEach(k => sum[k] = filas.reduce((a,r) => a + (+r[k]||0), 0));
  const th = cols.map(c => `<th>${c.t}</th>`).join('');
  const trs = filas.map(r => '<tr>' + cols.map(c => {
    let v = c.f ? c.f(r[c.k], r) : r[c.k];
    if (v == null) v = '';
    if (c.pill && v) v = `<span class="pill ${r[c.k]}">${v}</span>`;
    if (c.num) v = v === '' ? '' : fmt2(v);
    return `<td${c.num?' class="num"':''}>${v}</td>`;
  }).join('') + '</tr>').join('');
  const tf = '<tr>' + cols.map(c => c.num ? `<td class="num">${fmt2(sum[c.k])}</td>` : '<td></td>').join('') + '</tr>';
  return `<table class="datos"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody><tfoot>${tf}</tfoot></table>`;
}

// Acciones de escritura (RPC controladas)
window.accionCobrada = async (id, ref) => {
  const fecha = prompt(`Marcar ${ref} como COBRADA.\nFecha de cobro (YYYY-MM-DD):`, new Date().toISOString().slice(0,10));
  if (!fecha) return;
  try {
    const r = await rpc('cm_marcar_cobrada', { p_factura_id: id, p_fecha: fecha });
    alert(r.ok ? `✓ ${r.factura} cobrada (${r.fecha_cobro})` : `No se pudo: ${r.error}`);
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
// ALERTAS
// ============================================================
async function cargarAlertas() {
  const st = $('alStatus'); st.textContent = 'cargando…';
  try {
    const rows = await fetchDetalle('/v_cm_alertas?select=*&order=severidad.asc,fecha.asc');
    $('alTabla').innerHTML = tablaHtml(rows, [
      { k:'severidad', t:'Nivel', pill:true }, { k:'tipo', t:'Tipo' },
      { k:'referencia', t:'Referencia' }, { k:'cliente', t:'Cliente' },
      { k:'fecha', t:'Fecha' }, { k:'importe', t:'Importe €', num:true }, { k:'detalle', t:'Detalle' }
    ]);
    st.textContent = `${rows.length} alerta(s)`;
    ponerBadge(rows.length);
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); st.textContent = 'inicia sesión'; }
    else st.textContent = e.message;
  }
}
function ponerBadge(n) {
  const b = $('badgeAlertas');
  if (n > 0) { b.textContent = n; b.style.display = 'inline-block'; } else b.style.display = 'none';
}
async function cargarBadgeAlertas() {
  try { const rows = await fetchDetalle('/v_cm_alertas?select=tipo'); ponerBadge(rows.length); } catch {}
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

async function preguntar(texto) {
  texto = (texto || $('chatInput').value).trim();
  if (!texto) return;
  $('chatInput').value = '';
  addMsg('usuario', texto.replace(/</g,'&lt;'));
  teoEstado('pensando');
  const msg = addMsg('teo', '<em>pensando…</em>');
  try {
    const r = await fetch(FUNC_QA, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: ANON, Authorization: `Bearer ${ANON}` },
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
      const cols = filas.length ? Object.keys(filas[0]).map(k => ({
        k, t: k.replace(/^p?_/,'').replace(/_/g,' '),
        num: typeof filas[0][k] === 'number' && !['n','orden'].includes(k)
      })) : [];
      const cont = document.createElement('div'); cont.className = 'tabla-scroll';
      cont.innerHTML = tablaHtml(filas, cols);
      msg.appendChild(cont);
      const prov = document.createElement('span'); prov.className = 'prov'; prov.textContent = 'vía ' + (d.proveedor||'IA');
      msg.appendChild(prov);
      hablar(d.habla || `${d.titulo}: ${filas.length} resultados.`);
    } else {
      msg.innerHTML = (d.respuesta || '(sin respuesta)').replace(/</g,'&lt;').replace(/\n/g,'<br>') +
        `<span class="prov">vía ${d.proveedor||'IA'}</span>`;
      hablar(d.habla || d.respuesta);
    }
    teoEstado($('chkVoz').checked ? 'hablando' : 'reposo');
    if (!$('chkVoz').checked) teoEstado('reposo');
  } catch (e) {
    if (e.message === 'SIN_SESION') {
      msg.innerHTML = 'Para informes de detalle necesitas <strong>iniciar sesión</strong> (botón "entrar" arriba).';
      mostrarLogin();
    } else {
      msg.innerHTML = '<span class="error">' + e.message.replace(/</g,'&lt;') + '</span>';
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
  $('btnAlertas').onclick = cargarAlertas;
  $('btnElegir').onclick = () => $('inputFicheros').click();
  $('inputFicheros').addEventListener('change', e => subirFicheros(e.target.files));
  const zona = $('zonaSubir');
  zona.addEventListener('dragover', e => { e.preventDefault(); zona.classList.add('arrastre'); });
  zona.addEventListener('dragleave', () => zona.classList.remove('arrastre'));
  zona.addEventListener('drop', e => { e.preventDefault(); zona.classList.remove('arrastre'); subirFicheros(e.dataTransfer.files); });
  $('btnVerBandeja').onclick = verBandeja;
  $('btnEnviar').onclick = () => preguntar();
  $('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter') preguntar(); });
  $('btnMic').onclick = () => { if (rec) { try { rec.start(); } catch {} } };

  ponerEstados();
  initVoz();
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
