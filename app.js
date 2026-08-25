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

// ⚠ NUNCA usar toISOString() para convertir una fecha del calendario a texto: convierte a UTC
// y desde España (UTC+1/+2) devuelve EL DÍA ANTERIOR. Se destapó el 04-08-2026 auditando el
// briefing: pedía la previsión "del próximo mes" y consultaba del 31-ago al 29-sep, con lo que
// presentaba como septiembre los cinco hitos que vencían el 31 de agosto. La fecha era
// correcta como suma y falsa como etiqueta, que es la peor combinación.
const fechaIso = (dt) => `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`;
$('hoy').textContent = fechaIso(new Date());

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
// Bloque E: memoria conversacional de Kira. Solo los últimos turnos y solo texto — es
// contexto para desambiguar ("¿y de CAF?"), no un archivo del chat. Se declara aquí, con el
// resto del estado de sesión, porque cerrarSesion() la vacía.
let historialChat = [];
const LS_SES = 'cm_sesion_v8', LS_BIO = 'cm_bio_v8', LS_BIO_DATA = 'cm_bio_data_v8', LS_VOZ = 'cm_voz_v8';

function emailDe(tok) {
  try { return JSON.parse(atob(tok.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).email || ''; }
  catch { return ''; }
}

async function persistirSesion() {
  if (!ses) return;
  if (bioActivada()) {
    if (bioKey) await bioGuardarCifrado(ses.refresh_token);
    else {
      // Modo barrera (sin PRF): el refresh vive en claro dentro de LS_BIO_DATA — hay que
      // mantenerlo al día también cuando se entra por contraseña, o caduca y el
      // desbloqueo muere (mismo fallo que el caso PRF, ver bioRevincular).
      const data = JSON.parse(localStorage.getItem(LS_BIO_DATA) || '{}');
      if (data.plano) localStorage.setItem(LS_BIO_DATA, JSON.stringify({ plano: ses.refresh_token }));
    }
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
  historialChat = [];      // la memoria del chat no sobrevive al cierre de sesión
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
    $('loginError').textContent = 'No se pudo desbloquear: ' + e.message +
      (e.message === 'sesión caducada' ? ' — entra con la contraseña y el desbloqueo se re-vinculará solo.' : '');
  }
}

// Tras entrar con la contraseña de RESPALDO estando el desbloqueo activado: el refresh
// token cifrado quedó obsoleto (caducó o Supabase lo rotó) y Hello fallaba con "sesión
// caducada" PARA SIEMPRE — entrar por contraseña no lo reparaba porque sin assertion no
// hay bioKey con la que re-cifrar (visto 2026-07-22 en el preview). Una assertion
// re-deriva la clave PRF y deja cifrado el token vigente.
async function bioRevincular() {
  const cfg = JSON.parse(localStorage.getItem(LS_BIO) || 'null');
  if (!cfg || !cfg.prf || bioKey || !ses) return;
  try {
    const out = await bioAssertion();
    if (out) { bioKey = await claveDesdePrf(out); await bioGuardarCifrado(ses.refresh_token); }
  } catch {
    alert('El desbloqueo del dispositivo sigue sin re-vincularse: la próxima entrada volverá a pedir contraseña. Se reintentará tras el siguiente login.');
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
    cargarClientes(); cargarBadgeAlertas(); comprobarAvisos();
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
  cerrarMenu();
  // Toda la app queda tras el login (decisión 2026-07-05): cualquier pantalla exige sesión.
  if (!ses) mostrarLogin();
  if (t.dataset.pantalla === 'proyectos' && ses) cargarProyectos();
  if (t.dataset.pantalla === 'informes' && ses) cargarInformesGuardados();
  if (t.dataset.pantalla === 'subir' && ses) { cargarIngesta(); cargarIngestaProp(); cargarIngestaCorr(); }
}));

// Menú lateral en móvil (F3): en escritorio el sidebar es fijo y esto no llega a actuar.
function cerrarMenu() {
  $('navLateral').classList.remove('abierto');
  $('navVelo').hidden = true;
  $('btnMenu').setAttribute('aria-expanded', 'false');
}
$('btnMenu').addEventListener('click', () => {
  const abierto = $('navLateral').classList.toggle('abierto');
  $('navVelo').hidden = !abierto;
  $('btnMenu').setAttribute('aria-expanded', String(abierto));
});
$('navVelo').addEventListener('click', cerrarMenu);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') cerrarMenu(); });

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
    $('sFacturado').textContent = `${r.n_facturado||0} facturas emitidas con documento`;
    $('vPendiente').textContent = fmt0(r.pendiente) + ' €';
    $('sPendiente').textContent = `${r.n_pendiente||0} hitos pendientes hasta ${fyFinCorto()}`;
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
let sub = 'propuestas', clientes = {}, usuarios = {};   // id -> {nombre, nif} / id -> {nombre}
let ultimaFilas = [], ultimaCols = [];

// Cada fila abre la ficha de la propuesta que la engloba (m284 expone propuesta_id en las
// cuatro vistas). El vínculo se sigue, nunca se deduce del código: PRJ-FY26-078 cuelga de
// PROP-FY26-084, y dos proyectos distintos pueden colgar de la misma propuesta.
const btnFicha = (v) => v ? `<button class="ficha-btn" data-prop="${esc(v)}" title="Abrir la ficha de la propuesta">◧ ficha</button>` : '';
const celda = (clase) => (v) => v ? `<span class="${clase}">${esc(v)}</span>` : '<span class="celda-vacia">—</span>';
const accionesPropuesta = (r) => {
  if (r.estado === 'PROPUESTA_ENVIADA') return ''
    + `<button class="verde mini" data-accion="aceptar" data-id="${r.propuesta_id}" data-ref="${esc(r.codigo||'')}">✓ aceptar</button> `
    + `<button class="azul mini" data-accion="seguimiento" data-id="${r.propuesta_id}" data-ref="${esc(r.codigo||'')}">📞 seguir</button> `
    + `<button class="gris mini" data-accion="cerrar-no" data-id="${r.propuesta_id}" data-ref="${esc(r.codigo||'')}">✗ cerrar</button>`;
  if (r.estado === 'OPORTUNIDAD') return ''
    + `<button class="gris mini" data-accion="cerrar-no" data-id="${r.propuesta_id}" data-ref="${esc(r.codigo||'')}">✗ perdida</button>`;
  return '';
};

// Las cuatro vistas de la pantalla, en el orden del encargo (03-08). Todas leen de las vistas
// v_cm_consultar_* (m284/m286), que ya traen grupo, cliente y referidor resueltos y el par
// vive_desde/vive_hasta con el que se filtra por ejercicio.
// ⚠ Estados: «cerrada» se descompone en ACEPTADA / RECHAZADA / PERDIDA — las 78 propuestas
// cerradas compartían etiqueta y no se podían distinguir.
const VISTAS = {
  propuestas: {
    ruta: '/v_cm_consultar_propuestas', orden: 'fecha_envio.desc.nullslast', fecha: 'fecha_envio',
    estados: { OPORTUNIDAD:'Oportunidad', PROPUESTA_ENVIADA:'Enviada', ACEPTADA:'Aceptada', RECHAZADA:'Rechazada', PERDIDA:'Perdida' },
    cols: [
      // La ficha solo en las aceptadas: sin proyectos ni crónica estaría vacía.
      { k:'propuesta_id', t:'Ficha', html:true, f:(v,r) => r.estado === 'ACEPTADA' ? btnFicha(v) : '' },
      { k:'codigo', t:'Código' },
      { k:'grupo', t:'Grupo', html:true, f:celda('celda-grupo') },
      { k:'cliente', t:'Cliente', cls:'recorta' },
      { k:'estado', t:'Estado', pill:true },
      { k:'fecha_envio', t:'Envío' }, { k:'fecha_aceptacion', t:'Aceptación' },
      { k:'importe', t:'Importe €', num:true },
      { k:'_acc', t:'', html:true, f:(v,r) => accionesPropuesta(r) },
    ],
  },
  proyectos: {
    ruta: '/v_cm_consultar_proyectos', orden: 'codigo.asc', fecha: 'vive_desde',
    estados: { PENDIENTE_IDR:'Pendiente de IDR', PENDIENTE_INFO:'Pendiente de información', ACTIVO:'Activo',
               PENDIENTE_REVISION_CLIENTE:'Pendiente de revisión', COMPLETADO:'Completado', PAUSADO:'Pausado', LOST:'Perdido' },
    cols: [
      { k:'propuesta_id', t:'Ficha', html:true, f:btnFicha },
      { k:'codigo', t:'Código' },
      { k:'grupo', t:'Grupo', html:true, f:celda('celda-grupo') },
      { k:'cliente', t:'Cliente', cls:'recorta' },
      { k:'referidor', t:'Referidor', html:true, cls:'recorta', f:celda('celda-ref') },
      { k:'estado', t:'Estado', pill:true },
      { k:'descripcion', t:'Descripción', cls:'desc' },
      { k:'importe', t:'Importe €', num:true },
      { k:'facturado', t:'Facturado €', num:true },
      { k:'pendiente', t:'Pendiente €', num:true },
    ],
  },
  hitos: {
    ruta: '/v_cm_consultar_hitos', orden: 'fecha_prevista.asc', fecha: 'fecha_prevista',
    estados: { previsto:'Previsto', facturado:'Facturado' },
    cols: [
      { k:'propuesta_id', t:'Ficha', html:true, f:btnFicha },
      { k:'codigo', t:'Hito' }, { k:'proyecto', t:'Proyecto' },
      { k:'grupo', t:'Grupo', html:true, f:celda('celda-grupo') },
      { k:'cliente', t:'Cliente', cls:'recorta' },
      { k:'descripcion', t:'Descripción', cls:'desc' },
      { k:'estado', t:'Estado', pill:true },
      { k:'fecha_prevista', t:'Prevista' },
      { k:'importe', t:'Importe €', num:true },
      { k:'_acc', t:'', html:true, f:(v,r) => r.estado === 'previsto'
          ? `<button class="azul mini" data-accion="mover-hito" data-id="${r.hito_id}" data-ref="${esc(r.codigo||'')}" data-fecha="${esc(r.fecha_prevista||'')}">📅 mover</button>` : '' },
    ],
  },
  facturas: {
    ruta: '/v_cm_consultar_facturas', orden: 'fecha_emision.desc', fecha: 'fecha_emision',
    estados: { EMITIDA:'Emitida', ANULADA:'Anulada' },
    cols: [
      { k:'propuesta_id', t:'Ficha', html:true, f:btnFicha },
      { k:'numero', t:'Número', f:(v,r) => v || r.codigo_legible },
      { k:'grupo', t:'Grupo', html:true, f:celda('celda-grupo') },
      { k:'cliente', t:'Cliente', cls:'recorta' },
      { k:'fecha_emision', t:'Emisión' },
      { k:'estado', t:'Estado', pill:true },
      { k:'base', t:'Base €', num:true }, { k:'total', t:'Total €', num:true },
      // Reforma 2026-08 (D17/D19): lo que distingue una factura real de un apunte sin respaldo
      // es el DOCUMENTO, no el estado.
      { k:'tiene_documento', t:'Documento', f:(v) => v ? 'sí' : '—' },
    ],
  },
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
  const e = VISTAS[sub].estados;
  $('fEstado').innerHTML = '<option value="">— estado —</option>' +
    Object.entries(e).map(([k, r]) => `<option value="${k}">${r}</option>`).join('');
}
document.querySelectorAll('.subtab').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.subtab').forEach(x => x.classList.remove('activa'));
  b.classList.add('activa'); sub = b.dataset.sub; ponerEstados(); $('expTabla').innerHTML = '';
  $('expStatus').textContent = '';
  // El catálogo de los filtros cambia con la vista (m289): lo elegido para una puede no existir
  // en la siguiente, así que se limpia en vez de arrastrar una selección que daría vacío.
  ['cliente','grupo','referidor'].forEach(c => selFiltro[c] = []);
  document.querySelectorAll('#pantalla-explorar .multi').forEach(m => {
    m.querySelectorAll('.chip').forEach(c => c.remove());
    m.querySelector('input').placeholder = m.dataset.campo + '…';
    m.querySelector('.sug').classList.remove('abierta');
  });
}));

// ---- Filtros de selección múltiple (cliente / grupo / referidor) ----
// Con 128 entidades una lista plana no sirve: se teclea y se eligen varias, que suman.
const selFiltro = { cliente: [], grupo: [], referidor: [] };
const CLASE_CHIP = { cliente: '', grupo: 'gr', referidor: 'rf' };
let catPorVista = {}, catClientes = null, cargando = {}, ejercicios = null, fySel = null;

// El catálogo de cada filtro sale de la PROPIA VISTA que se va a filtrar (m289): el desplegable
// de Facturas solo ofrece quien tiene facturas (56 clientes, no 74). Si una opción está en la
// lista, hay al menos una fila detrás — no se puede elegir algo que devuelva vacío.
async function cargarCatalogo(vista) {
  if (catPorVista[vista]) return catPorVista[vista];
  if (cargando[vista]) return cargando[vista];
  cargando[vista] = (async () => {
    const filas = await fetchDetalle(`/v_cm_catalogo_filtros?select=tipo,id,nombre&vista=eq.${vista}&order=nombre.asc`);
    const c = { cliente: [], grupo: [], referidor: [] };
    filas.forEach(f => { if (c[f.tipo]) c[f.tipo].push({ id: f.id, nombre: f.nombre }); });
    catPorVista[vista] = c;
    return c;
  })().finally(() => { delete cargando[vista]; });
  return cargando[vista];
}

// Cliente 360º filtra sobre todos los clientes con actividad, no sobre una vista concreta.
async function cargarClientesFiltro() {
  if (catClientes) return catClientes;
  const cli = await fetchDetalle('/v_cm_clientes?select=id,nombre&order=nombre.asc');
  catClientes = cli.map(x => ({ id: x.id, nombre: x.nombre }));
  return catClientes;
}

async function cargarEjercicios() {
  if (ejercicios) return ejercicios;
  ejercicios = await fetchDetalle('/v_cm_ejercicios?select=*&order=fecha_inicio.asc');
  // Los botones de ejercicio salen de la base: FY27 aparecerá solo cuando exista.
  $('fyBotones').innerHTML = ejercicios.map(f => `<button class="fy" data-fy="${esc(f.codigo)}">${esc(f.codigo)}</button>`).join(' ');
  $('fyBotones').querySelectorAll('.fy').forEach(b => b.addEventListener('click', () => {
    const ya = b.classList.contains('on');
    $('fyBotones').querySelectorAll('.fy').forEach(x => x.classList.remove('on'));
    if (!ya) { b.classList.add('on'); fySel = b.dataset.fy; } else fySel = null;
    buscar().catch(() => {});
  }));
  return ejercicios;
}

// opciones.store    → dónde guarda la selección (por defecto, los filtros de Consultar)
// opciones.uni      → selección única: sustituye lo elegido y cierra la lista
// opciones.alCambiar→ qué hacer al cambiar la selección
// opciones.vacio    → texto del campo cuando no hay nada elegido
function montarMulti(m, opciones = {}) {
  const campo = m.dataset.campo, caja = m.querySelector('.caja'),
        inp = m.querySelector('input'), sug = m.querySelector('.sug');
  const store = opciones.store || selFiltro;
  const uni = !!opciones.uni;
  const alCambiar = opciones.alCambiar || (() => buscar().catch(() => {}));
  const vacio = opciones.vacio || (campo + '…');
  // De dónde salen las opciones: por defecto, el catálogo de la vista activa de Consultar.
  const fuente = opciones.fuente || (async () => (await cargarCatalogo(sub))[campo]);
  const pintar = () => {
    caja.querySelectorAll('.chip').forEach(c => c.remove());
    store[campo].forEach(o => {
      const c = document.createElement('span');
      c.className = 'chip ' + (CLASE_CHIP[campo] || '');
      c.innerHTML = `<span></span><b>×</b>`;
      c.querySelector('span').textContent = o.nombre;      // textContent: nunca interpolar
      c.querySelector('b').onclick = (ev) => { ev.stopPropagation();
        store[campo] = store[campo].filter(x => x.id !== o.id); pintar(); alCambiar(); };
      caja.insertBefore(c, inp);
    });
    inp.placeholder = store[campo].length ? '' : vacio;
  };
  // La lista se despliega al pulsar, sin necesidad de teclear, y NO se cierra al marcar: es
  // multiselección, así que se marcan varias seguidas y se cierra con Escape o pulsando fuera.
  // Escribir solo filtra las opciones.
  let lista = null;   // catálogo cargado para el contexto actual
  const pintarLista = () => {
    const q = inp.value.trim().toLowerCase();
    const marcado = (o) => store[campo].some(s => s.id === o.id);
    const op = (lista || []).filter(o => o.nombre.toLowerCase().includes(q)).slice(0, 60);
    sug.innerHTML = '';
    if (!op.length) { sug.innerHTML = '<div class="vacio">sin coincidencias</div>'; return; }
    op.forEach(o => {
      const d = document.createElement('div');
      d.className = 'opcion' + (marcado(o) ? ' marcada' : '');
      const c = document.createElement('span'); c.className = 'tick'; c.textContent = marcado(o) ? '✓' : '';
      const t = document.createElement('span'); t.textContent = o.nombre;
      d.append(c, t);
      d.onclick = (ev) => {
        ev.stopPropagation();
        if (uni) {
          // Selección única: sustituye lo elegido y cierra, como cualquier desplegable normal.
          store[campo] = marcado(o) ? [] : [o];
          inp.value = ''; pintar(); sug.classList.remove('abierta'); alCambiar();
          return;
        }
        if (marcado(o)) store[campo] = store[campo].filter(s => s.id !== o.id);
        else store[campo].push(o);
        pintar(); pintarLista(); alCambiar();   // multiselección: la lista sigue abierta
      };
      sug.appendChild(d);
    });
  };
  const abrir = async () => {
    sug.classList.add('abierta');
    // Se pide siempre: el catálogo depende de la vista activa y cambia al cambiar de subpestaña.
    // Al arrancar puede no haber sesión todavía, así que aquí se reintenta en vez de quedarse mudo.
    sug.innerHTML = '<div class="vacio">cargando…</div>';
    try { lista = await fuente(); }
    catch (e) { sug.innerHTML = `<div class="vacio">${esc(e.message === 'SIN_SESION' ? 'inicia sesión para filtrar' : e.message)}</div>`; return; }
    pintarLista();
  };
  const cerrar = () => sug.classList.remove('abierta');

  caja.onclick = () => { inp.focus(); if (!sug.classList.contains('abierta')) abrir(); else cerrar(); };
  inp.onfocus = abrir;
  inp.oninput = () => { if (lista) { sug.classList.add('abierta'); pintarLista(); } };
  inp.onkeydown = (e) => {
    if (e.key === 'Backspace' && !inp.value && store[campo].length) { store[campo].pop(); pintar(); if (lista) pintarLista(); alCambiar(); }
    if (e.key === 'Escape') cerrar();
  };
  document.addEventListener('click', (e) => { if (!m.contains(e.target)) cerrar(); });
}

async function buscar() {
  const st = $('expStatus'); st.textContent = 'buscando…'; st.className = 'status';
  try {
    await cargarEjercicios();
    const v = VISTAS[sub];
    let q = `${v.ruta}?select=*&order=${v.orden}&limit=500`;

    const est = $('fEstado').value;
    if (est) q += `&estado=eq.${encodeURIComponent(est)}`;

    // Los tres desplegables se combinan entre sí; dentro de cada uno, las opciones suman.
    ['cliente','grupo','referidor'].forEach(c => {
      if (selFiltro[c].length) q += `&${c}_id=in.(${selFiltro[c].map(o => o.id).join(',')})`;
    });

    // Ejercicio: no es «a cuál pertenece» sino «qué estuvo vivo durante él». Las vistas exponen
    // vive_desde/vive_hasta con extremos abiertos (m286), así que basta el solapamiento.
    if (fySel) {
      const fy = ejercicios.find(e => e.codigo === fySel);
      if (fy) q += `&vive_desde=lte.${fy.fecha_fin}&vive_hasta=gte.${fy.fecha_inicio}`;
    }

    const d1 = $('fDesde').value, d2 = $('fHasta').value;
    if (d1) q += `&${v.fecha}=gte.${d1}`;
    if (d2) q += `&${v.fecha}=lte.${d2}`;

    const filas = await fetchDetalle(q);
    ultimaFilas = filas; ultimaCols = v.cols;
    $('expTabla').innerHTML = tablaHtml(filas, v.cols);
    st.textContent = `${filas.length} resultado(s)`
      + (filas.length === 500 ? ' — ⚠ limitados a 500, afina el filtro' : '')
      + (fySel ? ` · ${fySel}` : '');
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); st.textContent = 'inicia sesión para ver el detalle'; }
    else { st.textContent = e.message; st.className = 'status error'; }
  }
}

// ============================================================
// WORK-IN-PROGRESS (03-08-2026; antes «Proyectos»)
// Una ficha = una PROPUESTA. Si sus proyectos están en estados distintos,
// sale una ficha por estado. Lo completado y lo perdido no aparecen: el WIP
// enseña trabajo en curso. Todo el cálculo vive en v_cm_wip (m274).
// ============================================================
const WIP_COLUMNAS = [
  ['PENDIENTE_IDR',              'Pendiente de IDR',           'Sin encargos. Aquí entran los que acabas de ganar, hasta que sale el primer IDR.'],
  ['PENDIENTE_INFO',             'Pendiente de información',   'Sin encargos.'],
  ['ACTIVO',                     'Activo',                     'Sin encargos.'],
  ['PENDIENTE_REVISION_CLIENTE', 'Pendiente revisión cliente', 'Sin encargos.'],
  ['PAUSADO',                    'Pausado',                    'Sin encargos. Estado excepcional.'],
];

async function cargarProyectos() {
  const res = $('wipResumen'); res.textContent = 'cargando…'; res.className = 'wip-resumen';
  try {
    const rows = await fetchDetalle('/v_cm_wip?select=*&order=orden_estado.asc,pendiente.desc');
    const porEstado = {};
    WIP_COLUMNAS.forEach(([cod]) => porEstado[cod] = []);
    rows.forEach(r => (porEstado[r.estado] || (porEstado[r.estado] = [])).push(r));

    $('proyectosKanban').innerHTML = WIP_COLUMNAS.map(([cod, rotulo, vacio]) => {
      const fichas = porEstado[cod] || [];
      const suma = fichas.reduce((a, f) => a + (+f.pendiente || 0), 0);
      return `
      <div class="kanban-col${cod === 'PAUSADO' ? ' pausado' : ''}">
        <h4><span>${esc(rotulo)}</span><span class="n">${fichas.length}</span></h4>
        <div class="suma${suma ? '' : ' cero'}">${suma ? fmt0(suma) + ' €' : '—'}</div>
        ${fichas.length ? fichas.map(fichaWip).join('') : `<div class="vacia">${esc(vacio)}</div>`}
      </div>`;
    }).join('');

    const total = rows.reduce((a, f) => a + (+f.pendiente || 0), 0);
    res.textContent = `${rows.length} encargo(s) vivo(s) · ${fmt0(total)} € pendientes de facturar`;
    // Cada ficha abre la pantalla del encargo (delegación, patrón de FASE A)
    $('proyectosKanban').querySelectorAll('.kanban-card[data-propuesta]').forEach(c =>
      c.addEventListener('click', () => irAPropuesta(c.dataset.propuesta)));
  } catch (e) {
    if (e.message === 'SIN_SESION') { mostrarLogin(); res.textContent = 'inicia sesión'; }
    else { res.textContent = e.message; res.className = 'wip-resumen error'; }
  }
}

function fichaWip(f) {
  const titulo = f.despacho
    ? `<span class="despacho">${esc(f.despacho)}</span><span class="barra">/</span>${esc(f.cliente)}`
    : esc(f.cliente);
  const multi = f.n_proyectos > 1 ? ` <span class="pill multi">${f.n_proyectos} proyectos</span>` : '';
  const desc = f.descripcion
    ? `<span class="scope">${esc(f.descripcion)}</span>`
    : `<span class="scope vacio">sin descripción en la base</span>`;
  const imp = +f.pendiente
    ? `<span class="imp">${fmt0(f.pendiente)} €</span>`
    : `<span class="imp cero">todo facturado</span>`;
  const equipo = [f.gerentes ? `<span class="g">${esc(f.gerentes)}</span>` : '', esc(f.consultores || '')]
    .filter(Boolean).join(' · ');
  return `<div class="kanban-card" data-propuesta="${esc(f.propuesta_id)}">
      <span class="grupo">${titulo}${multi}</span>
      ${desc}
      ${imp}
      ${equipo ? `<span class="equipo">${equipo}</span>` : ''}
    </div>`;
}

// ============================================================
// PANTALLA DE PROPUESTA (03-08-2026, maqueta validada por Antonio)
// Se abre pinchando una ficha del WIP. Cuatro bloques: línea de estados por
// proyecto, ficha, equipo y crónica. El estado NO se edita a mano: se registra
// el hecho y la base lo mueve (m276).
// ============================================================
const PASOS = [
  { rot: 'Propuesta aceptada',         estado: null,                         hecho: null },
  { rot: 'Pendiente de IDR',           estado: 'PENDIENTE_IDR',              hecho: null },
  { rot: 'Pendiente de información',   estado: 'PENDIENTE_INFO',             hecho: 'IDR_ENVIADO' },
  { rot: 'Activo',                     estado: 'ACTIVO',                     hecho: 'INFO_RECIBIDA' },
  { rot: 'Pendiente revisión cliente', estado: 'PENDIENTE_REVISION_CLIENTE', hecho: 'BORRADOR_FINAL_ENVIADO' },
  { rot: 'Completado',                 estado: 'COMPLETADO',                 hecho: 'CLIENTE_APRUEBA' },
];
const ORDEN_ESTADO = { PENDIENTE_IDR: 1, PENDIENTE_INFO: 2, ACTIVO: 3, PENDIENTE_REVISION_CLIENTE: 4, COMPLETADO: 5 };

let propActual = null, propDatos = null, propEquipoCat = null;
const modoEdicion = { estado: false, ficha: false, equipo: false };

function irAPropuesta(id) {
  document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('activa'));
  document.querySelectorAll('.pantalla').forEach(x => x.classList.remove('activa'));
  $('pantalla-propuesta').classList.add('activa');
  window.scrollTo(0, 0);
  cargarPropuesta(id);
}

async function cargarPropuesta(id) {
  propActual = id;
  Object.keys(modoEdicion).forEach(k => modoEdicion[k] = false);
  $('propTitulo').textContent = 'cargando…'; $('propSubtitulo').textContent = '';
  try {
    const [ficha, proyectos, cronica] = await Promise.all([
      fetchDetalle(`/v_cm_propuesta_ficha?select=*&propuesta_id=eq.${id}`),
      fetchDetalle(`/v_cm_propuesta_proyectos?select=*&propuesta_id=eq.${id}&order=codigo.asc`),
      fetchDetalle(`/v_cm_propuesta_cronica?select=*&propuesta_id=eq.${id}&order=fecha.asc`),
    ]);
    if (!ficha.length) { $('propTitulo').textContent = 'no encontrada'; return; }
    propDatos = { ficha: ficha[0], proyectos, cronica };
    if (!propEquipoCat) propEquipoCat = await fetchDetalle('/v_cm_equipo_disponible?select=*&order=orden_jerarquico.asc,nombre.asc');
    pintarPropuesta();
  } catch (e) {
    if (e.message === 'SIN_SESION') mostrarLogin();
    else $('propTitulo').textContent = e.message;
  }
}

function pintarPropuesta() {
  const f = propDatos.ficha, ps = propDatos.proyectos;
  $('propTitulo').innerHTML = `${esc(f.cliente)} · <span class="desc">${esc(f.descripcion || 'sin descripción')}</span>`;
  const trozos = [
    f.fecha_aceptacion ? `Aceptada el <b>${fmtFecha(f.fecha_aceptacion)}</b>` : 'Sin fecha de aceptación',
    `<b>${fmt0(f.importe_aceptado || f.importe_propuesto)} €</b>`,
    `${f.n_proyectos} proyecto${f.n_proyectos === 1 ? '' : 's'}`,
  ];
  if (f.referidor) trozos.push(`referida por <b>${esc(f.referidor)}</b>`);
  $('propSubtitulo').innerHTML = trozos.join(' · ');

  // --- línea de estados, una por proyecto ---
  $('propProyectos').innerHTML = ps.map(p => {
    const actual = ORDEN_ESTADO[p.estado] || 0;
    const hechos = p.hechos || {};
    const pasos = PASOS.map((paso, i) => {
      const pos = i === 0 ? 0 : ORDEN_ESTADO[paso.estado];
      const clase = pos < actual ? 'hecho' : (pos === actual ? 'actual' : '');
      let fecha = '&nbsp;';
      if (i === 0) fecha = propDatos.ficha.fecha_aceptacion ? fmtFecha(propDatos.ficha.fecha_aceptacion) : '<span class="sin">sin fecha</span>';
      else if (paso.hecho && hechos[paso.hecho]) fecha = fmtFecha(hechos[paso.hecho]);
      else if (clase) fecha = '<span class="sin">sin anotar</span>';
      const pulsable = modoEdicion.estado && paso.hecho && pos > actual;
      return `<div class="paso ${clase}${pulsable ? ' pulsable' : ''}"${pulsable ? ` data-hecho="${paso.hecho}" data-proy="${esc(p.proyecto_id)}"` : ''}>
          <div class="bola">${clase === 'hecho' ? '✓' : (clase === 'actual' ? '●' : '')}</div>
          <div class="rot">${esc(paso.rot)}</div><div class="fec">${fecha}</div>
        </div>`;
    }).join('');
    return `<div class="proy">
        <div class="tit">${esc(p.cliente)} <span class="cod">${esc(p.codigo)}</span></div>
        <div class="sub">${fmt0(p.honorarios)} €</div>
        <div class="linea">${pasos}</div>
      </div>`;
  }).join('');
  if (modoEdicion.estado) {
    $('propProyectos').insertAdjacentHTML('afterbegin',
      '<p class="aviso-edicion">Pulsa el paso que quieras registrar. Se anota con la fecha de hoy y el estado se mueve solo.</p>');
    $('propProyectos').querySelectorAll('.paso.pulsable').forEach(el =>
      el.addEventListener('click', () => registrarHecho(el.dataset.proy, el.dataset.hecho)));
  }

  // --- ficha ---
  const campos = [
    ['Fecha de aceptación', f.fecha_aceptacion ? fmtFecha(f.fecha_aceptacion) : '—'],
    ['Cliente de servicio', f.cliente_servicio || '—'],
    ['Referida por', f.referidor || '—'],
    ['Importe aceptado', fmt0(f.importe_aceptado || 0) + ' €'],
    ['Enviada', f.fecha_envio ? fmtFecha(f.fecha_envio) : '—'],
  ];
  const filas = ps.map(p => `<tr>
      <td class="n">${esc(p.factura_a || '—')}</td>
      <td>${p.num_auxadi ? `<span class="mono">${esc(p.num_auxadi)}</span>` : '<span class="sinnum">sin número</span>'}</td>
      <td>${fmt0(p.honorarios)} €</td>
      <td>${+p.facturado ? fmt0(p.facturado) + ' €' + (p.fecha_facturado ? ` <span class="mono">· ${fmtFecha(p.fecha_facturado)}</span>` : '') : '—'}</td>
      <td>${+p.pendiente ? fmt0(p.pendiente) + ' €' : '—'}</td>
      <td>${p.fecha_estimada ? `<span class="mono">${fmtFecha(p.fecha_estimada)}</span>` : '—'}</td>
    </tr>`).join('');
  $('propFicha').innerHTML = `
    <div class="campos">${campos.map(([k, v]) => `<div class="campo"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}</div>
    <table><tr><th>Se factura a</th><th>Nº cliente Auxadi</th><th>Honorarios</th><th>Facturado</th><th>Pendiente</th><th>Fecha estimada</th></tr>${filas}</table>
    ${modoEdicion.ficha ? `
      <div class="edicion">
        <label class="k">Descripción de los servicios</label>
        <textarea id="propEditDesc" rows="3">${esc(f.descripcion || '')}</textarea>
        <label class="k">Fecha de aceptación</label>
        <input id="propEditFecha" type="date" value="${f.fecha_aceptacion || ''}">
        ${ps.filter(p => !p.num_auxadi).map(p => `
          <label class="k">Nº cliente Auxadi de ${esc(p.factura_a)}</label>
          <input class="propEditNum" data-proy="${esc(p.proyecto_id)}" type="text" inputmode="numeric" placeholder="solo dígitos">`).join('')}
        <div><button id="propGuardarFicha" class="azul">Guardar</button></div>
      </div>` : `<p class="desc-larga"><b>Servicios:</b> ${esc(f.descripcion || 'sin descripción registrada')}</p>`}`;
  if (modoEdicion.ficha) $('propGuardarFicha').onclick = guardarFicha;

  // --- equipo ---
  const asignados = { GERENTE: new Set(), CONSULTOR: new Set() };
  ps.forEach(p => {
    (p.gerentes || '').split(', ').filter(Boolean).forEach(n => asignados.GERENTE.add(n));
    (p.consultores || '').split(', ').filter(Boolean).forEach(n => asignados.CONSULTOR.add(n));
  });
  const columna = (cat, rotulo) => {
    const gente = propEquipoCat.filter(u => u.categoria === cat);
    const fuera = [...asignados[cat]].filter(n => !gente.some(u => u.nombre === n));
    const btn = (nombre, id, esFuera) =>
      `<button class="btn-p${asignados[cat].has(nombre) ? ' on' : ''}${esFuera ? ' fuera' : ''}"
        ${modoEdicion.equipo && !esFuera ? `data-cat="${cat}" data-nombre="${esc(nombre)}" data-id="${esc(id)}"` : 'disabled'}>${esc(nombre)}</button>`;
    return `<div><h4>${esc(rotulo)}</h4><div class="btns">
        ${gente.map(u => btn(u.nombre, u.id, false)).join('')}
        ${fuera.map(n => btn(n, '', true)).join('')}
      </div></div>`;
  };
  $('propEquipo').innerHTML = `<div class="equipo">${columna('GERENTE', 'Gerentes')}${columna('CONSULTOR', 'Consultores')}</div>
    ${modoEdicion.equipo ? `<p class="aviso-edicion">Los cambios se aplican a los ${ps.length} proyecto(s) del encargo.</p>
      <div><button id="propGuardarEquipo" class="azul">Guardar equipo</button></div>` : ''}`;
  if (modoEdicion.equipo) {
    $('propEquipo').querySelectorAll('.btn-p[data-cat]').forEach(b =>
      b.addEventListener('click', () => b.classList.toggle('on')));
    $('propGuardarEquipo').onclick = guardarEquipo;
  }

  // --- crónica ---
  $('propCronica').innerHTML = propDatos.cronica.length
    ? `<ul class="cron">${propDatos.cronica.map(c => `<li>
        <span class="f">${fmtFecha(c.fecha)}</span>
        <span class="q"><b>${esc(c.titulo)}</b>${c.detalle ? ' — ' + esc(c.detalle) : ''}
        <span class="org">· ${esc(c.origen)}</span></span></li>`).join('')}</ul>`
    : '<p class="vacia">Sin anotaciones registradas.</p>';
}

const fmtFecha = (f) => { if (!f) return '—'; const [a, m, d] = f.slice(0, 10).split('-'); return `${d}-${m}-${a.slice(2)}`; };

async function registrarHecho(proyectoId, hecho) {
  try {
    const r = await rpc('cm_registrar_hecho_proyecto', { p_proyecto_id: proyectoId, p_tipo_evento: hecho, p_fecha: null, p_nota: null });
    if (!r?.ok) { alert(r?.error || 'no se pudo registrar'); return; }
    await cargarPropuesta(propActual);
  } catch (e) { alert(e.message); }
}

async function guardarFicha() {
  try {
    const desc = $('propEditDesc').value.trim(), fecha = $('propEditFecha').value || null;
    const r = await rpc('cm_actualizar_ficha_propuesta', { p_propuesta_id: propActual, p_descripcion: desc, p_fecha_aceptacion: fecha });
    if (!r?.ok) { alert(r?.error || 'no se pudo guardar'); return; }
    for (const inp of document.querySelectorAll('.propEditNum')) {
      const num = inp.value.trim(); if (!num) continue;
      const p = propDatos.proyectos.find(x => x.proyecto_id === inp.dataset.proy);
      const ent = await fetchDetalle(`/proyecto?select=cliente_facturacion_id&id=eq.${p.proyecto_id}`);
      const r2 = await rpc('cm_actualizar_num_cliente_auxadi', { p_entidad_id: ent[0].cliente_facturacion_id, p_numero: num });
      if (!r2?.ok) { alert(r2?.error || 'no se pudo guardar el número'); return; }
    }
    modoEdicion.ficha = false;
    await cargarPropuesta(propActual);
  } catch (e) { alert(e.message); }
}

async function guardarEquipo() {
  try {
    for (const cat of ['GERENTE', 'CONSULTOR']) {
      const ids = [...$('propEquipo').querySelectorAll(`.btn-p.on[data-cat="${cat}"]`)].map(b => b.dataset.id);
      for (const p of propDatos.proyectos) {
        const r = await rpc('cm_asignar_equipo', { p_proyecto_id: p.proyecto_id, p_papel: cat, p_usuarios: ids });
        if (!r?.ok) { alert(r?.error || 'no se pudo guardar el equipo'); return; }
      }
    }
    modoEdicion.equipo = false;
    await cargarPropuesta(propActual);
  } catch (e) { alert(e.message); }
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
    const cls = c.cls ? ` class="${c.cls}"` : '';
    if (c.pill && v) return `<td${cls}><span class="pill ${esc(r[c.k])}">${esc(v)}</span></td>`;
    if (c.html) return `<td${cls}>${v}</td>`;
    if (c.num) return `<td class="num">${v === '' ? '' : fmt2(v)}</td>`;
    return `<td${cls}>${esc(v)}</td>`;
  }).join('') + '</tr>').join('');
  const tf = '<tr>' + cols.map(c => c.num ? `<td class="num">${fmt2(sum[c.k])}</td>` : '<td></td>').join('') + '</tr>';
  return `<table class="datos"><thead><tr>${th}</tr></thead><tbody>${trs}</tbody><tfoot>${tf}</tfoot></table>`;
}
// Delegación de eventos para los botones de acción de las tablas (E2): nunca se interpola
// el dato del usuario en un atributo onclick, solo en data-* ya escapados por esc().
$('expTabla').addEventListener('click', (e) => {
  const f = e.target.closest('button[data-prop]');
  if (f) { irAPropuesta(f.dataset.prop); return; }
  const b = e.target.closest('button[data-accion]');
  if (!b) return;
  const { accion, id, ref, fecha } = b.dataset;
  if (accion === 'mover-hito') accionMoverHito(id, ref, fecha);
  else if (accion === 'seguimiento') accionSeguimiento(id, ref);
  else if (accion === 'aceptar') abrirAceptacion(id, ref);
  else if (accion === 'cerrar-no') accionCerrarSinAceptar(id, ref);
});

// Acciones de escritura (RPC controladas)
// Reforma 2026-08 (D19): retirada accionCobrada — el proceso de cobro no se gestiona
// desde Kira, así que no hay acción que lo marque.
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

// ============================================================
// FASE 4 · CIERRE Y ACEPTACIÓN DE PROPUESTAS (reforma 2026-08)
// Maqueta validada por Antonio el 2026-08-02 → maqueta_aceptacion_propuesta.html
//
// Antes, aceptar era cambiar el estado y un trigger deducía el resto: un proyecto por línea
// de la oferta y siempre dos hitos al 50/50 (D9.5 y D12 lo prohíben). Ahora la división y el
// calendario se INDICAN aquí, y la RPC crea exactamente eso.
// ============================================================

// Cerrar sin aceptar. NO se pregunta la salida: la elige la RPC según haya habido oferta
// emitida o no (D3), porque el dato no puede depender de que la pantalla acierte.
window.accionCerrarSinAceptar = async (id, ref) => {
  const filas = await fetchDetalle(`/propuesta?select=fecha_envio&id=eq.${id}`).catch(() => null);
  const hubo = filas && filas[0] && filas[0].fecha_envio;
  const salida = hubo ? 'PROPUESTA RECHAZADA' : 'OPORTUNIDAD PERDIDA';
  const matiz  = hubo
    ? 'Sí computa como oferta perdida en el cuadro de mando.'
    : 'NO computa como oferta perdida: nunca llegó a emitirse oferta, se reporta aparte.';
  if (!confirm(`Cerrar ${ref} como ${salida}.\n\n${matiz}\n\n¿Continuar?`)) return;
  try {
    const r = await rpc('cm_cerrar_propuesta_sin_aceptar', { p_propuesta_id: id });
    alert(r.ok ? `✓ ${r.propuesta} cerrada como ${r.salida}` : `No se pudo: ${r.error}`);
    if (r.ok) { buscar(); cargarBadgeAlertas(); }
  } catch (e) {
    if (e.message === 'SIN_SESION') mostrarLogin(); else alert('Error: ' + e.message);
  }
};

const acep = { id:null, ref:'', propuesta:null, docOk:false, docPath:null,
               modo:1, proys:[], comun:null, tocado:[], tab:0, total:0 };
const clonaHitos = hs => hs.map(h => ({ ...h }));
const HITOS_5050 = () => ([
  { concepto:'50% aceptación',     pct:50, fecha:hoyIso(), disparador:'PROYECTO_CREADO' },
  { concepto:'50% borrador final', pct:50, fecha:'',        disparador:'BORRADOR_FINAL_ENVIADO' },
]);
// Fecha local, no UTC: esta fecha se GUARDA (hitos de la aceptación), así que entre las 00:00
// y las 02:00 de España toISOString() habría registrado el día anterior.
function hoyIso(){ return fechaIso(new Date()); }

window.abrirAceptacion = async (id, ref) => {
  try {
    await cargarClientes();
    const [p] = await fetchDetalle(`/propuesta?select=id,codigo_legible,importe_propuesto,importe_aceptado,`
      + `cliente_servicio_id,cliente_facturacion_id,fecha_envio,pdf_storage_path,pdf_filename&id=eq.${id}`);
    if (!p) { alert('No encuentro la propuesta.'); return; }
    const lineas = await fetchDetalle(`/propuesta_linea?select=id,orden,descripcion,importe_propuesto`
      + `&propuesta_id=eq.${id}&order=orden`);

    Object.assign(acep, {
      id, ref, propuesta: p, lineas: lineas || [],
      docOk: !!p.pdf_storage_path, docPath: p.pdf_storage_path,
      total: Number(p.importe_aceptado ?? p.importe_propuesto) || 0,
      modo: 1, comun: HITOS_5050(), tab: 0,
      proys: [{ cubierta: p.cliente_servicio_id || '', factura: p.cliente_facturacion_id || '',
                importe: Number(p.importe_aceptado ?? p.importe_propuesto) || 0, hitos: null }],
      tocado: [false],
    });
    $('acepTitulo').textContent = `Confirmar aceptación · ${p.codigo_legible}`;
    const cli = (clientes[p.cliente_servicio_id] || {}).nombre || '—';
    $('acepMeta').textContent = `${cli} · propuesto ${fmt2(p.importe_propuesto)} €`
      + (p.fecha_envio ? ` · enviada ${p.fecha_envio}` : '');
    $('acepVelo').hidden = false; $('acepCaja').hidden = false;
    pintarAceptacion();
  } catch (e) {
    if (e.message === 'SIN_SESION') mostrarLogin(); else alert('Error: ' + e.message);
  }
};
function cerrarAceptacion(){ $('acepVelo').hidden = true; $('acepCaja').hidden = true; }
$('acepCerrar').addEventListener('click', cerrarAceptacion);
$('acepCancelar').addEventListener('click', cerrarAceptacion);
$('acepVelo').addEventListener('click', cerrarAceptacion);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('acepCaja').hidden) cerrarAceptacion();
});

// Las entidades se ofrecen en un <select> con datalist implícito: son ~130, caben.
function opcionesEntidad(sel) {
  return '<option value="">— elegir —</option>' + Object.entries(clientes)
    .sort((a,b) => (a[1].nombre||'').localeCompare(b[1].nombre||''))
    .map(([id,c]) => `<option value="${id}"${id===sel?' selected':''}>${esc(c.nombre||'?')}</option>`).join('');
}

function pintarAceptacion() {
  const a = acep;
  if (a.tab >= a.proys.length) a.tab = 0;
  const varios = a.modo === 2;

  const filasProy = a.proys.map((p,i) => `<tr>
    <td class="sub">${i+1}</td>
    <td><select data-ap="cubierta" data-i="${i}">${opcionesEntidad(p.cubierta)}</select></td>
    <td><select data-ap="factura" data-i="${i}">${opcionesEntidad(p.factura)}</select></td>
    <td class="imp"><input class="imp" data-ap="importe" data-i="${i}" value="${p.importe}"></td>
    <td>${varios ? `<button class="mini gris" data-ap="quitar" data-i="${i}">✕</button>` : ''}</td></tr>`).join('');

  const sumaP = a.proys.reduce((s,p) => s + (Number(p.importe)||0), 0);
  const cuadraP = Math.abs(sumaP - a.total) < 0.005;

  const hs = hitosDe(a.tab);
  const base = Number(a.proys[a.tab].importe) || 0;
  const sumaH = hs.reduce((s,h) => s + base*(Number(h.pct)||0)/100, 0);
  const cuadraH = Math.abs(sumaH - base) < 0.005;

  $('acepCuerpo').innerHTML = `
    <div class="prop-campos">
      <div><label>Importe aceptado</label>
        <input id="acepTotal" value="${a.total}" inputmode="decimal"></div>
      <div><label>Fecha de aceptación</label>
        <input id="acepFecha" type="date" value="${hoyIso()}"></div>
    </div>

    <div class="acep-bloque ${a.docOk ? '' : 'falta'}">
      <h4>1 · Documento de aceptación — obligatorio</h4>
      <div class="acep-drop ${a.docOk ? 'cargado' : ''}" id="acepDrop">
        ${a.docOk
          ? `✓ ${esc(a.docPath || 'documento registrado')}<div class="acep-hint">pulsa para sustituirlo</div>`
          : '📎 pulsa para elegir el PDF firmado o el correo del cliente<div class="acep-hint">sin esto no se puede confirmar</div>'}
      </div>
      <input type="file" id="acepFile" accept=".pdf,.msg,.eml,.png,.jpg" hidden>
    </div>

    <div class="acep-bloque">
      <h4>2 · ¿En cuántos proyectos se divide?</h4>
      <label class="acep-opcion ${!varios?'sel':''}">
        <input type="radio" name="acepModo" ${!varios?'checked':''} data-ap="modo" data-v="1">
        <div><div>Un solo proyecto</div><div class="d">La regla general. Que la oferta lleve varias líneas no implica varios proyectos.</div></div></label>
      <label class="acep-opcion ${varios?'sel':''}">
        <input type="radio" name="acepModo" ${varios?'checked':''} data-ap="modo" data-v="2">
        <div><div>Varios proyectos</div><div class="d">Solo si (a) se factura a varias sociedades del grupo, o (b) hay fases o años que se facturan por separado.</div></div></label>
      <table><thead><tr><th style="width:28px">#</th><th>Empresa cubierta <span class="sub">(cliente del trabajo)</span></th>
        <th>Se factura a</th><th class="imp" style="width:120px">Importe</th><th style="width:32px"></th></tr></thead>
        <tbody>${filasProy}</tbody></table>
      ${varios ? `<button class="mini gris" data-ap="anadir">+ añadir proyecto</button>
        ${a.lineas.length > 1 ? `<button class="mini gris" data-ap="traer">↻ traer las ${a.lineas.length} líneas de la oferta</button>` : ''}` : ''}
      <div class="acep-cuadre"><span>Suma de los proyectos</span>
        <span class="imp">${fmt2(sumaP)} €</span>
        <span class="${cuadraP?'ok':'ko'}">${cuadraP ? '✓ cuadra' : '✗ ' + (sumaP>a.total?'sobran ':'faltan ') + fmt2(Math.abs(a.total-sumaP)) + ' €'}</span></div>
    </div>

    <div class="acep-bloque">
      <h4>3 · Calendario de facturación</h4>
      ${varios ? bloqueComun() : ''}
      <div class="acep-tabs">${a.proys.map((p,i) =>
        `<span class="acep-tab ${i===a.tab?'sel':''}" data-ap="tab" data-i="${i}">${
          a.proys.length>1 ? 'Proyecto '+(i+1)+' · ' : ''}${esc((clientes[p.cubierta]||{}).nombre || '(sin elegir)')}${
          varios && a.tocado[i] ? ' <b class="ajus">·ajustado</b>' : ''}</span>`).join('')}</div>
      ${tablaHitos(hs, base, cuadraH, sumaH, 'h')}
    </div>`;

  const faltan = [];
  if (!a.docOk) faltan.push('el documento de aceptación');
  if (!cuadraP) faltan.push('que el reparto entre proyectos cuadre');
  if (!todosLosPlazosCuadran()) faltan.push('que los plazos de cada proyecto cuadren');
  if (a.proys.some(p => !p.cubierta)) faltan.push('la empresa cubierta de todos los proyectos');
  const nh = a.proys.reduce((s,_,i) => s + hitosDe(i).length, 0);
  const ok = faltan.length === 0;
  $('acepResumen').className = 'acep-resumen' + (ok ? '' : ' ko');
  $('acepResumen').textContent = ok
    ? `Se ${a.proys.length>1?'crearán':'creará'} ${a.proys.length} proyecto${a.proys.length>1?'s':''} y ${nh} hito${nh>1?'s':''}, por ${fmt2(a.total)} €.`
    : 'Falta ' + faltan.join(', ') + '.';
  $('acepConfirmar').disabled = !ok;
}

function hitosDe(i) {
  if (!acep.proys[i].hitos) acep.proys[i].hitos = clonaHitos(acep.modo===2 ? acep.comun : HITOS_5050());
  return acep.proys[i].hitos;
}
function todosLosPlazosCuadran() {
  return acep.proys.every((p,i) => {
    const base = Number(p.importe)||0;
    const s = hitosDe(i).reduce((x,h) => x + base*(Number(h.pct)||0)/100, 0);
    return Math.abs(s - base) < 0.005;
  });
}
function bloqueComun() {
  const suma = acep.comun.reduce((s,h) => s + (Number(h.pct)||0), 0);
  const ok = Math.abs(suma-100) < 0.005;
  const ajust = acep.tocado.filter(Boolean).length;
  return `<div class="acep-comun">
    <div class="t">Calendario común — se aplica a los ${acep.proys.length} proyectos</div>
    ${tablaHitos(acep.comun, null, ok, suma, 'c')}
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-top:6px">
      <div><button class="mini gris" data-ap="c-add">+ plazo</button>
        <button class="mini gris" data-ap="c-5050">↻ 50/50</button>
        <button class="mini gris" data-ap="c-100">↻ 100% de una vez</button></div>
      <div><span class="${ok?'ok':'ko'}" style="margin-right:10px">${ok?'✓ suma 100%':'✗ suma '+suma+'%'}</span>
        <button class="morado mini" data-ap="c-aplicar">aplicar a los ${acep.proys.length}</button></div>
    </div>
    <p class="acep-hint">${ajust
      ? `<b style="color:var(--ambar)">${ajust} proyecto${ajust>1?'s':''} con el calendario ajustado a mano</b> — aplicar el común los devolvería al patrón.`
      : 'Puedes ajustar cualquiera por separado en sus pestañas.'}</p></div>`;
}
// pre = 'h' (plazos de un proyecto, con importe) | 'c' (calendario común, solo porcentajes)
function tablaHitos(hs, base, cuadra, suma, pre) {
  const conImporte = pre === 'h';
  const filas = hs.map((h,j) => `<tr>
    <td class="sub">${j+1}</td>
    <td><input data-ap="${pre}-concepto" data-j="${j}" value="${esc(h.concepto||'')}"></td>
    <td class="imp" style="width:70px"><input class="imp" data-ap="${pre}-pct" data-j="${j}" value="${h.pct}"></td>
    ${conImporte ? `<td class="imp">${fmt2(base*(Number(h.pct)||0)/100)} €</td>` : ''}
    <td style="width:140px"><input type="date" data-ap="${pre}-fecha" data-j="${j}" value="${h.fecha||''}"></td>
    <td style="width:190px"><select data-ap="${pre}-disp" data-j="${j}">${
      ['PROYECTO_CREADO','BORRADOR_FINAL_ENVIADO','MANUAL'].map(d =>
        `<option${d===h.disparador?' selected':''}>${d}</option>`).join('')}</select></td>
    <td style="width:30px"><button class="mini gris" data-ap="${pre}-del" data-j="${j}">✕</button></td></tr>`).join('');
  return `<table><thead><tr><th style="width:28px">#</th><th>Concepto</th><th class="imp">%</th>
    ${conImporte ? '<th class="imp">Importe</th>' : ''}<th>Fecha prevista</th><th>Se factura cuando…</th><th></th></tr></thead>
    <tbody>${filas}</tbody></table>
    ${conImporte ? `<div style="margin:4px 0"><button class="mini gris" data-ap="h-add">+ plazo</button>
      <button class="mini gris" data-ap="h-5050">↻ 50/50</button>
      <button class="mini gris" data-ap="h-100">↻ 100% de una vez</button></div>
      <div class="acep-cuadre"><span>Suma de los plazos</span><span class="imp">${fmt2(suma)} €</span>
        <span class="${cuadra?'ok':'ko'}">${cuadra?'✓ cuadra con el proyecto':'✗ faltan '+fmt2(base-suma)+' €'}</span></div>
      <p class="acep-hint">Sin fecha prevista el hito no entra en la previsión. El segundo plazo suele ir sin fecha porque depende del borrador final.</p>` : ''}`;
}

// Un solo manejador para todo el modal: el HTML se repinta entero en cada cambio, así que no
// puede haber listeners colgados de nodos que ya no existen (mismo patrón que #expTabla).
$('acepCuerpo').addEventListener('click', (e) => {
  const t = e.target.closest('[data-ap]'); if (!t) return;
  const k = t.dataset.ap, i = +t.dataset.i, j = +t.dataset.j, a = acep;
  if (k === 'modo') {
    a.modo = +t.dataset.v;
    if (a.modo === 1) { a.proys = [a.proys[0]]; a.tocado = [false]; a.proys[0].importe = a.total; a.proys[0].hitos = null; }
    else if (a.proys.length === 1) { a.proys.push({ cubierta:'', factura:a.proys[0].factura, importe:0, hitos:null }); a.tocado.push(false); }
    a.tab = 0;
  }
  else if (k === 'anadir') { a.proys.push({ cubierta:'', factura:a.proys[0].factura, importe:0, hitos:clonaHitos(a.comun) }); a.tocado.push(false); }
  else if (k === 'quitar') { if (a.proys.length<2) return; a.proys.splice(i,1); a.tocado.splice(i,1); a.tab=0; }
  else if (k === 'traer') {
    // Botón, no automatismo: las líneas SUGIEREN la división, no la deciden (D9.5).
    a.proys = a.lineas.map(l => ({ cubierta:'', factura:a.propuesta.cliente_facturacion_id||'',
                                   importe:Number(l.importe_propuesto)||0, hitos:clonaHitos(a.comun) }));
    a.tocado = a.proys.map(() => false); a.tab = 0;
    alert('Traídas las líneas de la oferta con sus importes. Falta indicar la empresa cubierta de cada proyecto: la oferta no lo dice.');
  }
  else if (k === 'tab') a.tab = i;
  else if (k === 'h-add') { hitosDe(a.tab).push({concepto:'plazo',pct:0,fecha:'',disparador:'MANUAL'}); a.tocado[a.tab]=true; }
  else if (k === 'h-del') { const hs=hitosDe(a.tab); if(hs.length<2) return; hs.splice(j,1); a.tocado[a.tab]=true; }
  else if (k === 'h-5050') { a.proys[a.tab].hitos = HITOS_5050(); a.tocado[a.tab]=true; }
  else if (k === 'h-100')  { a.proys[a.tab].hitos = [{concepto:'100% del encargo',pct:100,fecha:hoyIso(),disparador:'PROYECTO_CREADO'}]; a.tocado[a.tab]=true; }
  else if (k === 'c-add')  a.comun.push({concepto:'plazo',pct:0,fecha:'',disparador:'MANUAL'});
  else if (k === 'c-del')  { if(a.comun.length<2) return; a.comun.splice(j,1); }
  else if (k === 'c-5050') { a.comun = HITOS_5050(); aplicarComun(); }
  else if (k === 'c-100')  { a.comun = [{concepto:'100% del encargo',pct:100,fecha:hoyIso(),disparador:'PROYECTO_CREADO'}]; aplicarComun(); }
  else if (k === 'c-aplicar') aplicarComun();
  else return;
  pintarAceptacion();
});
function aplicarComun(){ acep.proys.forEach((p,i) => { p.hitos = clonaHitos(acep.comun); acep.tocado[i]=false; }); }

$('acepCuerpo').addEventListener('input', (e) => {
  const t = e.target.closest('[data-ap]'); if (!t) return;
  const k = t.dataset.ap, i = +t.dataset.i, j = +t.dataset.j, a = acep, v = t.value;
  if (t.id === 'acepTotal') { a.total = Number(v)||0; if (a.modo===1) a.proys[0].importe = a.total; }
  else if (k === 'cubierta') a.proys[i].cubierta = v;
  else if (k === 'factura')  a.proys[i].factura = v;
  else if (k === 'importe')  a.proys[i].importe = Number(v)||0;
  else if (k.startsWith('h-')) { const h = hitosDe(a.tab)[j]; h[campoDe(k)] = k==='h-pct' ? (Number(v)||0) : v; a.tocado[a.tab]=true; }
  else if (k.startsWith('c-')) { const h = a.comun[j]; h[campoDe(k)] = k==='c-pct' ? (Number(v)||0) : v; }
  else return;
  // Repintar en cada tecla movería el cursor: solo se repinta lo que cambia de estado.
  clearTimeout(acep._t); acep._t = setTimeout(pintarAceptacion, 350);
});
$('acepCuerpo').addEventListener('change', (e) => {
  if (e.target.tagName === 'SELECT' || e.target.type === 'date') { clearTimeout(acep._t); pintarAceptacion(); }
});
const campoDe = k => ({ concepto:'concepto', pct:'pct', fecha:'fecha', disp:'disparador' })[k.slice(2)];

// Subida del documento de aceptación al bucket de documentos y registro en la propuesta.
$('acepCuerpo').addEventListener('click', (e) => {
  if (e.target.closest('#acepDrop')) $('acepFile').click();
});
$('acepCuerpo').addEventListener('change', async (e) => {
  const inp = e.target.closest('#acepFile'); if (!inp || !inp.files.length) return;
  const f = inp.files[0], drop = $('acepDrop');
  drop.textContent = 'subiendo…';
  try {
    const tok = await getToken(); if (!tok) throw new Error('SIN_SESION');
    const limpio = f.name.replace(/[^\w.\-]/g, '_');
    const ruta = `propuestas/aceptaciones/${acep.propuesta.codigo_legible}_${Date.now()}_${limpio}`;
    const r = await fetch(`${URL_SB}/storage/v1/object/tps-documentos/${ruta}`, {
      method:'POST', headers:{ apikey:ANON, Authorization:`Bearer ${tok}`, 'Content-Type': f.type || 'application/pdf' },
      body: f });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    await fetchDetalle(`/propuesta?id=eq.${acep.id}`, { method:'PATCH',
      headers:{ Prefer:'return=minimal' },
      body: JSON.stringify({ pdf_storage_path: ruta, pdf_filename: f.name }) });
    acep.docOk = true; acep.docPath = ruta;
  } catch (err) {
    acep.docOk = false;
    if (err.message === 'SIN_SESION') mostrarLogin();
    else alert('No se pudo subir el documento: ' + err.message);
  }
  pintarAceptacion();
});

$('acepConfirmar').addEventListener('click', async () => {
  const b = $('acepConfirmar'); b.disabled = true; b.textContent = 'creando…';
  try {
    const proyectos = acep.proys.map((p,i) => ({
      entidad_cubierta_id: p.cubierta,
      cliente_facturacion_id: p.factura || null,
      importe: Number(p.importe) || 0,
      hitos: hitosDe(i).map(h => ({ concepto: h.concepto, pct: Number(h.pct)||0,
                                    fecha: h.fecha || null, disparador: h.disparador })),
    }));
    const r = await rpc('cm_confirmar_aceptacion_propuesta', {
      p_propuesta_id: acep.id,
      p_importe_aceptado: acep.total,
      p_fecha_aceptacion: $('acepFecha').value || hoyIso(),
      p_proyectos: proyectos,
    });
    if (r.ok) {
      alert(`✓ ${r.propuesta} aceptada.\n\nCreados ${r.n_proyectos} proyecto(s) y ${r.n_hitos} hito(s):\n${r.proyectos.join(', ')}`);
      cerrarAceptacion(); buscar(); cargarBadgeAlertas();
    } else { alert('No se pudo: ' + r.error); }
  } catch (e) {
    if (e.message === 'SIN_SESION') mostrarLogin(); else alert('Error: ' + e.message);
  }
  b.textContent = 'Confirmar aceptación'; pintarAceptacion();
});

// Exportar CSV (lo último buscado)
function exportarCsv() {
  if (!ultimaFilas.length) { alert('Busca algo primero.'); return; }
  // Fuera las columnas que no son datos: los botones de acción y el de ficha (03-08).
  const cols = ultimaCols.filter(c => c.k !== '_acc' && c.t !== 'Ficha');
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
// compacta reutilizable en ambos sitios.
//
// Reforma 2026-08 (D19): fuera "Cobrado FY" y "Pendiente de cobro". No es solo que no se
// gestione el cobro: es que ya NO HAY dato, y fmt0(null) pinta un 0 — que se lee como
// "no ha cobrado nada", justo lo contrario de "no lo sé". En su sitio van dos datos que sí
// son hechos y que la RPC ya devolvía sin que nadie los mostrase.
// ============================================================
// Estado propio del desplegable de esta pantalla: no comparte selección con los filtros de
// Consultar, aunque use el mismo componente y el mismo catálogo.
const selC360 = { cliente: [] };

function renderClienteMini(r) {
  return `<div class="cliente-mini">
    <div class="nombre">${esc(r.cliente)}</div>
    <div class="fila"><span>Facturado FY</span><span>${fmt0(r.facturado_fy)} €</span></div>
    <div class="fila"><span>Previsto futuro</span><span>${fmt0(r.previsto_futuro)} €</span></div>
    <div class="fila"><span>Proyectos activos</span><span>${r.proyectos_activos}</span></div>
    <div class="fila"><span>Propuestas abiertas</span><span>${r.propuestas_abiertas}</span></div>
  </div>`;
}
async function buscarCliente360(nombre) {
  const cont = $('c360Resultado'); cont.innerHTML = '<span class="status">buscando…</span>';
  try {
    const filas = await rpc('rpt_cliente_resumen', { p_cliente: nombre });
    if (!filas.length) { cont.innerHTML = `<span class="status">Sin coincidencias para "${esc(nombre)}".</span>`; return; }
    if (filas.length > 1) {
      // La RPC busca por coincidencia parcial, así que un nombre puede ser subcadena de otro
      // («Monlux» dentro de «Monlux, S.A.»). Viniendo del desplegable el nombre es exacto, así
      // que si hay una coincidencia literal se usa esa y no se pregunta.
      const exacta = filas.find(r => (r.cliente || '').toLowerCase() === nombre.toLowerCase());
      if (exacta) { await pintarCliente360(exacta); return; }
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
      <div class="c360-kpi"><div class="label">Previsto futuro</div><div class="valor">${fmt0(r.previsto_futuro)} €</div></div>
      <div class="c360-kpi"><div class="label">Proyectos activos</div><div class="valor">${r.proyectos_activos}</div></div>
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
// El ÚNICO formato que la ingesta sabe leer es el PDF (decisión de Antonio, 25-08-2026).
// Se comprueba AQUÍ y no solo en el `accept` del input: ese atributo únicamente filtra el
// diálogo de Windows, y arrastrando —o eligiendo «todos los archivos»— entra cualquier cosa.
// Es lo que pasó el 24-08: cuatro correos .msg subieron con un «✓ en bandeja» y se quedaron
// invisibles para siempre, porque el lector solo abre .pdf y nadie avisaba de lo contrario.
const esPdf = (f) => /\.pdf$/i.test(f.name);

async function subirFicheros(files) {
  const tipo = $('subTipo').value, lista = $('listaSubidas');
  for (const f of files) {
    const item = document.createElement('div'); item.className = 'item';
    item.innerHTML = `<span>${f.name}</span><span class="status">subiendo…</span>`;
    lista.prepend(item);
    if (!esPdf(f)) {
      item.lastElementChild.textContent = '✗ solo se admite PDF — imprime el documento a PDF y vuelve a subirlo';
      item.lastElementChild.className = 'error';
      continue;
    }
    try {
      const tok = await getToken();
      if (!tok) throw new Error('inicia sesión');
      const nombre = f.name.replace(/[^\w.\-() ]/g, '_');
      const r = await fetch(`${URL_SB}/storage/v1/object/${BUCKET_INBOX}/${tipo}/${encodeURIComponent(nombre)}`, {
        // Tipo FIJO, no `f.type`: un .msg no declara ninguno y acababa etiquetado como PDF
        // en el almacén, así que el fichero mentía sobre lo que era.
        method: 'POST', headers: { apikey: ANON, Authorization: `Bearer ${tok}`, 'Content-Type': 'application/pdf' },
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
      // Lo que no es PDF la ingesta NO lo lee, y antes se quedaba aquí sin que nada lo dijera.
      // Marcarlo es la única señal que ve Antonio de que ese documento no va a procesarse.
      if (objetos.length) {
        const partes = objetos.map(o => /\.pdf$/i.test(o.name)
          ? esc(o.name)
          : `<span class="error">${esc(o.name)} ⚠ no es PDF: la ingesta no puede leerlo</span>`);
        html += `<div class="sub" style="margin:6px 0"><strong>${tipo}</strong>: ${partes.join(' · ')}</div>`;
      }
    }
    $('bandejaLista').innerHTML = html || '<span class="sub">bandeja vacía — todo procesado</span>';
    st.textContent = '';
  } catch (e) { st.textContent = e.message; }
}

// ============================================================
// INGESTA SERVER-SIDE (FASE G): bandeja de propuestas pendientes de revisar.
// La Edge Function cm-ingesta nunca toca `factura`; aquí es donde Antonio confirma
// (cm_confirmar_ingesta_factura) o descarta (cm_descartar_ingesta).
// ============================================================
const CONFIANZA_TXT = {
  nif_exacto: 'NIF exacto',
  nif_raiz: 'raíz del NIF (sufijo distinto)',
  denominacion: 'solo por nombre',
};
async function cargarIngesta() {
  const st = $('ingStatus');
  try {
    const filas = await fetchDetalle('/v_cm_ingesta_pendiente?select=*');
    const n = filas.length;
    const b = $('ingBadge');
    if (n) { b.textContent = n; b.style.display = 'inline-block'; } else b.style.display = 'none';
    $('ingLista').innerHTML = n ? filas.map(f => {
      const imp = f.base_imponible ?? f.total;
      const cab = `${esc(f.numero_auxadi || '(sin número)')} · ${esc(f.fecha_emision || '—')} · ${imp != null ? fmt2(imp) + ' €' : '—'}`;
      if (f.casado) {
        return `<div class="informe-guardado">
          <span class="nombre">${cab}<br>
            <span class="fecha">casa con ${esc(f.hito)} — ${esc(f.cliente)} · confianza: ${esc(CONFIANZA_TXT[f.confianza] || f.confianza)}</span>
          </span>
          <span style="display:flex;gap:6px">
            <button class="mini verde" data-ing-ok="${f.id}">Confirmar</button>
            <button class="mini gris" data-ing-no="${f.id}">Descartar</button>
          </span></div>`;
      }
      return `<div class="informe-guardado" style="border-color:rgba(255,214,10,.4)">
        <span class="nombre">${cab}<br>
          <span class="fecha" style="color:var(--ambar)">⚠ ${esc(f.motivo_duda || 'sin casar')}</span>
        </span>
        <span style="display:flex;gap:6px">
          <button class="mini gris" data-ing-no="${f.id}">Descartar</button>
        </span></div>`;
    }).join('') : '<span class="status">nada pendiente de revisar</span>';
    st.textContent = n ? `${n} pendiente(s)` : '';
    st.className = 'status';
  } catch (e) {
    if (e.message !== 'SIN_SESION') { st.textContent = e.message; st.className = 'status error'; }
  }
}
$('ingLista').addEventListener('click', async (e) => {
  const ok = e.target.closest('button[data-ing-ok]');
  const no = e.target.closest('button[data-ing-no]');
  if (ok) {
    if (!confirm('¿Confirmar? Se marcará la factura como ENVIADA con los datos del PDF.')) return;
    try {
      const r = await rpc('cm_confirmar_ingesta_factura', { p_ingesta_id: ok.dataset.ingOk });
      alert(r.ok ? `✓ ${r.factura} actualizada con la factura ${r.numero_auxadi}` : `No se pudo: ${r.error}`);
      cargarIngesta();
    } catch (err) { alert('Error: ' + err.message); }
  } else if (no) {
    const motivo = prompt('¿Por qué lo descartas? (opcional)') || null;
    try {
      await rpc('cm_descartar_ingesta', { p_ingesta_id: no.dataset.ingNo, p_motivo: motivo });
      cargarIngesta();
    } catch (err) { alert('Error: ' + err.message); }
  }
});

// ============================================================
// INGESTA DE PROPUESTAS (FASE G.4)
// ============================================================
// Diferencia clave con las facturas: una factura se CASA contra un HITO pendiente que ya existe
// así que basta confirmar/descartar. Una propuesta es un ALTA desde cero, y la extracción
// acierta el total en ~3 de cada 4 documentos: por eso cliente, fecha, importe y líneas
// llegan EDITABLES y lo que se manda a la RPC es lo que quede en pantalla, no lo extraído.
// Un mismo documento puede proponer VARIAS altas (bloques), que se confirman una a una.

const CONFIANZA_CLI = {
  nif_exacto: 'NIF exacto',
  denominacion: 'por denominación',
  tokens: 'por nombre aproximado',
  pie_legal: '⚠ solo aparece en el pie legal',
};

let CAT = null;   // catálogos (tipo_servicio + entidades), se cargan una vez
async function catalogos() {
  if (CAT) return CAT;
  const [servicios, entidades] = await Promise.all([
    fetchDetalle('/tipo_servicio?select=codigo,nombre_es&activo=is.true&order=nombre_es'),
    fetchDetalle('/entidad_legal?select=id,denominacion_social&order=denominacion_social'),
  ]);
  CAT = { servicios, entidades };
  return CAT;
}

const optsServicio = (sel) => CAT.servicios
  .map(s => `<option value="${esc(s.codigo)}"${s.codigo === sel ? ' selected' : ''}>${esc(s.nombre_es)}</option>`).join('');

const optsEntidad = (sel) => CAT.entidades
  .map(e => `<option value="${e.id}"${e.id === sel ? ' selected' : ''}>${esc(e.denominacion_social)}</option>`).join('');

function filaLineaProp(l, i) {
  return `<tr data-linea="${i}">
    <td><input class="lp-desc" value="${esc(l.descripcion || '')}"></td>
    <td><select class="lp-serv">${optsServicio(l.tipo_servicio || 'LF_COMPLETO')}</select></td>
    <td><select class="lp-clas">
      <option value="cartera">cartera</option>
      <option value="incidental"${l.clasificacion === 'incidental' ? ' selected' : ''}>incidental</option>
    </select></td>
    <td class="imp"><input class="lp-imp num" value="${l.importe ?? ''}"></td>
    <td><button class="mini gris" data-lp-del="${i}" title="quitar línea">×</button></td>
  </tr>`;
}

function bloqueProp(f, b) {
  const hecho = (f.bloques_aplicados || []).includes(b.idx);
  const lineas = (b.lineas || []).map(filaLineaProp).join('');
  const conf = CONFIANZA_CLI[b.confianza_cliente] || b.confianza_cliente || '—';
  return `<div class="prop-bloque${hecho ? ' hecho' : ''}" data-bloque="${b.idx}" data-ing="${f.id}">
    ${f.n_bloques > 1 ? `<h4>Alta ${b.idx + 1} de ${f.n_bloques}${hecho ? ' — ya confirmada' : ''}</h4>` : ''}
    <div class="prop-campos">
      <div>
        <label>Cliente</label>
        <select class="pb-cliente">
          <option value="">— elige el cliente —</option>
          ${/* pie_legal NO se preselecciona: es probablemente el remitente, no el cliente.
               Se deja en la lista como sugerencia, pero que lo elija Antonio a conciencia. */
            optsEntidad(b.confianza_cliente === 'pie_legal' ? null : b.cliente_id)}
        </select>
        <div class="sub">${b.cliente ? `detectado: ${esc(b.cliente)} (${esc(conf)})` : 'no se ha identificado ninguno'}
          · <button class="mini gris pb-nuevo">crear cliente nuevo</button></div>
      </div>
      <div><label>Fecha de envío</label><input type="date" class="pb-fecha" value="${esc(f.fecha_envio || '')}"></div>
      <div><label>Importe propuesto (€)</label><input class="pb-importe num" value="${b.importe ?? ''}"></div>
    </div>
    <table class="prop-lineas">
      <thead><tr><th style="width:44%">Concepto</th><th>Tipo de servicio</th><th>Clasif.</th><th class="imp">Importe</th><th></th></tr></thead>
      <tbody>${lineas}</tbody>
    </table>
    <div class="top-row">
      <button class="mini gris pb-addlinea">+ añadir línea</button>
      <span class="status pb-cuadre"></span>
    </div>
    ${hecho ? '' : `<div class="top-row" style="justify-content:flex-end;gap:8px;margin-top:8px">
      <button class="mini verde pb-confirmar">Confirmar alta${f.n_bloques > 1 ? ' ' + (b.idx + 1) : ''}</button>
    </div>`}
  </div>`;
}

function tarjetaProp(f) {
  const bloques = (f.cambios_propuestos && f.cambios_propuestos.bloques) || [];
  const avisos = (f.avisos || []).filter(Boolean);
  const pills = [
    `<span class="pill ${f.confianza === 'alta' ? 'ok' : 'warn'}">confianza ${esc(f.confianza || '?')}</span>`,
    f.tipo_doc === 'EMAIL' ? '<span class="pill morado">es un email</span>' : '',
    `<span class="pill">${esc(f.metodo_extraccion || '')}</span>`,
  ].join('');

  if (!bloques.length) {
    return `<div class="prop-tarjeta" data-ing="${f.id}">
      <div class="prop-cab"><div><strong>${esc(nombreArchivo(f.archivo))}</strong>
        <div class="sub">${esc(f.motivo_duda || 'sin datos suficientes para proponer un alta')}</div></div>
        <div class="pills">${pills}</div></div>
      ${avisos.map(a => `<div class="prop-aviso">${esc(a)}</div>`).join('')}
      <div class="top-row" style="justify-content:flex-end"><button class="mini gris pt-descartar">Descartar</button></div>
    </div>`;
  }

  // Cuatro estados, no dos: hasta el 25-08 cualquier cosa distinta de «cuadra» caía en
  // «⚠ sin total explícito», incluso con el total pintado en la línea de arriba (pasaba
  // siempre que el importe venía de la cascada de IA y no de una tabla del regex).
  const cuadre = f.cuadra === true
    ? '<span class="ok">✓ el total cuadra con la suma de líneas</span>'
    : f.descuento
      ? '<span class="warn">tiene descuento: el total no cuadra con las líneas a propósito</span>'
    : f.cuadra === false
      ? '<span class="warn">⚠ las líneas no suman el total del documento: revísalo</span>'
    : f.total_documento == null
      ? '<span class="warn">⚠ sin total explícito en el documento</span>'
      : '<span class="sub">sin líneas con las que cuadrar</span>';

  return `<div class="prop-tarjeta" data-ing="${f.id}">
    <div class="prop-cab">
      <div><strong>${esc(nombreArchivo(f.archivo))}</strong>
        <div class="sub">total del documento: ${f.total_documento != null ? fmt2(f.total_documento) + ' €' : '—'} · ${cuadre}</div>
      </div>
      <div class="pills">${pills}</div>
    </div>
    ${avisos.map(a => `<div class="prop-aviso${/pie legal|email/.test(a) ? ' grave' : ''}">${esc(a)}</div>`).join('')}
    ${bloques.map(b => bloqueProp(f, b)).join('')}
    <div class="top-row" style="justify-content:flex-end;margin-top:6px">
      <button class="mini gris pt-descartar">Descartar documento</button>
    </div>
  </div>`;
}

const nombreArchivo = (p) => String(p || '').split('/').pop();

async function cargarIngestaProp() {
  const st = $('ingpStatus');
  try {
    await catalogos();
    const filas = await fetchDetalle('/v_cm_ingesta_pendiente_propuesta?select=*');
    const n = filas.length;
    const b = $('ingpBadge');
    if (n) { b.textContent = n; b.style.display = 'inline-block'; } else b.style.display = 'none';
    $('ingpLista').innerHTML = n ? filas.map(tarjetaProp).join('')
                                 : '<span class="status">nada pendiente de revisar</span>';
    $('ingpLista').querySelectorAll('.prop-bloque').forEach(recalcularCuadre);
    st.textContent = n ? `${n} documento(s)` : '';
    st.className = 'status';
  } catch (e) {
    if (e.message !== 'SIN_SESION') { st.textContent = e.message; st.className = 'status error'; }
  }
}

// El cuadre se calcula SIEMPRE en JS y se refresca al teclear: nunca se le pide a la IA
// (lección de FASE I). Avisa en vivo si las líneas dejan de sumar el importe de la cabecera.
function recalcularCuadre(bloque) {
  const imp = num(bloque.querySelector('.pb-importe').value);
  const suma = [...bloque.querySelectorAll('.lp-imp')].reduce((a, i) => a + (num(i.value) || 0), 0);
  const el = bloque.querySelector('.pb-cuadre');
  if (!suma) { el.textContent = ''; return; }
  const ok = imp != null && Math.abs(suma - imp) < 0.01;
  el.textContent = ok ? `✓ las líneas suman ${fmt2(suma)} €`
                      : `⚠ las líneas suman ${fmt2(suma)} € y el importe dice ${imp != null ? fmt2(imp) : '—'} €`;
  el.className = 'status pb-cuadre ' + (ok ? 'ok' : 'warn');
}

const num = (v) => {
  const n = Number(String(v).replace(/\./g, '').replace(',', '.').replace(/[^\d.-]/g, ''));
  return Number.isFinite(n) ? n : null;
};

function datosBloque(bloque) {
  const lineas = [...bloque.querySelectorAll('tr[data-linea]')].map(tr => ({
    descripcion: tr.querySelector('.lp-desc').value.trim(),
    importe: num(tr.querySelector('.lp-imp').value),
    tipo_servicio: tr.querySelector('.lp-serv').value,
    clasificacion: tr.querySelector('.lp-clas').value,
  // Se admiten importes NEGATIVOS: la extracción puede traer la fila de descuento como
  // línea propia (visto con ITV FY2025: 7 brutos + «Discount −10.050» = 23.450). Con el
  // filtro anterior (> 0) esa línea se descartaba AL CONFIRMAR pero seguía pintada en
  // pantalla: el cuadre visual decía ✓ y el alta se guardaba descuadrada en silencio.
  })).filter(l => l.importe != null && l.importe !== 0);
  return {
    p_ingesta_id: bloque.dataset.ing,
    p_bloque_idx: Number(bloque.dataset.bloque),
    p_cliente_id: bloque.querySelector('.pb-cliente').value || null,
    p_fecha_envio: bloque.querySelector('.pb-fecha').value || null,
    p_importe: num(bloque.querySelector('.pb-importe').value),
    p_lineas: lineas,
  };
}

$('ingpLista').addEventListener('input', (e) => {
  if (e.target.matches('.pb-importe, .lp-imp')) recalcularCuadre(e.target.closest('.prop-bloque'));
});

$('ingpLista').addEventListener('click', async (e) => {
  const bloque = e.target.closest('.prop-bloque');

  if (e.target.matches('.pb-addlinea')) {
    const tbody = bloque.querySelector('tbody');
    tbody.insertAdjacentHTML('beforeend', filaLineaProp({}, tbody.children.length));
    return;
  }
  if (e.target.matches('[data-lp-del]')) {
    e.target.closest('tr').remove();
    recalcularCuadre(bloque);
    return;
  }
  if (e.target.matches('.pb-nuevo')) {
    const den = prompt('Denominación social del cliente nuevo:');
    if (!den || !den.trim()) return;
    const nif = prompt('NIF (opcional):') || null;
    bloque.dataset.nuevoCliente = JSON.stringify({ denominacion: den.trim(), nif: nif && nif.trim() });
    bloque.querySelector('.pb-cliente').insertAdjacentHTML('afterbegin',
      `<option value="" selected>➕ ${esc(den.trim())} (se creará al confirmar)</option>`);
    return;
  }

  if (e.target.matches('.pb-confirmar')) {
    const d = datosBloque(bloque);
    if (bloque.dataset.nuevoCliente) { d.p_nuevo_cliente = JSON.parse(bloque.dataset.nuevoCliente); d.p_cliente_id = null; }
    if (!d.p_cliente_id && !d.p_nuevo_cliente) { alert('Elige un cliente o crea uno nuevo.'); return; }
    if (!d.p_importe) { alert('Revisa el importe antes de confirmar.'); return; }
    const suma = d.p_lineas.reduce((a, l) => a + l.importe, 0);
    const aviso = suma && Math.abs(suma - d.p_importe) > 0.01
      ? `\n\n⚠ Las líneas suman ${fmt2(suma)} € y el importe dice ${fmt2(d.p_importe)} €.` : '';
    if (!confirm(`Se creará una propuesta nueva en estado OPORTUNIDAD por ${fmt2(d.p_importe)} € con ${d.p_lineas.length} línea(s).${aviso}`)) return;
    try {
      const r = await rpc('cm_confirmar_ingesta_propuesta', d);
      alert(r.ok
        ? `✓ ${r.propuesta} creada (${r.lineas} línea(s), ${fmt2(r.importe)} €)` +
          (r.bloques_pendientes ? `\nQuedan ${r.bloques_pendientes} alta(s) por confirmar en este documento.` : '')
        : `No se pudo: ${r.error}`);
      cargarIngestaProp();
    } catch (err) { alert('Error: ' + err.message); }
    return;
  }

  if (e.target.matches('.pt-descartar')) {
    const id = e.target.closest('.prop-tarjeta').dataset.ing;
    const motivo = prompt('¿Por qué lo descartas? (opcional)') || null;
    try {
      await rpc('cm_descartar_ingesta', { p_ingesta_id: id, p_motivo: motivo });
      cargarIngestaProp();
    } catch (err) { alert('Error: ' + err.message); }
  }
});

// ============================================================
// INGESTA DE CORRESPONDENCIA (25-08-2026)
// ============================================================
// Datos complementarios de entidad que llegan DESPUÉS de la aprobación: CIF, dirección
// fiscal, VAT, email… La función solo propone los campos que DIFIEREN de la ficha; aquí
// se elige la entidad, se edita lo propuesto y se confirma campo a campo (checkbox).
// Nada se aplica sin marcar y confirmar — misma filosofía que propuestas: lo que se manda
// a la RPC es lo que quede en pantalla.

const ETIQUETA_CAMPO = {
  nif: 'NIF / CIF',
  vat_number: 'VAT intracomunitario',
  direccion_fiscal: 'Dirección fiscal',
  codigo_postal: 'Código postal',
  ciudad: 'Ciudad',
  pais: 'País',
  email_general: 'Email',
  web: 'Web',
  idioma_correspondencia: 'Idioma',
};

function tarjetaCorr(f) {
  const campos = Object.entries(f.campos || {});
  const avisos = (f.avisos || []).filter(Boolean);
  const pills = [
    `<span class="pill ${f.confianza === 'media' ? 'ok' : 'warn'}">confianza ${esc(f.confianza || '?')}</span>`,
    `<span class="pill">${esc(f.metodo_extraccion || '')}</span>`,
  ].join('');

  const filas = campos.map(([campo, det]) => `<tr data-campo="${esc(campo)}">
    <td><label style="display:flex;gap:6px;align-items:center">
      <input type="checkbox" class="cc-aplicar" checked> ${esc(ETIQUETA_CAMPO[campo] || campo)}</label></td>
    <td class="sub">${det.actual != null ? esc(det.actual) : '<em>— vacío —</em>'}</td>
    <td><input class="cc-valor" value="${esc(det.propuesto || '')}">${det.verificado === false
      ? '<div class="sub" style="color:var(--ambar)">⚠ no aparece literal en el documento</div>' : ''}</td>
  </tr>`).join('');

  return `<div class="prop-tarjeta corr-tarjeta" data-ing="${f.id}">
    <div class="prop-cab">
      <div><strong>${esc(nombreArchivo(f.archivo))}</strong>
        <div class="sub">${campos.length
          ? `${campos.length} campo(s) que completar en la ficha`
          : esc(f.motivo_duda || 'sin datos nuevos frente a la ficha')}</div>
      </div>
      <div class="pills">${pills}</div>
    </div>
    ${avisos.map(a => `<div class="prop-aviso">${esc(a)}</div>`).join('')}
    <div class="prop-campos" style="margin-bottom:8px">
      <div>
        <label>Entidad</label>
        <select class="cc-entidad">
          <option value="">— elige la entidad —</option>
          ${optsEntidad(f.entidad_id)}
        </select>
        <div class="sub">${f.entidad ? `detectada: ${esc(f.entidad)} (${esc(CONFIANZA_CLI[f.confianza_entidad] || f.confianza_entidad || '—')})` : 'no se ha identificado'}</div>
      </div>
    </div>
    ${campos.length ? `<table class="prop-lineas">
      <thead><tr><th style="width:30%">Campo</th><th>En la ficha</th><th>Propuesto</th></tr></thead>
      <tbody>${filas}</tbody>
    </table>` : ''}
    ${f.otros ? `<div class="sub" style="margin-top:6px">Otros datos del documento: ${esc(f.otros)}</div>` : ''}
    <div class="top-row" style="justify-content:flex-end;gap:8px;margin-top:8px">
      <button class="mini gris cc-descartar">Descartar</button>
      ${campos.length ? '<button class="mini verde cc-confirmar">Aplicar a la ficha</button>' : ''}
    </div>
  </div>`;
}

async function cargarIngestaCorr() {
  const st = $('ingcStatus');
  try {
    await catalogos();
    const filas = await fetchDetalle('/v_cm_ingesta_pendiente_correspondencia?select=*');
    const n = filas.length;
    const b = $('ingcBadge');
    if (n) { b.textContent = n; b.style.display = 'inline-block'; } else b.style.display = 'none';
    $('ingcLista').innerHTML = n ? filas.map(tarjetaCorr).join('')
                                 : '<span class="status">nada pendiente de revisar</span>';
    st.textContent = n ? `${n} documento(s)` : '';
    st.className = 'status';
  } catch (e) {
    if (e.message !== 'SIN_SESION') { st.textContent = e.message; st.className = 'status error'; }
  }
}

$('ingcLista').addEventListener('click', async (e) => {
  const tarjeta = e.target.closest('.corr-tarjeta');
  if (!tarjeta) return;

  if (e.target.matches('.cc-confirmar')) {
    const entidad = tarjeta.querySelector('.cc-entidad').value;
    if (!entidad) { alert('Elige la entidad antes de aplicar.'); return; }
    const campos = {};
    tarjeta.querySelectorAll('tr[data-campo]').forEach(tr => {
      if (tr.querySelector('.cc-aplicar').checked) {
        const v = tr.querySelector('.cc-valor').value.trim();
        if (v) campos[tr.dataset.campo] = v;
      }
    });
    const n = Object.keys(campos).length;
    if (!n) { alert('No hay ningún campo marcado con valor.'); return; }
    if (!confirm(`Se actualizarán ${n} campo(s) de la ficha de la entidad. ¿Seguro?`)) return;
    try {
      const r = await rpc('cm_confirmar_ingesta_correspondencia',
        { p_ingesta_id: tarjeta.dataset.ing, p_entidad_id: entidad, p_campos: campos });
      alert(r.ok ? `✓ ${r.entidad}: ${r.aplicados} campo(s) actualizados` : `No se pudo: ${r.error}`);
      cargarIngestaCorr();
    } catch (err) { alert('Error: ' + err.message); }
    return;
  }

  if (e.target.matches('.cc-descartar')) {
    const motivo = prompt('¿Por qué lo descartas? (opcional)') || null;
    try {
      await rpc('cm_descartar_ingesta', { p_ingesta_id: tarjeta.dataset.ing, p_motivo: motivo });
      cargarIngestaCorr();
    } catch (err) { alert('Error: ' + err.message); }
  }
});

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

// En Android getVoices() devuelve [] en el primer arranque y se puebla después: sin escuchar
// 'voiceschanged' la primera respuesta salía con la voz por defecto del sistema (inglés).
let vozCache = null;
function vozFemenina() {
  if (vozCache) return vozCache;
  const esVoces = speechSynthesis.getVoices().filter(v => v.lang && v.lang.toLowerCase().startsWith('es'));
  const fem = /helena|laura|elvira|sabina|paloma|luc[ií]a|m[oó]nica|montse|dalia|camila|isidora|catalina|female|mujer/i;
  // Preferencia por las voces NEURALES de España (04-08-2026). Este equipo tiene 48 voces en
  // español y la elección caía en "Microsoft Helena", una SAPI clásica, solo porque aparece
  // antes en la lista; estando disponible "Elvira Online (Natural)" es-ES, que suena
  // muchísimo mejor. Es la misma voz que ya se eligió para Hermes (es-ES-ElviraNeural).
  const esEs = esVoces.filter(v => /^es-ES/i.test(v.lang));
  const natural = (v) => /natural|neural|online/i.test(v.name);
  vozCache = esEs.find(v => natural(v) && fem.test(v.name))
      || esEs.find(v => fem.test(v.name))
      || esVoces.find(v => natural(v) && fem.test(v.name))
      || esVoces.find(v => fem.test(v.name))
      || esVoces.find(v => /google/i.test(v.name))
      || esVoces[0] || null;
  return vozCache;
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
  // Los filtros de PostgREST usan la coma como separador: sin escapar, un cliente como
  // "Construcciones y Auxiliar de Ferrocarriles, S.A." rompería la consulta entera.
  const qUrl = encodeURIComponent(q.replace(/[,()*]/g, ' ').trim());

  if (rpcNombre === 'cm_reprogramar_hito') {
    // m290: se busca por `busqueda` (código del hito + código de proyecto + TODOS los clientes
    // relacionados), no por codigo_legible. Antes el prompt prometía "nombre de cliente" y el
    // resolutor solo miraba el código del hito: la acción fallaba siempre (lección #212).
    const rows = await fetchDetalle(`/v_cm_hitos_app?select=id,codigo_legible,estado,importe_neto,fecha_prevista,cliente,proyecto_codigo&busqueda=ilike.*${qUrl}*&limit=20`);
    const cands = rows.map(r => ({
      id: r.id, ref: r.codigo_legible, estado: r.estado, importe: r.importe_neto,
      fecha_prevista: r.fecha_prevista, cliente: r.cliente,
    }));
    // Decir "el hito de ITV" da varios candidatos. Reprogramar solo tiene sentido sobre los
    // que aún no se han facturado: si al quedarse con esos queda uno solo, no hay ambigüedad
    // real. Se filtra DESPUÉS de buscar, nunca antes, para no responder "no encuentro nada"
    // a quien da el código exacto de un hito ya facturado.
    const previstos = cands.filter(c => c.estado === 'previsto');
    return (cands.length > 1 && previstos.length === 1) ? previstos : cands;
  }

  if (rpcNombre === 'cm_registrar_hecho_proyecto') {
    // Bloque C: anotar una nota en la crónica, pausar un proyecto o darlo por perdido. Las
    // tres se dicen hablando, no hay botón en la app (decisión del 03-08).
    const rows = await fetchDetalle(`/v_cm_proyectos_app?select=id,codigo_legible,estado,cliente,descripcion&busqueda=ilike.*${qUrl}*&limit=20`);
    return rows.map(r => ({
      id: r.id, ref: r.codigo_legible, estado: r.estado, cliente: r.cliente,
      descripcion: r.descripcion,
    }));
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
      const params = d.rpc === 'cm_reprogramar_hito' ? { p_hito_id: resuelto.id, p_fecha: d.fecha }
        : d.rpc === 'cm_registrar_hecho_proyecto'
          ? { p_proyecto_id: resuelto.id, p_tipo_evento: d.hecho, p_fecha: d.fecha || null, p_nota: d.nota || null }
          : { p_propuesta_id: resuelto.id, p_nota: d.nota || d.resumen };
      const r = await rpc(d.rpc, params);
      if (r.ok) {
        // El estado del proyecto lo mueve la BASE a partir del hecho (m276), no la pantalla:
        // por eso se muestra lo que la RPC dice que pasó, no lo que se esperaba que pasara.
        // Con NOTA el estado no cambia, y entonces no se anuncia ningún cambio.
        linea.textContent = d.rpc === 'cm_reprogramar_hito' ? `✓ ${r.hito} reprogramado: ${r.antes} → ${r.ahora}`
          : d.rpc === 'cm_registrar_hecho_proyecto'
            ? `✓ ${r.proyecto}: ${r.hecho} (${r.fecha})` +
              (r.estado_antes !== r.estado_despues ? ` — estado ${r.estado_antes} → ${r.estado_despues}` : '')
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
    const iso = fechaIso;   // local, NUNCA toISOString() — ver el comentario de fechaIso
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

function recordar(rol, texto) {
  if (!texto) return;
  historialChat.push({ rol, texto: String(texto).slice(0, 300) });
  if (historialChat.length > 6) historialChat = historialChat.slice(-6);
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
      body: JSON.stringify({ pregunta: texto, historial: historialChat })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    // Se recuerda DESPUÉS de enviar: el historial que viaja es el de los turnos anteriores.
    recordar('usuario', texto);
    recordar('kira', d.respuesta || d.resumen || d.titulo || '');

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

// ============================================================
// NOTIFICACIONES PUSH (FASE J). Clave pública VAPID: no es un secreto, es la mitad
// pública del par (se usa igual que la clave ANON, embebida en el cliente por diseño).
// ============================================================
const VAPID_PUBLIC = 'BELkLIuqpIWPBMerr8wnx82-DJlf_yDKGg2myhvIiKai5GsqhUUZ4iHuivzBVIPZ7aJPBFZB5wH16Ny3Y0efGhY';
function urlBase64ToUint8Array(base64) {
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  const base64safe = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64safe);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}
async function activarAvisos() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    alert('Este navegador no soporta notificaciones push.'); return;
  }
  const tok = await getToken();
  if (!tok) { mostrarLogin(); return; }
  try {
    const permiso = await Notification.requestPermission();
    if (permiso !== 'granted') { alert('Permiso de notificaciones denegado.'); return; }
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC),
      });
    }
    const j = sub.toJSON();
    const r = await rpc('cm_guardar_push_sub', {
      p_endpoint: j.endpoint, p_p256dh: j.keys.p256dh, p_auth: j.keys.auth,
      p_user_agent: navigator.userAgent,
    });
    if (r.ok) {
      alert('✓ Avisos activados en este dispositivo.');
      $('btnAvisos').textContent = '🔔 avisos activados'; $('btnAvisos').disabled = true;
    }
  } catch (e) { alert('No se pudo activar: ' + e.message); }
}
async function comprobarAvisos() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  try {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) { $('btnAvisos').textContent = '🔔 avisos activados'; $('btnAvisos').disabled = true; }
  } catch {}
}

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
      if (bioActivada()) await bioRevincular(); // repara Hello tras entrar por respaldo
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
  $('btnAvisos').onclick = activarAvisos;
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) $('btnAvisos').style.display = 'none';

  $('refresh').onclick = cargarPanel;
  $('btnBuscar').onclick = buscar;
  $('btnCsv').onclick = exportarCsv;
  // Consultar (03-08): tres filtros de selección múltiple en lugar del campo de texto de cliente,
  // y los botones de ejercicio, que se pintan al cargar los catálogos.
  document.querySelectorAll('#pantalla-explorar .multi').forEach(m => montarMulti(m));
  cargarEjercicios().catch(() => {});
  // Work-in-Progress: sin filtros ni botón de buscar (03-08-2026), se carga al entrar.

  // Pantalla de propuesta: volver al WIP y los tres lápices de edición
  $('propVolver').onclick = (e) => {
    e.preventDefault();
    document.querySelectorAll('.pantalla').forEach(x => x.classList.remove('activa'));
    $('pantalla-proyectos').classList.add('activa');
    document.querySelector('.nav-item[data-pantalla="proyectos"]').classList.add('activa');
    cargarProyectos();
  };
  [['propLapizEstado', 'estado'], ['propLapizFicha', 'ficha'], ['propLapizEquipo', 'equipo']].forEach(([boton, clave]) => {
    $(boton).onclick = () => {
      modoEdicion[clave] = !modoEdicion[clave];
      $(boton).classList.toggle('activo', modoEdicion[clave]);
      pintarPropuesta();
    };
  });
  $('btnElegir').onclick = () => $('inputFicheros').click();
  $('inputFicheros').addEventListener('change', e => subirFicheros(e.target.files));
  const zona = $('zonaSubir');
  zona.addEventListener('dragover', e => { e.preventDefault(); zona.classList.add('arrastre'); });
  zona.addEventListener('dragleave', () => zona.classList.remove('arrastre'));
  zona.addEventListener('drop', e => { e.preventDefault(); zona.classList.remove('arrastre'); subirFicheros(e.dataTransfer.files); });
  $('btnVerBandeja').onclick = verBandeja;
  $('btnIngRefrescar').onclick = cargarIngesta;
  $('btnIngpRefrescar').onclick = cargarIngestaProp;
  $('btnIngcRefrescar').onclick = cargarIngestaCorr;
  $('btnInfGenerar').onclick = () => generarInforme(false);
  $('btnInfRefinar').onclick = () => generarInforme(true);
  $('btnInfGuardar').onclick = guardarInformeActual;
  $('btnInfPdf').onclick = exportarInformePdf;
  $('btnInfExcel').onclick = exportarInformeExcel;
  // Cliente 360º (03-08): desplegable de selección única en lugar de la caja de texto.
  montarMulti($('c360Cliente'), {
    store: selC360, uni: true, vacio: 'elige un cliente…',
    fuente: cargarClientesFiltro,      // todos los clientes con actividad, no los de una vista
    alCambiar: () => {
      const c = selC360.cliente[0];
      if (c) buscarCliente360(c.nombre); else $('c360Resultado').innerHTML = '';
    },
  });
  $('btnEnviar').onclick = () => preguntar();
  $('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter') preguntar(); });
  $('btnMic').onclick = () => { if (rec) { try { rec.start(); } catch {} } };

  ponerEstados();
  initVoz();
  // E8: la preferencia de voz sobrevive a recargar (antes se marcaba siempre por defecto)
  const vozGuardada = localStorage.getItem(LS_VOZ);
  if (vozGuardada !== null) $('chkVoz').checked = vozGuardada === '1';
  $('chkVoz').addEventListener('change', () => localStorage.setItem(LS_VOZ, $('chkVoz').checked ? '1' : '0'));
  if ('speechSynthesis' in window) {
    speechSynthesis.getVoices(); // precarga de voces
    // Android puebla la lista de forma asíncrona: al llegar, se rehace la elección.
    speechSynthesis.addEventListener('voiceschanged', () => { vozCache = null; vozFemenina(); });
  }

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
