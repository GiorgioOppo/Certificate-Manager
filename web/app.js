(() => {
  'use strict';

  const i18n = window.CertificateI18n;
  const msg = (key, values) => i18n.t(key, values);
  const byId = id => document.getElementById(id);
  const on = (id, event, handler) => { const node = byId(id); if (node) node.addEventListener(event, handler); };
  const currentPage = document.body.dataset.page || 'overview';
  const labels = { healthy: msg('m_337648528a3b'), warning: msg('m_e77156af7a9b'), urgent: msg('m_9dc81c64f153'), expired: msg('m_89bf53640b26'), not_yet_valid: msg('m_321c57909f41') };
  const dateFormat = new Intl.DateTimeFormat(i18n.locale, { day: '2-digit', month: 'short', year: 'numeric' });
  const dateTimeFormat = new Intl.DateTimeFormat(i18n.locale, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const timeFormat = new Intl.DateTimeFormat(i18n.locale, { hour: '2-digit', minute: '2-digit' });
  let state = { certificates: [], notifications: [], outbox: [], delivery: {}, monitors: [], monitor_events: [], monitoring: {}, csrf_token: '' };
  let loaded = false;
  let connected = false;
  let refreshing = null;
  let uploading = false;
  let checking = false;
  let deleting = false;
  let deletionTarget = null;
  let detailsTargetId = null;
  let deleteTargetId = null;
  let desktopEnabled = false;
  let desktopBaselinePending = false;
  let desktopRequesting = false;
  let detailsCertificate = null;
  let contactsDirty = false;
  let savingContacts = false;
  let renewing = false;
  let distributing = false;
  let processingDelivery = false;
  let smtpDirty = false;
  let smtpInitialized = false;
  let smtpBusy = '';
  let contactSequence = 0;
  let remoteChecking = false;
  let remoteImporting = false;
  let remoteResult = null;
  let remoteExpectedId = null;
  let remoteExpiryTimer = null;
  let remoteSnapshotExpired = false;
  let skipDetailsFocusRestore = false;
  let monitorEditingId = null;
  let monitorDraftDirty = false;
  let monitorMutating = false;
  let monitorDeleteTarget = null;
  let monitorDeleting = false;
  let monitorSelectSignature = '';
  let monitorRefreshTimer = null;
  const expandedMonitorIds = new Set();
  const seenNotifications = new Set();
  const legacyRoutes = {
    main: '/', overview: '/', registry: '/certificati', monitoring: '/servizi',
    'monitor-form': '/servizi#monitor-form', 'monitor-alerts': '/servizi#monitor-alerts',
    'remote-check': '/verifica', verify: '/verifica', acquire: '/importa',
    'import-panel': '/importa', directory: '/rubrica', reminders: '/promemoria', delivery: '/email', workflow: '/workflow'
  };
  let initialContextApplied = false;
  function initializeWorkflow() {
    const tabs = Array.from(document.querySelectorAll('.workflow-tab'));
    if (!tabs.length) return;
    function select(tab, { focus = false, updateHash = false } = {}) {
      for (const item of tabs) {
        const selected = item === tab;
        item.setAttribute('aria-selected', String(selected));
        item.tabIndex = selected ? 0 : -1;
        byId(item.getAttribute('aria-controls')).hidden = !selected;
      }
      if (focus) tab.focus({ preventScroll: true });
      if (updateHash) {
        const url = new URL(window.location.href);
        url.hash = tab.getAttribute('aria-controls');
        window.history.replaceState(null, '', url.pathname + url.search + url.hash);
      }
    }
    const fromHash = () => tabs.find(tab => '#' + tab.getAttribute('aria-controls') === window.location.hash) || tabs[0];
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => select(tab, { updateHash: true }));
      tab.addEventListener('keydown', event => {
        let next;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = tabs.length - 1;
        else return;
        event.preventDefault();
        select(tabs[next], { focus: true, updateHash: true });
      });
    });
    window.addEventListener('hashchange', () => select(fromHash()));
    select(fromHash());
  }
  const registryContactSelection = { business: '', technical: '' };
  const registryContactSignatures = { business: '', technical: '' };
  const registryCASelection = { root_ca: '', intermediate_ca: '' };
  const registryCASignatures = { root_ca: '', intermediate_ca: '' };
  const registryCAFilters = [
    { field: 'root_ca', id: 'root-ca-filter', all: msg('m_a865299e526e') },
    { field: 'intermediate_ca', id: 'intermediate-ca-filter', all: msg('m_a9aa957607c9') }
  ];

  function navigateTo(destination, { focusHeading = false, scroll = true } = {}) {
    const path = destination.startsWith('#') ? legacyRoutes[destination.slice(1)] || destination : destination;
    const url = new URL(i18n.localURL(path), window.location.href);
    if (url.pathname !== window.location.pathname) {
      window.location.assign(url.pathname + url.search + url.hash);
      return;
    }
    if (url.hash && window.location.hash !== url.hash) window.history.replaceState(null, '', url.pathname + window.location.search + url.hash);
    const target = byId(url.hash.slice(1)) || byId('page-title');
    if (scroll && target) target.scrollIntoView({ block: 'start' });
    if (focusHeading && target) { target.tabIndex = -1; target.focus({ preventScroll: true }); }
  }

  function applyInitialContext() {
    if (initialContextApplied) return;
    initialContextApplied = true;
    const rawId = new URLSearchParams(window.location.search).get('certificate_id');
    if (rawId === null) return;
    const cert = /^[1-9]\d*$/.test(rawId) ? state.certificates.find(item => String(item.id) === rawId) : null;
    if (!cert) { message(msg('m_c9ac1fd7cfb2'), true); return; }
    if (currentPage === 'verify') {
      setRemoteExpected(cert);
      byId('remote-target').value = /^https:\/\//i.test(string(cert.source, '')) ? cert.source : string(cert.common_name, '');
      remoteFeedback(msg('m_f80311c9f5ff'));
      byId('remote-target').focus({ preventScroll: true });
    } else if (currentPage === 'monitoring') {
      if (cert.is_ca || cert.archived) { monitorFeedback(msg('m_f78e3fcbd4b7'), true); return; }
      renderMonitorSelect();
      resetMonitorForm();
      byId('monitor-certificate').value = String(cert.id);
      byId('monitor-target').value = /^https:\/\//i.test(string(cert.source, '')) ? cert.source : string(cert.common_name, '');
      monitorFeedback(msg('m_f116c4d5dd89'));
      byId('monitor-target').focus({ preventScroll: true });
    } else if (currentPage === 'registry' || currentPage === 'overview') showDetails(cert);
  }

  function string(value, fallback = '—') {
    if (value === null || value === undefined || value === '') return fallback;
    if (Array.isArray(value)) return value.join(', ') || fallback;
    return String(value);
  }

  function date(value, withTime = false) {
    if (value === null || value === undefined || value === '') return '—';
    const timestamp = Number(value);
    if (!Number.isFinite(timestamp)) return '—';
    const parsed = new Date(timestamp * 1000);
    return Number.isNaN(parsed.getTime()) ? '—' : (withTime ? dateTimeFormat : dateFormat).format(parsed);
  }

  function name(certificate) {
    return string(certificate.common_name, string(certificate.sans, string(certificate.subject, string(certificate.source, msg('m_7047cf9d6d49')))));
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function badge(status) {
    const safeStatus = Object.prototype.hasOwnProperty.call(labels, status) ? status : 'healthy';
    return element('span', `badge badge-${safeStatus}`, labels[safeStatus]);
  }

  function message(text, error = false) {
    const box = byId('status-message');
    box.textContent = text;
    box.classList.toggle('message-error', error);
    box.hidden = !text;
  }

  function setConnection(ok, errorText) {
    connected = ok;
    byId('connection-dot').classList.toggle('disconnected', !ok);
    byId('connection-label').textContent = ok ? msg('m_7f6d934fa4a6') : msg('m_2970cb421b15');
    byId('connection-error').hidden = ok;
    if (!ok) byId('connection-error').textContent = errorText || msg('m_b08e4623f4ea');
    updateButtons();
  }

  function updateButtons() {
    byId('check-button').disabled = !connected || checking || uploading || deleting;
    for (const id of ['choose-files', 'certificate-files']) if (byId(id)) byId(id).disabled = !connected || uploading || deleting;
    if (byId('process-delivery')) byId('process-delivery').disabled = !connected || processingDelivery || !state.delivery.configured;
    if (byId('outbox-list')) for (const button of byId('outbox-list').querySelectorAll('.retry-delivery')) button.disabled = !connected;
    updateDetailButtons();
    updateRemoteButtons();
    updateMonitorButtons();
    updateSmtpButtons();
    updateDesktopButton();
  }

  function updateDetailButtons() {
    const cert = detailsCertificate;
    const busy = savingContacts || renewing || distributing;
    const blocked = !connected || !cert || busy;
    byId('save-contacts').disabled = blocked;
    byId('add-business-contact').disabled = blocked;
    byId('add-technical-contact').disabled = blocked;
    for (const input of byId('contacts-form').querySelectorAll('input, .remove-contact')) input.disabled = blocked;
    byId('choose-renewal').disabled = blocked || contactsDirty || !!cert.archived || !!cert.is_ca;
    byId('renewal-file').disabled = byId('choose-renewal').disabled;
    byId('distribute-certificate').disabled = blocked || contactsDirty || !!cert.archived || !cert.pem_available || !(cert.contacts || []).some(contact => contact.role === 'technical');
    byId('verify-online').disabled = blocked || remoteChecking || remoteImporting;
    byId('monitor-from-details').disabled = blocked || monitorMutating || !!cert.archived || !!cert.is_ca;
    byId('close-details').disabled = busy;
    byId('details-done').disabled = busy;
    byId('contacts-unsaved').hidden = !contactsDirty;
    let help = msg('m_cc3de5c8914d');
    if (cert && cert.archived) help = msg('m_ec21bf86d325');
    else if (cert && cert.is_ca) help = msg('m_252be4dfc959');
    else if (contactsDirty) help = msg('m_ab8f05842744');
    else if (cert && !cert.pem_available) help = msg('m_821a1caffd4d');
    else if (cert && !(cert.contacts || []).some(contact => contact.role === 'technical')) help = msg('m_3defd4bb65f8');
    byId('certificate-action-help').textContent = help;
  }

  async function request(path, options = {}, diagnostic = false) {
    const headers = new Headers(options.headers || {});
    if (options.method && options.method !== 'GET') {
      if (!state.csrf_token) throw new Error(msg('m_b72a4e3e193d'));
      headers.set('X-CSRF-Token', state.csrf_token);
    }
    let response;
    try {
      response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    } catch (_) {
      setConnection(false);
      throw new Error(msg('m_3270741485cb'));
    }
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error(msg('m_ede6fe682b8f')); }
    i18n.localizeResponse(data);
    if (!response.ok || (data.error && !diagnostic)) {
      const error = new Error(string(data.error, msg('m_1f200d72c67d', [response.status])));
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function remoteFeedback(text, error = false) {
    if (!byId('remote-feedback')) return;
    const box = byId('remote-feedback');
    box.textContent = text;
    box.hidden = !text;
    box.classList.toggle('message-error', error);
  }

  function updateRemoteButtons() {
    if (!byId('remote-form')) return;
    const busy = remoteChecking || remoteImporting;
    byId('remote-submit').disabled = !connected || busy;
    byId('remote-target').disabled = busy;
    byId('remote-clear-expected').disabled = busy;
    byId('remote-submit').textContent = remoteChecking ? msg('m_12c3542bd127') : msg('m_3e6e28ad4294');
    byId('remote-submit').setAttribute('aria-busy', String(remoteChecking));
    byId('remote-import').disabled = !connected || busy || !remoteResult || !remoteResult.token || remoteSnapshotExpired;
    byId('remote-import').textContent = remoteImporting ? msg('m_bb33d5cd59dd') : remoteResult && !remoteResult.verified ? msg('m_7c089e391254') : msg('m_090a05ee5e45');
    byId('remote-download').hidden = !remoteResult || !remoteResult.download_url || remoteSnapshotExpired || busy;
  }

  function clearRemoteResult() {
    if (!byId('remote-result')) return;
    if (remoteExpiryTimer) clearTimeout(remoteExpiryTimer);
    remoteExpiryTimer = null;
    remoteResult = null;
    remoteSnapshotExpired = false;
    byId('remote-result').hidden = true;
    byId('remote-download').removeAttribute('href');
    updateRemoteButtons();
  }

  function setRemoteExpected(cert) {
    if (!byId('remote-form')) return;
    remoteExpectedId = cert ? cert.id : null;
    byId('remote-comparison-context').hidden = !cert;
    byId('remote-expected-label').textContent = cert ? msg('m_3c6699b81c53', [name(cert), cert.id]) : '';
  }

  function safeRemoteDownload(value) {
    if (!value) return null;
    try {
      const url = new URL(value, window.location.href);
      return url.origin === window.location.origin && url.pathname.startsWith('/api/remote/') ? url.pathname + url.search : null;
    } catch (_) { return null; }
  }

  function remoteStage(label, ok, skipped, description) {
    const item = element('li', `remote-stage ${ok ? 'stage-ok' : skipped ? 'stage-skipped' : 'stage-failed'}`);
    const symbol = element('span', 'remote-stage-symbol', ok ? '✓' : skipped ? '–' : '!');
    symbol.setAttribute('aria-hidden', 'true');
    const text = element('div');
    text.append(element('strong', '', label), element('span', 'remote-stage-state', ok ? msg('m_4ceee80a9958') : skipped ? msg('m_ada1a615e72f') : msg('m_55f744d9e86e')), element('p', '', description));
    item.append(symbol, text);
    return item;
  }

  function renderRemoteResult(result) {
    if (!byId('remote-result')) return;
    byId('remote-result').hidden = false;
    const connectedTLS = !!result.tls_ok;
    const verified = connectedTLS && !!result.verified && !!result.chain_trusted && !!result.hostname_valid && !!result.time_valid;
    result.verified = verified;
    result.download_url = safeRemoteDownload(result.download_url);
    byId('remote-result-title').textContent = connectedTLS ? msg('m_45becae9c687') : msg('m_e6dd1fb773ef');
    const host = string(result.host, string(result.target));
    const endpointHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    byId('remote-result-endpoint').textContent = `${endpointHost}:${string(result.port, '443')}${result.address ? ` · ${result.address}` : ''} · ${date(result.checked_at, true)}${result.tls_version ? ` · ${result.tls_version}` : ''}`;
    const verdict = byId('remote-result-verdict');
    verdict.textContent = connectedTLS ? verified ? msg('m_6e003abb3586') : msg('m_e85bf2050a71') : msg('m_f33e5946809a');
    verdict.classList.toggle('remote-verdict-ok', verified);
    verdict.classList.toggle('remote-verdict-error', !verified);
    byId('remote-stages').replaceChildren(
      remoteStage(msg('m_d25ca4e0249e'), !!result.dns_ok, false, result.dns_ok ? msg('m_bd58b9d4836b', [string(result.address)]) : msg('m_5efed86deb64')),
      remoteStage(msg('m_f0b8c621dea2'), !!result.tcp_ok, !result.dns_ok, result.tcp_ok ? msg('m_8ca13161cac7', [string(result.port, '443')]) : result.dns_ok ? msg('m_06a167b4cde6') : msg('m_c46cb6566187')),
      remoteStage(msg('m_633bf7591b51'), connectedTLS, !result.tcp_ok, connectedTLS ? msg('m_8dd5eefd66a4') : result.tcp_ok ? msg('m_304006fd9be6') : msg('m_114bdefdd2c7')));
    byId('remote-verification').hidden = !connectedTLS;
    const checks = document.createDocumentFragment();
    for (const [label, ok, detail] of [
      [msg('m_163d294ea28b'), !!result.chain_trusted, result.chain_trusted ? msg('m_92e04038b031') : msg('m_f995bef398ce')],
      [msg('m_53cdb5d32c8d'), !!result.hostname_valid, result.hostname_valid ? msg('m_fa067fae8143') : msg('m_d6307c04bc39')],
      [msg('m_263486a44e79'), !!result.time_valid, result.time_valid ? msg('m_81c0c40f8eca') : msg('m_24fe7fad8207')]
    ]) {
      const item = element('li', ok ? 'remote-check-ok' : 'remote-check-failed');
      item.append(element('strong', '', `${ok ? '✓' : '!'} ${label}`), element('span', '', detail));
      checks.append(item);
    }
    byId('remote-verification-list').replaceChildren(checks);
    const errorText = string(result.verification_error, string(result.error, ''));
    byId('remote-verification-error').textContent = errorText;
    byId('remote-verification-error').hidden = !errorText;
    // Network failures still belong to the probe result, not to app connectivity.
    remoteFeedback(connectedTLS ? verified ? msg('m_e198418f8a89') : msg('m_4ebb821498a4') : errorText || msg('m_3c1c4da90ddc'), !verified);
    const comparison = byId('remote-comparison-result');
    comparison.hidden = !result.expected_certificate_id;
    comparison.classList.toggle('remote-comparison-changed', result.comparison === 'changed');
    comparison.textContent = result.comparison === 'same' ? msg('m_cc108023d0f1') : result.comparison === 'changed' ? msg('m_87d06aee7d3f') : msg('m_92dce54d8265');
    byId('remote-certificate').hidden = !connectedTLS || !result.certificate;
    if (connectedTLS && result.certificate) {
      const cert = result.certificate;
      const data = byId('remote-certificate-data');
      data.replaceChildren();
      addDetail(data, msg('m_c52778252d3b'), cert.common_name);
      addDetail(data, msg('m_2ab68816f88b'), cert.issuer);
      addDetail(data, msg('m_8693b331d694'), date(cert.not_before, true));
      addDetail(data, msg('m_9f1341d2d44b'), date(cert.not_after, true));
      addDetail(data, msg('m_ffe7dccec599'), cert.sans, true);
      addDetail(data, msg('m_4cdd497e69c7'), cert.fingerprint, true, true);
      const chain = document.createDocumentFragment();
      for (const [index, presented] of (result.presented_chain || []).entries()) {
        const item = element('li', 'remote-chain-item');
        item.append(element('span', 'remote-chain-number', String(index + 1)));
        const content = element('div');
        content.append(element('strong', '', name(presented)), element('span', 'remote-chain-type', presented.is_ca ? msg('m_d6df4e5f7b36') : msg('m_5c2dcb28341e')), element('p', '', msg('m_0fc1627c503c', [string(presented.issuer)])), element('p', '', msg('m_7f1fbe0b9fcd', [date(presented.not_before), date(presented.not_after)])), element('code', '', string(presented.fingerprint)));
        item.append(content);
        chain.append(item);
      }
      byId('remote-chain').replaceChildren(chain);
      if (result.download_url) byId('remote-download').href = result.download_url;
      byId('remote-import-note').textContent = verified ? msg('m_de6c0ff72481') : msg('m_d2daec53cb3f');
      byId('remote-import-note').classList.toggle('remote-import-warning', !verified);
    }
    updateRemoteButtons();
  }

  async function checkRemote(event) {
    event.preventDefault();
    if (remoteChecking || remoteImporting) return;
    if (!connected) { remoteFeedback(msg('m_2aa89124d301'), true); return; }
    const target = byId('remote-target').value.trim();
    if (!target) { byId('remote-target').reportValidity(); return; }
    clearRemoteResult();
    if (target.includes('*')) { remoteFeedback(msg('m_66747cd01ccd'), true); byId('remote-target').focus(); return; }
    remoteChecking = true;
    updateButtons();
    remoteFeedback(msg('m_38383cba0fb3'));
    const body = new URLSearchParams({ target });
    if (remoteExpectedId !== null) body.append('certificate_id', String(remoteExpectedId));
    try {
      const result = await request('/api/remote/check', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }, true);
      remoteResult = result;
      remoteFeedback('');
      renderRemoteResult(result);
      if (result.token) {
        const remaining = Math.max(0, Math.min(600000, Number(result.checked_at) * 1000 + 600000 - Date.now()));
        remoteExpiryTimer = setTimeout(() => {
          remoteSnapshotExpired = true;
          updateRemoteButtons();
          remoteFeedback(msg('m_b0a63966bfd8'));
        }, Number.isFinite(remaining) ? remaining : 600000);
      }
    } catch (error) { remoteFeedback(error.message, true); }
    finally { remoteChecking = false; updateButtons(); }
  }

  async function importRemote() {
    if (!remoteResult || !remoteResult.token || remoteChecking || remoteImporting || remoteSnapshotExpired) return;
    remoteImporting = true;
    updateButtons();
    remoteFeedback(msg('m_274f68d887e0'));
    try {
      const body = new URLSearchParams({ token: remoteResult.token });
      const result = await request('/api/remote/import', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
      await refresh(true);
      const imported = Number(result.imported) || 0;
      const duplicates = Number(result.duplicates) || 0;
      const monitoringText = result.monitoring_error ? msg('m_ec98a20cd2ce', [result.monitoring_error]) : result.monitoring_added ? msg('m_3d0e34425fd1') : result.monitor_id ? msg('m_5a3b49b55eff') : '';
      const text = msg('m_3ad59c9b7ae5', [imported, imported === 1 ? msg('m_c00b4773d246') : msg('m_fd3fd468ab84'), duplicates ? msg('m_98927fd9a8c0', [duplicates]) : '', monitoringText, remoteResult.verified ? '' : msg('m_cc989104ae06')]);
      remoteFeedback(text, !!result.monitoring_error);
      message(text, !!result.monitoring_error);
    } catch (error) {
      if (error.status === 400 || error.status === 404) {
        remoteSnapshotExpired = true;
        remoteFeedback(msg('m_2b07eedd8e19', [error.message]), true);
      } else remoteFeedback(error.message, true);
    } finally { remoteImporting = false; updateButtons(); }
  }

  function verifyDetailsOnline() {
    if (!detailsCertificate || remoteChecking || remoteImporting) return;
    if (contactsDirty) {
      detailFeedback(msg('m_878b9f7f6794'), true);
      byId('save-contacts').focus({ preventScroll: true });
      return;
    }
    const destination = `/verifica?certificate_id=${encodeURIComponent(detailsCertificate.id)}`;
    skipDetailsFocusRestore = true;
    byId('details-dialog').close();
    window.location.assign(i18n.localURL(destination));
  }

  const monitorStatusLabels = { pending: msg('m_a540633b2ac8'), ok: msg('m_c51df5e3c085'), unreachable: msg('m_bdcb15a81070'), tls_error: msg('m_99d6cdbad9d1'), changed: msg('m_5bca2a9e048d'), verification_error: msg('m_7e32b29440c5'), error: msg('m_002475934054') };
  const monitorEventLabels = { unreachable: msg('m_cf97269425c9'), tls_error: msg('m_c3e0a05b3c05'), changed: msg('m_0e05d3821ed7'), verification_error: msg('m_31461aebcccf'), error: msg('m_002475934054'), recovered: msg('m_128e7be91423') };

  function monitorFeedback(text, error = false) {
    if (!byId('monitor-feedback')) return;
    const node = byId('monitor-feedback');
    node.textContent = text;
    node.hidden = !text;
    node.classList.toggle('message-error', error);
  }

  function eligibleMonitorCertificates() {
    return state.certificates.filter(cert => !cert.is_ca && !cert.archived);
  }

  function renderMonitorSelect() {
    if (!byId('monitor-certificate')) return;
    const certificates = eligibleMonitorCertificates();
    const signature = JSON.stringify(certificates.map(cert => [cert.id, name(cert)]));
    if (signature === monitorSelectSignature) return;
    monitorSelectSignature = signature;
    const select = byId('monitor-certificate');
    const previous = select.value;
    const options = document.createDocumentFragment();
    const placeholder = element('option', '', certificates.length ? msg('m_bd03450c9f22') : msg('m_96ece1dee80b'));
    placeholder.value = '';
    options.append(placeholder);
    for (const cert of certificates) {
      const option = element('option', '', `${name(cert)} · ID ${cert.id}`);
      option.value = String(cert.id);
      options.append(option);
    }
    select.replaceChildren(options);
    if (certificates.some(cert => String(cert.id) === previous)) select.value = previous;
    byId('monitor-no-certificates').hidden = certificates.length > 0;
  }

  function updateMonitorButtons() {
    for (const id of ['monitor-delete-close', 'monitor-delete-cancel', 'monitor-delete-confirm']) byId(id).disabled = monitorDeleting;
    if (!byId('monitor-form')) return;
    const unavailable = !connected || monitorMutating;
    const archivedEdit = monitorEditingId !== null && (state.monitors || []).some(monitor => String(monitor.id) === String(monitorEditingId) && !!monitor.archived);
    for (const field of byId('monitor-form').querySelectorAll('input, select, button')) field.disabled = unavailable;
    if (archivedEdit) for (const field of byId('monitor-form').querySelectorAll('input, select')) field.disabled = true;
    byId('monitor-save').disabled = unavailable || archivedEdit || !eligibleMonitorCertificates().length;
    byId('monitor-save').textContent = monitorMutating ? msg('m_08a43825230b') : monitorEditingId ? msg('m_55b0f70b6858') : msg('m_fba0566e3d77');
    for (const button of byId('monitor-list').querySelectorAll('button')) button.disabled = unavailable || (button.dataset.requiresEnabled === 'true' && button.dataset.monitorEnabled !== 'true') || (button.dataset.requiresCurrent === 'true' && button.dataset.monitorArchived === 'true');
    for (const button of byId('monitor-event-list').querySelectorAll('button')) button.disabled = unavailable;
    const enabled = (state.monitors || []).filter(monitor => !!monitor.enabled);
    const now = Number(state.now) || Date.now() / 1000;
    const checking = !!state.monitoring.checking || enabled.some(monitor => Number(monitor.claim_until) > now);
    byId('monitor-worker-label').textContent = !connected ? msg('m_6b071398e6da') : checking ? msg('m_f5af527ecd72') : enabled.length ? msg('m_f6172a0bc42a') : msg('m_ef720d947641');
  }

  function monitorBody(monitor, enabled = !!monitor.enabled) {
    return new URLSearchParams({ certificate_id: String(monitor.certificate_id), target: monitor.target, interval_minutes: String(Math.max(1, Math.round(Number(monitor.interval_seconds) / 60))), enabled: enabled ? '1' : '0', email_alerts: monitor.email_alerts ? '1' : '0', email_recipients: (monitor.email_recipients || []).map(contact => contact.email).join(';') });
  }

  function resetMonitorForm() {
    if (!byId('monitor-form')) return;
    monitorEditingId = null;
    monitorDraftDirty = false;
    byId('monitor-form').reset();
    byId('monitor-interval').value = '15';
    byId('monitor-enabled').checked = true;
    byId('monitor-form-title').textContent = msg('m_c672df2a7c52');
    byId('monitor-cancel-edit').hidden = true;
    updateMonitorButtons();
  }

  function editMonitor(monitor) {
    if (monitorMutating || monitor.archived) return;
    monitorEditingId = monitor.id;
    renderMonitorSelect();
    byId('monitor-certificate').value = String(monitor.certificate_id);
    byId('monitor-target').value = monitor.target;
    byId('monitor-interval').value = String(Math.max(1, Math.round(Number(monitor.interval_seconds) / 60)));
    byId('monitor-enabled').checked = !!monitor.enabled;
    byId('monitor-email-enabled').checked = !!monitor.email_alerts;
    byId('monitor-email-recipients').value = (monitor.email_recipients || []).map(contact => contact.email).join('; ');
    byId('monitor-form-title').textContent = msg('m_674048e64d83', [monitor.id]);
    byId('monitor-cancel-edit').hidden = false;
    monitorFeedback(msg('m_30fc379225a1'));
    updateMonitorButtons();
    navigateTo('#monitoring', { scroll: false });
    byId('monitor-form').scrollIntoView({ block: 'start' });
    byId('monitor-target').focus({ preventScroll: true });
  }

  async function saveMonitor(event) {
    event.preventDefault();
    if (monitorMutating || !connected) return;
    const target = byId('monitor-target').value.trim();
    if (target.includes('*')) {
      monitorFeedback(msg('m_1a2357037103'), true);
      byId('monitor-target').focus();
      return;
    }
    if (!byId('monitor-form').reportValidity()) return;
    const enabled = byId('monitor-enabled').checked;
    const body = new URLSearchParams({ certificate_id: byId('monitor-certificate').value, target, interval_minutes: byId('monitor-interval').value, enabled: enabled ? '1' : '0' });
    body.set('email_alerts', byId('monitor-email-enabled').checked ? '1' : '0');
    body.set('email_recipients', byId('monitor-email-recipients').value.trim());
    const editing = monitorEditingId;
    monitorMutating = true;
    updateButtons();
    try {
      await request(editing ? `/api/monitors/${encodeURIComponent(editing)}` : '/api/monitors', { method: editing ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
      await refresh(true);
      resetMonitorForm();
      monitorFeedback(enabled ? msg('m_afe9ff208581') : msg('m_4625ee05fb5b'));
    } catch (error) { monitorFeedback(error.message, true); }
    finally { monitorMutating = false; updateButtons(); }
  }

  async function changeMonitorState(monitor) {
    if (monitorMutating || monitor.archived) return;
    monitorMutating = true;
    updateButtons();
    try {
      await request(`/api/monitors/${encodeURIComponent(monitor.id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: monitorBody(monitor, !monitor.enabled) });
      await refresh(true);
      monitorFeedback(monitor.enabled ? msg('m_160ced8e6626') : msg('m_37e08512b2f0'));
    } catch (error) { monitorFeedback(error.message, true); }
    finally { monitorMutating = false; updateButtons(); }
  }

  async function checkMonitorNow(monitor) {
    if (monitorMutating || !monitor.enabled || monitor.archived) return;
    monitorMutating = true;
    updateButtons();
    try {
      await request(`/api/monitors/${encodeURIComponent(monitor.id)}/check`, { method: 'POST' });
      monitorFeedback(msg('m_c0ef9ebe6475'));
      await refresh(true);
      if (monitorRefreshTimer) clearTimeout(monitorRefreshTimer);
      monitorRefreshTimer = setTimeout(() => refresh(), 12000);
    } catch (error) { monitorFeedback(error.message, true); }
    finally { monitorMutating = false; updateButtons(); }
  }

  function showMonitorDelete(monitor) {
    if (monitorMutating) return;
    monitorDeleteTarget = monitor;
    byId('monitor-delete-target').textContent = monitor.target;
    byId('monitor-delete-error').hidden = true;
    byId('monitor-delete-dialog').showModal();
    byId('monitor-delete-dialog').scrollTop = 0;
    byId('monitor-delete-cancel').focus({ preventScroll: true });
  }

  function closeMonitorDelete() {
    if (monitorDeleting) return;
    byId('monitor-delete-dialog').close();
  }

  function focusMonitorHeading() {
    navigateTo('#monitoring', { scroll: false });
    byId('monitoring-title').tabIndex = -1;
    byId('monitoring-title').focus({ preventScroll: true });
  }

  async function confirmMonitorDelete() {
    if (!monitorDeleteTarget || monitorMutating) return;
    const monitor = monitorDeleteTarget;
    monitorMutating = monitorDeleting = true;
    updateButtons();
    try {
      await request(`/api/monitors/${encodeURIComponent(monitor.id)}`, { method: 'DELETE' });
      byId('monitor-delete-dialog').close();
      if (String(monitorEditingId) === String(monitor.id)) resetMonitorForm();
      expandedMonitorIds.delete(String(monitor.id));
      await refresh(true);
      monitorFeedback(msg('m_f92883d43500'));
      focusMonitorHeading();
    } catch (error) {
      byId('monitor-delete-error').textContent = error.message;
      byId('monitor-delete-error').hidden = false;
    } finally { monitorMutating = monitorDeleting = false; updateButtons(); }
  }

  async function acknowledgeMonitorEvent(event) {
    if (monitorMutating) return;
    monitorMutating = true;
    updateButtons();
    try {
      await request(`/api/monitor-events/${encodeURIComponent(event.id)}/ack`, { method: 'POST' });
      await refresh(true);
      monitorFeedback(msg('m_e4df67bf34e1'));
    } catch (error) { monitorFeedback(error.message, true); }
    finally { monitorMutating = false; updateButtons(); }
  }

  function monitoringDetailsButton(label, monitor, action) {
    const button = element('button', 'button button-secondary monitor-action', label);
    button.type = 'button';
    button.dataset.monitorId = String(monitor.id);
    button.addEventListener('click', action);
    return button;
  }

  function renderMonitoring() {
    if (!byId('monitor-list')) return;
    const monitors = state.monitors || [];
    const events = [...(state.monitor_events || [])].sort((a, b) => Number(b.created_at) - Number(a.created_at) || Number(b.id) - Number(a.id));
    const stats = state.monitoring || {};
    const now = Number(state.now) || Date.now() / 1000;
    const enabled = monitors.filter(monitor => !!monitor.enabled);
    const problems = enabled.filter(monitor => monitor.last_status !== 'ok' && monitor.last_status !== 'pending');
    const stat = (value, fallback) => Number.isFinite(Number(value)) && value !== null && value !== undefined ? Number(value) : fallback;
    byId('monitor-count').textContent = monitors.length;
    byId('monitor-enabled-count').textContent = stat(stats.enabled, enabled.length);
    byId('monitor-problem-count').textContent = stat(stats.problems, problems.length);
    byId('monitor-paused-count').textContent = monitors.length - enabled.length;
    byId('monitor-unread-count').textContent = stat(stats.unacknowledged, events.filter(event => !event.acknowledged_at).length);
    const isChecking = !!stats.checking || monitors.some(monitor => monitor.enabled && Number(monitor.claim_until) > now);
    byId('monitor-worker-label').textContent = isChecking ? msg('m_f5af527ecd72') : enabled.length ? msg('m_f6172a0bc42a') : msg('m_ef720d947641');
    byId('monitor-worker-status').classList.toggle('monitor-worker-busy', isChecking);
    renderMonitorSelect();
    const fragment = document.createDocumentFragment();
    for (const monitor of monitors) {
      const item = element('li', 'monitor-item');
      const heading = element('div', 'monitor-item-heading');
      const identity = element('div', 'monitor-identity');
      identity.append(element('strong', '', monitor.target), element('p', '', msg('m_49750c8f6c5d', [string(monitor.common_name, msg('m_7047cf9d6d49')), monitor.certificate_id])));
      const checking = !!monitor.enabled && Number(monitor.claim_until) > now;
      const queued = !!monitor.enabled && !checking && Number(monitor.next_check_at) <= now;
      const status = monitor.last_status === 'ok' && !monitor.verified ? 'verification_error' : Object.prototype.hasOwnProperty.call(monitorStatusLabels, monitor.last_status) ? monitor.last_status : 'error';
      const label = monitor.archived ? msg('m_f4b80a58e651') : !monitor.enabled ? msg('m_2f4e01b4c978') : checking ? msg('m_b94c47746e76') : queued ? msg('m_4d6cac7a9238') : monitorStatusLabels[status];
      const badgeClass = monitor.archived || !monitor.enabled ? 'paused' : checking || queued ? 'checking' : status;
      const statusBadge = element('span', `monitor-status monitor-status-${badgeClass}`, label);
      heading.append(identity, statusBadge);
      item.append(heading);
      if (monitor.archived) item.append(element('p', 'monitor-archived-help', msg('m_e6728f972e93')));
      if ((!monitor.enabled || checking || queued) && status !== 'pending') item.append(element('p', `monitor-last-outcome${status === 'ok' ? '' : ' monitor-last-problem'}`, msg('m_23814c37da0d', [monitorStatusLabels[status]])));
      const timing = element('div', 'monitor-timing');
      timing.append(element('span', '', msg('m_a03ac665f29e', [monitor.last_checked_at ? date(monitor.last_checked_at, true) : msg('m_df1fe7130cdc')])), element('span', '', msg('m_3623361fbb08', [monitor.enabled ? checking ? msg('m_1254376799b0') : queued ? msg('m_a3dfb7d0b518') : date(monitor.next_check_at, true) : msg('m_61395f43e51c')])), element('span', '', msg('m_1a616dea3233', [Math.round(Number(monitor.interval_seconds) / 60)])));
      item.append(timing);
      if (monitor.email_alerts) item.append(element('p', 'workflow-help', `${flow('monitor_email')}: ${(monitor.email_recipients || []).map(contact => contact.email).join('; ')}`));
      if (monitor.last_error) item.append(element('p', 'monitor-error', string(monitor.last_error)));
      const details = element('details', 'monitor-diagnostics');
      details.open = expandedMonitorIds.has(String(monitor.id));
      details.addEventListener('toggle', () => { if (details.open) expandedMonitorIds.add(String(monitor.id)); else expandedMonitorIds.delete(String(monitor.id)); });
      details.append(element('summary', '', msg('m_a0c12fe37e08')));
      const data = element('dl', 'details-data');
      addDetail(data, msg('m_b0ae9dd3e7a4'), monitor.expected_fingerprint, true, true);
      addDetail(data, msg('m_d66a2945e632'), monitor.last_fingerprint, true, true);
      addDetail(data, msg('m_a5c44bddfedc'), monitor.last_address);
      addDetail(data, msg('m_300fa7f8d13d'), !monitor.last_checked_at ? msg('m_7f2bcf68a458') : monitor.verified ? msg('m_bdeefebe600b') : msg('m_371087056f39'));
      addDetail(data, msg('m_f9fdf2d62c06'), !monitor.last_checked_at ? msg('m_b7deb75a3fe0') : `DNS: ${monitor.dns_ok ? msg('m_4ceee80a9958') : msg('m_89a7bf7a2b32')} · TCP: ${monitor.tcp_ok ? msg('m_4ceee80a9958') : msg('m_89a7bf7a2b32')} · TLS: ${monitor.tls_ok ? msg('m_4ceee80a9958') : msg('m_89a7bf7a2b32')}`, true);
      details.append(data);
      item.append(details);
      const actions = element('div', 'monitor-item-actions');
      const edit = monitoringDetailsButton(msg('m_49e493ba9d9c'), monitor, () => editMonitor(monitor));
      const toggle = monitoringDetailsButton(monitor.enabled ? msg('m_9bd4d1e04ad5') : msg('m_b0cc9c2660cb'), monitor, () => changeMonitorState(monitor));
      const check = monitoringDetailsButton(msg('m_2b497ac32e48'), monitor, () => checkMonitorNow(monitor));
      for (const button of [edit, toggle, check]) {
        button.dataset.requiresCurrent = 'true';
        button.dataset.monitorArchived = String(!!monitor.archived);
        if (monitor.archived) button.title = msg('m_22ca1c2d8419');
      }
      actions.append(edit, toggle);
      check.dataset.requiresEnabled = 'true';
      check.dataset.monitorEnabled = String(!!monitor.enabled);
      const remove = monitoringDetailsButton(msg('m_fd69f0d7f263'), monitor, () => showMonitorDelete(monitor));
      remove.dataset.rowAction = 'remove-monitor';
      actions.append(check, remove);
      item.append(actions);
      fragment.append(item);
    }
    byId('monitor-list').replaceChildren(fragment);
    byId('monitor-empty').hidden = monitors.length > 0;
    const eventFragment = document.createDocumentFragment();
    for (const event of events) {
      const read = !!event.acknowledged_at;
      const item = element('li', `monitor-event${event.kind === 'recovered' ? ' monitor-event-recovered' : ''}${read ? ' monitor-event-read' : ''}`);
      const content = element('div', 'monitor-event-content');
      const heading = element('div', 'monitor-event-heading');
      heading.append(element('strong', '', monitorEventLabels[event.kind] || msg('m_4fab62062a11')), element('span', 'monitor-event-read-label', read ? msg('m_2b966dbe0c4a') : msg('m_680610dd40d3')));
      content.append(heading, element('p', 'monitor-event-target', `${string(event.common_name, msg('m_4e6c44675d7d'))} · ${string(event.target)}`), element('p', 'monitor-event-message', string(event.message)), element('time', 'monitor-event-time', `${date(event.created_at, true)}${read ? msg('m_a24e48ae59e3', [date(event.acknowledged_at, true)]) : ''}`));
      if (event.kind === 'changed') {
        const fingerprints = element('dl', 'monitor-event-fingerprints');
        addDetail(fingerprints, msg('m_a7d9abd429aa'), event.expected_fingerprint, true, true);
        addDetail(fingerprints, msg('m_3d669c305fb7'), event.observed_fingerprint, true, true);
        content.append(fingerprints);
      }
      item.append(content);
      if (!read) {
        const acknowledge = element('button', 'button button-secondary monitor-ack', msg('m_9056a4fc556e'));
        acknowledge.type = 'button';
        acknowledge.addEventListener('click', () => acknowledgeMonitorEvent(event));
        item.append(acknowledge);
      }
      eventFragment.append(item);
    }
    byId('monitor-event-list').replaceChildren(eventFragment);
    byId('monitor-event-count').textContent = events.length;
    byId('monitor-events-empty').hidden = events.length > 0;
    updateMonitorButtons();
    if (monitorEditingId !== null && monitors.some(monitor => String(monitor.id) === String(monitorEditingId) && !!monitor.archived)) monitorFeedback(msg('m_5f50b0ac5a8c'), true);
  }

  function monitorDetailsService() {
    if (!detailsCertificate || monitorMutating || detailsCertificate.is_ca || detailsCertificate.archived) return;
    if (contactsDirty) {
      detailFeedback(msg('m_c26c321e7c12'), true);
      byId('save-contacts').focus({ preventScroll: true });
      return;
    }
    const destination = `/servizi?certificate_id=${encodeURIComponent(detailsCertificate.id)}#monitor-form`;
    skipDetailsFocusRestore = true;
    byId('details-dialog').close();
    window.location.assign(i18n.localURL(destination));
  }

  function renderSummary() {
    const certificates = state.certificates.filter(cert => !cert.archived);
    byId('nav-count').textContent = certificates.length;
    byId('nav-monitor-count').textContent = (state.monitors || []).filter(monitor => monitor.enabled && !monitor.archived).length;
    byId('nav-alert-count').textContent = state.notifications.length;
    byId('nav-delivery-count').textContent = (Number(state.delivery.pending) || 0) + (Number(state.delivery.failed) || 0);
    if (!byId('total-count')) return;
    byId('total-count').textContent = certificates.length;
    byId('expired-count').textContent = certificates.filter(cert => cert.status === 'expired').length;
    byId('soon-count').textContent = certificates.filter(cert => cert.status !== 'expired' && Number(cert.days_remaining) >= 0 && Number(cert.days_remaining) <= 15).length;
    byId('upcoming-count').textContent = certificates.filter(cert => Number(cert.days_remaining) > 15 && Number(cert.days_remaining) <= 45).length;
  }

  function renderOverview() {
    if (!byId('overview-status')) return;
    const now = Number(state.now) || Date.now() / 1000;
    const certificates = state.certificates.filter(cert => !cert.archived && !cert.is_ca);
    const due = certificates.filter(cert => Number(cert.not_after) <= now || (Number.isFinite(Number(cert.days_remaining)) && Number(cert.days_remaining) <= 45))
      .sort((a, b) => Number(a.not_after) - Number(b.not_after));
    const expiryFragment = document.createDocumentFragment();
    for (const cert of due.slice(0, 5)) {
      const item = element('li', 'overview-list-item');
      const content = element('div', 'overview-item-main');
      const open = element('button', 'overview-item-action', name(cert));
      open.type = 'button';
      open.dataset.certificateId = String(cert.id);
      open.dataset.rowAction = 'details';
      open.setAttribute('aria-label', msg('m_2c369df7a4f6', [name(cert)]));
      open.addEventListener('click', () => showDetails(cert));
      content.append(open, element('span', 'overview-item-meta', msg('m_8e0346e2c9a2', [date(cert.not_after), Number(cert.not_after) <= now ? msg('m_a29c9c023a67') : msg('m_c57af6e5979f', [Math.max(0, Number(cert.days_remaining))])])));
      const status = badge(cert.status);
      status.classList.add('overview-item-status');
      item.append(content, status);
      expiryFragment.append(item);
    }
    byId('overview-expiries').replaceChildren(expiryFragment);
    byId('overview-expiries-empty').hidden = due.length > 0;
    const monitors = (state.monitors || []).filter(monitor => monitor.enabled && !monitor.archived);
    const effectiveStatus = monitor => monitor.last_status === 'ok' && !monitor.verified ? 'verification_error' : Object.prototype.hasOwnProperty.call(monitorStatusLabels, monitor.last_status) ? monitor.last_status : 'error';
    const isProblem = monitor => !['ok', 'pending'].includes(effectiveStatus(monitor));
    const services = [...monitors].sort((a, b) => Number(isProblem(b)) - Number(isProblem(a)) || String(a.target).localeCompare(String(b.target), i18n.locale));
    const serviceFragment = document.createDocumentFragment();
    for (const monitor of services.slice(0, 5)) {
      const item = element('li', 'overview-list-item');
      const content = element('div', 'overview-item-main');
      const link = element('a', 'overview-item-action', string(monitor.target));
      link.href = '/servizi';
      content.append(link, element('span', 'overview-item-meta', `${string(monitor.common_name, msg('m_7047cf9d6d49'))} · ${monitor.last_checked_at ? msg('m_8888d37c9203', [date(monitor.last_checked_at, true)]) : msg('m_d40ad9a2d252')}`));
      const status = effectiveStatus(monitor);
      const checking = Number(monitor.claim_until) > now;
      const statusBadge = element('span', `overview-item-status monitor-status monitor-status-${checking ? 'checking' : status}`, checking ? msg('m_b94c47746e76') : monitorStatusLabels[status]);
      item.append(content, statusBadge);
      serviceFragment.append(item);
    }
    byId('overview-services').replaceChildren(serviceFragment);
    byId('overview-services-empty').hidden = monitors.length > 0;
    const expired = certificates.filter(cert => Number(cert.not_after) <= now).length;
    const problems = monitors.filter(isProblem).length;
    const unreadCount = Number(state.monitoring.unacknowledged);
    const unread = Number.isFinite(unreadCount) ? unreadCount : (state.monitor_events || []).filter(event => !event.acknowledged_at).length;
    const pending = monitors.filter(monitor => effectiveStatus(monitor) === 'pending').length;
    const status = byId('overview-status');
    const attention = expired > 0 || problems > 0 || unread > 0;
    status.classList.toggle('overview-status-attention', attention);
    status.classList.toggle('overview-status-empty', !certificates.length && !monitors.length);
    byId('overview-status-title').textContent = attention ? msg('m_c2d47d0182db') : pending ? msg('m_53b86c2dc768') : certificates.length || monitors.length ? msg('m_5cd02e28cab3') : msg('m_d92a975c8a0f');
    const notices = [];
    if (expired) notices.push(`${expired} ${expired === 1 ? msg('m_908dbc1eebf0') : msg('m_316f9b9ae578')}`);
    if (problems) notices.push(`${problems} ${problems === 1 ? msg('m_de6c10c14cad') : msg('m_59549e86b07b')}`);
    if (unread) notices.push(`${unread} ${unread === 1 ? msg('m_2a63f628475c') : msg('m_a974ba86c134')}`);
    byId('overview-status-text').textContent = attention ? `${notices.join(' · ')}.` : pending ? msg('m_36a032af164b', [pending, pending === 1 ? msg('m_2004b3d3055c') : msg('m_c9b93f8debe9')]) : certificates.length || monitors.length ? due.length ? msg('m_724732e8656c') : msg('m_c4c6c1efb3cd') : msg('m_8392375ef36d');
  }

  function isoDate(value) {
    const parsed = new Date(Number(value) * 1000);
    return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString().slice(0, 10);
  }

  function matchesStatus(cert, filter) {
    const now = Number(state.now) || Date.now() / 1000;
    if (filter === 'valid') return Number(cert.not_before) <= now && now < Number(cert.not_after);
    if (filter === 'expired') return Number(cert.not_after) <= now;
    if (filter === 'future') return Number(cert.not_before) > now && Number(cert.not_after) > now;
    return true;
  }

  function registryCell(label, className, value) {
    const cell = element('td', className);
    cell.setAttribute('role', 'cell');
    cell.dataset.label = label;
    const mobileLabel = element('span', 'registry-cell-label', label);
    mobileLabel.setAttribute('aria-hidden', 'true');
    cell.append(mobileLabel);
    if (value !== undefined) cell.append(element('span', 'registry-cell-value', value));
    return cell;
  }

  function caCell(label, value, missing, className) {
    const cell = registryCell(label, `issuer-cell ca-cell ${className}`, string(value, missing));
    cell.title = string(value, missing);
    if (!value) cell.classList.add('missing-data');
    return cell;
  }

  function registryContactsCell(cert, role) {
    const technical = role === 'technical';
    const label = technical ? msg('m_a6da5b872c69') : msg('m_3ce1f3185cbc');
    const cell = registryCell(label, `registry-contacts-cell registry-${role}-cell`);
    const contacts = (cert.contacts || []).filter(contact => contact.role === role);
    if (contacts.length) {
      const list = element('ul', 'registry-contact-list');
      for (const contact of contacts) {
        const item = element('li');
        if (contact.name) item.append(element('strong', 'registry-contact-name', string(contact.name)));
        item.append(element('span', 'registry-contact-email', string(contact.email)));
        list.append(item);
      }
      cell.append(list);
    } else cell.append(element('span', 'registry-contact-empty', technical ? msg('m_b885364181d5') : msg('m_2ab58de94fb7')));
    const manage = element('button', 'text-button registry-manage-contacts', msg('m_0913a0dafe5b'));
    manage.type = 'button';
    manage.dataset.certificateId = String(cert.id);
    manage.dataset.rowAction = `contacts-${role}`;
    manage.setAttribute('aria-label', msg('m_b86878bae76e', [label.toLocaleLowerCase(i18n.locale), name(cert)]));
    manage.addEventListener('click', () => {
      showDetails(cert);
      const heading = byId('contacts-title');
      heading.scrollIntoView({ block: 'start' });
      byId(technical ? 'add-technical-contact' : 'add-business-contact').focus({ preventScroll: true });
    });
    cell.append(manage);
    return cell;
  }

  function contactEmail(value) {
    return string(value, '').trim().toLowerCase();
  }

  function renderRegistryContactFilters() {
    for (const role of ['business', 'technical']) {
      const select = byId(`${role}-contact-filter`);
      if (!select) continue;
      const people = new Map();
      for (const cert of state.certificates) {
        for (const contact of cert.contacts || []) {
          if (contact.role !== role) continue;
          const email = contactEmail(contact.email);
          if (!email) continue;
          const displayName = string(contact.name, '').trim();
          const previous = people.get(email);
          if (previous === undefined || (displayName && (!previous || displayName.localeCompare(previous, i18n.locale) < 0))) people.set(email, displayName);
        }
      }
      const options = [...people].map(([email, displayName]) => [email, displayName ? `${displayName} — ${email}` : email]);
      options.sort((a, b) => a[1].localeCompare(b[1], i18n.locale) || a[0].localeCompare(b[0]));
      const selected = registryContactSelection[role];
      // Keep an obsolete selection explicit: a contact removal must not broaden results.
      if (selected && !people.has(selected)) options.push([selected, msg('m_ed0033837b1a', [selected])]);
      const signature = JSON.stringify(options);
      if (signature !== registryContactSignatures[role]) {
        const fragment = document.createDocumentFragment();
        const all = element('option', '', role === 'technical' ? msg('m_691c0065ccdb') : msg('m_06501f271e8c'));
        all.value = '';
        fragment.append(all);
        for (const [email, label] of options) {
          const option = element('option', '', label);
          option.value = email;
          fragment.append(option);
        }
        select.replaceChildren(fragment);
        registryContactSignatures[role] = signature;
      }
      if (select.value !== selected) select.value = selected;
    }
  }

  function matchesRegistryContact(cert, role) {
    const selected = registryContactSelection[role];
    return !selected || (cert.contacts || []).some(contact => contact.role === role && contactEmail(contact.email) === selected);
  }

  function registryCAValues(cert, field) {
    const raw = string(cert[field], '');
    const names = (field === 'intermediate_ca' ? raw.split('\n') : [raw]).map(value => value.trim()).filter(Boolean);
    if (names.length) return names.map(value => `dn:${value}`);
    return [field === 'intermediate_ca' && cert.chain_status === 'complete' ? 'none' : 'missing'];
  }

  function registryCALabel(value) {
    return value === 'none' ? msg('m_c1066229d9de') : value === 'missing' ? msg('m_ce1391381fc8') : value.slice(3);
  }

  function renderRegistryCAFilters() {
    for (const { field, id, all } of registryCAFilters) {
      const select = byId(id);
      if (!select) continue;
      const available = new Set(state.certificates.flatMap(cert => registryCAValues(cert, field)));
      const options = [...available].map(value => [value, registryCALabel(value)]);
      options.sort((a, b) => a[1].localeCompare(b[1], i18n.locale) || a[0].localeCompare(b[0]));
      const selected = registryCASelection[field];
      if (selected && !available.has(selected)) options.push([selected, msg('m_70aa9511e469', [registryCALabel(selected)])]);
      const signature = JSON.stringify(options);
      if (signature !== registryCASignatures[field]) {
        const fragment = document.createDocumentFragment();
        const any = element('option', '', all);
        any.value = '';
        fragment.append(any);
        for (const [value, label] of options) {
          const option = element('option', '', label);
          option.value = value;
          fragment.append(option);
        }
        select.replaceChildren(fragment);
        registryCASignatures[field] = signature;
      }
      if (select.value !== selected) select.value = selected;
      select.title = select.selectedOptions[0] ? select.selectedOptions[0].textContent : all;
    }
  }

  function matchesRegistryCA(cert, field) {
    const selected = registryCASelection[field];
    return !selected || registryCAValues(cert, field).includes(selected);
  }

  function matchesExpiry(cert, filter) {
    if (filter === 'all') return true;
    const days = Number(filter);
    const now = Number(state.now) || Date.now() / 1000;
    const start = Number(cert.not_before);
    const expiry = Number(cert.not_after);
    return [45, 30, 15, 2].includes(days) && Number.isFinite(start) && Number.isFinite(expiry) && start <= now && now < expiry && expiry <= now + days * 86400;
  }

  function renderTable() {
    if (!byId('certificate-table')) return;
    renderRegistryContactFilters();
    renderRegistryCAFilters();
    const search = byId('search').value.trim().toLocaleLowerCase(i18n.locale);
    const statusFilter = byId('status-filter').value;
    const expiryFilter = byId('expiry-filter').value;
    const hasExpiryFilter = expiryFilter !== 'all';
    byId('expiry-filter-help').hidden = !hasExpiryFilter;
    const includeArchived = byId('include-archived').checked;
    const hasContactFilter = registryContactSelection.business || registryContactSelection.technical;
    const hasCAFilter = registryCASelection.root_ca || registryCASelection.intermediate_ca;
    byId('reset-registry-filters').disabled = !search && statusFilter === 'all' && !includeArchived && !hasContactFilter && !hasCAFilter && !hasExpiryFilter;
    const filtered = state.certificates.filter(cert => (includeArchived || !cert.archived) && matchesStatus(cert, statusFilter) && matchesExpiry(cert, expiryFilter) && matchesRegistryContact(cert, 'business') && matchesRegistryContact(cert, 'technical') && matchesRegistryCA(cert, 'root_ca') && matchesRegistryCA(cert, 'intermediate_ca') && [cert.common_name, cert.subject, cert.issuer, cert.root_ca, cert.intermediate_ca, cert.sans, cert.source, cert.serial, cert.fingerprint, date(cert.not_before), date(cert.not_after), isoDate(cert.not_before), isoDate(cert.not_after), ...(cert.contacts || []).flatMap(contact => [contact.name, contact.email])].some(value => string(value, '').toLocaleLowerCase(i18n.locale).includes(search)))
      .sort((a, b) => Number(a.not_after) - Number(b.not_after));
    const fragment = document.createDocumentFragment();
    for (const cert of filtered) {
      const row = element('tr');
      row.setAttribute('role', 'row');
      const domain = registryCell(msg('m_9e8c181b3d68'), 'domain-cell');
      const open = element('button', 'domain-button', name(cert));
      open.type = 'button';
      open.dataset.certificateId = String(cert.id);
      open.dataset.rowAction = 'details';
      open.setAttribute('aria-label', msg('m_2c369df7a4f6', [name(cert)]));
      open.addEventListener('click', () => showDetails(cert));
      domain.append(open, element('span', 'domain-subtitle', string(cert.source, msg('m_c418dd99aaed'))));
      if (cert.archived) domain.append(element('span', 'archived-label', msg('m_dbcc8ebd6118')));
      const rootCA = caCell(msg('m_e4946c348010'), cert.root_ca, msg('m_ce1391381fc8'), 'registry-root-cell');
      const intermediateCA = caCell(msg('m_413f30694c1b'), cert.intermediate_ca, cert.chain_status === 'complete' ? msg('m_a622e67e36e3') : msg('m_ce1391381fc8'), 'registry-intermediate-cell');
      const days = Number(cert.days_remaining);
      const daysCell = registryCell(msg('m_700358f9a24b'), `days-cell registry-days-cell${cert.status === 'expired' || cert.status === 'urgent' ? ' is-danger' : ''}`);
      daysCell.append(element('span', '', Number.isFinite(days) ? String(days) : '—'), element('span', 'days-suffix', msg('m_cbd3cfb9b9f5')));
      const status = registryCell(msg('m_5d788017bfe4'), 'registry-status-cell');
      status.append(badge(cert.status), element('span', 'operational-badge', operationalLabel(cert)));
      const actions = registryCell(msg('m_1c3e6183f58f'), 'row-actions');
      const details = element('button', 'button button-secondary registry-open-details', msg('m_7f1893e1b4be'));
      details.type = 'button';
      details.setAttribute('aria-label', msg('m_2c369df7a4f6', [name(cert)]));
      details.addEventListener('click', () => showDetails(cert));
      const remove = element('button', 'icon-button');
      remove.type = 'button';
      remove.dataset.certificateId = String(cert.id);
      remove.dataset.rowAction = 'delete';
      remove.setAttribute('aria-label', msg('m_363f4259d091', [name(cert)]));
      remove.title = msg('m_a7bbbcc3962b');
      remove.append(trashIcon());
      remove.addEventListener('click', () => showDelete(cert));
      actions.append(details, remove);
      const expiry = registryCell(msg('m_51bf843f1751'), `date-cell registry-expiry-cell${cert.status === 'expired' || cert.status === 'urgent' ? ' is-danger' : ''}`, date(cert.not_after));
      const issued = registryCell(msg('m_ceae689d29f2'), 'date-cell registry-issued-cell', date(cert.not_before));
      row.append(domain, expiry, registryContactsCell(cert, 'business'), registryContactsCell(cert, 'technical'), status, rootCA, intermediateCA, issued, daysCell, actions);
      fragment.append(row);
    }
    byId('certificate-table').replaceChildren(fragment);
    byId('table-empty').hidden = filtered.length > 0;
    byId('table-count').textContent = filtered.length;
    if (loaded) {
      const filtering = search || statusFilter !== 'all' || hasContactFilter || hasCAFilter || hasExpiryFilter || state.certificates.length;
      byId('empty-title').textContent = filtering ? msg('m_2d0f9f550d1f') : msg('m_48a14edf4df4');
      byId('empty-description').textContent = filtering ? msg('m_81f1f65aaa04') : msg('m_9b90a01aaecc');
    }
    byId('table-footer-text').textContent = msg('m_70435314d0c7', [filtered.length, state.certificates.length]);
  }

  function trashIcon() {
    const namespace = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(namespace, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(namespace, 'path');
    path.setAttribute('d', 'M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14M10 11v6M14 11v6');
    svg.append(path);
    return svg;
  }

  function noticeText(notice) {
    const threshold = Number(notice.threshold);
    return threshold === 0 ? msg('m_2f3b9ccb6317') : msg('m_e004e892e464', [threshold]);
  }

  function renderNotifications() {
    if (!byId('notification-list')) return;
    const notifications = [...state.notifications].sort((a, b) => Number(b.sent_at) - Number(a.sent_at) || Number(b.id) - Number(a.id));
    byId('notification-count').textContent = notifications.length;
    const fragment = document.createDocumentFragment();
    for (const notice of notifications) {
      const item = element('li', 'notification-item');
      const symbol = element('span', `notice-symbol${Number(notice.threshold) === 0 ? ' expired' : ''}`, Number(notice.threshold) === 0 ? '!' : '↗');
      symbol.setAttribute('aria-hidden', 'true');
      const content = element('div', 'notification-content');
      content.append(element('strong', '', string(notice.common_name, msg('m_7047cf9d6d49'))),
        element('p', '', msg('m_ee05127783bd', [noticeText(notice), date(notice.not_after)])),
        element('time', 'notification-time', msg('m_c2f79e4b1248', [date(notice.sent_at, true)])));
      const time = content.querySelector('time');
      const parsed = new Date(Number(notice.sent_at) * 1000);
      if (!Number.isNaN(parsed.getTime())) time.dateTime = parsed.toISOString();
      item.append(symbol, content);
      fragment.append(item);
    }
    byId('notification-list').replaceChildren(fragment);
    byId('notifications-empty').hidden = notifications.length > 0;
  }

  function smtpFeedback(text, error = false) {
    const box = byId('smtp-feedback');
    if (!box) return;
    box.textContent = text;
    box.classList.toggle('message-error', error);
    box.hidden = !text;
  }

  function updateSmtpButtons() {
    const form = byId('smtp-form');
    if (!form) return;
    const busy = !!smtpBusy;
    for (const control of form.querySelectorAll('input, select')) control.disabled = busy;
    byId('smtp-save').disabled = !connected || busy;
    byId('smtp-test').disabled = !connected || busy;
    byId('smtp-reset').disabled = busy;
    byId('smtp-save').textContent = smtpBusy === 'save' ? msg('m_c4f57f0165aa') : msg('m_ffbecd2fe9c0');
    byId('smtp-test').textContent = smtpBusy === 'test' ? msg('m_12c3542bd127') : msg('m_8c58348f2ad8');
    form.setAttribute('aria-busy', String(busy));
    byId('smtp-clear-password').disabled = busy || !!byId('smtp-password').value;
    byId('smtp-unsaved').hidden = !smtpDirty;
    byId('smtp-reset').hidden = !smtpDirty;
  }

  function populateSmtpForm() {
    const smtp = state.smtp || {};
    byId('smtp-host').value = string(smtp.host, '');
    byId('smtp-port').value = Number(smtp.port) || 587;
    byId('smtp-security').value = smtp.security === 'tls' ? 'tls' : 'starttls';
    byId('smtp-from').value = string(smtp.from_email, '');
    byId('smtp-username').value = string(smtp.username, '');
    byId('smtp-password').value = '';
    byId('smtp-password').placeholder = smtp.password_set ? msg('m_f0bb0cb00dc6') : msg('m_8c6ff713120a');
    byId('smtp-enabled').checked = !!smtp.enabled;
    byId('smtp-clear-password').checked = false;
    for (const input of byId('smtp-form').querySelectorAll('input')) input.setCustomValidity('');
    smtpDirty = false;
    smtpInitialized = true;
  }

  function renderSmtp() {
    if (!byId('smtp-form')) return;
    const smtp = state.smtp || {};
    const status = byId('smtp-config-status');
    status.textContent = smtp.configured ? msg('m_cd9a1288d744') : smtp.enabled && smtp.error ? msg('m_e05828eae3d5') : smtp.exists || smtp.source === 'environment' ? msg('m_a1a6665f085f') : msg('m_9c412ce26d63');
    status.classList.toggle('smtp-config-active', !!smtp.configured);
    status.classList.toggle('smtp-config-error', !!smtp.enabled && !!smtp.error);
    const source = smtp.source === 'database'
      ? msg('m_b0b778773199')
      : smtp.source === 'environment'
        ? msg('m_f4d37b830af9')
        : msg('m_2f3c772b6431');
    byId('smtp-config-source').textContent = `${source}${smtp.source === 'database' && smtp.updated_at ? msg('m_1bf3c5666697', [date(smtp.updated_at, true)]) : ''}`;
    byId('smtp-password-status').textContent = smtp.password_set ? msg('m_485a115c7008') : msg('m_67b4360610c8');
    byId('smtp-clear-password-label').hidden = !smtp.password_set;
    if (!smtpInitialized) {
      populateSmtpForm();
      byId('smtp-settings').open = !smtp.configured;
    } else if (!smtpDirty && !smtpBusy) populateSmtpForm();
    updateSmtpButtons();
  }

  function smtpFormChanged(event) {
    if (event.target instanceof HTMLInputElement) event.target.setCustomValidity('');
    if (byId('smtp-password').value) byId('smtp-clear-password').checked = false;
    smtpDirty = true;
    smtpFeedback('');
    updateSmtpButtons();
  }

  function smtpFormData(forTest) {
    const enabled = byId('smtp-enabled').checked;
    const requiresComplete = forTest || enabled;
    const host = byId('smtp-host');
    const from = byId('smtp-from');
    const port = byId('smtp-port');
    host.setCustomValidity('');
    from.setCustomValidity('');
    port.setCustomValidity('');
    if (requiresComplete && !host.value.trim()) {
      host.setCustomValidity(msg('m_040c4faf93be'));
      host.reportValidity();
      return null;
    }
    if (requiresComplete && (!from.value.trim() || !from.validity.valid)) {
      from.setCustomValidity(msg('m_5c7fe784915c'));
      from.reportValidity();
      return null;
    }
    if (port.value && (!port.validity.valid || !Number.isInteger(Number(port.value)) || Number(port.value) < 1 || Number(port.value) > 65535)) {
      port.setCustomValidity(msg('m_4ff656f07cf3'));
      port.reportValidity();
      return null;
    }
    if (requiresComplete && !port.value) {
      port.setCustomValidity(msg('m_0794f1476d18'));
      port.reportValidity();
      return null;
    }
    const body = new URLSearchParams();
    body.set('enabled', enabled ? '1' : '0');
    body.set('host', host.value.trim());
    body.set('port', port.value || '587');
    body.set('security', byId('smtp-security').value);
    body.set('from_email', from.value.trim());
    body.set('username', byId('smtp-username').value.trim());
    body.set('password', byId('smtp-password').value);
    body.set('clear_password', byId('smtp-clear-password').checked ? '1' : '0');
    return body;
  }

  async function saveSmtp(event) {
    event.preventDefault();
    if (!connected || smtpBusy) return;
    const body = smtpFormData(false);
    if (!body) return;
    smtpBusy = 'save';
    smtpFeedback('');
    updateSmtpButtons();
    try {
      const result = await request('/api/smtp/settings', { method: 'PUT', body });
      byId('smtp-password').value = '';
      byId('smtp-clear-password').checked = false;
      smtpDirty = false;
      // The server never returns the saved password. Refresh only public settings.
      const updated = await refresh(true);
      smtpFeedback(string(result.message, msg('m_882373ddd490')) + (updated ? '' : msg('m_24c485bb59c6')));
    } catch (error) { smtpFeedback(error.message, true); }
    finally { smtpBusy = ''; if (!smtpDirty && connected) populateSmtpForm(); updateSmtpButtons(); }
  }

  async function testSmtp() {
    if (!connected || smtpBusy) return;
    const body = smtpFormData(true);
    if (!body) return;
    smtpBusy = 'test';
    smtpFeedback(msg('m_ae28b35fe763'));
    updateSmtpButtons();
    try {
      const result = await request('/api/smtp/test', { method: 'POST', body });
      smtpFeedback(string(result.message, msg('m_ddb5f3179e98')));
    } catch (error) { smtpFeedback(error.message, true); }
    finally { smtpBusy = ''; updateSmtpButtons(); }
  }

  function renderDelivery() {
    if (!byId('outbox-list')) return;
    const delivery = state.delivery || {};
    const smtp = state.smtp || {};
    byId('delivery-status').textContent = delivery.configured ? msg('m_6b1e0d1fb08f') : smtp.enabled && smtp.error ? msg('m_573b4f750558') : smtp.exists || smtp.source === 'environment' ? msg('m_440fb752a4a5') : msg('m_37b177f50000');
    byId('delivery-description').textContent = delivery.configured ? msg('m_39462fa0503e') : smtp.error ? msg('m_c68b77fc16bd', [smtp.error]) : msg('m_898904626928');
    byId('delivery-banner').classList.toggle('delivery-configured', !!delivery.configured);
    renderSmtp();
    byId('delivery-pending').textContent = Number(delivery.pending) || 0;
    byId('delivery-failed').textContent = Number(delivery.failed) || 0;
    byId('delivery-sent').textContent = Number(delivery.sent) || 0;
    const outbox = [...(state.outbox || [])].sort((a, b) => Number(b.created_at) - Number(a.created_at) || Number(b.id) - Number(a.id));
    byId('outbox-count').textContent = outbox.length;
    byId('outbox-empty').hidden = outbox.length > 0;
    const fragment = document.createDocumentFragment();
    const statusLabels = { pending: msg('m_6f3524690512'), sending: msg('m_75bd5dbef4d5'), sent: msg('m_1e62f913c789'), failed: msg('m_55f744d9e86e') };
    for (const entry of outbox) {
      const item = element('li', 'outbox-item');
      const content = element('div', 'outbox-content');
      const header = element('div', 'outbox-item-heading');
      header.append(element('strong', '', string(entry.subject, entry.kind === 'certificate' ? msg('m_4fa62f7b59b2') : msg('m_55ad6e8f6641'))), element('span', `delivery-badge delivery-${Object.prototype.hasOwnProperty.call(statusLabels, entry.status) ? entry.status : 'pending'}`, statusLabels[entry.status] || msg('m_6f3524690512')));
      content.append(header, element('p', 'outbox-recipient', `${string(entry.recipient_name, msg('m_449c73e689f8'))} · ${string(entry.recipient_email)}`));
      content.append(element('p', 'outbox-meta', msg('m_9c83efbbd253', [entry.kind === 'certificate' ? msg('m_a9a635e1d23c') : entry.kind === 'monitor' ? flow('monitor_email') : entry.kind === 'escalation' ? flow('policy_title') : msg('m_9e66123dc753'), date(entry.created_at, true), entry.status === 'sent' ? msg('m_fd6fc605af8e', [date(entry.sent_at, true)]) : '', Number(entry.attempts) || 0])));
      if (entry.last_error) content.append(element('p', 'outbox-error', string(entry.last_error)));
      const actions = element('div', 'outbox-actions');
      const download = element('a', 'button button-secondary', msg('m_885afe758592'));
      download.href = `/api/outbox/${encodeURIComponent(entry.id)}/message`;
      download.download = '';
      actions.append(download);
      if (entry.status === 'failed') {
        const retry = element('button', 'button button-secondary retry-delivery', msg('m_9ea0b378e05c'));
        retry.type = 'button';
        retry.disabled = !connected;
        retry.addEventListener('click', async () => {
          retry.disabled = true;
          try {
            await request(`/api/outbox/${encodeURIComponent(entry.id)}/retry`, { method: 'POST' });
            message(msg('m_571e084a3b5e'));
            await refresh(true);
          } catch (error) { message(error.message, true); retry.disabled = !connected; }
        });
        actions.append(retry);
      }
      item.append(content, actions);
      fragment.append(item);
    }
    byId('outbox-list').replaceChildren(fragment);
  }

  async function refresh(force = false) {
    if (refreshing) {
      if (!force) return refreshing;
      await refreshing;
      return refresh();
    }
    refreshing = (async () => {
      try {
        const next = await request('/api/state');
        if (!Array.isArray(next.certificates) || !Array.isArray(next.notifications) || typeof next.csrf_token !== 'string' || !next.csrf_token) throw new Error(msg('m_a4b2aefaf4e2'));
        state = next;
        state.delivery = next.delivery || {};
        state.smtp = next.smtp || {};
        state.outbox = next.outbox || [];
        state.monitors = (Array.isArray(next.monitors) ? next.monitors : []).map(monitor => ({ ...monitor, email_recipients: (next.monitor_mail || []).filter(contact => String(contact.monitor_id) === String(monitor.id)) }));
        state.monitor_events = Array.isArray(next.monitor_events) ? next.monitor_events : [];
        state.monitoring = next.monitoring || {};
        loaded = true;
        renderSummary();
        renderTable();
        renderNotifications();
        renderDelivery();
        renderMonitoring();
        renderOverview();
        renderDirectory();
        if (detailsCertificate && byId('details-dialog').open && !workflowDirty && !contactsDirty) {
          detailsCertificate = state.certificates.find(cert => String(cert.id) === String(detailsCertificate.id)) || detailsCertificate;
          renderCertificateWorkflow(detailsCertificate);
        }
        byId('last-updated').textContent = msg('m_8a5e2da88d8b', [timeFormat.format(new Date())]);
        setConnection(true);
        if (desktopBaselinePending) {
          baselineDesktopNotices();
          desktopBaselinePending = false;
        }
        notifyDesktop(state.notifications);
        notifyMonitorDesktop(state.monitor_events);
        applyInitialContext();
        return true;
      } catch (error) {
        setConnection(false, msg('m_6b686f6361e8', [error.message]));
        if (!loaded && byId('empty-title')) {
          byId('empty-title').textContent = msg('m_1ba0b56b73a3');
          byId('empty-description').textContent = msg('m_8050493c3601');
        }
        return false;
      } finally { refreshing = null; }
    })();
    return refreshing;
  }

  function addDetail(container, label, value, wide = false, mono = false) {
    const field = element('div', `detail-field${wide ? ' wide' : ''}${mono ? ' monospace' : ''}`);
    field.append(element('dt', '', label), element('dd', '', string(value)));
    container.append(field);
  }

  function showDetails(cert) {
    if (workflowDirty && !window.confirm(flow('discard_draft'))) return;
    detailsCertificate = cert;
    contactsDirty = false;
    detailsTargetId = String(cert.id);
    byId('details-title').textContent = name(cert);
    byId('details-status').replaceChildren(badge(cert.status));
    if (cert.archived) {
      byId('details-status').append(element('span', 'archived-label', msg('m_dbcc8ebd6118')));
      if (cert.superseded_by) {
        const successor = state.certificates.find(item => String(item.id) === String(cert.superseded_by));
        if (successor) {
          const openSuccessor = element('button', 'text-button', msg('m_c13f7eafa92d'));
          openSuccessor.type = 'button';
          openSuccessor.addEventListener('click', () => showDetails(successor));
          byId('details-status').append(openSuccessor);
        }
      }
    }
    byId('details-chain-note').textContent = cert.chain_status === 'complete' ? msg('m_5ca600c39103') : cert.chain_status === 'legacy' ? msg('m_c107bb191d4e') : msg('m_cd1c5a532fd8');
    if (cert.chain_status !== 'complete') { const addCA = element('a', 'text-link', flow('add_ca')); addCA.href = i18n.localURL('/importa'); byId('details-chain-note').append(document.createTextNode(' '), addCA); }
    detailFeedback('');
    const download = byId('download-certificate');
    download.hidden = !cert.pem_available;
    download.href = `/api/certificates/${encodeURIComponent(cert.id)}/download`;
    const data = byId('details-data');
    data.replaceChildren();
    addDetail(data, msg('m_c52778252d3b'), cert.common_name);
    addDetail(data, msg('m_3868d2843d59'), cert.is_ca ? msg('m_21b6194bb578') : msg('m_a94d60e9f8fd'));
    addDetail(data, msg('m_8693b331d694'), date(cert.not_before, true));
    addDetail(data, msg('m_9f1341d2d44b'), date(cert.not_after, true));
    addDetail(data, msg('m_700358f9a24b'), Number.isFinite(Number(cert.days_remaining)) ? cert.days_remaining : '—');
    addDetail(data, msg('m_7ff0c0574456'), date(cert.added_at, true));
    addDetail(data, msg('m_309612f53898'), cert.subject, true);
    addDetail(data, msg('m_2ab68816f88b'), cert.issuer, true);
    addDetail(data, msg('m_e4946c348010'), string(cert.root_ca, msg('m_ce1391381fc8')), true);
    addDetail(data, msg('m_4600e1a76847'), string(cert.intermediate_ca, cert.chain_status === 'complete' ? msg('m_bb9e901e6372') : msg('m_1d98176835cc')), true);
    addDetail(data, msg('m_ffe7dccec599'), Array.isArray(cert.sans) ? cert.sans.join('\n') : cert.sans, true);
    addDetail(data, msg('m_488b09e885d9'), cert.serial, true, true);
    addDetail(data, msg('m_d1592115787b'), `${string(cert.key_algorithm)}${Number(cert.key_bits) > 0 ? ` · ${cert.key_bits} bit` : ''}`);
    addDetail(data, msg('m_ed3e4bea2c2b'), cert.signature_algorithm);
    addDetail(data, msg('m_4cdd497e69c7'), cert.fingerprint, true, true);
    addDetail(data, msg('m_9b8fbb8db650'), cert.source, true);
    renderContacts(cert.contacts || []);
    workflowDirty = false;
    renderCertificateWorkflow(cert);
    updateDetailButtons();
    const dialog = byId('details-dialog');
    if (!dialog.open) dialog.showModal();
    dialog.scrollTop = 0;
    byId('close-details').focus({ preventScroll: true });
  }

  function detailFeedback(text, error = false) {
    const node = byId('details-feedback');
    node.textContent = text;
    node.hidden = !text;
    node.classList.toggle('message-error', error);
    if (text && byId('details-dialog').open) node.scrollIntoView({ block: 'nearest' });
  }

  function markContactsDirty() {
    contactsDirty = true;
    updateDetailButtons();
  }

  function updateContactEmptyStates() {
    for (const role of ['business', 'technical']) byId(`${role}-contacts-empty`).hidden = byId(`${role}-contacts`).children.length > 0;
  }

  function addContact(role, contact = {}, focus = false) {
    const row = element('div', 'contact-row');
    row.dataset.role = role;
    const rowId = ++contactSequence;
    const nameLabel = element('label', 'contact-name-label', msg('m_44a2b0eef0b9'));
    const nameInput = element('input');
    nameInput.type = 'text';
    nameInput.maxLength = 120;
    nameInput.autocomplete = 'name';
    nameInput.id = `contact-name-${rowId}`;
    nameInput.dataset.field = 'name';
    nameInput.value = string(contact.name, '');
    nameLabel.htmlFor = nameInput.id;
    nameLabel.append(nameInput);
    const emailLabel = element('label', 'contact-email-label', msg('m_969ccbd3cf63'));
    const emailInput = element('input');
    emailInput.type = 'email';
    emailInput.maxLength = 254;
    emailInput.autocomplete = 'email';
    emailInput.id = `contact-email-${rowId}`;
    emailInput.dataset.field = 'email';
    emailInput.value = string(contact.email, '');
    emailLabel.htmlFor = emailInput.id;
    emailLabel.append(emailInput);
    const remove = element('button', 'icon-button remove-contact');
    remove.type = 'button';
    remove.title = msg('m_6cca62a74db3');
    remove.setAttribute('aria-label', msg('m_c80dcd76bb39', [role === 'business' ? msg('m_0322c11ef214') : msg('m_44d66aa24073'), string(contact.name, string(contact.email, msg('m_018b7f02dab7')))]));
    remove.append(trashIcon());
    remove.addEventListener('click', () => {
      row.remove();
      updateContactEmptyStates();
      markContactsDirty();
      byId(role === 'business' ? 'add-business-contact' : 'add-technical-contact').focus({ preventScroll: true });
    });
    row.append(nameLabel, emailLabel, remove);
    row.addEventListener('input', () => {
      emailInput.setCustomValidity('');
      emailInput.required = !!nameInput.value.trim() || !!emailInput.value.trim();
      remove.setAttribute('aria-label', msg('m_c80dcd76bb39', [role === 'business' ? msg('m_0322c11ef214') : msg('m_44d66aa24073'), nameInput.value.trim() || emailInput.value.trim() || msg('m_018b7f02dab7')]));
      markContactsDirty();
    });
    byId(`${role}-contacts`).append(row);
    updateContactEmptyStates();
    if (focus) { markContactsDirty(); nameInput.focus(); }
  }

  function renderContacts(contacts) {
    byId('business-contacts').replaceChildren();
    byId('technical-contacts').replaceChildren();
    for (const contact of contacts) if (contact.role === 'business' || contact.role === 'technical') addContact(contact.role, contact);
    updateContactEmptyStates();
  }

  async function saveContacts(event) {
    event.preventDefault();
    if (!detailsCertificate || savingContacts) return;
    const contacts = [];
    const body = new URLSearchParams();
    for (const row of byId('contacts-form').querySelectorAll('.contact-row')) {
      const nameInput = row.querySelector('[data-field="name"]');
      const emailInput = row.querySelector('[data-field="email"]');
      const contactName = nameInput.value.trim();
      const email = emailInput.value.trim();
      if (!contactName && !email) continue;
      emailInput.required = true;
      if (!email || !emailInput.reportValidity()) {
        if (!email) { emailInput.setCustomValidity(msg('m_f6b9fe9caf25')); emailInput.reportValidity(); }
        return;
      }
      contacts.push({ role: row.dataset.role, name: contactName, email });
      body.append('role', row.dataset.role);
      body.append('name', contactName);
      body.append('email', email);
    }
    const cert = detailsCertificate;
    savingContacts = true;
    updateDetailButtons();
    detailFeedback(msg('m_5767f2edd851'));
    try {
      await request(`/api/certificates/${encodeURIComponent(cert.id)}/contacts`, { method: 'PUT', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
      contactsDirty = false;
      const refreshed = await refresh(true);
      detailsCertificate = (refreshed && state.certificates.find(item => String(item.id) === String(cert.id))) || { ...cert, contacts };
      renderContacts(detailsCertificate.contacts || []);
      detailFeedback(contacts.length ? `${contacts.length} ${contacts.length === 1 ? msg('m_9d84eadd0ca3') : msg('m_898e92f39a55')}.` : msg('m_b7c9f09d032c'));
    } catch (error) { detailFeedback(error.message, true); }
    finally { savingContacts = false; updateDetailButtons(); }
  }

  async function distributeCertificate() {
    if (!detailsCertificate || distributing || contactsDirty) return;
    distributing = true;
    updateDetailButtons();
    detailFeedback(msg('m_7543aff9cacd'));
    try {
      const result = await request(`/api/certificates/${encodeURIComponent(detailsCertificate.id)}/distribute`, { method: 'POST' });
      const count = Number(result.queued) || 0;
      await refresh(true);
      detailFeedback(`${count ? msg('m_e839b5386f0d', [count, count === 1 ? msg('m_cb0974078de8') : msg('m_f8db05be308d')]) : msg('m_4f77452cc8a6')} ${state.delivery.configured ? msg('m_6218ff5e17c0') : msg('m_e9d2c019001a')}`);
    } catch (error) { detailFeedback(error.message, true); }
    finally { distributing = false; updateDetailButtons(); }
  }

  async function processDelivery() {
    if (processingDelivery) return;
    processingDelivery = true;
    updateButtons();
    try {
      const result = await request('/api/delivery/process', { method: 'POST' });
      await refresh(true);
      message(result.configured === false || !state.delivery.configured ? msg('m_95fd070f7fe5') : msg('m_6f4e68cfcb7f'));
    } catch (error) { message(error.message, true); }
    finally { processingDelivery = false; updateButtons(); }
  }

  function showDelete(cert) {
    if (deleting || uploading) return;
    deletionTarget = cert;
    deleteTargetId = String(cert.id);
    byId('delete-name').textContent = name(cert);
    byId('delete-error').hidden = true;
    byId('confirm-delete').disabled = false;
    byId('delete-dialog').showModal();
    byId('cancel-delete').focus();
  }

  function closeDelete() {
    if (deleting) return;
    byId('delete-dialog').close();
    deletionTarget = null;
  }

  async function confirmDelete() {
    if (!deletionTarget || deleting) return;
    const cert = deletionTarget;
    deleting = true;
    byId('confirm-delete').disabled = true;
    byId('delete-error').hidden = true;
    updateButtons();
    try {
      await request(`/api/certificates/${encodeURIComponent(cert.id)}`, { method: 'DELETE' });
      byId('delete-dialog').close();
      deletionTarget = null;
      message(msg('m_beeca1f72a0d', [name(cert)]));
      await refresh(true);
      focusRegistry();
    } catch (error) {
      byId('delete-error').textContent = error.message;
      byId('delete-error').hidden = false;
    } finally {
      deleting = false;
      byId('confirm-delete').disabled = false;
      updateButtons();
    }
  }

  async function checkNow() {
    if (checking) return;
    checking = true;
    byId('check-button').setAttribute('aria-busy', 'true');
    updateButtons();
    try {
      const result = await request('/api/check', { method: 'POST' });
      const count = Number(result.new_notifications) || 0;
      message(count ? msg('m_d9112b708236', [count, count === 1 ? msg('m_5957a109400f') : msg('m_38d68dd2941c')]) : msg('m_8fb87e16c3e2'));
      await refresh(true);
    } catch (error) { message(error.message, true); }
    finally { checking = false; byId('check-button').removeAttribute('aria-busy'); updateButtons(); }
  }

  function persistDesktopPreference(enabled) {
    try {
      if (enabled) sessionStorage.setItem('certificate-desktop-notifications', 'enabled');
      else sessionStorage.removeItem('certificate-desktop-notifications');
    } catch (_) { /* The current page can still show notifications when storage is unavailable. */ }
  }

  function restoreDesktopPreference() {
    try {
      desktopEnabled = 'Notification' in window && Notification.permission === 'granted' && sessionStorage.getItem('certificate-desktop-notifications') === 'enabled';
    } catch (_) { desktopEnabled = false; }
    desktopBaselinePending = desktopEnabled;
  }

  function baselineDesktopNotices() {
    for (const notice of state.notifications) seenNotifications.add(noticeKey(notice));
    for (const event of state.monitor_events) seenNotifications.add(`monitor:${event.id}`);
  }

  function updateDesktopButton() {
    if (desktopEnabled && (!('Notification' in window) || Notification.permission !== 'granted')) {
      desktopEnabled = false;
      desktopBaselinePending = false;
      persistDesktopPreference(false);
    }
    const button = byId('desktop-notifications');
    if (!button) return;
    if (!('Notification' in window) || !window.isSecureContext) {
      button.textContent = msg('m_3f732501ba41');
      button.disabled = true;
      byId('desktop-help').textContent = msg('m_5d61de5c79fa');
    } else if (Notification.permission === 'denied') {
      button.textContent = msg('m_cefcf76c54fa');
      button.disabled = true;
      byId('desktop-help').textContent = msg('m_c8ea3388683e');
    } else {
      button.textContent = desktopEnabled ? msg('m_1d0b4cfc9aa6') : msg('m_fce95e162c24');
      button.disabled = desktopRequesting || (!connected && !desktopEnabled);
    }
  }

  async function toggleDesktop() {
    if (desktopRequesting) return;
    if (desktopEnabled) {
      desktopEnabled = false;
      desktopBaselinePending = false;
      persistDesktopPreference(false);
      updateDesktopButton();
      message(msg('m_d0d71846f074'));
      return;
    }
    if (!('Notification' in window)) return;
    const button = byId('desktop-notifications');
    desktopRequesting = true;
    button.disabled = true;
    try {
      const permission = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
      if (permission === 'granted') {
        // Baseline all existing notices so permission never replays old reminders.
        baselineDesktopNotices();
        desktopBaselinePending = false;
        desktopEnabled = true;
        persistDesktopPreference(true);
        message(msg('m_cc209b108174'));
      } else if (permission === 'default') message(msg('m_09e1c1bc356d'));
    } catch (_) { message(msg('m_02a431852eac'), true); }
    desktopRequesting = false;
    updateDesktopButton();
  }

  function notifyDesktop(notifications) {
    if (!desktopEnabled || !('Notification' in window) || Notification.permission !== 'granted') return;
    const fresh = notifications.filter(notice => !seenNotifications.has(noticeKey(notice)));
    for (const notice of fresh) seenNotifications.add(noticeKey(notice));
    if (!fresh.length) return;
    try {
      const first = fresh[0];
      const notification = fresh.length === 1
        ? new Notification(name(first), { body: msg('m_d2eac5bdeb99', [noticeText(first), date(first.not_after)]), tag: `certificate-${first.certificate_id}` })
        : new Notification(msg('m_87f8f8e2e3f4', [fresh.length]), { body: msg('m_b623fab67720'), tag: 'certificate-reminders' });
      notification.onclick = () => { window.focus(); navigateTo('#reminders', { focusHeading: true }); notification.close(); };
    } catch (_) { /* The in-page reminder remains available if the OS rejects an alert. */ }
  }

  function noticeKey(notice) {
    return `${notice.certificate_id}:${notice.threshold}`;
  }

  function notifyMonitorDesktop(events) {
    if (!desktopEnabled || !('Notification' in window) || Notification.permission !== 'granted') return;
    const fresh = events.filter(event => !seenNotifications.has(`monitor:${event.id}`));
    for (const event of fresh) seenNotifications.add(`monitor:${event.id}`);
    const unread = fresh.filter(event => !event.acknowledged_at);
    if (!unread.length) return;
    try {
      const first = unread[0];
      const notification = unread.length === 1
        ? new Notification(monitorEventLabels[first.kind] || msg('m_4fab62062a11'), { body: `${string(first.target)} · ${string(first.message)}`, tag: `monitor-${first.monitor_id}` })
        : new Notification(msg('m_9ae91139a1ec', [unread.length]), { body: msg('m_5819614dff05'), tag: 'monitor-events' });
      notification.onclick = () => { window.focus(); navigateTo('#monitor-alerts', { focusHeading: true }); notification.close(); };
    } catch (_) { /* Monitoring history remains available if the OS rejects an alert. */ }
  }

  function focusRegistry() {
    const heading = byId('registry-title') || byId('page-title');
    if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
  }

  function restoreRowFocus(certificateId, action) {
    const container = byId(currentPage === 'overview' ? 'overview-expiries' : 'certificate-table');
    const button = container && [...container.querySelectorAll('button')]
      .find(item => item.dataset.certificateId === certificateId && item.dataset.rowAction === action);
    if (button) button.focus({ preventScroll: true });
    else focusRegistry();
  }

  function saveRegistryFilters() {
    if (!byId('search')) return;
    try { sessionStorage.setItem('certificate-registry-filters', JSON.stringify({ search: byId('search').value, status: byId('status-filter').value, expiry: byId('expiry-filter').value, archived: byId('include-archived').checked, ...registryContactSelection, ...registryCASelection })); } catch (_) { /* Browsing remains available when storage is disabled. */ }
  }

  function restoreRegistryFilters() {
    if (!byId('search')) return;
    try {
      const saved = JSON.parse(sessionStorage.getItem('certificate-registry-filters') || 'null');
      if (!saved || typeof saved !== 'object') return;
      if (typeof saved.search === 'string') byId('search').value = saved.search;
      if ([...byId('status-filter').options].some(option => option.value === saved.status)) byId('status-filter').value = saved.status;
      if ([...byId('expiry-filter').options].some(option => option.value === saved.expiry)) byId('expiry-filter').value = saved.expiry;
      byId('include-archived').checked = saved.archived === true;
      for (const role of ['business', 'technical']) if (typeof saved[role] === 'string' && saved[role].length <= 254) registryContactSelection[role] = contactEmail(saved[role]);
      for (const { field } of registryCAFilters) {
        const value = saved[field];
        if (typeof value === 'string' && (value === 'missing' || value === 'none' || value.startsWith('dn:'))) registryCASelection[field] = value;
      }
    } catch (_) { /* Start with default filters when storage is unavailable. */ }
  }

  on('choose-files', 'click', () => byId('certificate-files').click());
  on('certificate-files', 'change', event => previewFiles(event.target.files));
  on('search', 'input', () => { saveRegistryFilters(); renderTable(); });
  on('status-filter', 'change', () => { saveRegistryFilters(); renderTable(); });
  on('expiry-filter', 'change', () => { saveRegistryFilters(); renderTable(); });
  on('include-archived', 'change', () => { saveRegistryFilters(); renderTable(); });
  for (const role of ['business', 'technical']) on(`${role}-contact-filter`, 'change', event => {
    registryContactSelection[role] = event.target.value;
    saveRegistryFilters();
    renderTable();
  });
  for (const { field, id } of registryCAFilters) on(id, 'change', event => {
    registryCASelection[field] = event.target.value;
    saveRegistryFilters();
    renderTable();
  });
  on('reset-registry-filters', 'click', () => {
    byId('search').value = '';
    byId('status-filter').value = 'all';
    byId('expiry-filter').value = 'all';
    byId('include-archived').checked = false;
    registryContactSelection.business = '';
    registryContactSelection.technical = '';
    registryCASelection.root_ca = '';
    registryCASelection.intermediate_ca = '';
    saveRegistryFilters();
    renderTable();
  });
  // Acquisition and deployment are separate: importing a renewal never implies installation.
  const flow = (key, values) => msg(`flow.${key}`, values);
  let workflowBusy = false;
  let workflowDirty = false;
  let workflowDirtyForm = null;
  function lockWorkflowForm(form) {
    workflowDirty = true; workflowDirtyForm = form;
    for (const other of document.querySelectorAll('.workflow-form')) {
      if (other !== form) for (const field of other.querySelectorAll('input, select, textarea, button')) field.disabled = true;
    }
  }
  function discardWorkflowDraft() {
    workflowDirty = false; workflowDirtyForm = null; directoryEditingPerson = null; directoryEditingGroup = null;
    if (detailsCertificate && byId('details-dialog').open) renderCertificateWorkflow(detailsCertificate);
    renderDirectory();
  }
  let importDrafts = [];
  let inventoryRows = [];
  let inventoryRunning = false;
  let inventoryStopped = false;
  let directoryEditingPerson = null;
  let directoryEditingGroup = null;
  const operationalLabels = () => ({ registered: flow('registered'), in_use: flow('in_use'), installed: flow('in_use'), ready: flow('ready'), staged: flow('ready'), pending_installation: flow('ready'), deploying: flow('deploying'), retired: flow('retired'), archived: flow('retired') });
  function operationalLabel(cert) {
    const status = cert.operational_status || cert.deployment_status || (cert.archived ? 'archived' : 'registered');
    return operationalLabels()[status] || status;
  }
  function formField(label, type = 'text', value = '', options = {}) {
    const wrapper = element('label', options.wide ? 'workflow-form-field wide' : 'workflow-form-field');
    const title = element('span', '', label);
    const input = element(type === 'textarea' ? 'textarea' : 'input');
    if (type !== 'textarea') input.type = type;
    input.value = value === null || value === undefined ? '' : String(value);
    input.maxLength = options.maxLength || (type === 'textarea' ? 4000 : 254);
    if (options.required) input.required = true;
    wrapper.append(title, input);
    return { wrapper, input };
  }
  function action(label, handler, primary = false) {
    const button = element('button', `button ${primary ? 'button-primary' : 'button-secondary'}`, label);
    button.type = 'button';
    button.addEventListener('click', handler);
    return button;
  }
  function appendOption(select, value, label) {
    const option = element('option', '', label);
    option.value = String(value);
    select.append(option);
  }
  async function workflowRequest(path, method, body, feedback = detailFeedback, sourceForm = null) {
    if (workflowDirty && workflowDirtyForm !== sourceForm) { feedback(flow('save_current_form'), true); return false; }
    if (workflowBusy || savingContacts || renewing || distributing || uploading) return false;
    workflowBusy = true;
    try {
      await request(path, { method, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
      workflowDirty = false; workflowDirtyForm = null;
      await refresh(true);
      if (detailsCertificate) {
        detailsCertificate = state.certificates.find(cert => String(cert.id) === String(detailsCertificate.id)) || detailsCertificate;
        renderCertificateWorkflow(detailsCertificate);
      }
      feedback(flow('saved'));
      return true;
    } catch (error) { feedback(error.message, true); return false; }
    finally { workflowBusy = false; }
  }

  async function previewFiles(fileList, previousId = null) {
    const files = [...fileList];
    if (!files.length || uploading || inventoryRunning) return;
    if (!connected) { message(msg('m_a277990d9b87'), true); return; }
    uploading = true;
    updateButtons();
    const drafts = [];
    const errors = [];
    for (const file of files) {
      try {
        if (!file.size || file.size > 16 * 1024 * 1024) throw new Error(msg('m_b2997d798a03'));
        const result = await request('/api/import/preview', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(file.name) }, body: file });
        drafts.push({ file, result, previousId });
      } catch (error) { errors.push(`${file.name}: ${error.message}`); }
    }
    uploading = false;
    if (byId('certificate-files')) byId('certificate-files').value = '';
    if (byId('renewal-file')) byId('renewal-file').value = '';
    byId('preview-chain-files').value = '';
    updateButtons();
    if (errors.length) message(errors.join('\n'), true);
    if (!drafts.length) return;
    importDrafts.push(...drafts);
    renderImportPreview();
    if (byId('details-dialog').open) byId('details-dialog').close();
    if (!byId('import-preview-dialog').open) byId('import-preview-dialog').showModal();
  }
  function renderImportPreview() {
    const content = byId('import-preview-list');
    content.replaceChildren();
    let count = 0;
    for (const draft of importDrafts) {
      const card = element('article', 'import-preview-card');
      card.append(element('h4', '', draft.file.name));
      const certificates = draft.result.certificates || [];
      count += certificates.length;
      for (const cert of certificates) {
        const data = element('dl', 'details-data');
        addDetail(data, msg('m_c52778252d3b'), cert.common_name);
        addDetail(data, msg('m_8693b331d694'), date(cert.not_before, true));
        addDetail(data, msg('m_9f1341d2d44b'), date(cert.not_after, true));
        addDetail(data, msg('m_e4946c348010'), cert.root_ca);
        addDetail(data, msg('m_4600e1a76847'), cert.intermediate_ca);
        addDetail(data, msg('m_2ab68816f88b'), cert.issuer, true);
        addDetail(data, msg('m_ffe7dccec599'), cert.sans, true);
        addDetail(data, msg('m_4cdd497e69c7'), cert.fingerprint, true, true);
        card.append(element('strong', '', name(cert)), data);
        const duplicate = cert.duplicate_id || cert.existing_id;
        card.append(element('p', `chain-note${duplicate ? '' : ' import-new-note'}`, duplicate ? flow('duplicate', [duplicate]) : flow('new_certificate')));
        if (!cert.is_ca && cert.chain_status !== 'complete' && !cert.chain_complete) card.append(element('p', 'import-chain-warning', flow('missing_chain', [string(cert.issuer)])));
      }
      const selectLabel = element('label', 'workflow-form-field', flow('import_choice'));
      const select = element('select');
      appendOption(select, '', flow('import_new'));
      const leaf = certificates.find(cert => !cert.is_ca);
      const candidates = draft.result.renewal_candidates || (leaf && leaf.renewal_candidates) || [];
      const candidateIds = new Set(candidates.map(candidate => String(typeof candidate === 'object' ? candidate.id || candidate.certificate_id : candidate)));
      if (draft.previousId) candidateIds.add(String(draft.previousId));
      for (const id of candidateIds) {
        const cert = state.certificates.find(item => String(item.id) === id);
        if (cert && !cert.archived && !cert.is_ca) appendOption(select, id, flow('link_previous', [name(cert), id, date(cert.not_after)]));
      }
      if (draft.previousId) select.value = String(draft.previousId);
      draft.selection = select;
      selectLabel.append(select);
      if (leaf && !(leaf.duplicate_id || leaf.existing_id)) card.append(selectLabel);
      card.append(element('p', 'workflow-help', flow('overlap_help')), element('p', 'workflow-help', flow('chain_preview_help')));
      content.append(card);
    }
    byId('import-preview-count').textContent = String(count);
  }
  async function confirmImportPreview() {
    if (uploading || !importDrafts.length) return;
    uploading = true;
    updateButtons();
    byId('confirm-import').disabled = true;
    byId('add-preview-chain').disabled = true;
    byId('cancel-import-preview').disabled = true;
    const errors = [];
    const successful = [];
    for (const draft of importDrafts) {
      try {
        const previousId = draft.selection.value;
        const result = await request(previousId ? `/api/certificates/${encodeURIComponent(previousId)}/renew` : '/api/certificates', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(draft.file.name) }, body: draft.file });
        successful.push(result);
      } catch (error) { errors.push(`${draft.file.name}: ${error.message}`); }
    }
    uploading = false;
    byId('confirm-import').disabled = false;
    byId('add-preview-chain').disabled = false;
    byId('cancel-import-preview').disabled = false;
    importDrafts = [];
    byId('import-preview-dialog').close();
    if (byId('certificate-files')) byId('certificate-files').value = '';
    if (byId('renewal-file')) byId('renewal-file').value = '';
    await refresh(true);
    updateButtons();
    message(errors.length ? errors.join('\n') : flow('import_complete', [successful.length]), errors.length > 0);
    if (successful.length === 1 && successful[0].certificate_id) {
      const cert = state.certificates.find(item => String(item.id) === String(successful[0].certificate_id));
      if (cert) showDetails(cert);
    }
  }

  // RFC 4180 quoting, CRLF, embedded newlines and optional UTF-8 BOM.
  function parseInventoryCSV(source) {
    const text = source.replace(/^\uFEFF/, '');
    const rows = []; let row = []; let value = ''; let quoted = false; let closed = false;
    for (let index = 0; index <= text.length; index++) {
      const character = index === text.length ? '\n' : text[index];
      if (quoted) {
        if (index === text.length) throw new Error(flow('csv_quote_error'));
        if (character === '"' && text[index + 1] === '"') { value += '"'; index++; }
        else if (character === '"') { quoted = false; closed = true; }
        else value += character;
      } else if (character === '"' && !value && !closed) quoted = true;
      else if (character === ',' || character === '\n' || character === '\r') {
        row.push(value); value = ''; closed = false;
        if (character !== ',') {
          if (row.some(item => item.trim())) rows.push(row);
          row = [];
          if (character === '\r' && text[index + 1] === '\n') index++;
        }
      } else if (closed || character === '"') throw new Error(flow('csv_quote_error'));
      else value += character;
    }
    if (rows.length < 2) throw new Error(flow('csv_empty'));
    const header = rows.shift().map(value => value.trim().toLowerCase());
    if (new Set(header).size !== header.length || !header.includes('url') || header.some(key => !['url', 'business_name', 'business_email', 'technical_name', 'technical_email'].includes(key))) throw new Error(flow('csv_header'));
    if (rows.length > 100) throw new Error(flow('csv_limit'));
    return rows.map((values, index) => {
      const row = { line: index + 2, contacts: [], result: null, imported: false, error: '', target: '' };
      if (values.length !== header.length) row.error = flow('csv_columns');
      const data = Object.fromEntries(header.map((key, offset) => [key, (values[offset] || '').trim()]));
      row.target = data.url;
      try {
        const candidate = new URL(/^https:\/\//i.test(data.url) ? data.url : `https://${data.url}`);
        if ((/^[a-z][a-z0-9+.-]*:\/\//i.test(data.url) && !/^https:\/\//i.test(data.url)) || !data.url || candidate.protocol !== 'https:' || candidate.username || candidate.password || candidate.hostname.includes('*') || /[\s\u0000-\u001f]/.test(data.url)) throw new Error();
      } catch (_) { row.error = flow('csv_target_error'); }
      for (const role of ['business', 'technical']) {
        const emails = (data[`${role}_email`] || '').split(';').map(value => value.trim()).filter(Boolean);
        const names = (data[`${role}_name`] || '').split(';').map(value => value.trim());
        for (const [offset, email] of emails.entries()) {
          if (!/^[^\s@;,]+@[^\s@;,]+\.[^\s@;,]+$/.test(email)) row.error = flow('csv_email_error');
          row.contacts.push({ role, name: names[offset] || '', email });
        }
      }
      return row;
    });
  }
  function renderInventory() {
    const content = byId('inventory-results');
    if (!content) return;
    content.replaceChildren();
    for (const row of inventoryRows) {
      const card = element('article', `inventory-row${row.error ? ' is-error' : ''}`);
      card.append(element('strong', '', `${row.line} · ${row.target}`));
      if (row.error) card.append(element('p', '', row.error));
      else if (row.imported) card.append(element('p', '', flow('csv_imported')));
      else if (row.result) {
        const cert = row.result.certificate || (row.result.certificates || [])[0];
        card.append(element('p', '', `${cert ? name(cert) : ''} · ${cert ? date(cert.not_after) : '—'}`));
        if (cert) { const metadata = element('dl', 'details-data'); addDetail(metadata, msg('m_2ab68816f88b'), cert.issuer, true); addDetail(metadata, msg('m_8693b331d694'), date(cert.not_before)); addDetail(metadata, msg('m_4cdd497e69c7'), cert.fingerprint, true, true); card.append(metadata); }
        if (row.result.verification_error) card.append(element('p', 'import-chain-warning', row.result.verification_error));
        if (row.result.verified === false) card.append(element('p', 'import-chain-warning', flow('csv_unverified')));
      } else card.append(element('p', '', flow('csv_ready')));
      if (row.contacts.length) card.append(element('p', 'workflow-help', row.contacts.map(contact => `${contact.role === 'technical' ? msg('m_a6da5b872c69') : msg('m_3ce1f3185cbc')}: ${contact.email}`).join(' · ')));
      content.append(card);
    }
    const valid = inventoryRows.length && inventoryRows.every(row => !row.error);
    byId('inventory-check').disabled = inventoryRunning || !valid;
    byId('inventory-import').disabled = inventoryRunning || !inventoryRows.some(row => row.result && !row.error && !row.imported);
    byId('inventory-preview').disabled = inventoryRunning;
    byId('inventory-text').disabled = inventoryRunning;
    byId('inventory-file').disabled = inventoryRunning;
    byId('inventory-cancel').hidden = !inventoryRunning;
  }
  function previewInventory() {
    if (inventoryRunning) return;
    try {
      inventoryRows = parseInventoryCSV(byId('inventory-text').value);
      byId('inventory-feedback').textContent = flow('csv_validated', [inventoryRows.length]);
    } catch (error) { inventoryRows = []; byId('inventory-feedback').textContent = error.message; }
    renderInventory();
  }
  async function runInventory(importing) {
    if (inventoryRunning || uploading || !inventoryRows.length) return;
    inventoryRunning = true; inventoryStopped = false;
    renderInventory();
    for (const [index, row] of inventoryRows.entries()) {
      if (inventoryStopped) break;
      if (row.error || row.imported || (importing && !row.result)) continue;
      byId('inventory-feedback').textContent = flow(importing ? 'csv_import_progress' : 'csv_progress', [index + 1, inventoryRows.length]);
      try {
        if (!importing) {
          row.result = await request('/api/remote/check', { method: 'POST', body: new URLSearchParams({ target: row.target }) }, true);
          if (!row.result.token) throw new Error(row.result.error || flow('csv_no_certificate'));
        } else {
          // Snapshots expire after ten minutes: always refresh immediately before explicit import.
          const checkedFingerprint = row.result.certificate && row.result.certificate.fingerprint;
          row.result = await request('/api/remote/check', { method: 'POST', body: new URLSearchParams({ target: row.target }) }, true);
          if (!row.result.token) throw new Error(row.result.error || flow('csv_no_certificate'));
          if (checkedFingerprint && (!row.result.certificate || checkedFingerprint !== row.result.certificate.fingerprint)) throw new Error(flow('csv_certificate_changed'));
          const body = new URLSearchParams({ token: row.result.token });
          const imported = await request('/api/remote/import', { method: 'POST', body });
          if (imported.monitoring_error) throw new Error(imported.monitoring_error);
          if (row.contacts.length && imported.certificate_id) {
            await refresh(true);
            const current = state.certificates.find(cert => String(cert.id) === String(imported.certificate_id));
            const contacts = new Map((current && current.contacts || []).map(contact => [`${contact.role}:${contact.email.toLowerCase()}`, contact]));
            for (const contact of row.contacts) contacts.set(`${contact.role}:${contact.email.toLowerCase()}`, contact);
            const assignments = new URLSearchParams();
            for (const contact of contacts.values()) { assignments.append('role', contact.role); assignments.append('name', contact.name || ''); assignments.append('email', contact.email); }
            await request(`/api/certificates/${encodeURIComponent(imported.certificate_id)}/contacts`, { method: 'PUT', body: assignments });
          }
          row.imported = true;
        }
      } catch (error) { row.error = error.message; }
      renderInventory();
    }
    inventoryRunning = false;
    byId('inventory-feedback').textContent = inventoryStopped ? flow('csv_stopped') : flow('csv_done');
    renderInventory();
    if (importing) await refresh(true);
  }
  function jobStatusLabel(value) { return flow(`job_${value || 'requested'}`); }
  function dateInputValue(value) {
    if (!Number(value)) return '';
    const parsed = new Date(Number(value) * 1000);
    return `${parsed.getFullYear()}-${String(parsed.getMonth() + 1).padStart(2, '0')}-${String(parsed.getDate()).padStart(2, '0')}`;
  }
  function inputEpoch(value) { return value ? String(Math.floor(new Date(`${value}T12:00:00`).getTime() / 1000)) : ''; }
  function renderCertificateWorkflow(cert) {
    renderRenewalCase(cert);
    renderReminderPolicy(cert);
    renderDirectoryAssignment(cert);
  }
  function renderRenewalCase(cert) {
    const container = byId('process-content');
    container.replaceChildren();
    if (cert.is_ca) { container.append(element('p', 'workflow-help', flow('ca_no_case'))); return; }
    container.append(element('p', 'workflow-help', flow('overlap_help')));
    const jobs = (state.renewal_jobs || []).filter(job => String(job.old_certificate_id) === String(cert.id) || String(job.new_certificate_id) === String(cert.id));
    const job = jobs.find(item => !item.finished_at) || jobs[0];
    const summary = element('div', 'process-summary');
    summary.append(element('span', 'operational-badge', operationalLabel(cert)));
    if (job) {
      summary.append(element('strong', '', `${flow('case_number', [job.id])} · ${jobStatusLabel(job.status)}`));
      for (const [kind, id] of [['previous', job.old_certificate_id], ['replacement', job.new_certificate_id]]) {
        const linked = state.certificates.find(item => String(item.id) === String(id));
        if (linked) summary.append(action(flow(kind, [name(linked), id]), () => showDetails(linked)));
      }
    }
    container.append(summary);
    const form = element('form', 'workflow-form');
    const fields = element('div', 'workflow-form-grid');
    const responsible = formField(flow('responsible'), 'text', job && job.responsible, { maxLength: 200 });
    const requested = formField(flow('requested_at'), 'date', dateInputValue(job && job.requested_at));
    const renewal = formField(flow('planned_renewal_at'), 'date', dateInputValue(job && job.planned_renewal_at));
    const install = formField(flow('planned_install_at'), 'date', dateInputValue(job && job.planned_install_at));
    const notes = formField(flow('notes'), 'textarea', job && job.notes, { wide: true });
    const statusLabel = element('label', 'workflow-form-field', flow('case_status'));
    const status = element('select');
    for (const value of ['requested', 'awaiting_ca', 'signed', 'delivered', 'installing']) appendOption(status, value, jobStatusLabel(value));
    if (job && ['verified', 'retired'].includes(job.status)) appendOption(status, job.status, jobStatusLabel(job.status));
    status.value = job && job.status || 'requested';
    statusLabel.append(status);
    fields.append(responsible.wrapper, statusLabel, requested.wrapper, renewal.wrapper, install.wrapper, notes.wrapper);
    form.append(fields);
    if (!job || !job.new_certificate_id) {
      const candidateLabel = element('label', 'workflow-form-field', flow('link_existing'));
      const candidate = element('select');
      appendOption(candidate, '', flow('no_replacement'));
      const predecessor = state.certificates.find(item => String(item.id) === String(job ? job.old_certificate_id : cert.id)) || cert;
      for (const replacement of state.certificates.filter(item => !item.is_ca && !item.archived && item.id !== predecessor.id && item.common_name === predecessor.common_name && Number(item.not_after) > Number(predecessor.not_after))) {
        appendOption(candidate, replacement.id, `${name(replacement)} · ID ${replacement.id} · ${date(replacement.not_after)}`);
      }
      candidateLabel.append(candidate); form.append(candidateLabel);
      form.replacementSelector = candidate;
    }
    const save = element('button', 'button button-primary', job ? flow('save_case') : flow('create_case'));
    save.type = 'submit';
    save.disabled = !!cert.archived || !!(job && job.finished_at);
    form.append(save, action(flow('cancel'), discardWorkflowDraft));
    form.addEventListener('input', () => lockWorkflowForm(form));
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const body = new URLSearchParams({ old_certificate_id: String(job ? job.old_certificate_id : cert.id), status: status.value, responsible: responsible.input.value.trim(), requested_at: inputEpoch(requested.input.value), planned_renewal_at: inputEpoch(renewal.input.value), planned_install_at: inputEpoch(install.input.value), notes: notes.input.value.trim() });
      if (form.replacementSelector && form.replacementSelector.value) { body.set('new_certificate_id', form.replacementSelector.value); if (['requested', 'awaiting_ca'].includes(body.get('status'))) body.set('status', 'signed'); }
      workflowRequest(job ? `/api/renewal-jobs/${encodeURIComponent(job.id)}` : '/api/renewal-jobs', job ? 'PUT' : 'POST', body, detailFeedback, form);
    });
    container.append(form);
    if (!job || !job.new_certificate_id) return;
    const endpoints = (state.renewal_endpoints || []).filter(endpoint => String(endpoint.job_id) === String(job.id));
    const endpointList = element('ul', 'deployment-endpoints');
    for (const endpoint of endpoints) {
      const item = element('li');
      const info = element('div');
      info.append(element('strong', '', endpoint.target), element('p', '', endpoint.verified_at ? flow('endpoint_verified', [date(endpoint.verified_at, true)]) : flow('endpoint_waiting')));
      const observed = endpoint.last_fingerprint;
      if (observed) info.append(element('p', '', observed === job.new_fingerprint ? flow('observed_new') : observed === job.old_fingerprint ? flow('observed_previous') : flow('observed_unexpected')));
      if (!endpoint.enabled) info.append(element('p', 'import-chain-warning', flow('endpoint_paused')));
      const verify = action(flow('verify_install'), () => workflowRequest(`/api/renewal-jobs/${encodeURIComponent(job.id)}/check-install`, 'POST', new URLSearchParams({ monitor_id: String(endpoint.monitor_id) })));
      verify.disabled = !!job.finished_at || !endpoint.enabled;
      item.append(info, verify); endpointList.append(item);
    }
    container.append(element('h4', '', flow('deployment_title')), element('p', 'workflow-help', flow('deployment_help')), endpointList);
    const actions = element('div', 'action-row');
    if (!endpoints.length) {
      container.append(element('p', 'import-chain-warning', flow('no_endpoints')));
      const retire = action(flow('retire_manual'), () => {
        if (window.confirm(flow('retire_confirm'))) workflowRequest(`/api/renewal-jobs/${encodeURIComponent(job.id)}/retire`, 'POST', new URLSearchParams());
      });
      retire.disabled = !!job.finished_at;
      actions.append(retire);
    } else {
      const check = action(flow('verify_all'), () => workflowRequest(`/api/renewal-jobs/${encodeURIComponent(job.id)}/check-install`, 'POST', new URLSearchParams({ monitor_id: '0' })));
      const complete = action(flow('complete_case'), () => workflowRequest(`/api/renewal-jobs/${encodeURIComponent(job.id)}/complete`, 'POST', new URLSearchParams()), true);
      check.disabled = !!job.finished_at;
      complete.disabled = !!job.finished_at || endpoints.some(endpoint => !endpoint.verified_at);
      actions.append(check, complete);
    }
    container.append(actions);
  }
  function renderReminderPolicy(cert) {
    const container = byId('policy-content');
    const policy = (state.reminder_policies || []).find(item => String(item.certificate_id) === String(cert.id)) || { thresholds: '45,30,15,2,0', enabled: true, escalation_after_days: 7 };
    const form = element('form', 'workflow-form');
    const fields = element('div', 'workflow-form-grid');
    const thresholds = formField(flow('thresholds'), 'text', policy.thresholds, { required: true });
    thresholds.input.pattern = '\\s*\\d+\\s*(,\\s*\\d+\\s*)*';
    const escalationEmail = formField(flow('escalation_email'), 'email', policy.escalation_email);
    const escalationName = formField(flow('escalation_name'), 'text', policy.escalation_name, { maxLength: 120 });
    const delay = formField(flow('escalation_delay'), 'number', policy.escalation_after_days);
    delay.input.min = '0'; delay.input.max = '365'; delay.input.step = '1'; delay.input.required = true;
    fields.append(thresholds.wrapper, escalationEmail.wrapper, escalationName.wrapper, delay.wrapper);
    const enabled = element('label', 'checkbox-field');
    const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.checked = policy.enabled !== false && policy.enabled !== 0;
    enabled.append(checkbox, element('span', '', flow('reminders_enabled')));
    const save = element('button', 'button button-primary', flow('save_policy')); save.type = 'submit';
    form.append(element('p', 'workflow-help', flow('policy_help')), fields, enabled, save, action(flow('cancel'), discardWorkflowDraft));
    form.addEventListener('input', () => lockWorkflowForm(form));
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      workflowRequest(`/api/certificates/${encodeURIComponent(cert.id)}/reminder-policy`, 'PUT', new URLSearchParams({ thresholds: thresholds.input.value.trim(), enabled: checkbox.checked ? '1' : '0', escalation_email: escalationEmail.input.value.trim(), escalation_name: escalationName.input.value.trim(), escalation_after_days: delay.input.value }), detailFeedback, form);
    });
    container.replaceChildren(form);
  }
  function renderDirectoryAssignment(cert) {
    const container = byId('directory-assign-content');
    const form = element('form', 'workflow-form');
    const roleLabel = element('label', 'workflow-form-field', flow('role'));
    const role = element('select');
    appendOption(role, 'business', msg('m_3ce1f3185cbc')); appendOption(role, 'technical', msg('m_a6da5b872c69'));
    roleLabel.append(role); form.append(roleLabel);
    const choices = element('div', 'directory-choices');
    for (const [kind, list] of [['person_id', state.people || []], ['group_id', state.groups || []]]) {
      for (const item of list) {
        const label = element('label', 'checkbox-field');
        const input = element('input'); input.type = 'checkbox'; input.name = kind; input.value = String(item.id);
        label.append(input, element('span', '', kind === 'person_id' ? `${item.name || ''} · ${item.email}` : flow('group_label', [item.name])));
        choices.append(label);
      }
    }
    form.append(element('p', 'workflow-help', flow('assignment_help')), choices);
    const save = element('button', 'button button-primary', flow('assign_selected')); save.type = 'submit'; save.disabled = !(state.people || []).length && !(state.groups || []).length;
    form.append(save);
    const link = element('a', 'text-link', flow('open_directory')); link.href = i18n.localURL('/rubrica'); form.append(link);
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (contactsDirty) { detailFeedback(msg('m_ab8f05842744'), true); return; }
      const body = new URLSearchParams({ role: role.value });
      for (const checkbox of choices.querySelectorAll('input:checked')) body.append(checkbox.name, checkbox.value);
      workflowRequest(`/api/certificates/${encodeURIComponent(cert.id)}/assignments`, 'POST', body).then(ok => { if (ok) renderContacts(detailsCertificate.contacts || []); });
    });
    container.replaceChildren(form);
  }
  function renderDirectory() {
    const container = byId('directory-content');
    if (!container || directoryEditingPerson !== null || directoryEditingGroup !== null || workflowDirty) return;
    container.replaceChildren();
    const feedback = (text, error) => message(text, error);
    const grid = element('div', 'directory-grid');
    const peoplePanel = element('section', 'panel directory-panel');
    peoplePanel.append(element('h2', '', flow('people')), element('p', 'workflow-help', flow('people_help')));
    const personForm = element('form', 'workflow-form');
    const personName = formField(msg('m_44a2b0eef0b9'), 'text', '', { maxLength: 120 });
    const personEmail = formField(msg('m_969ccbd3cf63'), 'email', '', { required: true });
    const personChoices = element('div', 'directory-choices');
    for (const group of state.groups || []) {
      const label = element('label', 'checkbox-field'); const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.value = String(group.id);
      label.append(checkbox, element('span', '', group.name)); personChoices.append(label);
    }
    const personSave = element('button', 'button button-primary', flow('save_person')); personSave.type = 'submit';
    const personCancel = action(flow('cancel'), () => { discardWorkflowDraft(); }); personCancel.hidden = true;
    personForm.append(personName.wrapper, personEmail.wrapper, personChoices, personSave, personCancel);
    personForm.addEventListener('input', () => { personCancel.hidden = false; lockWorkflowForm(personForm); });
    personForm.addEventListener('submit', async event => {
      event.preventDefault(); if (!personForm.reportValidity()) return;
      const body = new URLSearchParams({ name: personName.input.value.trim(), email: personEmail.input.value.trim() });
      for (const checkbox of personChoices.querySelectorAll('input:checked')) body.append('group_id', checkbox.value);
      const id = directoryEditingPerson;
      if (await workflowRequest(id ? `/api/people/${encodeURIComponent(id)}` : '/api/people', id ? 'PUT' : 'POST', body, feedback, personForm)) { discardWorkflowDraft(); }
    });
    peoplePanel.append(personForm);
    const people = element('ul', 'directory-list');
    for (const person of state.people || []) {
      const item = element('li'); const info = element('div'); info.append(element('strong', '', person.name || person.email), element('p', '', person.email));
      const edit = action(flow('edit'), () => {
        if (workflowDirty && workflowDirtyForm !== personForm) { message(flow('save_current_form'), true); return; }
        directoryEditingPerson = person.id; lockWorkflowForm(personForm); personCancel.hidden = false;
        personName.input.value = person.name || ''; personEmail.input.value = person.email;
        for (const checkbox of personChoices.querySelectorAll('input')) checkbox.checked = (person.group_ids || []).map(String).includes(checkbox.value);
        personName.input.focus();
      });
      const remove = action(flow('remove'), async () => {
        if (workflowDirty) { message(flow('save_current_form'), true); return; }
        if (!window.confirm(flow('delete_person_confirm', [person.email]))) return;
        await workflowRequest(`/api/people/${encodeURIComponent(person.id)}`, 'DELETE', new URLSearchParams(), feedback);
      });
      item.append(info, edit, remove); people.append(item);
    }
    peoplePanel.append(people);
    const groupPanel = element('section', 'panel directory-panel');
    groupPanel.append(element('h2', '', flow('groups')), element('p', 'workflow-help', flow('groups_help')));
    const groupForm = element('form', 'workflow-form');
    const groupName = formField(flow('group_name'), 'text', '', { required: true, maxLength: 120 });
    const members = element('div', 'directory-choices');
    for (const person of state.people || []) {
      const label = element('label', 'checkbox-field'); const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.value = String(person.id);
      label.append(checkbox, element('span', '', `${person.name || ''} · ${person.email}`)); members.append(label);
    }
    const groupSave = element('button', 'button button-primary', flow('save_group')); groupSave.type = 'submit';
    const groupCancel = action(flow('cancel'), () => { discardWorkflowDraft(); }); groupCancel.hidden = true;
    groupForm.append(groupName.wrapper, members, groupSave, groupCancel);
    groupForm.addEventListener('input', () => { groupCancel.hidden = false; lockWorkflowForm(groupForm); });
    groupForm.addEventListener('submit', async event => {
      event.preventDefault(); if (!groupForm.reportValidity()) return;
      const body = new URLSearchParams({ name: groupName.input.value.trim() });
      for (const checkbox of members.querySelectorAll('input:checked')) body.append('person_id', checkbox.value);
      const id = directoryEditingGroup;
      if (await workflowRequest(id ? `/api/groups/${encodeURIComponent(id)}` : '/api/groups', id ? 'PUT' : 'POST', body, feedback, groupForm)) { discardWorkflowDraft(); }
    });
    groupPanel.append(groupForm);
    const groups = element('ul', 'directory-list');
    for (const group of state.groups || []) {
      const item = element('li'); const info = element('div'); info.append(element('strong', '', group.name), element('p', '', flow('member_count', [(group.member_ids || []).length])));
      const edit = action(flow('edit'), () => {
        if (workflowDirty && workflowDirtyForm !== groupForm) { message(flow('save_current_form'), true); return; }
        directoryEditingGroup = group.id; lockWorkflowForm(groupForm); groupCancel.hidden = false; groupName.input.value = group.name;
        for (const checkbox of members.querySelectorAll('input')) checkbox.checked = (group.member_ids || []).map(String).includes(checkbox.value);
        groupName.input.focus();
      });
      const remove = action(flow('remove'), async () => {
        if (workflowDirty) { message(flow('save_current_form'), true); return; }
        if (!window.confirm(flow('delete_group_confirm', [group.name]))) return;
        await workflowRequest(`/api/groups/${encodeURIComponent(group.id)}`, 'DELETE', new URLSearchParams(), feedback);
      });
      item.append(info, edit, remove); groups.append(item);
    }
    groupPanel.append(groups); grid.append(peoplePanel, groupPanel); container.append(grid);
  }

  on('contacts-form', 'submit', saveContacts);
  on('add-business-contact', 'click', () => addContact('business', {}, true));
  on('add-technical-contact', 'click', () => addContact('technical', {}, true));
  on('choose-renewal', 'click', () => byId('renewal-file').click());
  on('renewal-file', 'change', event => previewFiles(event.target.files, detailsCertificate && detailsCertificate.id));
  on('distribute-certificate', 'click', distributeCertificate);
  on('process-delivery', 'click', processDelivery);
  on('smtp-form', 'submit', saveSmtp);
  on('smtp-form', 'input', smtpFormChanged);
  on('smtp-form', 'change', smtpFormChanged);
  on('smtp-test', 'click', testSmtp);
  on('smtp-reset', 'click', () => { populateSmtpForm(); smtpFeedback(msg('m_263251812ba1')); updateSmtpButtons(); });
  on('remote-form', 'submit', checkRemote);
  on('remote-import', 'click', importRemote);
  on('remote-target', 'input', () => { clearRemoteResult(); remoteFeedback(''); });
  on('remote-clear-expected', 'click', () => { setRemoteExpected(null); clearRemoteResult(); remoteFeedback(''); byId('remote-target').focus(); });
  on('verify-online', 'click', verifyDetailsOnline);
  on('monitor-form', 'submit', saveMonitor);
  for (const eventName of ['input', 'change']) on('monitor-form', eventName, () => {
    monitorDraftDirty = true;
    byId('monitor-cancel-edit').hidden = false;
  });
  on('monitor-cancel-edit', 'click', () => { resetMonitorForm(); monitorFeedback(msg('m_092b37887c7e')); });
  on('monitor-from-details', 'click', monitorDetailsService);
  on('monitor-delete-close', 'click', closeMonitorDelete);
  on('monitor-delete-cancel', 'click', closeMonitorDelete);
  on('monitor-delete-confirm', 'click', confirmMonitorDelete);
  on('monitor-delete-dialog', 'cancel', event => { if (monitorDeleting) event.preventDefault(); });
  on('monitor-delete-dialog', 'close', () => {
    if (!byId('monitor-list')) return;
    const button = [...byId('monitor-list').querySelectorAll('.monitor-action')].find(item => monitorDeleteTarget && item.dataset.monitorId === String(monitorDeleteTarget.id) && item.dataset.rowAction === 'remove-monitor');
    if (button) button.focus({ preventScroll: true }); else focusMonitorHeading();
  });
  on('check-button', 'click', checkNow);
  on('close-details', 'click', () => byId('details-dialog').close());
  on('details-done', 'click', () => byId('details-dialog').close());
  on('details-dialog', 'close', () => {
    workflowDirty = false;
    if (skipDetailsFocusRestore) skipDetailsFocusRestore = false;
    else restoreRowFocus(detailsTargetId, 'details');
  });
  on('details-dialog', 'cancel', event => { if (savingContacts || renewing || distributing) event.preventDefault(); });
  on('close-delete', 'click', closeDelete);
  on('cancel-delete', 'click', closeDelete);
  on('confirm-delete', 'click', confirmDelete);
  on('delete-dialog', 'cancel', event => { if (deleting) event.preventDefault(); else deletionTarget = null; });
  on('delete-dialog', 'close', () => restoreRowFocus(deleteTargetId, 'delete'));
  on('desktop-notifications', 'click', toggleDesktop);
  const zone = byId('drop-zone');
  if (zone) {
    let dragDepth = 0;
    zone.addEventListener('dragenter', event => { event.preventDefault(); dragDepth++; if (!uploading) zone.classList.add('is-dragging'); });
    zone.addEventListener('dragover', event => { event.preventDefault(); event.dataTransfer.dropEffect = uploading ? 'none' : 'copy'; });
    zone.addEventListener('dragleave', event => { event.preventDefault(); dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) zone.classList.remove('is-dragging'); });
    zone.addEventListener('drop', event => { event.preventDefault(); dragDepth = 0; zone.classList.remove('is-dragging'); previewFiles(event.dataTransfer.files); });
  }
  // Prevent a dropped certificate outside the drop area from replacing the app.
  window.addEventListener('dragover', event => event.preventDefault());
  window.addEventListener('drop', event => event.preventDefault());
  window.addEventListener('online', () => refresh());
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  window.addEventListener('certificate-language-change', event => {
    if ((contactsDirty && byId('details-dialog').open) || smtpDirty || monitorDraftDirty || workflowDirty || importDrafts.length) {
      event.preventDefault();
      message(i18n.serverMessage('Salva o annulla le modifiche prima di cambiare lingua.'), true);
    } else if (inventoryRunning || workflowBusy || uploading || checking || deleting || savingContacts || renewing || distributing || processingDelivery || smtpBusy || remoteChecking || remoteImporting || monitorMutating || monitorDeleting) {
      event.preventDefault();
      message(i18n.serverMessage('Modifica della lingua non disponibile durante un’operazione. Attendi il completamento.'), true);
    }
  });
  on('confirm-import', 'click', confirmImportPreview);
  on('cancel-import-preview', 'click', () => { if (!uploading) { importDrafts = []; byId('import-preview-dialog').close(); } });
  on('import-preview-dialog', 'cancel', event => { if (uploading) event.preventDefault(); else importDrafts = []; });
  on('inventory-preview', 'click', previewInventory);
  on('inventory-text', 'input', () => { inventoryRows = []; renderInventory(); });
  on('preview-chain-files', 'change', event => previewFiles(event.target.files));
  on('add-preview-chain', 'click', () => byId('preview-chain-files').click());
  on('inventory-check', 'click', () => runInventory(false));
  on('inventory-import', 'click', () => runInventory(true));
  on('inventory-cancel', 'click', () => { inventoryStopped = true; });
  on('inventory-file', 'change', async event => {
    const file = event.target.files[0]; if (!file) return;
    if (file.size > 1024 * 1024) { byId('inventory-feedback').textContent = flow('csv_size'); return; }
    byId('inventory-text').value = await file.text(); previewInventory();
  });
  window.addEventListener('beforeunload', event => {
    if (workflowDirty || importDrafts.length || inventoryRunning) { event.preventDefault(); event.returnValue = ''; }
  });
  initializeWorkflow();
  restoreRegistryFilters();
  restoreDesktopPreference();
  let legacyId = '';
  try { legacyId = decodeURIComponent(window.location.hash.slice(1)); } catch (_) { /* Ignore malformed fragments. */ }
  const legacyPath = window.location.pathname === '/' ? legacyRoutes[legacyId] : null;
  if (legacyPath && legacyPath !== '/') {
    const destination = new URL(legacyPath, window.location.href);
    destination.search = window.location.search;
    window.location.replace(destination.pathname + destination.search + destination.hash);
    return;
  }
  updateDesktopButton();
  refresh();
  setInterval(refresh, 30000);
})();
