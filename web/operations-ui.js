(() => {
  'use strict';
  const core = () => window.CertificateCore;
  const t = (key, values = []) => window.CertificateI18n.t(`ops.${key}`, values);
  const el = (tag, cls, text) => core().element(tag, cls, text);
  const button = (text, handler, primary = false) => core().action(text, handler, primary);
  const api = (path, fields, method = 'POST') => core().request(`/api/operations/${path}`, { method, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: fields });
  const get = path => core().request(`/api/operations/${path}`);
  const reportError = (box, error) => { box.replaceChildren(el('p', 'import-chain-warning', error.message)); };
  const certById = id => (core().getState().certificates || []).find(cert => String(cert.id) === String(id));
  const caseStatus = value => core().flow(`job_${value}`);
  const fieldValue = value => value === null || value === undefined || value === '' ? '—' : String(value);
  const feedback = () => { const p = el('p', 'ops-feedback'); p.setAttribute('role', 'status'); return p; };
  const section = (title, help) => { const box = el('section', 'ops-panel'); box.append(el('h4', '', title)); if (help) box.append(el('p', 'workflow-help', help)); return box; };
  const table = headers => {
    const wrap = el('div', 'ops-table-wrap'); wrap.tabIndex = 0;
    const node = el('table', 'ops-table'); const head = el('thead'); const tr = el('tr');
    headers.forEach(title => { const th = el('th', '', title); th.scope = 'col'; tr.append(th); }); head.append(tr);
    const body = el('tbody'); node.append(head, body); wrap.append(node); return { wrap, body };
  };
  const cell = value => { const td = el('td'); if (value instanceof Node) td.append(value); else td.textContent = fieldValue(value); return td; };
  function download(value, filename) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json;charset=utf-8' }));
    const a = el('a'); a.href = url; a.download = filename; document.body.append(a); a.click(); a.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function modal(title, content, confirmLabel = t('confirm')) {
    return new Promise(resolve => {
      const dialog = el('dialog', 'ops-dialog'); const h = el('h3', '', title); h.id = `ops-dialog-${Date.now()}`; dialog.setAttribute('aria-labelledby', h.id);
      const actions = el('div', 'action-row'); const cancel = button(t('cancel'), () => dialog.close('cancel'));
      actions.append(cancel); if (confirmLabel) actions.append(button(confirmLabel, () => dialog.close('confirm'), true));
      dialog.append(h, content, actions); dialog.addEventListener('close', () => { const confirmed = dialog.returnValue === 'confirm'; dialog.remove(); resolve(confirmed); }, { once: true });
      document.body.append(dialog); dialog.showModal(); cancel.focus();
    });
  }
  function keyValue(host, title, value) { host.append(el('dt', '', title), el('dd', '', fieldValue(value))); }
  function comparisonView(result, linked = false) {
    const box = el('div');
    if (!linked) box.append(el('p', result.candidate ? 'chain-note' : 'import-chain-warning', result.candidate ? t('compatible') : t('incompatible')));
    if (!result.identity_matches && result.identity_message) box.append(el('p', 'import-chain-warning', result.identity_message));
    const grid = table([t('field'), t('previous'), t('replacement')]);
    const fields = [ ['common_name', t('cn')], ['sans', 'SAN'], ['issuer', t('issuer')], ['root_ca', t('root_ca')], ['intermediate_ca', t('intermediate_ca')], ['not_before', t('issued')], ['not_after', t('expires')], ['fingerprint', t('fingerprint')], ['key', t('key')], ['signature_algorithm', t('signature')] ];
    for (const [key, label] of fields) {
      let a = result.previous[key], b = result.next[key];
      if (key === 'root_ca' || key === 'intermediate_ca') { a = result.previous_chain[key]; b = result.next_chain[key]; }
      if (key === 'not_before' || key === 'not_after') { a = core().date(a, true); b = core().date(b, true); }
      if (key === 'key') { a = `${result.previous.key_algorithm} ${result.previous.key_bits}`; b = `${result.next.key_algorithm} ${result.next.key_bits}`; }
      const tr = el('tr'); if (String(a) !== String(b)) tr.className = 'ops-row-changed'; tr.append(cell(label), cell(a), cell(b)); grid.body.append(tr);
    }
    box.append(grid.wrap); return box;
  }
  function compareChoice(form, previous, select) {
    const box = section(t('compare_title'), t('compare_help')); const result = el('div'); let sequence = 0;
    const compare = button(t('compare'), async () => {
      const version = ++sequence; compare.disabled = true; result.replaceChildren(el('p', '', t('loading')));
      try { const data = await api('compare', new URLSearchParams({ old_certificate_id: previous.id, new_certificate_id: select.value })); if (version === sequence && box.isConnected) result.replaceChildren(comparisonView(data)); }
      catch (error) { if (version === sequence) reportError(result, error); }
      finally { if (version === sequence) compare.disabled = !select.value; }
    });
    compare.disabled = !select.value;
    select.addEventListener('change', () => { sequence++; result.replaceChildren(); compare.disabled = !select.value; });
    box.append(compare, result); form.append(box);
  }
  function checklistView(data) {
    const box = el('div'); box.append(el('p', data.can_complete ? 'chain-note' : 'import-chain-warning', data.can_complete ? t('ready_close') : t('blocked_close')));
    for (const reason of data.reason_codes || []) box.append(el('p', 'workflow-help', t(`reason_${reason}`)));
    const grid = table([t('service'), t('last_check'), t('expected_observed'), t('result')]);
    for (const endpoint of data.endpoints || []) {
      const fingerprints = el('div'); fingerprints.append(el('p', '', `${t('expected')}: ${fieldValue(endpoint.expected_fingerprint)}`), el('p', '', `${t('observed')}: ${fieldValue(endpoint.observed_fingerprint)}`));
      const reasons = el('ul'); (endpoint.reason_codes || []).forEach(reason => reasons.append(el('li', '', t(`reason_${reason}`)))); if (!(endpoint.reason_codes || []).length) reasons.append(el('li', '', t('verified')));
      const tr = el('tr', endpoint.can_complete ? '' : 'ops-row-error'); tr.append(cell(endpoint.target), cell(core().date(endpoint.last_checked_at, true)), cell(fingerprints), cell(reasons)); grid.body.append(tr);
    }
    if (data.endpoints.length) box.append(grid.wrap);
    box.append(el('p', 'workflow-help', t('checklist_validity', [core().date(data.now, true)]))); return box;
  }
  function renewal(container, job, completeButton) {
    const panel = section(t('checklist_title'), t('checklist_help')); const output = el('div'); const stamp = feedback();
    let checking = false, latest = null;
    if (completeButton) completeButton.disabled = true;
    const reload = async () => {
      if (checking || !panel.isConnected) return null; checking = true; inspect.disabled = true;
      try {
        const data = await get(`renewals/${encodeURIComponent(job.id)}/checklist`);
        if (!panel.isConnected) return null;
        latest = data; output.replaceChildren(checklistView(data)); stamp.textContent = '';
        if (completeButton) completeButton.disabled = !data.can_complete || !!job.finished_at;
        return data;
      } catch (error) { if (panel.isConnected) reportError(output, error); if (completeButton) completeButton.disabled = true; return null; }
      finally { checking = false; inspect.disabled = false; }
    };
    const inspect = button(t('refresh_checklist'), reload);
    panel.append(inspect, output, stamp); container.append(panel);
    if (completeButton) completeButton.addEventListener('click', async event => {
      event.preventDefault(); event.stopImmediatePropagation(); completeButton.disabled = true;
      const data = await reload();
      if (data && data.can_complete) await core().workflowRequest(`/api/renewal-jobs/${encodeURIComponent(job.id)}/complete`, 'POST', new URLSearchParams());
    }, true);
    // The server remains authoritative; elapsed evidence disables completion between polls.
    const timer = window.setInterval(() => {
      if (!panel.isConnected) { window.clearInterval(timer); return; }
      if (!latest || !completeButton || !latest.can_complete) return;
      const now = Date.now() / 1000;
      const stale = latest.endpoints.some(endpoint => [endpoint.verify_requested_at, endpoint.verified_at, endpoint.last_checked_at].some(at => !at || Number(at) < now - 900));
      if (stale) { completeButton.disabled = true; stamp.textContent = t('evidence_expired'); }
    }, 5000);
    reload();
    const deliveries = section(t('delivery_title'), t('delivery_help')); const deliveryOutput = el('div');
    const loadDelivery = async () => {
      try {
        const data = await get(`renewals/${encodeURIComponent(job.id)}/delivery`); if (!deliveries.isConnected) return;
        const grid = table([t('recipient'), t('status'), t('attempts'), t('actions')]);
        for (const recipient of data.recipients) {
          const actions = el('div', 'action-row');
          if (recipient.outbox_id) { const link = el('a', 'button button-secondary', t('download_message')); link.href = `/api/outbox/${encodeURIComponent(recipient.outbox_id)}/message`; link.download = ''; actions.append(link); }
          if (recipient.status === 'failed') actions.append(button(t('retry_failed'), async () => { if (await core().workflowRequest(`/api/outbox/${encodeURIComponent(recipient.outbox_id)}/retry`, 'POST', new URLSearchParams())) loadDelivery(); }));
          const status = el('div'); status.append(el('span', '', t(`mail_${recipient.status}`))); if (recipient.last_error) status.append(el('p', 'import-chain-warning', recipient.last_error)); if (recipient.sent_at) status.append(el('p', 'workflow-help', core().date(recipient.sent_at, true)));
          const tr = el('tr'); tr.append(cell(`${recipient.name || ''} <${recipient.email}>`), cell(status), cell(recipient.attempts), cell(actions)); grid.body.append(tr);
        }
        deliveryOutput.replaceChildren(data.recipients.length ? grid.wrap : el('p', 'workflow-help', t('no_technical_recipients')));
      } catch (error) { if (deliveries.isConnected) reportError(deliveryOutput, error); }
    };
    deliveries.append(button(t('refresh'), loadDelivery), deliveryOutput); container.append(deliveries); loadDelivery();
    if (job.new_certificate_id) {
      const comparePanel = section(t('compare_title'), t('compare_help')); const compareOutput = el('div');
      comparePanel.append(button(t('compare'), async () => {
        try { const data = await api('compare', new URLSearchParams({ old_certificate_id: job.old_certificate_id, new_certificate_id: job.new_certificate_id })); if (comparePanel.isConnected) compareOutput.replaceChildren(comparisonView(data, true)); }
        catch (error) { if (comparePanel.isConnected) reportError(compareOutput, error); }
      }), compareOutput); container.append(comparePanel);
    }
    const reportPanel = section(t('report_title'), t('report_help')); const reportStatus = feedback();
    reportPanel.append(button(t('download_report'), async () => { try { const data = await get(`renewals/${encodeURIComponent(job.id)}/report`); download(data, `certificate-manager-rinnovo-${job.id}.json`); } catch (error) { reportStatus.textContent = error.message; } }), reportStatus); container.append(reportPanel);
  }
  function reminderPreview(form, cert, bodyGetter) {
    const box = section(t('reminder_preview_title'), t('reminder_preview_help')); const output = el('div'); let sequence = 0;
    const preview = button(t('simulate'), async () => {
      if (!form.reportValidity()) return; const version = ++sequence; preview.disabled = true; output.replaceChildren(el('p', '', t('loading')));
      try {
        const data = await api('reminder-preview', bodyGetter()); if (!box.isConnected || version !== sequence) return;
        const grid = table([t('threshold'), t('scheduled_date'), t('effective_date'), t('status')]);
        for (const event of data.events) { const tr = el('tr'); tr.append(cell(`${event.threshold} ${t('days')}`), cell(core().date(event.scheduled_at, true)), cell(core().date(event.at, true)), cell(t(`event_${event.status}`))); grid.body.append(tr); }
        const result = el('div'); result.append(grid.wrap, el('p', '', `${t('recipients')}: ${data.recipients.map(r => `${r.name || ''} <${r.email}>`).join('; ') || t('none')}`));
        result.append(el('p', '', `${t('escalation')}: ${data.escalation.email || t('none')} · ${t(`event_${data.escalation.status}`)} · ${core().date(data.escalation.at, true)}`)); output.replaceChildren(result);
      } catch (error) { if (version === sequence) reportError(output, error); }
      finally { if (version === sequence) preview.disabled = false; }
    });
    form.addEventListener('input', () => { sequence++; output.replaceChildren(el('p', 'workflow-help', t('draft_changed'))); preview.disabled = false; });
    box.append(preview, output); form.append(box);
  }
  async function directoryReview(type, id, proposedBody = null) {
    try {
      const fields = new URLSearchParams(proposedBody || ''); fields.set('type', type); fields.set('id', id); if (proposedBody) fields.set('proposed', '1');
      const data = await api('directory-impact', fields);
      const content = el('div'); content.append(el('p', 'workflow-help', t('directory_help')));
      const grid = table([t('certificate'), t('role')]);
      for (const cert of data.certificates) { const tr = el('tr'); tr.append(cell(`${cert.common_name} · ID ${cert.certificate_id}`), cell(t(`role_${cert.role}`))); grid.body.append(tr); }
      content.append(el('h4', '', t('before')), grid.wrap);
      if (data.proposal) {
        const summary = el('dl', 'details-data');
        keyValue(summary, t('before'), `${data.item.name || ''}${type === 'person' ? ` <${data.item.email}>` : ''}`);
        keyValue(summary, t('after'), `${data.proposal.name || ''}${type === 'person' ? ` <${data.proposal.email}>` : ''}`);
        keyValue(summary, t('memberships_before'), data.proposal.memberships_before.map(item => `${item.name}${item.email ? ` <${item.email}>` : ''}`).join('; ') || t('none'));
        keyValue(summary, t('memberships_after'), data.proposal.memberships_after.map(item => `${item.name}${item.email ? ` <${item.email}>` : ''}`).join('; ') || t('none'));
        content.append(summary, el('h4', '', t('after')));
        const projected = table([t('certificate'), t('role')]);
        for (const cert of data.proposal.certificates) { const tr = el('tr'); tr.append(cell(`${cert.common_name} · ID ${cert.certificate_id}`), cell(t(`role_${cert.role}`))); projected.body.append(tr); }
        content.append(projected.wrap);
      }
      content.append(el('p', '', t('pending_mail_count', [data.pending_mail.length])));
      const mail = el('ul'); for (const entry of data.pending_mail) mail.append(el('li', '', `${entry.recipient_email} · ${t(`mail_${entry.status}`)} · ID ${entry.certificate_id}`)); content.append(mail);
      if (data.monitor_recipients.length) content.append(el('p', 'workflow-help', t('monitor_recipients_count', [data.monitor_recipients.length])));
      return await modal(t('directory_title'), content, t('continue_change'));
    } catch (error) { core().message(error.message, true); return false; }
  }
  let agendaUpdate = null, templateUpdate = null, auditLoaded = false;
  function setupAgenda(host) {
    const panel = section(t('agenda_title'), t('agenda_help')); const filters = el('div', 'workflow-form-grid');
    const statusLabel = el('label', 'workflow-form-field', t('status')); const status = el('select'); core().appendOption(status, '', t('all_statuses'));
    ['requested', 'awaiting_ca', 'signed', 'delivered', 'installing', 'verified', 'retired'].forEach(value => core().appendOption(status, value, caseStatus(value))); statusLabel.append(status);
    const owner = core().formField(t('responsible'), 'search'); const overdueLabel = el('label', 'checkbox-field'); const overdue = el('input'); overdue.type = 'checkbox'; overdueLabel.append(overdue, el('span', '', t('only_overdue')));
    filters.append(statusLabel, owner.wrapper, overdueLabel); const results = el('div'); panel.append(filters, results); host.append(panel);
    const render = () => {
      const state = core().getState(), now = Date.now() / 1000;
      const jobs = (state.renewal_jobs || []).filter(job => (!status.value || job.status === status.value) && (!owner.input.value.trim() || (job.responsible || '').toLocaleLowerCase().includes(owner.input.value.trim().toLocaleLowerCase())) && (!overdue.checked || (!job.finished_at && ((job.planned_renewal_at && job.planned_renewal_at < now && !job.new_certificate_id) || (job.planned_install_at && job.planned_install_at < now)))));
      jobs.sort((a, b) => (Number(a.planned_install_at || a.planned_renewal_at || Number.MAX_SAFE_INTEGER) - Number(b.planned_install_at || b.planned_renewal_at || Number.MAX_SAFE_INTEGER)) || Number(b.id) - Number(a.id));
      const grid = table([t('case'), t('certificate'), t('status'), t('responsible'), t('planned_renewal'), t('planned_install'), t('actions')]);
      for (const job of jobs) {
        const late = !job.finished_at && ((job.planned_renewal_at && job.planned_renewal_at < now && !job.new_certificate_id) || (job.planned_install_at && job.planned_install_at < now));
        const label = el('div'); label.append(el('span', '', caseStatus(job.status))); if (late) label.append(el('strong', 'import-chain-warning', t('overdue')));
        const open = button(t('open_case'), () => { const cert = certById(job.old_certificate_id); if (cert) core().openRenewalCase(cert, job.id); });
        const tr = el('tr', late ? 'ops-row-error' : ''); tr.append(cell(`#${job.id}`), cell(`${job.old_common_name} · ID ${job.old_certificate_id} → ${job.new_certificate_id || '—'}`), cell(label), cell(job.responsible), cell(core().date(job.planned_renewal_at)), cell(core().date(job.planned_install_at)), cell(open)); grid.body.append(tr);
      }
      results.replaceChildren(el('p', 'workflow-help', t('case_count', [jobs.length])), jobs.length ? grid.wrap : el('p', '', t('no_cases')));
    };
    status.addEventListener('change', render); owner.input.addEventListener('input', render); overdue.addEventListener('change', render); render(); return render;
  }
  function setupTemplates(host) {
    const panel = section(t('templates_title'), t('templates_help')); const output = feedback();
    const form = el('form', 'workflow-form'); const grid = el('div', 'workflow-form-grid');
    const selectLabel = el('label', 'workflow-form-field', t('template')); const select = el('select'); selectLabel.append(select);
    const fields = { name: core().formField(t('template_name'), 'text', '', { required: true, maxLength: 120 }), thresholds: core().formField(t('thresholds'), 'text', '45,30,15,2,0', { required: true }), escalation_email: core().formField(t('escalation_email'), 'email'), escalation_name: core().formField(t('escalation_name'), 'text', '', { maxLength: 120 }), escalation_after_days: core().formField(t('escalation_delay'), 'number', '7', { required: true }) };
    fields.escalation_after_days.input.min = '0'; fields.escalation_after_days.input.max = '365';
    const enabledLabel = el('label', 'checkbox-field'); const enabled = el('input'); enabled.type = 'checkbox'; enabled.checked = true; enabledLabel.append(enabled, el('span', '', t('enabled')));
    grid.append(selectLabel, ...Object.values(fields).map(field => field.wrapper), enabledLabel); form.append(grid);
    const save = el('button', 'button button-primary', t('save_template')); save.type = 'submit';
    const remove = button(t('delete_template'), async () => {
      if (!select.value) return; const content = el('p', '', t('delete_template_confirm')); if (!await modal(t('delete_template'), content)) return;
      try { await api(`templates/${encodeURIComponent(select.value)}`, new URLSearchParams(), 'DELETE'); select.value = ''; await loadTemplates(); loadFields(); output.textContent = t('saved'); }
      catch (error) { output.textContent = error.message; }
    });
    form.append(el('div', 'action-row')); form.lastChild.append(save, remove, button(t('cancel'), () => { loadFields(); output.textContent = ''; }));
    const targets = el('div', 'ops-certificate-options'); const reviewOutput = el('div'); const apply = button(t('apply_template'), async () => {
      if (!plan) return; apply.disabled = true;
      try { const body = new URLSearchParams(plan.body); body.set('plan_hash', plan.hash); await api(`templates/${encodeURIComponent(plan.templateId)}/apply`, body); output.textContent = t('template_applied'); plan = null; reviewOutput.replaceChildren(); await core().refresh(true); }
      catch (error) { output.textContent = error.message; } finally { apply.disabled = !plan; }
    }, true);
    let templates = [], plan = null, dirty = false, reviewGeneration = 0; const choices = new Map();
    const invalidate = () => { reviewGeneration++; plan = null; apply.disabled = true; reviewOutput.replaceChildren(); };
    const loadFields = () => {
      const template = templates.find(item => String(item.id) === select.value);
      for (const [key, field] of Object.entries(fields)) field.input.value = template ? template[key] : key === 'thresholds' ? '45,30,15,2,0' : key === 'escalation_after_days' ? '7' : '';
      enabled.checked = template ? !!template.enabled : true; remove.disabled = !template; dirty = false; invalidate();
    };
    const loadTemplates = async (chosen = select.value) => {
      const data = await get('templates'); if (!panel.isConnected) return; templates = data.templates;
      select.replaceChildren(); core().appendOption(select, '', t('new_template')); templates.forEach(item => core().appendOption(select, item.id, item.name)); select.value = templates.some(item => String(item.id) === String(chosen)) ? String(chosen) : ''; remove.disabled = !select.value;
    };
    select.addEventListener('change', loadFields);
    form.addEventListener('input', event => { if (event.target !== select) { dirty = true; invalidate(); } });
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (!form.reportValidity()) return; save.disabled = true;
      const locked = [select, enabled, remove, ...Object.values(fields).map(field => field.input)]; locked.forEach(input => { input.disabled = true; });
      const body = new URLSearchParams(); for (const [key, field] of Object.entries(fields)) body.set(key, field.input.value.trim()); body.set('enabled', enabled.checked ? '1' : '0');
      try { const data = await api(select.value ? `templates/${encodeURIComponent(select.value)}` : 'templates', body, select.value ? 'PUT' : 'POST'); await loadTemplates(data.id); dirty = false; invalidate(); output.textContent = t('saved'); }
      catch (error) { output.textContent = error.message; } finally { save.disabled = false; locked.forEach(input => { input.disabled = false; }); remove.disabled = !select.value; }
    });
    const preview = button(t('review_template'), async () => {
      if (!select.value || dirty) { output.textContent = t('save_template_first'); return; }
      const body = new URLSearchParams(); for (const [id, choice] of choices) if (choice.select.checked) { body.append('certificate_id', id); if (choice.exclude.checked) body.append('exclude_id', id); }
      preview.disabled = true; invalidate(); const generation = reviewGeneration;
      try {
        const reviewedId = select.value; const data = await api(`templates/${encodeURIComponent(reviewedId)}/plan`, body);
        if (!panel.isConnected || generation !== reviewGeneration) return;
        const grid = table([t('certificate'), t('before'), t('after'), t('status')]);
        const describe = policy => `${policy.thresholds} · ${policy.enabled ? t('enabled') : t('paused')} · ${policy.escalation_name || ''} <${policy.escalation_email || '—'}> · ${policy.escalation_after_days} ${t('days')}`;
        for (const change of data.changes) { const tr = el('tr'); tr.append(cell(`${change.common_name} · ID ${change.certificate_id}`), cell(describe(change.before)), cell(change.excluded ? describe(change.before) : describe(change.after)), cell(change.excluded ? t('excluded') : t('will_update'))); grid.body.append(tr); }
        reviewOutput.append(grid.wrap); plan = { body: body.toString(), hash: data.plan_hash, templateId: reviewedId }; apply.disabled = false; output.textContent = t('review_ready');
      } catch (error) { output.textContent = error.message; } finally { preview.disabled = false; }
    });
    apply.disabled = true;
    const selectAll = button(t('select_all'), () => { for (const choice of choices.values()) { choice.select.checked = true; choice.exclude.disabled = false; } invalidate(); });
    const clear = button(t('clear_selection'), () => { for (const choice of choices.values()) { choice.select.checked = false; choice.exclude.checked = false; choice.exclude.disabled = true; } invalidate(); });
    panel.append(form, el('h4', '', t('template_targets')), el('p', 'workflow-help', t('exceptions_help'))); const actions = el('div', 'action-row'); actions.append(selectAll, clear); panel.append(actions, targets, preview, reviewOutput, apply, output); host.append(panel);
    const update = () => {
      const certificates = core().getState().certificates.filter(cert => !cert.is_ca && !cert.archived); const valid = new Set(certificates.map(cert => String(cert.id)));
      for (const [id, choice] of choices) if (!valid.has(id)) { choice.row.remove(); choices.delete(id); invalidate(); }
      for (const cert of certificates) if (!choices.has(String(cert.id))) {
        const row = el('div', 'ops-certificate-choice'); const label = el('label', 'checkbox-field'); const selected = el('input'); selected.type = 'checkbox'; label.append(selected, el('span', '', `${core().name(cert)} · ID ${cert.id} · ${core().date(cert.not_after)}`));
        const excludeLabel = el('label', 'checkbox-field'); const exclude = el('input'); exclude.type = 'checkbox'; exclude.disabled = true; excludeLabel.append(exclude, el('span', '', t('exclude_exception')));
        selected.addEventListener('change', () => { exclude.disabled = !selected.checked; if (!selected.checked) exclude.checked = false; invalidate(); }); exclude.addEventListener('change', invalidate);
        row.append(label, excludeLabel); targets.append(row); choices.set(String(cert.id), { row, select: selected, exclude });
      }
    };
    window.addEventListener('certificate-language-change', event => { if (dirty || plan) { event.preventDefault(); output.textContent = t('unsaved_template'); } });
    window.addEventListener('beforeunload', event => { if (dirty || plan) { event.preventDefault(); event.returnValue = ''; } });
    loadTemplates().catch(error => { output.textContent = error.message; }); update(); return update;
  }
  function setupAudit(host) {
    const panel = section(t('audit_title'), t('audit_help')); panel.id = 'ops-audit-panel'; const output = el('div'); let loaded = false;
    const load = async () => {
      try {
        const rows = await core().request('/api/audit'); const grid = table([t('date'), t('entity'), t('action'), t('details')]);
        for (const entry of rows) { const tr = el('tr'); tr.append(cell(core().date(entry.created_at, true)), cell(`${entry.entity_type} #${entry.entity_id}`), cell(entry.action), cell(entry.detail)); grid.body.append(tr); }
        output.replaceChildren(rows.length ? grid.wrap : el('p', '', t('no_history'))); loaded = true;
      } catch (error) { reportError(output, error); }
    };
    panel.append(button(t('load_history'), load), output); host.append(panel); return () => { if (loaded) load(); };
  }
  function render() {
    const c = core(); if (!c) return;
    if (c.currentPage === 'renewals') { const host = c.byId('renewals-content'); if (host) { if (!agendaUpdate) agendaUpdate = setupAgenda(host); else agendaUpdate(); } }
    if (c.currentPage === 'reminders') { const host = c.byId('reminders'); if (host) { if (!templateUpdate) templateUpdate = setupTemplates(host); else templateUpdate(); } }
    if (c.currentPage === 'workflow' && !auditLoaded) { const host = c.byId('workflow'); if (host) { setupAudit(host); auditLoaded = true; } }
  }
  window.CertificateOperationsUI = { render, compareChoice, renewal, reminderPreview, directoryReview };
})();
