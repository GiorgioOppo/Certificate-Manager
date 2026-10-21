(() => {
  'use strict';
  const c = window.CertificateCore;
  if (!c) return;
  const t = (key, values) => c.flow('x_' + key, values);
  const el = c.element;
  const post = (path, body) => c.request(path, { method: 'POST', body });
  function table(headers, rows) {
    const wrap = el('div', 'ext-table-scroll');
    const node = el('table', 'ext-table');
    const head = el('thead'), tr = el('tr');
    for (const header of headers) { const th = el('th', '', header); th.scope = 'col'; tr.append(th); }
    head.append(tr); const body = el('tbody');
    for (const values of rows) { const row = el('tr'); for (const value of values) { const cell = el('td'); if (value instanceof Node) cell.append(value); else cell.textContent = value == null || value === '' ? '—' : String(value); row.append(cell); } body.append(row); }
    node.append(head, body); wrap.append(node); return wrap;
  }
  function modal(title, content, confirmLabel = t('confirm'), validate = () => true) {
    return new Promise(resolve => {
      const dialog = el('dialog', 'dialog ext-dialog');
      const heading = el('h2', '', title); heading.id = 'operation-review-heading'; dialog.setAttribute('aria-labelledby', heading.id);
      const footer = el('div', 'dialog-footer'); let done = false;
      const finish = value => { if(done)return;done=true;dialog.close();dialog.remove();resolve(value); };
      footer.append(c.action(t('cancel'), () => finish(false)), c.action(confirmLabel, () => {if(validate())finish(true);}, true));
      dialog.append(heading, content, footer);dialog.addEventListener('cancel', event => {event.preventDefault();finish(false);});
      document.body.append(dialog);dialog.showModal();
    });
  }
  function download(filename, text, mime = 'text/csv;charset=utf-8') {
    const url = URL.createObjectURL(new Blob([text], {type:mime}));const link = el('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  window.CertificateUI = { table, modal, download };
  window.CertificateEnhancements = {
    render(state) { window.CertificateOperationsUI?.render(state); window.CertificateIncidentsUI?.render(state); if(c.currentPage==='import') pollBatches(); },
    compareChoice(...args) { window.CertificateOperationsUI?.compareChoice(...args); },
    renewal(...args) { window.CertificateOperationsUI?.renewal(...args); },
    reminderPreview(...args) { window.CertificateOperationsUI?.reminderPreview(...args); },
    directoryReview(...args) { return window.CertificateOperationsUI ? window.CertificateOperationsUI.directoryReview(...args) : Promise.resolve(false); }
    ,remote: remoteGuidance
  };
  function remoteGuidance(result, previousId) {
    const existing=c.byId('remote-renewal-guidance');if(existing)existing.remove();
    if(!previousId||!result?.certificate||result.comparison!=='changed')return;
    const host=c.byId('remote-result');if(!host)return;const panel=el('section','ext-panel');panel.id='remote-renewal-guidance';panel.append(el('h3','',t('changed_workflow')),el('p','workflow-help',t('changed_help')));
    const replacement=c.getState().certificates.find(cert=>cert.fingerprint===result.certificate.fingerprint);
    const previous=c.getState().certificates.find(cert=>String(cert.id)===String(previousId));
    const output=el('p');output.setAttribute('role','status');
    if(!replacement)panel.append(c.action(t('import_candidate'),()=>c.importRemote()));
    else {
      const linked=(c.getState().renewal_jobs||[]).find(job=>String(job.old_certificate_id)===String(previousId)&&String(job.new_certificate_id)===String(replacement.id));
      if(linked)panel.append(c.action(c.flow('case_number',[linked.id]),()=>c.openRenewalCase(previous,linked.id)));
      else {
        const compare=c.action(t('compare_and_link'),async()=>{
          compare.disabled=true;
          try {
            const data=await post('/api/operations/compare',new URLSearchParams({old_certificate_id:previousId,new_certificate_id:replacement.id}));
            const content=el('div');content.append(el('p',data.candidate?'workflow-help':'import-chain-warning',data.candidate?t('compatible'):t('incompatible')));
            content.append(table([t('details'),t('previous'),t('replacement')],['common_name','sans','issuer','root_ca','intermediate_ca','not_before','not_after','fingerprint'].map(field=>[field,['not_before','not_after'].includes(field)?c.date(previous?.[field]):previous?.[field],['not_before','not_after'].includes(field)?c.date(replacement[field]):replacement[field]])));
            if(await modal(t('compare_and_link'),content,data.candidate&&result.verified?t('confirm_link'):t('close')) && data.candidate&&result.verified){
              await post('/api/renewal-jobs',new URLSearchParams({old_certificate_id:previousId,new_certificate_id:replacement.id}));await c.refresh(true);remoteGuidance(result,previousId);
            }
          }catch(error){output.textContent=error.message;}finally{compare.disabled=false;}
        });panel.append(compare);
      }
    }
    panel.append(output);host.append(panel);
  }
  let batchBusy = false;
  let activeBatch = null;
  let lastBatchSignature = '';
  function batchStatus(value) { return t('batch_' + value); }
  function describePlan(plan) {
    const content=el('div'); if(!plan)return content;
    const cert=plan.certificate || {};
    content.append(el('p','',`${cert.common_name || ''} · ${cert.fingerprint || ''}`));
    content.append(el('p','workflow-help',`${window.CertificateI18n.t('ops.root_ca')}: ${cert.root_ca || '—'} · ${window.CertificateI18n.t('ops.intermediate_ca')}: ${cert.intermediate_ca || '—'} · ${c.date(cert.not_before)} → ${c.date(cert.not_after)}`));
    content.append(el('p','',`${t(cert.new ? 'new_certificate' : 'existing_certificate')} · ${t(plan.monitor?.created ? 'new_monitor' : 'existing_monitor')}`));
    content.append(table([t('role'),t('email'),t('existing_name'),t('incoming_name'),t('change'),t('affected_certificates')],(plan.contacts||[]).map(contact=>[c.msg(contact.role==='technical'?'m_a6da5b872c69':'m_3ce1f3185cbc'),contact.email,contact.existing_name,contact.name,t('change_'+contact.action),contact.affected_certificates||0])));
    return content;
  }
  async function reviewBatch(batch) {
    const content=el('div');content.append(el('p','workflow-help',t('atomic_help')));
    const selection=[];
    for(const row of batch.rows || []) {
      const section=el('section','ext-review-row'); const label=el('label','checkbox-field');const checkbox=el('input');checkbox.type='checkbox';checkbox.checked=row.status==='ready';checkbox.disabled=row.status!=='ready';
      label.append(checkbox,el('strong','',`${t('row')} ${row.line} · ${row.target} · ${batchStatus(row.status)}`));section.append(label);
      selection.push({row,checkbox});if(row.error)section.append(el('p','import-chain-warning',row.error));section.append(describePlan(row.plan));content.append(section);
    }
    const policyLabel=el('label','workflow-form-field',t('name_conflicts'));const policy=el('select');
    const hasConflicts=(batch.rows||[]).some(row=>row.status==='ready'&&Number(row.plan?.conflicts)>0);
    if(hasConflicts){c.appendOption(policy,'',t('choose_policy'));policy.required=true;}
    c.appendOption(policy,'keep',t('keep_names'));c.appendOption(policy,'update',t('update_names'));policyLabel.append(policy);const warning=el('p','import-chain-warning');warning.setAttribute('role','alert');content.append(policyLabel,warning);
    if(!await modal(t('review_changes'),content,t('approve_batch'),()=>{if(!selection.some(item=>item.checkbox.checked&&!item.checkbox.disabled)){warning.textContent=t('select_rows');return false;}return policy.reportValidity();}))return;
    const selected=selection.filter(item=>item.checkbox.checked&&!item.checkbox.disabled);if(!selected.length){c.message(t('select_rows'),true);return;}
    const body=new URLSearchParams({review_token:batch.review_token,name_policy:policy.value});for(const item of selected)body.append('row_id',item.row.id);
    await post(`/api/inventory/batches/${batch.id}/start`,body);c.message(t('background_help'));await pollBatches(true);
  }
  async function openBatch(id) {
    activeBatch=id;const batch=await c.request(`/api/inventory/batches/${id}`);
    const content=el('div');content.append(el('p','',`${t('batch')} ${batch.id} · ${batchStatus(batch.status)}`));
    content.append(table([t('row'),t('url'),t('status'),t('details')],(batch.rows||[]).map(row=>[row.line,row.target,batchStatus(row.status),row.error||row.certificate_id&&`ID ${row.certificate_id}`])));
    const actions=el('div','action-row');
    actions.append(c.action(t('report'),()=>downloadBatchReport(batch)),c.action(t('failed_csv'),()=>downloadBatchReport(batch,true)));
    content.append(actions);
    if(await modal(t('batch_details'),content,['review','paused'].includes(batch.status)?t('review_changes'):t('close'))) {
      if(['review','paused'].includes(batch.status))await reviewBatch(batch);
    }
  }
  function csvCell(value, protect=false) { let text=String(value??'');if(protect&&/^[=+\-@\t\r]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"'; }
  function downloadBatchReport(batch, failedOnly=false) {
    const fields=['url','business_name','business_email','technical_name','technical_email'];
    const headers=failedOnly?fields:['line',...fields,'status','certificate_id','error'];
    const rows=(batch.rows||[]).filter(row=>!failedOnly||row.status!=='imported').map(row=>{
      const payload=new URLSearchParams(row.payload||'');const contacts={business:[],technical:[]};const roles=payload.getAll('role'),names=payload.getAll('name'),emails=payload.getAll('email');roles.forEach((role,index)=>contacts[role]?.push({name:names[index]||'',email:emails[index]||''}));
      const values=[row.target,...['business','technical'].flatMap(role=>[contacts[role].map(p=>p.name).join(';'),contacts[role].map(p=>p.email).join(';')])];
      return failedOnly?values:[row.line,...values,batchStatus(row.status),row.certificate_id||'',row.error||''];
    });
    download(`certificate-manager-lotto-${batch.id}${failedOnly?'-correggere':''}.csv`,'\uFEFF'+[headers,...rows].map(row=>row.map(value=>csvCell(value,!failedOnly)).join(',')).join('\r\n')+'\r\n');
  }
  async function pollBatches(force=false) {
    const mount=c.byId('inventory-batches');if(!mount||batchBusy||!c.getState().csrf_token)return;batchBusy=true;
    try {
      const result=await c.request('/api/inventory/batches');const batches=result.batches||[];
      const signature=JSON.stringify(batches);if(!force&&signature===lastBatchSignature)return;lastBatchSignature=signature;
      const details=el('details','ext-panel panel');details.open=true;details.append(el('summary','',t('saved_batches')),el('p','workflow-help',t('background_help')));
      details.append(table([t('batch'),t('status'),t('progress'),t('updated'),t('actions')],batches.map(batch=>{
        const buttons=el('div','action-row');buttons.append(c.action(t('open'),()=>openBatch(batch.id).catch(error=>c.message(error.message,true))));
        if(['draft','review','paused'].includes(batch.status))buttons.append(c.action(t('replan'),async()=>{try{await post(`/api/inventory/batches/${batch.id}/plan`,new URLSearchParams());await pollBatches(true);}catch(error){c.message(error.message,true);}}));
        if(['planning','running'].includes(batch.status))buttons.append(c.action(t('pause'),async()=>{try{await post(`/api/inventory/batches/${batch.id}/pause`,new URLSearchParams());await pollBatches(true);}catch(error){c.message(error.message,true);}}));
        return [batch.name||batch.id,batchStatus(batch.status),`${batch.imported||0}/${batch.row_count} · ${batch.ready_count||0} ${t('batch_ready')} · ${batch.errors||0} ${t('batch_error')}`,c.date(batch.updated_at,true),buttons];
      })));
      mount.replaceChildren(details);
      if(activeBatch)window.dispatchEvent(new CustomEvent('certificate-batch-update',{detail:await c.request(`/api/inventory/batches/${activeBatch}`)}));
    } catch(error) { c.message(error.message,true); } finally { batchBusy=false; }
  }
  window.CertificateInventoryUI = {
    describePlan, reviewBatch, csvCell, download,
    async prepare(rows) {
      const body=new URLSearchParams({rows:String(rows.length),name:new Date().toLocaleString(window.CertificateI18n.locale)});
      rows.forEach((row,index)=>{body.set(`row_${index}_target`,row.target);body.set(`row_${index}_line`,row.line);const payload=new URLSearchParams({target:row.target});for(const contact of row.contacts||[]){payload.append('role',contact.role);payload.append('name',contact.name||'');payload.append('email',contact.email);}body.set(`row_${index}_payload`,payload.toString());});
      let batch=await post('/api/inventory/batches',body);activeBatch=batch.id;
      batch=await post(`/api/inventory/batches/${batch.id}/plan`,new URLSearchParams());await pollBatches(true);return batch;
    },
    async current(id) {return c.request(`/api/inventory/batches/${id}`);},
    async refresh() {await pollBatches(true);}
  };
  if(c.currentPage==='import')setInterval(()=>pollBatches(),2500);
  document.addEventListener('DOMContentLoaded',()=>{if(c.getState().csrf_token)window.CertificateEnhancements.render(c.getState());});
})();
