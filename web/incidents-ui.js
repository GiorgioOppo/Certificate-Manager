(() => {
  'use strict';
  const t = (key, values) => window.CertificateI18n.t(`incident.${key}`, values);
  let core, root, currentState, incidentState = { monitor_options: [], claims: [] };
  let fetching = null, signature = '', optionsForm, claimForm, optionsSelect, eventSelect;
  let optionFields, claimFields, optionsSummary, claimSummary, detail, feedback;
  const optionDrafts = new Map(), claimDrafts = new Map();
  const statusLabels = () => Object.fromEntries(['pending','ok','unreachable','tls_error','changed','verification_error','error'].map(key => [key,t(`technical_${key}`)]));
  const localDate = value => {
    if (!Number(value)) return '';
    const d = new Date(Number(value) * 1000);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0,16);
  };
  const epoch = value => value ? Math.floor(new Date(value).getTime()/1000) : 0;
  const node = (tag, classes, text) => core.element(tag, classes, text);
  function selectField(label, id) {
    const wrapper = node('label','workflow-form-field');
    const select = node('select'); select.id = id; select.required = true;
    wrapper.append(node('span','',label),select); return {wrapper,input:select};
  }
  function tell(text,error=false) { feedback.hidden=!text;feedback.textContent=text;feedback.classList.toggle('error',error); }
  function monitor() { return (currentState.monitors||[]).find(item=>String(item.id)===optionsSelect.value); }
  function event() { return (currentState.monitor_events||[]).find(item=>String(item.id)===eventSelect.value); }
  function configureForm() {
    const data = node('section','ext-section'); data.append(node('h3','',t('options_title')),node('p','',t('options_help')));
    optionsForm=node('form','workflow-form ext-form');
    const choose=selectField(t('service'),'incident-monitor');optionsSelect=choose.input;
    const threshold=core.formField(t('threshold'),'number','1',{required:true});threshold.input.min='1';threshold.input.max='10';threshold.input.step='1';
    const start=core.formField(t('maintenance_start'),'datetime-local');
    const end=core.formField(t('maintenance_end'),'datetime-local');
    const reason=core.formField(t('maintenance_reason'),'text','',{maxLength:1000,wide:true});
    optionFields={threshold:threshold.input,start:start.input,end:end.input,reason:reason.input};
    optionsSummary=node('p','ext-note');
    optionsForm.append(choose.wrapper,threshold.wrapper,start.wrapper,end.wrapper,reason.wrapper);
    const actions=node('div','workflow-form-actions');const save=core.action(t('save_options'),()=>optionsForm.requestSubmit(),true);
    const clear=core.action(t('clear_maintenance'),()=>{start.input.value='';end.input.value='';reason.input.value='';saveOptionDraft();});actions.append(save,clear);
    optionsForm.append(actions,optionsSummary);data.append(optionsForm);
    optionsSelect.addEventListener('change',fillOptions);
    for(const input of Object.values(optionFields))input.addEventListener('input',saveOptionDraft);
    optionsForm.addEventListener('submit',async e=>{
      e.preventDefault();if(!optionsForm.reportValidity()||!optionsSelect.value)return;
      const {threshold,start,end,reason}=optionFields;
      if((start.value&&!end.value)||(!start.value&&end.value)|| (start.value&&epoch(end.value)<=epoch(start.value))){tell(t('invalid_window'),true);return;}
      const body=new URLSearchParams({monitor_id:optionsSelect.value,failure_threshold:threshold.value,maintenance_start:String(epoch(start.value)),maintenance_end:String(epoch(end.value)),maintenance_reason:reason.value});
      await mutate('/api/incidents/monitor-options',body,optionsForm,()=>optionDrafts.delete(optionsSelect.value),t('options_saved'));
    });
    return data;
  }
  function claimEditor() {
    const data=node('section','ext-section');data.append(node('h3','',t('claims_title')),node('p','',t('claims_help')));
    claimForm=node('form','workflow-form ext-form');const choose=selectField(t('event'),'incident-event');eventSelect=choose.input;
    const responsible=core.formField(t('responsible'),'text','',{required:true,maxLength:120});
    const notes=core.formField(t('notes'),'textarea','',{wide:true,maxLength:4000});
    const due=core.formField(t('due_at'),'datetime-local');const status=selectField(t('claim_status'),'incident-claim-status');
    ['open','investigating','resolved'].forEach(value=>core.appendOption(status.input,value,t(`claim_${value}`)));
    claimFields={responsible:responsible.input,notes:notes.input,due:due.input,status:status.input};
    claimSummary=node('p','ext-note');detail=node('div','ext-detail');
    claimForm.append(choose.wrapper,responsible.wrapper,status.wrapper,due.wrapper,notes.wrapper);
    const actions=node('div','workflow-form-actions');actions.append(core.action(t('save_claim'),()=>claimForm.requestSubmit(),true),core.action(t('event_details'),showEventDetails));
    claimForm.append(actions,claimSummary);data.append(claimForm,detail);
    eventSelect.addEventListener('change',()=>{detail.replaceChildren();fillClaim();});
    for(const input of Object.values(claimFields))input.addEventListener('input',saveClaimDraft);
    claimForm.addEventListener('submit',async e=>{
      e.preventDefault();if(!claimForm.reportValidity()||!eventSelect.value)return;
      const v=claimFields;const body=new URLSearchParams({responsible:v.responsible.value,notes:v.notes.value,due_at:String(epoch(v.due.value)),status:v.status.value});
      await mutate(`/api/incidents/events/${encodeURIComponent(eventSelect.value)}/claim`,body,claimForm,()=>claimDrafts.delete(eventSelect.value),t('claim_saved'));
    });
    return data;
  }
  function mount() {
    if(root)return;
    root=node('section','ext-panel');root.id='incident-workflows';root.append(node('h2','',t('title')));
    feedback=node('p','message');feedback.hidden=true;feedback.setAttribute('role','status');feedback.setAttribute('aria-live','polite');
    root.append(feedback,configureForm(),claimEditor());
    document.getElementById('monitoring').append(root);
  }
  function saveOptionDraft(){optionDrafts.set(optionsSelect.value,Object.fromEntries(Object.entries(optionFields).map(([key,input])=>[key,input.value])));}
  function saveClaimDraft(){claimDrafts.set(eventSelect.value,Object.fromEntries(Object.entries(claimFields).map(([key,input])=>[key,input.value])));}
  function fillOptions() {
    const m=monitor();const data=incidentState.monitor_options.find(item=>String(item.monitor_id)===optionsSelect.value)||{};
    const draft=optionDrafts.get(optionsSelect.value)||{threshold:String(data.failure_threshold||1),start:localDate(data.maintenance_start),end:localDate(data.maintenance_end),reason:data.maintenance_reason||''};
    for(const [key,input] of Object.entries(optionFields))input.value=draft[key];
    optionsForm.querySelectorAll('button,input').forEach(input=>input.disabled=!m);
    updateOptionsSummary();
  }
  function updateOptionsSummary() {
    const m=monitor();if(!m){optionsSummary.textContent=t('no_monitors');return;}
    const data=incidentState.monitor_options.find(item=>String(item.monitor_id)===String(m.id))||{};
    const pieces=[t('technical_result',[statusLabels()[m.last_status]||m.last_status]),t('failure_count',[Number(data.consecutive_failures)||0,Number(data.failure_threshold)||1])];
    const now=Number(currentState.now)||Date.now()/1000;
    if(Number(data.maintenance_end)>now&&Number(data.maintenance_start)<=now)pieces.push(t('maintenance_active',[core.date(data.maintenance_end,true)]));
    else if(Number(data.maintenance_start)>now)pieces.push(t('maintenance_scheduled',[core.date(data.maintenance_start,true),core.date(data.maintenance_end,true)]));
    if(data.post_maintenance_check)pieces.push(t('fresh_check_pending'));
    optionsSummary.textContent=pieces.join(' · ');
  }
  function fillClaim() {
    const selected=event();const data=incidentState.claims.find(item=>String(item.event_id)===eventSelect.value)||{};
    const draft=claimDrafts.get(eventSelect.value)||{responsible:data.responsible||'',notes:data.notes||'',due:localDate(data.due_at),status:data.status||'open'};
    for(const [key,input] of Object.entries(claimFields))input.value=draft[key];
    claimForm.querySelectorAll('button,input,textarea').forEach(input=>input.disabled=!selected);claimFields.status.disabled=!selected;
    updateClaimSummary();
  }
  function updateClaimSummary(){
    const selected=event();if(!selected){claimSummary.textContent=t('no_events');return;}
    const m=(currentState.monitors||[]).find(item=>String(item.id)===String(selected.monitor_id));
    const claim=incidentState.claims.find(item=>String(item.event_id)===String(selected.id));
    claimSummary.textContent=[t('technical_result',[statusLabels()[m?.last_status]||m?.last_status||'—']),t('claim_result',[claim?t(`claim_${claim.status}`):t('unassigned')]),t('claim_does_not_recover')].join(' · ');
  }
  async function mutate(path,body,form,onSuccess,text){
    if(form.dataset.busy)return;form.dataset.busy='true';form.querySelectorAll('button').forEach(button=>button.disabled=true);tell('');
    try{await core.request(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});onSuccess();await core.refresh();await load();fillOptions();fillClaim();tell(text);}
    catch(error){tell(error.message,true);}
    finally{delete form.dataset.busy;form.querySelectorAll('button').forEach(button=>button.disabled=false);}
  }
  async function showEventDetails(){
    const selected=event();if(!selected)return;
    try{
      const result=await core.request(`/api/incidents/events/${encodeURIComponent(selected.id)}`);const data=result.events[0];if(!data)return;
      detail.replaceChildren();detail.append(node('h4','',t('event_details')),node('p','',`${data.target} · ${core.date(data.created_at,true)}`));
      const list=node('dl','details-data');for(const [key,value] of [[t('technical_result_label'),statusLabels()[data.last_status]||data.last_status],[t('claim_status'),data.claim_status?t(`claim_${data.claim_status}`):t('unassigned')],[t('expected_fingerprint'),data.expected_fingerprint],[t('observed_fingerprint'),data.observed_fingerprint||'—']])list.append(node('dt','',key),node('dd','',value));detail.append(list);
      if(data.kind==='changed'){
        detail.append(node('p','',t('changed_help')));
        const m=(currentState.monitors||[]).find(item=>String(item.id)===String(data.monitor_id));
        const link=node('a','button button-secondary',t('acquire_compare'));link.href=window.CertificateI18n.localURL(`/verifica?certificate_id=${encodeURIComponent(m?.certificate_id||'')}&target=${encodeURIComponent(data.target)}&event_id=${encodeURIComponent(data.id)}#remote-check`);detail.append(link);
      }
    }catch(error){tell(error.message,true);}
  }
  function updateSelect(select,items,label){const current=select.value;select.replaceChildren();core.appendOption(select,'',t('choose'));for(const item of items)core.appendOption(select,item.id,label(item));select.value=items.some(item=>String(item.id)===current)?current:items.length?String(items[0].id):'';}
  function update(){
    const nextSignature=JSON.stringify([(currentState.monitors||[]).map(m=>[m.id,m.target]),(currentState.monitor_events||[]).map(e=>[e.id,e.kind,e.target])]);
    const focused = optionsForm.contains(document.activeElement)||claimForm.contains(document.activeElement);
    if(nextSignature!==signature&&focused){updateOptionsSummary();updateClaimSummary();return;}
    if(nextSignature!==signature){signature=nextSignature;updateSelect(optionsSelect,currentState.monitors||[],m=>m.target);updateSelect(eventSelect,currentState.monitor_events||[],e=>`${core.date(e.created_at,true)} · ${statusLabels()[e.kind]||e.kind} · ${e.target}`);fillOptions();fillClaim();}
    else {updateOptionsSummary();updateClaimSummary();if(!optionDrafts.has(optionsSelect.value)&&!optionsForm.contains(document.activeElement))fillOptions();if(!claimDrafts.has(eventSelect.value)&&!claimForm.contains(document.activeElement))fillClaim();}
  }
  async function load(){if(fetching)return fetching;fetching=core.request('/api/incidents/state').then(data=>{incidentState=data;update();}).catch(error=>tell(error.message,true)).finally(()=>fetching=null);return fetching;}
  function render(state){core=window.CertificateCore;if(!core||core.currentPage!=='monitoring')return;currentState=state;mount();update();if(state.incidents){incidentState=state.incidents;update();}else void load();}
  window.CertificateIncidentsUI={render};
})();
