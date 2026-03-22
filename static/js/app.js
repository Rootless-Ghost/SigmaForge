/* ══════════════════════════════════════════════
   SigmaForge — Application JavaScript
   ══════════════════════════════════════════════ */

// ── State ─────────────────────────────────
let selectedTechniques = [];
let currentRuleYaml = '';
let currentConversions = {};
let validatorConversions = {};
let selectionCounter = 0;
let filterCounter = 0;

// ── Init ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initMITRE();
    initLogSourceFields();
    initSIEMTabs();
    refreshLibrary();

    // Update fields when log source changes
    document.getElementById('rule-logsource').addEventListener('change', () => {
        updateAllFieldDropdowns();
    });
});

// ── Tab Navigation ────────────────────────
function initTabs() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');

            if (btn.dataset.tab === 'library') refreshLibrary();
        });
    });
}

// ── SIEM Output Tabs ──────────────────────
function initSIEMTabs() {
    document.querySelectorAll('.output-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.target || 'main';
            const backend = tab.dataset.backend;
            const container = tab.closest('.output-tabs') || tab.parentElement;

            container.querySelectorAll('.output-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            if (target === 'validator') {
                document.getElementById('validator-siem-output').textContent =
                    validatorConversions[backend] || 'No conversion available';
            } else {
                document.getElementById('output-siem').textContent =
                    currentConversions[backend] || 'No conversion available';
            }
        });
    });
}

// ── MITRE ATT&CK ─────────────────────────
function initMITRE() {
    renderMITREList();

    document.getElementById('mitre-tactic-filter').addEventListener('change', renderMITREList);
    document.getElementById('mitre-search').addEventListener('input', renderMITREList);
}

function renderMITREList() {
    const container = document.getElementById('mitre-list');
    const tacticFilter = document.getElementById('mitre-tactic-filter').value;
    const search = document.getElementById('mitre-search').value.toLowerCase();

    let html = '';
    for (const [techId, info] of Object.entries(MITRE_MAP)) {
        if (tacticFilter && info.tactic !== tacticFilter) continue;
        if (search && !techId.toLowerCase().includes(search) &&
            !info.name.toLowerCase().includes(search)) continue;

        const checked = selectedTechniques.includes(techId) ? 'checked' : '';
        const tacticLabel = info.tactic.replace(/-/g, ' ');

        html += `
            <label class="mitre-item">
                <input type="checkbox" value="${techId}" ${checked}
                       onchange="toggleTechnique('${techId}')">
                <span class="tech-id">${techId}</span>
                <span class="tech-name">${info.name}</span>
                <span class="tech-tactic">${tacticLabel}</span>
            </label>
        `;
    }

    container.innerHTML = html || '<div class="placeholder" style="padding:0.5rem">No techniques match your filter</div>';
}

function toggleTechnique(techId) {
    const idx = selectedTechniques.indexOf(techId);
    if (idx === -1) {
        selectedTechniques.push(techId);
    } else {
        selectedTechniques.splice(idx, 1);
    }
    updateSelectedTechniques();
}

function removeTechnique(techId) {
    selectedTechniques = selectedTechniques.filter(t => t !== techId);
    updateSelectedTechniques();
    renderMITREList();
}

function updateSelectedTechniques() {
    const container = document.getElementById('selected-techniques');
    if (selectedTechniques.length === 0) {
        container.innerHTML = '<span class="label">Selected:</span><span class="none-selected">None selected</span>';
        return;
    }

    let html = '<span class="label">Selected:</span>';
    for (const techId of selectedTechniques) {
        const info = MITRE_MAP[techId];
        const name = info ? info.name : techId;
        html += `
            <span class="technique-tag" title="${name}">
                ${techId}
                <span class="remove-tech" onclick="removeTechnique('${techId}')">×</span>
            </span>
        `;
    }
    container.innerHTML = html;
}

// ── Log Source Fields ────────────────────
function initLogSourceFields() {
    updateAllFieldDropdowns();
}

function getFieldsForLogSource() {
    const logSource = document.getElementById('rule-logsource').value;
    const src = LOG_SOURCES[logSource];
    return src ? (src.fields || []) : [];
}

function updateAllFieldDropdowns() {
    const fields = getFieldsForLogSource();
    document.querySelectorAll('.field-name').forEach(select => {
        const currentVal = select.value;
        select.innerHTML = '<option value="">Select field...</option>';
        fields.forEach(f => {
            select.innerHTML += `<option value="${f}" ${f === currentVal ? 'selected' : ''}>${f}</option>`;
        });
        // Allow custom field
        select.innerHTML += '<option value="__custom__">Custom field...</option>';
    });
}

function populateFieldDropdown(select) {
    const fields = getFieldsForLogSource();
    select.innerHTML = '<option value="">Select field...</option>';
    fields.forEach(f => {
        select.innerHTML += `<option value="${f}">${f}</option>`;
    });
    select.innerHTML += '<option value="__custom__">Custom field...</option>';

    select.addEventListener('change', function() {
        if (this.value === '__custom__') {
            const customField = prompt('Enter custom field name:');
            if (customField) {
                const opt = document.createElement('option');
                opt.value = customField;
                opt.textContent = customField;
                this.insertBefore(opt, this.lastElementChild);
                this.value = customField;
            } else {
                this.value = '';
            }
        }
    });
}

// ── Selection / Filter Management ─────────
function addSelection() {
    selectionCounter++;
    const name = `selection_${selectionCounter}`;
    addDetectionBlock(name, 'selection');
}

function addFilter() {
    filterCounter++;
    const name = `filter_${filterCounter}`;
    addDetectionBlock(name, 'filter');
}

function addDetectionBlock(name, type) {
    const container = document.getElementById('selections-container');
    const badgeClass = type === 'selection' ? 'badge-selection' : 'badge-filter';
    const typeLabel = type.toUpperCase();

    const div = document.createElement('div');
    div.className = 'selection-block';
    div.dataset.type = type;
    div.dataset.name = name;
    div.innerHTML = `
        <div class="selection-header">
            <input type="text" class="selection-name" value="${name}" placeholder="${type} name">
            <span class="selection-type-badge ${badgeClass}">${typeLabel}</span>
            <button class="btn-icon" onclick="addFieldToSelection(this)" title="Add field">+</button>
            <button class="btn-icon btn-danger" onclick="removeSelection(this)" title="Remove">×</button>
        </div>
        <div class="selection-fields">
            <div class="field-row">
                <select class="field-name"><option value="">Select field...</option></select>
                <select class="field-modifier">
                    <option value="">No modifier</option>
                    <option value="contains">contains</option>
                    <option value="startswith">startswith</option>
                    <option value="endswith">endswith</option>
                    <option value="re">regex</option>
                    <option value="all">all</option>
                    <option value="base64">base64</option>
                    <option value="cidr">cidr</option>
                </select>
                <textarea class="field-values" rows="1" placeholder="value1, value2 (comma-separated)"></textarea>
                <button class="btn-icon btn-danger" onclick="removeField(this)" title="Remove field">×</button>
            </div>
        </div>
    `;

    container.appendChild(div);
    populateFieldDropdown(div.querySelector('.field-name'));
    updateConditionHint();
}

function addFieldToSelection(btn) {
    const block = btn.closest('.selection-block');
    const fieldsContainer = block.querySelector('.selection-fields');

    const row = document.createElement('div');
    row.className = 'field-row';
    row.innerHTML = `
        <select class="field-name"><option value="">Select field...</option></select>
        <select class="field-modifier">
            <option value="">No modifier</option>
            <option value="contains">contains</option>
            <option value="startswith">startswith</option>
            <option value="endswith">endswith</option>
            <option value="re">regex</option>
            <option value="all">all</option>
            <option value="base64">base64</option>
            <option value="cidr">cidr</option>
        </select>
        <textarea class="field-values" rows="1" placeholder="value1, value2 (comma-separated)"></textarea>
        <button class="btn-icon btn-danger" onclick="removeField(this)" title="Remove field">×</button>
    `;

    fieldsContainer.appendChild(row);
    populateFieldDropdown(row.querySelector('.field-name'));
}

function removeSelection(btn) {
    const block = btn.closest('.selection-block');
    block.remove();
    updateConditionHint();
}

function removeField(btn) {
    const row = btn.closest('.field-row');
    const container = row.closest('.selection-fields');
    if (container.querySelectorAll('.field-row').length > 1) {
        row.remove();
    }
}

function updateConditionHint() {
    const names = [];
    document.querySelectorAll('.selection-block').forEach(block => {
        const name = block.querySelector('.selection-name').value;
        if (name) names.push(name);
    });

    const condInput = document.getElementById('rule-condition');
    if (names.length === 1) {
        condInput.value = names[0];
    } else if (names.length > 1) {
        const selections = names.filter((_, i) => {
            const block = document.querySelectorAll('.selection-block')[i];
            return block && block.dataset.type === 'selection';
        });
        const filters = names.filter((_, i) => {
            const block = document.querySelectorAll('.selection-block')[i];
            return block && block.dataset.type === 'filter';
        });

        let cond = selections.join(' or ');
        if (filters.length > 0) {
            cond = `(${cond}) and not (${filters.join(' or ')})`;
        }
        condInput.value = cond;
    }
}

// ── Generate Rule ─────────────────────────
function generateRule() {
    const data = collectFormData();

    fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(res => res.json())
    .then(result => {
        if (!result.success) {
            showToast(result.error || 'Generation failed', 'error');
            return;
        }

        currentRuleYaml = result.rule_yaml;
        currentConversions = result.conversions;

        // Display YAML
        document.getElementById('output-yaml').textContent = result.rule_yaml;

        // Display validation
        showValidation(result.validation);

        // Display MITRE info
        showMITREInfo(result.mitre_info);

        // Show SIEM tabs
        document.getElementById('siem-tabs').style.display = 'flex';
        document.getElementById('siem-output').style.display = 'block';
        document.getElementById('output-siem').textContent =
            result.conversions.splunk || 'No conversion available';

        // Enable buttons
        document.getElementById('btn-copy-yaml').disabled = false;
        document.getElementById('btn-save').disabled = false;

        showToast('Rule generated successfully', 'success');
    })
    .catch(err => {
        showToast('Error: ' + err.message, 'error');
    });
}

function collectFormData() {
    const selections = [];
    const filters = [];

    document.querySelectorAll('.selection-block').forEach(block => {
        const name = block.querySelector('.selection-name').value || 'selection';
        const type = block.dataset.type || 'selection';
        const fields = [];

        block.querySelectorAll('.field-row').forEach(row => {
            const field = row.querySelector('.field-name').value;
            const modifier = row.querySelector('.field-modifier').value;
            const valuesStr = row.querySelector('.field-values').value;

            if (field && valuesStr.trim()) {
                const values = valuesStr.split(',').map(v => v.trim()).filter(v => v);
                fields.push({ field, modifier, values });
            }
        });

        if (fields.length > 0) {
            const entry = { name, fields };
            if (type === 'filter') {
                filters.push(entry);
            } else {
                selections.push(entry);
            }
        }
    });

    const fpStr = document.getElementById('rule-falsepositives').value;
    const refsStr = document.getElementById('rule-references').value;
    const fieldsStr = document.getElementById('rule-fields').value;

    return {
        title: document.getElementById('rule-title').value,
        description: document.getElementById('rule-description').value,
        author: document.getElementById('rule-author').value,
        level: document.getElementById('rule-level').value,
        status: document.getElementById('rule-status').value,
        log_source: document.getElementById('rule-logsource').value,
        condition: document.getElementById('rule-condition').value,
        mitre_techniques: selectedTechniques,
        selections,
        filters,
        falsepositives: fpStr ? fpStr.split(',').map(s => s.trim()).filter(s => s) : [],
        references: refsStr ? refsStr.split(',').map(s => s.trim()).filter(s => s) : [],
        fields: fieldsStr ? fieldsStr.split(',').map(s => s.trim()).filter(s => s) : [],
    };
}

// ── Display helpers ──────────────────────
function showValidation(validation) {
    const container = document.getElementById('validation-status');
    container.style.display = 'flex';

    if (validation.valid) {
        container.className = 'validation-status valid';
        let html = '<div class="validation-icon">✓</div><div class="validation-messages">';
        html += '<div class="success-msg">Rule is valid</div>';
        validation.warnings.forEach(w => {
            html += `<div class="warning-msg">⚠ ${w}</div>`;
        });
        html += '</div>';
        container.innerHTML = html;
    } else {
        container.className = 'validation-status invalid';
        let html = '<div class="validation-icon">✗</div><div class="validation-messages">';
        validation.errors.forEach(e => {
            html += `<div class="error-msg">✗ ${e}</div>`;
        });
        validation.warnings.forEach(w => {
            html += `<div class="warning-msg">⚠ ${w}</div>`;
        });
        html += '</div>';
        container.innerHTML = html;
    }
}

function showMITREInfo(mitreInfo) {
    const panel = document.getElementById('mitre-info-panel');
    if (!mitreInfo || mitreInfo.length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'block';
    let html = '';
    mitreInfo.forEach(info => {
        const tacticLabel = info.tactic.replace(/-/g, ' ');
        html += `
            <div class="mitre-info-item">
                <span class="mitre-id">${info.id}</span>
                <span class="mitre-name">${info.name}</span>
                <span class="mitre-tactic-label">${info.tactic_id} ${tacticLabel}</span>
            </div>
        `;
    });
    panel.innerHTML = html;
}

// ── Templates ─────────────────────────────
function loadTemplate(key) {
    fetch(`/api/template/${key}`)
    .then(res => res.json())
    .then(result => {
        if (!result.success) {
            showToast(result.error || 'Failed to load template', 'error');
            return;
        }

        // Switch to builder tab
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelector('[data-tab="builder"]').classList.add('active');
        document.getElementById('tab-builder').classList.add('active');

        // Populate form
        const tmpl = result.template;
        document.getElementById('rule-title').value = tmpl.name || '';
        document.getElementById('rule-description').value = tmpl.description || '';
        document.getElementById('rule-level').value = tmpl.level || 'medium';
        document.getElementById('rule-status').value = tmpl.status || 'experimental';
        document.getElementById('rule-logsource').value = tmpl.log_source || 'process_creation';
        document.getElementById('rule-falsepositives').value = (tmpl.falsepositives || []).join(', ');
        document.getElementById('rule-fields').value = (tmpl.fields || []).join(', ');

        // Set MITRE techniques
        selectedTechniques = tmpl.mitre_techniques || [];
        updateSelectedTechniques();
        renderMITREList();

        // Update field dropdowns
        updateAllFieldDropdowns();

        // Populate detection blocks
        populateDetectionBlocks(tmpl.detection);

        // Show output
        currentRuleYaml = result.rule_yaml;
        currentConversions = result.conversions;
        document.getElementById('output-yaml').textContent = result.rule_yaml;
        showValidation(result.validation);
        showMITREInfo(result.mitre_info);

        document.getElementById('siem-tabs').style.display = 'flex';
        document.getElementById('siem-output').style.display = 'block';
        document.getElementById('output-siem').textContent =
            result.conversions.splunk || 'No conversion available';

        document.getElementById('btn-copy-yaml').disabled = false;
        document.getElementById('btn-save').disabled = false;

        showToast(`Template loaded: ${tmpl.name}`, 'info');
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

function populateDetectionBlocks(detection) {
    const container = document.getElementById('selections-container');
    container.innerHTML = '';
    selectionCounter = 0;
    filterCounter = 0;

    for (const [key, val] of Object.entries(detection)) {
        if (key === 'condition') continue;

        const isFilter = key.startsWith('filter');
        const type = isFilter ? 'filter' : 'selection';
        const badgeClass = isFilter ? 'badge-filter' : 'badge-selection';

        const div = document.createElement('div');
        div.className = 'selection-block';
        div.dataset.type = type;
        div.dataset.name = key;

        let fieldsHtml = '';
        if (typeof val === 'object' && !Array.isArray(val)) {
            for (const [fieldKey, fieldVal] of Object.entries(val)) {
                let fieldName = fieldKey;
                let modifier = '';
                if (fieldKey.includes('|')) {
                    const parts = fieldKey.split('|');
                    fieldName = parts[0];
                    modifier = parts.slice(1).join('|');
                }

                const values = Array.isArray(fieldVal) ? fieldVal.join(', ') : String(fieldVal);

                fieldsHtml += `
                    <div class="field-row">
                        <select class="field-name">
                            <option value="${fieldName}" selected>${fieldName}</option>
                        </select>
                        <select class="field-modifier">
                            <option value="" ${!modifier ? 'selected' : ''}>No modifier</option>
                            <option value="contains" ${modifier === 'contains' ? 'selected' : ''}>contains</option>
                            <option value="startswith" ${modifier === 'startswith' ? 'selected' : ''}>startswith</option>
                            <option value="endswith" ${modifier === 'endswith' ? 'selected' : ''}>endswith</option>
                            <option value="re" ${modifier === 're' ? 'selected' : ''}>regex</option>
                            <option value="all" ${modifier === 'all' ? 'selected' : ''}>all</option>
                            <option value="base64" ${modifier === 'base64' ? 'selected' : ''}>base64</option>
                            <option value="cidr" ${modifier === 'cidr' ? 'selected' : ''}>cidr</option>
                        </select>
                        <textarea class="field-values" rows="1">${values}</textarea>
                        <button class="btn-icon btn-danger" onclick="removeField(this)" title="Remove field">×</button>
                    </div>
                `;
            }
        }

        div.innerHTML = `
            <div class="selection-header">
                <input type="text" class="selection-name" value="${key}" placeholder="${type} name">
                <span class="selection-type-badge ${badgeClass}">${type.toUpperCase()}</span>
                <button class="btn-icon" onclick="addFieldToSelection(this)" title="Add field">+</button>
                <button class="btn-icon btn-danger" onclick="removeSelection(this)" title="Remove">×</button>
            </div>
            <div class="selection-fields">${fieldsHtml}</div>
        `;

        container.appendChild(div);

        // Populate field dropdowns properly
        div.querySelectorAll('.field-name').forEach(select => {
            const currentVal = select.value;
            populateFieldDropdown(select);
            select.value = currentVal;
            // If the field isn't in the standard list, add it
            if (!select.value && currentVal) {
                const opt = document.createElement('option');
                opt.value = currentVal;
                opt.textContent = currentVal;
                select.insertBefore(opt, select.lastElementChild);
                select.value = currentVal;
            }
        });
    }

    document.getElementById('rule-condition').value = detection.condition || 'selection';
}

// ── Validator ─────────────────────────────
function validateRule() {
    const ruleYaml = document.getElementById('validate-input').value;
    if (!ruleYaml.trim()) {
        showToast('Paste a Sigma rule first', 'error');
        return;
    }

    fetch('/api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_yaml: ruleYaml })
    })
    .then(res => res.json())
    .then(result => {
        const container = document.getElementById('validator-results');
        if (!result.success) {
            container.innerHTML = `<div class="error-msg">Error: ${result.error}</div>`;
            return;
        }

        const v = result.validation;
        let html = '';
        if (v.valid) {
            html += '<div class="validation-status valid"><div class="validation-icon">✓</div><div class="validation-messages"><div class="success-msg">Rule is valid</div>';
        } else {
            html += '<div class="validation-status invalid"><div class="validation-icon">✗</div><div class="validation-messages">';
        }
        v.errors.forEach(e => html += `<div class="error-msg">✗ ${e}</div>`);
        v.warnings.forEach(w => html += `<div class="warning-msg">⚠ ${w}</div>`);
        if (v.valid && v.warnings.length === 0) {
            html += '<div class="success-msg">No warnings</div>';
        }
        html += '</div></div>';
        container.innerHTML = html;
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

function convertFromValidator() {
    const ruleYaml = document.getElementById('validate-input').value;
    if (!ruleYaml.trim()) {
        showToast('Paste a Sigma rule first', 'error');
        return;
    }

    const promises = ['splunk', 'elastic', 'eql', 'sentinel'].map(backend =>
        fetch('/api/convert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_yaml: ruleYaml, backend })
        }).then(r => r.json()).then(r => ({ backend, query: r.query || r.error || 'Error' }))
    );

    Promise.all(promises).then(results => {
        validatorConversions = {};
        results.forEach(r => validatorConversions[r.backend] = r.query);

        document.getElementById('validator-conversions').style.display = 'block';
        document.getElementById('validator-siem-output').textContent =
            validatorConversions.splunk || 'No conversion available';

        showToast('Conversions generated', 'success');
    }).catch(err => showToast('Error: ' + err.message, 'error'));
}

// ── Library ───────────────────────────────
function refreshLibrary() {
    fetch('/api/library/list')
    .then(res => res.json())
    .then(result => {
        const container = document.getElementById('library-list');
        if (!result.success || result.rules.length === 0) {
            container.innerHTML = '<span class="placeholder">No saved rules yet. Generate a rule and click "Save to Library".</span>';
            return;
        }

        let html = '';
        result.rules.forEach(rule => {
            html += `
                <div class="library-item">
                    <div class="library-item-info">
                        <h4>${rule.title}</h4>
                        <p>${rule.description || 'No description'}</p>
                    </div>
                    <div class="library-item-meta">
                        <span class="template-level level-${rule.level}" style="position:static">${rule.level.toUpperCase()}</span>
                        <span class="meta-tag">${rule.status}</span>
                    </div>
                    <div class="library-item-actions">
                        <button class="btn btn-sm btn-accent" onclick="loadFromLibrary('${rule.filename}')">Load</button>
                        <button class="btn btn-sm btn-secondary" onclick="deleteFromLibrary('${rule.filename}')">Delete</button>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    })
    .catch(err => {
        document.getElementById('library-list').innerHTML =
            `<span class="placeholder">Error loading library: ${err.message}</span>`;
    });
}

function saveToLibrary() {
    if (!currentRuleYaml) {
        showToast('Generate a rule first', 'error');
        return;
    }

    fetch('/api/library/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_yaml: currentRuleYaml })
    })
    .then(res => res.json())
    .then(result => {
        if (result.success) {
            showToast(result.message, 'success');
        } else {
            showToast(result.error, 'error');
        }
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

function loadFromLibrary(filename) {
    fetch(`/api/library/load/${filename}`)
    .then(res => res.json())
    .then(result => {
        if (!result.success) {
            showToast(result.error, 'error');
            return;
        }

        // Switch to validator tab and display
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelector('[data-tab="validator"]').classList.add('active');
        document.getElementById('tab-validator').classList.add('active');

        document.getElementById('validate-input').value = result.rule_yaml;

        // Show validation
        const container = document.getElementById('validator-results');
        const v = result.validation;
        let html = '';
        if (v.valid) {
            html += '<div class="validation-status valid"><div class="validation-icon">✓</div><div class="validation-messages"><div class="success-msg">Rule is valid</div>';
        } else {
            html += '<div class="validation-status invalid"><div class="validation-icon">✗</div><div class="validation-messages">';
        }
        v.errors.forEach(e => html += `<div class="error-msg">✗ ${e}</div>`);
        v.warnings.forEach(w => html += `<div class="warning-msg">⚠ ${w}</div>`);
        html += '</div></div>';
        container.innerHTML = html;

        // Show conversions
        validatorConversions = result.conversions;
        document.getElementById('validator-conversions').style.display = 'block';
        document.getElementById('validator-siem-output').textContent =
            validatorConversions.splunk || 'No conversion';

        showToast(`Loaded: ${filename}`, 'info');
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

function deleteFromLibrary(filename) {
    if (!confirm(`Delete rule: ${filename}?`)) return;

    fetch(`/api/library/delete/${filename}`, { method: 'DELETE' })
    .then(res => res.json())
    .then(result => {
        if (result.success) {
            showToast(result.message, 'success');
            refreshLibrary();
        } else {
            showToast(result.error, 'error');
        }
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

function exportLibrary() {
    fetch('/api/library/export')
    .then(res => res.json())
    .then(result => {
        if (!result.success) {
            showToast('Export failed', 'error');
            return;
        }
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sigmaforge_export_${new Date().toISOString().slice(0,10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`Exported ${result.rule_count} rules`, 'success');
    })
    .catch(err => showToast('Error: ' + err.message, 'error'));
}

// ── Clipboard ─────────────────────────────
function copyOutput(type) {
    let text = '';
    if (type === 'yaml') {
        text = currentRuleYaml;
    }
    if (text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copied to clipboard', 'success');
        }).catch(() => {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('Copied to clipboard', 'success');
        });
    }
}

function copySIEMQuery() {
    const text = document.getElementById('output-siem').textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('SIEM query copied', 'success');
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('SIEM query copied', 'success');
    });
}

// ── Toast Notifications ──────────────────
function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        if (toast.parentNode) toast.remove();
    }, 3000);
}

// ── Clear Form ────────────────────────────
function clearForm() {
    // Metadata
    document.getElementById('rule-title').value = '';
    document.getElementById('rule-author').value = 'SigmaForge';
    document.getElementById('rule-description').value = '';
    document.getElementById('rule-level').value = 'medium';
    document.getElementById('rule-status').value = 'experimental';
    document.getElementById('rule-logsource').value = 'process_creation';

    // MITRE
    selectedTechniques = [];
    updateSelectedTechniques();
    renderMITREList();

    // Detection - reset to single empty selection
    const container = document.getElementById('selections-container');
    container.innerHTML = '';
    selectionCounter = 0;
    filterCounter = 0;
    addDetectionBlock('selection', 'selection');
    document.getElementById('rule-condition').value = 'selection';

    // Additional fields
    document.getElementById('rule-falsepositives').value = '';
    document.getElementById('rule-references').value = '';
    document.getElementById('rule-fields').value = '';

    // Clear output
    document.getElementById('output-yaml').innerHTML = '<span class="placeholder">Generated rule will appear here...</span>';
    document.getElementById('validation-status').style.display = 'none';
    document.getElementById('mitre-info-panel').style.display = 'none';
    document.getElementById('siem-tabs').style.display = 'none';
    document.getElementById('siem-output').style.display = 'none';
    document.getElementById('btn-copy-yaml').disabled = true;
    document.getElementById('btn-save').disabled = true;
    currentRuleYaml = '';
    currentConversions = {};

    // Update field dropdowns for new log source
    updateAllFieldDropdowns();

    showToast('Form cleared', 'info');
}
