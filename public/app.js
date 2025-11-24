const API = (window.APP_CONFIG && window.APP_CONFIG.apiBase) || '/api/v1';
let token = localStorage.getItem('token') || '';

const state = {
  stands: [],
  selectedStand: null,
  documents: [],
  servers: [],
  vms: [],
  distributions: [],
  graph: { nodes: [], edges: [] },
};

const el = (id) => document.getElementById(id);
const loginStatus = el('loginStatus');

const api = async (path, options = {}) => {
  const headers = options.headers || {};
  const opts = { method: options.method || 'GET', headers };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.formData) {
    opts.body = options.formData;
  } else if (options.body) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(options.body);
  }
  const res = await fetch(`${API}${path}`, opts);
  const text = await res.text();
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? JSON.parse(text || '{}') : text;
  if (!res.ok) {
    const message = data && data.message ? data.message : res.statusText;
    throw new Error(message);
  }
  return data;
};

const updateLoginUi = () => {
  const loggedIn = !!token;
  el('loginBtn').style.display = loggedIn ? 'none' : 'inline-flex';
  el('logoutBtn').style.display = loggedIn ? 'inline-flex' : 'none';
  loginStatus.textContent = loggedIn ? 'Админ' : 'Гость';
};

const login = async () => {
  const username = el('loginUser').value;
  const password = el('loginPass').value;
  try {
    const { token: t } = await api('/auth/login', { method: 'POST', body: { username, password } });
    token = t;
    localStorage.setItem('token', token);
    loginStatus.textContent = 'Вход выполнен';
    updateLoginUi();
  } catch (err) {
    loginStatus.textContent = err.message;
  }
};

const logout = () => {
  token = '';
  localStorage.removeItem('token');
  updateLoginUi();
};

const loadStands = async () => {
  const q = el('searchInput').value.trim();
  const status = el('filterStatus').value.trim();
  const tag = el('filterTag').value.trim();
  const params = new URLSearchParams();
  if (q) params.append('q', q);
  if (status) params.append('status', status);
  if (tag) params.append('tag', tag);
  const data = await api(`/stands?${params.toString()}`);
  state.stands = data.items;
  renderStands();
};

const renderStands = () => {
  const container = el('standList');
  container.innerHTML = '';
  if (state.stands.length === 0) {
    container.innerHTML = '<div class="muted">Нет данных</div>';
    return;
  }
  state.stands.forEach((s) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
          <strong>${s.name}</strong>
          <div class="muted">${s.description || 'Без описания'}</div>
        </div>
        <button data-id="${s.id}">Открыть</button>
      </div>
      <div class="tags">
        ${s.tags.map((t) => `<span class="tag">${t}</span>`).join('')}
      </div>
      <div class="muted">Статус: ${s.status || 'n/a'} • Владелец: ${s.owner || '—'}</div>
    `;
    card.querySelector('button').onclick = () => selectStand(s.id);
    container.appendChild(card);
  });
};

const selectStand = async (id) => {
  const stand = await api(`/stands/${id}`);
  state.selectedStand = stand;
  el('standHeader').innerHTML = `
    <div class="muted">ID: ${stand.id}</div>
    <h2 style="margin:0;">${stand.name}</h2>
    <div class="muted">${stand.description || 'Без описания'}</div>
    <div class="tags">${stand.tags.map((t) => `<span class="tag">${t}</span>`).join('')}</div>
    <div class="muted">Статус: ${stand.status} • Владелец: ${stand.owner || '—'}</div>
  `;
  await Promise.all([loadDocuments(id), loadServers(id), loadVms(id), loadDistributions(id), loadGraph(id)]);
  renderTabs('info');
};

const loadDocuments = async (standId) => {
  const data = await api(`/stands/${standId}/documents`);
  state.documents = data.items;
};

const loadServers = async (standId) => {
  const data = await api(`/stands/${standId}/servers`);
  state.servers = data.items;
};

const loadVms = async (standId) => {
  const data = await api(`/stands/${standId}/vms`);
  state.vms = data.items;
};

const loadDistributions = async (standId) => {
  const data = await api(`/stands/${standId}/distributions`);
  const products = data.items || [];
  const withVersions = await Promise.all(products.map(async (p) => {
    const versions = await api(`/distributions/${p.id}/versions`);
    return { ...p, versions: versions.items || [] };
  }));
  state.distributions = withVersions;
};

const loadGraph = async (standId) => {
  state.graph = await api(`/stands/${standId}/graph`);
};

const renderTabs = (active) => {
  const tabs = [
    { id: 'info', label: 'Инфо' },
    { id: 'documents', label: 'Документы' },
    { id: 'servers', label: 'Железо' },
    { id: 'vms', label: 'ВМ' },
    { id: 'distributions', label: 'Дистрибутивы' },
    { id: 'graph', label: 'Схема' },
  ];
  const bar = el('tabs');
  bar.innerHTML = '';
  tabs.forEach((t) => {
    const btn = document.createElement('div');
    btn.className = `tab ${active === t.id ? 'active' : ''}`;
    btn.textContent = t.label;
    btn.onclick = () => renderTabs(t.id);
    bar.appendChild(btn);
  });
  const container = el('tabContent');
  container.innerHTML = '';
  if (!state.selectedStand) {
    container.innerHTML = '<div class="muted">Нет выбранного стенда</div>';
    return;
  }
  const renderers = {
    info: renderInfoTab,
    documents: renderDocumentsTab,
    servers: renderServersTab,
    vms: renderVmsTab,
    distributions: renderDistributionsTab,
    graph: renderGraphTab,
  };
  (renderers[active] || renderInfoTab)(container);
};

const renderInfoTab = (container) => {
  const stand = state.selectedStand;
  const editable = !!token;
  const div = document.createElement('div');
  div.className = 'stack';
  div.innerHTML = `
    <div class="muted">Создан: ${stand.created_at}</div>
    <div class="grid two">
      <div>
        <label class="muted">Статус</label>
        <input id="standStatus" value="${stand.status || ''}" ${editable ? '' : 'disabled'} />
      </div>
      <div>
        <label class="muted">Владелец</label>
        <input id="standOwner" value="${stand.owner || ''}" ${editable ? '' : 'disabled'} />
      </div>
    </div>
    <div>
      <label class="muted">Теги (через запятую)</label>
      <input id="standTags" value="${stand.tags.join(', ')}" ${editable ? '' : 'disabled'} />
    </div>
    <div>
      <label class="muted">Описание</label>
      <textarea id="standDesc" rows="3" ${editable ? '' : 'disabled'}>${stand.description || ''}</textarea>
    </div>
  `;
  if (editable) {
    const btn = document.createElement('button');
    btn.textContent = 'Сохранить стенд';
    btn.onclick = async () => {
      try {
        const payload = {
          description: el('standDesc').value,
          status: el('standStatus').value,
          owner: el('standOwner').value,
          tags: el('standTags').value.split(',').map((v) => v.trim()).filter(Boolean),
        };
        const updated = await api(`/stands/${stand.id}`, { method: 'PUT', body: payload });
        state.selectedStand = updated;
        await loadStands();
        selectStand(stand.id);
      } catch (err) {
        alert(err.message);
      }
    };
    div.appendChild(btn);
  }
  container.appendChild(div);
};

const renderDocumentsTab = (container) => {
  const wrap = document.createElement('div');
  wrap.className = 'stack';
  if (token) {
    const form = document.createElement('div');
    form.className = 'form-row';
    form.innerHTML = `
      <input type="text" id="docTitle" placeholder="Название" />
      <input type="file" id="docFile" />
      <label class="muted"><input type="checkbox" id="docInline" /> Inline</label>
      <button id="uploadDocBtn">Загрузить</button>
    `;
    form.querySelector('#uploadDocBtn').onclick = async () => {
      const fileInput = el('docFile');
      if (!fileInput.files[0]) { alert('Файл обязателен'); return; }
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      fd.append('title', el('docTitle').value || fileInput.files[0].name);
      fd.append('editable_inline', el('docInline').checked);
      try {
        await api(`/stands/${state.selectedStand.id}/documents`, { method: 'POST', formData: fd });
        await loadDocuments(state.selectedStand.id);
        renderTabs('documents');
      } catch (err) {
        alert(err.message);
      }
    };
    wrap.appendChild(form);
  }
  const list = document.createElement('div');
  list.className = 'list';
  if (state.documents.length === 0) list.innerHTML = '<div class="muted">Нет документов</div>';
  state.documents.forEach((d) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;">
        <div><strong>${d.title}</strong><div class="muted">${d.description || ''}</div></div>
        <div class="muted">${new Date(d.created_at).toLocaleString()}</div>
      </div>
      <div class="form-row">
        <a href="${API}/documents/${d.id}/download" target="_blank"><button>Скачать</button></a>
        ${d.editable_inline ? `<button data-edit="${d.id}">Редактировать</button>` : ''}
        ${token ? `<button class="danger" data-del="${d.id}">Удалить</button>` : ''}
      </div>
      ${d.editable_inline ? `<textarea id="docContent-${d.id}" rows="6" style="display:none;"></textarea><button data-save="${d.id}" style="display:none;">Сохранить</button>` : ''}
    `;
    if (d.editable_inline) {
      const editBtn = card.querySelector(`[data-edit="${d.id}"]`);
      const textarea = card.querySelector(`#docContent-${d.id}`);
      const saveBtn = card.querySelector(`[data-save="${d.id}"]`);
      editBtn.onclick = async () => {
        const content = await api(`/documents/${d.id}/content`);
        textarea.value = typeof content === 'string' ? content : '';
        textarea.style.display = 'block';
        saveBtn.style.display = 'inline-flex';
      };
      saveBtn.onclick = async () => {
        try {
          await fetch(`${API}/documents/${d.id}/content`, {
            method: 'PUT',
            headers: { Authorization: `Bearer ${token}` },
            body: textarea.value,
          });
          alert('Сохранено');
        } catch (err) {
          alert(err.message);
        }
      };
    }
    if (token) {
      const delBtn = card.querySelector(`[data-del="${d.id}"]`);
      if (delBtn) delBtn.onclick = async () => {
        await api(`/documents/${d.id}`, { method: 'DELETE' });
        await loadDocuments(state.selectedStand.id);
        renderTabs('documents');
      };
    }
    list.appendChild(card);
  });
  wrap.appendChild(list);
  container.appendChild(wrap);
};

const renderServersTab = (container) => {
  const wrap = document.createElement('div');
  wrap.className = 'stack';
  if (token) {
    const form = document.createElement('div');
    form.className = 'grid two';
    form.innerHTML = `
      <input id="srvName" placeholder="Имя сервера" />
      <input id="srvLocation" placeholder="Локация" />
      <input id="srvCpu" placeholder="CPU" />
      <input id="srvRam" placeholder="RAM" />
      <input id="srvStorage" placeholder="Диски" />
      <input id="srvNetwork" placeholder="Сеть" />
      <input id="srvRole" placeholder="Роль" />
      <button id="srvCreate">Добавить</button>
    `;
    form.querySelector('#srvCreate').onclick = async () => {
      try {
        await api(`/stands/${state.selectedStand.id}/servers`, {
          method: 'POST',
          body: {
            name: el('srvName').value,
            location: el('srvLocation').value,
            cpu: el('srvCpu').value,
            ram: el('srvRam').value,
            storage: el('srvStorage').value,
            network: el('srvNetwork').value,
            role: el('srvRole').value,
          },
        });
        await loadServers(state.selectedStand.id);
        renderTabs('servers');
      } catch (err) { alert(err.message); }
    };
    wrap.appendChild(form);
  }
  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>Имя</th><th>CPU</th><th>RAM</th><th>Роль</th></tr></thead>
    <tbody>${state.servers.map((s) => `<tr><td>${s.name}</td><td>${s.cpu || ''}</td><td>${s.ram || ''}</td><td>${s.role || ''}</td></tr>`).join('')}</tbody>
  `;
  wrap.appendChild(table);
  container.appendChild(wrap);
};

const renderVmsTab = (container) => {
  const wrap = document.createElement('div');
  wrap.className = 'stack';
  if (token) {
    const form = document.createElement('div');
    form.className = 'grid two';
    form.innerHTML = `
      <input id="vmName" placeholder="Имя ВМ" />
      <input id="vmGroup" placeholder="ID группы (опц.)" />
      <input id="vmIps" placeholder="IP через запятую" />
      <input id="vmOs" placeholder="OS" />
      <input id="vmRole" placeholder="Роль" />
      <input id="vmPort" placeholder="SSH порт" value="22" />
      <button id="vmCreate">Добавить ВМ</button>
    `;
    form.querySelector('#vmCreate').onclick = async () => {
      try {
        await api(`/stands/${state.selectedStand.id}/vms`, {
          method: 'POST',
          body: {
            name: el('vmName').value,
            group_id: el('vmGroup').value || null,
            ips: el('vmIps').value.split(',').map((v) => v.trim()).filter(Boolean),
            os: el('vmOs').value,
            role: el('vmRole').value,
            ssh_port: parseInt(el('vmPort').value, 10) || 22,
          },
        });
        await loadVms(state.selectedStand.id);
        renderTabs('vms');
      } catch (err) { alert(err.message); }
    };
    wrap.appendChild(form);
  }
  const userInput = document.createElement('input');
  userInput.placeholder = 'Пользователь SSH';
  userInput.value = 'root';
  wrap.appendChild(userInput);
  const list = document.createElement('div');
  list.className = 'list';
  state.vms.forEach((vm) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `<strong>${vm.name}</strong><div class="muted">${vm.role || ''}</div>`;
    const ipRow = document.createElement('div');
    ipRow.className = 'form-row';
    (vm.ips || []).forEach((ip) => {
      const btn = document.createElement('button');
      btn.textContent = `${ip}:${vm.ssh_port || 22}`;
      btn.onclick = () => {
        const user = userInput.value || 'root';
        const href = `ssh://${user}@${ip}:${vm.ssh_port || 22}`;
        window.location.href = href;
      };
      ipRow.appendChild(btn);
    });
    card.appendChild(ipRow);
    list.appendChild(card);
  });
  wrap.appendChild(list);
  container.appendChild(wrap);
};

const renderDistributionsTab = (container) => {
  const wrap = document.createElement('div');
  wrap.className = 'stack';
  if (token) {
    const form = document.createElement('div');
    form.className = 'form-row';
    form.innerHTML = `
      <input id="distName" placeholder="Название продукта" />
      <input id="distDesc" placeholder="Описание" />
      <button id="distCreate">Добавить продукт</button>
    `;
    form.querySelector('#distCreate').onclick = async () => {
      try {
        await api(`/stands/${state.selectedStand.id}/distributions`, { method: 'POST', body: { name: el('distName').value, description: el('distDesc').value } });
        await loadDistributions(state.selectedStand.id);
        renderTabs('distributions');
      } catch (err) { alert(err.message); }
    };
    wrap.appendChild(form);
  }
  state.distributions.forEach((d) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `<strong>${d.name}</strong><div class="muted">${d.description || ''}</div>`;
    if (token) {
      const upload = document.createElement('div');
      upload.className = 'form-row';
      upload.innerHTML = `
        <input type="file" id="verFile-${d.id}" />
        <input type="text" id="verDesc-${d.id}" placeholder="Комментарий" />
        <label class="muted"><input type="checkbox" id="verActive-${d.id}" /> Актуальная</label>
        <button data-up="${d.id}">Загрузить версию</button>
      `;
      upload.querySelector(`[data-up="${d.id}"]`).onclick = async () => {
        const fd = new FormData();
        const file = upload.querySelector(`#verFile-${d.id}`).files[0];
        if (!file) { alert('Файл обязателен'); return; }
        fd.append('file', file);
        fd.append('description', upload.querySelector(`#verDesc-${d.id}`).value);
        fd.append('is_active', upload.querySelector(`#verActive-${d.id}`).checked);
        try {
          await api(`/distributions/${d.id}/versions`, { method: 'POST', formData: fd });
          await loadDistributions(state.selectedStand.id);
          renderTabs('distributions');
        } catch (err) { alert(err.message); }
      };
      card.appendChild(upload);
    }
    const versions = document.createElement('div');
    versions.className = 'stack';
    (d.versions || []).forEach((v) => {
      const line = document.createElement('div');
      line.className = 'form-row';
      line.innerHTML = `
        <span>${v.file_name}</span>
        ${v.is_active ? '<span class="tag">active</span>' : ''}
        <a href="${API}/distribution-versions/${v.id}/download" target="_blank"><button>Скачать</button></a>
        ${token ? `<button class="danger" data-del="${v.id}">Удалить</button>` : ''}
      `;
      if (token) {
        line.querySelector(`[data-del="${v.id}"]`).onclick = async () => {
          await api(`/distribution-versions/${v.id}`, { method: 'DELETE' });
          await loadDistributions(state.selectedStand.id);
          renderTabs('distributions');
        };
      }
      versions.appendChild(line);
    });
    card.appendChild(versions);
    wrap.appendChild(card);
  });
  container.appendChild(wrap);
};

const renderGraphTab = (container) => {
  const wrap = document.createElement('div');
  wrap.className = 'stack';
  const textarea = document.createElement('textarea');
  textarea.rows = 14;
  textarea.value = JSON.stringify(state.graph, null, 2);
  wrap.appendChild(textarea);
  if (token) {
    const btn = document.createElement('button');
    btn.textContent = 'Сохранить схему';
    btn.onclick = async () => {
      try {
        const parsed = JSON.parse(textarea.value || '{}');
        await api(`/stands/${state.selectedStand.id}/graph`, { method: 'PUT', body: parsed });
        await loadGraph(state.selectedStand.id);
        alert('Схема сохранена');
      } catch (err) { alert(err.message); }
    };
    wrap.appendChild(btn);
  }
  container.appendChild(wrap);
};

const bindEvents = () => {
  el('loginBtn').onclick = login;
  el('logoutBtn').onclick = logout;
  el('searchBtn').onclick = loadStands;
  el('createStandBtn').onclick = async () => {
    if (!token) { alert('Нужен вход'); return; }
    try {
      const name = el('newStandName').value.trim();
      if (!name) { alert('Имя обязательно'); return; }
      const created = await api('/stands', { method: 'POST', body: { name } });
      await loadStands();
      selectStand(created.id);
      el('newStandName').value = '';
    } catch (err) { alert(err.message); }
  };
};

const init = async () => {
  updateLoginUi();
  bindEvents();
  await loadStands();
};

init().catch((err) => {
  console.error(err);
  loginStatus.textContent = err.message;
});
